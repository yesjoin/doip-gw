// ============================================================================
// doip_client.cpp —— 站在诊断仪那边，走一遍 M2 的最小流程
//
// 用法：doip-client [--host 127.0.0.1] [--port 13400] [--sa 0E00] [--type 00] [--alive]
//
// 流程：TCP 连上 → 发 0x0005 路由激活 → 读 0x0006 → （可选）发 0x0007 读 0x0008
// 打印的每一行都和 doip-serve 那侧对得上，方便"两边对照看"。
// ============================================================================
#include "DiagResponseCollector.h"   // M11：多响应配对（纯逻辑，无 socket）
#include "DoIpCodec.h"
#include "DoIpDiagnostic.h"   // DiagNack 名字表
#include "DoIpRouting.h"      // 为了 nameOf(ActivationResponseCode)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace doip;

// 假时钟：只用来给收集器打时间戳（"这一条比上一条晚多久"），不参与任何超时判定
static long nowMs ()
{
    using namespace std::chrono;
    return static_cast<long> (
        duration_cast<milliseconds> (steady_clock::now ().time_since_epoch ()).count ());
}

static bool sendVec (int fd, const std::vector<std::uint8_t> &b)
{
    std::size_t sent = 0;
    while (sent < b.size ())
    {
        const ssize_t n = ::send (fd, b.data () + sent, b.size () - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t> (n);
    }
    return true;
}

// 收一条完整报文；返回 false 表示超时或对面关了
static bool recvMessage (int fd, std::vector<std::uint8_t> &whole, int ms, std::string &why)
{
    whole.clear ();
    while (true)
    {
        pollfd p;
        p.fd      = fd;
        p.events  = POLLIN;
        p.revents = 0;
        if (::poll (&p, 1, ms) <= 0)
        {
            why = "超时";
            return false;
        }
        std::uint8_t buf[2048];
        const ssize_t got = ::recv (fd, buf, sizeof (buf), 0);
        if (got <= 0)
        {
            why = "对端关闭了连接";
            return false;
        }
        whole.insert (whole.end (), buf, buf + got);

        Message m;
        ParseResult pr = parseMessage (whole.data (), whole.size (), m);
        if (pr.error == ParseError::None) return true;
        if (pr.error != ParseError::NeedMoreData)
        {
            why = "报文格式不对";
            return false;
        }
    }
}

// 带缓冲的收：服务器会把 0x8002 和 0x8001 响应连着发，
// 一次 recv 可能同时读到两条，只看第一条会把响应丢掉。
static bool recvMsgBuf (int fd, Message &out, std::vector<std::uint8_t> &buf, int ms, std::string &why)
{
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (ms);
    while (true)
    {
        ParseResult pr = parseMessage (buf.data (), buf.size (), out);
        if (pr.error == ParseError::None)
        {
            buf.erase (buf.begin (), buf.begin () + static_cast<std::ptrdiff_t> (pr.consumed));
            return true;
        }
        if (pr.error != ParseError::NeedMoreData)
        {
            why = "报文格式不对";
            return false;
        }

        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) { why = "超时"; return false; }
        const int left = static_cast<int> (
            std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());

        pollfd p;
        p.fd      = fd;
        p.events  = POLLIN;
        p.revents = 0;
        if (::poll (&p, 1, left <= 0 ? 1 : left) <= 0) { why = "超时"; return false; }

        std::uint8_t tmp[2048];
        const ssize_t got = ::recv (fd, tmp, sizeof (tmp), 0);
        if (got <= 0) { why = "对端关闭了连接"; return false; }
        buf.insert (buf.end (), tmp, tmp + got);
    }
}

// "22 F1 90" / "22f190" 都认
static bool parseHex (const std::string &s, std::vector<std::uint8_t> &out)
{
    out.clear ();
    std::size_t i = 0;
    while (i < s.size ())
    {
        while (i < s.size () && (s[i] == ' ' || s[i] == '\t')) ++i;
        if (i >= s.size ()) break;
        if (i + 1 >= s.size ()) return false;
        auto val = [&] (char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = val (s[i]);
        const int lo = val (s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back (static_cast<std::uint8_t> ((hi << 4) | lo));
        i += 2;
    }
    return !out.empty ();
}

static std::string udsServiceNameStr (std::uint8_t sid)
{
    if (sid == 0x7F) return "负响应";
    if (sid > 0x40 && sid < 0x7F)
    {
        char b[64];
        std::snprintf (b, sizeof (b), "正响应（对应 0x%02X）", static_cast<unsigned> (sid - 0x40));
        return std::string (b);
    }
    switch (sid)
    {
    case 0x10: return "DiagnosticSessionControl";
    case 0x11: return "ECUReset";
    case 0x14: return "ClearDiagnosticInformation";
    case 0x19: return "ReadDTCInformation";
    case 0x22: return "ReadDataByIdentifier";
    case 0x27: return "SecurityAccess";
    case 0x2E: return "WriteDataByIdentifier";
    case 0x31: return "RoutineControl";
    case 0x34: return "RequestDownload";
    case 0x36: return "TransferData";
    case 0x37: return "RequestTransferExit";
    case 0x3E: return "TesterPresent";
    default:   return "未知服务";
    }
}

static void printHex (const std::vector<std::uint8_t> &b)
{
    for (std::size_t i = 0; i < b.size (); ++i)
    {
        std::printf ("%02X%s", b[i], (i + 1 == b.size ()) ? "" : " ");
    }
}

int main (int argc, char **argv)
{
    std::string host = "127.0.0.1";
    std::uint16_t port = 13400;
    std::uint16_t sa   = 0x0E00;
    std::uint8_t type  = 0x00;
    bool alive = false;
    std::uint16_t ta = 0x0001;              // 诊断目标（M3 只有实体自己）
    std::uint16_t dsa = 0;                  // 诊断报文里的 SA（默认跟随 --sa）
    bool hasDsa = false;                    // 用来演示"冒用别人地址"
    std::string diagHex;                    // --diag "22 F1 86"
    bool hasDiag = false;
    bool all = false;                       // M11：--all 收齐所有响应（功能寻址用）
    long windowMs = 900;                    // 静默窗口：多久没有新响应当"收工"（毫秒）
    bool trace = false;                     // M12：--trace 打每条响应的到达时刻与首末跨度

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--host" && i + 1 < argc)       host = argv[++i];
        else if (a == "--port" && i + 1 < argc)  port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--sa" && i + 1 < argc)    sa = static_cast<std::uint16_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--type" && i + 1 < argc)  type = static_cast<std::uint8_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--ta" && i + 1 < argc)    ta = static_cast<std::uint16_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--dsa" && i + 1 < argc)   { dsa = static_cast<std::uint16_t> (std::strtoul (argv[++i], nullptr, 16)); hasDsa = true; }
        else if (a == "--alive")                 alive = true;
        else if (a == "--diag" && i + 1 < argc)  { diagHex = argv[++i]; hasDiag = true; }
        else if (a == "--all")                   all = true;
        else if (a == "--window" && i + 1 < argc) windowMs = std::atol (argv[++i]);
        else if (a == "--trace")                  trace = true;
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--host 127.0.0.1] [--port 13400] [--sa 0E00] [--ta 0001] "
                          "[--dsa 0E01] [--type 00] [--diag \"22 F1 86\"] [--all] [--window 900] "
                          "[--trace] [--alive]\n", argv[0]);
            std::fprintf (stderr,
                          "     --trace 只对 --all 生效：每条打 RESPn_AT，末尾打 FIRST_AT/LAST_AT/SPAN_AT（毫秒，"
                          "从发出诊断请求算起）\n");
            return 2;
        }
    }

    const int fd = ::socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::fprintf (stderr, "socket() 失败\n"); return 1; }

    sockaddr_in addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons (port);
    if (::inet_pton (AF_INET, host.c_str (), &addr.sin_addr) != 1)
    {
        std::fprintf (stderr, "host 不合法：%s\n", host.c_str ());
        ::close (fd);
        return 2;
    }

    if (::connect (fd, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        std::fprintf (stderr, "连不上 %s:%u（实体端起了吗？）\n", host.c_str (), static_cast<unsigned> (port));
        ::close (fd);
        return 1;
    }
    // M12：诊断仪这边也关掉 Nagle —— 请求和 ACK 都是小报文，别让它们互相等
    {
        int nodelay = 1;
        ::setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof (nodelay));
    }
    std::printf ("已连接 %s:%u\n", host.c_str (), static_cast<unsigned> (port));

    // 1) 路由激活
    RoutingActivationRequest req;
    req.sourceAddress  = sa;
    req.activationType = type;
    const std::vector<std::uint8_t> reqBytes =
        build (PayloadType::RoutingActivationReq, encodePayload (req));
    std::printf ("→ 0x0005 路由激活：SA=0x%04X type=0x%02X（%zu 字节）\n",
                 req.sourceAddress, req.activationType, reqBytes.size ());
    if (!sendVec (fd, reqBytes))
    {
        std::fprintf (stderr, "发送失败\n");
        ::close (fd);
        return 1;
    }

    std::vector<std::uint8_t> got;
    std::string why;
    if (!recvMessage (fd, got, 3000, why))
    {
        std::printf ("← 没拿到应答：%s\n", why.c_str ());
        ::close (fd);
        return 1;
    }

    Message m;
    parseMessage (got.data (), got.size (), m);
    if (m.header.payloadType != 0x0006)
    {
        std::printf ("← 不是 0x0006，而是 0x%04X（%zu 字节）\n",
                     static_cast<unsigned> (m.header.payloadType), got.size ());
        ::close (fd);
        return 1;
    }

    RoutingActivationResponse res;
    if (!decodePayload (m.payload, res, why))
    {
        std::printf ("← 0x0006 解不开：%s\n", why.c_str ());
        ::close (fd);
        return 1;
    }
    std::printf ("← 0x0006 应答：tester=0x%04X entity=0x%04X code=0x%02X (%s)\n",
                 res.testerAddress, res.entityAddress,
                 static_cast<unsigned> (res.responseCode),
                 nameOf (static_cast<ActivationResponseCode> (res.responseCode)));

    if (res.responseCode != static_cast<std::uint8_t> (ActivationResponseCode::Success))
    {
        std::printf ("激活没成功，后面的事不用做了。\n");
        ::close (fd);
        return 1;
    }

    // 2) 诊断（可选）：0x8001 → 0x8002 ACK → 0x8001 响应
    std::vector<std::uint8_t> inbuf;         // 这个缓冲要跨多次 recv 用
    if (hasDiag)
    {
        std::vector<std::uint8_t> uds;
        if (!parseHex (diagHex, uds))
        {
            std::fprintf (stderr, "--diag 里的十六进制不合法：%s\n", diagHex.c_str ());
            ::close (fd);
            return 2;
        }

        DiagnosticMessage dm;
        dm.sourceAddress = hasDsa ? dsa : sa;
        dm.targetAddress = ta;
        dm.uds           = uds;
        const std::vector<std::uint8_t> dbytes =
            build (PayloadType::DiagnosticMessage, encodePayload (dm));
        std::printf ("→ 0x8001 诊断：SA=0x%04X TA=0x%04X UDS=", dm.sourceAddress, dm.targetAddress);
        printHex (uds);
        std::printf ("（%s，%zu 字节）\n", udsServiceNameStr (uds[0]).c_str (), uds.size ());
        if (!sendVec (fd, dbytes))
        {
            std::fprintf (stderr, "发送失败\n");
            ::close (fd);
            return 1;
        }

        Message ack;
        if (!recvMsgBuf (fd, ack, inbuf, 3000, why))
        {
            std::printf ("← 没拿到回执：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }

        if (ack.header.payloadType == 0x8003)
        {
            DiagnosticNegativeAck na;
            decodePayload (ack.payload, na, why);
            const std::string nm = nameOf (static_cast<DiagNack> (na.nackCode));
            std::printf ("← 0x8003 NACK：SA=0x%04X TA=0x%04X code=0x%02X (%s)\n",
                         na.sourceAddress, na.targetAddress,
                         static_cast<unsigned> (na.nackCode), nm.c_str ());
            if (all) std::printf ("RESPONSE_COUNT=0\n");   // 连门都没进，更没有答案
            if (all && trace) std::printf ("FIRST_AT=-1\nLAST_AT=-1\nSPAN_AT=-1\n");   // 没有时间可谈
            ::close (fd);
            return 1;
        }

        if (ack.header.payloadType != 0x8002)
        {
            std::printf ("← 收到 0x%04X，不是 0x8002\n", static_cast<unsigned> (ack.header.payloadType));
            ::close (fd);
            return 1;
        }

        DiagnosticPositiveAck pa;
        if (!decodePayload (ack.payload, pa, why))
        {
            std::printf ("← 0x8002 解不开：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }
        std::printf ("← 0x8002 ACK：SA=0x%04X TA=0x%04X code=0x%02X\n",
                     pa.sourceAddress, pa.targetAddress, static_cast<unsigned> (pa.ackCode));

        // ---- M11：--all，收齐所有响应，按 SA 归档 ----
        //
        // 功能寻址的答案条数不由网关决定，由"谁在听"决定。所以这里既不能"收一条就走"，
        // 也不能"按第几条猜是谁"——只认 SA。收工信号只有一种：静默满窗口（DoIP 没有批次结束字段）。
        if (all)
        {
            DiagResponseCollector collector;
            // ★ M12：所有时刻都相对"诊断请求发出那一刻"。
            //   为什么不用绝对时间：两张对照表（流式 / 攒批）要比的是"首条等了多久"，
            //   跨进程的绝对时间会带入启动差，只有相对量可比。
            const long t0 = nowMs ();
            long firstAt = -1;
            long lastAt  = -1;
            std::size_t traced = 0;
            std::printf ("→ 收集响应：静默窗口 %ldms（每来一条就重新计时）\n", windowMs);

            while (true)
            {
                Message one;
                if (!recvMsgBuf (fd, one, inbuf, static_cast<int> (windowMs), why))
                {
                    std::printf ("   （静默 %ldms 无新响应，收工：%s）\n", windowMs, why.c_str ());
                    break;
                }
                // 0x8003 可能后到：ACK 先回、NACK 后回（网关先受理再判断有没有人答）
                if (one.header.payloadType == 0x8003)
                {
                    DiagnosticNegativeAck na;
                    if (decodePayload (one.payload, na, why))
                    {
                        std::printf ("← 0x8003 NACK：SA=0x%04X TA=0x%04X code=0x%02X (%s)\n",
                                     na.sourceAddress, na.targetAddress,
                                     static_cast<unsigned> (na.nackCode),
                                     nameOf (static_cast<DiagNack> (na.nackCode)));
                    }
                    break;   // 一条答案都没有，再等也没有
                }
                if (one.header.payloadType != 0x8001)
                {
                    std::printf ("← 收到 0x%04X（不是响应，跳过）\n",
                                 static_cast<unsigned> (one.header.payloadType));
                    continue;
                }
                DiagnosticMessage dr;
                if (!decodePayload (one.payload, dr, why))
                {
                    std::printf ("← 一条 0x8001 解不开：%s（跳过）\n", why.c_str ());
                    continue;
                }

                const long at = nowMs () - t0;
                if (firstAt < 0) firstAt = at;      // 第一条的到达时刻 = "首条答案时延"
                lastAt = at;
                if (trace) std::printf ("RESP%zu_AT=%ld\n", traced, at);
                ++traced;

                const auto oc = collector.add (dr.sourceAddress, dr.uds, nowMs ());
                std::printf ("← #%zu 0x8001：SA=0x%04X UDS=", collector.arrivals (), dr.sourceAddress);
                printHex (dr.uds);
                if (oc == DiagResponseCollector::Outcome::Duplicate)
                    std::printf ("   ← 这台已经答过（重复）");
                std::printf ("\n");

            }

            std::printf ("\n—— 多响应汇总：不同 SA %zu 台，到过 %zu 条，重复 %zu 次，改口 %zu 次，窗口 %ldms ——\n",
                         collector.count (), collector.arrivals (),
                         collector.duplicates (), collector.changes (), windowMs);
            if (collector.count () == 0)
            {
                std::printf ("  一条都没有：要么没人听这个地址，要么窗口比最慢的那台还短。\n");
            }
            else
            {
                for (std::size_t i = 0; i < collector.count (); ++i)
                {
                    const CollectedResponse &r = collector.at (i);
                    std::printf ("  #%zu  SA=0x%04X  %s  字节 %zu（重复 %zu，改口 %zu）\n",
                                 r.seq, r.sa,
                                 udsServiceNameStr (r.uds.empty () ? 0 : r.uds[0]).c_str (),
                                 r.uds.size (), r.duplicates, r.changes);
                }
            }

            // 机器可读的那几行：脚本只认这些，人看上面的表
            std::printf ("RESPONSE_COUNT=%zu\n", collector.count ());
            std::printf ("RESPONSE_ARRIVALS=%zu\n", collector.arrivals ());
            std::printf ("RESPONSE_SAS=");
            for (std::size_t i = 0; i < collector.count (); ++i)
                std::printf ("%s0x%04X", (i == 0 ? "" : ","), collector.at (i).sa);
            std::printf ("\n");
            for (std::size_t i = 0; i < collector.count (); ++i)
            {
                std::printf ("RESP%zu_SA=0x%04X\n", i, collector.at (i).sa);
                std::printf ("RESP%zu_HEX=", i);
                printHex (collector.at (i).uds);
                std::printf ("\n");
            }
            std::printf ("COLLECTOR_DUPLICATES=%zu\n", collector.duplicates ());
            std::printf ("COLLECTOR_CHANGES=%zu\n", collector.changes ());
            if (trace)
            {
                // SPAN = 最后一条 - 第一条：看得出"是不是被最慢那台拖成了整批"
                std::printf ("FIRST_AT=%ld\n", firstAt);
                std::printf ("LAST_AT=%ld\n", lastAt);
                std::printf ("SPAN_AT=%ld\n", (firstAt < 0 || lastAt < 0) ? -1 : lastAt - firstAt);
            }
        }
        else
        {

        Message resp;
        if (!recvMsgBuf (fd, resp, inbuf, 3000, why))
        {
            std::printf ("← 没有收到诊断响应：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }
        if (resp.header.payloadType != 0x8001)
        {
            std::printf ("← 响应类型是 0x%04X，不是 0x8001\n",
                         static_cast<unsigned> (resp.header.payloadType));
            ::close (fd);
            return 1;
        }

        DiagnosticMessage dr;
        if (!decodePayload (resp.payload, dr, why))
        {
            std::printf ("← 0x8001 响应解不开：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }
        std::printf ("← 0x8001 响应：SA=0x%04X TA=0x%04X UDS=",
                     dr.sourceAddress, dr.targetAddress);
        printHex (dr.uds);
        std::printf ("（%s）\n", udsServiceNameStr (dr.uds.empty () ? 0 : dr.uds[0]).c_str ());

        }   // else（--all 的对照分支：只收第一条）

    }

    // 3) 心跳（可选）
    if (alive)
    {
        std::printf ("→ 0x0007 心跳请求\n");
        sendVec (fd, build (PayloadType::AliveCheckReq, {}));

        std::vector<std::uint8_t> hb;
        if (!recvMessage (fd, hb, 2000, why))
        {
            std::printf ("← 心跳没回应：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }
        Message hm;
        parseMessage (hb.data (), hb.size (), hm);
        AliveCheckResponse acr;
        if (hm.header.payloadType == 0x0008 && decodePayload (hm.payload, acr, why))
        {
            std::printf ("← 0x0008 心跳应答：source=0x%04X\n", acr.sourceAddress);
        }
        else
        {
            std::printf ("← 收到 0x%04X，不是预期的心跳应答\n",
                         static_cast<unsigned> (hm.header.payloadType));
        }
    }

    std::printf ("\n激活完成。正常情况下这个连接能一直活着，直到你关掉它。\n");
    ::close (fd);
    return 0;
}
