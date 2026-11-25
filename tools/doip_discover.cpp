// ============================================================================
// doip_discover.cpp —— M1 的工具：一端当实体，一端当客户端
//
// 实体：  doip-discover --serve --port 13400 --seconds 10
// 客户端：doip-discover --host 127.0.0.1 --wait-ms 1000
//         doip-discover --broadcast --wait-ms 1000          （真的往 255.255.255.255 发）
//         doip-discover --eid 001122334455 --wait-ms 1000    （只问这个 EID）
//         doip-discover --vin LSVAA20A8F2100001              （只问这个 VIN）
//
// 为什么要这个工具：M2 之后你会不停问"到底有没有发出去"，有它就是一眼的事。
// ============================================================================
#include "DoIpDiscovery.h"

#if defined (__unix__) || defined (__APPLE__)
#    define TOOL_HAS_POSIX 1
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define TOOL_HAS_POSIX 0
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace doip;

// "001122334455" → 6 字节
static bool hexToBytes (const std::string &hex, std::vector<std::uint8_t> &out)
{
    if (hex.size () % 2 != 0) return false;
    for (std::size_t i = 0; i < hex.size (); i += 2)
    {
        auto d = [] (char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = d (hex[i]);
        const int lo = d (hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back (static_cast<std::uint8_t> ((hi << 4) | lo));
    }
    return true;
}

static void printReply (const std::vector<std::uint8_t> &bytes, const std::string &from)
{
#if TOOL_HAS_POSIX
    Message m;
    ParseResult pr = parseMessage (bytes.data (), bytes.size (), m);
    if (pr.error != ParseError::None)
    {
        std::printf ("  来自 %-22s 报文坏了（%s），%zu 字节\n", from.c_str (), nameOf (pr.error), bytes.size ());
        return;
    }

    const PayloadType t = toType (m.header.payloadType);
    if (t == PayloadType::VehicleAnnouncement)
    {
        VehicleAnnouncement v;
        std::string err;
        if (!decodePayload (m.payload, v, err))
        {
            std::printf ("  来自 %-22s 0x0004 载荷解不开：%s\n", from.c_str (), err.c_str ());
            return;
        }
        std::printf ("  来自 %-22s VIN=%s  逻辑地址=0x%04X  furtherAction=0x%02X\n",
                     from.c_str (), v.vin.c_str (), v.logicalAddress, v.furtherAction);
        std::printf ("  %-29s EID=", "");
        for (auto b : v.eid) std::printf ("%02X", b);
        std::printf ("  GID=");
        for (auto b : v.gid) std::printf ("%02X", b);
        std::printf ("\n");
    }
    else if (t == PayloadType::EntityStatusRes)
    {
        // M14：0x4002 的四个数 —— 每个都能在网关日志里对上账
        EntityStatusInfo s;
        std::string err;
        if (!decodePayload (m.payload, s, err))
        {
            std::printf ("  来自 %-22s 0x4002 载荷解不开：%s\n", from.c_str (), err.c_str ());
            return;
        }
        std::printf ("  来自 %-22s 0x4002 实体状态：%s\n", from.c_str (),
                     s.nodeType == kNodeTypeGateway ? "网关（会往子网转）" : "节点（只答自己）");
        std::printf ("  %-29s socket %u/%u 在用（连接数，不是激活数），最大载荷 %u 字节%s\n",
                     "", static_cast<unsigned> (s.curOpenSockets),
                     static_cast<unsigned> (s.maxOpenSockets),
                     static_cast<unsigned> (s.maxDataSize),
                     s.maxDataSize == 0 ? "（对面没告知）" : "");
    }
    else if (t == PayloadType::PowerModeRes)
    {
        PowerModeInfo p;
        std::string err;
        if (!decodePayload (m.payload, p, err))
        {
            std::printf ("  来自 %-22s 0x4004 载荷解不开：%s\n", from.c_str (), err.c_str ());
            return;
        }
        std::printf ("  来自 %-22s 0x4004 电源模式：%s\n", from.c_str (),
                     p.mode == kPowerReady ? "ready（能做诊断）" :
                     p.mode == kPowerNotReady ? "not ready（车没上电/ECU 没醒，要人去叫）" :
                                                "not supported（能答，但给不出这个信息）");
    }
    else
    {
        std::printf ("  来自 %-22s %s\n", from.c_str (), nameOf (t));
    }
#else
    (void) bytes;
    (void) from;
#endif
}

int main (int argc, char **argv)
{
    bool        serve     = false;
    bool        broadcast = false;
    bool        askStatus = false;      // M14：问 0x4001
    bool        askPower  = false;      // M14：问 0x4003
    std::uint16_t port    = 13400;
    std::string host      = "127.0.0.1";
    int         waitMs    = 1000;
    int         seconds   = 10;
    std::string eidHex;
    std::string vin;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--serve")      serve = true;
        else if (a == "--broadcast") broadcast = true;
        else if (a == "--port" && i + 1 < argc)    port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--host" && i + 1 < argc)    host = argv[++i];
        else if (a == "--wait-ms" && i + 1 < argc) waitMs = std::atoi (argv[++i]);
        else if (a == "--seconds" && i + 1 < argc) seconds = std::atoi (argv[++i]);
        else if (a == "--eid" && i + 1 < argc)     eidHex = argv[++i];
        else if (a == "--vin" && i + 1 < argc)     vin = argv[++i];
        else if (a == "--status")  askStatus = true;   // M14
        else if (a == "--power")   askPower  = true;   // M14
        else
        {
            std::fprintf (stderr, "不认识的参数：%s\n", a.c_str ());
            return 2;
        }
    }

#if !TOOL_HAS_POSIX
    std::fprintf (stderr, "这个工具需要 POSIX socket（Linux/macOS）。\n");
    return 2;
#else
    EntityConfig cfg;            // 实体身份，想改就改这里

    // ---------------- 实体模式 ----------------
    if (serve)
    {
        UdpDiscoveryServer srv (cfg, port);
        std::string err;
        if (!srv.open (err))
        {
            std::fprintf (stderr, "起不来：%s\n", err.c_str ());
            return 1;
        }
        std::printf ("实体已就位：VIN=%s 逻辑地址=0x%04X 端口=%u\n",
                     cfg.vin.c_str (), cfg.logicalAddress, static_cast<unsigned> (srv.port ()));
        std::printf ("身份：EID=");
        for (auto b : cfg.eid) std::printf ("%02X", b);
        std::printf ("  GID=");
        for (auto b : cfg.gid) std::printf ("%02X", b);
        std::printf ("\n等 %d 秒，期间收到的请求都会打出来...\n\n", seconds);

        // M14：这台"实体"也要回答 0x4001 / 0x4003。
        //   不接的话，同一台机器上 --serve 和 doip-gateway 的行为就不一致，
        //   拿它当参照去测网关就会得出"网关没实现"的错误结论。
        srv.entityStatus = [] () { return entityStatusFromCounts (8, 0, kDefaultMaxPayload); };
        srv.powerMode    = PowerModeInfo{kPowerReady};

        srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };
        srv.runFor (std::chrono::seconds (seconds));

        std::printf ("\n共收到 %zu 个数据报，回了 %zu 个应答。\n", srv.datagrams (), srv.answered ());
        return 0;
    }

    // ---------------- 客户端模式 ----------------
    int fd = ::socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        std::fprintf (stderr, "socket() 失败\n");
        return 1;
    }

    timeval tv;
    tv.tv_sec  = waitMs / 1000;
    tv.tv_usec = (waitMs % 1000) * 1000;
    ::setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

    // 组请求：三种发现请求 + 两种实体自述请求（M14），一次只发一种
    std::vector<std::uint8_t> payload;
    PayloadType type = PayloadType::VehicleIdRequest;
    if (askStatus)
    {
        type = PayloadType::EntityStatusReq;    // 0x4001，载荷必须 0 字节
    }
    else if (askPower)
    {
        type = PayloadType::PowerModeReq;       // 0x4003，载荷必须 0 字节
    }
    else if (!eidHex.empty ())
    {
        if (!hexToBytes (eidHex, payload) || payload.size () != 6)
        {
            std::fprintf (stderr, "--eid 需要 6 字节（12 个十六进制字符），比如 001122334455\n");
            return 2;
        }
        type = PayloadType::VehicleIdRequestEid;
    }
    else if (!vin.empty ())
    {
        if (vin.size () != 17)
        {
            std::fprintf (stderr, "--vin 需要 17 位，现在 %zu 位\n", vin.size ());
            return 2;
        }
        payload.assign (vin.begin (), vin.end ());
        type = PayloadType::VehicleIdRequestVin;
    }
    std::vector<std::uint8_t> reqBytes = build (type, payload);

    sockaddr_in to;
    std::memset (&to, 0, sizeof (to));
    to.sin_family = AF_INET;
    to.sin_port   = htons (port);
    if (broadcast)
    {
        // 发广播要单独开权限位；收广播不用（绑定 0.0.0.0 就行）
        int on = 1;
        ::setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof (on));
        to.sin_addr.s_addr = htonl (INADDR_BROADCAST);
        std::printf ("向 255.255.255.255:%u 广播「%s」\n",
                     static_cast<unsigned> (port), nameOf (type));
    }
    else
    {
        to.sin_addr.s_addr = ::inet_addr (host.c_str ());
        std::printf ("向 %s:%u 单播「%s」\n", host.c_str (),
                     static_cast<unsigned> (port), nameOf (type));
    }

    if (::sendto (fd, reqBytes.data (), reqBytes.size (), 0,
                  reinterpret_cast<sockaddr *> (&to), sizeof (to)) <= 0)
    {
        std::fprintf (stderr, "发不出去\n");
        ::close (fd);
        return 1;
    }

    std::printf ("等 %d ms 的应答...\n", waitMs);
    int count = 0;
    while (true)
    {
        std::uint8_t      buf[1500];
        sockaddr_in       from;
        std::memset (&from, 0, sizeof (from));
        socklen_t         flen = sizeof (from);
        const ssize_t     n = ::recvfrom (fd, buf, sizeof (buf), 0,
                                          reinterpret_cast<sockaddr *> (&from), &flen);
        if (n <= 0) break;    // 超时：没人再答了

        char fromStr[64];
        std::snprintf (fromStr, sizeof (fromStr), "%s:%u", ::inet_ntoa (from.sin_addr),
                       static_cast<unsigned> (ntohs (from.sin_port)));
        std::vector<std::uint8_t> got (buf, buf + n);
        printReply (got, fromStr);
        ++count;
    }
    ::close (fd);

    if (count == 0)
    {
        std::printf ("没有任何应答。可能的原因：\n"
                     "  ① 对面没起（先开一个 doip-discover --serve 或 doip-gateway）\n"
                     "  ② 端口不对（两边 --port 要一致）\n"
                     "  ③ 用了 --broadcast，但虚拟机的 NAT 不转广播 —— 这种情况先用 127.0.0.1 单播验逻辑\n"
                     "  ④ 带了 --eid / --vin，条件不匹配（实体选择沉默，这是对的）\n"
                     "  ⑤ --status / --power 只有实现了 M14 的实体才答；只做发现的实体沉默也是对的\n");
        return 1;
    }
    std::printf ("共收到 %d 个应答。\n", count);
    return 0;
#endif
}
