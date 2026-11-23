// ============================================================================
// diagnostic_selftest.cpp —— M3 自测
//
// A 段：判定逻辑（未激活 / 冒用地址 / 目标不认识 / 超长 / 正常）
// B 段：真 TCP 上跑一遍完整链路（0x8001 → 0x8002 → 0x8001 响应）
//
// 这里用了一个"带缓冲的客户端"（Client::recvMsg）：
//   因为服务器会把 0x8002 和 0x8001 响应连着发出去，
//   一次 recv 可能同时收到两条 —— 只看第一条、把剩下的扔掉，
//   就会出现"偶发收不到响应"。这类 bug 在自测里必须复现得出来。
// ============================================================================
#include "DoIpDiagnostic.h"
#include "DoIpTcpServer.h"

#if defined (__unix__) || defined (__APPLE__)
#    define TEST_HAS_POSIX 1
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define TEST_HAS_POSIX 0
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace doip;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond)
    {
        std::printf ("[PASS] %s\n", what.c_str ());
        ++g_pass;
    }
    else
    {
        std::printf ("[FAIL] %s\n", what.c_str ());
        ++g_fail;
    }
}

// 造一条 0x8001 的载荷：SA(2) + TA(2) + UDS
static std::vector<std::uint8_t> diagPayload (std::uint16_t sa, std::uint16_t ta,
                                              const std::vector<std::uint8_t> &uds)
{
    std::vector<std::uint8_t> p;
    p.push_back (static_cast<std::uint8_t> (sa >> 8));
    p.push_back (static_cast<std::uint8_t> (sa & 0xFF));
    p.push_back (static_cast<std::uint8_t> (ta >> 8));
    p.push_back (static_cast<std::uint8_t> (ta & 0xFF));
    p.insert (p.end (), uds.begin (), uds.end ());
    return p;
}

#if TEST_HAS_POSIX
struct Client
{
    int                       fd = -1;
    std::vector<std::uint8_t> buf;       // 已收到但还没消费的字节

    bool connectTo (std::uint16_t port)
    {
        fd = ::socket (AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        sockaddr_in a;
        std::memset (&a, 0, sizeof (a));
        a.sin_family      = AF_INET;
        a.sin_port        = htons (port);
        a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
        if (::connect (fd, reinterpret_cast<sockaddr *> (&a), sizeof (a)) < 0)
        {
            ::close (fd);
            fd = -1;
            return false;
        }
        return true;
    }

    bool send (const std::vector<std::uint8_t> &b)
    {
        std::size_t done = 0;
        while (done < b.size ())
        {
            const ssize_t n = ::send (fd, b.data () + done, b.size () - done, 0);
            if (n <= 0) return false;
            done += static_cast<std::size_t> (n);
        }
        return true;
    }

    // 从缓冲里拿一条完整报文；没有就再 recv，直到凑齐/超时/断开
    bool recvMsg (Message &out, int ms)
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
            if (pr.error != ParseError::NeedMoreData) return false;

            const auto now = std::chrono::steady_clock::now ();
            if (now >= deadline) return false;
            const int left = static_cast<int> (
                std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());

            pollfd p;
            p.fd      = fd;
            p.events  = POLLIN;
            p.revents = 0;
            if (::poll (&p, 1, left <= 0 ? 1 : left) <= 0) return false;

            std::uint8_t tmp[2048];
            const ssize_t got = ::recv (fd, tmp, sizeof (tmp), 0);
            if (got <= 0) return false;
            buf.insert (buf.end (), tmp, tmp + got);
        }
    }

    // 收一条"不是某类型"的报文（用来确认连接被关而不是悄悄沉默）
    bool closedWithin (int ms)
    {
        const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (ms);
        while (true)
        {
            const auto now = std::chrono::steady_clock::now ();
            if (now >= deadline) return false;
            pollfd p;
            p.fd      = fd;
            p.events  = POLLIN;
            p.revents = 0;
            const int left = static_cast<int> (
                std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());
            if (::poll (&p, 1, left <= 0 ? 1 : left) <= 0) return false;

            std::uint8_t tmp[1024];
            const ssize_t got = ::recv (fd, tmp, sizeof (tmp), 0);
            if (got <= 0) return true;          // 0 = 对面关了，<0 = 出错，都算"连接结束"
            buf.insert (buf.end (), tmp, tmp + got);
        }
    }

    void closeIt ()
    {
        if (fd >= 0) ::close (fd);
        fd = -1;
        buf.clear ();
    }
};
#endif

int main ()
{
    // =======================================================================
    std::printf ("=== A 诊断通道判定（纯逻辑）===\n");
    DiagnosticPolicy pol;
    pol.entityAddress = 0x0001;
    pol.maxUds        = 8;            // 故意调很小，好测"超长"
    DiagnosticChannel ch (pol);

    // 未激活
    DiagOutcome o1 = ch.handle (diagPayload (0x0E00, 0x0001, {0x22, 0xF1, 0x86}), false, 0);
    check (o1.action == DiagAction::Nack, "未激活 → Nack");
    check (o1.code == 0x02, "未激活 → 0x8003 0x02（源地址不在连接表里）");
    check (o1.reason.find ("激活") != std::string::npos, "理由写清了「没激活」");

    // 结构不足 4 字节
    DiagOutcome o2 = ch.handle ({0x0E, 0x00, 0x00}, true, 0x0E00);
    check (o2.action == DiagAction::Nack, "载荷 3 字节 → Nack");
    check (o2.code == 0x00, "结构不对时 code=0，交给服务器走 0x0000 0x04");

    // 刚好 4 字节：UDS 为空，通道不拦（空 UDS 该由 UDS 层回 7F，不该由 DoIP 层猜）
    DiagOutcome o3 = ch.handle ({0x0E, 0x00, 0x00, 0x01}, true, 0x0E00);
    check (o3.action == DiagAction::AckAndForward, "UDS 为空也放行（UDS 语义归 ECU）");
    check (o3.uds.empty (), "切出来的 UDS 确实是空的");

    // 正常
    DiagOutcome o4 = ch.handle (diagPayload (0x0E00, 0x0001, {0x22, 0xF1, 0x86}), true, 0x0E00);
    check (o4.action == DiagAction::AckAndForward, "正常请求 → 受理");
    check (o4.code == 0x00, "0x8002 的码只有 0x00");
    check (o4.sourceAddress == 0x0E00 && o4.targetAddress == 0x0001, "SA/TA 解析正确（大端）");
    check (o4.uds.size () == 3 && o4.uds[0] == 0x22 && o4.uds[2] == 0x86, "UDS 字节原样切出");

    // 冒用源地址
    DiagOutcome o5 = ch.handle (diagPayload (0x0E01, 0x0001, {0x22, 0xF1, 0x86}), true, 0x0E00);
    check (o5.code == 0x02, "SA 不是这条连接激活的那个 → 0x02");
    check (o5.sourceAddress == 0x0E01, "拒绝时仍把请求里的 SA 带出来（日志用）");

    // 目标不是我
    DiagOutcome o6 = ch.handle (diagPayload (0x0E00, 0x0002, {0x3E, 0x00}), true, 0x0E00);
    check (o6.code == 0x03, "TA 不认识 → 0x03");
    check (o6.targetAddress == 0x0002, "拒绝时报的是请求里的 TA");

    // 超长
    std::vector<std::uint8_t> big (9, 0xAA);
    big[0] = 0x22;
    DiagOutcome o7 = ch.handle (diagPayload (0x0E00, 0x0001, big), true, 0x0E00);
    check (o7.code == 0x04, "9 字节 > 上限 8 → 0x04");

    std::vector<std::uint8_t> exact (8, 0xAA);
    exact[0] = 0x22;
    DiagOutcome o8 = ch.handle (diagPayload (0x0E00, 0x0001, exact), true, 0x0E00);
    check (o8.action == DiagAction::AckAndForward, "正好等于上限 → 放行（边界是 > 才拒）");

    // 码值名字
    check (std::string (nameOf (DiagNack::InvalidSourceAddress)).find ("0x02") != std::string::npos,
           "0x02 有名字");
    check (std::string (nameOf (DiagNack::UnknownTargetAddress)).find ("0x03") != std::string::npos,
           "0x03 有名字");
    check (std::string (nameOf (DiagNack::MessageTooLarge)).find ("0x04") != std::string::npos,
           "0x04 有名字");
    check (std::string (nameOf (DiagNack::TransportProtocolError)).find ("0x08") != std::string::npos,
           "0x08 有名字");

    // 回执报文形状：0x8002 / 0x8003 都是 8 头 + 5 载荷 = 13 字节
    DiagnosticPositiveAck pa;
    pa.sourceAddress = 0x0001;
    pa.targetAddress = 0x0E00;
    pa.ackCode       = 0x00;
    std::vector<std::uint8_t> ackBytes = build (PayloadType::DiagnosticPositiveAck, encodePayload (pa));
    check (ackBytes.size () == 13, "0x8002 = 8 + 5 = 13 字节");
    check (ackBytes[8] == 0x00 && ackBytes[9] == 0x01, "0x8002 载荷前两字节是 SA=00 01");
    check (ackBytes[10] == 0x0E && ackBytes[11] == 0x00, "接着是 TA=0E 00");
    check (ackBytes[12] == 0x00, "第 5 字节是 ack code 0x00");

    DiagnosticNegativeAck na;
    na.sourceAddress = 0x0001;
    na.targetAddress = 0x0E00;
    na.nackCode      = 0x03;
    std::vector<std::uint8_t> nackBytes = build (PayloadType::DiagnosticNegativeAck, encodePayload (na));
    check (nackBytes.size () == 13, "0x8003 = 8 + 5 = 13 字节");
    check (nackBytes[12] == 0x03, "第 5 字节是 nack code 0x03");

    // 假 ECU
    DiagnosticRequest r1;
    r1.uds = {0x3E, 0x00};
    std::vector<std::uint8_t> resp;
    std::string err;
    check (stubEcuAnswer (r1, resp, err) && resp.size () == 2 && resp[0] == 0x7E && resp[1] == 0x00,
           "假 ECU：3E 00 → 7E 00");

    DiagnosticRequest r2;
    r2.uds = {0x22, 0xF1, 0x86};
    check (stubEcuAnswer (r2, resp, err) && resp.size () == 4 && resp[0] == 0x62 && resp[3] == 0x01,
           "假 ECU：22 F1 86 → 62 F1 86 01（和项目一同一答案）");

    DiagnosticRequest r3;
    r3.uds = {0x22, 0xF1, 0x90};
    check (stubEcuAnswer (r3, resp, err) && resp.size () == 3 && resp[0] == 0x7F && resp[2] == 0x31,
           "假 ECU：不认识的 DID → 7F 22 31");

    DiagnosticRequest r4;
    check (!stubEcuAnswer (r4, resp, err), "假 ECU：空 UDS → 返回 false（不猜）");

    // =======================================================================
    std::printf ("\n=== B 真 TCP：0x8001 → 0x8002 → 0x8001 响应 ===\n");
#if TEST_HAS_POSIX
    TcpServerConfig cfg;
    cfg.port             = 0;
    cfg.entityAddress    = 0x0001;
    cfg.maxUds           = 64;                          // 40 字节要能过，65 字节要拒
    cfg.idleBeforeAliveCheck = std::chrono::milliseconds (5000);

    DoIpTcpServer srv (cfg);
    std::string openErr;
    check (srv.open (openErr), "TCP 服务器起来了");

    // 装假 ECU；顺手让 0x31 开头的请求返回失败，用来验 0x8003 0x08
    srv.diagnosticSink = [] (const DiagnosticRequest &req,
                             std::vector<std::uint8_t> &out,
                             std::string &e) -> bool {
        if (req.uds.size () >= 1 && req.uds[0] == 0x31)
        {
            e = "假故障：故意让下游报传输层错误";
            return false;
        }
        return stubEcuAnswer (req, out, e);
    };

    const std::uint16_t port = srv.port ();
    std::thread th ([&srv] { srv.runFor (std::chrono::seconds (8)); });

    Client c;
    check (c.connectTo (port), "客户端连上");
    if (c.fd >= 0)
    {
        // 激活
        RoutingActivationRequest ar;
        ar.sourceAddress  = 0x0E00;
        ar.activationType = 0x00;
        c.send (build (PayloadType::RoutingActivationReq, encodePayload (ar)));

        Message m;
        check (c.recvMsg (m, 800), "激活有应答");
        RoutingActivationResponse rr;
        check (decodePayload (m.payload, rr, openErr) && rr.responseCode == 0x10, "激活码 0x10");

        // ---- 正常诊断 ----
        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E00, 0x0001, {0x22, 0xF1, 0x86})));
        Message ack;
        check (c.recvMsg (ack, 800), "收到 0x8002 应答");
        check (ack.header.payloadType == 0x8002, "第一条回来的是 ACK（先回执再算业务）");
        DiagnosticPositiveAck pa2;
        check (decodePayload (ack.payload, pa2, openErr), "ACK 载荷能解码");
        check (pa2.sourceAddress == 0x0001 && pa2.targetAddress == 0x0E00, "ACK 里 SA=实体, TA=tester");
        check (pa2.ackCode == 0x00, "ack code 0x00");

        Message resp;
        check (c.recvMsg (resp, 800), "随后收到 0x8001 响应");
        check (resp.header.payloadType == 0x8001, "响应类型是 0x8001");
        DiagnosticMessage dresp;
        check (decodePayload (resp.payload, dresp, openErr), "响应载荷能解码");
        check (dresp.sourceAddress == 0x0001 && dresp.targetAddress == 0x0E00, "响应 SA=实体, TA=tester");
        check (dresp.uds.size () == 4 && dresp.uds[0] == 0x62 && dresp.uds[3] == 0x01,
               "UDS 应答就是假 ECU 给的 62 F1 86 01");
        check (srv.diagnosticRequests () >= 1 && srv.diagnosticAcks () >= 1, "服务器统计：请求/ACK 各记一笔");

        // ---- 3E 00 ----
        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E00, 0x0001, {0x3E, 0x00})));
        Message a2, r2m;
        check (c.recvMsg (a2, 800) && a2.header.payloadType == 0x8002, "3E 00 也有 ACK");
        check (c.recvMsg (r2m, 800) && r2m.header.payloadType == 0x8001, "3E 00 有响应");
        DiagnosticMessage d2;
        check (decodePayload (r2m.payload, d2, openErr) && d2.uds.size () == 2 && d2.uds[0] == 0x7E,
               "3E 00 → 7E 00");

        // ---- 冒用地址：拒绝但连接还在 ----
        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E01, 0x0001, {0x22, 0xF1, 0x86})));
        Message n1;
        check (c.recvMsg (n1, 800), "冒用地址收到应答（不是沉默）");
        check (n1.header.payloadType == 0x8003, "回的是 0x8003");
        DiagnosticNegativeAck na2;
        check (decodePayload (n1.payload, na2, openErr) && na2.nackCode == 0x02, "码值 0x02");

        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E00, 0x0001, {0x22, 0xF1, 0x86})));
        Message a3;
        check (c.recvMsg (a3, 800) && a3.header.payloadType == 0x8002,
               "拒绝之后连接还能继续用（0x8003 不等于断线）");

        Message r3m;
        c.recvMsg (r3m, 800);   // 吃掉这次正常请求的响应，别污染后面的判断

        // ---- 目标不是我 ----
        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E00, 0x0002, {0x3E, 0x00})));
        Message n2;
        check (c.recvMsg (n2, 800) && n2.header.payloadType == 0x8003, "目标不认识 → 0x8003");
        DiagnosticNegativeAck na3;
        check (decodePayload (n2.payload, na3, openErr) && na3.nackCode == 0x03, "码值 0x03");

        // ---- 超长：65 字节 > 64 ----
        std::vector<std::uint8_t> tooBig (65, 0xAA);
        tooBig[0] = 0x22;
        c.send (build (PayloadType::DiagnosticMessage, diagPayload (0x0E00, 0x0001, tooBig)));
        Message n3;
        check (c.recvMsg (n3, 800) && n3.header.payloadType == 0x8003, "超长 → 0x8003");
        DiagnosticNegativeAck na4;
        check (decodePayload (n3.payload, na4, openErr) && na4.nackCode == 0x04, "码值 0x04");

        // ---- 40 字节：DoIP 层不该嫌大（拆帧是 M4 的事） ----
        std::vector<std::uint8_t> forty (40, 0x5A);
        forty[0] = 0x22;
        c.send (build (PayloadType::DiagnosticMessage, diagPayload (0x0E00, 0x0001, forty)));
        Message a4;
        check (c.recvMsg (a4, 800) && a4.header.payloadType == 0x8002,
               "40 字节请求在 DoIP 层被受理（大小不是这一层的门槛）");
        Message r4m;
        check (c.recvMsg (r4m, 800) && r4m.header.payloadType == 0x8001, "40 字节请求也有响应");
        DiagnosticMessage d4;
        check (decodePayload (r4m.payload, d4, openErr) && d4.uds[0] == 0x7F,
               "假 ECU 对 22 xx 未知 DID 回 7F 22 31");

        // ---- 下游失败 → 0x8003 0x08 ----
        c.send (build (PayloadType::DiagnosticMessage,
                       diagPayload (0x0E00, 0x0001, {0x31, 0x01, 0x02})));
        Message a5, n4;
        check (c.recvMsg (a5, 800) && a5.header.payloadType == 0x8002, "先收到 ACK");
        check (c.recvMsg (n4, 800) && n4.header.payloadType == 0x8003, "下游失败 → 0x8003");
        DiagnosticNegativeAck na5;
        check (decodePayload (n4.payload, na5, openErr) && na5.nackCode == 0x08, "码值 0x08（传输层错误）");
        check (srv.diagnosticNacks () >= 3, "统计里 NACK 累加（0x02/0x03/0x04/0x08 都算）");

        // ---- 载荷不足 4 字节 → 0x0000 0x04 并断开 ----
        c.send (build (PayloadType::DiagnosticMessage, {0x0E, 0x00, 0x00}));
        Message g1;
        check (c.recvMsg (g1, 800), "结构不对收到 0x0000");
        check (g1.header.payloadType == 0x0000, "类型是通用头负应答");
        check (g1.payload.size () == 1 && g1.payload[0] == 0x04, "码值 0x04（长度不符）");
        check (c.closedWithin (600), "随后连接被关闭（字节流不可信）");
        c.closeIt ();
    }

    // ---- 未激活就发诊断：回 0x8003 0x02 再断（M2 是直接断，M3 补上了码值）----
    Client c2;
    check (c2.connectTo (port), "第二个客户端连上");
    if (c2.fd >= 0)
    {
        c2.send (build (PayloadType::DiagnosticMessage,
                        diagPayload (0x0E00, 0x0001, {0x3E, 0x00})));
        Message n6;
        check (c2.recvMsg (n6, 800), "未激活发诊断也收到应答");
        check (n6.header.payloadType == 0x8003, "回 0x8003（不是装作没看见）");
        DiagnosticNegativeAck na6;
        check (decodePayload (n6.payload, na6, openErr) && na6.nackCode == 0x02, "码值 0x02");
        check (c2.closedWithin (600), "回过 NACK 后断开（非法序列不留活口）");
        c2.closeIt ();
    }

    srv.requestStop ();
    th.join ();
#else
    std::printf ("[SKIP] 本平台没有 POSIX socket\n");
#endif

    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M3 全绿 —— 收下、验名、回执、交给下游，再把答案送回去。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
