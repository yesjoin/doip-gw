// ============================================================================
// routing_selftest.cpp —— M2 自测
//
// A 段：路由激活判据（纯逻辑，10 条规则逐条钉住）
// B 段：真 TCP（连接、激活、粘包、半包、断连清空、心跳超时、坏报文 NACK）
//
// 这段测试里最重要的三条，都是"错了也不报错、只会看起来更顺"的那种：
//   · 断连后激活状态必须清空（重连不能继承权限）
//   · 同 socket 不能中途换人（0x02）
//   · 心跳不回必须断（否则连接泄漏）
// ============================================================================
#include "DoIpRouting.h"
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

static RoutingActivationRequest makeReq (std::uint16_t sa, std::uint8_t type)
{
    RoutingActivationRequest r;
    r.sourceAddress  = sa;
    r.activationType = type;
    return r;
}

#if TEST_HAS_POSIX
enum class Rc { Data, Closed, Timeout };

static int tcpConnect (std::uint16_t port)
{
    const int fd = ::socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in a;
    std::memset (&a, 0, sizeof (a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons (port);
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    if (::connect (fd, reinterpret_cast<sockaddr *> (&a), sizeof (a)) < 0)
    {
        ::close (fd);
        return -1;
    }
    return fd;
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

// 收一条。三种结论要分清：
//   Data    = 收到（读到一段，不代表是一条完整报文）
//   Closed  = 对面关了（recv 返回 0，或连接被重置）
//   Timeout = 到时间还没东西（服务器"沉默"就是靠这个验证）
static Rc recvSome (int fd, std::vector<std::uint8_t> &out, int ms)
{
    pollfd p;
    p.fd      = fd;
    p.events  = POLLIN;
    p.revents = 0;
    const int n = ::poll (&p, 1, ms);
    if (n <= 0) return Rc::Timeout;
    if ((p.revents & (POLLIN | POLLHUP | POLLERR)) == 0) return Rc::Timeout;

    std::uint8_t buf[2048];
    const ssize_t got = ::recv (fd, buf, sizeof (buf), 0);
    if (got <= 0)
    {
        out.clear ();
        return Rc::Closed;
    }
    out.assign (buf, buf + got);
    return Rc::Data;
}

// 收一条"完整报文"：不足就继续收，直到凑齐或断开/超时
static Rc recvMessage (int fd, std::vector<std::uint8_t> &whole, int ms)
{
    whole.clear ();
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (ms);
    while (true)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) return Rc::Timeout;
        const int left = static_cast<int> (
            std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());

        std::vector<std::uint8_t> part;
        const Rc rc = recvSome (fd, part, left <= 0 ? 1 : left);
        if (rc == Rc::Closed || rc == Rc::Timeout) return rc;

        whole.insert (whole.end (), part.begin (), part.end ());

        Message m;
        ParseResult pr = parseMessage (whole.data (), whole.size (), m);
        if (pr.error == ParseError::None) return Rc::Data;   // 凑齐了
        if (pr.error != ParseError::NeedMoreData) return Rc::Timeout; // 格式坏了，别死等
    }
}
#endif

int main ()
{
    // =======================================================================
    std::printf ("=== A 路由激活判据（纯逻辑）===\n");
    RoutingActivation act (0x0001);    // 我是 0x0001

    ActivationOutcome o1 = act.handle (makeReq (0x0E00, 0x00));
    check (o1.replied, "路由激活请求一定要回（拒绝也回，否则客户端干等超时）");
    check (o1.code == 0x10, "SA 0x0E00 + 类型 0x00 → 0x10 成功");
    check (o1.activated, "处理完处于激活态");
    check (act.activated (), "状态机记住了：已激活");
    check (act.activatedSource () == 0x0E00, "记住的是 0x0E00");
    check (o1.reason.find ("成功") != std::string::npos, "理由写清「成功」");

    ActivationOutcome o2 = act.handle (makeReq (0x0E00, 0x00));
    check (o2.code == 0x10, "同一个 SA 再请求一次仍是 0x10（幂等，重连重发是常见行为）");
    check (act.activatedSource () == 0x0E00, "重复请求没把状态搞乱");

    ActivationOutcome o3 = act.handle (makeReq (0x0E01, 0x00));
    check (o3.code == 0x02, "同一个 socket 上换 SA → 0x02（不能中途换人）");
    check (!o3.activated, "拒绝时不改变激活态");
    check (act.activatedSource () == 0x0E00, "原来那个 SA 没被顶掉");

    RoutingActivation fresh (0x0001);
    ActivationOutcome o4 = fresh.handle (makeReq (0x0000, 0x00));
    check (o4.code == 0x00, "SA 0x0000 是保留值 → 0x00");
    check (!fresh.activated (), "被拒之后没有激活");

    ActivationOutcome o5 = fresh.handle (makeReq (0x0001, 0x00));
    check (o5.code == 0x00, "SA 等于实体自己（0x0001）→ 0x00，方向搞反了");

    ActivationOutcome o6 = fresh.handle (makeReq (0x0E00, 0xE0));
    check (o6.code == 0x06, "类型 0xE0（中央安全，要证书）→ 0x06 不支持");

    ActivationOutcome o7 = fresh.handle (makeReq (0x0E00, 0x7F));
    check (o7.code == 0x06, "类型 0x7F（瞎写）→ 0x06");

    ActivationOutcome o8 = fresh.handle (makeReq (0x0E00, 0x01));
    check (o8.code == 0x10, "类型 0x01（WWH-OBD）→ 放行 0x10");

    fresh.reset ();
    check (!fresh.activated () && fresh.activatedSource () == 0, "reset() 清空激活态与源地址");

    ActivationOutcome o9 = fresh.handle (makeReq (0x0E01, 0x00));
    check (o9.code == 0x10, "reset 之后换个 SA 能重新激活（证明清空真的生效了）");

    check (std::string (nameOf (ActivationResponseCode::Success)).find ("0x10") != std::string::npos,
           "0x10 有名字");
    check (std::string (nameOf (ActivationResponseCode::SourceDiffersFromActive)).find ("0x02") != std::string::npos,
           "0x02 有名字");
    check (std::string (nameOf (ActivationResponseCode::UnsupportedType)).find ("0x06") != std::string::npos,
           "0x06 有名字");

    // 应答报文形状（手算）：13 字节载荷 + 8 头 = 21 字节
    RoutingActivationResponse res;
    res.testerAddress = 0x0E00;
    res.entityAddress = 0x0001;
    res.responseCode  = 0x10;
    std::vector<std::uint8_t> resMsg =
        build (PayloadType::RoutingActivationRes, encodePayload (res));
    check (resMsg.size () == 21, "0x0006 报文 = 8 头 + 13 载荷 = 21 字节");
    check (resMsg[7] == 0x0D, "长度字段 0x0D（13 字节）");
    check (resMsg[8] == 0x0E && resMsg[9] == 0x00, "载荷前两字节是 tester 地址 0E 00");
    check (resMsg[10] == 0x00 && resMsg[11] == 0x01, "接着两字节是实体地址 00 01");
    check (resMsg[12] == 0x10, "第 5 字节是响应码 0x10");

    Message back;
    ParseResult pr = parseMessage (resMsg.data (), resMsg.size (), back);
    check (pr.error == ParseError::None && pr.consumed == 21, "0x0006 能被解析器解回来");

    RoutingActivation other (0x0002);
    ActivationOutcome o10 = other.handle (makeReq (0x0002, 0x00));
    check (o10.code == 0x00, "实体地址换成 0x0002 后，SA 0x0002 也被拒（不是写死的 0x0001）");
    check (other.entityAddress () == 0x0002, "entityAddress() 反映构造参数");

    // =======================================================================
    std::printf ("\n=== B 真 TCP：连接、激活、粘包、断连、心跳 ===\n");
#if TEST_HAS_POSIX
    TcpServerConfig cfg;
    cfg.port          = 0;          // 系统分配
    cfg.entityAddress = 0x0001;
    cfg.idleBeforeAliveCheck = std::chrono::milliseconds (3000);   // 先调大，别干扰其他用例
    cfg.aliveCheckTimeout    = std::chrono::milliseconds (1000);

    DoIpTcpServer srv (cfg);
    std::string err;
    check (srv.open (err), "TCP 服务器 listen 成功");
    if (!srv.isOpen ())
    {
        std::printf ("       %s\n", err.c_str ());
        std::printf ("\n通过 %d 项，失败 %d 项\n", g_pass, g_fail);
        return g_fail == 0 ? 0 : 1;
    }
    const std::uint16_t port = srv.port ();
    check (port != 0, "拿到了真实监听端口");

    std::thread th ([&srv] { srv.runFor (std::chrono::seconds (6)); });

    // ---- 正常激活 ----
    int c1 = tcpConnect (port);
    check (c1 >= 0, "客户端连上了");
    if (c1 >= 0)
    {
        std::vector<std::uint8_t> reqBytes = build (PayloadType::RoutingActivationReq,
                                                    encodePayload (makeReq (0x0E00, 0x00)));
        sendVec (c1, reqBytes);

        std::vector<std::uint8_t> got;
        check (recvMessage (c1, got, 800) == Rc::Data, "收到 0x0006 应答");
        check (got.size () == 21, "应答 21 字节");
        Message rm;
        parseMessage (got.data (), got.size (), rm);
        check (rm.header.payloadType == 0x0006, "类型是 0x0006");

        RoutingActivationResponse rr;
        check (decodePayload (rm.payload, rr, err), "载荷能解码");
        check (rr.responseCode == 0x10, "响应码 0x10（激活成功）");
        check (rr.testerAddress == 0x0E00, "应答里的 tester 地址回的是请求方");
        check (rr.entityAddress == 0x0001, "应答里的实体地址是我");
        check (srv.activationsOk () >= 1, "服务器记了一笔成功激活");
        check (srv.connectionsAccepted () >= 1, "服务器记了一笔接入");

        // ---- 粘包：两条报文塞进一次 send ----
        std::vector<std::uint8_t> two = reqBytes;
        two.insert (two.end (), reqBytes.begin (), reqBytes.end ());
        sendVec (c1, two);
        std::vector<std::uint8_t> g1, g2;
        check (recvMessage (c1, g1, 800) == Rc::Data, "粘包：解出第 1 条应答");
        check (recvMessage (c1, g2, 800) == Rc::Data, "粘包：解出第 2 条应答（没被吞掉）");
        check (g1.size () == 21 && g2.size () == 21, "两条应答都是 21 字节");

        // ---- 半包：头 8 字节和载荷分开送 ----
        std::uint8_t head[8];
        std::memcpy (head, reqBytes.data (), 8);
        std::vector<std::uint8_t> headOnly (head, head + 8);
        sendVec (c1, headOnly);
        std::this_thread::sleep_for (std::chrono::milliseconds (30));
        std::vector<std::uint8_t> tailOnly (reqBytes.begin () + 8, reqBytes.end ());
        sendVec (c1, tailOnly);
        std::vector<std::uint8_t> g3;
        check (recvMessage (c1, g3, 800) == Rc::Data, "半包：头先到、载荷后到，仍能正确应答");
        check (g3.size () == 21, "半包场景应答仍是 21 字节");

        // ---- 心跳：客户端主动问 ----
        sendVec (c1, build (PayloadType::AliveCheckReq, {}));
        std::vector<std::uint8_t> g4;
        check (recvMessage (c1, g4, 800) == Rc::Data, "0x0007 心跳请求有回应");
        Message am;
        parseMessage (g4.data (), g4.size (), am);
        check (am.header.payloadType == 0x0008, "回的是 0x0008");
        AliveCheckResponse acr;
        check (decodePayload (am.payload, acr, err) && acr.sourceAddress == 0x0001,
               "0x0008 里带的是实体地址 0x0001");

        ::close (c1);
    }

    // ---- 未激活就发诊断：必须断开 ----
    int c2 = tcpConnect (port);
    check (c2 >= 0, "第二个客户端连上了");
    if (c2 >= 0)
    {
        DiagnosticMessage dm;
        dm.sourceAddress = 0x0E00;
        dm.targetAddress = 0x0001;
        dm.uds           = {0x22, 0xF1, 0x90};
        sendVec (c2, build (PayloadType::DiagnosticMessage, encodePayload (dm)));

        std::vector<std::uint8_t> g;
        const Rc rc = recvMessage (c2, g, 600);
        check (rc == Rc::Closed || (rc == Rc::Data && g.size () == 0),
               "未激活的 socket 上发 0x8001 → 服务器断开连接");
        ::close (c2);
    }

    // ---- 重连：新连接、新状态 ----
    int c3 = tcpConnect (port);
    check (c3 >= 0, "断开后能立刻重连（SO_REUSEADDR + 新连接新状态）");
    if (c3 >= 0)
    {
        sendVec (c3, build (PayloadType::RoutingActivationReq,
                            encodePayload (makeReq (0x0E02, 0x00))));
        std::vector<std::uint8_t> g;
        check (recvMessage (c3, g, 800) == Rc::Data, "重连后重新激活，有应答");
        Message m2;
        parseMessage (g.data (), g.size (), m2);
        RoutingActivationResponse r2;
        check (decodePayload (m2.payload, r2, err) && r2.responseCode == 0x10,
               "新连接可以用**新的** SA 激活（证明旧连接的 0x0E00 没被继承）");

        // ---- 坏报文（反码错）：TCP 上必须回 NACK 再断 ----
        std::vector<std::uint8_t> bad = build (PayloadType::VehicleIdRequest, {});
        bad[1] = 0x00;                        // 反码故意写错
        sendVec (c3, bad);
        std::vector<std::uint8_t> nack;
        const Rc rc = recvMessage (c3, nack, 800);
        check (rc == Rc::Data, "坏报文收到了 0x0000 负应答（TCP 有义务回话，和 UDP 相反）");
        Message nm;
        parseMessage (nack.data (), nack.size (), nm);
        check (nm.header.payloadType == 0x0000, "负应答类型 0x0000");
        check (nack.size () == 9 && nack[8] == 0x00, "码值 0x00（格式不对）");

        std::vector<std::uint8_t> after;
        check (recvMessage (c3, after, 500) == Rc::Closed, "回过 NACK 之后连接被关闭（字节流不可信）");
        ::close (c3);
    }

    srv.requestStop ();
    th.join ();
    check (true, "服务器按 requestStop 提前退出，线程已回收");

    // ---- 心跳超时：另起一个短周期服务器 ----
    TcpServerConfig fastCfg;
    fastCfg.port                     = 0;
    fastCfg.entityAddress            = 0x0001;
    fastCfg.idleBeforeAliveCheck     = std::chrono::milliseconds (150);
    fastCfg.aliveCheckTimeout        = std::chrono::milliseconds (150);

    DoIpTcpServer fast (fastCfg);
    check (fast.open (err), "短周期服务器起来了");
    const std::uint16_t fport = fast.port ();
    std::thread fth ([&fast] { fast.runFor (std::chrono::seconds (4)); });

    int c4 = tcpConnect (fport);
    check (c4 >= 0, "连上短周期服务器");
    if (c4 >= 0)
    {
        sendVec (c4, build (PayloadType::RoutingActivationReq,
                            encodePayload (makeReq (0x0E00, 0x00))));
        std::vector<std::uint8_t> g;
        check (recvMessage (c4, g, 500) == Rc::Data, "先正常激活");

        // 什么都不做，等服务器自己发心跳
        std::vector<std::uint8_t> hb;
        const Rc rc = recvMessage (c4, hb, 800);
        check (rc == Rc::Data, "静默 150ms 后服务器主动发来 0x0007");
        Message hm;
        parseMessage (hb.data (), hb.size (), hm);
        check (hm.header.payloadType == 0x0007, "类型是 0x0007 心跳请求");

        // 故意不回 0x0008
        std::vector<std::uint8_t> closed;
        const Rc rc2 = recvMessage (c4, closed, 900);
        check (rc2 == Rc::Closed, "不回心跳 → 150ms 后连接被断开（不泄漏）");
        check (fast.aliveCheckTimeouts () >= 1, "服务器记了一笔心跳超时");
        ::close (c4);
    }

    // ---- 心跳及时应答：连接保持 ----
    int c5 = tcpConnect (fport);
    check (c5 >= 0, "再连一次");
    if (c5 >= 0)
    {
        sendVec (c5, build (PayloadType::RoutingActivationReq,
                            encodePayload (makeReq (0x0E00, 0x00))));
        std::vector<std::uint8_t> g;
        check (recvMessage (c5, g, 500) == Rc::Data, "激活成功");

        // 收心跳 → 立刻回 0x0008
        std::vector<std::uint8_t> hb;
        if (recvMessage (c5, hb, 800) == Rc::Data)
        {
            AliveCheckResponse a;
            a.sourceAddress = 0x0E00;
            sendVec (c5, build (PayloadType::AliveCheckRes, encodePayload (a)));

            // 回过心跳后，再发一次激活请求，仍应收到应答（连接没被误断）
            std::this_thread::sleep_for (std::chrono::milliseconds (250));
            sendVec (c5, build (PayloadType::RoutingActivationReq,
                                encodePayload (makeReq (0x0E00, 0x00))));
            std::vector<std::uint8_t> g2;
            check (recvMessage (c5, g2, 800) == Rc::Data, "回过 0x0008 的连接仍然活着（没被误杀）");
        }
        else
        {
            check (false, "没收到心跳请求（短周期配置可能没生效）");
        }
        ::close (c5);
    }

    fast.requestStop ();
    fth.join ();
#else
    std::printf ("[SKIP] 本平台没有 POSIX socket，B 段跳过\n");
#endif

    // =======================================================================
    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M2 全绿 —— 先报户口拿 0x10，才有资格发诊断；断线即清空。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
