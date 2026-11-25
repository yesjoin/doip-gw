// ============================================================================
// DoIpTcpServer.cpp —— M2 实现
//
// 读这段代码时盯三处：
//   ① handleConn 里的 while + consumed 循环 —— 这就是"粘包"的解法
//   ② dropConn 里那句 routing.reset() —— "激活状态跟连接走"的唯一入口
//   ③ pumpTimers —— 心跳的两个时钟（该发了 / 等超时了）
// ============================================================================
#include "DoIpTcpServer.h"

#if defined (__unix__) || defined (__APPLE__)
#    define DOIP_HAS_POSIX 1
#    include <arpa/inet.h>
#    include <fcntl.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <netinet/tcp.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define DOIP_HAS_POSIX 0
#endif

#include <cstdio>
#include <cstring>

namespace doip
{
namespace
{

std::string hex4 (std::uint16_t v)
{
    char b[16];
    std::snprintf (b, sizeof (b), "0x%04X", static_cast<unsigned> (v));
    return std::string (b);
}

} // namespace

DoIpTcpServer::DoIpTcpServer (const TcpServerConfig &cfg)
    : cfg_ (cfg),
      diag_ (DiagnosticPolicy{cfg.entityAddress, cfg.maxUds, cfg.targetKnown}),
      port_ (cfg.port)
{
}

DoIpTcpServer::~DoIpTcpServer ()
{
    close ();
}

void DoIpTcpServer::log (const std::string &s)
{
    if (logger) logger (s);
}

bool DoIpTcpServer::open (std::string &err)
{
#if DOIP_HAS_POSIX
    close ();

    // M13：把"能同时激活几台 tester"配进账本。
    // 它和 maxConnections 是两个数：连接可以挂着等，激活名额才是稀缺资源。
    registry_.setMaxActive (cfg_.maxActivated);

    listenFd_ = ::socket (AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0)
    {
        err = "socket() 失败";
        return false;
    }

    // SO_REUSEADDR：TIME_WAIT 状态下也能立刻重绑，
    // 不然"刚跑完一轮测试，端口要等 60 秒"会让你以为是代码坏了。
    int one = 1;
    ::setsockopt (listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    sockaddr_in addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons (port_);
    addr.sin_addr.s_addr = htonl (INADDR_ANY);

    if (::bind (listenFd_, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        err = "bind 失败（端口 " + std::to_string (port_) + " 被占用？）";
        close ();
        return false;
    }

    if (::listen (listenFd_, static_cast<int> (cfg_.maxConnections > 4 ? cfg_.maxConnections : 4)) < 0)
    {
        err = "listen() 失败";
        close ();
        return false;
    }

    // listen fd 设成非阻塞：acceptPending 里是 while(true) 循环，
    // 阻塞模式下"没有新连接了"这一步会永久卡在 accept()，整个服务器就死了
    // （M2 第一次跑就是栽在这——客户端连上、服务器一声不响，wchan=inet_csk_accept）。
    // ★ M12：自唤醒管道。广播线程"往队列里塞了一条答案"这件事不是 fd 事件，
    // 睡在 poll 上的 I/O 线程看不见；写一个字节到这个管道，poll 立刻返回。
    if (::pipe (wakeFd_) == 0)
    {
        for (int k = 0; k < 2; ++k)
        {
            const int f = ::fcntl (wakeFd_[k], F_GETFL, 0);
            if (f >= 0) ::fcntl (wakeFd_[k], F_SETFL, f | O_NONBLOCK);   // 写端非阻塞：队列满也不许卡住广播线程
        }
    }

    const int flags = ::fcntl (listenFd_, F_GETFL, 0);
    if (flags >= 0) ::fcntl (listenFd_, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in actual;
    std::memset (&actual, 0, sizeof (actual));
    socklen_t len = sizeof (actual);
    if (::getsockname (listenFd_, reinterpret_cast<sockaddr *> (&actual), &len) == 0)
    {
        port_ = ntohs (actual.sin_port);
    }
    return true;
#else
    err = "本平台没有 POSIX socket，M2 只支持 Linux/macOS";
    return false;
#endif
}

void DoIpTcpServer::close ()
{
#if DOIP_HAS_POSIX
    for (auto &c : conns_)
    {
        if (c.fd >= 0) ::close (c.fd);
        c.fd = -1;
    }
    conns_.clear ();

    if (listenFd_ >= 0)
    {
        ::close (listenFd_);
        listenFd_ = -1;
    }

    for (int k = 0; k < 2; ++k)
    {
        if (wakeFd_[k] >= 0) { ::close (wakeFd_[k]); wakeFd_[k] = -1; }
    }
#endif
}

std::size_t DoIpTcpServer::activeConnections () const
{
    std::size_t n = 0;
    for (const auto &c : conns_) if (c.fd >= 0) ++n;
    return n;
}

bool DoIpTcpServer::sendBytes (int fd, const std::vector<std::uint8_t> &b)
{
#if DOIP_HAS_POSIX
    std::size_t sent = 0;
    while (sent < b.size ())
    {
        const ssize_t n = ::send (fd, b.data () + sent, b.size () - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t> (n);
    }
    return true;
#else
    (void) fd; (void) b;
    return false;
#endif
}

void DoIpTcpServer::acceptPending ()
{
#if DOIP_HAS_POSIX
    while (true)
    {
        sockaddr_in peer;
        std::memset (&peer, 0, sizeof (peer));
        socklen_t plen = sizeof (peer);
        const int fd = ::accept (listenFd_, reinterpret_cast<sockaddr *> (&peer), &plen);
        if (fd < 0) break;

        if (conns_.size () >= cfg_.maxConnections)
        {
            // 超了就直接关，不要"先收下再想办法" —— 那会掩盖容量问题。
            ::close (fd);
            log ("连接数已满（" + std::to_string (cfg_.maxConnections) + "），拒绝新连接");
            continue;
        }

        // ★ M12：TCP_NODELAY。ACK(0x8002) 和紧随其后的第一条答案(0x8001)是两条小报文，
        // 不开这个，Nagle 会把第二条压住等前一条的 ACK —— 40ms 的"延迟确认"就是这么来的。
        // 关掉 Nagle 之后，同样的答案从"43ms 到手"变成"1ms 到手"，而且这部分延迟
        // 根本不是网关的排队，量的时候别把它记在账上。
        {
            int nodelay = 1;
            ::setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof (nodelay));
        }

        Conn c;
        c.id           = nextConnId_++;
        c.fd           = fd;
        c.routing      = RoutingActivation (cfg_.entityAddress);
        c.lastActivity = std::chrono::steady_clock::now ();
        conns_.push_back (c);
        ++accepted_;
        log ("接受连接（第 " + std::to_string (accepted_) + " 个）");
    }
#endif
}

bool DoIpTcpServer::handleConn (Conn &c)
{
#if DOIP_HAS_POSIX
    std::uint8_t buf[4096];
    const ssize_t got = ::recv (c.fd, buf, sizeof (buf), 0);
    if (got <= 0)
    {
        // 0 = 对端正常关闭；<0 = 出错。两种都按"连接结束"处理。
        dropConn (c, got == 0 ? "对端关闭了连接" : "recv 出错");
        return false;
    }

    c.in.insert (c.in.end (), buf, buf + got);
    c.lastActivity = std::chrono::steady_clock::now ();

    // ---- 核心循环：粘包的解药 ----
    // 每次解一条，吃掉 consumed 个字节，剩下的留给下一轮。
    // 判据是 parseMessage 的三种结论：
    //   NeedMoreData → 半包，跳出循环等下次 recv
    //   其它错误     → TCP 上要回 NACK，然后断开（字节流已经不可信了）
    //   None         → 处理掉这条，继续解下一条
    while (!c.in.empty ())
    {
        Message m;
        ParseResult pr = parseMessage (c.in.data (), c.in.size (), m, cfg_.maxPayload);

        if (pr.error == ParseError::NeedMoreData)
        {
            break;                                  // 半包：一个字节都别丢
        }

        if (pr.error != ParseError::None)
        {
            log (std::string ("坏报文（") + nameOf (pr.error) + "）→ 回 0x0000 负应答并断开");
            std::vector<std::uint8_t> nack = buildGenericNack (
                static_cast<GenericNack> (pr.nackCode));
            sendBytes (c.fd, nack);
            dropConn (c, "字节流已不可信");
            return false;
        }

        c.in.erase (c.in.begin (), c.in.begin () + static_cast<std::ptrdiff_t> (pr.consumed));

        const PayloadType t = toType (m.header.payloadType);
        std::string err;

        if (t == PayloadType::RoutingActivationReq)
        {
            RoutingActivationRequest req;
            if (!decodePayload (m.payload, req, err))
            {
                log ("0x0005 载荷长度不对（" + err + "）→ 回 0x0000 负应答并断开");
                std::vector<std::uint8_t> nack = buildGenericNack (GenericNack::InvalidPayloadLength);
                sendBytes (c.fd, nack);
                dropConn (c, "路由激活请求格式不对");
                return false;
            }

            ActivationOutcome out = c.routing.handle (req);

            // ---- M13：连接级判据过了，再做实体级仲裁 ----
            //
            // 顺序不能反：0x02（本 socket 换人）、0x06（类型不支持）、0x00（地址非法）
            // 都是"你这条连接自己有问题"，而 0x03 / 0x01 是"实体这边的情况"。
            // 先把自己判清楚，现场看到 0x03 才知道该去找另一台诊断仪，而不是怀疑自己写错。
            //
            // 实体级否决时，必须把连接级刚置上的激活状态**撤回去**。
            // reset() 是唯一入口（M2 定的规矩），这里也一样，不许直接动 activated_。
            if (out.activated && out.code == static_cast<std::uint8_t> (ActivationResponseCode::Success))
            {
                TesterRegistry::Result reg = registry_.tryRegister (req.sourceAddress, c.id);
                if (!reg.ok)
                {
                    c.routing.reset ();
                    out.activated = false;
                    out.code      = reg.code;
                    out.reason    = reg.reason;
                }
                else
                {
                    out.reason = "源地址 " + hex4 (req.sourceAddress) + " 路由激活成功" +
                                 "（实体已登记 " + std::to_string (registry_.active ()) + "/" +
                                 std::to_string (registry_.maxActive ()) + "）";
                }
            }

            RoutingActivationResponse res;
            res.testerAddress = req.sourceAddress;      // 回谁就问谁
            res.entityAddress = cfg_.entityAddress;     // 我是谁
            res.responseCode  = out.code;
            res.reserved      = 0;
            res.oemSpecific   = 0;

            std::vector<std::uint8_t> bytes =
                build (PayloadType::RoutingActivationRes, encodePayload (res));
            sendBytes (c.fd, bytes);
            log ("0x0005 ← " + hex4 (req.sourceAddress) + "，" + out.reason +
                 " → 回 " + nameOf (static_cast<ActivationResponseCode> (out.code)));

            if (out.activated && out.code == static_cast<std::uint8_t> (ActivationResponseCode::Success))
            {
                ++activations_;
                c.lastActivity = std::chrono::steady_clock::now ();
            }
        }
        else if (t == PayloadType::AliveCheckReq)
        {
            // 客户端问"你还活着吗" → 回我的地址（规范里 0x0008 带的是**应答方**的地址）
            AliveCheckResponse a;
            a.sourceAddress = cfg_.entityAddress;
            sendBytes (c.fd, build (PayloadType::AliveCheckRes, encodePayload (a)));
            log ("0x0007 心跳请求 → 回 0x0008 " + hex4 (cfg_.entityAddress));
        }
        else if (t == PayloadType::AliveCheckRes)
        {
            // 客户端回应了我们的心跳
            c.aliveSent = false;
            log ("0x0008 客户端还活着，停止计时");
        }
        else if (t == PayloadType::DiagnosticMessage)
        {
            ++diagRequests_;
            DiagOutcome o = diag_.handle (m.payload, c.routing.activated (), c.routing.activatedSource ());

            // 载荷连 SA/TA 都读不出：这是"字节流已经不可信"，走 0x0000 0x04 然后断开
            if (o.code == 0 && o.action == DiagAction::Nack)
            {
                log (std::string ("0x8001 结构不对（") + o.reason + "）→ 回 0x0000 0x04 并断开");
                sendBytes (c.fd, buildGenericNack (GenericNack::InvalidPayloadLength));
                dropConn (c, "诊断报文结构不对");
                return false;
            }

            if (o.action == DiagAction::Nack)
            {
                ++diagNacks_;
                DiagnosticNegativeAck na;
                // M6 修正：回执的源地址写**请求里的 TA**，不是实体自己。
                // M5 时两者都是 0x0001，看不出差别；一给两台 ECU 分地址，
                // 第三方客户端立刻拒收 ACK（它按"我发的目标地址"匹配应答源）。
                na.sourceAddress = o.targetAddress;
                na.targetAddress = o.sourceAddress;        // 目标写请求里的源（发起者）
                na.nackCode      = o.code;
                sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
                log ("0x8001 拒绝：0x8003 " + std::string (nameOf (static_cast<DiagNack> (o.code))) +
                     "（" + o.reason + "）");

                // 没激活就发诊断：回了码之后仍然断开 —— 规范上这条连接本来就不该发诊断
                if (!c.routing.activated ())
                {
                    dropConn (c, "未激活就发诊断（已回 0x8003 0x02）");
                    return false;
                }
                continue;
            }

            // ---- 受理：先回 0x8002，再去算业务 ----
            ++diagAcks_;
            DiagnosticPositiveAck pa;
            // 同一条规则：应答源 = 请求目标。这条 ACK 是"代那台 ECU 回的"。
            pa.sourceAddress = o.targetAddress;
            pa.targetAddress = o.sourceAddress;
            pa.ackCode       = 0x00;                      // 唯一值：ACK
            sendBytes (c.fd, build (PayloadType::DiagnosticPositiveAck, encodePayload (pa)));
            log ("0x8001 ← " + hex4 (o.sourceAddress) + "，" + std::to_string (o.uds.size ()) +
                 " 字节 UDS → 回 0x8002 ACK");

            DiagnosticRequest req;
            req.sourceAddress = o.sourceAddress;
            req.targetAddress = o.targetAddress;
            req.uds           = o.uds;

            // ---- M10：异步下游优先 ----
            // 与 M8 的区别：这里**不在这里等结果**，投完就返回 poll 循环。
            // 结果是主循环从 asyncTake 里捞出来的（见 runFor 末尾的 drain）。
            if (asyncSubmit)
            {
                // 同一连接同一时刻只许一条在途：DoIP 没有流水线语义，
                // 硬塞第二条的结果是"两条请求的响应互相冒充"。
                if (c.pendingJob != 0)
                {
                    ++diagNacks_;
                    ++busyRejects_;
                    DiagnosticNegativeAck na;
                    na.sourceAddress = o.targetAddress;
                    na.targetAddress = o.sourceAddress;
                    na.nackCode      = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
                    sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
                    log ("上一条请求还没回（job=" + std::to_string (c.pendingJob) +
                         "），这条当场拒：0x8003 0x08");
                    continue;
                }

                DiagnosticMultiResult immediate;
                const std::uint64_t id = asyncSubmit (req, immediate);

                if (id == 0)
                {
                    ++diagNacks_;
                    DiagnosticNegativeAck na;
                    na.sourceAddress = o.targetAddress;
                    na.targetAddress = o.sourceAddress;
                    na.nackCode      = immediate.nackCode == 0
                                       ? static_cast<std::uint8_t> (DiagNack::TransportProtocolError)
                                       : immediate.nackCode;
                    sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
                    log ("投递当场被拒 → 0x8003：" + immediate.reason);
                    continue;
                }

                c.pendingJob    = id;
                c.pendingSa     = o.sourceAddress;
                c.pendingTarget = o.targetAddress;
                log ("0x8001 已投递（job=" + std::to_string (id) + "，TA=" +
                     hex4 (o.targetAddress) + "），I/O 先回 ACK 不等结果");
                continue;
            }

            // ---- M8：多响应下游（功能寻址）优先 ----
            // 一条请求 → N 条应答，每条都单独一条 0x8001：拼成一条的话，
            // 诊断仪只知道"有人答了"，不知道是几台、各自说了什么。
            if (diagnosticSinkMulti)
            {
                DiagnosticMultiResult mr = diagnosticSinkMulti (req);
                if (!mr.ok)
                {
                    ++diagNacks_;
                    DiagnosticNegativeAck na;
                    na.sourceAddress = o.targetAddress;
                    na.targetAddress = o.sourceAddress;
                    na.nackCode      = mr.nackCode;
                    sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
                    log ("下游拒绝 → 0x8003 " +
                         std::string (nameOf (static_cast<DiagNack> (mr.nackCode))) +
                         "：" + mr.reason);
                    continue;
                }
                for (const auto &rep : mr.replies)
                {
                    DiagnosticMessage back;
                    back.sourceAddress = rep.sourceAddress;   // 谁答的，SA 就是谁
                    back.targetAddress = o.sourceAddress;
                    back.uds           = rep.uds;
                    sendBytes (c.fd, build (PayloadType::DiagnosticMessage, encodePayload (back)));
                    ++diagReplies_;
                }
                log ("下游答了 " + std::to_string (mr.replies.size ()) +
                     " 条（广播）→ 逐条用 0x8001 送回 " + hex4 (o.sourceAddress));
                continue;
            }

            if (!diagnosticSink)
            {
                log ("没有装下游，只回 ACK（M3 允许这样，M4 必须接上 ISO-TP）");
                continue;
            }

            std::vector<std::uint8_t> resp;
            std::string err;
            if (!diagnosticSink (req, resp, err))
            {
                ++diagNacks_;
                DiagnosticNegativeAck na;
                na.sourceAddress = o.targetAddress;
                na.targetAddress = o.sourceAddress;
                na.nackCode      = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
                sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
                log ("下游出错 → 0x8003 0x08：" + err);
                continue;
            }

            DiagnosticMessage back;
            back.sourceAddress = o.targetAddress;      // 响应来自请求的目标（那台 ECU）
            back.targetAddress = o.sourceAddress;
            back.uds           = resp;
            sendBytes (c.fd, build (PayloadType::DiagnosticMessage, encodePayload (back)));
            ++diagReplies_;
            log ("下游答了 " + std::to_string (resp.size ()) + " 字节 → 用 0x8001 送回 " +
                 hex4 (o.sourceAddress));
        }
        else
        {
            log (std::string ("TCP 上收到 ") + nameOf (t) + "，M2 不处理");
        }
    }
    return true;
#else
    (void) c;
    return false;
#endif
}

// ---------------------------------------------------------------------------
// M12：流式交付的两半
//
// 上半 `onStreamReply` 由**广播线程**调（它手里握着所有通道的 busMu）：
// 只许把答案塞进队列，一微秒都不许多待——否则整轮广播被诊断仪的网络拖住。
// 下半 `drainStream` 由 **I/O 线程**每轮 poll 之后调：真正写 socket 的永远只有它。
// 这就是"一条总线一个主人、一个 socket 一个主人"的延续，而不是新发明。
// ---------------------------------------------------------------------------
void DoIpTcpServer::wakeIo ()
{
    if (wakeFd_[1] < 0) return;
    const char one = 1;
    // 必须接住返回值：glibc 给 write() 标了 warn_unused_result，
    // （void）强转在 -O0 下放过，-O2 一编就红 —— ci_local 故意用 -O2 就是这个原因。
    const ssize_t wr = ::write (wakeFd_[1], &one, 1);
    (void) wr;   // 非阻塞；管道满了（EAGAIN）也无所谓，反正已经有一次"醒着"
}

void DoIpTcpServer::onStreamReply (std::uint64_t jobId, const DiagnosticReply &rep)
{
    {
        std::lock_guard<std::mutex> g (streamMu_);
        streamQ_.push_back (PendingStream{jobId, rep});
    }
    wakeIo ();   // 叫醒 I/O 线程：这条答案别等 poll 自己超时
}

void DoIpTcpServer::drainStream ()
{
    std::vector<PendingStream> taken;
    {
        std::lock_guard<std::mutex> g (streamMu_);
        taken.swap (streamQ_);          // 拿锁只做交换，send 全在锁外做
    }

    for (const auto &ps : taken)
    {
        bool delivered = false;
        for (auto &c : conns_)
        {
            if (c.fd < 0 || c.pendingJob != ps.jobId) continue;

            DiagnosticMessage back;
            back.sourceAddress = ps.reply.sourceAddress;   // 谁答的，SA 就写谁
            back.targetAddress = c.pendingSa;
            back.uds           = ps.reply.uds;
            delivered = sendBytes (c.fd, build (PayloadType::DiagnosticMessage, encodePayload (back)));
            if (delivered)
            {
                ++streamed_;
                ++diagReplies_;
                ledger_.noteStreamed (ps.jobId);   // 交卷时要靠它知道"别再发一遍"
                log ("job=" + std::to_string (ps.jobId) + " 流式送达 1 条（SA=" +
                     hex4 (ps.reply.sourceAddress) + "），不等其他通道");
            }
            break;
        }
        if (!delivered)
        {
            ++streamDropped_;
            log ("job=" + std::to_string (ps.jobId) +
                 " 流式送达时连接已断/发送失败 → 丢弃（不转给下一个诊断仪）");
        }
    }
}

// ---------------------------------------------------------------------------
// M10：结果回家
//
// 找的是 **jobId**，不是"最后一条请求的连接"。这两者在小规模测试里看不出差别，
// 但两条连接一问一答交错时，"最后一条"就是错的——这正是"串包"在以太网侧的样子。
// 找不到连接 = 连接已经断了：结果必须丢，并记 orphanResults_。
// ---------------------------------------------------------------------------
void DoIpTcpServer::deliver (const AsyncResult &res)
{
    for (auto &c : conns_)
    {
        if (c.fd < 0 || c.pendingJob != res.jobId) continue;

        const std::uint16_t testerSa  = c.pendingSa;
        const std::uint16_t targetEcu = c.pendingTarget;
        c.pendingJob    = 0;
        c.pendingSa     = 0;
        c.pendingTarget = 0;

        if (!res.r.ok)
        {
            ledger_.forget (res.jobId);   // 失败的 job 也可能流过一部分（部分通道答了），账要销
            ++diagNacks_;
            DiagnosticNegativeAck na;
            na.sourceAddress = targetEcu;             // 回执的源 = 请求里的 TA（和 ACK 的规矩一致）
            na.targetAddress = testerSa;
            na.nackCode      = res.r.nackCode == 0
                               ? static_cast<std::uint8_t> (DiagNack::TransportProtocolError)
                               : res.r.nackCode;
            sendBytes (c.fd, build (PayloadType::DiagnosticNegativeAck, encodePayload (na)));
            log ("job=" + std::to_string (res.jobId) + " 失败 → 0x8003：" + res.r.reason);
            return;
        }

        // ★ M12：已经流式发出去的那几条不能再发一遍。
        //   交卷时 replies 里是**全部**答案，流式发过的是最前面的 already 条
        //   （广播按通道顺序收、按通道顺序外发，两边顺序一致）。
        const std::size_t total   = res.r.replies.size ();
        const std::size_t already = ledger_.streamed (res.jobId);
        ledger_.forget (res.jobId);

        std::size_t sent = 0;
        for (std::size_t i = (already < total ? already : total); i < total; ++i)
        {
            const auto &rep = res.r.replies[i];
            DiagnosticMessage back;
            back.sourceAddress = rep.sourceAddress;   // 谁答的，SA 就是谁
            back.targetAddress = testerSa;
            back.uds           = rep.uds;
            sendBytes (c.fd, build (PayloadType::DiagnosticMessage, encodePayload (back)));
            ++diagReplies_;
            ++sent;
        }
        log ("job=" + std::to_string (res.jobId) + " 回来 " +
             std::to_string (total) + " 条（流式已发 " + std::to_string (already) +
             " 条）→ 补齐 " + std::to_string (sent) + " 条");
        return;
    }

    ++orphanResults_;
    log ("job=" + std::to_string (res.jobId) +
         " 回来时找不到连接（已断开）→ 结果丢弃，不转给下一个诊断仪");
}

void DoIpTcpServer::dropConn (Conn &c, const std::string &why)
{
#if DOIP_HAS_POSIX
    if (c.fd >= 0)
    {
        ::close (c.fd);
        c.fd = -1;
    }
    // M10：断开时在途请求要作废。
    //   不作废的话，这条结果会留在交卷台上，等下一个诊断仪来"接住"它——
    //   在以太网侧这就是把别人的答案递给下一个人，和 M5 的"迟到帧"是同一类错。
    if (c.pendingJob != 0)
    {
        if (asyncAbandon) asyncAbandon (c.pendingJob);
        ledger_.forget (c.pendingJob);   // M12：这个 job 的流式账也一起销，迟到答案不许再发
        log ("连接断开时还有在途请求 job=" + std::to_string (c.pendingJob) + " → 已作废");
        c.pendingJob    = 0;
        c.pendingSa     = 0;
        c.pendingTarget = 0;
    }

    // ★ 唯一的状态清空入口。
    // 漏了这一句，"TCP 断了但激活状态还在"，重连就能直接发诊断 ——
    // 看起来更顺，实际是权限被继承。
    c.routing.reset ();
    // M13：实体级的地址也要还回去，否则这个地址永远"在别人的名下"，
    // 下一位 tester 拿同一个地址会一直吃 0x03 —— 地址泄漏比内存泄漏更难查。
    registry_.release (c.id);
    c.in.clear ();
    c.aliveSent = false;
    log ("关闭连接：" + why);
#else
    (void) c; (void) why;
#endif
}

void DoIpTcpServer::pumpTimers (std::chrono::steady_clock::time_point now)
{
    for (auto &c : conns_)
    {
        if (c.fd < 0) continue;
        if (!c.routing.activated ()) continue;      // 未激活的连接不做心跳

        if (!c.aliveSent)
        {
            if (now - c.lastActivity > cfg_.idleBeforeAliveCheck)
            {
                // 静默太久：主动问一句
                c.aliveSent     = true;
                c.aliveDeadline = now + cfg_.aliveCheckTimeout;
                sendBytes (c.fd, build (PayloadType::AliveCheckReq, {}));
                log ("静默超过 " + std::to_string (cfg_.idleBeforeAliveCheck.count ()) +
                     "ms → 发 0x0007 心跳请求，等 " +
                     std::to_string (cfg_.aliveCheckTimeout.count ()) + "ms");
            }
        }
        else if (now > c.aliveDeadline)
        {
            ++aliveTimeouts_;
            dropConn (c, "心跳超时（发过 0x0007 但没收到 0x0008）");
        }
    }
}

void DoIpTcpServer::runFor (std::chrono::milliseconds dur)
{
#if DOIP_HAS_POSIX
    if (listenFd_ < 0) return;

    const auto deadline = std::chrono::steady_clock::now () + dur;
    stop_ = false;

    while (!stop_)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) break;

        auto left = std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now);
        if (left > std::chrono::milliseconds (100)) left = std::chrono::milliseconds (100);

        // 把 listen fd 和所有连接 fd 一起丢进 poll。
        // 同时记一份"第 j 个 fd 对应 conns_ 里的哪个下标" ——
        // 不能事后靠顺序去猜，一旦 accept 插进来新连接，猜法就错位了。
        std::vector<pollfd>      fds;
        std::vector<std::size_t> owner;
        fds.push_back (pollfd{listenFd_, POLLIN, 0});
        owner.push_back (conns_.size ());          // 用 size() 当"这是 listen fd / 唤醒管道"的哨兵
        const bool hasWake = wakeFd_[0] >= 0;
        if (hasWake)
        {
            fds.push_back (pollfd{wakeFd_[0], POLLIN, 0});
            owner.push_back (conns_.size ());      // 同上：哨兵，循环里单独处理
        }
        for (std::size_t i = 0; i < conns_.size (); ++i)
        {
            if (conns_[i].fd < 0) continue;
            fds.push_back (pollfd{conns_[i].fd, POLLIN, 0});
            owner.push_back (i);
        }

        const int n = ::poll (fds.data (), fds.size (), static_cast<int> (left.count ()));
        if (n > 0)
        {
            if ((fds[0].revents & POLLIN) != 0) acceptPending ();

            if (hasWake && (fds[1].revents & POLLIN) != 0)
            {
                // 必须读空：不读空 poll 下一轮会一直报"可读"，变成忙等。
                char buf[64];
                while (::read (wakeFd_[0], buf, sizeof (buf)) > 0) {}
            }

            for (std::size_t j = (hasWake ? 2 : 1); j < fds.size (); ++j)
            {
                if ((fds[j].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
                if (owner[j] >= conns_.size ()) continue;
                if (conns_[owner[j]].fd < 0) continue;
                handleConn (conns_[owner[j]]);
            }
        }

        pumpTimers (std::chrono::steady_clock::now ());

        // ★ M12：先把"边到边"的答案放出去，再去捞整轮的结果。
        //   顺序有意：一条答案在广播还没结束时就应该到诊断仪手里，
        //   放到 asyncTake 后面等于又攒了一轮（最慢那台说了算）。
        drainStream ();

        // ★ M10：把已经完成的 CAN 结果送回各自的连接。
        //   放在 poll 之后的每一轮都做一次，而不是"等到有事件才做"——
        //   结果到达不会唤醒 poll（它不是 fd 事件），不主动捞就会一直躺在交卷台上。
        if (asyncTake)
        {
            AsyncResult ar;
            while (asyncTake (ar)) deliver (ar);
        }

        // 清理已关闭的连接
        for (std::size_t i = conns_.size (); i > 0; --i)
        {
            if (conns_[i - 1].fd < 0) conns_.erase (conns_.begin () + static_cast<std::ptrdiff_t> (i - 1));
        }
    }
#endif
}

} // namespace doip
