#pragma once
// ============================================================================
// DoIpTcpServer.h —— M2 TCP 连接 → M10 "I/O 线程永不等 CAN"
//
// 这一层干三件事：
//   ① 收连接、收字节、把字节拼成完整报文（TCP 会粘包也会半包）
//   ② 把 0x0005 交给 DoIpRouting（状态机在那里）并把结论组回 0x0006
//   ③ 心跳：静默太久发 0x0007，限时收不到 0x0008 就断开
//
// 和 M1 的 UDP 有一个关键区别：
//   **TCP 上收到坏报文要回 0x0000 负应答，然后断开。**
//   因为 TCP 是有连接的，对面在等你说话；UDP 上没有这层义务（还要避免广播风暴）。
//
// ★ M10 的两条新约定：
//   ① "受理"和"答复"可以分两次：0x8002 ACK 立刻回，0x8001 响应等 CAN 回来再回。
//      实现上就是每条连接记一个 `pendingJob`（0 = 没有在途请求），
//      再加上一条"同一连接同一时刻只许一条在途"的规矩（DoIP 没有流水线语义）。
//   ② 结果从哪来：`asyncTake` 每轮 poll 之后被调用一次，把已完成的结果交进来；
//      服务器只按 jobId 找连接，找不到（连接已断）就**丢弃并记账**，绝不转给下一个诊断仪。
//      这条规矩和 M5 的"迟到帧丢弃"是同一件事的以太网版本。
// ============================================================================
#include "DoIpCodec.h"
#include "DoIpDiagnostic.h"
#include "DoIpRouting.h"
#include "StreamLedger.h"   // M12：边收边发的记账（纯逻辑）

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace doip
{

struct TcpServerConfig
{
    std::uint16_t port             = 13400;   // 0 = 系统分配（自测用）
    std::uint16_t entityAddress    = 0x0001;
    std::size_t   maxConnections   = 4;
    std::uint32_t maxPayload       = kDefaultMaxPayload;
    std::size_t   maxUds           = 512;     // 单条诊断的 UDS 上限（超过 → 0x8003 0x04）

    // M6：谁能当诊断目标。为空 = 只认 entityAddress 自己（M3 语义）。
    std::function<bool (std::uint16_t)> targetKnown;

    // 心跳：激活后静默超过 idleBeforeAliveCheck → 发 0x0007；
    //       发出去后 aliveCheckTimeout 内没收到 0x0008 → 断开。
    std::chrono::milliseconds idleBeforeAliveCheck{2000};
    std::chrono::milliseconds aliveCheckTimeout{1000};
};

// 一条"回来的结果"：jobId 用来找连接，其余是结论
struct AsyncResult
{
    std::uint64_t      jobId = 0;
    DiagnosticMultiResult r;
};

class DoIpTcpServer
{
public:
    explicit DoIpTcpServer (const TcpServerConfig &cfg);
    ~DoIpTcpServer ();

    DoIpTcpServer (const DoIpTcpServer &)            = delete;
    DoIpTcpServer &operator= (const DoIpTcpServer &) = delete;

    bool          open (std::string &err);
    void          close ();
    bool          isOpen () const { return listenFd_ >= 0; }
    std::uint16_t port () const { return port_; }

    void runFor (std::chrono::milliseconds dur);
    void requestStop () { stop_ = true; }

    // 统计（日志与自测用）
    std::size_t connectionsAccepted () const { return accepted_; }
    std::size_t activationsOk () const { return activations_; }
    std::size_t aliveCheckTimeouts () const { return aliveTimeouts_; }
    std::size_t activeConnections () const;
    std::size_t diagnosticRequests () const { return diagRequests_; }
    std::size_t diagnosticAcks () const { return diagAcks_; }
    std::size_t diagnosticNacks () const { return diagNacks_; }
    std::size_t diagnosticReplies () const { return diagReplies_; }
    // M10：连接断了以后才回来的结果（本该丢弃，这里只计数）
    std::size_t orphanResults () const { return orphanResults_; }
    // M10：同一连接上来第二条请求时被拒的次数（没有流水线语义）
    std::size_t busyRejects () const { return busyRejects_; }
    // M12：边到边发出去的应答条数（不等一轮广播收齐）
    std::size_t streamedReplies () const { return streamed_; }
    // M12：流式送达时连接已经断了（过期答案，丢弃并记账）
    std::size_t streamDropped () const { return streamDropped_; }

    std::function<void (const std::string &)> logger;

    // M3 的下游。为空时：只回 0x8002，不产生响应报文（通道仍能验完）。
    DiagnosticSink diagnosticSink;

    // M8 的下游（可选，优先于上面那个）：一次请求 → 多条带源地址的响应。
    DiagnosticMultiSink diagnosticSinkMulti;

    // ---- M10：异步下游。设了就优先走这里，同步 sink 自动失效 ----
    // 返回 0 = 当场就失败（immediate 里是结论）；>0 = 在途，等 asyncTake 交卷
    std::function<std::uint64_t (const DiagnosticRequest &, DiagnosticMultiResult &immediate)> asyncSubmit;
    // 每轮 poll 之后调用一次；返回 false 表示"这一轮没有结果了"
    std::function<bool (AsyncResult &)> asyncTake;
    // 连接断开时把在途请求作废（结果回来也不许转给别人）
    std::function<void (std::uint64_t)> asyncAbandon;

    // ---- M12：流式交付 ----
    // 网关广播每收到一条应答就调这里一次。**它在网关持有全部 busMu 的状态下被调用**，
    // 所以这里只做一件事：塞进队列，立刻返回；真正的 send 在 runFor 的 drainStream 里。
    void onStreamReply (std::uint64_t jobId, const DiagnosticReply &rep);

private:
    struct Conn
    {
        int                                      fd = -1;
        std::vector<std::uint8_t>                in;          // 累积缓冲：半包就攒着
        RoutingActivation                        routing;
        std::chrono::steady_clock::time_point    lastActivity;
        bool                                     aliveSent = false;
        std::chrono::steady_clock::time_point    aliveDeadline;
        std::uint64_t                            pendingJob = 0;   // M10：在途请求号
        std::uint16_t                            pendingSa  = 0;   // M10：谁发的（0x8001 的 TA 写回去）
        std::uint16_t                            pendingTarget = 0; // M10：问的谁（失败时 0x8003 的 SA 写它）
    };

    void acceptPending ();
    bool handleConn (Conn &c);                                  // false = 要关闭
    void dropConn (Conn &c, const std::string &why);
    void pumpTimers (std::chrono::steady_clock::time_point now);
    bool sendBytes (int fd, const std::vector<std::uint8_t> &b);
    void deliver (const AsyncResult &res);                      // 结果 → 对应连接
    void drainStream ();                                        // M12：把流式答案逐条送出
    void log (const std::string &s);

    TcpServerConfig cfg_;
    DiagnosticChannel diag_;
    std::uint16_t   port_;
    int             listenFd_ = -1;
    bool            stop_     = false;
    std::vector<Conn> conns_;
    std::size_t     accepted_    = 0;
    std::size_t     activations_ = 0;
    std::size_t     aliveTimeouts_ = 0;
    std::size_t     diagRequests_ = 0;
    std::size_t     diagAcks_     = 0;
    std::size_t     diagNacks_    = 0;
    std::size_t     diagReplies_  = 0;
    std::size_t     orphanResults_ = 0;
    std::size_t     busyRejects_   = 0;

    // M12：流式交付
    struct PendingStream
    {
        std::uint64_t    jobId = 0;
        DiagnosticReply  reply;
    };
    std::mutex               streamMu_;      // 广播线程写、I/O 线程读
    std::vector<PendingStream> streamQ_;     // 待发送的流式答案
    StreamLedger             ledger_;        // job → 已经流式发了几条（防重复发）
    std::size_t              streamed_      = 0;
    std::size_t              streamDropped_ = 0;
    // ★ 自唤醒管道：[0] 塞进 poll 集合，[1] 由广播线程写一个字节。
    //   没有它，答案进了队列也只能等 poll 自己超时（最长 100ms）才送出去，
    //   "首条答案几毫秒到手"就成了空话。
    int                      wakeFd_[2] = {-1, -1};
    void wakeIo ();
};

} // namespace doip
