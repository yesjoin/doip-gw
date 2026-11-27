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
//
// ★ M13：激活不只是"这条连接的事"。
//   连接级的 RoutingActivation 只管"这条 socket 里 SA 不许换人"，
//   它管不了"两台 tester 用同一个 SA 各开一条连接"——那需要一张实体级的账
//   （TesterRegistry：SA ↔ 连接号）。0x03 / 0x01 两个码第一次真的被用起来。
//
// ★ M14：这张账要能"对外被问出来"（UDP 0x4001 → 0x4002）。
//   要点只有一个：**跨线程读状态必须走原子量。**
//   conns_ 只有 I/O 线程在动，UDP 线程去遍历它 = 数据竞争（而且不会每次都崩，
//   是那种"跑十遍崩一次"的 bug）。所以这里维护一个 atomic 计数，
//   UDP 线程只读它 —— 快照可能差一条，但不可能是坏内存。
// ============================================================================
#include "DoIpCodec.h"
#include "DoIpDiagnostic.h"
#include "DoIpEntityStatus.h"   // M14：实体状态快照的类型
#include "DoIpRouting.h"
#include "ActivationAuth.h"     // M27：激活凭据（HMAC token）
#include "SourceSlot.h"         // M28：SA ↔ 1 字节位子（写上 CAN 源地址）
#include "OpPermission.h"
#include "SlotLedger.h"          // M29：位子租约账（把 ECU 的"第几号位子"还原成"哪台 SA"）
#include "StreamLedger.h"   // M12：边收边发的记账（纯逻辑）
#include "TesterRegistry.h" // M13：实体级的 tester 地址仲裁（纯逻辑）

#include <atomic>
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
    // M13：两个数分开。**连接 ≠ 激活**：
    //   maxConnections 是"能挂住几个 TCP socket"，maxActivated 是"同时能给几台 tester 激活"。
    //   M13 之前它们是同一个数（4），于是 0x01 "socket 都占满了" 这个码永远出不来 ——
    //   第 5 个客户端连 TCP 都连不上，根本走不到路由激活那一步。
    std::size_t   maxConnections   = 8;
    std::size_t   maxActivated     = 4;
    std::uint32_t maxPayload       = kDefaultMaxPayload;
    std::size_t   maxUds           = 512;     // 单条诊断的 UDS 上限（超过 → 0x8003 0x04）

    // ---- M27：入场券 ----
    // 不给 --tester-key 时 authRequired = false，行为与 M26 完全一致（开发和教学默认）。
    // 给了就等于"这一车上所有要动表的操作，先证明你是谁"。
    // token 装在 0x0005 的 OEM 4 字节里，绑源地址（见 ActivationAuth.h）。
    auth::Secret  authKey{};
    bool          authRequired = false;

    // M28：要不要给每条激活的连接分一个 1 字节的"位子"，让它跟着请求走到 CAN。
    //   默认关：关着的时候总线上所有诊断仪都是路由表里写的那个源地址（透明桥接）。
    bool          stampSlots = false;

    // ---- M30：诊断防火墙（按 SA 分"读 / 写 / 刷写"三档）----
    //   默认关：关着的时候一条诊断请求都不会被网关多看一眼前面 —— 和 M29 逐字节一样。
    //   开了之后越权的请求**不转发**，网关替 ECU 回 7F <SID> 33（越界，所以默认关）。
    bool                  enforceOps = false;
    ops::PermissionTable  opTable;

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
    // M13：实体级仲裁的两个观测量。**它们只涨不回退**，退场日志用它们说话。
    std::size_t addressConflicts () const { return registry_.conflicts (); }        // 0x03
    std::size_t activationCapacityRejects () const { return registry_.capacityRejects (); } // 0x01
    // M27：凭据的两本账。通过的次数就是"有过几个能证明自己的人"。
    std::size_t authPasses () const { return authPasses_; }
    std::size_t authRejects () const { return authRejects_; }
    // M28：现在占了几个"位子"（0 = 没开，或者一台都没激活）
    std::size_t slotsUsed () const { return slots_.used (); }
    // M29：把这份"位子租约账"落盘（给 doip-audit 对账用）。
    //   只在开了 --stamp-sa（cfg_.stampSlots）时才有内容；否则写出来就是空账 ——
    //   空账也有意义：它明确说"这次运行没有位子这回事"，而不是"文件丢了"。
    bool saveSlotLedger (const std::string &path, std::string &why) const
    {
        return slotLedger_.save (path, why);
    }
    std::string slotLedgerText () const { return slotLedger_.text (); }
    const slots::SlotLedger &slotLedger () const { return slotLedger_; }
    // M30：权限的两本账。放行多少、挡回多少，挡回里按"要哪一档"分开记 ——
    //   只报一个总数看不出"是谁在越刷写的界"。
    std::size_t opAllowed () const { return opAllowed_; }
    std::size_t opDenied () const { return opDenied_; }
    std::size_t opDeniedRead () const { return opDeniedRead_; }
    std::size_t opDeniedWrite () const { return opDeniedWrite_; }
    std::size_t opDeniedFlash () const { return opDeniedFlash_; }
    std::size_t activeTesters () const { return registry_.active (); }
    // M14：现在开着几条 TCP_DATA socket（**连接数，不是激活数**）。
    //   原子量：UDP 线程（回答 0x4001）要读它，I/O 线程要写它。
    std::size_t openSockets () const { return openSockets_.load (); }
    // M14：TCP 上收到"只该走 UDP"的请求的次数（0x4001 / 0x4003）。
    //   不回答、不断开，只记账 —— 惯着它只会让不合规的客户端以为这样也行。
    std::size_t udpOnlyRejects () const { return udpOnlyRejects_; }

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
        std::uint64_t                            id = 0;      // M13：连接号（实体级仲裁用它认人，不用 fd：fd 会被复用）
        int                                      fd = -1;
        std::vector<std::uint8_t>                in;          // 累积缓冲：半包就攒着
        RoutingActivation                        routing;
        std::chrono::steady_clock::time_point    lastActivity;
        bool                                     aliveSent = false;
        std::chrono::steady_clock::time_point    aliveDeadline;
        std::uint64_t                            pendingJob = 0;   // M10：在途请求号
        std::uint16_t                            pendingSa  = 0;   // M10：谁发的（0x8001 的 TA 写回去）
        std::uint16_t                            pendingTarget = 0; // M10：问的谁（失败时 0x8003 的 SA 写它）
        std::uint8_t                             slot = 0;         // M28：这条连接分到的"位子"（0 = 不知道/没开）
        std::uint16_t                            slotSa = 0;       // M28：这位子是发给谁的（归还时认它，不认"当前 SA"）
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
    std::size_t     authPasses_    = 0;   // M27：凭据对上的次数
    // M30：诊断防火墙的三个数（挡回按"要哪一档"分开记）
    std::size_t     opAllowed_      = 0;
    std::size_t     opDenied_       = 0;
    std::size_t     opDeniedRead_   = 0;
    std::size_t     opDeniedWrite_  = 0;
    std::size_t     opDeniedFlash_  = 0;
    std::size_t     authRejects_   = 0;   // M27：凭据不对被挡回去的次数

    // M13：实体级的 tester 地址仲裁。
    //   ★ 它不是连接状态，所以必须放在服务器上，而不是每条 Conn 里。
    //     放错地方的表现是"两个连接用同一个地址都激活成功"——这正是 M13 要堵的洞。
    TesterRegistry  registry_{4};     // open() 里按 cfg_.maxActivated 改上限
    // M28：SA ↔ 位子的映射。放在服务器上，因为位子是"实体级资源"（和 M13 的地址账同层）：
    //   放连接里 = 每条连接自己发号，两台会拿到同一个号。
    slots::SlotTable slots_;
    // M29：位子租约账（谁在什么时间段占着哪个位子）。同样放服务器上：
    //   它是"实体级"的历史，不属于某一条连接。落盘后由 doip-audit 与 ECU 流水对账。
    slots::SlotLedger       slotLedger_;      // M29：位子租约账（和 M12 的流式账不是一回事）
    std::uint64_t   nextConnId_ = 1;  // 连接号从 1 开始（0 当"没有"用，和 jobId 同一个约定）

    // M14：给 UDP 线程读的"现在开着几条 socket"。
    //   ★ 为什么不用 activeConnections()：那个函数遍历 conns_，只有 I/O 线程能调。
    //     同一个数换个线程读，就得换个读法。
    std::atomic<std::size_t> openSockets_{0};
    std::size_t              udpOnlyRejects_ = 0;

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
