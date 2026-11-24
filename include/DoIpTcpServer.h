#pragma once
// ============================================================================
// DoIpTcpServer.h —— M2：TCP 13400 连接 + 路由激活 + 心跳
//
// 这一层干三件事：
//   ① 收连接、收字节、把字节拼成完整报文（TCP 会粘包也会半包）
//   ② 把 0x0005 交给 DoIpRouting（状态机在那里）并把结论组回 0x0006
//   ③ 心跳：静默太久发 0x0007，限时收不到 0x0008 就断开
//
// 和 M1 的 UDP 有一个关键区别：
//   **TCP 上收到坏报文要回 0x0000 负应答，然后断开。**
//   因为 TCP 是有连接的，对面在等你说话；UDP 上没有这层义务（还要避免广播风暴）。
//   同一个"坏报文"，两层处理不同 —— 这就是"传输层决定错误模型"。
//
// 心跳的时间参数可以调小，自测才有办法在 1 秒内跑完"超时断开"。
// ============================================================================
#include "DoIpCodec.h"
#include "DoIpDiagnostic.h"
#include "DoIpRouting.h"

#include <chrono>
#include <cstdint>
#include <functional>
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
    // 网关会接成"查路由表"，于是 TA 打到背后的 ECU 也算合法目标。
    std::function<bool (std::uint16_t)> targetKnown;

    // 心跳：激活后静默超过 idleBeforeAliveCheck → 发 0x0007；
    //       发出去后 aliveCheckTimeout 内没收到 0x0008 → 断开。
    std::chrono::milliseconds idleBeforeAliveCheck{2000};
    std::chrono::milliseconds aliveCheckTimeout{1000};
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
    // M8：一次请求生成了几条 0x8001 响应（功能寻址时 > 1）
    std::size_t diagnosticReplies () const { return diagReplies_; }

    std::function<void (const std::string &)> logger;

    // M3 的下游。为空时：只回 0x8002，不产生响应报文（通道仍能验完）。
    // M4 把它接成 ISO-TP 通道。
    DiagnosticSink diagnosticSink;

    // M8 的下游（可选，优先于上面那个）：一次请求 → 多条带源地址的响应。
    // 只有功能寻址需要它；设了它之后，所有请求都走它（物理寻址返回一条即可）。
    DiagnosticMultiSink diagnosticSinkMulti;

private:
    struct Conn
    {
        int                                      fd = -1;
        std::vector<std::uint8_t>                in;          // 累积缓冲：半包就攒着
        RoutingActivation                        routing;
        std::chrono::steady_clock::time_point    lastActivity;
        bool                                     aliveSent = false;
        std::chrono::steady_clock::time_point    aliveDeadline;
    };

    void acceptPending ();
    bool handleConn (Conn &c);                                  // false = 要关闭
    void dropConn (Conn &c, const std::string &why);
    void pumpTimers (std::chrono::steady_clock::time_point now);
    bool sendBytes (int fd, const std::vector<std::uint8_t> &b);
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
};

} // namespace doip
