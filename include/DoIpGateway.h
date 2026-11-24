#pragma once
// ============================================================================
// DoIpGateway.h —— M4 单通道 → M6 多通道 → M10 每条通道一个工作线程
//
// 三个里程碑在这一层留下的东西：
//
// ① **一路一条通道。** 每个路由入口自带一个 IsoTpClient（各自的 txId/rxId）。
//    不是"共用一个客户端改 ID 再发"——那会在并发下互相改写配置。
//
// ② **M9：FD 是通道属性**（RouteEntry.fd → 帧长 64），所以同一张表能混挂经典与 FD。
//
// ③ **M10：互斥从"全局一把锁"改成"每条通道一把锁 + 一条工作线程"。**
//    M4~M9 的做法是：谁进来都先抢同一把锁，抢到的在 CAN 上走完一问一答，其余的等。
//    正确的部分：**同一条通道上必须串行**（响应分不清是谁的）；
//    错的部分：**两条不同通道也被迫排队**——明明一台在问 7A0、一台在问 18DA00F1，
//    却在以太网侧排成一条队伍。M10 把队伍的粒度改对了：
//      · 每条通道一个 JobQueue + 一个工作线程 → 通道内 FIFO，通道间并行
//      · 结果统一交到 ResultBoard（id → 结果），I/O 线程只负责收/发字节
//      · 连接断了 → abandon(id)：结果回来也不许转给下一个诊断仪
//    排队这件事因此从"锁的等待"变成"显式的队列"，才量得出排队时长与队列峰值。
//
// ④ **地址不认识就不发。** 查不到 TA 时立刻失败回 0x8003 0x03，绝不猜一台 ECU。
//
// ⑤ **"问一台"和"问一类"是两种动作**（M8）。功能地址走 broadcast()，
//    M10 起它有自己的线程：广播要独占所有通道（总线只有一条），但**不能占住 I/O 线程**。
// ============================================================================
#include "DoIpDiagnostic.h"
#include "IsoTpClient.h"
#include "JobQueue.h"
#include "RouteTable.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace doip
{

class DiagnosticGateway
{
public:
    DiagnosticGateway (const std::string &iface,
                       const RouteTable &table,
                       const IsoTpTiming &tim = IsoTpTiming{});

    ~DiagnosticGateway ();

    DiagnosticGateway (const DiagnosticGateway &)            = delete;
    DiagnosticGateway &operator= (const DiagnosticGateway &) = delete;

    // 按路由表逐个开通道并起工作线程。任何一条开不起来就整体失败
    bool start (std::string &err);
    void stop ();

    // ---- 同步接口（M4~M9 的行为，功能寻址/一次性调用仍走它）----
    bool operator() (const DiagnosticRequest &req,
                     std::vector<std::uint8_t> &resp,
                     std::string &err);

    DiagnosticMultiResult broadcast (const DiagnosticRequest &req);

    // ---- M10 异步接口：投递 → 立刻返回 id ----
    // 返回 0 表示"连排队都没排上"（地址不认识 / 通道没开），此时 immediate 里已经有结论。
    // 返回非 0 表示"已进队或已当场失败"，结论稍后用 waitResult / takeResult 取。
    std::uint64_t submit (const DiagnosticRequest &req, DiagnosticMultiResult &immediate);
    bool waitResult (std::uint64_t id, DiagnosticMultiResult &out, std::chrono::milliseconds timeout);
    bool takeResult (std::uint64_t &id, DiagnosticMultiResult &out);   // 非阻塞，I/O 线程用
    void abandon (std::uint64_t id);                                   // 连接断了：结果作废

    struct ChannelStats
    {
        std::uint16_t       ta      = 0;
        std::uint32_t       txId    = 0;
        std::uint32_t       rxId    = 0;
        bool                fd      = false;
        bool                open    = false;
        std::size_t         handled = 0;
        std::size_t         failed  = 0;
        std::size_t         queuePeak = 0;         // M10：队列最深到过几条
        std::size_t         maxQueueWaitMs = 0;    // M10：最长排了多久
        std::size_t         rejected = 0;          // M10：队列满被拒的次数
        IsoTpClient::Stats  stats;
    };

    std::size_t handled ()        const { return handled_.load (); }
    std::size_t failed ()         const { return failed_.load (); }
    std::size_t unknownTargets () const { return unknown_.load (); }
    std::size_t maxWaitMs ()      const { return maxWaitMs_.load (); }
    std::size_t functionalRequests () const { return funcReq_.load (); }
    std::size_t functionalReplies ()  const { return funcRep_.load (); }
    std::size_t silentBroadcasts ()   const { return silent_.load (); }
    // M10：连接断了以后作废的在途请求数（结果回来也不转交，只记账）
    std::size_t abandonedJobs ()      const { return abandoned_.load (); }
    const RouteTable &table ()    const { return table_; }
    std::vector<ChannelStats> channelStats () const;

private:
    struct Channel
    {
        Channel (const std::string &iface, const IsoTpConfig &cfg, const IsoTpTiming &tim)
            : client (iface, cfg, tim)
        {
        }
        IsoTpClient                        client;
        JobQueue                           queue{8};     // 一条通道最多排 8 条，满了当场拒
        std::thread                        worker;
        std::mutex                         busMu;        // "这条通道的总线使用权"（广播要全占）
        std::atomic<std::size_t>           handled{0};
        std::atomic<std::size_t>           failed{0};
        std::atomic<std::size_t>           maxQueueWaitMs{0};
    };

    void workerLoop (std::uint16_t ta);
    void functionalLoop ();
    DiagnosticMultiResult broadcastLocked (const DiagnosticRequest &req);   // 调用方已持有全部 busMu
    void lockAllBuses (std::vector<std::unique_lock<std::mutex>> &locks);   // 按 TA 升序，防死锁
    void finishJob (std::uint64_t id, JobResult r);

    std::string iface_;
    RouteTable  table_;
    IsoTpTiming tim_;
    std::map<std::uint16_t, std::unique_ptr<Channel>> chans_;

    ResultBoard        board_;
    JobQueue           funcQueue_{8};
    std::thread        funcThread_;
    std::mutex         funcMu_;      // 广播串行（同一时刻只允许一次广播）
    bool               running_ = false;

    std::atomic<std::size_t> handled_{0};
    std::atomic<std::size_t> failed_{0};
    std::atomic<std::size_t> unknown_{0};
    std::atomic<std::size_t> maxWaitMs_{0};
    std::atomic<std::size_t> funcReq_{0};
    std::atomic<std::size_t> funcRep_{0};
    std::atomic<std::size_t> silent_{0};
    std::atomic<std::size_t> abandoned_{0};
};

} // namespace doip
