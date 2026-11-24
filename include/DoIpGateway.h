#pragma once
// ============================================================================
// DoIpGateway.h —— M4 单通道 → M6 多通道
//
// M4：一个网关对一台 ECU（7E0/7E8 写死）。
// M6：一个网关对一串 ECU，靠 RouteTable 把 TA 翻成那对 CAN ID。
//
// 三件必须说清的事：
//
// ① **一路一条通道。** 每个路由入口自带一个 IsoTpClient（各自的 txId/rxId）。
//    不是"共用一个客户端改 ID 再发"——那会在并发下互相改写配置。
//
// ② **锁还是那一把。** 即使有两条 CAN 通道，它们在同一条总线上，物理层没法并行；
//    更重要的是：两个 tester 同时问同一台 ECU 时，响应必须严格对应。
//    所以仍然粗暴地串行化，代价是排队几毫秒（实测最长 0 ms）。
//
// ③ **地址不认识就不发。** 查不到 TA 时立刻失败，由上层回 0x8003 0x03，
//    绝不"猜一台 ECU 发过去"。诊断工程里，答错比不答危险得多。
//
// M8 补的第 ④ 件事：**"问一台"和"问一类"是两种动作。**
//    物理地址：一条通道一发一收，答案只有一条。
//    功能地址：广播一次，然后挨条通道收——**答案条数不由网关决定，由谁在听决定**。
//    所以功能寻址走 broadcast()，不复用 operator()：那个函数的契约是"一问一答"。
// ============================================================================
#include "DoIpDiagnostic.h"
#include "IsoTpClient.h"
#include "RouteTable.h"

#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace doip
{

class DiagnosticGateway
{
public:
    DiagnosticGateway (const std::string &iface,
                       const RouteTable &table,
                       const IsoTpTiming &tim = IsoTpTiming{});

    // 按路由表逐个开通道。任何一条开不起来就整体失败（配置错不该带病运行）
    bool start (std::string &err);
    void stop ();

    // 直接当 DiagnosticSink 用：查表 → 串行化 → 发 ISO-TP → 收响应
    bool operator() (const DiagnosticRequest &req,
                     std::vector<std::uint8_t> &resp,
                     std::string &err);

    // M8：功能寻址。一条广播 → 收集所有通道的应答。
    // 语义上它**不能**复用 operator()：那个函数是"一问一答"，这里的答案条数由 ECU 决定。
    DiagnosticMultiResult broadcast (const DiagnosticRequest &req);

    struct ChannelStats
    {
        std::uint16_t       ta      = 0;
        std::uint32_t       txId    = 0;
        std::uint32_t       rxId    = 0;
        bool                open    = false;
        std::size_t         handled = 0;
        std::size_t         failed  = 0;
        IsoTpClient::Stats  stats;
    };

    std::size_t handled ()        const { return handled_; }
    std::size_t failed ()         const { return failed_; }
    std::size_t unknownTargets () const { return unknown_; }
    std::size_t maxWaitMs ()      const { return maxWaitMs_; }
    // M8 的两个数：广播了几次、从 ECU 收回来几条应答（一次广播可以回多条）
    std::size_t functionalRequests () const { return funcReq_; }
    std::size_t functionalReplies ()  const { return funcRep_; }
    std::size_t silentBroadcasts ()   const { return silent_; }   // 广播了出去、一条都没答
    const RouteTable &table ()    const { return table_; }
    std::vector<ChannelStats> channelStats () const;

private:
    struct Channel
    {
        Channel (const std::string &iface, const IsoTpConfig &cfg, const IsoTpTiming &tim)
            : client (iface, cfg, tim)
        {
        }
        IsoTpClient client;
        std::size_t handled = 0;
        std::size_t failed  = 0;
    };

    std::string iface_;
    RouteTable  table_;
    IsoTpTiming tim_;
    std::map<std::uint16_t, std::unique_ptr<Channel>> chans_;

    std::mutex  mu_;                  // 串行化：一把锁换"不串包"
    std::size_t handled_    = 0;
    std::size_t failed_     = 0;
    std::size_t unknown_    = 0;
    std::size_t maxWaitMs_  = 0;
    std::size_t funcReq_    = 0;
    std::size_t funcRep_    = 0;
    std::size_t silent_     = 0;
};

} // namespace doip
