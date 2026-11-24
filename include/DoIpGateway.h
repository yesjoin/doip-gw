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
};

} // namespace doip
