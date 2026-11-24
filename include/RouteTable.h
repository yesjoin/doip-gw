#pragma once
// ============================================================================
// RouteTable.h —— M6：把"以太网上的目标地址"翻译成"CAN 上的那对 ID"
//
// 为什么需要它：
//   M4 的网关只认识一台 ECU，7E0/7E8 是写死的常量。可真实的网关后面挂着一串 ECU，
//   诊断仪发来的 0x8001 里只有一个 TA（目标逻辑地址），网关要做的事就一句话：
//     **TA → (请求 ID, 响应 ID)**
//   TA=0x0001 打到 7E0/7E8，TA=0x0002 打到 7A0/7A8，TA=0x0003 → 我不认识，回 0x8003 0x03。
//
// 三个设计决定：
//   ① 纯逻辑、不碰 socket：查表是查表，开通道是开通道。这样"地址冲突/重复/为 0"这类
//      规则能在内存里测，不用起 CAN。
//   ② **一个地址只能有一条路由**：重复注册直接报错，不搞"后者覆盖前者"——
//      配置错的时候，宁可启动失败，也不要运行时随机打到某台 ECU 上。
//   ③ 顺带把"两台 ECU 用同一对 CAN ID"也拦掉：那是配置写错了，不是合法的共享。
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>

namespace doip
{

struct RouteEntry
{
    std::uint16_t logicalAddress = 0;   // DoIP 目标地址（诊断仪报文里的 TA）
    std::uint32_t txId           = 0;   // 网关 → ECU：请求帧 ID
    std::uint32_t rxId           = 0;   // ECU → 网关：响应帧 ID
    std::string   name;                 // 打印/日志用，比如 "ECU_A"
};

class RouteTable
{
public:
    // 加一条路由。任何一条不合法就整条拒掉，并把原因写进 err。
    bool add (const RouteEntry &e, std::string &err);

    // 查表：找不到返回 nullptr（调用方据此回 0x8003 0x03）
    const RouteEntry *lookup (std::uint16_t ta) const;
    bool known (std::uint16_t ta) const { return lookup (ta) != nullptr; }

    std::size_t size () const { return entries_.size (); }
    const std::vector<RouteEntry> &entries () const { return entries_; }
    void clear () { entries_.clear (); }

private:
    std::vector<RouteEntry> entries_;
};

} // namespace doip
