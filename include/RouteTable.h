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
//
// M7 补的一层：ID 有**宽度**。11 位最大 0x7FF，再往上就是 29 位扩展帧。
//   表里存 32 位原值（宽度靠数值判断，见 CanId.h），所以这里只管"别超过 29 位上限"。
//   一笔 0x20000000 的配置如果放进来，发帧时内核只会回 EINVAL，
//   现象是"启动成功、每次请求都超时"——正是那种查三天都查不到的错。
// ============================================================================
//
// M8 补的一层：地址还分**物理**和**功能**。
//   物理地址（0x0001–0x0DFF 这一段是厂商自定）：一台 ECU 一个，语气是"我找那一台"。
//   功能地址（ISO 13400 里 0xE000–0xE3FF 是 ISO/SAE 保留的功能组，0xE400–0xEFFF 是
//   厂商自定义的功能组）：语气是"你们这一类，全都听着"。业界最常用的是 0xE400。
//   网关收到打在功能地址上的诊断，要做的事从"发一对 ID"变成
//   **"在 7DF 上广播一次，再把各自回的话收齐，一条一条送回给诊断仪"**。
//   所以功能路由不是"少一个 rxId"，而是另一种结构（见 FunctionalRoute）。
// ============================================================================
#include "CanId.h"

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

// 功能寻址：一个地址 → **一个广播 ID**（CAN 上通常是 0x7DF，29 位是 0x18DB33F1）。
// 响应 ID 故意不写在这里：谁答话由 ECU 自己决定（各自用自己的物理响应 ID），
// 网关要收的是"所有已知通道的响应"，不是某一条。
struct FunctionalRoute
{
    std::uint16_t logicalAddress = 0;   // 功能地址（0xE400 等）
    std::uint32_t txId           = 0;   // 广播 ID（所有 ECU 都在听的那个）
    std::string   name;
};

// 功能地址段判定。0xE000–0xE3FF 是 ISO/SAE 保留的功能组（WWH-OBD 用 0xE000），
// 自用应该落在 0xE400–0xEFFF 这一段（厂商自定义功能组）。
inline bool isFunctionalAddressRange (std::uint16_t a) { return a >= 0xE000 && a <= 0xEFFF; }
inline bool isVendorFunctionalAddress (std::uint16_t a) { return a >= 0xE400 && a <= 0xEFFF; }

class RouteTable
{
public:
    // 加一条物理路由。任何一条不合法就整条拒掉，并把原因写进 err。
    bool add (const RouteEntry &e, std::string &err);

    // 加一条功能路由（M8）。规则和物理路由一样严格，只是校验项不同：
    // 地址必须落在功能段、广播 ID 不能和任何物理 ID 撞。
    bool addFunctional (const FunctionalRoute &f, std::string &err);

    // 查表：找不到返回 nullptr（调用方据此回 0x8003 0x03）
    const RouteEntry *lookup (std::uint16_t ta) const;
    bool known (std::uint16_t ta) const { return lookup (ta) != nullptr; }

    // 功能地址查表（M8）：命中说明"这个 TA 是要广播的"
    const FunctionalRoute *lookupFunctional (std::uint16_t ta) const;
    bool knownFunctional (std::uint16_t ta) const { return lookupFunctional (ta) != nullptr; }

    // 一个地址算不算"本网关能到的目标"：物理表或功能表命中都算
    bool reachable (std::uint16_t ta) const { return known (ta) || knownFunctional (ta); }

    std::size_t size () const { return entries_.size (); }
    std::size_t sizeFunctional () const { return funcEntries_.size (); }
    const std::vector<RouteEntry> &entries () const { return entries_; }
    const std::vector<FunctionalRoute> &functionalEntries () const { return funcEntries_; }
    void clear () { entries_.clear (); funcEntries_.clear (); }

private:
    std::vector<RouteEntry>      entries_;
    std::vector<FunctionalRoute> funcEntries_;
};

} // namespace doip
