// ============================================================================
// SourceSlot.h —— M28：把"谁"从以太网带到 CAN（纯逻辑，header-only）
//
// 问题：M27 之后网关知道"谁在敲门"（0x0005 的票验过了），但 ECU 不知道。
//   网关是**传输桥**，不改报文内容（M3.5 定的规矩：不内嵌 UDS）。
//   那身份能放在哪？
//
// 答案在 29 位 CAN ID 的布局里：
//
//   0x18DA 00 F1   =   0x18DA | <目标地址 00> | <源地址 F1>
//            ↑ 优先级/格式     ↑ ECU 的地址     ↑ **诊断仪的地址**
//
//   源地址那一个字节，本来就是"谁在说话"的位置。11 位 ID（0x7A0 那种）
//   一共只有 11 位，全用来选"发给谁"，**没有源地址这一格** ——
//   这就是"为什么诊断要用 29 位寻址"最实在的理由，也是本项目
//   M7 讲扩展帧的伏笔在这里兑现。
//
// 但 DoIP 的源地址是 0x0E00（16 位，3584），塞不进 1 个字节。
// 所以网关做一次**槽位映射**：每台验证过的诊断仪分一个 1 字节的槽
//   SA 0x0E00 → 槽 1 → CAN 源地址 0xF1
//   SA 0x0E01 → 槽 2 → CAN 源地址 0xF2
// 于是 ECU 的流水能记成"这次是 0xF2 改的"，而网关日志里写着
// "0xF2 = SA 0x0E01"——**两张账拼起来才是"谁"**。
//
// ★ 边界（必须写在说明书上，不然会把它当身份证）：
//   1) 槽号是 1 个字节、只有 8 个，会话结束会**回收再发**给下一台诊断仪。
//      所以槽号不是"人"，是"位子"：同一位子上午坐过 A，下午坐过 B。
//      要追到人，必须拿时间 + 网关日志里的映射表去对，不能只看 ECU 的流水。
//   2) 这一层改的是 CAN ID，不是报文内容 —— 但它**破坏了透明桥接**：
//      诊断仪在总线上看到的源地址不再是自己声明的那个。
//      所以默认关（--stamp-sa 才开），并且 ECU 侧要接受"任意源地址"（掩码过滤）。
//   3) 只改请求方向。应答仍走 ECU 配的那一条 ID（源地址在应答里是 ECU 自己，
//      目标地址才是诊断仪；要把它也按槽改写，就得连路由表的接收侧一起动，
//      那是更大的手术，这一步不做）。
// ============================================================================
#ifndef DOIP_SOURCE_SLOT_H
#define DOIP_SOURCE_SLOT_H

#include "CanId.h"

#include <cstddef>
#include <cstdint>

namespace doip
{
namespace slots
{

constexpr std::uint8_t kMaxSlots = 8;      // 1..8
constexpr std::uint8_t kSlotBase = 0xF1;   // 槽 1 → 0xF1，槽 8 → 0xF8

inline std::uint8_t canSourceOf (std::uint8_t slot)
{
    return slot == 0 ? 0 : static_cast<std::uint8_t> (kSlotBase + slot - 1);
}

// DoIP 源地址 ↔ 槽号。满了给 0（不抢别人的位子）。
class SlotTable
{
public:
    // 同一台诊断仪拿回同一个槽；新来的拿最小空槽；满了给 0。
    std::uint8_t take (std::uint16_t sa)
    {
        if (sa == 0) return 0;
        const std::uint8_t old = slotOf (sa);
        if (old != 0) return old;
        for (std::uint8_t i = 0; i < kMaxSlots; ++i)
        {
            if (!e_[i].used)
            {
                e_[i].used = true;
                e_[i].sa   = sa;
                return static_cast<std::uint8_t> (i + 1);
            }
        }
        return 0;
    }

    // 连接断了才回收。释放不存在的 SA 返回 false（不静默）。
    bool release (std::uint16_t sa)
    {
        const std::uint8_t s = slotOf (sa);
        if (s == 0) return false;
        e_[s - 1] = Entry{};
        return true;
    }

    std::uint8_t slotOf (std::uint16_t sa) const
    {
        if (sa == 0) return 0;
        for (std::uint8_t i = 0; i < kMaxSlots; ++i)
            if (e_[i].used && e_[i].sa == sa) return static_cast<std::uint8_t> (i + 1);
        return 0;
    }

    std::uint16_t saOf (std::uint8_t slot) const
    {
        if (slot < 1 || slot > kMaxSlots) return 0;
        return e_[slot - 1].used ? e_[slot - 1].sa : 0;
    }

    std::size_t used () const
    {
        std::size_t n = 0;
        for (const auto &x : e_) if (x.used) ++n;
        return n;
    }

private:
    struct Entry
    {
        std::uint16_t sa   = 0;
        bool          used = false;
    };
    Entry e_[kMaxSlots];
};

// 把 29 位 ID 的源地址字节换成槽对应的地址。
//
//   11 位 ID → 原样返回：它没有源地址那一格，这就是"11 位报不出谁"。
//   slot = 0 → 原样返回（不知道是谁，就别装）。
inline std::uint32_t stampSource (std::uint32_t canId, std::uint8_t slot)
{
    if (slot == 0 || !isExtendedId (canId)) return canId;
    return (canId & 0xFFFFFF00u) | static_cast<std::uint32_t> (canSourceOf (slot));
}

// 反过来：从收到的 29 位 ID 里读源地址（ECU 侧用）。11 位 ID 给 0。
inline std::uint8_t sourceOf (std::uint32_t canId)
{
    if (!isExtendedId (canId)) return 0;
    return static_cast<std::uint8_t> (canId & 0xFFu);
}

} // namespace slots
} // namespace doip

#endif
