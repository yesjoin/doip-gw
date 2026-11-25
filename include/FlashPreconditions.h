// ============================================================================
// FlashPreconditions.h —— M19：刷之前先回答"现在能不能刷"（纯逻辑）
//
// 为什么要有这一层：
//   0x34 之前的门（M16）只问"你是谁、有没有钥匙"。它不回答"现在合不合适"：
//   电不够、会话没切、还没解锁、上一段下载没收尾 —— 这四件事里任何一件不成立，
//   刷下去都可能把 ECU 弄成砖。真实产线会在 0x34 之前先跑一条"前置条件检查"例程。
//
// 本项目的口径（0x31 01 0203 CheckProgrammingPreconditions）：
//   电压 ≥ 11500 mV；编程会话 0x02；已解锁；当前不在下载中。
//   四条全过 → 状态 00；任何一条不过 → 状态 01，并且**逐条**写清楚哪条不过。
//
// 为什么返回"状态 01"而不是 NRC：
//   请求本身完全合法（你就是在问"能不能刷"），答案是"不能" —— 这不是错误，
//   是一个合法的否定结论。用 NRC 会让诊断仪以为"服务用错了"。
//
// 为什么电压门槛要单独挡住 0x34：
//   "检查过"和"检查结果被遵守"是两件事。真实项目里刷写中途掉电是最常见的变砖原因，
//   所以 0x34 自己在进门时也要看一眼电压（0x22 conditionsNotCorrect，不是 NRC）。
// ============================================================================
#ifndef DOIP_FLASH_PRECONDITIONS_H
#define DOIP_FLASH_PRECONDITIONS_H

#include <cstdint>
#include <string>
#include <vector>

namespace doip {

struct Preconditions
{
    std::uint32_t batteryMv        = 12400;
    std::uint32_t minBatteryMv     = 11500;   // 12V 系统：低于 11.5V 就别刷
    bool          programmingSession = false;
    bool          unlocked           = false;
    bool          downloadActive     = false; // 0x34 之后、0x37 之前
};

struct PrecheckItem
{
    std::string what;
    bool        ok;
};

struct PrecheckResult
{
    bool                     ok = false;
    std::vector<PrecheckItem> items;

    // 给日志用的一行：电压 12400 mV ≥ 11500 ✓；会话 0x02 ✓；已解锁 ✓；不在下载中 ✓
    std::string summary () const
    {
        std::string s;
        for (std::size_t i = 0; i < items.size (); ++i)
        {
            if (i) s += "；";
            s += items[i].what + (items[i].ok ? " ✓" : " ✗");
        }
        return s;
    }
};

inline PrecheckResult checkProgrammingPreconditions (const Preconditions &p)
{
    PrecheckResult r;
    r.items.push_back ({"电压 " + std::to_string (p.batteryMv) + " mV ≥ " +
                        std::to_string (p.minBatteryMv), p.batteryMv >= p.minBatteryMv});
    r.items.push_back ({"会话 0x" + std::string (p.programmingSession ? "02（编程）" : "01（默认）"),
                        p.programmingSession});
    r.items.push_back ({"已解锁", p.unlocked});
    r.items.push_back ({"不在下载中", !p.downloadActive});

    r.ok = true;
    for (const auto &it : r.items) if (!it.ok) r.ok = false;
    return r;
}

} // namespace doip

#endif
