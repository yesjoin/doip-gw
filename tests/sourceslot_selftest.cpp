// ============================================================================
// sourceslot_selftest.cpp —— M28 的纯逻辑自测（源地址槽）
//
// 三组：
//   A 分配：同一台拿回同一个位子 / 新来的拿最小空槽 / 满了给 0（不抢）/ 释放后复用；
//   B 改写：只动 29 位 ID 的最低字节（源地址）/ 目标地址与高 24 位不动；
//   C 边界：11 位 ID 原样返回（它没有源地址这一格）/ slot=0 不装。
//
// 用法：./sourceslot-selftest        全绿退出码 0
// ============================================================================
#include "SourceSlot.h"

#include <cstdio>
#include <string>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                                                  \
    do {                                                                                   \
        if (cond) { ++gPass; }                                                             \
        else {                                                                             \
            ++gFail;                                                                       \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ());    \
        }                                                                                  \
    } while (0)

int main ()
{
    std::printf ("=== A 槽位分配 ===\n");
    {
        slots::SlotTable t;
        CHECK (t.used () == 0, "空表 0 个位子");
        CHECK (t.slotOf (0x0E00) == 0, "没分配过的 SA → 0");
        CHECK (t.saOf (0) == 0 && t.saOf (9) == 0, "越界槽号 → 0（不崩）");

        const std::uint8_t a = t.take (0x0E00);
        CHECK (a == 1, "第一台 → 槽 1");
        CHECK (t.take (0x0E00) == 1, "同一台再问 → 还是槽 1（不改号）");
        CHECK (t.used () == 1, "同一台占一个位子");

        CHECK (t.take (0x0E01) == 2, "第二台 → 槽 2");
        CHECK (t.slotOf (0x0E01) == 2 && t.saOf (2) == 0x0E01, "映射读得回来");

        CHECK (t.release (0x0E00), "释放槽 1");
        CHECK (t.used () == 1, "释放后只剩一个");
        CHECK (t.slotOf (0x0E00) == 0, "释放后就查不到");
        CHECK (t.take (0x0E05) == 1, "新来的复用最小空槽（1）");
        CHECK (!t.release (0x0E99), "释放不存在的 SA → false（不静默）");
    }
    {
        // 满了不抢：第 9 台给 0，而不是把第 1 台踢掉
        slots::SlotTable t;
        for (int i = 1; i <= 8; ++i) CHECK (t.take (static_cast<std::uint16_t> (0x0E00 + i)) == i,
                                            "第 i 台 → 槽 i");
        CHECK (t.used () == 8, "八个位子全占");
        CHECK (t.take (0x0E20) == 0, "第 9 台 → 0（位子满了，不抢别人的）");
        CHECK (t.used () == 8, "满了之后还是 8 个");
    }

    std::printf ("\n=== B 改写 29 位 ID ===\n");
    {
        // 18DA00F1：目标 0x00（那台 ECU），源 0xF1
        CHECK (slots::stampSource (0x18DA00F1u, 1) == 0x18DA00F1u, "槽 1 → 源地址还是 F1");
        CHECK (slots::stampSource (0x18DA00F1u, 2) == 0x18DA00F2u, "槽 2 → 源地址 F2");
        CHECK (slots::stampSource (0x18DA00F1u, 8) == 0x18DA00F8u, "槽 8 → 源地址 F8");
        CHECK ((slots::stampSource (0x18DA00F1u, 2) & 0xFFFFFF00u) == 0x18DA0000u,
               "只有最低字节变，目标地址与高 24 位不动");
        // 目标地址自己也是 F1（0x18DAF1F1）：只有**最低那一个** F1 被换掉，
        //   高位那个 F1 是目标，动了就等于发错人。
        CHECK (slots::stampSource (0x18DAF1F1u, 2) == 0x18DAF1F2u,
               "目标地址也是 F1 时，只动最低字节那个 F1（高位的 F1 是目标，不能碰）");
    }

    std::printf ("\n=== C 11 位与 0 槽：别装 ===\n");
    {
        CHECK (slots::stampSource (0x7A0u, 2) == 0x7A0u, "11 位 ID 原样返回（没有源地址这一格）");
        CHECK (slots::stampSource (0x7FFu, 8) == 0x7FFu, "11 位最大 0x7FF 也不改");
        CHECK (slots::stampSource (0x18DA00F1u, 0) == 0x18DA00F1u, "槽 0（不知道是谁）→ 不装");
        CHECK (slots::sourceOf (0x18DA00F2u) == 0xF2, "读回来：扩展帧 → 源地址 F2");
        CHECK (slots::sourceOf (0x7A0u) == 0, "读回来：11 位 → 0（报不出谁）");
        CHECK (slots::sourceOf (0x80000000u | 0x18DA00F3u) == 0xF3, "带 EFF 标志位也读得对");
        CHECK (slots::canSourceOf (0) == 0 && slots::canSourceOf (1) == 0xF1 &&
               slots::canSourceOf (8) == 0xF8, "槽 → CAN 源地址：0/1/8");
        // 往返：槽 k 写进去，读出来还是 0xF(k)
        for (std::uint8_t k = 1; k <= 8; ++k)
        {
            const std::uint32_t id = slots::stampSource (0x18DA00F1u, k);
            CHECK (slots::sourceOf (id) == slots::canSourceOf (k), "槽 k 写进去再读出来一致");
        }
    }

    std::printf ("\n=== 汇总：通过 %d 项，失败 %d 项 ===\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
