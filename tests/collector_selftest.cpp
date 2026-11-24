// ============================================================================
// collector_selftest.cpp —— M11 的纯逻辑自测（DiagResponseCollector）
//
// 为什么要单测而没有一条依赖真总线：
//   多响应配对的所有难点都在"归档"和"收工判断"上，而这两件事只依赖
//   （SA, 字节, 时间戳）三个输入。给个假时钟，就能把"窗口边界""重复答""改口"
//   这些现场极难复现的情形，一秒内测完。
//
// 用法：./collector-selftest        全绿时退出码 0
// ============================================================================
#include "DiagResponseCollector.h"

#include <cstdio>
#include <initializer_list>
#include <vector>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, what);     \
        }                                                              \
    } while (0)

static std::vector<std::uint8_t> bytes (std::initializer_list<int> xs)
{
    std::vector<std::uint8_t> v;
    for (int x : xs) v.push_back (static_cast<std::uint8_t> (x));
    return v;
}

// 造一条 VIN 正响应：62 F1 90 + 17 字节 ASCII
static std::vector<std::uint8_t> vin (const char *s)
{
    std::vector<std::uint8_t> v{0x62, 0xF1, 0x90};
    for (const char *p = s; *p; ++p) v.push_back (static_cast<std::uint8_t> (*p));
    return v;
}

int main ()
{
    // ---- A. 空收集器 ----
    {
        DiagResponseCollector c;
        CHECK (c.count () == 0, "空收集器：0 台");
        CHECK (c.arrivals () == 0, "空收集器：0 条");
        CHECK (c.empty (), "空收集器：empty() 为真");
        CHECK (c.find (0x0003) == nullptr, "空收集器：找不到任何地址");
        CHECK (c.quietMs (1000) == -1, "空收集器：静默时长返回 -1（从来没响过）");
        CHECK (!c.settled (100000, 10), "空收集器：等多久都不算收工（0 条不能收工）");
    }

    // ---- B. 顺序与归档 ----
    {
        DiagResponseCollector c;
        CHECK (c.add (0x0006, vin ("LSVCC0000C7654321"), 100) == DiagResponseCollector::Outcome::Fresh,
               "第一条：Fresh");
        CHECK (c.add (0x0003, vin ("LSVZZ0000B7654321"), 130) == DiagResponseCollector::Outcome::Fresh,
               "第二条：Fresh");
        CHECK (c.count () == 2, "两台不同的 ECU");
        CHECK (c.arrivals () == 2, "到过两条");
        CHECK (c.at (0).sa == 0x0006, "第 1 条按**到达顺序**排（先到的 0x0006）");
        CHECK (c.at (1).sa == 0x0003, "第 2 条按到达顺序排");
        CHECK (c.at (0).seq == 1 && c.at (1).seq == 2, "seq 是 1、2");
        CHECK (c.find (0x0003) != nullptr && c.find (0x0003)->seq == 2, "find(0x0003) 是第 2 条");
        CHECK (c.find (0x0009) == nullptr, "find(不存在的地址) 返回 nullptr");
    }

    // ---- C. 同一台又答一遍：重复，不是新的一台 ----
    {
        DiagResponseCollector c;
        c.add (0x0007, vin ("LSVSS0000S7654321"), 100);
        CHECK (c.add (0x0007, vin ("LSVSS0000S7654321"), 150) == DiagResponseCollector::Outcome::Duplicate,
               "同一台再答：Duplicate");
        CHECK (c.count () == 1, "台数仍是 1（重复不涨台数）");
        CHECK (c.arrivals () == 2, "到过 2 条");
        CHECK (c.duplicates () == 1, "重复次数 1");
        CHECK (c.changes () == 0, "内容一样，改口次数 0");
        CHECK (c.at (0).uds == vin ("LSVSS0000S7654321"), "保留第一次的正文");
        CHECK (c.at (0).firstMs == 100 && c.at (0).lastMs == 150, "第一次/最近一次时刻分开记");

        // 同一台答了**不一样**的：这不是重复，是它中途改了状态
        CHECK (c.add (0x0007, bytes ({0x7F, 0x22, 0x31}), 200)
                   == DiagResponseCollector::Outcome::Duplicate,
               "同一台第三次：仍是 Duplicate（台数不涨）");
        CHECK (c.changes () == 1, "内容不同 → 改口次数 1");
        CHECK (c.at (0).uds == vin ("LSVSS0000S7654321"), "改口也不覆盖第一条正文");
        CHECK (c.at (0).duplicates == 2, "这台一共多答了 2 次");
    }

    // ---- D. 静默窗口：边界与推迟 ----
    {
        DiagResponseCollector c;
        c.add (0x0003, vin ("LSVZZ0000B7654321"), 1000);
        CHECK (!c.settled (1050, 100), "静默 50ms < 窗口 100ms，不能收工");
        CHECK (!c.settled (1099, 100), "静默 99ms，仍不能收工");
        CHECK (c.settled (1100, 100), "静默正好 100ms，可以收工（边界含等号）");
        CHECK (c.settled (1200, 100), "静默 200ms，可以收工");

        c.add (0x0006, vin ("LSVCC0000C7654321"), 1100);   // 又来一条
        CHECK (!c.settled (1150, 100), "新响应把收工时间往后推（静默重新算）");
        CHECK (c.quietMs (1150) == 50, "quietMs 从**最后一条**算起");
        CHECK (c.settled (1200, 100), "从 1100 起静默满 100ms 才收工");
    }

    // ---- E. 负响应也算答案 ----
    {
        DiagResponseCollector c;
        c.add (0x0003, vin ("LSVZZ0000B7654321"), 10);
        c.add (0x0006, bytes ({0x7F, 0x22, 0x31}), 20);
        CHECK (!c.at (0).negative (), "正响应：negative() 为假");
        CHECK (c.at (1).negative (), "0x7F 开头：negative() 为真");
        CHECK (c.count () == 2, "不支持 DID 的那台也算一条答案（不能当没答）");
    }

    // ---- F. 长报文逐字节 ----
    {
        std::vector<std::uint8_t> big{0x62, 0xF1, 0xA2};
        for (int i = 0; i < 197; ++i) big.push_back (static_cast<std::uint8_t> (i & 0xFF));
        DiagResponseCollector c;
        c.add (0x0006, big, 5);
        CHECK (c.at (0).uds.size () == 200, "200 字节一刀不少");
        CHECK (c.at (0).uds == big, "长报文逐字节相同");
    }

    // ---- G. 规模：20 台一起答 ----
    {
        DiagResponseCollector c;
        for (int i = 0; i < 20; ++i)
        {
            c.add (static_cast<std::uint16_t> (0x0E00 + i), bytes ({0x50, static_cast<int> (i)}), 100 + i);
        }
        CHECK (c.count () == 20, "20 台都能归档");
        CHECK (c.at (19).sa == 0x0E13, "第 20 条是最后加进去的那台");
        CHECK (c.find (0x0E00) != nullptr && c.find (0x0E13) != nullptr, "两头都能查到");
        CHECK (c.quietMs (119) == 0, "最后一条在 119，静默 0ms");
        CHECK (c.settled (219, 100), "20 台之后静默满窗口即可收工");
    }

    // ---- H. reset 之后从零开始 ----
    {
        DiagResponseCollector c;
        c.add (0x0003, vin ("LSVZZ0000B7654321"), 1);
        c.reset ();
        CHECK (c.count () == 0 && c.arrivals () == 0, "reset 清干净了");
        CHECK (c.quietMs (10) == -1, "reset 之后又变成「从来没响过」");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    if (gFail == 0)
        std::printf ("M11 的多响应配对逻辑全绿 —— 按 SA 归档、重复记数不覆盖、静默满窗口才收工。\n");
    return gFail == 0 ? 0 : 1;
}
