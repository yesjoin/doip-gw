// ============================================================================
// denymerge_selftest.cpp —— M34：多份越权账合并
//
// 钉六件事：
//   ① 同一组跨份累加次数，perRun 保住每份各几次（不是只有一个总和）；
//   ② 只在一份里出现的组，perRun 其余位是 0，runs() 报 1；
//   ③ 合并账不套单账 32 组上限（事后阅读不该再丢）；
//   ④ totalHits / dropped 都是各份相加；丢弃只进合计、不进按人按物；
//   ⑤ runsOfSa / runsOfDid 求并集（同一个人的多组试探分散在不同份里也算到）；
//   ⑥ from() 不改输入账（纯函数，合并完原件还能用）。
// ============================================================================
#include "DenyMerge.h"

#include <string>
#include <vector>

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
    const ops::Tier R = ops::Tier::Read, W = ops::Tier::Write, F = ops::Tier::Flash;

    // ---- A 跨份累加（8 项）----
    {
        deny::DenyLedger a, b, c;
        a.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 10);
        a.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 12);
        a.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 14);   // a：3 次
        b.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 5);
        b.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 6);
        b.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 7);
        b.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 8);    // b：4 次

        const std::vector<deny::DenyLedger> src = { a, b };
        const deny::MergedLedger m = deny::MergedLedger::from (src);

        CHECK (m.sources () == 2, "A1 记下了合并了几份（2）");
        CHECK (m.size () == 1, "A2 同一组跨份还是 1 条");
        CHECK (m.entries ()[0].count == 7, "A3 次数是各份之和（3+4=7）");
        CHECK (m.entries ()[0].perRun.size () == 2, "A4 perRun 长度 = 份数");
        CHECK (m.entries ()[0].perRun[0] == 3 && m.entries ()[0].perRun[1] == 4,
               "A5 每份各几次都留着（3 / 4），不是一个 7 糊过去");
        CHECK (m.entries ()[0].runs () == 2, "A6 这个组 2/2 份都出现过");
        CHECK (m.totalHits () == 7, "A7 合计 = 各份 totalHits 之和");
        CHECK (m.entries ()[0].why == deny::Reason::DidLevel && m.entries ()[0].did == 0xF1B0,
               "A8 原因与 DID 原样带过来");
    }

    // ---- B 只在一份出现（6 项）----
    {
        deny::DenyLedger a, b, c;
        a.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 1);          // a：0x0E00 0x2E
        c.note (0x0E01, 0x22, 0xF1B0, F, W, deny::Reason::DidLevel, 1);   // c：0x0E01 读钥匙表
        c.note (0x0E01, 0x22, 0xF1B0, F, W, deny::Reason::DidLevel, 2);   // c：2 次

        const std::vector<deny::DenyLedger> src = { a, b, c };
        const deny::MergedLedger m = deny::MergedLedger::from (src);

        CHECK (m.size () == 2, "B1 两份不同的组 → 2 条");
        CHECK (m.totalHits () == 3, "B2 合计 3 次");
        const deny::MergedEntry *e = m.worst ();
        CHECK (e != nullptr && e->sa == 0x0E01 && e->count == 2, "B3 worst 挑次数最多的（0x0E01 ×2）");
        CHECK (e != nullptr && e->perRun[0] == 0 && e->perRun[1] == 0 && e->perRun[2] == 2,
               "B4 只在一份里出现 → 其余位是 0（0/0/2）");
        CHECK (e != nullptr && e->runs () == 1, "B5 runs() 报 1（不是 3）");
        CHECK (m.entries ()[0].runs () == 1 && m.entries ()[0].perRun[0] == 1,
               "B6 先插入的那条（0x0E00 0x2E）只在第 1 份出现");
    }

    // ---- C 不套 32 组上限（5 项）----
    {
        deny::DenyLedger a, b;
        for (std::uint16_t i = 0; i < 40; ++i)                              // 40 组，超单账上限
            a.note (static_cast<std::uint16_t> (0x1000 + i), 0x22, 0, W, R, deny::Reason::OpTier, i);
        b.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 1);

        CHECK (a.size () == deny::DenyLedger::kMaxEntries, "C1 单账自己封顶在 32（丢最旧）");
        const std::vector<deny::DenyLedger> src = { a, b };
        const deny::MergedLedger m = deny::MergedLedger::from (src);
        CHECK (m.size () == 33, "C2 合并账保留全部 33 组（不套单账上限）");
        CHECK (m.totalHits () == a.totalHits () + 1, "C3 合计 = 账上留的 + 丢掉的 + 第二份的 1 次（40+1）");
        CHECK (m.droppedEntries () == a.droppedEntries (), "C4 丢弃组数原样带过来");
        CHECK (m.droppedHits () == a.droppedHits (), "C5 丢弃命中数原样带过来");
    }

    // ---- D 丢弃与来源（5 项）----
    {
        deny::DenyLedger a, b, c;
        for (std::uint16_t i = 0; i < 40; ++i)                              // a：33 组进门，丢 8 组
            a.note (static_cast<std::uint16_t> (0x2000 + i), 0x2E, 0, W, R, deny::Reason::OpTier, i);
        b.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 1);
        // c 是空账

        const std::vector<deny::DenyLedger> src = { a, b, c };
        const deny::MergedLedger m = deny::MergedLedger::from (src);

        CHECK (m.sources () == 3, "D1 一份空账也算一份来源");
        CHECK (m.sourcesWithDrop () == 1, "D2 只有 a 有丢弃 → 1 份");
        CHECK (m.droppedEntries () == a.droppedEntries () && m.droppedEntries () == 8,
               "D3 丢弃组数 = 8（40 进 32 留）");
        CHECK (m.droppedHits () == 8 && m.droppedHits () == a.droppedHits (),
               "D4 丢弃命中数 = 8（每组各 1 次）");
        CHECK (m.totalHits () == a.totalHits () + b.totalHits () + c.totalHits (),
               "D5 合计 = 各份 totalHits（含丢弃）精确相等");
    }

    // ---- E 按人按物求并集（6 项）----
    {
        deny::DenyLedger a, b, c;
        a.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 1);   // 第 1 份：0x0E00 → F1B0
        b.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 1);          // 第 2 份：0x0E00 → 非 DID
        c.note (0x0E00, 0x31, 0, F, R, deny::Reason::OpTier, 1);          // 第 3 份：0x0E00 → 0x31

        const std::vector<deny::DenyLedger> src = { a, b, c };
        const deny::MergedLedger m = deny::MergedLedger::from (src);

        CHECK (m.size () == 3, "E1 三组三条");
        CHECK (m.hitsOfSa (0x0E00) == 3, "E2 同一 SA 三组各 1 次 → 3 次");
        // 三组分散在三份账里，并集应该是 3/3 —— 取最大只会得到 1/3。
        CHECK (m.runsOfSa (0x0E00) == 3, "E3 runsOfSa 求并集（3/3），不是取最大（1/3）");
        CHECK (m.hitsOfDid (0xF1B0) == 1 && m.hitsOfDid (0) == 2, "E4 按对象：DID 1 次、非 DID 2 次");
        CHECK (m.runsOfDid (0xF1B0) == 1, "E5 钥匙表只在第 1 份出现过");
        CHECK (m.runsOfDid (0) == 2, "E6 非 DID 出现在第 2、3 份（并集 2）");
    }

    // ---- F 纯函数：不改原件（3 项）----
    {
        deny::DenyLedger a;
        a.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 1);
        const std::uint64_t before = a.totalHits ();
        const std::size_t   size0  = a.size ();
        const std::vector<deny::DenyLedger> src = { a };
        const deny::MergedLedger m = deny::MergedLedger::from (src);
        CHECK (m.size () == 1 && m.totalHits () == before, "F1 合并结果对单份也对得上");
        CHECK (a.totalHits () == before && a.size () == size0, "F2 合并没动原件");
        CHECK (m.entries ()[0].perRun.size () == 1 && m.entries ()[0].perRun[0] == 1,
               "F3 单份 perRun 就一格（1）");
    }

    std::printf ("通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
