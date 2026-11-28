// ============================================================================
// doip_deny.cpp —— M33/M34：读网关的越权账，回答"谁在试探什么"
//
// M30 / M31 挡回只打在 stdout，进程一停就没了；这个工具是"事后能查"的那一半。
//   doip-deny --ledger /tmp/deny.txt [--top 5]          一份账
//   doip-deny --merge a.txt b.txt c.txt [--top 5]       多份账 ← M34
//
// 单份账按三个方向汇总：
//   合计     —— 一共挡了多少次（含被丢弃的；丢弃单独报，因为一条记录可能带很多次）
//   按 SA    —— "哪台诊断仪一直在撞墙"（追人）
//   按 DID   —— "哪个数据被反复试探"（追对象：钥匙表、VIN…）
//   明细     —— 每条：谁 / 想什么 / 要哪档 / 有哪档 / 为什么 / 次数 / 时间窗
//
// 合并多份（M34）的区别只有一个，但很关键：
//   **只并计数、不并秒**。每份账的秒是那个进程自己的单调秒，跨运行不可比。
//   所以合并明细报的是"每份各几次"（5/3/0）而不是时间窗 ——
//   分布比总和更能看出"一直在撞"还是"只来过一次"。
//
// ★ 口径三处必须说清：
//   1) 账是**本次运行**的：单份时间秒不可跨进程比，合并账干脆不带秒。
//   2) 被丢弃的命中没有"是谁"：只进合计，不进按人/按物的汇总。
//   3) 一份坏就整次不合并：半份总账比没有账更危险。
//
// 退出码：0 = 读通（含空账：这次一次都没挡，也是正常结论）
//         1 = 文件打不开 / 格式坏 / 校验和不符（坏账绝不"差不多就行"）
//         2 = 用法不对
// ============================================================================
#include "DenyLedger.h"
#include "DenyMerge.h"
#include "DidPolicy.h"
#include "OpPermission.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static void usage (const char *me)
{
    std::fprintf (stderr,
                  "用法：%s --ledger <网关的越权账文件> [--top N]\n"
                  "      %s --merge <账1> <账2> ... [--top N]\n"
                  "      --ledger：单份账（一次运行）\n"
                  "      --merge ：多份账合并（只看计数分布，时间秒不可跨运行比）\n"
                  "      --top   ：明细里最多列前 N 条（按次数降序），默认全部\n",
                  me, me);
}

// 单份账的正文（M33）。
static int printOne (const std::string &path, deny::DenyLedger &L, long top)
{
    std::printf ("越权账：%s\n", path.c_str ());
    if (L.size () == 0)
    {
        std::printf ("  本次运行没有挡回任何请求（这是结论，不是文件坏了）\n");
        return 0;
    }

    std::printf ("合计：%llu 次挡回，%zu 条记录", static_cast<unsigned long long> (L.totalHits ()),
                 L.size ());
    if (L.droppedEntries () > 0)
        std::printf ("；账满丢了 %zu 条（连带 %zu 次命中，已计入合计但不计入下面按人/按物）",
                     L.droppedEntries (), L.droppedHits ());
    std::printf ("\n");

    std::printf ("按 SA（谁在撞墙）：\n");
    {
        std::vector<std::uint16_t> sas;
        for (const auto &e : L.entries ())
        {
            bool seen = false;
            for (std::uint16_t s : sas) if (s == e.sa) seen = true;
            if (!seen) sas.push_back (e.sa);
        }
        for (std::size_t i = 0; i + 1 < sas.size (); ++i)
            for (std::size_t j = 0; j + 1 < sas.size () - i; ++j)
                if (L.hitsOfSa (sas[j]) < L.hitsOfSa (sas[j + 1]))
                {
                    const std::uint16_t t = sas[j];
                    sas[j] = sas[j + 1];
                    sas[j + 1] = t;
                }
        for (std::uint16_t s : sas)
            std::printf ("  0x%04X：%llu 次\n", static_cast<unsigned> (s),
                         static_cast<unsigned long long> (L.hitsOfSa (s)));
    }

    std::printf ("按对象（被试探的是谁）：\n");
    {
        std::vector<std::uint16_t> dids;
        for (const auto &e : L.entries ())
        {
            bool seen = false;
            for (std::uint16_t d : dids) if (d == e.did) seen = true;
            if (!seen) dids.push_back (e.did);
        }
        for (std::size_t i = 0; i + 1 < dids.size (); ++i)
            for (std::size_t j = 0; j + 1 < dids.size () - i; ++j)
                if (L.hitsOfDid (dids[j]) < L.hitsOfDid (dids[j + 1]))
                {
                    const std::uint16_t t = dids[j];
                    dids[j] = dids[j + 1];
                    dids[j + 1] = t;
                }
        for (std::uint16_t d : dids)
        {
            const std::string label =
                d != 0 ? "DID " + dids::hex4 (d) + "（" + dids::didName (d) + "）"
                       : "非 DID 请求（0x2E/0x34/0x31…）";
            std::printf ("  %s：%llu 次\n", label.c_str (),
                         static_cast<unsigned long long> (L.hitsOfDid (d)));
        }
    }

    std::printf ("明细（按次数从多到少）：\n");
    {
        std::vector<deny::Entry> rows = L.entries ();
        for (std::size_t i = 0; i + 1 < rows.size (); ++i)
            for (std::size_t j = 0; j + 1 < rows.size () - i; ++j)
                if (rows[j].count < rows[j + 1].count)
                {
                    const deny::Entry t = rows[j];
                    rows[j] = rows[j + 1];
                    rows[j + 1] = t;
                }
        const std::size_t n = (top >= 0 && static_cast<std::size_t> (top) < rows.size ())
                                  ? static_cast<std::size_t> (top)
                                  : rows.size ();
        for (std::size_t i = 0; i < n; ++i)
        {
            const deny::Entry &e = rows[i];
            const std::string obj = e.did != 0 ? "DID " + dids::hex4 (e.did) + "（" + dids::didName (e.did) + "）"
                                               : "—";
            std::printf ("  0x%04X 想 0x%02X  %s  %s ×%llu  （本次运行第 %u–%u 秒）\n",
                         static_cast<unsigned> (e.sa), static_cast<unsigned> (e.sid), obj.c_str (),
                         deny::reasonName (e.why), static_cast<unsigned long long> (e.count),
                         static_cast<unsigned> (e.firstSec), static_cast<unsigned> (e.lastSec));
        }
        if (n < rows.size ())
            std::printf ("  …另有 %zu 条未列出（--top 只截明细，上面的汇总仍是全量）\n",
                         rows.size () - n);
    }
    return 0;
}

// 多份合并的正文（M34）。
static int printMerge (const std::vector<std::string> &paths, long top)
{
    deny::MergedLedger M;
    std::vector<std::size_t> bad;
    std::string why;
    if (!deny::MergedLedger::loadAll (paths, M, bad, why))
    {
        // 一份坏就不合并：半份总账比没有账更危险（会让人以为"就这些"）。
        std::fprintf (stderr, "越权账合并失败：%s\n", why.c_str ());
        std::fprintf (stderr, "  %zu 份里有 %zu 份读不出来；坏账不参与合并，整份结果也不给\n",
                      paths.size (), bad.size ());
        return 1;
    }

    std::printf ("越权账合并：%zu 份\n", M.sources ());
    if (M.size () == 0)
    {
        std::printf ("  这 %zu 份账里都没有挡回记录（这是结论，不是文件坏了）\n", M.sources ());
        return 0;
    }

    std::printf ("合计：%llu 次挡回，%zu 组记录（合并账不套单账 %zu 组上限）\n",
                 static_cast<unsigned long long> (M.totalHits ()), M.size (),
                 deny::DenyLedger::kMaxEntries);
    if (M.droppedEntries () > 0)
        std::printf ("  其中 %zu/%zu 份账有丢弃，共丢 %zu 组 / %zu 次命中（只进合计，不进按人/按物）\n",
                     M.sourcesWithDrop (), M.sources (), M.droppedEntries (), M.droppedHits ());
    // 这句是 M34 最重要的口径：合并只并计数，不并秒。
    std::printf ("  时间：只并计数、不并秒 —— 各份的秒是各自进程的单调秒，跨运行不是同一时刻\n");

    std::printf ("按 SA（谁在撞墙）：\n");
    {
        std::vector<std::uint16_t> sas;
        for (const auto &e : M.entries ())
        {
            bool seen = false;
            for (std::uint16_t s : sas) if (s == e.sa) seen = true;
            if (!seen) sas.push_back (e.sa);
        }
        for (std::size_t i = 0; i + 1 < sas.size (); ++i)
            for (std::size_t j = 0; j + 1 < sas.size () - i; ++j)
                if (M.hitsOfSa (sas[j]) < M.hitsOfSa (sas[j + 1]))
                {
                    const std::uint16_t t = sas[j];
                    sas[j] = sas[j + 1];
                    sas[j + 1] = t;
                }
        for (std::uint16_t s : sas)
            std::printf ("  0x%04X：%llu 次（出现于 %zu/%zu 份）\n", static_cast<unsigned> (s),
                         static_cast<unsigned long long> (M.hitsOfSa (s)), M.runsOfSa (s),
                         M.sources ());
    }

    std::printf ("按对象（被试探的是谁）：\n");
    {
        std::vector<std::uint16_t> dids;
        for (const auto &e : M.entries ())
        {
            bool seen = false;
            for (std::uint16_t d : dids) if (d == e.did) seen = true;
            if (!seen) dids.push_back (e.did);
        }
        for (std::size_t i = 0; i + 1 < dids.size (); ++i)
            for (std::size_t j = 0; j + 1 < dids.size () - i; ++j)
                if (M.hitsOfDid (dids[j]) < M.hitsOfDid (dids[j + 1]))
                {
                    const std::uint16_t t = dids[j];
                    dids[j] = dids[j + 1];
                    dids[j + 1] = t;
                }
        for (std::uint16_t d : dids)
        {
            const std::string label =
                d != 0 ? "DID " + dids::hex4 (d) + "（" + dids::didName (d) + "）"
                       : "非 DID 请求（0x2E/0x34/0x31…）";
            std::printf ("  %s：%llu 次（出现于 %zu/%zu 份）\n", label.c_str (),
                         static_cast<unsigned long long> (M.hitsOfDid (d)), M.runsOfDid (d),
                         M.sources ());
        }
    }

    std::printf ("明细（按次数从多到少；括号里是每份各几次）：\n");
    {
        std::vector<deny::MergedEntry> rows = M.entries ();
        for (std::size_t i = 0; i + 1 < rows.size (); ++i)
            for (std::size_t j = 0; j + 1 < rows.size () - i; ++j)
                if (rows[j].count < rows[j + 1].count)
                {
                    const deny::MergedEntry t = rows[j];
                    rows[j] = rows[j + 1];
                    rows[j + 1] = t;
                }
        const std::size_t n = (top >= 0 && static_cast<std::size_t> (top) < rows.size ())
                                  ? static_cast<std::size_t> (top)
                                  : rows.size ();
        for (std::size_t i = 0; i < n; ++i)
        {
            const deny::MergedEntry &e = rows[i];
            const std::string obj = e.did != 0 ? "DID " + dids::hex4 (e.did) + "（" + dids::didName (e.did) + "）"
                                               : "—";
            std::string dist;
            for (std::size_t k = 0; k < e.perRun.size (); ++k)
                dist += (k == 0 ? "" : "/") + std::to_string (e.perRun[k]);
            std::printf ("  0x%04X 想 0x%02X  %s  %s ×%llu  （每份：%s）\n",
                         static_cast<unsigned> (e.sa), static_cast<unsigned> (e.sid), obj.c_str (),
                         deny::reasonName (e.why), static_cast<unsigned long long> (e.count),
                         dist.c_str ());
        }
        if (n < rows.size ())
            std::printf ("  …另有 %zu 条未列出（--top 只截明细，上面的汇总仍是全量）\n",
                         rows.size () - n);
    }
    return 0;
}

int main (int argc, char **argv)
{
    std::string              path;
    std::vector<std::string> mergePaths;
    long                     top = -1;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--ledger" && i + 1 < argc)
            path = argv[++i];
        else if (a == "--merge")
        {
            // --merge 后面到下一个 -- 开关之间全是路径（文件名以 - 开头极少，不处理）。
            while (i + 1 < argc && argv[i + 1][0] != '-') mergePaths.push_back (argv[++i]);
        }
        else if (a == "--top" && i + 1 < argc)
        {
            bool ok = true;
            long v = 0;
            for (const char *p = argv[i + 1]; *p != '\0'; ++p)
            {
                if (*p < '0' || *p > '9') { ok = false; break; }
                v = v * 10 + (*p - '0');
                if (v > 1000000) { ok = false; break; }
            }
            if (!ok || v <= 0) { usage (argv[0]); return 2; }
            top = v;
            ++i;
        }
        else { usage (argv[0]); return 2; }
    }

    if (path.empty () && mergePaths.empty ()) { usage (argv[0]); return 2; }
    if (!path.empty () && !mergePaths.empty ())
    {
        std::fprintf (stderr, "--ledger 与 --merge 只能选一个（一份还是多份，口径不同）\n");
        usage (argv[0]);
        return 2;
    }

    if (!mergePaths.empty ()) return printMerge (mergePaths, top);

    deny::DenyLedger L;
    std::string why;
    if (!deny::DenyLedger::load (path, L, why))
    {
        // 坏账不猜：宁可让人去查文件，也不要拿一份"差不多"的账去追责。
        std::fprintf (stderr, "越权账读不出来：%s\n", why.c_str ());
        return 1;
    }
    return printOne (path, L, top);
}
