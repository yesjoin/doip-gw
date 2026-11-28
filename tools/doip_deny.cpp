// ============================================================================
// doip_deny.cpp —— M33：读一份网关的越权账（DOIPDENY 1），回答"谁在试探什么"
//
// M30 / M31 挡回只打在 stdout，进程一停就没了；这个工具就是"事后能查"的那一半。
//   doip-deny --ledger /tmp/deny.txt [--top 5]
//
// 它按三个方向汇总同一份账：
//   合计     —— 一共挡了多少次（含被丢弃的；丢弃单独报，因为一条记录可能带很多次）
//   按 SA    —— "哪台诊断仪一直在撞墙"（追人）
//   按 DID   —— "哪个数据被反复试探"（追对象：钥匙表、VIN…）
//   明细     —— 每条：谁 / 想什么 / 要哪档 / 有哪档 / 为什么 / 次数 / 时间窗
//
// ★ 口径两处必须说清，否则会被误读：
//   1) 账是**本次运行**的：时间秒是进程单调秒，跨进程不可比。所以只报"第一次到第几次
//      之间的相对跨度"，不报绝对时刻。
//   2) 被丢弃的命中没有"是谁"：它们的信息已经没了，只进合计，不进按人/按物的汇总。
//
// 退出码：0 = 读通（含空账：这次运行一次都没挡，也是正常结论）
//         1 = 文件打不开 / 格式坏 / 校验和不符（坏账绝不"差不多就行"）
//         2 = 用法不对
// ============================================================================
#include "DenyLedger.h"
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
                  "      --ledger：网关 --deny-ledger 落下的文件（DOIPDENY 1）\n"
                  "      --top   ：明细里最多列前 N 条（按次数降序），默认全部\n",
                  me);
}

int main (int argc, char **argv)
{
    std::string path;
    long        top = -1;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--ledger" && i + 1 < argc)
            path = argv[++i];
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
    if (path.empty ()) { usage (argv[0]); return 2; }

    deny::DenyLedger L;
    std::string why;
    if (!deny::DenyLedger::load (path, L, why))
    {
        // 坏账不猜：宁可让人去查文件，也不要拿一份"差不多"的账去追责。
        std::fprintf (stderr, "越权账读不出来：%s\n", why.c_str ());
        return 1;
    }

    std::printf ("越权账：%s\n", path.c_str ());
    if (L.size () == 0)
    {
        std::printf ("  本次运行没有挡回任何请求（这是结论，不是文件坏了）\n");
        return 0;
    }

    // ---- 合计 ----
    std::printf ("合计：%llu 次挡回，%zu 条记录", static_cast<unsigned long long> (L.totalHits ()),
                 L.size ());
    if (L.droppedEntries () > 0)
        std::printf ("；账满丢了 %zu 条（连带 %zu 次命中，已计入合计但不计入下面按人/按物）",
                     L.droppedEntries (), L.droppedHits ());
    std::printf ("\n");

    // ---- 按 SA ----
    std::printf ("按 SA（谁在撞墙）：\n");
    {
        // 账接口没给"枚举 SA"，这里从记录里收一份不重复的（最多 32 条，无所谓效率）。
        std::vector<std::uint16_t> sas;
        for (const auto &e : L.entries ())
        {
            bool seen = false;
            for (std::uint16_t s : sas) if (s == e.sa) seen = true;
            if (!seen) sas.push_back (e.sa);
        }
        // 次数多的排前面。
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

    // ---- 按 DID ----
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

    // ---- 明细（按次数降序；次数相同按"先出现的"） ----
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
            // 时间窗报"跨度"而不是绝对时刻：跨进程的秒不可比。
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
