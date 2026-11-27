// ============================================================================
// doip_audit.cpp —— M29：把 ECU 流水里的"谁 F2"还原成"0x0E01 那台诊断仪"
//
// 两边各记一半：
//   ECU 的流水（--key-store 落盘的 DOIPKEYRING 4）：谁 = 0xF1..0xF8（CAN 源地址 = 位子）
//   网关的位子账（--slot-ledger 落盘的 DOIPSLOTS 1）：哪个 SA 在什么时间段占着哪个位子
// 拼起来才是"谁"。
//
// ★ 这一步的价值不在"能对上"，在"对不上时说什么"：
//   位子会回收。同一个位子在这次运行里被两台 SA 用过，"这条流水是谁干的"就没有唯一答案。
//   这时工具报**歧义 + 候选清单**并让 --strict 退出码非 0，而不是挑一个最像的。
//   宁可说"不知道"，也不要给一个查案时会把人带偏的答案。
//
// 用法：
//   doip-audit --key-store /tmp/ecu.txt --slot-ledger /tmp/gw_slots.txt [--strict]
//
// 退出码：0 = 没有歧义（含"谁=00 不知道"这种正常情况）
//         1 = 文件打不开 / 格式坏
//         2 = --strict 且存在歧义（或位子在账里查不到）
// ============================================================================
#include "KeyRingLog.h"
#include "KeyRingStore.h"
#include "SlotLedger.h"
#include "SourceSlot.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace doip;

static void usage (const char *me)
{
    std::fprintf (stderr,
                  "用法：%s --key-store <ECU 的钥匙表文件> [--slot-ledger <网关的位子账>] [--strict]\n"
                  "      --key-store  ：ECU --key-store 落下的文件（DOIPKEYRING 1/2/3/4）\n"
                  "      --slot-ledger：网关 --slot-ledger 落下的文件（DOIPSLOTS 1），没有就按\"查不到\"处理\n"
                  "      --strict     ：出现歧义或查不到时退出码 2（CI 用）\n",
                  me);
}

static std::string hex4 (std::uint16_t v)
{
    char buf[8];
    std::snprintf (buf, sizeof buf, "%04X", static_cast<unsigned> (v));
    return buf;
}

int main (int argc, char **argv)
{
    std::string keyStorePath;
    std::string ledgerPath;
    bool        strict = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--key-store" && i + 1 < argc)        keyStorePath = argv[++i];
        else if (a == "--slot-ledger" && i + 1 < argc) ledgerPath   = argv[++i];
        else if (a == "--strict")                      strict = true;
        else { usage (argv[0]); return 2; }
    }
    if (keyStorePath.empty ()) { usage (argv[0]); return 2; }

    // ---- ECU 那边：钥匙表 + 流水 ----
    const keys::LoadResult ec = keys::load (keyStorePath);
    if (ec.status != keys::LoadStatus::Ok)
    {
        std::fprintf (stderr, "钥匙表读不出来：%s\n", ec.why.c_str ());
        return 1;
    }

    // ---- 网关那边：位子租约账 ----
    slots::SlotLedger ledger;
    bool haveLedger = false;
    if (!ledgerPath.empty ())
    {
        std::string why;
        if (slots::SlotLedger::load (ledgerPath, ledger, why))
        {
            haveLedger = true;
        }
        else
        {
            // 账坏了不等于"这条流水没问题"：明确说出来，后面一律按"查不到"处理。
            std::fprintf (stderr, "位子账读不出来（%s）：位子一律按「查不到」处理\n", why.c_str ());
        }
    }

    std::printf ("ECU 流水：%s（%zu 条，版本 %s，第 %u 次上电）\n", keyStorePath.c_str (),
                 ec.log.size (), hex4 (ec.generation).c_str (), static_cast<unsigned> (ec.boot));
    if (!ec.why.empty ()) std::printf ("  注：%s\n", ec.why.c_str ());
    if (haveLedger)
        std::printf ("网关位子账：%s（%zu 条租约，未归还 %zu）\n", ledgerPath.c_str (), ledger.size (),
                     ledger.openCount ());
    else if (!ledgerPath.empty ())
        std::printf ("网关位子账：读不出来（见上一行）\n");
    else
        std::printf ("网关位子账：没给（--slot-ledger），下面凡是带位子的都会是「查不到」\n");

    if (ec.log.empty ())
    {
        std::printf ("结论：这条账上没有流水（出厂表，或者文件是 v1/v2）—— 没什么可对\n");
        return 0;
    }

    std::size_t nUnique = 0, nAmbiguous = 0, nUnknown = 0, nZero = 0;
    for (std::size_t i = 0; i < ec.log.size (); ++i)
    {
        const keys::LogEntry &e = ec.log.at (i);      // 0 = 最新
        std::printf ("\n第 %zu 条%s：%s 0x%s，%s，版本 %s，第 %u 次上电 +%us，谁 %02X\n",
                     i + 1, i == 0 ? "（最新）" : "",
                     keys::actName (e.act), hex4 (e.keyId).c_str (),
                     keys::channelName (e.channel), hex4 (e.generation).c_str (),
                     static_cast<unsigned> (e.boot), static_cast<unsigned> (e.seconds),
                     static_cast<unsigned> (e.actor));

        if (e.actor == 0)
        {
            ++nZero;
            std::printf ("  → 不知道是谁（00）：11 位帧没有源地址那一格 / 上电参数 / 这次没开 --stamp-sa\n");
            continue;
        }
        if (e.actor < slots::kSlotBase || e.actor > static_cast<std::uint8_t> (slots::kSlotBase + slots::kMaxSlots - 1))
        {
            ++nUnknown;
            std::printf ("  → 谁是 %02X 不在 0xF1..0xF8 里：这条流水不是这套位子机制写出来的\n",
                         static_cast<unsigned> (e.actor));
            continue;
        }

        const std::uint8_t slot = static_cast<std::uint8_t> (e.actor - slots::kSlotBase + 1);
        slots::Verdict v        = ledger.resolve (slot);
        if (!haveLedger) v.kind = slots::Verdict::Kind::Unknown;

        if (v.kind == slots::Verdict::Kind::Unique)
        {
            ++nUnique;
            std::printf ("  → 0x%s（位子 %u）\n", hex4 (v.sa).c_str (), static_cast<unsigned> (slot));
        }
        else if (v.kind == slots::Verdict::Kind::Ambiguous)
        {
            ++nAmbiguous;
            std::printf ("  → 歧义：位子 %u 在这次运行里被 %zu 台用过（", static_cast<unsigned> (slot),
                         v.candidates.size ());
            for (std::size_t k = 0; k < v.candidates.size (); ++k)
                std::printf ("%s0x%s", k ? " / " : "", hex4 (v.candidates[k]).c_str ());
            std::printf ("）—— 这条无法唯一还原\n");
        }
        else
        {
            ++nUnknown;
            std::printf ("  → 查不到：位子 %u 不在网关账里（网关没开 --slot-ledger？或账被截断了）\n",
                         static_cast<unsigned> (slot));
        }
    }

    std::printf ("\n结论：可唯一还原 %zu 条，歧义 %zu 条，查不到 %zu 条，"
                 "不知道（00）%zu 条（共 %zu 条）\n",
                 nUnique, nAmbiguous, nUnknown, nZero, ec.log.size ());
    if (nUnique == 0 && nAmbiguous == 0 && nUnknown == 0 && nZero > 0)
        std::printf ("  这一批全是 00：说明这次运行没有把「谁」送到 CAN 侧（或者那台 ECU 是 11 位寻址）。\n");
    if (nAmbiguous > 0)
        std::printf ("  歧义不是工具的缺陷，是位子会回收的必然结果：要对到人，得让位子带一个不可复用的编号，"
                     "或者干脆按连接记（那就要改协议）。\n");
    if (nUnknown > 0)
        std::printf ("  查不到的常见原因：网关这次没开 --slot-ledger，或者账只写了一半。\n");

    if (strict && (nAmbiguous > 0 || nUnknown > 0)) return 2;
    return 0;
}
