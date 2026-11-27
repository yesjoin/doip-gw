// ============================================================================
// slotledger_selftest.cpp —— M29：位子租约账
//
// 要钉住的三件事：
//   ① 记账要照实（同一台重连是两条、还错的要留痕、满了丢最旧的要知道丢了）；
//   ② 判"谁"只有三态：唯一 / 歧义 / 查不到 —— **绝不猜**；
//   ③ 落盘要能自证（定长 36、版本行、校验和，任一不对就判坏）。
// ============================================================================
#include "SlotLedger.h"

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
    std::printf ("=== A 记账基本 ===\n");
    {
        slots::SlotLedger L;
        CHECK (L.size () == 0 && L.openCount () == 0, "A1 新账是空的");

        L.noteTake (1, 0x0E00, 1, 10);
        CHECK (L.size () == 1 && L.openCount () == 1, "A2 借一个位子 → 一条 open 租约");
        CHECK (L.leases ()[0].slot == 1 && L.leases ()[0].sa == 0x0E00 && L.leases ()[0].conn == 1,
               "A3 记下了槽、SA、连接号");

        CHECK (L.noteRelease (1, 0x0E00, 20), "A4 归还成功");
        CHECK (L.size () == 1 && L.openCount () == 0, "A5 归还后仍是一条租约（历史不删，只关掉）");
        CHECK (L.leases ()[0].freeSec == 20 && !L.leases ()[0].open, "A6 归还秒与状态都记上了");

        CHECK (!L.noteRelease (1, 0x0E00, 30), "A7 还一个已经还过的 → false（不静默成功）");
        CHECK (L.orphanReleases () == 1, "A8 多还那一次留了痕（账要能查出自己不对）");

        // 同一台诊断仪断线重连：两条租约，不合并
        slots::SlotLedger R;
        R.noteTake (1, 0x0E00, 1, 10);
        R.noteRelease (1, 0x0E00, 20);
        R.noteTake (1, 0x0E00, 2, 30);
        CHECK (R.size () == 2, "A9 同一台重连 → 两条租约（几次本身是信息，不能合并）");
        CHECK (R.ownersOf (1).size () == 1, "A10 但只有一台 SA（判谁时不因次数变歧义）");
    }

    std::printf ("\n=== B 判「谁」：三态，不猜 ===\n");
    {
        slots::SlotLedger L;
        CHECK (L.resolve (1).kind == slots::Verdict::Kind::Unknown, "B1 空账 → 查不到");

        L.noteTake (2, 0x0E01, 1, 10);
        const slots::Verdict v = L.resolve (2);
        CHECK (v.kind == slots::Verdict::Kind::Unique && v.sa == 0x0E01, "B2 只有一台用过 → 唯一，且给得出 SA");
        CHECK (L.resolve (1).kind == slots::Verdict::Kind::Unknown, "B3 别的槽不受影响");

        // 位子回收：1 号先给 0x0E00，还给另一台 0x0E02
        L.noteTake (1, 0x0E00, 2, 20);
        L.noteRelease (1, 0x0E00, 25);
        L.noteTake (1, 0x0E02, 3, 30);
        const slots::Verdict a = L.resolve (1);
        CHECK (a.kind == slots::Verdict::Kind::Ambiguous, "B4 同一槽先后两台 → 歧义");
        CHECK (a.candidates.size () == 2 && a.candidates[0] == 0x0E00 && a.candidates[1] == 0x0E02,
               "B5 候选按出现顺序、去重");

        // 哪怕两台都已经还了，历史仍然算数：这就是"不猜"的意思
        L.noteRelease (1, 0x0E02, 35);
        CHECK (L.resolve (1).kind == slots::Verdict::Kind::Ambiguous,
               "B6 都归还了也还是歧义（账记的是历史，不是此刻谁占着）");
        CHECK (L.openCount () == 1, "B7 此刻只有 2 号位子还占着（1 号两位住户都已归还，和 B6 并不矛盾）");

        CHECK (std::string (slots::verdictName (slots::Verdict::Kind::Ambiguous)) == "歧义",
               "B8 三种结论各有名字（日志和审计输出共用一套词）");    }

    std::printf ("\n=== C 满了绕圈 ===\n");
    {
        slots::SlotLedger L;
        for (int i = 0; i < 70; ++i)
            L.noteTake (static_cast<std::uint8_t> (i % 8 + 1), static_cast<std::uint16_t> (0x0E00 + i),
                        static_cast<std::uint32_t> (i + 1), static_cast<std::uint32_t> (i));
        CHECK (L.size () == slots::SlotLedger::kMaxLeases, "C1 超出容量后停在 64 条");
        CHECK (L.dropped () == 70 - slots::SlotLedger::kMaxLeases, "C2 丢了几条要记下来（不是悄悄丢）");
        CHECK (L.leases ()[0].sa == 0x0E00 + 6, "C3 丢的是最旧的那几条（留下的是后 64 条）");
    }

    std::printf ("\n=== D 落盘格式 ===\n");
    {
        slots::SlotLedger L;
        L.noteTake (1, 0x0E00, 1, 10);
        L.noteRelease (1, 0x0E00, 20);
        L.noteTake (2, 0x0E01, 2, 30);      // 这条没还

        const std::string t = L.text ();
        CHECK (t.compare (0, 12, "DOIPSLOTS 1\n") == 0, "D1 第一行是版本行");
        CHECK (t.find ("SUM ") != std::string::npos, "D2 末尾有校验和");

        const std::size_t nl1 = t.find ('\n');
        const std::size_t nl2 = t.find ('\n', nl1 + 1);
        const std::string line1 = t.substr (nl1 + 1, nl2 - nl1 - 1);
        CHECK (line1.size () == 36, "D3 P 行定长 36 字符");
        CHECK (line1.compare (0, 9, "P 01 0E00") == 0, "D4 槽与 SA 在前");
        CHECK (line1.compare (28, 8, "00000014") == 0, "D5 归还秒在最右（20 = 0x14）");

        const std::size_t nl3 = t.find ('\n', nl2 + 1);
        const std::string line2 = t.substr (nl2 + 1, nl3 - nl2 - 1);
        CHECK (line2.size () == 36 && line2.compare (28, 8, "--------") == 0,
               "D6 没还的租约，归还段是 8 个减号（定长不破）");

        slots::SlotLedger back;
        std::string whyBack;
        const bool okBack = slots::SlotLedger::parse (t, back, whyBack);
        CHECK (okBack && back.size () == 2, "D7 自己写出来的能读回来");
        CHECK (back.openCount () == 1 && back.leases ()[0].sa == 0x0E00 &&
                   back.leases ()[1].sa == 0x0E01,
               "D8 槽、SA、开关状态一个不差");
        CHECK (back.resolve (1).kind == slots::Verdict::Kind::Unique, "D9 读回来还能判谁");

        auto bad = [] (const std::string &txt) -> bool {
            slots::SlotLedger j;
            std::string        w;
            return !slots::SlotLedger::parse (txt, j, w);
        };

        // ---- 坏文件：校验和对但形状不对 / 校验和不对 ----
        std::string bad35 = t;
        const std::size_t p = bad35.find ("P 01 0E00");
        bad35.erase (p + 20, 1);      // 砍掉一个字符 → 35 字符
        // 重算校验和，让它坏在"形状"而不是"校验和"
        const std::size_t sumAt = bad35.find ("SUM ");
        const std::string body = bad35.substr (0, sumAt);
        bad35 = body + "SUM " + keys::checksumOf (body) + "\n";
        CHECK (bad (bad35), "D10 P 行 35 字符 → 判坏（定长就是定长）");

        std::string badSum = t;
        badSum[badSum.size () - 2] = (badSum[badSum.size () - 2] == 'a') ? 'b' : 'a';
        CHECK (bad (badSum), "D11 校验和改一位 → 判坏");

        std::string badVer = t;
        badVer.replace (0, 12, "DOIPSLOTS 2\n");
        CHECK (bad (badVer), "D12 版本行不认识 → 判坏（只认 1）");

        std::string badSlot = t;
        const std::size_t q = badSlot.find ("P 01 0E00");
        badSlot.replace (q + 2, 2, "09");
        const std::size_t s2 = badSlot.find ("SUM ");
        const std::string body2 = badSlot.substr (0, s2);
        badSlot = body2 + "SUM " + keys::checksumOf (body2) + "\n";
        CHECK (bad (badSlot), "D13 位子 09 越界 → 判坏");

        std::string cut = t.substr (0, t.find ("SUM "));   // 只有版本行 + P 行，没有 SUM
        CHECK (bad (cut), "D14 半截文件（缺 SUM）→ 判坏");
    }

    std::printf ("\n=== E 文件往返 ===\n");
    {
        const std::string path = "/tmp/m29_selftest_slots.txt";
        std::remove (path.c_str ());
        slots::SlotLedger L;
        L.noteTake (3, 0x0E02, 9, 100);
        L.noteRelease (3, 0x0E02, 110);
        L.noteTake (3, 0x0E00, 10, 120);

        std::string why;
        CHECK (L.save (path, why), "E1 写盘成功");
        slots::SlotLedger onDisk;
        std::string whyDisk;
        const bool okDisk = slots::SlotLedger::load (path, onDisk, whyDisk);
        CHECK (okDisk && onDisk.size () == 2, "E2 从盘上读回来两条");
        CHECK (onDisk.resolve (3).kind == slots::Verdict::Kind::Ambiguous,
               "E3 盘上读回来的账照样判得出歧义（这是对账工具真正用到的那条路）");
        std::remove (path.c_str ());
    }

    std::printf ("\n=== F 时间 ===\n");
    {
        const std::uint32_t t0 = slots::nowSec ();
        const std::uint32_t t1 = slots::nowSec ();
        CHECK (t1 >= t0, "F1 单调秒不会倒退（账里的先后顺序靠它）");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
