// ============================================================================
// preconditions_selftest.cpp —— M19 自测：DID 表（0x22 / 0x2E）+ 前置条件检查（0x31 01 0203）
//
// 这段不碰 socket、不碰 CAN，只验"纯逻辑"：
//   A. DidTable 读：五个 DID 的字节形状、电压大端、指纹大端、不认识的 DID
//   B. DidTable 写：只读 DID → 0x31；长度不对 → 0x13；正常 → 6E F1 84 且读回一致
//   C. 前置条件：四条规则逐条过、任意一条不过就整体不过、边界值（门槛正好等于）
// ============================================================================
#include "DidTable.h"
#include "FlashPreconditions.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

int gChecks = 0;
int gFails  = 0;

void check (bool ok, const std::string &what)
{
    ++gChecks;
    if (!ok) ++gFails;
    std::printf ("%s %s\n", ok ? "[ OK ]" : "[FAIL]", what.c_str ());
}

std::string hex (const std::vector<std::uint8_t> &b)
{
    std::string s;
    char t[4];
    for (std::size_t i = 0; i < b.size (); ++i)
    {
        std::snprintf (t, sizeof t, "%02X", b[i]);
        if (i) s += ' ';
        s += t;
    }
    return s;
}

std::vector<std::uint8_t> bytes (std::initializer_list<int> v)
{
    std::vector<std::uint8_t> r;
    for (int x : v) r.push_back (static_cast<std::uint8_t> (x));
    return r;
}

} // namespace

int main ()
{
    std::printf ("=== M19 前置条件 / DID 表 自测 ===\n\n");
    std::string why;

    // ---------------- A. 读 ----------------
    std::printf ("A. 0x22 readDataByIdentifier\n");
    {
        doip::DidTable d ("PART-ABC1234", "SW-1.0.3", "ECU-A-0007", 0x00000000u, 12400);
        std::vector<std::uint8_t> r;

        // 先读、再判、再拼日志：把 read 和 hex 写在同一个表达式里，
        // 求值顺序不确定，日志会打出上一次的 r（这里已经吃过一次这个亏）。
        const bool ok187 = d.read (0xF187, r, why);
        check (ok187 && r.size () == 3 + 12 && r[0] == 0x62 && r[1] == 0xF1 && r[2] == 0x87,
               "A1 读 F187 零件号：62 F1 87 + 12 字节 ASCII（" + hex (r) + "）");
        check (r.size () > 3 && r[3] == 'P' && r[14] == '4', "A2 零件号首尾字节对得上（P…4）");

        const bool ok188 = d.read (0xF188, r, why);
        check (ok188 && r.size () == 3 + 8 && r[3] == 'S',
               "A3 读 F188 软件版本：62 F1 88 + 8 字节（" + hex (r) + "）");
        const bool ok18C = d.read (0xF18C, r, why);
        check (ok18C && r.size () == 3 + 10 && r[3] == 'E',
               "A4 读 F18C 序列号：62 F1 8C + 10 字节（" + hex (r) + "）");

        const bool okVolt = d.read (0xF1A5, r, why);
        check (okVolt && r.size () == 5 && r[3] == 0x30 && r[4] == 0x70,
               "A5 读 F1A5 电压 12400 mV → 30 70（大端，能手算：0x3070=12400）");

        const bool okFp = d.read (0xF184, r, why);
        check (okFp && r.size () == 7 && r[3] == 0 && r[6] == 0,
               "A6 读 F184 指纹初始 0x00000000 → 00 00 00 00（" + hex (r) + "）");

        check (!d.read (0xF1A4, r, why), "A7 不认识的 DID（F1A4）→ read 返回 false（由调用方回 7F 22 31）");

        // 电压换一个：1000 mV = 0x03E8，9812 mV = 0x2654
        doip::DidTable low ("P", "S", "N", 0, 9812);
        check (low.read (0xF1A5, r, why) && r[3] == 0x26 && r[4] == 0x54,
               "A8 9812 mV → 26 54（不是 98 12 —— 这是 u16 大端，量纲是 mV）");
    }

    // ---------------- B. 写 ----------------
    std::printf ("\nB. 0x2E writeDataByIdentifier\n");
    {
        doip::DidTable d ("PART-ABC1234", "SW-1.0.3", "ECU-A-0007", 0x00000000u, 12400);

        std::vector<std::uint8_t> r;
        // 只读 DID 也想写
        check (d.write (0xF187, bytes ({1, 2, 3, 4}), r, why) && r.size () == 3 && r[0] == 0x7F &&
               r[1] == 0x2E && r[2] == doip::kNrcRequestOutOfRange,
               "B1 写只读 DID F187 → 7F 2E 31（找错对象，不是数据错）");

        // 长度不对
        check (d.write (0xF184, bytes ({0xA1, 0xB2, 0xC3}), r, why) && r.size () == 3 &&
               r[0] == 0x7F && r[1] == 0x2E && r[2] == doip::kNrcIncorrectLength,
               "B2 写 F184 只给 3 字节 → 7F 2E 13（这才是数据错）");

        // 正常写
        const auto ok = d.write (0xF184, bytes ({0xA1, 0xB2, 0xC3, 0xD4}), r, why);
        check (ok && r.size () == 3 && r[0] == 0x6E && r[1] == 0xF1 && r[2] == 0x84,
               "B3 写 F184 4 字节 → 6E F1 84（" + hex (r) + "）");
        check (d.fingerprint () == 0xA1B2C3D4u, "B4 指纹变成 0xA1B2C3D4（按大端拼：A1 是最高位）");

        std::vector<std::uint8_t> rd;
        check (d.read (0xF184, rd, why) && rd.size () == 7 && rd[3] == 0xA1 && rd[6] == 0xD4,
               "B5 写完之后读回来是 A1 B2 C3 D4（跨请求保存，不是回显）");

        // 再写一次，覆盖
        check (d.write (0xF184, bytes ({0, 0, 0, 1}), r, why) && d.fingerprint () == 1u,
               "B6 再写 00 00 00 01 → 指纹被覆盖成 1（不是累加）");
    }

    // ---------------- C. 前置条件 ----------------
    std::printf ("\nC. 0x31 01 0203 checkProgrammingPreconditions\n");
    {
        doip::Preconditions p;
        p.batteryMv = 12400;
        p.programmingSession = true;
        p.unlocked = true;
        p.downloadActive = false;

        const auto all = doip::checkProgrammingPreconditions (p);
        check (all.ok, "C1 四条全过 → ok=true（" + all.summary () + "）");
        check (all.items.size () == 4, "C2 恰好四条检查项，日志能逐条打出来");

        p.batteryMv = 11499;
        const auto low = doip::checkProgrammingPreconditions (p);
        check (!low.ok, "C3 电压 11499 < 门槛 11500 → ok=false");
        check (!low.items[0].ok && low.items[1].ok && low.items[2].ok && low.items[3].ok,
               "C4 只有电压这一条是 ✗，别的仍是 ✓（不能一票把全部染红）");

        p.batteryMv = 11500;
        check (doip::checkProgrammingPreconditions (p).ok, "C5 边界：正好 11500 mV 算过（≥ 不是 >）");

        p.batteryMv = 12400;
        p.programmingSession = false;
        const auto noSess = doip::checkProgrammingPreconditions (p);
        check (!noSess.ok && !noSess.items[1].ok, "C6 默认会话 → 不过，且原因指向会话（" +
               noSess.items[1].what + "）");

        p.programmingSession = true;
        p.unlocked = false;
        check (!doip::checkProgrammingPreconditions (p).ok,
               "C7 编程会话但没解锁 → 不过（会话对了不等于能刷）");

        p.unlocked = true;
        p.downloadActive = true;
        check (!doip::checkProgrammingPreconditions (p).ok,
               "C8 已经在 0x34–0x37 之间下载 → 不过（别在下载中途再问一次）");

        p.downloadActive = false;
        p.batteryMv = 9000;
        p.unlocked = false;
        const auto multi = doip::checkProgrammingPreconditions (p);
        check (!multi.ok && !multi.items[0].ok && !multi.items[2].ok && multi.items[1].ok,
               "C9 三条坏两条：电压 ✗ + 未解锁 ✗ 同时出现，日志要能看全（" + multi.summary () + "）");

        check (all.summary ().find ('\xE2') != std::string::npos,
               "C10 summary 里带 ✓/✗（UTF-8 三字节，E2 开头），终端能看出哪条不过");
    }

    std::printf ("\n结果：%d 项，失败 %d 项\n", gChecks, gFails);
    return gFails == 0 ? 0 : 1;
}
