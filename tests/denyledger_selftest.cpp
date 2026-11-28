// ============================================================================
// denyledger_selftest.cpp —— M33：越权账（聚合 / 上限 / 定长落盘 / 判坏）
//
// 钉五件事：
//   ① 同一组 (SA, 服务号, DID, 需档, 有档, 原因) 聚合成一条，只累加次数；
//   ② 满了丢最旧，但"丢几条记录"和"丢几次命中"是两个数，都要报；
//   ③ 落盘定长 47、带 SUM、往返一致，坏文件一律判坏（含"次数是 0"这种形状对但没意义）；
//   ④ 汇总口径：totalHits 含丢弃，hitsOfSa/hitsOfDid 只算账上的（丢掉的连"是谁"都没了）；
//   ⑤ 次数是**十进制**那一格：10 次读回来必须是 10，不是 16（这一组是真抓过 bug 的）。
// ============================================================================
#include "DenyLedger.h"

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

    // ---- A 聚合（10 项）----
    {
        deny::DenyLedger L;
        CHECK (L.size () == 0 && L.totalHits () == 0, "A1 空账：0 条、0 次");

        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 100);
        CHECK (L.size () == 1 && L.entries ()[0].count == 1, "A2 第一次记下就是 1 次");
        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 103);
        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 107);
        CHECK (L.size () == 1 && L.entries ()[0].count == 3, "A3 同一组 3 次 → 1 条 3 次（聚合）");
        CHECK (L.entries ()[0].firstSec == 100 && L.entries ()[0].lastSec == 107,
               "A4 首秒留最早、末秒更新成最新（中间那些秒不存）");

        L.note (0x0E01, 0x2E, 0, W, R, deny::Reason::OpTier, 110);
        CHECK (L.size () == 2, "A5 换一台 SA 就是另一条");
        L.note (0x0E00, 0x34, 0, F, R, deny::Reason::OpTier, 111);
        CHECK (L.size () == 3, "A6 换服务号就是另一条");
        L.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 112);
        CHECK (L.size () == 4, "A7 换 DID 就是另一条");
        L.note (0x0E00, 0x22, 0xF1B0, W, R, deny::Reason::DidLevel, 113);
        CHECK (L.size () == 5, "A8 同一 DID 但「要的档」不同也是另一条");
        L.note (0x0E00, 0x22, 0xF1B0, F, W, deny::Reason::OpTier, 114);
        CHECK (L.size () == 6, "A9 同一组但原因不同也是另一条（追责时是两种问题）");
        CHECK (L.totalHits () == 8, "A10 合计 = 3+1+1+1+1+1 各条次数之和（聚合的那条按 3 算）");
    }

    // ---- B 上限（6 项）----
    {
        deny::DenyLedger L;
        // 造 33 条互不相干的记录，第 1 条带 5 次。
        for (std::uint16_t i = 0; i < deny::DenyLedger::kMaxEntries + 1; ++i)
        {
            const std::uint16_t sa = static_cast<std::uint16_t> (0x0E00 + i);
            if (i == 0)
                for (int k = 0; k < 5; ++k) L.note (sa, 0x10, 0, W, R, deny::Reason::OpTier, 10);
            else
                L.note (sa, 0x10, 0, W, R, deny::Reason::OpTier, 10);
        }
        CHECK (L.size () == deny::DenyLedger::kMaxEntries, "B1 账最多 kMaxEntries 条");
        CHECK (L.droppedEntries () == 1, "B2 丢了几条：1");
        CHECK (L.droppedHits () == 5, "B3 丢了几次命中：5（那一条带着 5 次）");
        CHECK (L.entries ()[0].sa == 0x0E01, "B4 丢的是最旧那条（0x0E00 那条 5 次的没了）");
        CHECK (L.totalHits () == deny::DenyLedger::kMaxEntries + 5,
               "B5 合计 = 剩下的 32 条各 1 次 + 丢掉的 5 次（不报就会少报）");
        CHECK (L.hitsOfSa (0x0E00) == 0, "B6 丢掉的连「是谁」都没了，按人汇总里查不到它");
    }

    // ---- C 落盘与判坏（16 项）----
    {
        deny::DenyLedger L;
        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 0x00000064);
        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 0x0000006B);   // 与上一条同组 → 计数 2
        L.note (0x0E01, 0x22, 0xF1B0, F, W, deny::Reason::DidLevel, 0x00000070);
        L.note (0x0E01, 0x34, 0, F, R, deny::Reason::OpTier, 0x00000071);   // 第三条（不同服务号）
        const std::string t = L.text ();

        CHECK (t.compare (0, 10, "DOIPDENY 1") == 0, "C1 版本行是 DOIPDENY 1");
        CHECK (t.size () == 10 + 1 + 3 * (47 + 1) + 20 + 1, "C2 三行 47 + 版本行 + SUM（总长对得上）");

        // 逐行长度：D 行必须 47。
        {
            std::size_t pos = t.find ('\n') + 1;
            bool allOk = true;
            for (int i = 0; i < 3; ++i)
            {
                const std::size_t nl = t.find ('\n', pos);
                if (nl - pos != 47) allOk = false;
                pos = nl + 1;
            }
            CHECK (allOk, "C3 每条 D 行都是 47 字符（定长）");
        }
        CHECK (t.find ("D 0E00 2E 0000 2 1 0 00000002 00000064 0000006B") != std::string::npos,
               "C4 行内容与字段宽度对（次数两位补零、时间八位十六进制）");

        deny::DenyLedger back;
        std::string why;
        CHECK (deny::DenyLedger::parse (t, back, why), "C5 自己写的能自己读回");
        CHECK (back.size () == 3 && back.entries ()[0].count == 2 &&
               back.entries ()[1].did == 0xF1B0 && back.entries ()[1].why == deny::Reason::DidLevel,
               "C6 读回后条数、次数、DID、原因都对");
        CHECK (back.totalHits () == 4, "C7 读回后合计也对");

        // 改一位 → 校验和红
        std::string bad = t;
        bad[bad.find ("00000002")] = '3';
        deny::DenyLedger tmp;
        CHECK (!deny::DenyLedger::parse (bad, tmp, why) && why.find ("校验和不符") != std::string::npos,
               "C8 改一位就判坏（SUM 抓到）");
        // 截断（去掉最后一行）
        std::string cut = t.substr (0, t.find_last_of ('\n', t.size () - 2) + 1);
        CHECK (!deny::DenyLedger::parse (cut, tmp, why), "C9 半截文件判坏（最后一行不是 SUM）");
        // 版本号 2
        std::string v2 = t;
        v2[9] = '2';
        CHECK (!deny::DenyLedger::parse (v2, tmp, why) && why.find ("版本行不对") != std::string::npos,
               "C10 版本 2 判坏");
        // 行短一位（先重算校验和，证明坏在形状而不是被 SUM 顺手挡住）
        {
            std::string shortLine = "D 0E00 2E 0000 2 1 0 0000002 00000064 0000006B\n";   // 46 字符
            std::string body = "DOIPDENY 1\n" + shortLine;
            std::string withSum = body + "SUM " + keys::checksumOf (body) + "\n";
            CHECK (!deny::DenyLedger::parse (withSum, tmp, why) && why.find ("形状") != std::string::npos,
                   "C11 行短一位：校验和是对的，仍然判坏（坏在形状）");
        }
        // 非十六进制
        {
            std::string body = "DOIPDENY 1\nD 0E0Z 2E 0000 2 1 0 00000001 00000064 00000064\n";
            std::string withSum = body + "SUM " + keys::checksumOf (body) + "\n";
            CHECK (!deny::DenyLedger::parse (withSum, tmp, why), "C12 字段不是十六进制判坏");
        }
        // 档位越界（need=4）
        {
            std::string body = "DOIPDENY 1\nD 0E00 2E 0000 4 1 0 00000001 00000064 00000064\n";
            std::string withSum = body + "SUM " + keys::checksumOf (body) + "\n";
            CHECK (!deny::DenyLedger::parse (withSum, tmp, why) && why.find ("越界") != std::string::npos,
                   "C13 档位 4 越界判坏");
        }
        // 次数 0
        {
            std::string body = "DOIPDENY 1\nD 0E00 2E 0000 2 1 0 00000000 00000064 00000064\n";
            std::string withSum = body + "SUM " + keys::checksumOf (body) + "\n";
            CHECK (!deny::DenyLedger::parse (withSum, tmp, why) && why.find ("次数是 0") != std::string::npos,
                   "C14 次数 0 判坏（形状对，但没意义）");
        }
        // 空账（只有版本行 + SUM）是合法的
        {
            deny::DenyLedger empty;
            deny::DenyLedger rt;
            CHECK (deny::DenyLedger::parse (empty.text (), rt, why) && rt.size () == 0 && rt.totalHits () == 0,
                   "C15 空账合法：本次运行一次都没挡（不是坏账）");
        }
        CHECK (keys::checksumOf ("DOIPDENY 1\n").size () == 16, "C16 校验和 16 位（与整套账一个口径）");
    }

    // ---- D 汇总（5 项）----
    {
        deny::DenyLedger L;
        L.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 5);
        L.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 6);
        L.note (0x0E00, 0x2E, 0, W, R, deny::Reason::OpTier, 7);
        L.note (0x0E01, 0x34, 0, F, W, deny::Reason::OpTier, 8);
        CHECK (L.hitsOfSa (0x0E00) == 3 && L.hitsOfSa (0x0E01) == 1, "D1 按人汇总");
        CHECK (L.hitsOfSa (0x0E02) == 0, "D2 没出现过的 SA 是 0（不是「查不到」）");
        CHECK (L.hitsOfDid (0xF1B0) == 2, "D3 按 DID 汇总：钥匙表被试探 2 次");
        CHECK (L.hitsOfDid (0) == 2, "D4 did=0 是非 DID 请求（两个 2E/34 计数在一起）");
        const deny::Entry *w = L.worst ();
        CHECK (w != nullptr && w->sa == 0x0E00 && w->count == 2, "D5 最深的一条（次数最多）");
    }

    // ---- E 读写往返（5 项）----
    {
        deny::DenyLedger L;
        L.note (0x0E02, 0x31, 0, F, W, deny::Reason::OpTier, 1234);
        const std::string path = "denyledger_selftest.tmp";
        std::string why;
        CHECK (L.save (path, why), "E1 写盘成功");
        deny::DenyLedger back;
        CHECK (deny::DenyLedger::load (path, back, why), "E2 读盘成功");
        CHECK (back.size () == 1 && back.entries ()[0].sa == 0x0E02, "E3 往返字段一致");
        CHECK (back.entries ()[0].count == 1 && back.entries ()[0].firstSec == 1234, "E4 次数与时间也一致");
        std::remove (path.c_str ());
        CHECK (!deny::DenyLedger::load ("no_such_deny_ledger", back, why),
               "E5 打不开的文件判失败（不猜成空账）");
    }

    // ---- F 次数那一格是十进制（M33 真抓过的 bug）（6 项）----
    {
        // 10 次：写出去是 "00000010"。按十六进制读回来会变成 16 —— 前 9 次两者同形，看不出来。
        deny::DenyLedger L;
        for (int k = 0; k < 10; ++k)
            L.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::DidLevel, 50 + k);
        const std::string t10 = L.text ();
        CHECK (t10.find ("00000010") != std::string::npos, "F1 10 次写成十进制「00000010」");

        deny::DenyLedger b10;
        std::string why;
        CHECK (deny::DenyLedger::parse (t10, b10, why) && b10.entries ()[0].count == 10,
               "F2 10 次读回来是 10（不是十六进制读出来的 16）");
        CHECK (b10.totalHits () == 10, "F3 合计也是 10，不虚高");

        // 37 次：十六进制读会变成 55 —— 差得足够远，让人一眼看出"账不对"。
        deny::DenyLedger L37;
        for (int k = 0; k < 37; ++k)
            L37.note (0x0E01, 0x2E, 0, W, R, deny::Reason::OpTier, 60 + k);
        deny::DenyLedger b37;
        CHECK (deny::DenyLedger::parse (L37.text (), b37, why) && b37.entries ()[0].count == 37,
               "F4 37 次读回来是 37（按十六进制会读成 55）");

        // 原因多了一种（M32 的响应侧）。它必须能落盘读回，名字也要说得清。
        deny::DenyLedger Lr;
        Lr.note (0x0E00, 0x22, 0xF1B0, F, R, deny::Reason::RespDid, 70);
        deny::DenyLedger br;
        CHECK (deny::DenyLedger::parse (Lr.text (), br, why) && br.size () == 1 &&
               br.entries ()[0].why == deny::Reason::RespDid,
               "F5 第三种原因（响应被挡）能落盘读回");
        CHECK (std::string (deny::reasonName (deny::Reason::RespDid)) == "响应被挡（数据没出去）",
               "F6 三种原因各有各的说法（追责时是三种问题）");
    }

    std::printf ("通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
