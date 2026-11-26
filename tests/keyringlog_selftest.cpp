// ============================================================================
// keyringlog_selftest.cpp —— M26 的纯逻辑自测（变更流水）
//
// 四组：
//   A 环形缓冲：新在前、满 8 丢最旧、越界不崩、clear；
//   B 一行文本：形状固定 36 字符、字段位置、坏的字段一律不认；
//   C 与表联动：记下来的指纹是"改完之后"的，动作/通道有话说；
//   D 落盘：v3 的头三行、流水跟着 VER 自洽、v1/v2 兼容、坏拼接判坏。
//
// C 组的重点是**时序**：流水记的是"改完之后长什么样"，不是"改之前"。
//   记错这一秒，对账时就会拿旧指纹去比新表 —— 那比不记更坏。
//
// 用法：./keyringlog-selftest        全绿退出码 0
// ============================================================================
#include "FirmwareManifest.h"   // 只为 fw::demoKey
#include "KeyRing.h"
#include "KeyRingLog.h"
#include "KeyRingStore.h"
#include "Sha256.h"

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

static keys::KeyRing makeRing ()
{
    keys::KeyRing r;
    r.install (0x0001, fw::demoKey (0x0001));
    r.install (0x0002, fw::demoKey (0x0002));
    return r;
}

static keys::LogEntry entryOf (std::uint16_t id, std::uint16_t gen, keys::Act act,
                               keys::Channel ch, std::uint16_t boot, std::uint32_t sec)
{
    keys::LogEntry e;
    e.keyId       = id;
    e.generation  = gen;
    e.fingerprint = 0x70D3;
    e.act         = act;
    e.channel     = ch;
    e.boot        = boot;
    e.seconds     = sec;
    return e;
}

int main ()
{
    // ---- A. 环形缓冲 ----
    {
        keys::ChangeLog L;
        CHECK (L.empty () && L.size () == 0, "A1 新流水是空的");

        L.append (entryOf (0x0001, 1, keys::Act::Install, keys::Channel::Physical, 1, 0));
        CHECK (L.size () == 1 && L.at (0).keyId == 0x0001, "A2 第一条就是最新的一条");

        L.append (entryOf (0x0002, 2, keys::Act::Install, keys::Channel::Broadcast, 1, 3));
        CHECK (L.at (0).keyId == 0x0002 && L.at (1).keyId == 0x0001,
               "A3 新在前：at(0) 是后进去的");

        L.clear ();
        CHECK (L.empty (), "A4 clear 之后是空的");

        // 塞 9 条，只留最近 8 条 —— 第 1 条必须被挤掉
        for (int i = 1; i <= 9; ++i)
            L.append (entryOf (static_cast<std::uint16_t> (i), static_cast<std::uint16_t> (i),
                               keys::Act::Install, keys::Channel::Physical, 1,
                               static_cast<std::uint32_t> (i)));
        CHECK (L.size () == keys::ChangeLog::kMax, "A5 满 8 条就不再长");
        CHECK (L.at (0).keyId == 9 && L.at (7).keyId == 2, "A6 丢的是最旧的（1 号没了，9→2 都在）");

        const std::size_t big = 99;
        CHECK (L.at (big).keyId == 0, "A7 越界读给哑值，不崩");
    }

    // ---- B. 一行文本 ----
    {
        const keys::LogEntry e = entryOf (0x0003, 0x0007, keys::Act::Retire,
                                          keys::Channel::Broadcast, 0x0002, 0x0000002A);
        const std::string ln = keys::logLine (e);
        CHECK (ln.size () == 37 && ln[36] == '\n', "B1 一行是 36 个字符 + 换行（定长，脚本好切）");
        CHECK (ln.compare (0, 2, "L ") == 0, "B2 以「L 」开头（和 K 行区分得开）");
        CHECK (ln.compare (2, 4, "0007") == 0, "B3 第 2–5 位是世代");
        CHECK (ln.compare (12, 2, "02") == 0, "B4 第 12–13 位是动作（退役 = 02）");
        CHECK (ln.compare (15, 2, "02") == 0, "B5 第 15–16 位是通道（广播 = 02）");
        CHECK (ln.compare (18, 4, "0003") == 0, "B6 第 18–21 位是 keyId");
        CHECK (ln.compare (28, 8, "0000002A") == 0, "B7 最后 8 位是上电后秒数");

        keys::LogEntry back;
        CHECK (keys::parseLogLine (ln.substr (0, 36), back) && back.generation == 7 &&
                   back.keyId == 0x0003 && back.act == keys::Act::Retire &&
                   back.channel == keys::Channel::Broadcast && back.boot == 2 && back.seconds == 42,
               "B8 自己写出来的能读回来，字段一个不差");

        // 以下五条：形状或字段不对，一律不认（宁可判坏，不猜）
        keys::LogEntry dummy;
        CHECK (!keys::parseLogLine (ln.substr (0, 35), dummy), "B9 少一个字符 → 不认");
        CHECK (!keys::parseLogLine ("L 0007 70D3 06 01 0003 0002 0000002A", dummy),
               "B10 动作 06 不存在 → 不认（0 也不认，0 是「没有变更」）");
        CHECK (!keys::parseLogLine ("L 0007 70D3 01 04 0003 0002 0000002A", dummy),
               "B11 通道 04 不存在 → 不认");
        CHECK (!keys::parseLogLine ("L 0007 70D3 01 01 0000 0002 0000002A", dummy),
               "B12 keyId 0 只允许「重建」，普通动作不给 0 → 不认");
        CHECK (keys::parseLogLine ("L 0007 70D3 05 03 0000 0002 0000002A", dummy),
               "B13 重建这一条可以 keyId 0（它动的不是某一吧钥匙）");
    }

    // ---- C. 与表联动 ----
    {
        const keys::KeyRing base = makeRing ();
        const std::uint16_t fpBefore = keys::fingerprintOf (base);
        keys::KeyRing r = base;
        r.install (0x0003, fw::demoKey (0x0003));
        const std::uint16_t fpAfter = keys::fingerprintOf (r);

        CHECK (fpBefore != fpAfter, "C1 装一把新钥匙，指纹确实变了（不然记它没意义）");

        keys::ChangeLog L;
        keys::LogEntry e;
        e.generation = 1;                 // 改完之后才是第 1 代
        e.fingerprint = fpAfter;          // 记"改完之后"的指纹
        e.keyId = 0x0003;
        e.act = keys::Act::Install;
        e.channel = keys::Channel::Physical;
        e.boot = 1;
        e.seconds = 2;
        L.append (e);
        CHECK (L.at (0).fingerprint == fpAfter, "C2 流水里的指纹是「改完之后」的");
        CHECK (L.at (0).fingerprint != fpBefore, "C3 不是「改之前」的（记错这一秒就没法对账）");

        CHECK (std::string (keys::actName (keys::Act::Revoke)) == "吊销" &&
                   std::string (keys::actName (keys::Act::Revive)) == "复活",
               "C4 吊销和退役不混（两个完全不同的故事）");
        CHECK (std::string (keys::channelName (keys::Channel::Broadcast)) == "广播",
               "C5 通道有话说（广播改和逐台改要分得开）");

        const std::string d = L.dump ();
        CHECK (d.find ("0x0003") != std::string::npos && d.find ("版本 1") != std::string::npos,
               "C6 dump 里能看见是哪把、哪一代");
    }

    // ---- D. 落盘 ----
    {
        keys::KeyRing r = makeRing ();
        r.install (0x0003, fw::demoKey (0x0003));
        keys::ChangeLog L;
        L.append (entryOf (0x0003, 1, keys::Act::Install, keys::Channel::Physical, 1, 4));
        L.append (entryOf (0x0003, 2, keys::Act::Retire, keys::Channel::Physical, 2, 7));

        const std::string text = keys::encode (r, 2, 2, &L);
        CHECK (text.compare (0, 14, "DOIPKEYRING 3\n") == 0, "D1 版本行写 3（v3）");
        CHECK (text.compare (14, 9, "VER 0002\n") == 0, "D2 第二行 VER 0002");
        CHECK (text.compare (23, 10, "BOOT 0002\n") == 0, "D3 第三行 BOOT 0002");
        CHECK (text.find ("\nL 0001 70D3") != std::string::npos, "D4 装着流水（按出现顺序：旧在前）");
        CHECK (text.find ("\nL 0002 70D3") != std::string::npos, "D5 两条都在");

        const keys::LoadResult back = keys::decode (text);
        CHECK (back.status == keys::LoadStatus::Ok, "D6 v3 自己写出来的能读回来");
        CHECK (back.generation == 2 && back.boot == 2, "D7 世代与上电序都回来了");
        CHECK (back.ring.size () == 3, "D8 表也还在（3 把）");
        CHECK (back.log.size () == 2 && back.log.at (0).act == keys::Act::Retire,
               "D9 流水读回来还是新在前（最新一条是退役）");
        CHECK (back.log.at (0).seconds == 7, "D10 秒数一个不差");

        // v2 兼容：去掉 BOOT 和 L 行，改版本行 —— 表和世代必须还在，流水按空算
        std::string v2 = "DOIPKEYRING 2\nVER 0002\n";
        for (const auto &ln : {"K 0001 00 " + Sha256::hex (fw::demoKey (0x0001)) + "\n",
                               "K 0002 00 " + Sha256::hex (fw::demoKey (0x0002)) + "\n"})
            v2 += ln;
        const keys::LoadResult b2 = keys::decode (v2 + "SUM " + keys::checksumOf (v2) + "\n");
        CHECK (b2.status == keys::LoadStatus::Ok, "D11 v2 文件照样读得进来");
        CHECK (b2.generation == 2 && b2.ring.size () == 2, "D12 v2：表和世代都在");
        CHECK (b2.boot == 0 && b2.log.empty (), "D13 v2：上电序 0、流水空（旧文件没写过这些）");

        // 以下四条：校验和对，但内容互相矛盾 —— 必须判坏
        std::string noBoot = "DOIPKEYRING 3\nVER 0002\n";
        noBoot += "K 0001 00 " + Sha256::hex (fw::demoKey (0x0001)) + "\n";
        const keys::LoadResult nb = keys::decode (noBoot + "SUM " + keys::checksumOf (noBoot) + "\n");
        CHECK (nb.status == keys::LoadStatus::Corrupt, "D14 v3 缺 BOOT 行 → 判坏（不猜 0）");

        std::string genMismatch = "DOIPKEYRING 3\nVER 0005\nBOOT 0002\n";
        genMismatch += "L 0004 70D3 01 01 0003 0002 00000004\n";
        CHECK (keys::decode (genMismatch + "SUM " + keys::checksumOf (genMismatch) + "\n").status ==
                   keys::LoadStatus::Corrupt,
               "D15 流水最新世代（4）与 VER（5）对不上 → 判坏（文件被拼过）");

        std::string genNoLog = "DOIPKEYRING 3\nVER 0005\nBOOT 0002\n";
        const keys::LoadResult nl = keys::decode (genNoLog + "SUM " + keys::checksumOf (genNoLog) + "\n");
        CHECK (nl.status == keys::LoadStatus::Ok && nl.log.empty () && nl.generation == 5,
               "D16 「有世代、没流水」照样读得进来（v2 升上来的样子）");
        CHECK (nl.why.find ("没有流水") != std::string::npos,
               "D17 但要大声说出来：改过 5 次、账本没写（只报不判，判坏会把能用的表变空表）");

        std::string nine = "DOIPKEYRING 3\nVER 0009\nBOOT 0002\n";
        for (int i = 1; i <= 9; ++i)
        {
            char buf[48];
            std::snprintf (buf, sizeof buf, "L 000%d 70D3 01 01 0003 0002 0000000%d\n", i, i);
            nine += buf;
        }
        CHECK (keys::decode (nine + "SUM " + keys::checksumOf (nine) + "\n").status ==
                   keys::LoadStatus::Corrupt,
               "D18 9 条流水超过定长 8 → 判坏（不截断）");

        // 文件层：写盘 / 读回，流水与上电序都要活过"重启"
        const std::string path = "/tmp/m26_selftest_log.txt";
        std::remove (path.c_str ());
        std::string why;
        CHECK (keys::save (r, path, why, 2, 2, &L), "D19 带流水写盘成功");
        const keys::LoadResult onDisk = keys::load (path);
        CHECK (onDisk.status == keys::LoadStatus::Ok && onDisk.log.size () == 2 &&
                   onDisk.boot == 2 && onDisk.generation == 2,
               "D20 从盘上读回来：流水、上电序、世代都在");
        std::remove (path.c_str ());

        // 没给 log 指针的老调用也得能写（默认参数），且写出来仍是 v3（BOOT 0000、没有 L 行）
        const std::string plain = keys::encode (r, 1);
        CHECK (plain.find ("BOOT 0000\n") != std::string::npos && plain.find ("\nL ") == std::string::npos,
               "D21 老调用不传 log：BOOT 补 0、没有流水行");
        CHECK (keys::decode (plain).status == keys::LoadStatus::Ok, "D22 这种文件也读得回来");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
