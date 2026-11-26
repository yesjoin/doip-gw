// ============================================================================
// keyringstamp_selftest.cpp —— M25 的纯逻辑自测（清单指纹 + 变更世代）
//
// 四组：
//   A 规范串与指纹：顺序无关、状态敏感、材料相等即相同、空表有确定值；
//   B 指纹能抓住"计数一样但内容不一样"（M24 摘要抓不住的那种）；
//   C 世代：0 保留、+1、到头绕回 1、不绕回 0；
//   D 落盘里的版本：v2 带 VER、v1 旧文件读成 0、VER 坏值判坏、v1 文件仍然校验内容。
//
// 为什么 A 组第一条就是"顺序无关"：表按装入顺序存，两台车装钥匙的先后可能不同 ——
//   不排序，同一张表在两个进程里算出两个指纹，这个指纹就没法对账了。
//
// 用法：./keyringstamp-selftest        全绿退出码 0
// ============================================================================
#include "FirmwareManifest.h"   // 只为 fw::demoKey
#include "KeyRing.h"
#include "KeyRingStamp.h"
#include "KeyRingStore.h"
#include "Sha256.h"

#include <cstdio>
#include <initializer_list>
#include <string>
#include <utility>

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

static keys::KeyRing ringOf (std::initializer_list<std::pair<std::uint16_t, keys::State>> rows)
{
    keys::KeyRing r;
    for (const auto &row : rows)
    {
        r.install (row.first, fw::demoKey (row.first));
        if (row.second != keys::State::Active) r.setState (row.first, row.second);
    }
    return r;
}

static std::string signedText (const std::string &body)
{
    return body + "SUM " + keys::checksumOf (body) + "\n";
}

int main ()
{
    // ---- A. 规范串与指纹 ----
    {
        const keys::KeyRing two = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Active}});
        CHECK (keys::canonicalOf (two) == "0001=00;0002=00;", "A1 规范串是「id=状态;」按 id 升序");

        // 装进去的顺序反过来，规范串和指纹必须一样
        keys::KeyRing rev;
        rev.install (0x0002, fw::demoKey (0x0002));
        rev.install (0x0001, fw::demoKey (0x0001));
        CHECK (keys::canonicalOf (rev) == keys::canonicalOf (two), "A2 装入顺序不影响规范串");
        CHECK (keys::fingerprintOf (rev) == keys::fingerprintOf (two), "A3 装入顺序不影响指纹");

        CHECK (keys::fingerprintOf (two) != 0, "A4 指纹不是 0（2 字节空间里恰好算出 0 的概率极低，这里确认一下）");
        CHECK (keys::fingerprintText (keys::fingerprintOf (two)).size () == 4, "A5 指纹按 4 个 hex 报");

        // 状态敏感：同样两把钥匙，一把退役 → 指纹必须变
        const keys::KeyRing retiring =
            ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Retiring}});
        CHECK (keys::fingerprintOf (retiring) != keys::fingerprintOf (two), "A6 状态差一个 → 指纹不同");
        const keys::KeyRing revoked =
            ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Revoked}});
        CHECK (keys::fingerprintOf (revoked) != keys::fingerprintOf (retiring),
               "A7 退役和吊销是两种处境 → 指纹也不同");

        // 空表也是确定值（空表是合法状态，不是"没有指纹"）
        CHECK (keys::canonicalOf (keys::KeyRing {}) == "", "A8 空表规范串是空串");
        CHECK (keys::fingerprintOf (keys::KeyRing {}) == keys::fingerprintOf (keys::KeyRing {}),
               "A9 空表指纹稳定（同一份空表算两次一样）");

        // 为什么用 SHA-256 而不是"各 id 异或"：两把钥匙互换状态时，异或会正好抵消。
        //   而"谁退役了、谁启用了"恰恰是最需要被抓到的一类改动。
        const keys::KeyRing oneOff =
            ringOf ({{0x0001, keys::State::Retiring}, {0x0002, keys::State::Active}});
        const keys::KeyRing twoOff =
            ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Retiring}});
        CHECK (keys::fingerprintOf (oneOff) != keys::fingerprintOf (twoOff),
               "A10 两把互换状态 → 指纹不同（异或实现会在这里抵消）");
    }

    // ---- B. 抓得住 M24 摘要抓不住的"假一致" ----
    {
        // A 装了 5 号，B 装了 6 号：都是 4 把、都全部启用 → 摘要完全一样
        const keys::KeyRing a = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Active},
                                         {0x0003, keys::State::Active}, {0x0005, keys::State::Active}});
        const keys::KeyRing b = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Active},
                                         {0x0003, keys::State::Active}, {0x0006, keys::State::Active}});
        CHECK (a.size () == b.size (), "B1 两台都是 4 把（摘要的「总」一样）");
        CHECK (a.count (keys::State::Active) == b.count (keys::State::Active),
               "B2 两台都全部启用（摘要的「启用」一样）");
        CHECK (keys::fingerprintOf (a) != keys::fingerprintOf (b),
               "B3 但指纹不同 —— 这就是 M24 摘要看不见的那种假一致");

        // 反过来：真一样的时候指纹必须一样（不然车队永远对不上）
        const keys::KeyRing a2 = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Active},
                                          {0x0003, keys::State::Active}, {0x0005, keys::State::Active}});
        CHECK (keys::fingerprintOf (a) == keys::fingerprintOf (a2), "B4 内容真一样 → 指纹一样");
    }

    // ---- C. 世代 ----
    {
        CHECK (keys::nextGeneration (0) == 1, "C1 从 0（没改过 / 旧文件）改一次 → 1");
        CHECK (keys::nextGeneration (1) == 2, "C2 正常 +1");
        CHECK (keys::nextGeneration (7) == 8, "C3 正常 +1（7 → 8）");
        CHECK (keys::nextGeneration (0xFFFE) == 0xFFFF, "C4 到顶前一步");
        CHECK (keys::nextGeneration (0xFFFF) == 1, "C5 到头绕回 1（**不绕回 0**：0 留给旧文件）");
        CHECK (keys::nextGeneration (3) != 0, "C6 任何一代 +1 都不会变成 0");

        const keys::KeyRing two = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Active}});
        CHECK (keys::stampText (two, 7) == "版本 7，指纹 " + keys::fingerprintText (keys::fingerprintOf (two)),
               "C7 一句话里带版本和指纹");
    }

    // ---- D. 版本落盘：写 v3、v2 和 v1 也读 ----
    {
        keys::KeyRing r = ringOf ({{0x0001, keys::State::Active}, {0x0002, keys::State::Revoked}});
        const std::string v3 = keys::encode (r, 9);
        CHECK (v3.compare (0, 14, "DOIPKEYRING 3\n") == 0, "D1 写出来是 v3（M26 起盘上只写新格式）");
        CHECK (v3.compare (14, 9, "VER 0009\n") == 0, "D2 VER 行带世代（4 hex）");
        CHECK (v3.compare (23, 10, "BOOT 0000\n") == 0, "D2b BOOT 行跟着世代一起写（没给上电序就是 0）");
        const keys::LoadResult back = keys::decode (v3);
        CHECK (back.status == keys::LoadStatus::Ok && back.generation == 9, "D3 读回世代 9");
        CHECK (back.ring.dump () == r.dump (), "D4 表本身一个不差");

        // v1 旧文件（M23 写的）：没有 VER 行，世代按 0 算，表照读
        const std::string v1 = signedText ("DOIPKEYRING 1\nK 0001 00 " +
                                          Sha256::hex (fw::demoKey (0x0001)) + "\n");
        const keys::LoadResult old = keys::decode (v1);
        CHECK (old.status == keys::LoadStatus::Ok, "D5 v1 旧文件仍然读得进来（写新读旧）");
        CHECK (old.generation == 0, "D6 旧文件没有 VER → 世代 0（不被当成一次真实变更）");
        CHECK (old.ring.size () == 1 && old.ring.find (0x0001) != nullptr, "D7 旧文件的表内容照读");

        // v1 上照样跑内容校验：校验和对了但状态非法，仍然判坏
        const std::string badV1 = signedText ("DOIPKEYRING 1\nK 0001 03 " +
                                              Sha256::hex (fw::demoKey (0x0001)) + "\n");
        CHECK (keys::decode (badV1).status == keys::LoadStatus::Corrupt,
               "D8 v1 也照样查内容（状态 03 → 坏）");

        // VER 行写坏：判坏，不猜 0
        const std::string body = "DOIPKEYRING 2\nVER 00ZZ\n";
        CHECK (keys::decode (signedText (body)).status == keys::LoadStatus::Corrupt,
               "D9 VER 不是 hex → 判坏（不悄悄当成 0）");
        const std::string missingVer = "DOIPKEYRING 2\n";
        CHECK (keys::decode (signedText (missingVer)).status == keys::LoadStatus::Corrupt,
               "D10 v2 但没有 VER 行 → 判坏（v2 的 VER 是必需的，不套 v1 的默认）");
        const std::string bigVer = "DOIPKEYRING 2\nVER 10000\n";
        CHECK (keys::decode (signedText (bigVer)).status == keys::LoadStatus::Corrupt,
               "D11 VER 超过 16 位 → 判坏");

        // 世代变了，校验和必须跟着变（不然"改了版本"这件事在盘上可以悄悄发生）
        CHECK (keys::checksumOf (keys::encode (r, 1).substr (0, keys::encode (r, 1).rfind ("SUM "))) !=
               keys::checksumOf (keys::encode (r, 2).substr (0, keys::encode (r, 2).rfind ("SUM "))),
               "D12 换代改的是 SUM 之前的字节 → 校验和必然不同");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
