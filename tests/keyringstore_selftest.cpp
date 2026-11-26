// ============================================================================
// keyringstore_selftest.cpp —— M23 的纯逻辑自测（钥匙表落盘 / 读回 / 读坏了不猜）
//
// 四组：
//   A 编码：行形状、状态字节、校验和长度；
//   B 往返：存下去再读回来，id / 状态 / 材料 / dump 一个不差；
//   C 坏文件：半截、被手改、版本不对、内容非法 —— 一律 Corrupt，**且不套默认两把**；
//   D 文件层：真写文件、rename 覆盖、目录不存在、不留 .tmp、空表合法。
//
// 为什么 C 组占一半：落盘这一层出事故的方式几乎全在"读坏了怎么办"，
//   而最坏的处理方式是"读坏了当空的/当默认的" —— 那等于把吊销的钥匙复活。
//
// 用法：./keyringstore-selftest        全绿退出码 0
// ============================================================================
#include "FirmwareManifest.h"   // 只为 fw::demoKey（演示用的钥匙材料）
#include "KeyRing.h"
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

// 手工拼一个"格式合法、校验和也对"的文件，用来验内容校验（校验和 ≠ 内容合法）
static std::string signedText (const std::string &body) { return body + "SUM " + keys::checksumOf (body) + "\n"; }

static const char *kPath  = "/tmp/m23_selftest_ring.txt";
static const char *kPath2 = "/tmp/m23_selftest_ring2.txt";
static const char *kBad   = "/tmp/m23_selftest_ring_bad.txt";

int main ()
{
    std::remove (kPath);
    std::remove (kPath2);
    std::remove (kBad);

    // ---- A. 编码 ----
    {
        const std::string empty = keys::encode (keys::KeyRing {});
        CHECK (empty.compare (0, 14, "DOIPKEYRING 1\n") == 0, "A1 第一行是版本行");
        CHECK (empty.size () == 14 + 4 + 16 + 1, "A2 空表就是版本行 + 校验和行（没有空 K 行）");

        const std::string two = keys::encode (makeRing ());
        CHECK (two.find ("\nK 0001 00 ") != std::string::npos, "A3 1 号以「K 0001 00」开头（状态是 00 启用）");
        CHECK (two.find ("\nK 0002 00 ") != std::string::npos, "A4 2 号也在");

        keys::KeyRing r = makeRing ();
        r.setState (0x0002, keys::State::Revoked);
        CHECK (keys::encode (r).find ("\nK 0002 02 ") != std::string::npos,
               "A5 吊销存成 02（不是「删掉」也不是「00」）");

        CHECK (keys::checksumOf ("DOIPKEYRING 1\n").size () == 16, "A6 校验和是 16 个 hex 字符");
        CHECK (keys::checksumOf ("a") != keys::checksumOf ("b"), "A7 校验和真的跟着内容变");
    }

    // ---- B. 往返 ----
    {
        keys::KeyRing r;
        r.install (0x0001, fw::demoKey (0x0001));
        r.install (0x0007, fw::demoKey (0x0007));
        r.setState (0x0001, keys::State::Retiring);
        r.setState (0x0007, keys::State::Revoked);

        const keys::LoadResult back = keys::decode (keys::encode (r));
        CHECK (back.status == keys::LoadStatus::Ok, "B1 自己写出来的东西能读回来");
        CHECK (back.ring.size () == 2, "B2 把数不变");
        CHECK (back.ring.find (0x0001) != nullptr &&
                   back.ring.find (0x0001)->state == keys::State::Retiring,
               "B3 退役状态原样回来");
        CHECK (back.ring.find (0x0007) != nullptr &&
                   back.ring.find (0x0007)->state == keys::State::Revoked,
               "B4 吊销状态原样回来（这一条就是 M23 的全部意义）");
        CHECK (Sha256::hex (back.ring.find (0x0007)->key) == Sha256::hex (fw::demoKey (0x0007)),
               "B5 钥匙材料逐字节相同");
        CHECK (back.ring.dump () == r.dump (), "B6 dump 一致（顺序也一致：装进去的顺序）");
        CHECK (keys::decode (keys::encode (keys::KeyRing {})).status == keys::LoadStatus::Ok,
               "B7 空表也是合法文件");
    }

    // ---- C. 坏文件：一律不采用，且不套默认两把 ----
    {
        const keys::KeyRing r = makeRing ();
        const std::string good = keys::encode (r);
        const std::string body = good.substr (0, good.rfind ("SUM "));   // 校验和行之前

        // C1 半截：把 SUM 行砍掉 5 个字符（模拟写到一半断电）
        const std::string cut = good.substr (0, good.size () - 6);
        const keys::LoadResult c1 = keys::decode (cut);
        CHECK (c1.status == keys::LoadStatus::Corrupt, "C1 半截文件判坏（不尝试抢救）");

        // C2 被手改：把 1 号的 00 改成 02，校验和不动
        std::string tampered = good;
        const std::size_t k1 = tampered.find ("K 0001 00 ");
        tampered.replace (k1 + 7, 2, "02");
        const keys::LoadResult c2 = keys::decode (tampered);
        CHECK (c2.status == keys::LoadStatus::Corrupt, "C2 改了状态、校验和没跟着改 → 判坏");
        CHECK (c2.ring.size () == 0 && c2.ring.find (0x0001) == nullptr,
               "C3 判坏时给的是**空表**，不是默认两把（否则吊销的钥匙就复活了）");
        CHECK (c2.why.find ("校验和") != std::string::npos, "C4 理由说得出是校验和不对");

        // C5 校验和本身改一位
        std::string wrongSum = good;
        wrongSum[good.size () - 3] = (good[good.size () - 3] == 'a') ? 'b' : 'a';
        CHECK (keys::decode (wrongSum).status == keys::LoadStatus::Corrupt, "C5 校验和改一位 → 判坏");

        // C6 版本行不对
        std::string v2 = body;
        v2.replace (0, 14, "DOIPKEYRING 2\n");
        CHECK (keys::decode (signedText (v2)).status == keys::LoadStatus::Corrupt, "C6 版本行不是 1 → 判坏");

        // 以下四条：校验和都是对的（用 signedText 重算），坏在**内容**
        std::string dup = "DOIPKEYRING 1\nK 0001 00 " + Sha256::hex (fw::demoKey (0x0001)) + "\n" +
                          "K 0001 00 " + Sha256::hex (fw::demoKey (0x0002)) + "\n";
        CHECK (keys::decode (signedText (dup)).status == keys::LoadStatus::Corrupt,
               "C7 同 id 两行（校验和对但内容非法）→ 判坏");

        std::string badState = "DOIPKEYRING 1\nK 0001 03 " + Sha256::hex (fw::demoKey (0x0001)) + "\n";
        CHECK (keys::decode (signedText (badState)).status == keys::LoadStatus::Corrupt,
               "C8 状态 03 不存在 → 判坏");

        std::string zeroId = "DOIPKEYRING 1\nK 0000 00 " + Sha256::hex (fw::demoKey (0x0001)) + "\n";
        CHECK (keys::decode (signedText (zeroId)).status == keys::LoadStatus::Corrupt,
               "C9 keyId 0 不能占槽 → 判坏");

        std::string nine = "DOIPKEYRING 1\n";
        for (int i = 1; i <= 9; ++i)
        {
            char idbuf[8];
            std::snprintf (idbuf, sizeof idbuf, "%04X", i);
            nine += std::string ("K ") + idbuf + " 00 " + Sha256::hex (fw::demoKey (static_cast<std::uint16_t> (i))) + "\n";
        }
        CHECK (keys::decode (signedText (nine)).status == keys::LoadStatus::Corrupt,
               "C10 9 把超过定长 8 → 判坏（不截断成 8 把）");

        CHECK (keys::decode ("").status == keys::LoadStatus::Corrupt, "C11 空文件判坏（不是「空表」）");
        CHECK (keys::decode (body).status == keys::LoadStatus::Corrupt, "C12 只有 K 行没有 SUM 行 → 判坏");

        std::string extra = good + "K 0003 00 " + Sha256::hex (fw::demoKey (0x0003)) + "\n";
        CHECK (keys::decode (extra).status == keys::LoadStatus::Corrupt,
               "C13 校验和行后面又有一行 → 判坏（最后一行必须是 SUM）");
    }

    // ---- D. 文件层 ----
    {
        keys::KeyRing r;
        r.install (0x0001, fw::demoKey (0x0001));
        r.install (0x0002, fw::demoKey (0x0002));
        r.setState (0x0001, keys::State::Retiring);

        std::string why;
        CHECK (keys::save (r, kPath, why), "D1 写盘成功");
        CHECK (keys::load (kPath).status == keys::LoadStatus::Ok, "D2 读回来是 Ok");
        CHECK (keys::load (kPath).ring.dump () == r.dump (), "D3 读回来的表与写下去的一致");
        {
            std::FILE *tf = std::fopen ((std::string (kPath) + ".tmp").c_str (), "rb");
            CHECK (tf == nullptr, "D4 写完不留 .tmp");
            if (tf) std::fclose (tf);
        }

        // 覆盖写：改成吊销，再读 —— rename 换的是整份文件
        r.setState (0x0002, keys::State::Revoked);
        CHECK (keys::save (r, kPath, why), "D5 覆盖写成功（目标文件已存在）");
        const keys::LoadResult over = keys::load (kPath);
        CHECK (over.status == keys::LoadStatus::Ok &&
                   over.ring.find (0x0002)->state == keys::State::Revoked,
               "D6 覆盖之后读到的是新内容（吊销生效在盘上）");

        const keys::LoadResult miss = keys::load ("/tmp/m23_selftest_no_such_dir/no.txt");
        CHECK (miss.status == keys::LoadStatus::Missing, "D7 文件不存在 → Missing（第一次上电）");
        CHECK (miss.why.find ("第一次上电") != std::string::npos, "D8 理由说得清是第一次上电，不是坏了");

        CHECK (!keys::save (r, "/tmp/m23_selftest_no_such_dir/x.txt", why), "D9 目录不存在 → 写失败");
        CHECK (!why.empty (), "D10 写失败要带一句理由");

        // 模拟断电：把一份好文件砍成半截写进盘，再从盘上读
        {
            const std::string good = keys::encode (r);
            std::FILE *fp = std::fopen (kBad, "wb");
            CHECK (fp != nullptr, "D11 建得出坏文件");
            if (fp)
            {
                std::fwrite (good.data (), 1, good.size () - 6, fp);
                std::fclose (fp);
            }
            const keys::LoadResult bad = keys::load (kBad);
            CHECK (bad.status == keys::LoadStatus::Corrupt, "D12 盘上的半截文件读成 Corrupt");
            CHECK (bad.ring.size () == 0, "D13 坏文件不会变成「默认两把」");
        }

        CHECK (keys::save (keys::KeyRing {}, kPath2, why), "D14 空表也能写");
        CHECK (keys::load (kPath2).status == keys::LoadStatus::Ok &&
                   keys::load (kPath2).ring.size () == 0,
               "D15 空表读回来还是空表（合法，不是坏文件）");
    }

    std::remove (kPath);
    std::remove (kPath2);
    std::remove (kBad);

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
