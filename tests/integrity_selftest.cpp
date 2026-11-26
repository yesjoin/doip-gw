// ============================================================================
// integrity_selftest.cpp —— M18 的纯逻辑自测（SHA-256 + 刷写包清单/标签）
//
// 两件事分开验，混在一起就说不清是"哈希算错了"还是"清单判错了"：
//   A. 哈希本身：三条标准向量（known-answer test）+ 分块与一次算完等价 + 长度边界扫描；
//   B. 清单与校验：结构错（长度/magic/版本/钥匙）与内容错（标签/长度/哈希）分属不同类。
//
// 一句话记住两者的区别：
//   CRC 是线性的（改两个字节可以补回来）；SHA-256 是单向的（改了就得重新算预映像）；
//   标签（对称 MAC）证明"知道钥匙"，不证明"是厂商"（那要非对称签名）。
//
// 用法：./integrity-selftest        全绿退出码 0
// ============================================================================
#include "FirmwareManifest.h"
#include "Sha256.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ()); \
        }                                                              \
    } while (0)

int main ()
{
    // ---- A1. 标准向量：尺子先钉死 ----
    {
        CHECK (Sha256::hex (Sha256::ofText ("")) ==
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "sha256(\"\") 等于标准值");
        CHECK (Sha256::hex (Sha256::ofText ("abc")) ==
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
               "sha256(\"abc\") 等于标准值");
        CHECK (Sha256::hex (Sha256::ofText (
                   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
               "sha256(448 位标准向量) 等于标准值（跨 64 字节块边界）");
    }

    // ---- A2. 分块算 == 一次算（补位逻辑最容易在这里露馅）----
    {
        const std::string text = "the quick brown fox jumps over the lazy dog";
        const auto one = Sha256::ofText (text);
        Sha256 chunked;
        for (char ch : text)
            chunked.update (&ch, 1);
        const auto perByte = chunked.finish ();
        CHECK (one == perByte, "逐字节 update 与一次算得到同一个摘要");

        Sha256 mixed;
        mixed.update (text.data (), 5);
        mixed.update (text.data () + 5, 7);
        mixed.update (text.data () + 12, text.size () - 12);
        CHECK (mixed.finish () == one, "分三段 update 也是同一个摘要");
    }

    // ---- A3. 长度边界：55/56/63/64/65 都是补位最容易错的地方 ----
    {
        bool allSame = true;
        for (std::size_t n : {0u, 1u, 54u, 55u, 56u, 63u, 64u, 65u, 128u})
        {
            std::vector<std::uint8_t> v (n, 0xA5);
            const auto a = Sha256::of (v);
            Sha256 s;
            for (std::size_t i = 0; i < n; ++i) s.update (&v[i], 1);
            if (s.finish () != a) allSame = false;
        }
        CHECK (allSame, "0/1/54/55/56/63/64/65/128 字节：分块与一次算全部一致");

        // 差一个字节，摘要必须完全不同（否则说明"差不多"了）
        const auto A = Sha256::ofText ("package-A");
        const auto B = Sha256::ofText ("package-B");
        CHECK (A != B, "只差一个字符，摘要必须不同");
    }

    // ---- B1. 清单的结构 ----
    {
        std::vector<std::uint8_t> image = {1, 2, 3, 4, 5, 6, 7, 8};
        const auto sha  = Sha256::of (image);
        const auto key1 = fw::demoKey (0x0001);
        const auto m    = fw::buildManifest (8u, sha, 0x0001, key1);

        CHECK (m.size () == fw::kManifestBytes, "清单恰好 76 字节");
        CHECK (m[0] == 'D' && m[1] == 'G' && m[2] == 'I' && m[3] == 'M', "magic 是 DGIM");
        CHECK (m[4] == 0x01 && m[5] == 0x00, "版本 0x01、flags 0x00");
        CHECK (fw::readU32 (m, 6) == 8u, "长度字段（大端）读回 8");
        CHECK (fw::readU16 (m, 42) == 0x0001, "keyId 读回 0x0001");
        Sha256::Digest tagInManifest;
        for (int i = 0; i < 32; ++i) tagInManifest[i] = m[44 + i];
        CHECK (fw::tagOf (m, key1) == tagInManifest,
               "标签 = SHA-256(前 44 字节 || 钥匙)");
    }

    // ---- B2. 正例 ----
    {
        std::vector<std::uint8_t> image = {1, 2, 3, 4, 5, 6, 7, 8};
        const auto m   = fw::buildManifest (8u, Sha256::of (image), 0x0001, fw::demoKey (0x0001));
        const auto chk = fw::verify (image, m);
        CHECK (chk.ok (), "清单与镜像一致 → 通过");
        CHECK (chk.verdict == fw::Verdict::Ok, "判定是 Ok");
    }

    // ---- B3. 内容错：状态 01 那一类 ----
    {
        std::vector<std::uint8_t> image = {1, 2, 3, 4, 5, 6, 7, 8};
        auto m = fw::buildManifest (8u, Sha256::of (image), 0x0001, fw::demoKey (0x0001));

        std::vector<std::uint8_t> changed = image;
        changed[3] ^= 0x01;
        auto chk = fw::verify (changed, m);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::HashMismatch,
               "镜像改 1 个比特 → 哈希不符（这是 CRC 抓不到的那一类）");

        auto m2 = m;
        m2[9]   = 0x09;   // 清单说 9 字节，镜像 8 字节
        chk = fw::verify (image, m2);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::BadTag,
               "只改长度、不重算标签 → 先撞 BadTag（标签绑住了整个头）");

        // 用钥匙把改过的头重新算标签：这是"签错了长度"的真实情形，才轮到长度判定
        Sha256::Digest retag = fw::tagOf (m2, fw::demoKey (0x0001));
        for (int i = 0; i < 32; ++i) m2[44 + i] = retag[i];
        chk = fw::verify (image, m2);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::LengthMismatch,
               "标签正确但声明长度不符 → LengthMismatch（先便宜后贵的顺序走到了这一步）");

        auto m3 = m;
        m3[44] ^= 0x01;   // 改标签一个比特
        chk = fw::verify (image, m3);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::BadTag, "标签被改 → BadTag");
    }

    // ---- B4. 结构错：NRC 那一类 ----
    {
        std::vector<std::uint8_t> image = {1, 2, 3, 4, 5, 6, 7, 8};
        auto m = fw::buildManifest (8u, Sha256::of (image), 0x0001, fw::demoKey (0x0001));

        auto short_m = m;
        short_m.pop_back ();
        auto chk = fw::verify (image, short_m);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::BadLength, "清单 75 字节 → BadLength");

        auto m2 = m;
        m2[0] = 'X';
        chk = fw::verify (image, m2);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::BadMagic, "magic 不对 → BadMagic");

        auto m3 = m;
        m3[4] = 0x02;
        chk = fw::verify (image, m3);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::BadMagic, "版本 0x02 → BadMagic（不认识的格式）");

        auto m4 = m;
        m4[42] = 0x00; m4[43] = 0xFF;
        chk = fw::verify (image, m4);
        CHECK (!chk.ok () && chk.verdict == fw::Verdict::UnknownKey, "keyId 0x00FF → UnknownKey（没这把钥匙）");
    }

    // ---- B5. 换钥匙：标签跟着变，用错钥匙就验不过 ----
    {
        std::vector<std::uint8_t> image = {9, 8, 7};
        const auto m1 = fw::buildManifest (3u, Sha256::of (image), 0x0001, fw::demoKey (0x0001));
        const auto m2 = fw::buildManifest (3u, Sha256::of (image), 0x0002, fw::demoKey (0x0002));
        CHECK (m1 != m2, "同一份镜像、不同钥匙 → 清单不同（keyId 与标签都变）");
        CHECK (fw::verify (image, m1).ok () && fw::verify (image, m2).ok (), "两把钥匙各自的清单都能过");

        // 把 0x0001 的标签挪到 0x0002 的清单上：结构合法、标签不符
        auto forged = m2;
        for (int i = 0; i < 32; ++i) forged[44 + i] = m1[44 + i];
        CHECK (!fw::verify (image, forged).ok (), "用 1 号钥匙的标签冒充 2 号 → 验不过");
    }

    // ---- B6. 大镜像：跨多个 64 字节块也要一致 ----
    {
        std::vector<std::uint8_t> image (1000, 0x5A);
        const auto m = fw::buildManifest (static_cast<std::uint32_t> (image.size ()),
                                          Sha256::of (image), 0x0002, fw::demoKey (0x0002));
        CHECK (fw::verify (image, m).ok (), "1000 字节镜像：清单能过");
        image[999] = 0x5B;
        CHECK (!fw::verify (image, m).ok (), "1000 字节里改最后一个字节也验不过");
    }

    // ---- D. M21：v2 清单（含身份，标签盖住身份）----
    {
        std::vector<std::uint8_t> image = {9, 8, 7, 6, 5, 4, 3, 2};
        const auto key1 = fw::demoKey (0x0001);
        const auto m2   = fw::buildManifestV2 (8u, Sha256::of (image), 0x0001,
                                               "PART-ABC1234", "SW-1.10.0", key1);

        CHECK (m2.size () == fw::kManifestV2Bytes, "D1 v2 清单恰好 104 字节");
        CHECK (m2[4] == 0x02, "D2 版本字节是 0x02");
        CHECK (fw::readU16 (m2, 42) == 0x0001, "D3 v2 的 keyId 仍在偏移 42（前 44 字节与 v1 一致）");
        CHECK (fw::trimText (m2, 44, 12) == "PART-ABC1234", "D4 目标零件号 12 字节读得回来");
        CHECK (fw::trimText (m2, 56, 16) == "SW-1.10.0", "D5 目标版本（9 字节）能放进 16 字节字段，尾部补空格");

        const auto ok2 = fw::verify (image, m2);
        CHECK (ok2.ok () && ok2.hasIdentity && ok2.manifestVersion == 0x02,
               "D6 v2 整包验签通过，并且带回身份");
        CHECK (ok2.targetPart == "PART-ABC1234" && ok2.targetSw == "SW-1.10.0",
               "D7 验签结果里带着目标身份（" + ok2.targetPart + " / " + ok2.targetSw + "）");

        // 改一个字符的零件号：标签盖住这个字段，所以必须验不过
        auto changed = m2;
        changed[44] = static_cast<std::uint8_t> ('Q');
        CHECK (!fw::verify (image, changed).ok (),
               "D8 **改零件号一个字符 → 标签不符**（身份在标签范围内，改不了）");

        // 改版本号同理
        auto changed2 = m2;
        changed2[58] = static_cast<std::uint8_t> ('9');
        CHECK (!fw::verify (image, changed2).ok (), "D9 改目标版本一个字符 → 标签不符");

        // 换镜像
        auto swapped = image;
        swapped[0] = 0x11;
        CHECK (!fw::verify (swapped, m2).ok (), "D10 镜像换掉 → 哈希不符（v2 也要管内容）");

        // 长度与版本必须成对
        auto v1len = fw::buildManifest (8u, Sha256::of (image), 0x0001, key1);
        v1len[4] = 0x02;
        CHECK (fw::verify (image, v1len).verdict == fw::Verdict::BadMagic,
               "D11 76 字节却写版本 0x02 → 0x31（长度与版本必须成对）");
        auto v2len = m2;
        v2len[4] = 0x01;
        CHECK (fw::verify (image, v2len).verdict == fw::Verdict::BadMagic,
               "D12 104 字节却写版本 0x01 → 0x31");

        // 信封检查：不看镜像也能验结构 + 标签 + 身份
        const auto env = fw::checkEnvelope (m2);
        CHECK (env.ok () && env.hasIdentity && env.targetSw == "SW-1.10.0",
               "D13 checkEnvelope：只验信封也给身份（0205 预检就靠它）");
        CHECK (fw::checkEnvelope (changed).verdict == fw::Verdict::BadTag,
               "D14 信封检查同样抓改身份（标签不符）");
        CHECK (fw::checkEnvelope (v1len).verdict == fw::Verdict::BadMagic,
               "D15 信封检查也查长度与版本的配对");

        // v1 仍然能用（老包不能因为加了 v2 就作废）
        const auto m1 = fw::buildManifest (8u, Sha256::of (image), 0x0001, key1);
        const auto ok1 = fw::verify (image, m1);
        CHECK (ok1.ok () && !ok1.hasIdentity && ok1.manifestVersion == 0x01,
               "D16 v1 清单照旧能验，只是没有身份（hasIdentity=false）");

        // 标签覆盖长度不同：v1 的标签不能拿来当 v2 的标签
        auto mixed = m2;
        for (int i = 0; i < 32; ++i) mixed[72 + i] = m1[44 + i];
        CHECK (!fw::verify (image, mixed).ok (), "D17 把 v1 的标签搬到 v2 上 → 验不过（覆盖长度不同）");

        CHECK (fw::buildManifestV2 (8u, Sha256::of (image), 0x0001, "PART-ABC12345", "SW-1.0.3", key1)
                   .size () == fw::kManifestV2Bytes,
               "D18 零件号超 12 字节时也只是截断到 12（不改变结构长度）");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
