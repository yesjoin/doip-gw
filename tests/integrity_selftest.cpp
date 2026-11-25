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

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
