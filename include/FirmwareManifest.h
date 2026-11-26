// ============================================================================
// FirmwareManifest.h —— M18 立"清单 + 标签"，M21 把身份也放进清单里
//
// 为什么 CRC 不够：
//   M15 的 0x37 带 CRC-32，它证明"传的过程没出错"。但 CRC 是线性的 ——
//   有人换掉镜像里的两个字节，再补一个"补偿值"，CRC 照样能对上。
//   CRC 防手滑，不防有人动手。
//
// M18 的清单（v1，76 字节）：
//   [0..3]   "DGIM"          magic
//   [4]      0x01            version
//   [5]      0x00            flags（保留）
//   [6..9]   imageLen        u32 大端
//   [10..41] imageSha        SHA-256(镜像)，32 字节
//   [42..43] keyId           u16 大端
//   [44..75] tag             SHA-256(前 44 字节 || 钥匙)，32 字节
//
// M21 的清单（v2，104 字节）：多了"这包是给谁做的"两个字段，而且**在标签覆盖范围之内**：
//   [44..55] targetPart      12 字节 ASCII（右补空格）
//   [56..71] targetSw        16 字节 ASCII（右补空格）
//   [72..103] tag            SHA-256(前 **72** 字节 || 钥匙)
//
// 为什么身份必须在标签里：
//   M20 的目标版本是 tester 在 0x31 01 0204 里**口述**的，ECU 无从校验。
//   身份一进清单、又落在标签下面，改一个字符标签就崩 —— tester 就"说不了谎"了。
//   这就是从"声明"到"证明"的差别。
//
// 版本化兼容（这一步另一个考点）：
//   两种长度各自绑定一个版本号：76 ⇄ 0x01，104 ⇄ 0x02。长度对、版本不对 → 0x31。
//   v1 清单继续能用（老脚本、老包都不动），只是它**没有身份**，不能用来建立"已比对"的凭证。
//
// 标签（tag）是什么，不是什么：
//   对称 MAC（双方共用一把钥匙），证明"这个包是知道钥匙的人做的"，
//   不能证明"这是厂商做的"（那要非对称签名）。
//
// 校验顺序仍是先便宜后贵：
//   长度 → magic/版本 → 钥匙 ID → 标签（只看头部）→ 镜像哈希（要看整包）
// ============================================================================
#ifndef DOIP_FIRMWARE_MANIFEST_H
#define DOIP_FIRMWARE_MANIFEST_H

#include "KeyRing.h"
#include "Sha256.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace doip {
namespace fw {

inline constexpr std::size_t kManifestBytes          = 76;   // v1
inline constexpr std::size_t kManifestHeaderBytes    = 44;   // v1 的标签覆盖长度
inline constexpr std::size_t kManifestV2Bytes        = 104;  // v2
inline constexpr std::size_t kManifestV2HeaderBytes  = 72;   // v2 的标签覆盖长度
inline constexpr std::size_t kIdentityPartBytes      = 12;
inline constexpr std::size_t kIdentitySwBytes        = 16;

enum class Verdict
{
    Ok = 0,
    BadLength,       // 既不是 76 也不是 104（格式外的东西，0x13）
    BadMagic,        // magic / 版本 / flags 不对（不是我们这个格式，0x31）
    UnknownKey,      // keyId 不认识（0x31）
    RevokedKey,      // M22：keyId 在表里，但已被吊销（0x31，理由不同）
    BadTag,          // 标签对不上（有人换了清单或不知道钥匙）→ 状态 01
    LengthMismatch,  // 清单说的长度与镜像实际长度不符 → 状态 01
    HashMismatch     // 镜像哈希不符（包与镜像不是一对）→ 状态 01
};

struct Check
{
    Verdict     verdict  = Verdict::Ok;
    std::string reason;

    std::uint8_t manifestVersion = 0;    // 0x01 / 0x02（0 = 还没解析到）
    bool         hasIdentity     = false;  // v2 才有
    std::string  targetPart;             // v2 的零件号（已去掉尾部空格）
    std::string  targetSw;               // v2 的目标版本（已去掉尾部空格）
    keys::State  keyState = keys::State::Active;   // M22：用的是哪一档钥匙（退役/吊销要记账）

    bool ok () const { return verdict == Verdict::Ok; }
};

// 演示钥匙：keyId 0x0001/0x0002，key = SHA-256("doip-gw demo key <id>")。
// 真实项目里钥匙在刷写包和 ECU 的 NVM 里，不在源码里。
inline Sha256::Digest demoKey (std::uint16_t id)
{
    return Sha256::ofText ("doip-gw demo key " + std::to_string (id));
}

// 演示用的钥匙表：1 号、2 号两把都启用（等于 M18–M21 里那个 switch 的等价物）。
// M22 的真表由 stub 用 KeyRing 建，这里只是给老单元测试留一条默认路径。
inline keys::KeyRing demoRing ()
{
    keys::KeyRing ring;
    ring.install (0x0001, demoKey (0x0001));
    ring.install (0x0002, demoKey (0x0002));
    return ring;
}

inline std::string keyIdText (std::uint16_t id)
{
    char buf[8];
    std::snprintf (buf, sizeof buf, "%04X", static_cast<unsigned> (id));
    return buf;
}

// headerBytes 决定标签盖住清单的前多少字节（v1 = 44，v2 = 72）
inline Sha256::Digest tagOf (const std::vector<std::uint8_t> &manifest, const Sha256::Digest &key,
                             std::size_t headerBytes = kManifestHeaderBytes)
{
    std::vector<std::uint8_t> buf (manifest.begin (), manifest.begin () + headerBytes);
    buf.insert (buf.end (), key.begin (), key.end ());
    return Sha256::of (buf);
}

inline std::uint32_t readU32 (const std::vector<std::uint8_t> &b, std::size_t at)
{
    return (static_cast<std::uint32_t> (b[at]) << 24) |
           (static_cast<std::uint32_t> (b[at + 1]) << 16) |
           (static_cast<std::uint32_t> (b[at + 2]) << 8) |
           static_cast<std::uint32_t> (b[at + 3]);
}

inline std::uint16_t readU16 (const std::vector<std::uint8_t> &b, std::size_t at)
{
    return static_cast<std::uint16_t> ((b[at] << 8) | b[at + 1]);
}

// 定长 ASCII 字段：右补空格；解析时去掉尾部空格
inline std::vector<std::uint8_t> fixedText (const std::string &s, std::size_t n)
{
    std::vector<std::uint8_t> out;
    out.reserve (n);
    for (std::size_t i = 0; i < n; ++i)
        out.push_back (i < s.size () ? static_cast<std::uint8_t> (s[i]) : static_cast<std::uint8_t> (' '));
    return out;
}

inline std::string trimText (const std::vector<std::uint8_t> &b, std::size_t at, std::size_t n)
{
    std::string s;
    for (std::size_t i = 0; i < n; ++i) s.push_back (static_cast<char> (b[at + i]));
    while (!s.empty () && (s.back () == ' ' || s.back () == '\0')) s.pop_back ();
    return s;
}

// v1：76 字节，无身份
inline std::vector<std::uint8_t> buildManifest (std::uint32_t imageLen,
                                                const Sha256::Digest &imageSha,
                                                std::uint16_t keyId,
                                                const Sha256::Digest &key)
{
    std::vector<std::uint8_t> m;
    m.reserve (kManifestBytes);
    m.insert (m.end (), {'D', 'G', 'I', 'M'});
    m.push_back (0x01);   // version
    m.push_back (0x00);   // flags
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 24) & 0xFF));
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 16) & 0xFF));
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 8) & 0xFF));
    m.push_back (static_cast<std::uint8_t> (imageLen & 0xFF));
    m.insert (m.end (), imageSha.begin (), imageSha.end ());
    m.push_back (static_cast<std::uint8_t> ((keyId >> 8) & 0xFF));
    m.push_back (static_cast<std::uint8_t> (keyId & 0xFF));
    const Sha256::Digest tag = tagOf (m, key, kManifestHeaderBytes);
    m.insert (m.end (), tag.begin (), tag.end ());
    return m;
}

// v2：104 字节，含"这包是给谁做的"
inline std::vector<std::uint8_t> buildManifestV2 (std::uint32_t imageLen,
                                                  const Sha256::Digest &imageSha,
                                                  std::uint16_t keyId,
                                                  const std::string &targetPart,
                                                  const std::string &targetSw,
                                                  const Sha256::Digest &key)
{
    std::vector<std::uint8_t> m;
    m.reserve (kManifestV2Bytes);
    m.insert (m.end (), {'D', 'G', 'I', 'M'});
    m.push_back (0x02);   // version
    m.push_back (0x00);   // flags
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 24) & 0xFF));
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 16) & 0xFF));
    m.push_back (static_cast<std::uint8_t> ((imageLen >> 8) & 0xFF));
    m.push_back (static_cast<std::uint8_t> (imageLen & 0xFF));
    m.insert (m.end (), imageSha.begin (), imageSha.end ());
    m.push_back (static_cast<std::uint8_t> ((keyId >> 8) & 0xFF));
    m.push_back (static_cast<std::uint8_t> (keyId & 0xFF));
    const auto part = fixedText (targetPart, kIdentityPartBytes);
    const auto sw   = fixedText (targetSw, kIdentitySwBytes);
    m.insert (m.end (), part.begin (), part.end ());
    m.insert (m.end (), sw.begin (), sw.end ());
    const Sha256::Digest tag = tagOf (m, key, kManifestV2HeaderBytes);
    m.insert (m.end (), tag.begin (), tag.end ());
    return m;
}

// 返回 true = 这个 keyId 我们认识，并把钥匙写进 outKey
inline bool lookupKey (std::uint16_t keyId, Sha256::Digest &outKey)
{
    if (keyId == 0x0001 || keyId == 0x0002)
    {
        outKey = demoKey (keyId);
        return true;
    }
    return false;
}

// "信封"检查：长度 / magic / 版本 / 钥匙 / 标签 / 身份字段。
//   不看镜像 —— 所以它可以在镜像还没传上来之前就跑（M21 的 0x31 01 0205 用它做预检）。
//   校验顺序仍是先便宜后贵：长度 → magic/版本 → 钥匙 ID → 标签（只看头部）。
inline Check checkEnvelope (const std::vector<std::uint8_t> &manifest, const keys::KeyRing &ring)
{
    Check c;
    const std::size_t n = manifest.size ();

    if (n != kManifestBytes && n != kManifestV2Bytes)
    {
        c.verdict = Verdict::BadLength;
        c.reason  = "清单必须是 76 字节（v1）或 104 字节（v2），实际 " + std::to_string (n) + " 字节";
        return c;
    }
    const bool v2 = (n == kManifestV2Bytes);
    c.manifestVersion = v2 ? 0x02 : 0x01;
    const std::size_t headerBytes = v2 ? kManifestV2HeaderBytes : kManifestHeaderBytes;

    if (manifest[0] != 'D' || manifest[1] != 'G' || manifest[2] != 'I' || manifest[3] != 'M')
    {
        c.verdict = Verdict::BadMagic;
        c.reason  = "清单开头不是 DGIM（这包不是我们这套格式）";
        return c;
    }
    // 长度与版本必须成对：76 ⇄ 0x01，104 ⇄ 0x02
    const std::uint8_t wantVersion = v2 ? 0x02 : 0x01;
    if (manifest[4] != wantVersion || manifest[5] != 0x00)
    {
        c.verdict = Verdict::BadMagic;
        c.reason  = std::string ("清单版本 ").append (1, static_cast<char> ('0' + manifest[4])) +
                    " 与长度 " + std::to_string (n) + " 不配对（76 对应 1，104 对应 2）";
        return c;
    }

    // M22：钥匙从表里查，不是从源码里查。三种结论必须分开：
    //   表里没有 → 不认识（这包不是我们这套体系签的）；
    //   表里有但吊销了 → 拒收（这包可能是一个已知泄露的密钥签的）；
    //   表里有、退役了 → **照验**（在途的包还得能过），但要记账。
    const std::uint16_t keyId = readU16 (manifest, 42);
    const keys::Entry *entry = ring.find (keyId);
    if (entry == nullptr)
    {
        c.verdict = Verdict::UnknownKey;
        c.reason  = "keyId 0x" + keyIdText (keyId) + " 不在钥匙表里（当前：" + ring.dump () + "）";
        return c;
    }
    if (entry->state == keys::State::Revoked)
    {
        c.verdict = Verdict::RevokedKey;
        c.reason  = "keyId 0x" + keyIdText (keyId) + " 已被吊销（这把钥匙不可信，拒收它签的一切）";
        return c;
    }
    c.keyState = entry->state;

    const Sha256::Digest tag = tagOf (manifest, entry->key, headerBytes);
    bool tagSame = true;
    for (int i = 0; i < 32; ++i)
        if (tag[i] != manifest[headerBytes + static_cast<std::size_t> (i)]) { tagSame = false; break; }
    if (!tagSame)
    {
        c.verdict = Verdict::BadTag;
        c.reason  = "标签不符：这包不是知道钥匙的人做的（或者清单被改过）";
        return c;
    }

    if (v2)
    {
        c.hasIdentity = true;
        c.targetPart  = trimText (manifest, 44, kIdentityPartBytes);
        c.targetSw    = trimText (manifest, 56, kIdentitySwBytes);
    }

    c.verdict = Verdict::Ok;
    c.reason  = std::string ("信封对得上（v") + std::to_string (c.manifestVersion) + "，keyId 0x" +
                keyIdText (keyId) + " " + keys::stateName (entry->state) + "）";
    return c;
}

// 老路径：不传钥匙表就用演示表（1/2 号两把都启用）
inline Check checkEnvelope (const std::vector<std::uint8_t> &manifest)
{
    return checkEnvelope (manifest, demoRing ());
}

inline Check verify (const std::vector<std::uint8_t> &image,
                     const std::vector<std::uint8_t> &manifest,
                     const keys::KeyRing &ring)
{
    Check c = checkEnvelope (manifest, ring);
    if (!c.ok ()) return c;

    const std::uint32_t imageLen = readU32 (manifest, 6);
    if (imageLen != image.size ())
    {
        c.verdict = Verdict::LengthMismatch;
        c.reason  = "清单说 " + std::to_string (imageLen) + " 字节，ECU 里是 " +
                    std::to_string (image.size ()) + " 字节";
        return c;
    }

    const Sha256::Digest actual = Sha256::of (image);
    bool shaSame = true;
    for (int i = 0; i < 32; ++i)
        if (actual[i] != manifest[10 + i]) { shaSame = false; break; }
    if (!shaSame)
    {
        Sha256::Digest claimed;
        for (int i = 0; i < 32; ++i) claimed[i] = manifest[10 + i];
        c.verdict = Verdict::HashMismatch;
        c.reason  = "镜像哈希不符：ECU 里的 " + Sha256::hex (actual).substr (0, 16) +
                    "…，清单说 " + Sha256::hex (claimed).substr (0, 16) + "…";
        return c;
    }

    c.verdict = Verdict::Ok;
    c.reason  = "清单与镜像对得上（v" + std::to_string (c.manifestVersion) + "，长度 " +
                std::to_string (imageLen) + "）";
    return c;
}

inline Check verify (const std::vector<std::uint8_t> &image,
                     const std::vector<std::uint8_t> &manifest)
{
    return verify (image, manifest, demoRing ());
}

} // namespace fw
} // namespace doip

#endif
