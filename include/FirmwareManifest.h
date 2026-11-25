// ============================================================================
// FirmwareManifest.h —— M18：刷写包的"清单 + 标签"（纯逻辑，header-only）
//
// 为什么 CRC 不够：
//   M15 的 0x37 带 CRC-32，它证明"传的过程没出错"。但 CRC 是线性的 ——
//   有人换掉镜像里的两个字节，再补一个"补偿值"，CRC 照样能对上。
//   CRC 防手滑，不防有人动手。
//
// 清单长什么样（固定 76 字节，版本化了，不猜）：
//   [0..3]   "DGIM"          magic
//   [4]      0x01            version
//   [5]      0x00            flags（保留）
//   [6..9]   imageLen        u32 大端：镜像多少字节
//   [10..41] imageSha        SHA-256(镜像)，32 字节
//   [42..43] keyId           u16 大端：用哪把钥匙
//   [44..75] tag             SHA-256(前 44 字节 || 钥匙)，32 字节
//
// 标签（tag）是什么，不是什么 —— 这是本题最重要的一句话：
//   它是**对称 MAC**（双方共用一把钥匙），所以它证明"这个包是知道钥匙的人做的"，
//   不能证明"这是厂商做的"（那需要非对称签名：私钥签、公钥验）。
//   本项目的钥匙写在代码里，所以它防的是"别人顺手换包"，不是"对手蓄意伪造"。
//
// 校验顺序也是设计的一部分（先便宜后贵）：
//   长度 → magic/版本 → 钥匙 ID → 标签（只看 44 字节）→ 镜像哈希（要看整包）
//   镜像可能有几兆，标签只有 44 字节 —— 便宜的先做，贵的后做。
// ============================================================================
#ifndef DOIP_FIRMWARE_MANIFEST_H
#define DOIP_FIRMWARE_MANIFEST_H

#include "Sha256.h"

#include <cstdint>
#include <string>
#include <vector>

namespace doip {
namespace fw {

inline constexpr std::size_t kManifestBytes = 76;
inline constexpr std::size_t kManifestHeaderBytes = 44;

enum class Verdict
{
    Ok = 0,
    BadLength,       // 清单既不是 76 字节（格式外的东西，0x13）
    BadMagic,        // magic / version / flags 不对（不是我们这个格式，0x31）
    UnknownKey,      // keyId 不认识（0x31）
    BadTag,          // 标签对不上（有人换了清单或不知道钥匙）→ 状态 01
    LengthMismatch,  // 清单说的长度与镜像实际长度不符 → 状态 01
    HashMismatch     // 镜像哈希不符（包与镜像不是一对）→ 状态 01
};

struct Check
{
    Verdict     verdict = Verdict::Ok;
    std::string reason;

    bool ok () const { return verdict == Verdict::Ok; }
};

// 演示钥匙：keyId 0x0001/0x0002，key = SHA-256("doip-gw demo key <id>")。
// 真实项目里钥匙在刷写包和 ECU 的 NVM 里，不在源码里。
inline Sha256::Digest demoKey (std::uint16_t id)
{
    return Sha256::ofText ("doip-gw demo key " + std::to_string (id));
}

inline Sha256::Digest tagOf (const std::vector<std::uint8_t> &manifest, const Sha256::Digest &key)
{
    std::vector<std::uint8_t> buf (manifest.begin (), manifest.begin () + kManifestHeaderBytes);
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
    const Sha256::Digest tag = tagOf (m, key);
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

inline Check verify (const std::vector<std::uint8_t> &image,
                     const std::vector<std::uint8_t> &manifest)
{
    Check c;
    if (manifest.size () != kManifestBytes)
    {
        c.verdict = Verdict::BadLength;
        c.reason  = "清单必须是 " + std::to_string (kManifestBytes) + " 字节，实际 " +
                    std::to_string (manifest.size ()) + " 字节";
        return c;
    }
    if (manifest[0] != 'D' || manifest[1] != 'G' || manifest[2] != 'I' || manifest[3] != 'M')
    {
        c.verdict = Verdict::BadMagic;
        c.reason  = "清单开头不是 DGIM（这包不是我们这套格式）";
        return c;
    }
    if (manifest[4] != 0x01 || manifest[5] != 0x00)
    {
        c.verdict = Verdict::BadMagic;
        c.reason  = "清单版本/标志位不认识（版本 0x" + std::to_string (manifest[4]) + "）";
        return c;
    }

    Sha256::Digest key;
    std::uint16_t  keyId = readU16 (manifest, 42);
    if (!lookupKey (keyId, key))
    {
        c.verdict = Verdict::UnknownKey;
        c.reason  = "keyId 0x" + std::to_string (keyId) + " 不认识（ECU 里没有这把钥匙）";
        return c;
    }

    const Sha256::Digest tag = tagOf (manifest, key);
    bool tagSame = true;
    for (int i = 0; i < 32; ++i)
        if (tag[i] != manifest[44 + i]) { tagSame = false; break; }
    if (!tagSame)
    {
        c.verdict = Verdict::BadTag;
        c.reason  = "标签不符：这包不是知道钥匙的人做的（或者清单被改过）";
        return c;
    }

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
    c.reason  = "清单与镜像对得上（keyId 0x" + std::to_string (keyId) + "，长度 " +
                std::to_string (imageLen) + "）";
    return c;
}

} // namespace fw
} // namespace doip

#endif
