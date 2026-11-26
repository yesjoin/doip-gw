// ============================================================================
// ActivationAuth.h —— M27：路由激活的"入场券"（纯逻辑，header-only）
//
// 为什么这一步要单独做：
//   M26 的流水已经能答"什么时候、动了哪把、表变成了什么样"，
//   但"谁改的"这一栏还空着 —— 因为网关到现在为止**谁都放进来**：
//   一条 TCP 连接，发一个 0x0005，写个源地址，就拿到总线上的写权限。
//   日志里那句"0x0005 ← 0x0E00"只能说明"有人自称 0x0E00"。
//
// 所以顺序只能是先关门、再记名字：
//   1) 关门：激活时要求"能证明自己"（本文件）—— 证明不了就 0x04 MissingAuthentication；
//   2) 记名：把证明过的身份传到 CAN 侧、落进 ECU 的流水（下一步）。
//   先做 2 再回头补 1，等于先给陌生人发工牌。
//
// 用什么证明：
//   ISO 13400-2 的 0x0005 载荷是 SA(2) + 类型(1) + reserved(4) + **OEM(4)**。
//   标准把最后 4 字节留给 OEM —— 也就是"厂商想加什么就加什么"。
//   我们用它装一个 4 字节的 token：HMAC-SHA256(secret, "doip-ra|<SA>") 的头 4 字节。
//
// 为什么是 HMAC，而不是 sha256(secret + 消息)：
//   后者有长度扩展攻击 —— 攻击者拿到 H(secret||m) 之后，可以在 m 后面接一段自己造的尾巴，
//   不掌握 secret 也能算出 H(secret || m || 尾巴)。HMAC 用内外两层 0x36/0x5c 盐把这条路堵死。
//   （自测里 A 组直接用 RFC 4231 的官方向量钉住，跑得过官方答案才叫 HMAC。）
//
// 为什么 token 绑住 SA：
//   同一把 secret、同一台 tester 换一个源地址，token 就不一样。
//   这样"0x0E00 的票"不能原样拿去当"0x0E01 的票"用 —— 挡住最省事的那种冒充。
//
// ★ 已知边界（必须记住，不然会把"挡了一下"当成"安全"）：
//   1) 4 字节 = 32 位。对着一条连接硬猜，期望 2^31 次；能挡住随手试，挡不住有耐心的攻击者。
//      标准就只留了 4 字节 —— 这本身就是"身份不该做在这一层"的证据。
//   2) 静态凭据可以**重放**：抓到一次 0x0005，就能原样再发一次。
//      协议里没有 nonce 的位置（0x0005 不能"先问再答"），真车靠的是 TLS / 证书
//      （0x0005 里那个 0xE0 CentralSecurity 类型就是干这个的，本项目不做）。
//   3) 密钥是"预共享"的：网关和每台 tester 手里都有同一把。谁泄露谁就全泄露。
//   所以 M27 的准确说法是"把门关上了"，不是"门锁死了"。
// ============================================================================
#ifndef DOIP_ACTIVATION_AUTH_H
#define DOIP_ACTIVATION_AUTH_H

#include "Sha256.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace doip
{
namespace auth
{

// 32 字节的预共享密钥。用 Sha256::Digest 装着，只为了"定长、能比较、能打印"。
using Secret = Sha256::Digest;

// HMAC-SHA256（RFC 2104 / FIPS 198-1）。key 长度随便，内部先修到 64 字节。
inline Sha256::Digest hmacSha256 (const std::uint8_t *key, std::size_t keyLen,
                                  const void *msg, std::size_t msgLen)
{
    // ---- 第一步：把 key 修成 64 字节 ----
    //   长了（>64）先压成 32 —— 标准这么规定，不是我们偷懒；短了补 0。
    std::uint8_t k[64];
    std::memset (k, 0, sizeof k);
    if (keyLen > 64)
    {
        const Sha256::Digest kh = Sha256::of (key, keyLen);
        std::memcpy (k, kh.data (), 32);
    }
    else if (keyLen > 0)
    {
        std::memcpy (k, key, keyLen);
    }

    // ---- 第二步：内层 = SHA256((k ^ 0x36) || msg) ----
    std::uint8_t pad[64];
    for (int i = 0; i < 64; ++i) pad[i] = static_cast<std::uint8_t> (k[i] ^ 0x36);
    Sha256 inner;
    inner.update (pad, sizeof pad);
    inner.update (msg, msgLen);          // msgLen = 0 时指针不会被解引用
    const Sha256::Digest d = inner.finish ();

    // ---- 第三步：外层 = SHA256((k ^ 0x5c) || 内层摘要) ----
    for (int i = 0; i < 64; ++i) pad[i] = static_cast<std::uint8_t> (k[i] ^ 0x5c);
    Sha256 outer;
    outer.update (pad, sizeof pad);
    outer.update (d.data (), d.size ());
    return outer.finish ();
}

// SA 的 4 位十六进制文本 —— token 的"作用域"，也进日志。
inline std::string saText (std::uint16_t sa)
{
    static const char *digits = "0123456789ABCDEF";
    std::string s (4, '0');
    for (int i = 0; i < 4; ++i)
        s[i] = digits[(sa >> (12 - i * 4)) & 0x0F];
    return s;
}

// 这条连接该带的 token（4 字节，大端拼进 0x0005 的 OEM 字段）。
//   消息里带 "doip-ra|" 前缀是**域分离**：以后若别的地方也用这把 secret，
//   两处的 HMAC 不会撞成同一个值。
inline std::uint32_t tokenFor (const Secret &secret, std::uint16_t sa)
{
    const std::string msg = "doip-ra|" + saText (sa);
    const Sha256::Digest d =
        hmacSha256 (secret.data (), secret.size (), msg.data (), msg.size ());
    return (static_cast<std::uint32_t> (d[0]) << 24) |
           (static_cast<std::uint32_t> (d[1]) << 16) |
           (static_cast<std::uint32_t> (d[2]) << 8) |
           static_cast<std::uint32_t> (d[3]);
}

// 固定时间比较。为什么不能 `want == got` 了事：
//   普通的比较一发现不同就 return，"差在第几个字节"会从耗时里漏出去。
//   4 字节的票本来就短，再白送一个"逐字节试探"的侧信道，等于把门虚掩着。
inline bool tokenMatches (const Secret &secret, std::uint16_t sa, std::uint32_t got)
{
    const std::uint32_t diff = tokenFor (secret, sa) ^ got;
    std::uint8_t acc = 0;
    for (int i = 0; i < 4; ++i)
        acc = static_cast<std::uint8_t> (acc | ((diff >> (i * 8)) & 0xFFu));
    return acc == 0;
}

// 把日志/命令行里的 token 打成 8 位十六进制，方便肉眼对一遍。
inline std::string tokenText (std::uint32_t t)
{
    static const char *digits = "0123456789ABCDEF";
    std::string s (8, '0');
    for (int i = 0; i < 8; ++i)
        s[i] = digits[(t >> (28 - i * 4)) & 0x0F];
    return s;
}

// "64 位十六进制"→ 32 字节密钥。长度不对、有非十六进制字符，一律不认（不猜）。
inline bool parseSecret (const std::string &hex, Secret &out)
{
    if (hex.size () != 64) return false;
    auto nibble = [] (char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i)
    {
        const int hi = nibble (hex[i * 2]);
        const int lo = nibble (hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t> (hi * 16 + lo);
    }
    return true;
}

} // namespace auth
} // namespace doip

#endif
