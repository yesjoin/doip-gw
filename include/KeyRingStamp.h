// ============================================================================
// KeyRingStamp.h —— M25：一张表还要有"指纹"和"改过几次"
//
// M24 的摘要是四个计数：总 / 启用 / 退役 / 吊销。它便宜（4 个 u8，7 字节），
// 但它只回答"数量对不对"，回答不了"**是不是同一张表**"：
//
//   A 车装了 5 号   → 总 4 / 启用 4
//   B 车装了 6 号   → 总 4 / 启用 4     ← 摘要一模一样，认的却不是同一把钥匙
//
// 这不是假想的边角：车队轮换钥匙时，脚本按"逐台下发"，一台失败重试、一台先装了别的，
// 计数照样对得上，摘要照样"全绿"。**计数是数量，不是内容。**
//
// 所以再压一层，两个数：
//   · 指纹（fingerprint，u16）：把 (keyId, 状态) 的规范串排好序做 SHA-256，取前 2 字节。
//     它只看**内容**，不看历史。内容一样 → 指纹一样；内容差一个状态 → 指纹就不一样。
//   · 世代（generation，u16）：每成功改一次表 +1。它只看**历史**，不看内容。
//
// 为什么两个都要：
//   A 退役 3 号，又改回启用 → 内容和原来完全相同（指纹相同），但它**被动过**。
//   现场排查要能区分"这台没人碰过"和"这台被改回去过"—— 那是两个完全不同的故事。
//
// 为什么指纹是 2 字节而不是 4/8：
//   它就是给广播用的（`0x22 F1B2` 要 ≤7 字节）。2 字节 = 65536 分之一，
//   在"几台车的钥匙表"这个规模上足够抓错；**它不是防篡改手段**，
//   真要防篡改用 `FF02` 的清单签名（M18/M21），那是另一层。
//
// 世代为什么 0 不能用：0 专门留给"文件里没有 VER 行"的旧文件（M23 的 v1）。
//   于是"V1 旧文件读进来"和"从没改过"是同一件事，都不会被误当成一次真实变更。
// ============================================================================
#ifndef DOIP_KEY_RING_STAMP_H
#define DOIP_KEY_RING_STAMP_H

#include "KeyRing.h"
#include "Sha256.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace doip {
namespace keys {

// 世代：u16，1..0xFFFF。0 保留（见文件头）。
using Generation = std::uint16_t;

// 规范串：按 id 升序，一把一行 "XXXX=SS;"。
//   为什么要有"规范"这一步：表里是按装入顺序存的，两台车装钥匙的顺序可能不同。
//   不排序，同一张表在两个进程里会算出两个指纹 —— 那这个指纹就没法对账了。
inline std::string canonicalOf (const KeyRing &ring)
{
    std::vector<std::pair<std::uint16_t, std::uint8_t>> rows;
    for (std::size_t i = 0; i < ring.size (); ++i)
        rows.emplace_back (ring.at (i).id, stateCode (ring.at (i).state));
    std::sort (rows.begin (), rows.end ());

    std::string s;
    char buf[16];
    for (const auto &row : rows)
    {
        std::snprintf (buf, sizeof buf, "%04X=%02X;", static_cast<unsigned> (row.first),
                       static_cast<unsigned> (row.second));
        s += buf;
    }
    return s;
}

// 指纹 = SHA-256(规范串) 的前 2 字节（大端当成 u16）。
//   为什么取前 2 字节而不是"异或各 id"：异或对"两把互换状态"这种改动会正正好抵消 ——
//   那是最需要被抓到的一类改动。
inline std::uint16_t fingerprintOf (const KeyRing &ring)
{
    const Sha256::Digest d = Sha256::ofText (canonicalOf (ring));
    return static_cast<std::uint16_t> ((static_cast<std::uint16_t> (d[0]) << 8) | d[1]);
}

inline std::string fingerprintText (std::uint16_t fp)
{
    char buf[8];
    std::snprintf (buf, sizeof buf, "%04X", static_cast<unsigned> (fp));
    return std::string (buf);
}

// 下一代：成功改一次表就 +1；到头绕回 1（跳过 0）。
//   绕回为什么可以接受：世代只是"是不是同一段历史"的粗判，
//   65535 次变更之后才可能撞上，真到那个量级要靠清单版本（另一层）。
inline Generation nextGeneration (Generation g)
{
    if (g >= 0xFFFF) return 1;
    return static_cast<Generation> (g + 1);
}

// 一句话给日志/退账用："版本 7，指纹 3F21"
inline std::string stampText (const KeyRing &ring, Generation g)
{
    return "版本 " + std::to_string (static_cast<unsigned> (g)) + "，指纹 " +
           fingerprintText (fingerprintOf (ring));
}

} // namespace keys
} // namespace doip

#endif
