#pragma once
// ============================================================================
// DoIpEntityStatus.h —— M14：实体状态（0x4001/0x4002）与电源模式（0x4003/0x4004）
//
// 这两对报文和 M1 的车辆发现是"邻居"：都走 UDP 13400，都不需要 TCP 连接，
// 但回答的不是同一件事：
//   0x0001 → 0x0004   "你是谁、VIN 多少"        （发现）
//   0x4001 → 0x4002   "你还能接几台、能收多大"    （实体状态）
//   0x4003 → 0x4004   "现在能做诊断吗"           （电源模式）
//
// 为什么 M14 选这个：M13 刚建好一张实体级的账（谁激活了、几个名额在用），
// 但它只活在网关自己的日志里。0x4002 正好是标准里"把这些账对外公布"的那条报文 ——
// 装上它，M13 的账才从"自己知道"变成"诊断仪能问出来"。
//
// 三条容易讲错的点，先写在头里：
//   ① **0x4001 / 0x4003 只能走 UDP。** 它不是"连接内协商"，是"连上来之前先问清楚"。
//      TCP 上收到它属于不合规用法，本实现不回答、只记账（别惯着错误的客户端）。
//   ② **cur_open_sockets 数的是"开着的 TCP socket"，不是"激活了几台"。**
//      这两件事在 M13 才刚拆开（maxConnections 8 / maxActivated 4）。
//      混起来的话，一个没激活的连接会让 0x4002 报出"已占 1 个"，而实体实际还空闲。
//   ③ **对外报的 max_data_size 必须等于你真正在 parseMessage 里卡的那个数。**
//      报 32KB 却在内部分 4KB 拒收，诊断仪会按你的公告发大包，然后每次都被 NACK 0x02 ——
//      这不是"标准有问题"，是公告和实现不一致。
// ============================================================================
#include "DoIpCodec.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace doip
{

// ---------------------------------------------------------------------------
// 取值表（ISO 13400-2 表：节点类型 / 诊断电源模式）
// ---------------------------------------------------------------------------
constexpr std::uint8_t kNodeTypeGateway = 0x00;   // 网关：能从这边进、往子网转
constexpr std::uint8_t kNodeTypeNode    = 0x01;   // 节点：就到我自己，不转发

constexpr std::uint8_t kPowerNotReady     = 0x00;  // 还没准备好：不是所有 ECU 都能说话
constexpr std::uint8_t kPowerReady        = 0x01;  // 准备好：能做诊断
constexpr std::uint8_t kPowerNotSupported = 0x02;  // 能接这个请求，但给不出电源状态

// 0x4002 的载荷长度：4 字节（node type + max + cur）是 2012 的短式，
// 7 字节（再带 4 字节 max data size）是现在主流在用的长式。
// 解析两种都要认 —— 只认一种，遇到另一种实现就"解不开"。
constexpr std::size_t kEntityStatusShort = 3;
constexpr std::size_t kEntityStatusFull  = 7;

// ---------------------------------------------------------------------------
// 0x4002 的载荷：实体对自己能力的公告
// ---------------------------------------------------------------------------
struct EntityStatusInfo
{
    std::uint8_t  nodeType       = kNodeTypeGateway;
    std::uint8_t  maxOpenSockets = 8;      // 同时能挂住几条 TCP_DATA socket（1 字节，上限 255）
    std::uint8_t  curOpenSockets = 0;      // 现在开着几条（**连接数，不是激活数**）
    std::uint32_t maxDataSize    = kDefaultMaxPayload;  // 能处理的最大 DoIP 载荷，0 = 未告知
};

// 把"配置 + 当前计数"合成一份快照。
// 单拎出来是为了让"超过 255 要压到 255"这条边界能在内存里测 ——
// 真到了实体上，报 0x1FF 会被塞进 1 个字节，变成 0xFF 甚至 0x01，现场看日志完全对不上。
EntityStatusInfo entityStatusFromCounts (std::size_t maxConnections,
                                         std::size_t openSockets,
                                         std::uint32_t maxDataSize,
                                         std::uint8_t  nodeType = kNodeTypeGateway);

struct PowerModeInfo
{
    std::uint8_t mode = kPowerReady;
};

struct EntityReply
{
    bool                      replied = false;
    std::vector<std::uint8_t> bytes;    // 完整报文（8 字节头 + 载荷）
    std::string               reason;   // 为什么回 / 为什么不回
};

// 编码：结构 → payload 字节（不含 8 字节头）
inline std::vector<std::uint8_t> encodePayload (const EntityStatusInfo &s)
{
    std::vector<std::uint8_t> p;
    p.reserve (kEntityStatusFull);
    p.push_back (s.nodeType);
    p.push_back (s.maxOpenSockets);
    p.push_back (s.curOpenSockets);
    // 4 字节大端 —— DoIP 里所有多字节字段都是大端，别按 DBC 的小端习惯写
    p.push_back (static_cast<std::uint8_t> ((s.maxDataSize >> 24) & 0xFF));
    p.push_back (static_cast<std::uint8_t> ((s.maxDataSize >> 16) & 0xFF));
    p.push_back (static_cast<std::uint8_t> ((s.maxDataSize >> 8) & 0xFF));
    p.push_back (static_cast<std::uint8_t> (s.maxDataSize & 0xFF));
    return p;
}

inline std::vector<std::uint8_t> encodePayload (const PowerModeInfo &m)
{
    return {m.mode};
}

// 解码：长度不对就报错，不猜。
//   3 字节 → 老式短载荷：maxDataSize 当作 0（"未告知"），不是 4096。
//   7 字节 → 长载荷：四个字段都读。
//   其它   → 解不开。
inline bool decodePayload (const std::vector<std::uint8_t> &p, EntityStatusInfo &out, std::string &err)
{
    if (p.size () != kEntityStatusShort && p.size () != kEntityStatusFull)
    {
        err = "0x4002 载荷应为 3 或 7 字节，实际 " + std::to_string (p.size ()) + " 字节";
        return false;
    }
    out.nodeType       = p[0];
    out.maxOpenSockets = p[1];
    out.curOpenSockets = p[2];
    out.maxDataSize    = 0;
    if (p.size () == kEntityStatusFull)
    {
        out.maxDataSize = (static_cast<std::uint32_t> (p[3]) << 24) |
                          (static_cast<std::uint32_t> (p[4]) << 16) |
                          (static_cast<std::uint32_t> (p[5]) << 8)  |
                          (static_cast<std::uint32_t> (p[6]));
    }
    return true;
}

inline bool decodePayload (const std::vector<std::uint8_t> &p, PowerModeInfo &out, std::string &err)
{
    if (p.size () != 1)
    {
        err = "0x4004 载荷应为 1 字节，实际 " + std::to_string (p.size ()) + " 字节";
        return false;
    }
    if (p[0] > kPowerNotSupported)
    {
        // 0x03 及以上是"保留值"。这里当错误处理而不是猜成 ready ——
        // 猜错了会让人以为车能做诊断，实际连不上，排查方向全歪。
        err = "0x4004 的电源模式只定义 0x00–0x02，收到 0x" + std::to_string (p[0]);
        return false;
    }
    out.mode = p[0];
    return true;
}

// ---------------------------------------------------------------------------
// 纯逻辑：UDP 上收到一条报文，它是不是实体状态/电源模式请求，回什么
//   0x4001（载荷必须 0 字节）→ 0x4002
//   0x4003（载荷必须 0 字节）→ 0x4004
//   其它                      → 沉默
//
// 载荷不为 0 的 0x4001 为什么沉默而不是"回 NACK"：UDP 上没有 NACK 这一说
// （M1 就定下的规矩：坏报文安静丢弃，否则一个坏广播 + N 个实体 = 广播风暴）。
// 同理，这条函数永远不产生 0x0000。
// ---------------------------------------------------------------------------
inline EntityReply respondToEntityQuery (const Message &req,
                                        const EntityStatusInfo &status,
                                        const PowerModeInfo &power)
{
    EntityReply r;
    const PayloadType t = toType (req.header.payloadType);
    const std::size_t  n = req.payload.size ();

    if (t == PayloadType::EntityStatusReq)
    {
        if (n != 0)
        {
            r.reason = "0x4001 载荷应为 0 字节，实际 " + std::to_string (n) + " 字节 → 沉默";
            return r;
        }
        r.replied = true;
        r.bytes   = build (PayloadType::EntityStatusRes, encodePayload (status));
        r.reason  = "0x4001 → 0x4002：socket " + std::to_string (status.curOpenSockets) + "/" +
                    std::to_string (status.maxOpenSockets) + "，最大载荷 " +
                    std::to_string (status.maxDataSize) + " 字节";
        return r;
    }

    if (t == PayloadType::PowerModeReq)
    {
        if (n != 0)
        {
            r.reason = "0x4003 载荷应为 0 字节，实际 " + std::to_string (n) + " 字节 → 沉默";
            return r;
        }
        r.replied = true;
        r.bytes   = build (PayloadType::PowerModeRes, encodePayload (power));
        r.reason  = std::string ("0x4003 → 0x4004：") + (power.mode == kPowerReady ? "ready" :
                       power.mode == kPowerNotReady ? "not ready（车还没上电/ECU 还没醒）" :
                                                      "not supported（给不出这个信息）");
        return r;
    }

    r.reason = std::string ("不是实体状态/电源模式请求（") + nameOf (t) + "）→ 沉默";
    return r;
}

// ---------------------------------------------------------------------------
// 实现：把"配置 + 计数"折成快照
// ---------------------------------------------------------------------------
inline EntityStatusInfo entityStatusFromCounts (std::size_t maxConnections,
                                                std::size_t openSockets,
                                                std::uint32_t maxDataSize,
                                                std::uint8_t  nodeType)
{
    EntityStatusInfo s;
    s.nodeType       = nodeType;
    // 1 字节字段：超过 255 压到 255。宁可报"255 封顶"，也不要让它回绕成 0x01。
    s.maxOpenSockets = static_cast<std::uint8_t> (std::min<std::size_t> (maxConnections, 255));
    s.curOpenSockets = static_cast<std::uint8_t> (std::min<std::size_t> (openSockets, 255));
    s.maxDataSize    = maxDataSize;
    return s;
}

} // namespace doip
