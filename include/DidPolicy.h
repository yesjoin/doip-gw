#pragma once
// ============================================================================
// DidPolicy.h —— M31：读什么也分档（0x22 的 DID 白名单）
//
// M30 只看服务号：0x22 一律按"读"档。可 0x22 读的东西不是一样重的东西：
//   0xF190（VIN）读走没关系，那是印在挡风玻璃下面的；
//   0xF1B0（钥匙表）读走，等于把"这台车认哪些钥匙"整份交出去；
//   0xF1B2（清单指纹）读走，能判断车上是哪个包、有没有被换过。
// 同一档"读"，读的东西不一样重 —— 所以读档之内还得再分一次。
//
// ★ 只对 0x22 生效
//   DID 是 0x22 的参数。0x2E 写同一个 DID 时，参数同样在，但"写"本来就要写档，
//   敏感度由 M19（写指纹要编程会话 + 解锁）和 ECU 自己的 0x27 管。这一层只管"读"。
//
// ★ 三档，映射到 M30 的三档，不另造一套
//   公开(Open)   → 读档就够      （VIN、硬件版本、当前会话）
//   受限(Guarded)→ 要写档        （指纹、零件号这类"读了能判断版本/改动"的）
//   锁死(Secret) → 要刷写档      （钥匙表、清单指纹/摘要、流水这类"读了等于交底"的）
//   判定仍然走 PermissionTable::decide —— 只是"要什么档"多问了一次 DID。
//
// ★ 不认识的 DID 按"受限"（安全默认）
//   DID 空间 65536 个，厂商私有 DID 一大片。默认给它"公开"等于默许读走一切。
//   于是：想读什么，就一条条点名（--did F190:open）。默认档可以改（--did-default），
//   但改了要在横幅上看得见。
//
// ★ 名字只是给人看的
//   didName() 那张小表（VIN / 钥匙表 / …）不参与判定，只进日志。
//   判定只看 (DID, 级别) 这一对数 —— 改个名字不会改变谁能读。
//
// ★ 边界
//   1) 只在网关这一跳生效，能直接接 CAN 的人绕过。
//   2) 表是命令行配置，能改配置就能提权（和 M30 的档位、M27 的票同一个信任模型）。
//   3) 只区分"读哪个 DID"，不区分"读几条、读多快"——没有速率与配额。
//   4) 0x22 一次带多个 DID 的写法（有的实现支持）这里只认第一个，其余不管。
// ============================================================================
#include "OpPermission.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace doip
{
namespace dids
{

// 读一个 DID 需要什么"级别"。数字大小就是"谁包含谁"：Open < Guarded < Secret。
enum class Level : std::uint8_t
{
    Open    = 0,
    Guarded = 1,
    Secret  = 2
};

inline const char *levelName (Level l)
{
    switch (l)
    {
    case Level::Open:    return "公开";
    case Level::Guarded: return "受限";
    case Level::Secret:  return "锁死";
    default:             return "未知";
    }
}

// 只认 open / guarded / secret（大小写不敏感，容忍首尾空白）。
inline bool parseLevel (const std::string &s, Level &out)
{
    std::size_t b = 0, e = s.size ();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    std::string w = s.substr (b, e - b);
    for (char &c : w) if (c >= 'A' && c <= 'Z') c = static_cast<char> (c - 'A' + 'a');
    if (w == "open")    { out = Level::Open;    return true; }
    if (w == "guarded") { out = Level::Guarded; return true; }
    if (w == "secret")  { out = Level::Secret;  return true; }
    return false;
}

// 级别 → 需要哪一档（复用 M30 的三档，不另造）。
inline ops::Tier tierOf (Level l)
{
    switch (l)
    {
    case Level::Open:    return ops::Tier::Read;
    case Level::Guarded: return ops::Tier::Write;
    default:             return ops::Tier::Flash;
    }
}

// 只给日志看的一张备注表。**不参与判定**：判定只看 (did, level)。
inline const char *didName (std::uint16_t did)
{
    switch (did)
    {
    case 0xF184: return "指纹";
    case 0xF186: return "当前会话";
    case 0xF187: return "零件号";
    case 0xF188: return "软件指纹";
    case 0xF18C: return "变更流水";
    case 0xF190: return "VIN";
    case 0xF191: return "硬件版本";
    case 0xF1A5: return "电池电压";
    case 0xF1B0: return "钥匙表";
    case 0xF1B1: return "清单摘要";
    case 0xF1B2: return "清单指纹";
    case 0xF1B3: return "流水概览";
    default:     return "未登记";
    }
}

inline std::string hex4 (std::uint16_t v)
{
    char b[8];
    std::snprintf (b, sizeof b, "0x%04X", static_cast<unsigned> (v));
    return std::string (b);
}

// 一条"读 DID 相关"的报文：请求 0x22，或它的正响应 0x62。
//   两个方向都用这同一个结构 —— 请求侧问"你想读什么"，响应侧问"这条数据是什么"。
struct DidInfo
{
    std::uint16_t did    = 0;
    bool          isRead = false;          // 是不是读 DID 相关（0x22 请求 / 0x62 响应）
    Level         level  = Level::Guarded;  // 只有 isRead 时有意义（needFor* 才填）
    std::string   what;                    // 给日志看的一句话
};

inline bool classify (const std::uint8_t *uds, std::size_t len, DidInfo &out)
{
    out = DidInfo{};
    if (len < 3 || uds[0] != 0x22) return false;
    out.did    = static_cast<std::uint16_t> ((static_cast<std::uint16_t> (uds[1]) << 8) | uds[2]);
    out.isRead = true;
    return true;
}

// M32：读 DID 的正响应 0x62 <DID> <数据>。
//   请求侧挡了"想读"还不够 —— **数据就是靠这条 0x62 流出去的**。
//   两条腿合起来才是完整的防火墙：请求侧问"你想干什么"，响应侧问"数据往哪流"。
inline bool classifyResponse (const std::uint8_t *uds, std::size_t len, DidInfo &out)
{
    out = DidInfo{};
    if (len < 3 || uds[0] != 0x62) return false;
    out.did    = static_cast<std::uint16_t> ((static_cast<std::uint16_t> (uds[1]) << 8) | uds[2]);
    out.isRead = true;
    return true;
}

// DID → 级别。没登记过的拿默认级别。
class DidPolicy
{
public:
    void setDefault (Level l) { default_ = l; }
    Level defaultLevel () const { return default_; }

    // 同一个 DID 再配一次 = 改级别（后写的生效），不叠成两行。
    bool set (std::uint16_t did, Level l)
    {
        if (did == 0) return false;          // 0 留下当"没登记"（与默认级别同义）
        for (auto &e : entries_)
            if (e.did == did) { e.level = l; return true; }
        entries_.push_back (Entry{did, l});
        return true;
    }

    Level levelOf (std::uint16_t did) const
    {
        for (const auto &e : entries_)
            if (e.did == did) return e.level;
        return default_;
    }

    std::size_t   size () const { return entries_.size (); }
    std::uint16_t didAt (std::size_t i) const { return entries_[i].did; }
    Level         levelAt (std::size_t i) const { return entries_[i].level; }

private:
    struct Entry
    {
        std::uint16_t did;
        Level         level;
    };
    std::vector<Entry> entries_;
    Level              default_ = Level::Guarded;   // 不认识的按受限：安全默认
};

inline ops::Tier raise (ops::Tier base, ops::Tier didNeed)
{
    return static_cast<std::uint8_t> (base) >= static_cast<std::uint8_t> (didNeed) ? base : didNeed;
}

// 把"这一条需要什么档"往上抬一次。不是 DID 读请求 → 原样返回（不动别的服务）。
inline ops::Tier needFor (const DidPolicy &table, const std::uint8_t *uds, std::size_t len,
                          ops::Tier base, DidInfo &out)
{
    out = DidInfo{};
    if (!classify (uds, len, out)) return base;
    out.level = table.levelOf (out.did);
    out.what  = "读 DID " + hex4 (out.did) + "（" + didName (out.did) + "，" +
                levelName (out.level) + "级）";
    return raise (base, tierOf (out.level));
}

// M32：响应方向。0x62 <DID> 需要什么档；不是 DID 读响应 → 返回 Read 且 out.isRead=false。
//   调用方先看 out.isRead：false 的响应**不归这一层管**（7F / 50 / 71 / … 都原样走）。
inline ops::Tier needForResponse (const DidPolicy &table, const std::uint8_t *uds,
                                  std::size_t len, DidInfo &out)
{
    out = DidInfo{};
    if (!classifyResponse (uds, len, out)) return ops::Tier::Read;
    out.level = table.levelOf (out.did);
    out.what  = "读响应 DID " + hex4 (out.did) + "（" + didName (out.did) + "，" +
                levelName (out.level) + "级）";
    return tierOf (out.level);
}

}   // namespace dids
}   // namespace doip
