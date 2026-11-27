#pragma once
// ============================================================================
// OpPermission.h —— M30：按"操作"分权限（读 < 写 < 刷写）
//
// M27 只回答了"你是不是你自称的那台"（认证）。M28/M29 把"谁"送到了 CAN 侧。
// 但认证不等于授权：一台有票的读档诊断仪，照样能发 0x31 装钥匙、能发 0x34 刷写。
// 这一步补的是后半句：**你能干什么**。
//
// ★ 只按服务号分档，而且分三档，不做更细的
//   UDS 的服务号（第一个字节）本身就在表达"意图"：
//     读：0x22 读 DID、0x19 读 DTC、0x3E 保活（什么也不改）
//     写：0x10 切会话、0x27 安全访问、0x2E 写 DID、0x2F IO 控制、0x11 复位、0x14 清 DTC、
//         0x28 通信控制、0x85 DTC 设置、0x83 时序参数
//     刷写：0x31 例程（擦除/校验/装钥匙都在这一个服务里）、0x34 请求下载、0x36 传块、0x37 退出
//   三档是一个"阶梯"：读 ⊆ 写 ⊆ 刷写。给"写"档的人当然能读。
//
// ★ 为什么不给"不认识的服务号"一个中间档
//   中间档的意思是"看起来不危险就放"。而"看起来不危险"正是攻击面：新协议、厂商私有服务、
//   甚至打错的字节，都会落到"不认识"。所以不认识 → **按最高档要求**（安全默认）。
//
// ★ 为什么按 SA，不按连接号、不按位子
//   位子会回收（M29 的结论），连接号每次重连都变。**权限绑的是"人"**，也就是 SA。
//   票证明 SA（M27），表给出档（这里）——认证与授权分开，改其中一个不会牵动另一个。
//
// ★ 这一层是"越界"的，所以默认关
//   网关本来是传输桥（M3.5 的规矩：不改报文内容）。这里的"挡回"是网关**替 ECU** 回一条
//   UDS 负应答 7F <SID> 33 —— 那句话本来该由 ECU 说。所以：默认关、横幅写明、日志点名
//   （哪台 SA、想干什么、只有什么档）。0x33 不是自造的码：UDS 里就是 securityAccessDenied。
//
// ★ 它挡不住的事（写在代码里，免得被当成安全产品）
//   1) 只在网关这一侧生效：能直接接到 CAN 总线的人绕过它（真车靠总线段隔离 + ECU 自己的 0x27）。
//   2) 档位是**配置文件**，不是凭证的一部分：能改网关配置的人就能提权（M27 的票也一样是预共享）。
//   3) 只看服务号，不看参数：0x22 读什么 DID、0x31 哪个子功能，这一层都不看。
//      "读档的人能不能读安全相关的 DID"是下一层的事（要按 DID 配白名单）。
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace doip
{
namespace ops
{

// 权限档。数字大小就是"谁包含谁"：Read < Write < Flash。
enum class Tier : std::uint8_t
{
    None  = 0,
    Read  = 1,
    Write = 2,
    Flash = 3
};

inline const char *tierName (Tier t)
{
    switch (t)
    {
    case Tier::Read:  return "读";
    case Tier::Write: return "写";
    case Tier::Flash: return "刷写";
    default:          return "无";
    }
}

// 只认 read / write / flash（大小写不敏感，容忍首尾空白）。
inline bool parseTier (const std::string &s, Tier &out)
{
    std::size_t b = 0, e = s.size ();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    std::string w = s.substr (b, e - b);
    for (char &c : w) if (c >= 'A' && c <= 'Z') c = static_cast<char> (c - 'A' + 'a');
    if (w == "read")  { out = Tier::Read;  return true; }
    if (w == "write") { out = Tier::Write; return true; }
    if (w == "flash") { out = Tier::Flash; return true; }
    if (w == "none")  { out = Tier::None;  return true; }
    return false;
}

// 一条请求"最少需要哪一档"。
struct OpInfo
{
    std::uint8_t sid  = 0;        // 服务号（第一个字节）
    Tier         need = Tier::Flash;
    const char  *what = "不认识";  // 给人看的一句话
};

// 只看第一个字节。空载荷 / 响应服务号（0x40 以上）/ 不认识的 → Flash（安全默认）。
inline Tier classify (const std::uint8_t *uds, std::size_t len, OpInfo &out)
{
    out.sid = len ? uds[0] : 0;
    if (len == 0)
    {
        out.need = Tier::Flash;
        out.what = "空载荷（没有服务号）";
        return out.need;
    }
    switch (uds[0])
    {
    case 0x22: out.need = Tier::Read;  out.what = "读 DID(0x22)";        return out.need;
    case 0x19: out.need = Tier::Read;  out.what = "读 DTC(0x19)";        return out.need;
    case 0x3E: out.need = Tier::Read;  out.what = "保活(0x3E)";           return out.need;

    case 0x10: out.need = Tier::Write; out.what = "切会话(0x10)";        return out.need;
    case 0x11: out.need = Tier::Write; out.what = "复位(0x11)";          return out.need;
    case 0x14: out.need = Tier::Write; out.what = "清 DTC(0x14)";        return out.need;
    // 0x27 是"为写开门"的动作：按写档。刷写另有 0x31/0x34/0x36/0x37 挡着。
    case 0x27: out.need = Tier::Write; out.what = "安全访问(0x27)";       return out.need;
    case 0x28: out.need = Tier::Write; out.what = "通信控制(0x28)";       return out.need;
    case 0x2E: out.need = Tier::Write; out.what = "写 DID(0x2E)";        return out.need;
    case 0x2F: out.need = Tier::Write; out.what = "IO 控制(0x2F)";        return out.need;
    case 0x83: out.need = Tier::Write; out.what = "时序参数(0x83)";       return out.need;
    case 0x85: out.need = Tier::Write; out.what = "DTC 设置(0x85)";      return out.need;

    // 0x31 一个服务里混着"校验"（无害）和"擦除"（最危险），只看服务号分不开，整条按最高档。
    case 0x31: out.need = Tier::Flash; out.what = "例程(0x31)";          return out.need;
    case 0x34: out.need = Tier::Flash; out.what = "请求下载(0x34)";       return out.need;
    case 0x36: out.need = Tier::Flash; out.what = "传块(0x36)";          return out.need;
    case 0x37: out.need = Tier::Flash; out.what = "退出传输(0x37)";       return out.need;
    default:   break;
    }
    out.need = Tier::Flash;
    out.what = (uds[0] >= 0x40) ? "响应码当请求发（服务号≥0x40）" : "不认识的服务号";
    return out.need;
}

// SA → 档位。没配置的 SA 拿"默认档"。
class PermissionTable
{
public:
    void setDefault (Tier t) { default_ = t; }
    Tier defaultTier () const { return default_; }

    // 同一台 SA 再给一次 = 改档（后写的生效），不叠成两行。
    bool grant (std::uint16_t sa, Tier t)
    {
        if (sa == 0) return false;        // 0 不是一台诊断仪
        for (auto &e : entries_)
            if (e.sa == sa) { e.tier = t; return true; }
        entries_.push_back (Entry{sa, t});
        return true;
    }

    Tier levelOf (std::uint16_t sa) const
    {
        for (const auto &e : entries_)
            if (e.sa == sa) return e.tier;
        return default_;
    }

    struct Decision
    {
        bool          permit = false;
        Tier          need   = Tier::Flash;
        Tier          have   = Tier::None;
    };

    // 阶梯判：要的档 ≤ 给的档就放行。None 连读都不给。
    Decision decide (std::uint16_t sa, Tier need) const
    {
        Decision d;
        d.need   = need;
        d.have   = levelOf (sa);
        d.permit = (static_cast<std::uint8_t> (need) <= static_cast<std::uint8_t> (d.have)) &&
                   (need != Tier::None);
        return d;
    }

    std::size_t size () const { return entries_.size (); }
    std::uint16_t saAt (std::size_t i) const { return entries_[i].sa; }
    Tier tierAt (std::size_t i) const { return entries_[i].tier; }

private:
    struct Entry
    {
        std::uint16_t sa;
        Tier          tier;
    };
    std::vector<Entry> entries_;
    Tier               default_ = Tier::Read;   // 没列出来的 SA 只能读（最小可用）
};

}   // namespace ops
}   // namespace doip
