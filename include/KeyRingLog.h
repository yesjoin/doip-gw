// ============================================================================
// KeyRingLog.h —— M26：钥匙表被改过的那几笔，各是一句话
//
// M25 给了两个数：指纹（现在长什么样）、世代（被动过几次）。
// 但现场真正要问的是**一句话**：这张表为什么是这个样子？
//
//   "版本 4，指纹 70D3"   —— 只知道被改过四次，不知道改的是谁、动了哪把、什么时候
//   售后问一句"这表谁动过"，只能答"动过四次"。这不是回答。
//
// 所以再往下压一层：每成功改一次表，记**一条**流水：
//
//   世代 2 | 改完的指纹 2 | 动作 1 | 通道 1 | 动了哪把钥匙 2 | 第几次上电 2 | 上电后几秒 4
//
// 六个字段各管一件事，缺一个就问不下去：
//   · 世代   —— 它属于哪一段历史（和 F1B2 报出来的世代对得上）
//   · 指纹   —— 改完之后表长什么样（能直接和另一台对账）
//   · 动作   —— 装入 / 退役 / 复活 / 吊销 / 重建（"吊销"和"退役"是完全两件事）
//   · 通道   —— 上电参数 / 物理寻址 / 广播 / 重建（一条广播改了三台，和逐台改，风险不一样）
//   · keyId  —— 动的是哪一把（售后只关心"我那把 3 号钥匙怎么退役了"）
//   · 时间   —— 第几次带变更的上电 + 那次上电后多少秒
//
// 为什么"时间"是这两段、不是时间戳：
//   这台 ECU 没有 RTC，也没有 GNSS。它能诚实地报的只有"第几次带变更的上电"和
//   "那次上电之后过了多少秒"。**别的时间都是编的**。想要绝对时间必须有外部授时
//   （0x2E 写时钟、或证书里的时间），那是另一层的事。在这一层编一个假时间戳，
//   比没有时间戳更坏 —— 它会让人相信它。
//
// 为什么"谁"只有通道、没有身份：
//   网关现在不认诊断仪是谁（DoIP 层没有鉴权）。能记的只有"从哪条通道进来的"。
//   这一点要写在流水里、也写在文档里，而不是假装记下了操作者。
//   真要"谁"，得先有身份（DoIP 鉴权/证书），那是 M26 之后的事。
//
// 为什么定长 8 条、满了丢最旧的：
//   这是"最近发生了什么"的环形记录，不是审计日志。审计日志要能无限长、能导出、
//   不可篡改 —— 那是车队后台的事，不是这台 ECU 的内存。
//   定长 = 内存可预算、落盘可预算、读一条的报文长度可预算。
//   "丢最旧的"本身就是一句要写在说明书上的话：它记得住最近 8 笔，记不住全部。
// ============================================================================
#ifndef DOIP_KEY_RING_LOG_H
#define DOIP_KEY_RING_LOG_H

#include "KeyRing.h"
#include "KeyRingStamp.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace doip {
namespace keys {

// 动作。0 不用 —— 空表的概览要回一个 0，不能和"装入"撞上。
enum class Act : std::uint8_t
{
    Install = 0x01,   // 装一把新钥匙
    Retire  = 0x02,   // 置退役（还认，但不再新签）
    Revive  = 0x03,   // 从退役改回启用
    Revoke  = 0x04,   // 吊销（终态，拒收它签的一切）
    Rebuild = 0x05    // 整张表被重建（--reset-key-store）
};

inline std::uint8_t actCode (Act a) { return static_cast<std::uint8_t> (a); }

inline const char *actName (Act a)
{
    switch (a)
    {
        case Act::Install: return "装入";
        case Act::Retire:  return "退役";
        case Act::Revive:  return "复活";
        case Act::Revoke:  return "吊销";
        case Act::Rebuild: return "重建";
    }
    return "?";
}

inline bool actValid (std::uint8_t v) { return v >= 0x01 && v <= 0x05; }

// 通道：这次改动是从哪条路进来的。
//   广播改三台、逐台改三台，表可能一样，风险完全不一样 —— 所以这条要记。
enum class Channel : std::uint8_t
{
    Startup   = 0x00,   // 上电参数 --retire-key / --revoke-key
    Physical  = 0x01,   // 物理寻址（逐台）
    Broadcast = 0x02,   // 功能寻址（一条广播，几台一起改）
    Rebuild   = 0x03    // --reset-key-store
};

inline std::uint8_t chanCode (Channel c) { return static_cast<std::uint8_t> (c); }

inline const char *channelName (Channel c)
{
    switch (c)
    {
        case Channel::Startup:   return "上电参数";
        case Channel::Physical:  return "物理寻址";
        case Channel::Broadcast: return "广播";
        case Channel::Rebuild:   return "重建";
    }
    return "?";
}

inline bool channelValid (std::uint8_t v) { return v <= 0x03; }

// 一条流水。字段顺序 = 落盘顺序 = 报文顺序，三处一个样；改一处就得三处一起改。
struct LogEntry
{
    Generation    generation  = 0;                    // 改完之后的世代
    std::uint16_t fingerprint = 0;                    // 改完之后的指纹
    std::uint16_t keyId       = 0;                    // 动的是哪一把（重建时为 0）
    Act           act         = Act::Install;
    Channel       channel     = Channel::Physical;
    std::uint16_t boot        = 0;                    // 第几次带变更的上电
    std::uint32_t seconds     = 0;                    // 那次上电之后多少秒
};

// 定长环形记录，新在前：at(0) 是最近一条。
class ChangeLog
{
public:
    static const std::size_t kMax = 8;

    std::size_t size () const { return n_; }
    bool empty () const { return n_ == 0; }

    void append (const LogEntry &e)
    {
        newest_ = (newest_ + 1) % kMax;
        slot_[newest_]  = e;
        if (n_ < kMax) ++n_;
    }

    // 越界不崩：给一个全零的"空条"。读报文的地方懒得判 i，哑值比未定义行为好。
    const LogEntry &at (std::size_t i) const
    {
        static const LogEntry kNull {};
        if (i >= n_) return kNull;
        return slot_[(newest_ + kMax - i) % kMax];
    }

    void clear ()
    {
        n_      = 0;
        newest_ = 0;
        for (auto &s : slot_) s = LogEntry {};
    }

    // 控制台/退账用："装入 0x0003，广播，版本 2，指纹 70D3，第 1 次上电 +3s"
    std::string dump () const
    {
        if (empty ()) return "还没有变更";
        std::string s;
        for (std::size_t i = 0; i < n_; ++i)
        {
            const LogEntry &e = at (i);
            char buf[128];
            std::snprintf (buf, sizeof buf, "%s%s 0x%04X，%s，版本 %u，指纹 %04X，第 %u 次上电 +%us",
                           i == 0 ? "" : " ／ ", actName (e.act),
                           static_cast<unsigned> (e.keyId), channelName (e.channel),
                           static_cast<unsigned> (e.generation),
                           static_cast<unsigned> (e.fingerprint), static_cast<unsigned> (e.boot),
                           static_cast<unsigned> (e.seconds));
            s += buf;
        }
        return s;
    }

private:
    LogEntry    slot_[kMax] {};
    std::size_t n_      = 0;
    std::size_t newest_ = 0;
};

// 落盘一行：L <世代 4> <指纹 4> <动作 2> <通道 2> <keyId 4> <上电 4> <秒 8>，定长 36。
//   为什么这么笨：出事故时人要在串口里 cat 它，越直白越可靠。
inline std::string logLine (const LogEntry &e)
{
    char buf[64];
    std::snprintf (buf, sizeof buf, "L %04X %04X %02X %02X %04X %04X %08X\n",
                   static_cast<unsigned> (e.generation), static_cast<unsigned> (e.fingerprint),
                   static_cast<unsigned> (actCode (e.act)), static_cast<unsigned> (chanCode (e.channel)),
                   static_cast<unsigned> (e.keyId), static_cast<unsigned> (e.boot),
                   static_cast<unsigned> (e.seconds));
    return std::string (buf);
}

// 本文件自己的 hex 解析（不借 Store 的，免得头文件互相 include）
inline bool logHex (const std::string &s, std::uint64_t &out)
{
    out = 0;
    if (s.empty () || s.size () > 16) return false;
    for (char c : s)
    {
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        if (v < 0) return false;
        out = (out << 4) | static_cast<std::uint64_t> (v);
    }
    return true;
}

// 解一行落盘流水。形状不对 / 字段越界都返回 false —— 宁可判坏，不猜。
inline bool parseLogLine (const std::string &ln, LogEntry &out)
{
    if (ln.size () != 36 || ln.compare (0, 2, "L ") != 0) return false;

    std::uint64_t gen = 0, fp = 0, act = 0, chan = 0, id = 0, boot = 0, sec = 0;
    if (!logHex (ln.substr (2, 4), gen) || !logHex (ln.substr (7, 4), fp) ||
        !logHex (ln.substr (12, 2), act) || !logHex (ln.substr (15, 2), chan) ||
        !logHex (ln.substr (18, 4), id) || !logHex (ln.substr (23, 4), boot) ||
        !logHex (ln.substr (28, 8), sec))
        return false;

    if (gen > 0xFFFF || fp > 0xFFFF || id > 0xFFFF || boot > 0xFFFF || sec > 0xFFFFFFFF) return false;
    if (!actValid (static_cast<std::uint8_t> (act))) return false;
    if (!channelValid (static_cast<std::uint8_t> (chan))) return false;
    // keyId 0 只允许"重建"这一种（它动的不是某一把钥匙）
    if (id == 0 && act != actCode (Act::Rebuild)) return false;

    out.generation  = static_cast<Generation> (gen);
    out.fingerprint = static_cast<std::uint16_t> (fp);
    out.keyId       = static_cast<std::uint16_t> (id);
    out.act         = static_cast<Act> (act);
    out.channel     = static_cast<Channel> (chan);
    out.boot        = static_cast<std::uint16_t> (boot);
    out.seconds     = static_cast<std::uint32_t> (sec);
    return true;
}

} // namespace keys
} // namespace doip

#endif
