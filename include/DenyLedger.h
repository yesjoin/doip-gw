#pragma once
// ============================================================================
// DenyLedger.h —— M33：越权账（谁在试探什么，挡了多少次）
//
// M30 / M31 已经把"越权"这件事挡住了，但挡完只剩 stdout 一行 —— 进程一停就没了。
// 安全事件的价值恰恰在事后："上周谁在试 0x31？哪台诊断仪一直在读钥匙表？"
// 所以这一步把挡回记下来，并且是**能落盘、能读回、能被工具统计**的那种记法。
//
// ★ 聚合，不是流水
//   挡回和"位子租约"不一样：一台扫服务的机器一分钟能撞几百次，逐条流水会把账撑爆，
//   而且每条内容几乎一样。所以同一组 (SA, 服务号, DID, 要的档, 有的档, 原因) 合成一条，
//   只累加次数、记下第一次和最后一次的时间。要的是"谁在试探什么、多频繁"，
//   不是"第 37 次发生在第几秒"。
//
// ★ 丢弃是按条丢的，所以丢掉的命中数要单独报
//   满了（kMaxEntries=32）丢最旧那一条 —— 但一条记录可能带着 100 次命中。
//   于是 dropped 要分两个数：丢了几条记录、丢了多少次命中。
//   只报"丢了 1 条"会让人以为损失很小。
//
// ★ 账是"本次运行"的，不合并历史
//   M29 的教训在这里直接复用：进程单调秒重启就归零，两份账的时间**不可比**。
//   硬合并会出现"第一次在第 300 秒、最后一次在第 12 秒"这种自相矛盾的账。
//   所以要留历史，就在每次运行时另存一份（外部轮转），而不是让账自己合。
//
// ★ 原因分三种
//   OpTier   —— 服务号这一层就不够（M30：读档想 0x2E）
//   DidLevel —— 只看服务号本来能过，被 DID 级别抬掉（M31：读档读 0xF1B0）
//   RespDid  —— 请求放行了，但 ECU 答回来的 0x62 被响应侧挡掉（M32）
//   这三件事在追责时是三种问题：档太低 / 在碰敏感数据 / 数据差点漏出去。
//
// ★ 次数为什么是十进制（而不是跟时间一样用十六进制）
//   次数是这张账的主数，人一眼要读出"撞了 37 次"，不是"0x25 次"。
//   代价是**读的时候必须按十进制解析** —— 这一条在 M33 第一版上真摔了一跤：
//   写出去是十进制、读回来按十六进制，前 9 次没事（0-9 两种进制同形），
//   从第 10 次开始账就虚高（10 读成 16、37 读成 55）。单测第 F 组专门钉这一条。
//
// ★ 边界
//   1) 只记"被网关挡回"的，不记"ECU 自己拒的"（那归 ECU 的账）。
//   2) 账不签名：SUM 只防手滑与半截文件，防不了人改后重算。
//   3) 只按 SA / 服务号 / DID 聚合，不做速率与序列分析（"每分钟几次"属于监控，不属于账）。
// ============================================================================
#include "KeyRingStore.h"   // 复用 keys::checksumOf / keys::parseHex（整套账同一口径）
#include "OpPermission.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace doip
{
namespace deny
{

enum class Reason : std::uint8_t
{
    OpTier   = 0,   // 服务号这一层不够
    DidLevel = 1,   // DID 级别抬档才不够（请求侧）
    RespDid  = 2    // 请求放行了，但 0x62 出来时被响应侧挡掉（M32）
};

inline const char *reasonName (Reason r)
{
    switch (r)
    {
        case Reason::DidLevel: return "DID 级别不够";
        case Reason::RespDid:  return "响应被挡（数据没出去）";
        default:               return "服务号档不够";
    }
}

// 一条聚合记录：同一组 (谁, 想干什么, 要什么档, 有什么档, 为什么) 的 N 次。
struct Entry
{
    std::uint16_t sa       = 0;
    std::uint8_t  sid      = 0;     // 服务号
    std::uint16_t did      = 0;     // 0 = 不是 DID 请求
    ops::Tier     need     = ops::Tier::Flash;
    ops::Tier     have     = ops::Tier::None;
    Reason        why      = Reason::OpTier;
    std::uint64_t count    = 0;
    std::uint32_t firstSec = 0;
    std::uint32_t lastSec  = 0;
};

// 进程内单调秒（与 M29 同一个口径：只用来排先后，不跨进程比）。
inline std::uint32_t nowSec ()
{
    using namespace std::chrono;
    return static_cast<std::uint32_t> (
        duration_cast<seconds> (steady_clock::now ().time_since_epoch ()).count ());
}

// 次数这一格是**十进制** 8 位，所以单独写一个，别去借 keys::parseHex（那是十六进制的）。
//   M33 第一版就是在这里摔的：写出十进制、读回按十六进制，前 9 次同形看不出来。
inline bool parseDec (const std::string &s, std::uint64_t &out)
{
    out = 0;
    if (s.empty () || s.size () > 8) return false;
    for (char c : s)
    {
        if (c < '0' || c > '9') return false;
        out = out * 10 + static_cast<std::uint64_t> (c - '0');
    }
    return true;
}

class DenyLedger
{
public:
    static constexpr std::size_t kMaxEntries = 32;   // 满了丢最旧的，两个丢弃数都要报

    // 记一次挡回。同一组就是 ++count，顺带更新 lastSec；换了一组就新开一条。
    void note (std::uint16_t sa, std::uint8_t sid, std::uint16_t did, ops::Tier need,
               ops::Tier have, Reason why, std::uint32_t sec)
    {
        for (auto &e : entries_)
        {
            if (e.sa == sa && e.sid == sid && e.did == did && e.need == need &&
                e.have == have && e.why == why)
            {
                ++e.count;
                e.lastSec = sec;
                return;
            }
        }
        if (entries_.size () >= kMaxEntries)
        {
            // 丢最旧那条（按插入顺序，也就是"第一次出现"的顺序）。
            droppedHits_ += entries_.front ().count;
            entries_.erase (entries_.begin ());
            ++droppedEntries_;
        }
        Entry e;
        e.sa       = sa;
        e.sid      = sid;
        e.did      = did;
        e.need     = need;
        e.have     = have;
        e.why      = why;
        e.count    = 1;
        e.firstSec = sec;
        e.lastSec  = sec;
        entries_.push_back (e);
    }

    std::size_t size () const { return entries_.size (); }
    const std::vector<Entry> &entries () const { return entries_; }
    std::size_t droppedEntries () const { return droppedEntries_; }
    std::size_t droppedHits () const { return droppedHits_; }

    // 合计命中数 = 还在账上的 + 已经被丢掉的。报总数时两个都要算，否则会少报。
    std::uint64_t totalHits () const
    {
        std::uint64_t n = droppedHits_;
        for (const auto &e : entries_) n += e.count;
        return n;
    }

    // 某台 SA 一共被挡了多少次（账上的；丢掉的算不进"是谁"，因为它们的信息已经没了）。
    std::uint64_t hitsOfSa (std::uint16_t sa) const
    {
        std::uint64_t n = 0;
        for (const auto &e : entries_) if (e.sa == sa) n += e.count;
        return n;
    }

    // 某个 DID 一共被试探多少次（did=0 表示非 DID 请求）。
    std::uint64_t hitsOfDid (std::uint16_t did) const
    {
        std::uint64_t n = 0;
        for (const auto &e : entries_) if (e.did == did) n += e.count;
        return n;
    }

    // 最深的一条（次数最多）。空账返回 nullptr。
    const Entry *worst () const
    {
        const Entry *w = nullptr;
        for (const auto &e : entries_)
            if (w == nullptr || e.count > w->count) w = &e;
        return w;
    }

    // ---- 落盘 ----
    // DOIPDENY 1
    // D <SA4> <SID2> <DID4> <需档1> <有档1> <原因1> <次数8> <首秒8> <末秒8>    // 定长 47
    // SUM <16hex>
    //   次数用十进制 8 位：聚合账的"次数"是给人看的主数，十进制比十六进制好读；
    //   时间还是十六进制（跟位子账保持一致，也省得解释为什么只有它换了进制）。
    std::string text () const
    {
        std::string body = "DOIPDENY 1\n";
        char buf[96];
        for (const auto &e : entries_)
        {
            std::snprintf (buf, sizeof buf, "D %04X %02X %04X %u %u %u %08llu %08X %08X\n",
                           static_cast<unsigned> (e.sa), static_cast<unsigned> (e.sid),
                           static_cast<unsigned> (e.did),
                           static_cast<unsigned> (static_cast<std::uint8_t> (e.need)),
                           static_cast<unsigned> (static_cast<std::uint8_t> (e.have)),
                           static_cast<unsigned> (static_cast<std::uint8_t> (e.why)),
                           static_cast<unsigned long long> (e.count),
                           static_cast<unsigned> (e.firstSec), static_cast<unsigned> (e.lastSec));
            body += buf;
        }
        return body + "SUM " + keys::checksumOf (body) + "\n";
    }

    bool save (const std::string &path, std::string &why) const
    {
        const std::string body = text ();
        const std::string tmp  = path + ".tmp";
        std::FILE *f = std::fopen (tmp.c_str (), "wb");
        if (f == nullptr) { why = "打不开 " + tmp; return false; }
        const bool w = std::fwrite (body.data (), 1, body.size (), f) == body.size ();
        std::fclose (f);
        if (!w) { std::remove (tmp.c_str ()); why = "写 " + tmp + " 失败"; return false; }
        std::remove (path.c_str ());
        if (std::rename (tmp.c_str (), path.c_str ()) != 0)
        {
            std::remove (tmp.c_str ());
            why = "rename 到 " + path + " 失败";
            return false;
        }
        return true;
    }

    // 读盘用输出参数（与 SlotLedger 同一个理由：类里不能装一个完整的自己）。
    static bool parse (const std::string &text, DenyLedger &out, std::string &why)
    {
        std::vector<std::string> lines;
        {
            std::size_t pos = 0;
            while (pos <= text.size ())
            {
                const std::size_t nl = text.find ('\n', pos);
                if (nl == std::string::npos)
                {
                    if (pos < text.size ()) lines.push_back (text.substr (pos));
                    break;
                }
                lines.push_back (text.substr (pos, nl - pos));
                pos = nl + 1;
            }
        }
        if (lines.size () < 2)
        {
            why = "越权账至少要两行（版本行 / SUM），现在 " + std::to_string (lines.size ()) + " 行";
            return false;
        }
        if (lines[0] != "DOIPDENY 1")
        {
            why = "版本行不对（读到「" + lines[0] + "」，只认 DOIPDENY 1）";
            return false;
        }
        const std::string &last = lines.back ();
        if (last.size () != 20 || last.compare (0, 4, "SUM ") != 0)
        {
            why = "最后一行不是校验和（读到「" + last + "」）：文件可能是半截的";
            return false;
        }
        std::string body;
        for (std::size_t i = 0; i + 1 < lines.size (); ++i) body += lines[i] + "\n";
        if (keys::checksumOf (body) != last.substr (4))
        {
            why = "校验和不符：账被改过，或者写了一半";
            return false;
        }

        DenyLedger L;
        for (std::size_t i = 1; i + 1 < lines.size (); ++i)
        {
            const std::string &ln = lines[i];
            if (ln.size () != 47 || ln.compare (0, 2, "D ") != 0)
            {
                why = "第 " + std::to_string (i + 1) + " 行不是「D SA SID DID 需档 有档 原因 次数 首秒 末秒」的形状";
                return false;
            }
            std::uint64_t sa = 0, sid = 0, did = 0, cnt = 0, first = 0, last2 = 0;
            if (!keys::parseHex (ln.substr (2, 4), sa) || !keys::parseHex (ln.substr (7, 2), sid) ||
                !keys::parseHex (ln.substr (10, 4), did) || !keys::parseHex (ln.substr (30, 8), first) ||
                !keys::parseHex (ln.substr (39, 8), last2))
            {
                why = "第 " + std::to_string (i + 1) + " 行的字段不是十六进制";
                return false;
            }
            // 次数这一格按十进制读（写出去也是十进制）——按十六进制读会让 10 变 16、37 变 55。
            if (!parseDec (ln.substr (21, 8), cnt))
            {
                why = "第 " + std::to_string (i + 1) +
                      " 行的次数不是十进制 8 位（这一格故意用十进制，别按十六进制读）";
                return false;
            }
            const char nd = ln[15], hv = ln[17], rs = ln[19];
            if (nd < '0' || nd > '3' || hv < '0' || hv > '3' || rs < '0' || rs > '2')
            {
                why = "第 " + std::to_string (i + 1) + " 行的档位/原因越界";
                return false;
            }
            if (cnt == 0)
            {
                why = "第 " + std::to_string (i + 1) + " 行的次数是 0：一条 0 次的挡回没有意义";
                return false;
            }
            Entry e;
            e.sa       = static_cast<std::uint16_t> (sa);
            e.sid      = static_cast<std::uint8_t> (sid);
            e.did      = static_cast<std::uint16_t> (did);
            e.need     = static_cast<ops::Tier> (nd - '0');
            e.have     = static_cast<ops::Tier> (hv - '0');
            e.why      = static_cast<Reason> (rs - '0');
            e.count    = cnt;
            e.firstSec = static_cast<std::uint32_t> (first);
            e.lastSec  = static_cast<std::uint32_t> (last2);
            L.entries_.push_back (e);
        }
        out = L;
        why.clear ();
        return true;
    }

    static bool load (const std::string &path, DenyLedger &out, std::string &why)
    {
        std::FILE *f = std::fopen (path.c_str (), "rb");
        if (f == nullptr)
        {
            why = "打不开 " + path;
            return false;
        }
        std::string text;
        char buf[4096];
        std::size_t n = 0;
        while ((n = std::fread (buf, 1, sizeof buf, f)) > 0) text.append (buf, n);
        std::fclose (f);
        return parse (text, out, why);
    }

private:
    std::vector<Entry> entries_;
    std::size_t        droppedEntries_ = 0;
    std::size_t        droppedHits_    = 0;
};

}   // namespace deny
}   // namespace doip
