#pragma once
// ============================================================================
// SlotLedger.h —— M29：网关这边记的"位子租约"，把 ECU 的"第几号位子"还原成"哪台诊断仪"
//
// M28 之后，ECU 的流水第七格有了值：0xF1..0xF8（位子编号）。但它只回答
//   "是第几号位子干的"，回答不了"是谁" —— 而位子会回收再发：
//   今天 1 号位子是 0x0E00，明天可能是 0x0E01。
//
// 所以网关必须留一份自己的账：**哪个 SA 在什么时间段占着哪个位子**。
// 这份账和 ECU 的流水能对上（两边都记了 SA / 位子），对不上的时候必须说出来。
//
// ★ 三条原则（和整个项目一贯的口径一致）
//   ① **不猜**：一个位子如果在这次运行里被两台不同的 SA 用过，那"这条流水是谁干的"
//      就没有唯一答案。这时输出"歧义 + 候选清单"，而不是挑一个看起来最像的。
//   ② **不合并**：同一台诊断仪断线重连，是两条租约。账要照实记，"几次"本身就是信息。
//   ③ **账要能自证**：落盘带校验和（复用 KeyRingStore 那一套），半截文件 / 被手改一律判坏。
//
// ★ 为什么不让网关直接"把 SA 写进 ECU"
//   ECU 那边只有 1 个字节的位子可用（29 位 ID 的最低字节），放不下 2 字节的 SA；
//   而多写一条 UDS 请求去"补记名字"，就是在被诊断对象身上改状态 —— M28 已否决过一次。
//
// ★ 与 ECU 的时间对齐：做不到，所以不假装做
//   ECU 的时间是"第几次上电 + 上电后秒"，网关的时间是"本次进程的单调秒"，
//   两者没有共同时基。对账工具只按"位子 → SA 集合"判唯一性，**不按时间插值**：
//   "同一位上先后待过两台"就报歧义，而不是"按秒推算大概是哪台"。
// ============================================================================
#include "KeyRingStore.h"   // 复用 keys::checksumOf / keys::parseHex（同一套校验和口径）

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace doip
{
namespace slots
{

// 一条租约 = "某台 SA 从第 tookSec 秒到第 freeSec 秒占着 slot"。
//   open = true 表示"到网关进程退出还占着"（正常收尾不该有）。
struct Lease
{
    std::uint8_t  slot    = 0;
    std::uint16_t sa      = 0;
    std::uint32_t conn    = 0;      // 连接号（M13 的 id，用来区分"同一 SA 的两次连接"）
    std::uint32_t tookSec = 0;
    std::uint32_t freeSec = 0;
    bool          open    = true;
};

// 进程内单调秒。落盘只为看懂"先来后到"，不与 ECU 的"第几次上电 + 秒"对齐。
inline std::uint32_t nowSec ()
{
    using namespace std::chrono;
    return static_cast<std::uint32_t> (
        duration_cast<seconds> (steady_clock::now ().time_since_epoch ()).count ());
}

// "这个位子是谁的"的三种结论。Unknown = 账上没有这条位子（比如网关没开 --slot-ledger），
//   不是"没人用过"——这两件事差得很远。
struct Verdict
{
    enum Kind { Unknown, Unique, Ambiguous };
    Kind                       kind = Kind::Unknown;
    std::uint16_t              sa   = 0;      // Unique 时有效
    std::vector<std::uint16_t> candidates;    // 去重后的候选（Ambiguous 时不止一个）
};

inline const char *verdictName (Verdict::Kind k)
{
    switch (k)
    {
    case Verdict::Kind::Unique:    return "唯一";
    case Verdict::Kind::Ambiguous: return "歧义";
    default:                       return "查不到";
    }
}

class SlotLedger
{
public:
    static constexpr std::size_t kMaxLeases = 64;   // 满了丢最旧的，并记 dropped

    void noteTake (std::uint8_t slot, std::uint16_t sa, std::uint32_t conn, std::uint32_t sec)
    {
        // 正常流程不会走到这句（M28 的 SlotTable 保证一个槽同一时刻只有一台）；
        //   留着是为了"账自己也要自洽"，不是给正常路径用的。
        closeOpenOnSlot (slot, sec);
        if (leases_.size () >= kMaxLeases)
        {
            leases_.erase (leases_.begin ());
            ++dropped_;
        }
        Lease l;
        l.slot    = slot;
        l.sa      = sa;
        l.conn    = conn;
        l.tookSec = sec;
        l.open    = true;
        leases_.push_back (l);
    }

    // 归还。找不到对应的 open 租约就**什么都不做、只记账**（不编一条出来）：
    //   "还了一个没借过的位子"本身是 bug，账要留痕，而不是自己补圆。
    bool noteRelease (std::uint8_t slot, std::uint16_t sa, std::uint32_t sec)
    {
        for (auto it = leases_.rbegin (); it != leases_.rend (); ++it)
        {
            if (it->slot != slot || !it->open) continue;
            if (sa != 0 && it->sa != sa) continue;     // 同一槽可能先后换过人，按 SA 对上最近那条
            it->open    = false;
            it->freeSec = sec;
            return true;
        }
        ++orphanReleases_;
        return false;
    }

    // 这个位子被几台**不同的** SA 用过（按出现顺序）。
    std::vector<std::uint16_t> ownersOf (std::uint8_t slot) const
    {
        std::vector<std::uint16_t> out;
        for (const Lease &l : leases_)
        {
            if (l.slot != slot) continue;
            bool seen = false;
            for (std::uint16_t prev : out)
                if (prev == l.sa) { seen = true; break; }
            if (!seen) out.push_back (l.sa);
        }
        return out;
    }

    Verdict resolve (std::uint8_t slot) const
    {
        Verdict v;
        v.candidates = ownersOf (slot);
        if (v.candidates.empty ())
        {
            v.kind = Verdict::Kind::Unknown;
            return v;
        }
        if (v.candidates.size () == 1)
        {
            v.kind = Verdict::Kind::Unique;
            v.sa   = v.candidates[0];
            return v;
        }
        v.kind = Verdict::Kind::Ambiguous;
        return v;
    }

    std::size_t size () const { return leases_.size (); }
    std::size_t dropped () const { return dropped_; }
    std::size_t orphanReleases () const { return orphanReleases_; }
    std::size_t openCount () const
    {
        std::size_t n = 0;
        for (const Lease &l : leases_) if (l.open) ++n;
        return n;
    }
    const std::vector<Lease> &leases () const { return leases_; }

    // ---- 落盘 ----
    // DOIPSLOTS 1
    // P <槽2> <SA4> <连接8> <取秒8> <放秒8|-------->       // 定长 36 字符（没还就是 8 个减号）
    // SUM <16hex>
    //   连接号用 8 位：M13 的连接号是 64 位的自增，4 位十六进制约跑到 65535 就溢出,
    //   一溢出就会把这一行的定长挤破。宽度按"可能的最大值"留，不按"平时看起来够用"留。
    std::string text () const
    {
        std::string body = "DOIPSLOTS 1\n";
        char buf[96];
        for (const Lease &l : leases_)
        {
            if (l.open)
                std::snprintf (buf, sizeof buf, "P %02X %04X %08X %08X --------\n",
                               static_cast<unsigned> (l.slot), static_cast<unsigned> (l.sa),
                               static_cast<unsigned> (l.conn), static_cast<unsigned> (l.tookSec));
            else
                std::snprintf (buf, sizeof buf, "P %02X %04X %08X %08X %08X\n",
                               static_cast<unsigned> (l.slot), static_cast<unsigned> (l.sa),
                               static_cast<unsigned> (l.conn), static_cast<unsigned> (l.tookSec),
                               static_cast<unsigned> (l.freeSec));
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

    // 读盘用**输出参数**（不是返回一个带 SlotLedger 的结构）：
    //   类里面不能装一个"自己"的完整对象（那是不完整类型），这也省得为它再拆一层。
    static bool parse (const std::string &text, SlotLedger &out, std::string &why)
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
            why = "位子账至少要两行（版本行 / SUM），现在 " + std::to_string (lines.size ()) + " 行";
            return false;
        }
        if (lines[0] != "DOIPSLOTS 1")
        {
            why = "版本行不对（读到「" + lines[0] + "」，只认 DOIPSLOTS 1）";
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

        SlotLedger L;
        for (std::size_t i = 1; i + 1 < lines.size (); ++i)
        {
            const std::string &ln = lines[i];
            if (ln.size () != 36 || ln.compare (0, 2, "P ") != 0)
            {
                why = "第 " + std::to_string (i + 1) + " 行不是「P 槽 SA 连接 取秒 放秒」的形状";
                return false;
            }
            std::uint64_t slot = 0, sa = 0, conn = 0, took = 0, freed = 0;
            if (!keys::parseHex (ln.substr (2, 2), slot) || !keys::parseHex (ln.substr (5, 4), sa) ||
                !keys::parseHex (ln.substr (10, 8), conn) || !keys::parseHex (ln.substr (19, 8), took))
            {
                why = "第 " + std::to_string (i + 1) + " 行的字段不是十六进制";
                return false;
            }
            const std::string fs = ln.substr (28, 8);
            const bool open = (fs == "--------");
            if (!open && !keys::parseHex (fs, freed))
            {
                why = "第 " + std::to_string (i + 1) + " 行的归还秒不是十六进制";
                return false;
            }
            if (slot == 0 || slot > 8)
            {
                why = "第 " + std::to_string (i + 1) + " 行的位子越界（只认 1..8）";
                return false;
            }
            if (sa > 0xFFFF || conn > 0xFFFFFFFF)
            {
                why = "第 " + std::to_string (i + 1) + " 行的 SA 或连接号越界";
                return false;
            }
            Lease l;
            l.slot    = static_cast<std::uint8_t> (slot);
            l.sa      = static_cast<std::uint16_t> (sa);
            l.conn    = static_cast<std::uint32_t> (conn);
            l.tookSec = static_cast<std::uint32_t> (took);
            l.freeSec = static_cast<std::uint32_t> (freed);
            l.open    = open;
            L.leases_.push_back (l);
        }
        out = L;
        why.clear ();
        return true;
    }

    static bool load (const std::string &path, SlotLedger &out, std::string &why)
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
    void closeOpenOnSlot (std::uint8_t slot, std::uint32_t sec)
    {
        for (auto &l : leases_)
            if (l.slot == slot && l.open) { l.open = false; l.freeSec = sec; }
    }

    std::vector<Lease> leases_;
    std::size_t        dropped_        = 0;
    std::size_t        orphanReleases_ = 0;
};

}   // namespace slots
}   // namespace doip
