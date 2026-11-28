#pragma once
// ============================================================================
// DenyMerge.h —— M34：多份越权账合并（跨运行看"谁一直在撞"）
//
// M33 的账只代表**一次运行**：进程单调秒重启归零，两份账的时间不可比。
// 所以 M33 明确不做合并，只让外部按运行轮转存多份。可真要用起来，
// "上周谁一直在撞"这类问题必须跨文件算 —— 这个模块就是那道桥。
//
// ★ 只并计数，不并秒
//   合并后的每一条**不带时间**：不同进程的"第 300 秒"不是同一时刻。
//   硬取 min/max 会造出"第一次在第 300 秒、最后一次在第 12 秒"的假账。
//   取而代之的是**每份账里各几次**（perRun）：
//     5 / 3 / 0   比一个 8 更能看出"这人每周都在试，这周停了"
//
// ★ 合并账不套 32 组上限
//   单账 32 是"一次运行记不下就丢最旧"的现场取舍；合并账是事后阅读，
//   丢任何一组都等于把审计信息扔掉。所以合并结果保留全部组，只在输出里说明一句。
//
// ★ 一份坏就不合并
//   任一份打不开 / 校验和不符 → 整次合并不给结果，并点名坏在第几份。
//   半份总账比没有账更危险 —— 它会让人以为"就这些"。
//
// ★ 丢弃的命中仍然只有数字
//   每份账丢掉的组，身份已经不存在（M33 的口径），合并只能把数字相加：
//   "3 份里 2 份有丢弃、共丢 2 组 / 5 次命中"。它们进合计，不进按人/按物。
// ============================================================================
#include "DenyLedger.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace doip
{
namespace deny
{

// 合并后的一条：六元组 + 总次数 + 每份账里的次数分布。
struct MergedEntry
{
    std::uint16_t              sa   = 0;
    std::uint8_t               sid  = 0;
    std::uint16_t              did  = 0;
    ops::Tier                  need = ops::Tier::Flash;
    ops::Tier                  have = ops::Tier::None;
    Reason                     why  = Reason::OpTier;
    std::uint64_t              count = 0;   // 各份之和
    std::vector<std::uint64_t> perRun;      // 长度 = 份数；某份没有这组就是 0

    // 出现过几份账：1/3 说明只在一周里撞过，3/3 说明每周都在撞。
    std::size_t runs () const
    {
        std::size_t n = 0;
        for (std::uint64_t c : perRun)
            if (c > 0) ++n;
        return n;
    }
};

class MergedLedger
{
public:
    // 纯逻辑合并（不碰文件）：单测直接喂对象，e2e 走 loadAll。
    static MergedLedger from (const std::vector<DenyLedger> &src)
    {
        MergedLedger m;
        m.sources_ = src.size ();
        for (std::size_t i = 0; i < src.size (); ++i)
        {
            m.totalHits_ += src[i].totalHits ();
            m.droppedEntries_ += src[i].droppedEntries ();
            m.droppedHits_ += src[i].droppedHits ();
            if (src[i].droppedEntries () > 0) m.sourcesWithDrop_ += 1;
            for (const auto &e : src[i].entries ())
            {
                MergedEntry *hit = m.find (e);
                if (hit == nullptr)
                {
                    MergedEntry me;
                    me.sa = e.sa; me.sid = e.sid; me.did = e.did;
                    me.need = e.need; me.have = e.have; me.why = e.why;
                    me.perRun.assign (src.size (), 0);
                    m.entries_.push_back (std::move (me));
                    hit = &m.entries_.back ();
                }
                hit->count += e.count;
                hit->perRun[i] += e.count;   // 单账内同组已聚合，这里 += 只是稳一点
            }
        }
        return m;
    }

    // 读多份文件再合并。**任一份坏就整次失败**，并把坏在第几份说清楚。
    static bool loadAll (const std::vector<std::string> &paths, MergedLedger &out,
                         std::vector<std::size_t> &badIndexes, std::string &why)
    {
        badIndexes.clear ();
        why.clear ();
        std::vector<DenyLedger> src;
        src.reserve (paths.size ());
        for (std::size_t i = 0; i < paths.size (); ++i)
        {
            DenyLedger l;
            std::string w;
            if (!DenyLedger::load (paths[i], l, w))
            {
                badIndexes.push_back (i);
                if (why.empty ())
                    why = "第 " + std::to_string (i + 1) + " 份（" + paths[i] + "）：" + w;
                src.push_back (std::move (l));
                continue;
            }
            src.push_back (std::move (l));
        }
        if (!badIndexes.empty ()) return false;
        out = from (src);
        return true;
    }

    std::size_t         sources () const { return sources_; }
    std::size_t         size () const { return entries_.size (); }
    const std::vector<MergedEntry> &entries () const { return entries_; }
    std::uint64_t       totalHits () const { return totalHits_; }
    std::size_t         droppedEntries () const { return droppedEntries_; }
    std::size_t         droppedHits () const { return droppedHits_; }
    std::size_t         sourcesWithDrop () const { return sourcesWithDrop_; }

    std::uint64_t hitsOfSa (std::uint16_t sa) const
    {
        std::uint64_t n = 0;
        for (const auto &e : entries_) if (e.sa == sa) n += e.count;
        return n;
    }

    // 这个 SA 出现在几份账里（"每周都在"和"只来过一次"不是一回事）。
    // 同一个人可能有多组试探、分散在不同周，所以这里求**并集**而不是取最大。
    std::size_t runsOfSa (std::uint16_t sa) const
    {
        std::vector<char> seen (sources_, 0);
        for (const auto &e : entries_)
            if (e.sa == sa)
                for (std::size_t i = 0; i < e.perRun.size (); ++i)
                    if (e.perRun[i] > 0) seen[i] = 1;
        std::size_t n = 0;
        for (char b : seen) if (b != 0) ++n;
        return n;
    }

    std::uint64_t hitsOfDid (std::uint16_t did) const
    {
        std::uint64_t n = 0;
        for (const auto &e : entries_) if (e.did == did) n += e.count;
        return n;
    }

    std::size_t runsOfDid (std::uint16_t did) const
    {
        std::vector<char> seen (sources_, 0);
        for (const auto &e : entries_)
            if (e.did == did)
                for (std::size_t i = 0; i < e.perRun.size (); ++i)
                    if (e.perRun[i] > 0) seen[i] = 1;
        std::size_t n = 0;
        for (char b : seen) if (b != 0) ++n;
        return n;
    }

    // 撞得最狠的那一组（次数最多；并列取先出现的）。
    const MergedEntry *worst () const
    {
        const MergedEntry *w = nullptr;
        for (const auto &e : entries_)
            if (w == nullptr || e.count > w->count) w = &e;
        return w;
    }

private:
    MergedEntry *find (const Entry &e)
    {
        for (auto &m : entries_)
            if (m.sa == e.sa && m.sid == e.sid && m.did == e.did && m.need == e.need &&
                m.have == e.have && m.why == e.why)
                return &m;
        return nullptr;
    }

    std::vector<MergedEntry> entries_;
    std::size_t              sources_         = 0;
    std::size_t              sourcesWithDrop_ = 0;
    std::uint64_t            totalHits_       = 0;
    std::size_t              droppedEntries_  = 0;
    std::size_t              droppedHits_     = 0;
};

}   // namespace deny
}   // namespace doip
