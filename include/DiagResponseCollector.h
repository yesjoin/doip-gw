// ============================================================================
// DiagResponseCollector.h —— 诊断仪侧的"多响应配对"（M11）
//
// 为什么需要单独一个文件：
//
//   物理寻址时，一条请求回去只有一条答案，谁答的无所谓——反正只有那台。
//   功能寻址（TA=0xE400）反过来：一条请求打出去，**谁在听谁答**，
//   条数由总线上的 ECU 决定，不由网关决定。这时候客户端必须回答三个问题：
//
//     ① 这条答案是谁说的？（按 SA 归档，不能按"第几条"猜）
//     ② 收齐了吗？（DoIP 没有"批次结束"字段，只能靠静默窗口猜）
//     ③ 同一台又答了一遍，算重复还是算它改了主意？（内容不同就是改主意）
//
// 这三件事全是纯逻辑：给一条 (SA, UDS, 时间戳)，问它"现在是第几条、归谁、能不能收工"。
// 所以放在头文件里、不碰 socket，能在 tests 里用假时钟测完——
// 和 M10 的 JobQueue 是同一个思路：把能纯逻辑化的东西从 I/O 里剥出来。
// ============================================================================
#ifndef DOIP_DIAG_RESPONSE_COLLECTOR_H
#define DOIP_DIAG_RESPONSE_COLLECTOR_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace doip
{

// 一条已经归档的答案
struct CollectedResponse
{
    std::uint16_t sa{0};                 // 谁答的（诊断报文里的源地址）
    std::vector<std::uint8_t> uds;       // 第一次答的原始字节（重复的那次不覆盖）
    std::size_t   seq{0};                // 到达顺序，1 起（给人看"谁先答"）
    std::size_t   duplicates{0};         // 这台后来又答了几次
    std::size_t   changes{0};            // 后来的答案里，内容与第一次不同的次数
    long          firstMs{0};            // 第一次的到达时刻（调用方给的假时钟）
    long          lastMs{0};             // 最近一次的到达时刻

    // UDS 负响应（0x7F xx yy）：某台 ECU 不支持这个 DID，也是合法答案
    bool negative () const { return !uds.empty () && uds[0] == 0x7F; }
};

class DiagResponseCollector
{
public:
    enum class Outcome
    {
        Fresh,       // 新的一台
        Duplicate,   // 已有的一台又答了一遍
    };

    // 完全不看时钟，只看内容
    Outcome add (std::uint16_t sa, const std::vector<std::uint8_t> &uds, long nowMs)
    {
        CollectedResponse *slot = findMutable (sa);
        if (slot == nullptr)
        {
            CollectedResponse r;
            r.sa      = sa;
            r.uds     = uds;
            r.seq     = items_.size () + 1;
            r.firstMs = nowMs;
            r.lastMs  = nowMs;
            items_.push_back (r);
            ++arrivals_;
            return Outcome::Fresh;
        }

        // 同一台又答了：条数不涨，但"它答了几次""有没有改口"要记下来。
        // 第一条正文保留——本轮的答案是它第一次说的那句。
        ++slot->duplicates;
        if (slot->uds != uds) ++slot->changes;
        slot->lastMs = nowMs;
        ++arrivals_;
        return Outcome::Duplicate;
    }

    std::size_t count () const { return items_.size (); }        // 不同 SA 的台数
    std::size_t arrivals () const { return arrivals_; }          // 到过几条（含重复）
    std::size_t duplicates () const
    {
        std::size_t n = 0;
        for (const auto &r : items_) n += r.duplicates;
        return n;
    }
    std::size_t changes () const
    {
        std::size_t n = 0;
        for (const auto &r : items_) n += r.changes;
        return n;
    }
    bool empty () const { return items_.empty (); }

    const CollectedResponse &at (std::size_t i) const { return items_.at (i); }

    const CollectedResponse *find (std::uint16_t sa) const
    {
        for (const auto &r : items_)
            if (r.sa == sa) return &r;
        return nullptr;
    }

    // 距最后一条的静默时长；一条都没有时返回 -1（"从来没响过"和"很久没响"不是一回事）
    long quietMs (long nowMs) const
    {
        if (items_.empty ()) return -1;
        return nowMs - items_.back ().lastMs;
    }

    // "能不能收工"：至少有一条，且已经静默满 windowMs。
    // 为什么靠静默：DoIP 的 0x8001 没有"最后一条"标志，协议层压根没有批次概念；
    // 真实诊断仪用的是 UDS 的 P2* 计时——本质上也是"等它不响了"。
    bool settled (long nowMs, long windowMs) const
    {
        if (items_.empty ()) return false;
        return quietMs (nowMs) >= windowMs;
    }

    void reset ()
    {
        items_.clear ();
        arrivals_ = 0;
    }

private:
    CollectedResponse *findMutable (std::uint16_t sa)
    {
        for (auto &r : items_)
            if (r.sa == sa) return &r;
        return nullptr;
    }

    std::vector<CollectedResponse> items_;
    std::size_t arrivals_{0};
};

} // namespace doip

#endif // DOIP_DIAG_RESPONSE_COLLECTOR_H
