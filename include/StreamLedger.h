// ============================================================================
// StreamLedger.h —— M12 的"流式交付记账"（纯逻辑，无 socket）
//
// 为什么要这本账：
//
//   M11 里一轮广播的答案是**攒齐后一次性交回**的，所以诊断仪必须等到最慢那台
//   （ECU 慢 120ms，客户端就得等 130ms 才看到第一条）。
//   M12 改成"网关收一条、就往回发一条"：快的 ECU 几毫秒内就能让诊断仪看到答案。
//
//   但这样一来每个人都得回答一个问题：**同一条答案会不会发两遍？**
//   流程是"边到边发" + "最后再交一次卷"（JobResult 里仍然带着全部 replies），
//   如果交卷时把已经流式发过的又发一遍，客户端就会看到 duplicates，
//   M11 刚立起来的"按 SA 归档"会直接失真。
//
//   所以记一本小账：这个 job 已经流式发了 k 条；交卷时共 total 条，
//   该补发的就是 total - k 条（k >= total → 0）。这本账只有整数加减，
//   没有任何 socket 依赖，所以能在 tests 里一秒测完。
// ============================================================================
#ifndef DOIP_STREAM_LEDGER_H
#define DOIP_STREAM_LEDGER_H

#include <cstddef>
#include <cstdint>
#include <unordered_map>

namespace doip
{

class StreamLedger
{
public:
    // 流式发出了一条（由 I/O 线程在真正 send 成功之后调）
    void noteStreamed (std::uint64_t jobId)
    {
        ++perJob_[jobId];
        ++total_;
    }

    // 这个 job 已经流式发出去几条；没记过就是 0
    std::size_t streamed (std::uint64_t jobId) const
    {
        auto it = perJob_.find (jobId);
        return it == perJob_.end () ? 0 : it->second;
    }

    // 交卷时还该补发几条：total - 已流式（不会为负）
    std::size_t remainder (std::uint64_t jobId, std::size_t total) const
    {
        const std::size_t s = streamed (jobId);
        return s >= total ? 0 : total - s;
    }

    // 结果处理完（或连接断了）就把这个 job 的账销掉。
    // 销账是必须的：jobId 会一直涨，但账本不能跟着涨一辈子。
    void forget (std::uint64_t jobId)
    {
        perJob_.erase (jobId);
    }

    std::size_t jobs () const { return perJob_.size (); }
    std::size_t totalStreamed () const { return total_; }

    void clear ()
    {
        perJob_.clear ();
        total_ = 0;
    }

private:
    std::unordered_map<std::uint64_t, std::size_t> perJob_;
    std::size_t total_{0};
};

} // namespace doip

#endif // DOIP_STREAM_LEDGER_H
