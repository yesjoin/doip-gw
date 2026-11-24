// ============================================================================
// stream_selftest.cpp —— M12 的纯逻辑自测（StreamLedger）
//
// 这本账只做一件事：让"边收边发"和"最后交卷"不打架。
// 所以这里测的全是**同一批答案被两条路径各处理一次**的情形——
// 现场最难复现，但写错就会让客户端看到同一条答案两遍。
//
// 用法：./stream-selftest        全绿时退出码 0
// ============================================================================
#include "StreamLedger.h"

#include <cstdio>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, what);     \
        }                                                              \
    } while (0)

int main ()
{
    // ---- A. 一条都没流式：交卷时该全发 ----
    {
        StreamLedger l;
        CHECK (l.streamed (7) == 0, "没记过的 job：已发 0 条");
        CHECK (l.remainder (7, 3) == 3, "一条都没流式 → 交卷时补发 3 条");
        CHECK (l.jobs () == 0, "空账本：0 个 job");
        CHECK (l.totalStreamed () == 0, "空账本：累计 0 条");
    }

    // ---- B. 全部流式：交卷时一条都不该再发 ----
    {
        StreamLedger l;
        l.noteStreamed (7);
        l.noteStreamed (7);
        l.noteStreamed (7);
        CHECK (l.streamed (7) == 3, "同一个 job 记了 3 条");
        CHECK (l.remainder (7, 3) == 0, "3 条全流式过 → 交卷时补发 0 条（不重复发）");
        CHECK (l.totalStreamed () == 3, "累计 3 条");
    }

    // ---- C. 部分流式（这就是竞态：交卷比最后一条流式早/晚） ----
    {
        StreamLedger l;
        l.noteStreamed (9);
        l.noteStreamed (9);
        CHECK (l.remainder (9, 3) == 1, "流了 2 条、结果共 3 条 → 补发 1 条");
        l.noteStreamed (9);
        CHECK (l.remainder (9, 3) == 0, "补上第 3 条后 → 补发 0 条");
    }

    // ---- D. 账比结果还多（结果被截断/失败回落）：不能算出负数 ----
    {
        StreamLedger l;
        for (int i = 0; i < 5; ++i) l.noteStreamed (11);
        CHECK (l.remainder (11, 3) == 0, "已发 5 条 > 结果 3 条 → 补发 0（不许下溢）");
        CHECK (l.remainder (11, 0) == 0, "结果为 0 条（失败）→ 补发 0");
    }

    // ---- E. 多 job 互不干扰 ----
    {
        StreamLedger l;
        l.noteStreamed (1);
        l.noteStreamed (2);
        l.noteStreamed (2);
        CHECK (l.streamed (1) == 1, "job 1 只发了 1 条");
        CHECK (l.streamed (2) == 2, "job 2 发了 2 条（没被 job 1 串味）");
        CHECK (l.remainder (1, 3) == 2, "job 1 还要补 2 条");
        CHECK (l.remainder (2, 3) == 1, "job 2 还要补 1 条");
        CHECK (l.jobs () == 2, "两个 job 各占一个格子");
        CHECK (l.totalStreamed () == 3, "累计 3 条");
    }

    // ---- F. 销账：结果处理完就不该再占内存 ----
    {
        StreamLedger l;
        l.noteStreamed (3);
        l.noteStreamed (3);
        l.forget (3);
        CHECK (l.streamed (3) == 0, "销账之后查不到（当作没流式过）");
        CHECK (l.jobs () == 0, "账本清空了这一格");
        CHECK (l.remainder (3, 2) == 2, "销账后再来结果 → 当没流式过，补发 2 条");
        CHECK (l.totalStreamed () == 2, "累计计数是观测量，销账不回调");
    }

    // ---- G. 断线：销账后迟到的流式不该再冒出来 ----
    {
        StreamLedger l;
        l.noteStreamed (5);
        l.forget (5);          // 连接断了，job 作废
        l.noteStreamed (5);    // 但 worker 还在跑，迟到一条又记进来
        CHECK (l.streamed (5) == 1, "迟到的一条会重新占一格（这是已知的小瑕疵）");
        CHECK (l.remainder (5, 3) == 2, "此时若真有结果回来，会补发 2 条");
    }

    // ---- H. 大 jobId（uint64）与清零 ----
    {
        StreamLedger l;
        const std::uint64_t big = 9000000000ULL;
        l.noteStreamed (big);
        CHECK (l.streamed (big) == 1, "64 位 jobId 也能归档");
        CHECK (l.streamed (big + 1) == 0, "相邻 id 不会被算进来");
        l.clear ();
        CHECK (l.jobs () == 0 && l.totalStreamed () == 0, "clear() 全部归零");
        CHECK (l.streamed (big) == 0, "clear() 之后查不到");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    if (gFail == 0)
        std::printf ("M12 的流式记账全绿 —— 边收边发与最后交卷互不重复，销账不回头。\n");
    return gFail == 0 ? 0 : 1;
}
