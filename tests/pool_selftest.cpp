// ============================================================================
// pool_selftest.cpp —— M10：排队与交卷台的纯逻辑自测（不需要 vcan0）
//
// 并发最难的地方不是"写个线程"，而是那些只在特定时序下才出现的行为：
//   队列满了是拒还是等？stop 会不会把阻塞的线程永远留在那儿？
//   连接断了以后结果回来看不到主人，会不会被下一个人收走？
// 这些都**可以在内存里测**，不用碰 CAN。e2e 负责"真总线上的时序"，
// 这里负责"语义"，两层各管一段，才敢说并发是对的。
// ============================================================================
#include "JobQueue.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

using namespace doip;
using namespace std::chrono_literals;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond) { ++g_pass; std::printf ("[PASS] %s\n", what.c_str ()); }
    else      { ++g_fail; std::printf ("[FAIL] %s\n", what.c_str ()); }
}

static ChannelJob job (std::uint64_t id)
{
    ChannelJob j;
    j.id = id;
    j.req.targetAddress = 0x0003;
    j.req.sourceAddress = 0x0E00;
    j.req.uds           = {0x22, 0xF1, 0x90};
    j.enqueued          = std::chrono::steady_clock::now ();
    return j;
}

int main ()
{
    std::printf ("=== A 队列：FIFO / 容量 / 拒绝 / stop ===\n");

    {
        JobQueue q (8);
        check (q.push (job (1)) && q.push (job (2)) && q.push (job (3)), "三条都能入队");
        check (q.depth () == 3, "深度 = 3");
        check (q.peak () == 3, "峰值 = 3");

        ChannelJob out;
        check (q.pop (out) && out.id == 1, "先出的必须是第 1 条（FIFO）");
        check (q.pop (out) && out.id == 2, "接着第 2 条");
        check (q.depth () == 1, "取了两条，深度 = 1");
        check (q.pop (out) && out.id == 3, "最后第 3 条");
    }

    {
        JobQueue q (3);
        check (q.push (job (1)) && q.push (job (2)) && q.push (job (3)), "容量 3 刚好放满");
        check (!q.push (job (4)), "第 4 条被拒（有界队列，绝不让 I/O 线程等）");
        check (q.rejected () == 1, "拒绝次数记到 1");
        check (q.peak () == 3, "峰值停在 3（没有被撑大）");

        q.stop ();
        check (!q.push (job (5)), "stop 之后不再收活");
        ChannelJob out;
        check (q.pop (out) && out.id == 1, "stop 之后**已入队**的活还要跑完（不是丢弃）");
        check (q.pop (out) && out.id == 2, "第 2 条也一样跑完");
        check (q.pop (out) && out.id == 3, "第 3 条也一样");
        check (!q.pop (out), "取空之后 pop 立刻返回 false，不会卡住");
    }

    {
        // stop 必须能唤醒"正阻塞在空队列上"的线程：唤醒不了就是关网关时卡死
        JobQueue q (4);
        std::atomic<bool> returned{false};
        std::thread waiter ([&] {
            ChannelJob out;
            q.pop (out);                // 空队列上阻塞
            returned = true;
        });
        std::this_thread::sleep_for (30ms);
        check (!returned, "空队列上的 pop 是阻塞的（不该自己返回）");
        q.stop ();
        waiter.join ();
        check (returned, "stop 之后阻塞的 pop 被唤醒并返回");
    }

    std::printf ("\n=== B 交卷台：完成 / 超时 / 作废 ===\n");

    {
        ResultBoard b;
        const std::uint64_t id = b.add ();
        check (b.pending () == 1, "登记一条，在途 = 1");

        JobResult r;
        check (!b.wait (id, r, 10ms), "还没完成：wait 超时返回 false（不会死等）");

        JobResult done;
        done.ok = true;
        done.replies.push_back (DiagnosticReply{0x0003, {0x62, 0xF1, 0x90}});
        b.complete (id, done);

        std::uint64_t gotId = 0;
        JobResult out;
        check (b.takeAny (gotId, out) && gotId == id, "takeAny 取到的是同一个 id");
        check (out.ok && out.replies.size () == 1 && out.replies[0].sourceAddress == 0x0003,
               "结果原样带回来（含是谁答的）");
        check (b.pending () == 0, "取走之后在途 = 0，槽没有漏");
        check (!b.takeAny (gotId, out), "空了以后 takeAny 返回 false");
    }

    {
        // 作废 = 连接断了。结果后来回来了，也**不许**被别人取走。
        ResultBoard b;
        const std::uint64_t id = b.add ();
        b.abandon (id);
        check (b.pending () == 0, "作废之后槽立刻消失");

        JobResult late;
        late.ok = true;
        b.complete (id, late);         // 迟到的结果
        std::uint64_t gotId = 0;
        JobResult out;
        check (!b.takeAny (gotId, out), "迟到的结果不会被任何人取走（这就是 M5 迟到帧的以太网版）");

        JobResult never;
        check (!b.wait (id, never, 5ms), "对已作废的 id 等待，立刻返回 false");
    }

    {
        // 跨线程唤醒：工作线程干完活，等的人必须被叫醒（不是靠轮询撞上）
        ResultBoard b;
        const std::uint64_t id = b.add ();
        std::thread worker ([&] {
            std::this_thread::sleep_for (40ms);
            JobResult r;
            r.ok = true;
            b.complete (id, r);
        });

        const auto t0 = std::chrono::steady_clock::now ();
        JobResult out;
        const bool got = b.wait (id, out, 500ms);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds> (
            std::chrono::steady_clock::now () - t0).count ();
        worker.join ();

        check (got && out.ok, "等的人拿到了结果（跨线程唤醒生效）");
        check (ms >= 30 && ms < 200, "等的时间接近工作线程的 40ms，说明不是轮询撞上的（实测 " +
                                    std::to_string (ms) + " ms）");
    }

    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M10 排队语义全绿 —— 满了当场拒、stop 能唤醒、作废的结果没人接。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
