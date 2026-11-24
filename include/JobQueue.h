#pragma once
// ============================================================================
// JobQueue.h —— M10：把"排队"和"结果回收"从 socket 里拆出来
//
// 为什么单独拆一个头文件？
//   并发的问题有两层：
//     ① 队列本身（满了怎么办、stop 会不会卡住、FIFO 顺序）
//     ② socket 和 CAN（回不回、超不超时）
//   第 ① 层是**纯逻辑**，不碰 socket 就能测到死；第 ② 层只能在真总线上验。
//   把 ① 拆出来，M10 才有办法在 ctest 里把并发语义钉住——
//   否则一谈并发就只能"跑一遍 e2e 看看会不会红"，那是最不可靠的验证方式。
//
// 两个类：
//   JobQueue    —— 每条通道一个，工作线程从这里取活干（有界队列，满了当场拒）
//   ResultBoard —— 全局一个，登记"谁在等哪个结果"，工作线程干完就来这儿交卷
//
// 共同约定：**所有阻塞都带出口**。JobQueue 能被 stop 唤醒，ResultBoard 的 wait 带超时。
// 没有出口的阻塞，就是"网关卡死、ctrl-c 才退出"的来源。
// ============================================================================
#include "DoIpDiagnostic.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace doip
{

struct ChannelJob
{
    std::uint64_t            id = 0;
    DiagnosticRequest        req;
    std::chrono::steady_clock::time_point enqueued;   // 排队时刻：用来算"等了多久"
};

struct JobResult
{
    bool                            ok = false;
    std::uint8_t                    nackCode = 0;
    std::string                     reason;
    std::vector<DiagnosticReply>    replies;
};

// ---------------------------------------------------------------------------
// 有界 FIFO。
// 满了**当场拒**，不阻塞调用方：调用方可能是 I/O 线程，让它等 CAN 就等于把整个网关拖死。
// ---------------------------------------------------------------------------
class JobQueue
{
public:
    explicit JobQueue (std::size_t cap = 8) : cap_ (cap) {}

    bool push (const ChannelJob &j)
    {
        std::lock_guard<std::mutex> lk (mu_);
        if (stopped_ || jobs_.size () >= cap_)
        {
            ++rejected_;
            return false;
        }
        jobs_.push_back (j);
        if (jobs_.size () > peak_) peak_ = jobs_.size ();
        cv_.notify_one ();
        return true;
    }

    bool pop (ChannelJob &j)
    {
        std::unique_lock<std::mutex> lk (mu_);
        cv_.wait (lk, [this] { return stopped_ || !jobs_.empty (); });
        if (jobs_.empty ()) return false;          // stop 了且已经取空
        j = jobs_.front ();
        jobs_.pop_front ();
        ++pops_;
        return true;
    }

    void stop ()
    {
        std::lock_guard<std::mutex> lk (mu_);
        stopped_ = true;
        cv_.notify_all ();
    }

    std::size_t depth () const
    {
        std::lock_guard<std::mutex> lk (mu_);
        return jobs_.size ();
    }
    std::size_t peak () const     { std::lock_guard<std::mutex> lk (mu_); return peak_; }
    std::size_t rejected () const { std::lock_guard<std::mutex> lk (mu_); return rejected_; }
    std::size_t pops () const     { std::lock_guard<std::mutex> lk (mu_); return pops_; }

private:
    mutable std::mutex              mu_;
    std::condition_variable         cv_;
    std::deque<ChannelJob>          jobs_;
    std::size_t                     cap_;
    bool                            stopped_  = false;
    std::size_t                     peak_     = 0;
    std::size_t                     rejected_ = 0;
    std::size_t                     pops_     = 0;
};

// ---------------------------------------------------------------------------
// 交卷台：id → 结果。
// 三种结局都要能表达：
//   完成（complete） / 超时（wait 返回 false） / 作废（abandon，连接断了）
// 作废这一步很关键：连接断了以后结果还会回来，**不丢的话就会被下一台诊断仪收走**——
// 这正是 M5 里"迟到帧"的同一种错，只是换到了以太网侧。
// ---------------------------------------------------------------------------
class ResultBoard
{
public:
    std::uint64_t add ()
    {
        std::lock_guard<std::mutex> lk (mu_);
        const std::uint64_t id = ++next_;
        slots_[id] = Slot{};
        return id;
    }

    void complete (std::uint64_t id, JobResult r)
    {
        std::lock_guard<std::mutex> lk (mu_);
        auto it = slots_.find (id);
        if (it == slots_.end ()) return;            // 已被作废：结果直接丢
        it->second.r    = std::move (r);
        it->second.done = true;
        cv_.notify_all ();
    }

    bool wait (std::uint64_t id, JobResult &out, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lk (mu_);
        auto it = slots_.find (id);
        if (it == slots_.end ()) return false;
        if (!cv_.wait_for (lk, timeout, [&] {
                auto p = slots_.find (id);
                return p == slots_.end () || p->second.done;
            }))
        {
            return false;                            // 超时：槽留着，等它自己完成再被 takeAny 清掉
        }
        auto p = slots_.find (id);
        if (p == slots_.end ()) return false;        // 等待期间被作废
        out = std::move (p->second.r);
        slots_.erase (p);
        return true;
    }

    // 非阻塞：取走任意一个已完成的结果（I/O 线程每轮扫一遍）
    bool takeAny (std::uint64_t &id, JobResult &out)
    {
        std::lock_guard<std::mutex> lk (mu_);
        for (auto it = slots_.begin (); it != slots_.end (); ++it)
        {
            if (!it->second.done) continue;
            id  = it->first;
            out = std::move (it->second.r);
            slots_.erase (it);
            return true;
        }
        return false;
    }

    void abandon (std::uint64_t id)
    {
        std::lock_guard<std::mutex> lk (mu_);
        slots_.erase (id);
        cv_.notify_all ();
    }

    std::size_t pending () const
    {
        std::lock_guard<std::mutex> lk (mu_);
        return slots_.size ();
    }

private:
    struct Slot { JobResult r; bool done = false; };
    mutable std::mutex              mu_;
    std::condition_variable         cv_;
    std::map<std::uint64_t, Slot>   slots_;
    std::uint64_t                   next_ = 0;
};

} // namespace doip
