// ============================================================================
// DoIpGateway.cpp —— M4 桥接 → M6 多通道 → M10 每条通道一个工作线程
//
// 读这段代码按这个顺序：
//   ① start()        —— 开通道、起线程（谁拥有 socket，谁就有权发帧）
//   ② workerLoop()   —— 一条通道的完整生命周期：取活 → 独占总线 → 交卷
//   ③ submit()       —— 投递时的三种结局：立刻拒 / 进队 / 排队满（也是立刻拒，但要留痕）
//   ④ broadcastLocked() —— 广播：**必须一次占住所有通道**，因为总线只有一条
//
// M10 的关键一步是把"锁"改名成"队列"：
//   锁只能表达"等"，队列能表达"排了几个、排了多久、满了怎么办"。
//   排查现场时，这三样东西比"反正串行"有用得多。
// ============================================================================
#include "DoIpGateway.h"
#include "SourceSlot.h"   // M28：按槽号改写请求 ID 的源地址

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace doip
{
namespace
{

std::string hexTa (std::uint16_t v)
{
    char b[16];
    std::snprintf (b, sizeof (b), "0x%04X", static_cast<unsigned> (v));
    return std::string (b);
}

} // namespace

DiagnosticGateway::DiagnosticGateway (const std::string &iface,
                                     const RouteTable &table,
                                     const IsoTpTiming &tim)
    : iface_ (iface), table_ (table), tim_ (tim)
{
}

DiagnosticGateway::~DiagnosticGateway ()
{
    stop ();
}

bool DiagnosticGateway::start (std::string &err)
{
    if (running_) return true;

    // ---- 第一步：把 socket 全开起来，一条不成就整体失败 ----
    // 先全部 open、再统一起线程：半开状态下起线程，等于让工作线程对着没 bind 的 fd 发帧。
    for (const auto &e : table_.entries ())
    {
        IsoTpConfig cfg;
        cfg.txId = e.txId;
        cfg.rxId = e.rxId;
        cfg.frameBytes = e.fd ? kFdFrameBytes : kClassicFrameBytes;

        auto ch = std::unique_ptr<Channel> (new Channel (iface_, cfg, tim_));
        ch->txId = e.txId;   // M28：不装槽号时要回落到表里这一条
        std::string e2;
        if (!ch->client.open (e2))
        {
            err = "路由 " + (e.name.empty () ? std::string ("?") : e.name) +
                  "（TA=" + hexTa (e.logicalAddress) + "，" +
                  formatCanId (e.txId) + "/" + formatCanId (e.rxId) +
                  (e.fd ? "，FD" : "，经典帧") + "）开不起来：" + e2;
            for (auto &kv : chans_) kv.second->client.close ();
            chans_.clear ();
            return false;
        }
        chans_[e.logicalAddress] = std::move (ch);
    }

    // ---- 第二步：每条通道一条线程 ----
    running_ = true;
    for (auto &kv : chans_)
    {
        const std::uint16_t ta = kv.first;
        kv.second->worker = std::thread ([this, ta] { workerLoop (ta); });
    }
    funcThread_ = std::thread ([this] { functionalLoop (); });
    return true;
}

void DiagnosticGateway::stop ()
{
    if (!running_) return;
    running_ = false;

    for (auto &kv : chans_) kv.second->queue.stop ();
    funcQueue_.stop ();
    for (auto &kv : chans_)
    {
        if (kv.second->worker.joinable ()) kv.second->worker.join ();
    }
    if (funcThread_.joinable ()) funcThread_.join ();

    for (auto &kv : chans_) kv.second->client.close ();
    chans_.clear ();
}

// ---------------------------------------------------------------------------
// 一条通道的工作线程
//
// 顺序是刻意的：
//   取活（队列）→ 记排队时长 → **独占总线** → 发帧收帧 → 交卷（放锁之前不放结果）
// 放锁之后才交卷，是为了让"结果已经可用"和"总线上这条已经走完"的顺序对得上：
// 反过来的话，下一个请求可能在结果还没登记时就开始发帧，日志里就出现"回得比问得早"。
// ---------------------------------------------------------------------------
void DiagnosticGateway::workerLoop (std::uint16_t ta)
{
    auto it = chans_.find (ta);
    if (it == chans_.end ()) return;
    Channel &ch = *it->second;

    ChannelJob job;
    while (ch.queue.pop (job))
    {
        const auto waited = std::chrono::duration_cast<std::chrono::milliseconds> (
            std::chrono::steady_clock::now () - job.enqueued).count ();
        const std::size_t w = static_cast<std::size_t> (waited < 0 ? 0 : waited);
        std::size_t prev = ch.maxQueueWaitMs.load ();
        while (w > prev && !ch.maxQueueWaitMs.compare_exchange_weak (prev, w)) {}

        JobResult r;
        {
            // 这条通道的总线使用权。M10 只是把锁的粒度从"全局"改到"每通道"。
            std::lock_guard<std::mutex> bus (ch.busMu);
            std::vector<std::uint8_t> resp;
            std::string err;
            // M28：把"谁"写成 CAN 源地址。
            //   只改 29 位 ID 的最低字节；11 位 ID 原样（它没有源地址那一格）。
            //   槽号来自**这一次请求**（不是这条通道），两台诊断仪交叠时不串号。
            const std::uint32_t tx = stampSource_ ? slots::stampSource (ch.txId, job.req.actorSlot)
                                                  : ch.txId;
            if (ch.client.request (job.req.uds, resp, err, tx))
            {
                r.ok = true;
                r.replies.push_back (DiagnosticReply{job.req.targetAddress, resp});
            }
            else
            {
                r.ok = false;
                r.nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
                r.reason = err;
            }
        }

        if (r.ok) { ++ch.handled; ++handled_; }
        else      { ++ch.failed; ++failed_; }
        finishJob (job.id, std::move (r));
    }
}

// ---------------------------------------------------------------------------
// 广播线程（M8 的 broadcast 搬到独立线程）
//
// 为什么广播不能占 I/O 线程：广播要"挨条通道收 150ms"，两条通道就是 300ms，
// 这段时间里 I/O 线程连 accept 都做不了。而广播本身又是"全网动作"，
// 它确实**必须**独占所有通道（总线只有一条），所以只能在专用线程里独占。
// ---------------------------------------------------------------------------
void DiagnosticGateway::functionalLoop ()
{
    ChannelJob job;
    while (funcQueue_.pop (job))
    {
        const auto waited = std::chrono::duration_cast<std::chrono::milliseconds> (
            std::chrono::steady_clock::now () - job.enqueued).count ();
        const std::size_t w = static_cast<std::size_t> (waited < 0 ? 0 : waited);
        std::size_t prev = maxWaitMs_.load ();
        while (w > prev && !maxWaitMs_.compare_exchange_weak (prev, w)) {}

        // ★ M12：带 jobId 进来，每收到一条就往外交一条（不再攒齐）
        DiagnosticMultiResult mr = broadcastJob (job.id, job.req);

        JobResult r;
        r.ok       = mr.ok;
        r.nackCode = mr.nackCode;
        r.reason   = mr.reason;
        r.replies  = mr.replies;
        finishJob (job.id, std::move (r));
    }
}

// 按 TA 升序拿所有通道的总线锁：顺序固定才不会两条线程各拿一半互相等（死锁）
void DiagnosticGateway::lockAllBuses (std::vector<std::unique_lock<std::mutex>> &locks)
{
    locks.clear ();
    for (auto &kv : chans_)
    {
        if (kv.second) locks.emplace_back (kv.second->busMu);
    }
}

// ---------------------------------------------------------------------------
// 投递：三种结局都要有明确去处
//   ① 地址不认识 / 通道没开 → id=0 + immediate 里就是结论（不占队列）
//   ② 进程正常 → 进队，返回 id
//   ③ 队列满了 → **仍然返回 id**，但结果已经当场写好（0x08 排队满）
//      为什么给 id：调用方（TCP 服务器）只需要"记住一个号"，不该为"当场失败"多写一条分支。
// ---------------------------------------------------------------------------
std::uint64_t DiagnosticGateway::submit (const DiagnosticRequest &req, DiagnosticMultiResult &immediate)
{
    immediate = DiagnosticMultiResult{};
    const std::uint64_t id = board_.add ();

    if (table_.knownFunctional (req.targetAddress))
    {
        ChannelJob job;
        job.id       = id;
        job.req      = req;
        job.enqueued = std::chrono::steady_clock::now ();
        if (!funcQueue_.push (job))
        {
            ++failed_;
            immediate.nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
            immediate.reason   = "广播队列已满（上限 8 条），这条请求没排上";
            board_.abandon (id);
            return 0;
        }
        return id;
    }

    auto it = chans_.find (req.targetAddress);
    if (it == chans_.end () || !it->second)
    {
        ++unknown_;
        ++failed_;
        immediate.nackCode = static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress);
        immediate.reason   = "目标地址 " + hexTa (req.targetAddress) + " 不在路由表里";
        board_.abandon (id);
        return 0;
    }

    Channel &ch = *it->second;
    ChannelJob job;
    job.id       = id;
    job.req      = req;
    job.enqueued = std::chrono::steady_clock::now ();

    if (!ch.queue.push (job))
    {
        ++failed_;
        ++ch.failed;
        JobResult r;
        r.nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
        r.reason   = "通道 " + hexTa (req.targetAddress) +
                     " 的队列已满（上限 8 条），这条请求没排上";
        board_.complete (id, std::move (r));
        return id;
    }
    return id;
}

bool DiagnosticGateway::waitResult (std::uint64_t id, DiagnosticMultiResult &out,
                                   std::chrono::milliseconds timeout)
{
    JobResult r;
    if (!board_.wait (id, r, timeout))
    {
        // 超时也要把槽清掉，否则这个 id 会一直挂在表上（"漏一个槽"比"漏一条请求"更隐蔽）
        board_.abandon (id);
        return false;
    }
    out.ok       = r.ok;
    out.nackCode = r.nackCode;
    out.reason   = r.reason;
    out.replies  = std::move (r.replies);
    return true;
}

bool DiagnosticGateway::takeResult (std::uint64_t &id, DiagnosticMultiResult &out)
{
    JobResult r;
    if (!board_.takeAny (id, r)) return false;
    out.ok       = r.ok;
    out.nackCode = r.nackCode;
    out.reason   = r.reason;
    out.replies  = std::move (r.replies);
    return true;
}

void DiagnosticGateway::abandon (std::uint64_t id)
{
    // 连接断了：槽立刻删掉。工作线程过一会儿仍然会把结果交上来，
    // 但板子上已经没有这个 id —— 结果自然落地无声，不会被下一台诊断仪收走。
    ++abandoned_;
    board_.abandon (id);
}

void DiagnosticGateway::finishJob (std::uint64_t id, JobResult r)
{
    board_.complete (id, std::move (r));
}

// ---- 同步外壳：M4~M9 的调用方式不变 ----
bool DiagnosticGateway::operator() (const DiagnosticRequest &req,
                                   std::vector<std::uint8_t> &resp,
                                   std::string &err)
{
    resp.clear ();

    if (table_.knownFunctional (req.targetAddress))
    {
        DiagnosticMultiResult mr = broadcast (req);
        if (!mr.ok)
        {
            err = mr.reason;
            return false;
        }
        if (mr.replies.size () != 1)
        {
            err = "功能地址回了 " + std::to_string (mr.replies.size ()) + " 条应答，一问一答接口装不下";
            return false;
        }
        resp = mr.replies.front ().uds;
        return true;
    }

    DiagnosticMultiResult immediate;
    const std::uint64_t id = submit (req, immediate);
    if (id == 0)
    {
        err = immediate.reason;
        return false;
    }

    const auto t0 = std::chrono::steady_clock::now ();
    DiagnosticMultiResult mr;
    if (!waitResult (id, mr, std::chrono::milliseconds (8000)))
    {
        err = "等结果超时（8 秒）";
        return false;
    }

    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds> (
        std::chrono::steady_clock::now () - t0).count ();
    if (static_cast<std::size_t> (waited) > maxWaitMs_.load ())
        maxWaitMs_ = static_cast<std::size_t> (waited);

    if (!mr.ok)
    {
        err = mr.reason;
        return false;
    }
    if (mr.replies.size () != 1)
    {
        err = "一问一答接口收到 " + std::to_string (mr.replies.size ()) + " 条应答";
        return false;
    }
    resp = mr.replies.front ().uds;
    return true;
}

// ---------------------------------------------------------------------------
// M8：功能寻址（一条广播 → 多条应答）
//
// 五步，顺序不能乱：
//   ① 查功能表：TA 不在功能段 → 0x03（地址问题，不是传输问题）
//   ② 广播要**独占所有通道**：一次广播发上总线，其它通道此刻不能有半截多帧在飞
//   ③ **先给每条通道清仓**（上一条请求留下的尾巴会被当成这次的应答）
//   ④ 广播**只发一次**（借第一条通道的 socket 发——发帧不看 bind 的 rx 过滤）
//   ⑤ 挨条通道收，可能一条都没有：那是"听着但不应答" → 0x06，不是 0x03
// ---------------------------------------------------------------------------
DiagnosticMultiResult DiagnosticGateway::broadcast (const DiagnosticRequest &req)
{
    // 同步入口（M8 的 operator() 走这里）：jobId=0 → 不流式，行为和 M11 之前一样。
    return broadcastJob (0, req);
}

// M12：给一次广播一个 jobId，边收边交给 replySink。
// 和 broadcast(req) 的唯一差别就是"答案在路上就交出去"，
// 收锁的顺序、独占所有通道、失败语义，全都照旧。
DiagnosticMultiResult DiagnosticGateway::broadcastJob (std::uint64_t jobId, const DiagnosticRequest &req)
{
    std::lock_guard<std::mutex> one (funcMu_);          // 同一时刻只允许一次广播
    std::vector<std::unique_lock<std::mutex>> locks;
    lockAllBuses (locks);
    return broadcastLocked (jobId, req);
}

DiagnosticMultiResult DiagnosticGateway::broadcastLocked (std::uint64_t jobId, const DiagnosticRequest &req)
{
    DiagnosticMultiResult out;

    const FunctionalRoute *fr = table_.lookupFunctional (req.targetAddress);
    if (fr == nullptr)
    {
        ++unknown_;
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress);
        out.reason   = "功能地址 " + hexTa (req.targetAddress) + " 不在功能路由表里";
        return out;
    }

    if (chans_.empty ())
    {
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::TargetUnreachable);
        out.reason   = "网关没有打开任何物理通道，广播无处可去";
        return out;
    }

    if (req.uds.empty () || req.uds.size () > 7)
    {
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::MessageTooLarge);
        out.reason   = "功能寻址的请求必须是单帧（1–7 字节），现在是 " +
                       std::to_string (req.uds.size ()) + " 字节";
        return out;
    }

    for (auto &kv : chans_)
    {
        if (kv.second) kv.second->client.discardPending ();
    }

    auto first = chans_.begin ()->second.get ();
    std::string err;
    if (!first->client.sendFunctional (fr->txId, req.uds, err))
    {
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
        out.reason   = "广播发不出去：" + err;
        return out;
    }
    ++funcReq_;

    for (auto &kv : chans_)
    {
        if (!kv.second) continue;
        std::vector<std::uint8_t> r;
        std::string e2;
        if (kv.second->client.recvFunctional (r, static_cast<int> (tim_.funcWindowMs), e2))
        {
            DiagnosticReply rep;
            rep.sourceAddress = kv.first;
            rep.uds           = r;
            out.replies.push_back (rep);
            ++kv.second->handled;
            ++funcRep_;

            // ★ M12：这条答案不等其他通道了，立刻交出去。
            //   注意此刻**所有 busMu 都在本线程手里**，而且 out 还没返回，
            //   所以 sink 只许"塞进队列"——它要是去写 socket，整轮广播就被诊断仪拖住。
            if (replySink_ && jobId != 0)
            {
                replySink_ (jobId, rep);
                ++streamed_;
            }
        }
        else
        {
            ++kv.second->failed;
        }
    }

    if (out.replies.empty ())
    {
        ++silent_;
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::TargetUnreachable);
        out.reason   = "广播出去了，但没有一台 ECU 应答（可能不支持该服务，或响应超过单帧）";
        return out;
    }

    ++handled_;
    out.ok = true;
    return out;
}

std::vector<DiagnosticGateway::ChannelStats> DiagnosticGateway::channelStats () const
{
    std::vector<ChannelStats> out;
    for (const auto &e : table_.entries ())
    {
        ChannelStats cs;
        cs.ta   = e.logicalAddress;
        cs.txId = e.txId;
        cs.rxId = e.rxId;
        cs.fd   = e.fd;
        auto it = chans_.find (e.logicalAddress);
        if (it != chans_.end () && it->second)
        {
            cs.open           = it->second->client.isOpen ();
            cs.handled        = it->second->handled.load ();
            cs.failed         = it->second->failed.load ();
            cs.queuePeak      = it->second->queue.peak ();
            cs.maxQueueWaitMs = it->second->maxQueueWaitMs.load ();
            cs.rejected       = it->second->queue.rejected ();
            cs.stats          = it->second->client.stats ();
        }
        out.push_back (cs);
    }
    return out;
}

} // namespace doip
