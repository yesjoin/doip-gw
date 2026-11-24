// ============================================================================
// DoIpGateway.cpp —— M6：查表 → 串行化 → 走那条通道
// ============================================================================
#include "DoIpGateway.h"

#include <chrono>
#include <cstdio>

namespace doip
{

namespace
{
std::string hexTa (std::uint16_t v)
{
    char b[8];
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

bool DiagnosticGateway::start (std::string &err)
{
    for (const auto &e : table_.entries ())
    {
        IsoTpConfig cfg;
        cfg.txId = e.txId;
        cfg.rxId = e.rxId;
        // M9：这一条通道是按 FD 开还是按经典帧开，由路由表条目决定
        cfg.frameBytes = e.fd ? kFdFrameBytes : kClassicFrameBytes;

        auto ch = std::unique_ptr<Channel> (new Channel (iface_, cfg, tim_));
        std::string e2;
        if (!ch->client.open (e2))
        {
            // 哪一条开不起来就说清是哪一条：多通道配置错的时候，"有一个失败"没法排查
            err = "路由 " + (e.name.empty () ? std::string ("?") : e.name) +
                  "（TA=" + hexTa (e.logicalAddress) + "，" +
                  formatCanId (e.txId) + "/" + formatCanId (e.rxId) +
                  (e.fd ? "，FD" : "，经典帧") + "）开不起来：" + e2;
            return false;
        }
        chans_[e.logicalAddress] = std::move (ch);
    }
    return true;
}

void DiagnosticGateway::stop ()
{
    for (auto &kv : chans_)
    {
        if (kv.second) kv.second->client.close ();
    }
    chans_.clear ();
}

bool DiagnosticGateway::operator() (const DiagnosticRequest &req,
                                    std::vector<std::uint8_t> &resp,
                                    std::string &err)
{
    resp.clear ();

    // ---- 查表。查不到就到此为止：宁可回 0x03，也不许猜一台 ECU ----
    const RouteEntry *route = table_.lookup (req.targetAddress);
    if (route == nullptr)
    {
        ++unknown_;
        ++failed_;
        char buf[96];
        std::snprintf (buf, sizeof (buf), "目标地址 0x%04X 不在路由表里",
                       static_cast<unsigned> (req.targetAddress));
        err = buf;
        return false;
    }

    auto it = chans_.find (req.targetAddress);
    if (it == chans_.end () || !it->second)
    {
        ++failed_;
        err = "这条路由的通道没有打开";
        return false;
    }

    const auto t0 = std::chrono::steady_clock::now ();

    // 锁的作用不是"线程安全"，是**语义**：
    // 同一时刻只允许一条诊断在 CAN 上走，否则响应分不清是谁的。
    std::lock_guard<std::mutex> lock (mu_);

    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds> (
        std::chrono::steady_clock::now () - t0).count ();
    if (static_cast<std::size_t> (waited) > maxWaitMs_)
    {
        maxWaitMs_ = static_cast<std::size_t> (waited);
    }

    const bool ok = it->second->client.request (req.uds, resp, err);
    if (ok)
    {
        ++handled_;
        ++it->second->handled;
    }
    else
    {
        ++failed_;
        ++it->second->failed;
    }
    return ok;
}

// ---------------------------------------------------------------------------
// M8：功能寻址（一条广播 → 多条应答）
//
// 四步，顺序不能乱：
//   ① 查功能表：TA 不在功能段 → 0x03（地址问题，不是传输问题）
//   ② **先给每条通道清仓**。上一条请求留下的多帧尾巴如果还在缓冲区里，
//      会被当成"这次的应答"，现象是"回了个 VIN 给只问了 3E 00 的诊断仪"。
//   ③ 广播**只发一次**（借第一条通道的 socket 发——发帧不看 bind 的 rx 过滤）
//   ④ 挨条通道收，可能一条都没有：那说明"听着但不应答"（比如这台 ECU 不支持该服务）。
//      这时候回 0x06（目标存在但不可达），不是 0x03（地址不认识）——两者错因完全不同。
// ---------------------------------------------------------------------------
DiagnosticMultiResult DiagnosticGateway::broadcast (const DiagnosticRequest &req)
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

    // 功能请求必须是单帧（ISO-TP 的 SF 只有 7 字节）：这一点在发之前就要拦，
    // 因为"超过 7 字节的广播"根本不是配置问题，是**协议上做不到**（没有收件人给流控）。
    if (req.uds.empty () || req.uds.size () > 7)
    {
        ++failed_;
        out.nackCode = static_cast<std::uint8_t> (DiagNack::MessageTooLarge);
        out.reason   = "功能寻址的请求必须是单帧（1–7 字节），现在是 " +
                       std::to_string (req.uds.size ()) + " 字节";
        return out;
    }

    const auto t0 = std::chrono::steady_clock::now ();
    std::lock_guard<std::mutex> lock (mu_);

    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds> (
        std::chrono::steady_clock::now () - t0).count ();
    if (static_cast<std::size_t> (waited) > maxWaitMs_)
    {
        maxWaitMs_ = static_cast<std::size_t> (waited);
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
            rep.sourceAddress = kv.first;      // 这条应答是这台 ECU 说的
            rep.uds           = r;
            out.replies.push_back (rep);
            ++kv.second->handled;
            ++funcRep_;
        }
        else
        {
            // 没答也算"这条通道没参与"，不按失败记——功能请求本来就是"在的人答"。
            // 但要留个痕：日志里能看出是哪条通道沉默的（e2 里写着超时/多帧跳过）
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

std::vector<DiagnosticGateway::ChannelStats> DiagnosticGateway::channelStats () const{
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
            cs.open    = it->second->client.isOpen ();
            cs.handled = it->second->handled;
            cs.failed  = it->second->failed;
            cs.stats   = it->second->client.stats ();
        }
        out.push_back (cs);
    }
    return out;
}

} // namespace doip
