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

        auto ch = std::unique_ptr<Channel> (new Channel (iface_, cfg, tim_));
        std::string e2;
        if (!ch->client.open (e2))
        {
            // 哪一条开不起来就说清是哪一条：多通道配置错的时候，"有一个失败"没法排查
            err = "路由 " + (e.name.empty () ? std::string ("?") : e.name) +
                  "（TA=" + hexTa (e.logicalAddress) + "，" +
                  formatCanId (e.txId) + "/" + formatCanId (e.rxId) +
                  "）开不起来：" + e2;
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

std::vector<DiagnosticGateway::ChannelStats> DiagnosticGateway::channelStats () const
{
    std::vector<ChannelStats> out;
    for (const auto &e : table_.entries ())
    {
        ChannelStats cs;
        cs.ta   = e.logicalAddress;
        cs.txId = e.txId;
        cs.rxId = e.rxId;
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
