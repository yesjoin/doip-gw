// ============================================================================
// DoIpGateway.cpp —— M4 的"中间那根线"
// ============================================================================
#include "DoIpGateway.h"

namespace doip
{

DiagnosticGateway::DiagnosticGateway (const std::string &iface,
                                     const IsoTpConfig &cfg,
                                     const IsoTpTiming &tim)
    : client_ (iface, cfg, tim)
{
}

bool DiagnosticGateway::start (std::string &err)
{
    return client_.open (err);
}

void DiagnosticGateway::stop ()
{
    client_.close ();
}

bool DiagnosticGateway::operator() (const DiagnosticRequest &req,
                                    std::vector<std::uint8_t> &resp,
                                    std::string &err)
{
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

    resp.clear ();
    const bool ok = client_.request (req.uds, resp, err);
    if (ok) ++handled_;
    else    ++failed_;
    return ok;
}

} // namespace doip
