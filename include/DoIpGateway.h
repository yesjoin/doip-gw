#pragma once
// ============================================================================
// DoIpGateway.h —— M4：把 DoIP 诊断报文接到一条真 CAN 通道上
//
// 它是 M3 里 `diagnosticSink` 的一个实现：
//   收到 0x8001 的 UDS 字节 → ISO-TP 真发上 vcan0 → 收回响应 → 交回服务器
//
// 并发这里只有一句话，但很重要：
//   **CAN 是共享介质。** 两个 tester 同时发诊断，如果各开一条通道、各等各的响应，
//   双方都会看到对方 ECU 的帧，然后各自把"别人的响应"当成自己的答案。
//   所以这里用一把锁把请求串行化 —— 排队几毫秒，换来"永不串包"。
//   （验收硬指标第 4 条"两客户端并发不串包"就是这条。）
// ============================================================================
#include "DoIpDiagnostic.h"
#include "IsoTpClient.h"

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

namespace doip
{

class DiagnosticGateway
{
public:
    DiagnosticGateway (const std::string &iface,
                       const IsoTpConfig &cfg = IsoTpConfig{},
                       const IsoTpTiming &tim = IsoTpTiming{});

    bool start (std::string &err);
    void stop ();

    // 直接当 DiagnosticSink 用
    bool operator() (const DiagnosticRequest &req,
                     std::vector<std::uint8_t> &resp,
                     std::string &err);

    std::size_t handled ()  const { return handled_; }
    std::size_t failed ()   const { return failed_; }
    std::size_t maxWaitMs () const { return maxWaitMs_; }
    const IsoTpClient::Stats &stats () const { return client_.stats (); }
    bool open () const { return client_.isOpen (); }

private:
    IsoTpClient client_;
    std::mutex  mu_;                 // 串行化：一把锁换"不串包"
    std::size_t handled_  = 0;
    std::size_t failed_   = 0;
    std::size_t maxWaitMs_ = 0;
};

} // namespace doip
