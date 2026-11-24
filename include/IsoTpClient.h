#pragma once
// ============================================================================
// IsoTpClient.h —— M4：tester 侧的 ISO-TP 客户端（真 socket，SocketCAN）
//
// 和 IsoTpStack 的分工：
//   IsoTpStack   ：拆帧/重组，纯逻辑，可以在内存里测
//   IsoTpClient  ：把帧写到 vcan0、按 STmin 等、收流控、收响应
//
// 这一段最容易写错的地方不是协议，而是**"等"**：
//   发完首帧必须停住等流控；流控 FS=Wait 要再等；每个 CF 之间要隔 STmin。
//   少一个"等"，在本机上看着也对，一上真总线就成片丢帧。
// ============================================================================
#include "IsoTpStack.h"

#include <cstdint>
#include <string>
#include <vector>

namespace doip
{

struct IsoTpTiming
{
    std::uint32_t p2Ms         = 1000;   // 等流控 / 等响应的单步超时
    std::uint32_t stminDefault = 10;     // 对方没明确给时，我们按 10ms 发
    std::uint32_t funcWindowMs = 150;    // M8：功能寻址广播后，每条通道留给它回话的窗口
};

class IsoTpClient
{
public:
    IsoTpClient (const std::string &iface,
                 const IsoTpConfig &cfg  = IsoTpConfig{},
                 const IsoTpTiming &tim  = IsoTpTiming{});
    ~IsoTpClient ();

    IsoTpClient (const IsoTpClient &)            = delete;
    IsoTpClient &operator= (const IsoTpClient &) = delete;

    bool open (std::string &err);
    void close ();
    bool isOpen () const { return fd_ >= 0; }

    // 发一条 UDS 请求，收回一条 UDS 响应。单帧/多帧都走这里。
    bool request (const std::vector<std::uint8_t> &uds,
                  std::vector<std::uint8_t> &resp,
                  std::string &err);

    // ---- M8：功能寻址的两个动作，故意拆开 ----
    // 为什么拆开：广播只该发**一次**。如果每台 ECU 都调一次"发+收"，
    // 总线上就会出现 N 条一样的广播帧，ECU 会答 N 遍。所以"发"和"收"必须分开，
    // 由网关统一发一次，再挨条通道问"你收到回话了吗"。
    bool sendFunctional (std::uint32_t funcId,
                         const std::vector<std::uint8_t> &uds,
                         std::string &err);

    // 收本通道自己那台 ECU 对广播的应答（只认 cfg_.rxId）。
    // 功能寻址下响应必须是单帧：多帧需要网关回流控，而广播的流控"发给谁"说不清。
    bool recvFunctional (std::vector<std::uint8_t> &resp, int timeoutMs, std::string &err);

    // 把缓冲区里躺着的旧帧清掉（功能寻址前必须先做，否则会把上一条多帧的尾巴当本次响应）
    void discardPending () { drainStale (); }

    struct Stats
    {
        std::uint64_t requests      = 0;
        std::uint64_t framesSent    = 0;
        std::uint64_t framesRecv    = 0;
        std::uint64_t flowRecv      = 0;
        std::uint64_t flowSent      = 0;
        std::uint64_t timeouts      = 0;
        std::uint64_t seqErrors     = 0;
        std::uint64_t staleSkipped  = 0;   // 上一条事务的迟到帧 / 别的 tester 的帧，丢了多少
        std::uint64_t funcRequests  = 0;   // M8：发出去的广播条数
        std::uint64_t funcResponses = 0;   // M8：本通道收到的广播应答条数
        std::uint64_t funcMultiSkip = 0;   // M8：功能寻址上收到多帧响应、只能跳过的次数
    };
    const Stats &stats () const { return st_; }

private:
    bool sendFrame (const std::uint8_t data[64], std::string &err);
    bool sendFrameAs (std::uint32_t id, const std::uint8_t data[64], std::string &err);
    bool recvFrame (std::uint8_t data[64], std::size_t &len, int timeoutMs, std::string &err);
    bool waitFlowControl (FlowControl &fc, std::string &err);
    // 把缓冲区里已经躺着的旧帧先清掉（见 .cpp 里的说明：共享总线上这是必需的）
    std::size_t drainStale ();
    static std::uint32_t stminToMs (std::uint8_t stmin);

    std::string  iface_;
    IsoTpConfig  cfg_;
    IsoTpTiming  tim_;
    int          fd_ = -1;
    Stats        st_;
};

} // namespace doip
