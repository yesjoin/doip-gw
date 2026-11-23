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

    struct Stats
    {
        std::uint64_t requests      = 0;
        std::uint64_t framesSent    = 0;
        std::uint64_t framesRecv    = 0;
        std::uint64_t flowRecv      = 0;
        std::uint64_t flowSent      = 0;
        std::uint64_t timeouts      = 0;
        std::uint64_t seqErrors     = 0;
    };
    const Stats &stats () const { return st_; }

private:
    bool sendFrame (const std::uint8_t data[8], std::string &err);
    bool recvFrame (std::uint8_t data[8], std::uint8_t &dlc, int timeoutMs, std::string &err);
    bool waitFlowControl (FlowControl &fc, std::string &err);
    static std::uint32_t stminToMs (std::uint8_t stmin);

    std::string  iface_;
    IsoTpConfig  cfg_;
    IsoTpTiming  tim_;
    int          fd_ = -1;
    Stats        st_;
};

} // namespace doip
