// ============================================================================
// IsoTpClient.cpp —— M4：真 SocketCAN 上的 ISO-TP 客户端
//
// 一次 request 的完整节奏（按时间顺序，任何一步少"等"都会出问题）：
//
//   SF  →  直接发一帧                           → 等响应
//   FF  →  发首帧 → **停住等流控** → 按 BS/STmin 发 CF → 等响应
//   响应 →  SF 收下  /  FF 先回流控帧 再逐张收 CF
// ============================================================================
#include "IsoTpClient.h"

#if defined (__linux__)
#    define HAVE_SOCKETCAN 1
#    include <linux/can.h>
#    include <linux/can/raw.h>
#    include <net/if.h>
#    include <poll.h>
#    include <sys/ioctl.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define HAVE_SOCKETCAN 0
#endif

#include <chrono>
#include <cstring>
#include <thread>

namespace doip
{

IsoTpClient::IsoTpClient (const std::string &iface, const IsoTpConfig &cfg, const IsoTpTiming &tim)
    : iface_ (iface), cfg_ (cfg), tim_ (tim)
{
}

IsoTpClient::~IsoTpClient ()
{
    close ();
}

bool IsoTpClient::open (std::string &err)
{
#if HAVE_SOCKETCAN
    close ();

    fd_ = ::socket (PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0)
    {
        err = "打不开 CAN socket（需要 root 或 CAP_NET_RAW）";
        return false;
    }

    ifreq ifr;
    std::memset (&ifr, 0, sizeof (ifr));
    std::snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", iface_.c_str ());
    if (::ioctl (fd_, SIOCGIFINDEX, &ifr) < 0)
    {
        err = "找不到接口 " + iface_ + "（vcan0 起来了吗？）";
        close ();
        return false;
    }

    sockaddr_can addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind (fd_, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        err = "bind 到 " + iface_ + " 失败";
        close ();
        return false;
    }
    return true;
#else
    err = "本平台没有 SocketCAN（M4 只在 Linux 上跑）";
    return false;
#endif
}

void IsoTpClient::close ()
{
#if HAVE_SOCKETCAN
    if (fd_ >= 0) ::close (fd_);
#endif
    fd_ = -1;
}

std::uint32_t IsoTpClient::stminToMs (std::uint8_t stmin)
{
    if (stmin <= 0x7F) return stmin;                  // 毫秒
    if (stmin >= 0xF1 && stmin <= 0xF9)
        return 1;                                     // 100..900 微秒，按 1ms 兜底
    return 1;                                         // 0x80..0xF0 保留，按 1ms
}

bool IsoTpClient::sendFrame (const std::uint8_t data[8], std::string &err)
{
#if HAVE_SOCKETCAN
    can_frame f;
    std::memset (&f, 0, sizeof (f));
    f.can_id  = cfg_.txId;
    f.can_dlc = 8;
    std::memcpy (f.data, data, 8);
    if (::write (fd_, &f, sizeof (f)) != static_cast<ssize_t> (sizeof (f)))
    {
        err = "写 CAN 帧失败";
        return false;
    }
    ++st_.framesSent;
    return true;
#else
    (void) data; err = "没有 SocketCAN"; return false;
#endif
}

bool IsoTpClient::recvFrame (std::uint8_t data[8], std::uint8_t &dlc, int timeoutMs, std::string &err)
{
#if HAVE_SOCKETCAN
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (timeoutMs);
    while (true)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) { err = "接收超时"; return false; }
        const int left = static_cast<int> (
            std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());

        pollfd p;
        p.fd      = fd_;
        p.events  = POLLIN;
        p.revents = 0;
        if (::poll (&p, 1, left <= 0 ? 1 : left) <= 0) { err = "接收超时"; return false; }

        can_frame f;
        std::memset (&f, 0, sizeof (f));
        const ssize_t n = ::read (fd_, &f, sizeof (f));
        if (n < static_cast<ssize_t> (sizeof (f))) continue;

        // 只看 "ECU → tester" 这个 ID 的帧；总线是共享介质，别把别人的帧当自己的
        const std::uint32_t id = f.can_id & CAN_EFF_MASK;
        if (id != cfg_.rxId) continue;

        // ★ DLC 不一定是 8。项目一的 ECU 单帧就不补零（7E8#027E00 只有 3 字节），
        //   早期版本这里写 `if (can_dlc < 8) continue;`，结果所有短响应被当成噪声扔掉，
        //   现象是"3E 00 永远超时，而 22 F1 90 正常"（因为多帧响应的帧恰好都是 8 字节）。
        if (f.can_dlc == 0 || f.can_dlc > 8) continue;

        std::memcpy (data, f.data, f.can_dlc);
        for (std::uint8_t i = f.can_dlc; i < 8; ++i) data[i] = 0;
        dlc = f.can_dlc;
        ++st_.framesRecv;
        return true;
    }
#else
    (void) data; (void) timeoutMs; err = "没有 SocketCAN"; return false;
#endif
}

bool IsoTpClient::waitFlowControl (FlowControl &fc, std::string &err)
{
    std::uint8_t d[8];
    std::uint8_t dlc = 0;
    if (!recvFrame (d, dlc, static_cast<int> (tim_.p2Ms), err)) { ++st_.timeouts; return false; }
    if (kindOf (d) != FrameKind::FlowControl)
    {
        err = "首帧之后收到的不是流控帧（协议要求先等 FC）";
        return false;
    }
    ++st_.flowRecv;
    return parseFlowControl (d, fc, err);
}

bool IsoTpClient::request (const std::vector<std::uint8_t> &uds,
                           std::vector<std::uint8_t> &resp,
                           std::string &err)
{
    ++st_.requests;
    resp.clear ();

    std::vector<std::vector<std::uint8_t>> frames;
    if (!segmentMessage (uds, frames, err, cfg_.padByte)) return false;

    // ---- 第一帧 ----
    if (!sendFrame (frames[0].data (), err)) return false;

    // ---- 多帧：等流控，再按 BS / STmin 发连续帧 ----
    if (frames.size () > 1)
    {
        FlowControl fc;
        if (!waitFlowControl (fc, err)) return false;
        if (fc.status == FlowStatus::Overflow) { err = "对端流控溢出（装不下）"; return false; }
        while (fc.status == FlowStatus::Wait)
        {
            if (!waitFlowControl (fc, err)) return false;
        }

        const std::uint32_t stmin = fc.stMin == 0 ? tim_.stminDefault : stminToMs (fc.stMin);
        std::size_t sinceFc = 0;
        for (std::size_t i = 1; i < frames.size (); ++i)
        {
            if (fc.blockSize != 0 && sinceFc >= fc.blockSize)
            {
                if (!waitFlowControl (fc, err)) return false;
                if (fc.status == FlowStatus::Overflow) { err = "对端流控溢出（装不下）"; return false; }
                sinceFc = 0;
            }
            if (stmin > 0) std::this_thread::sleep_for (std::chrono::milliseconds (stmin));
            if (!sendFrame (frames[i].data (), err)) return false;
            ++sinceFc;
        }
    }

    // ---- 收响应 ----
    IsoTpAssembler asm_ (cfg_.maxMsg);
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (tim_.p2Ms * 2);
    while (std::chrono::steady_clock::now () < deadline)
    {
        std::uint8_t d[8];
        std::uint8_t dlc = 0;
        if (!recvFrame (d, dlc, static_cast<int> (tim_.p2Ms), err)) { ++st_.timeouts; return false; }

        if (kindOf (d) == FrameKind::FlowControl)
        {
            // 我们没发 FF 却收到 FC：是上一轮的残留或别人家的，跳过
            ++st_.flowRecv;
            continue;
        }

        const auto r = asm_.onFrame (d, resp, err, dlc);
        if (r == IsoTpAssembler::Result::Complete) return true;
        if (r == IsoTpAssembler::Result::Error) { ++st_.seqErrors; return false; }

        // 响应是 FF：必须回流控帧，否则 ECU 会一直停在那里
        if (kindOf (d) == FrameKind::FirstFrame)
        {
            std::uint8_t fcData[8];
            buildFlowControl (0, 0, cfg_.padByte, fcData);
            if (!sendFrame (fcData, err)) return false;
            ++st_.flowSent;
        }
    }

    err = "等响应超时";
    ++st_.timeouts;
    return false;
}

} // namespace doip
