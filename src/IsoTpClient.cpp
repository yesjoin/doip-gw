// ============================================================================
// 一次 request 的完整节奏（按时间顺序，任何一步少"等"都会出问题）：
//
//   SF  →  直接发一帧                           → 等响应
//   FF  →  发首帧 → **停住等流控** → 按 BS/STmin 发 CF → 等响应
//   响应 →  SF 收下  /  FF 先回流控帧 再逐张收 CF
// ============================================================================
#include "IsoTpClient.h"
#include "CanId.h"

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

    // M7：先把 ID 合法性和宽度查清，别等发帧时让内核回一句 EINVAL
    if (!isValidCanId (cfg_.txId) || !isValidCanId (cfg_.rxId))
    {
        err = "CAN ID 不合法（" + formatCanId (cfg_.txId) + " / " + formatCanId (cfg_.rxId) +
              "），29 位上限 0x1FFFFFFF";
        return false;
    }

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

    // ★ M9：要用 CAN FD，必须先给 socket 打开这个开关。
    //   不开的后果很隐蔽：FD 帧会被内核当成噪声直接丢掉（收不到），
    //   而写 FD 帧会回 EINVAL —— 现象又是"全都超时"。
    //   ⚠ 别用 #if defined (CAN_RAW_FD_FRAMES)：它在 linux/can/raw.h 里是**枚举成员**，
    //     defined() 只认 #define，这样写整段会被静默编译掉，setsockopt 从来没执行过——
    //     这正是 M9 第一次跑 e2e 时的真 bug，症状与"忘了开开关"一模一样。
    if (cfg_.frameBytes > kClassicFrameBytes)
    {
        const int on = 1;
        if (::setsockopt (fd_, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &on, sizeof (on)) < 0)
        {
            err = "这个网卡不支持 CAN FD（setsockopt CAN_RAW_FD_FRAMES 失败）";
            close ();
            return false;
        }
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

bool IsoTpClient::sendFrame (const std::uint8_t data[64], std::string &err)
{
    return sendFrameAs (cfg_.txId, data, err);
}

// M8 顺手抽出来的：同一套"置位 + 写 socket"，但 ID 由调用方给。
// 功能寻址要往 0x7DF 发，而 0x7DF 不是任何一条通道的 txId——只是"同一把 socket 换个目的 ID"。
bool IsoTpClient::sendFrameAs (std::uint32_t id, const std::uint8_t data[64], std::string &err)
{
#if HAVE_SOCKETCAN
    // ★ M9：FD 帧和经典帧是**两个不同的结构体**，长度也不一样（72 vs 16 字节）。
    //   写错结构体的报错是 EINVAL，现象还是"全超时"——所以这里按配置分两条路，不搞"兼容写"。
    if (cfg_.frameBytes > kClassicFrameBytes)
    {
        canfd_frame f;
        std::memset (&f, 0, sizeof (f));
        f.can_id = idForSend (id);
        f.len    = static_cast<std::uint8_t> (cfg_.frameBytes);
        std::memcpy (f.data, data, cfg_.frameBytes);
        if (::write (fd_, &f, sizeof (f)) != static_cast<ssize_t> (sizeof (f)))
        {
            err = "写 CAN FD 帧失败（" + formatCanId (id) + "，FD 帧长 " +
                  std::to_string (cfg_.frameBytes) + "）";
            return false;
        }
        ++st_.framesSent;
        return true;
    }

    can_frame f;
    std::memset (&f, 0, sizeof (f));
    // ★ M7：29 位 ID 必须置 CAN_EFF_FLAG，否则内核回 EINVAL，帧根本发不出去。
    //   现场表现为"启动正常、每条请求都超时"，而 candump 上一条帧都没有。
    //   标准帧则不能带这个位（内核会认为你在用 29 位帧发一个 11 位的 ID）。
    f.can_id  = idForSend (id);
    f.can_dlc = 8;
    std::memcpy (f.data, data, 8);
    if (::write (fd_, &f, sizeof (f)) != static_cast<ssize_t> (sizeof (f)))
    {
        err = "写 CAN 帧失败（" + formatCanId (id) +
              (isExtendedId (id) ? "，扩展帧" : "，标准帧") + "）";
        return false;
    }
    ++st_.framesSent;
    return true;
#else
    (void) id; (void) data; err = "没有 SocketCAN"; return false;
#endif
}

bool IsoTpClient::recvFrame (std::uint8_t data[64], std::size_t &len, int timeoutMs, std::string &err)
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

        // ★ M9：用 canfd_frame 读，能同时接住两种帧。
        //   FD socket 上经典帧只会读回 16 字节，FD 帧读回 72 字节；
        //   而且两种结构体的前 8 字节布局一致（can_id / 长度 / flags / ...），
        //   所以"长度"读同一个位置就行（can_dlc 与 len 都落在第 5 个字节）。
        canfd_frame f;
        std::memset (&f, 0, sizeof (f));
        const ssize_t n = ::read (fd_, &f, sizeof (f));
        if (n != static_cast<ssize_t> (sizeof (can_frame)) &&
            n != static_cast<ssize_t> (sizeof (canfd_frame))) continue;

        // 只看 "ECU → tester" 这个 ID 的帧；总线是共享介质，别把别人的帧当自己的。
        // 注意用 idFromRecv 剥掉标志位：内核回的 can_id 对扩展帧带着 CAN_EFF_FLAG，
        // 直接拿它和 0x18DAF100 比会永远不相等（少一步掩码，现象就是"全超时"）。
        const std::uint32_t id = idFromRecv (f.can_id);
        if (id != cfg_.rxId) continue;

        // ★ DLC 不一定是满帧，FD 也不是。项目一的 ECU 单帧就不补零（7E8#027E00 只有 3 字节），
        //   早期版本这里写 `if (can_dlc < 8) continue;`，结果所有短响应被当成噪声扔掉，
        //   现象是"3E 00 永远超时，而 22 F1 90 正常"（因为多帧响应的帧恰好都是 8 字节）。
        len = f.len;
        if (len == 0 || len > cfg_.frameBytes || len > kFdFrameBytes) continue;

        std::memcpy (data, f.data, len);
        for (std::size_t i = len; i < kFdFrameBytes; ++i) data[i] = 0;
        ++st_.framesRecv;
        return true;
    }
#else
    (void) data; (void) len; (void) timeoutMs; err = "没有 SocketCAN"; return false;
#endif
}

// ---------------------------------------------------------------------------
// 清掉"迟到帧"
//
// 为什么必须有这个：M4 的时候网关总是第一个用总线的人，一个请求接一个请求，
// 中间没有别人插话。但 M5 接上第三方客户端、或者总线上还跑着项目一的 tester 时，
// 我们的 socket 里会躺着**上一轮/别人家的 7E8 帧**：
//
//   tester 单聊 ECU 时 ECU 回了 20 字节 VIN（FF + 2 个 CF），
//   这些帧我们的 socket 也收到了（总线是共享的），只是没人读，就堆在缓冲区里。
//
// 下一次 request() 发完首帧去等流控，第一帧读出来的却是那堆旧 CF
// → "首帧之后收到的不是流控帧" → 整条请求失败。
// 现象很像"网关偶发超时"，实际是**没清仓**。
//
// 所以每次发请求前先把缓冲区读空（0 超时，读一条算一条），并记账 staleSkipped。
// ---------------------------------------------------------------------------
std::size_t IsoTpClient::drainStale ()
{
    std::size_t n = 0;
    while (true)
    {
        std::uint8_t d[kFdFrameBytes];
        std::size_t  dlc = 0;
        std::string  e;
        if (!recvFrame (d, dlc, 0, e)) break;
        ++n;
        ++st_.staleSkipped;
    }
    return n;
}

bool IsoTpClient::waitFlowControl (FlowControl &fc, std::string &err)
{
    // 等 FC 时也可能先撞上迟到帧/噪声帧：跳过，但整体不超过 p2 的预算。
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (tim_.p2Ms);
    while (true)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) { ++st_.timeouts; err = "等流控超时"; return false; }
        const int left = static_cast<int> (
            std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count ());

        std::uint8_t d[kFdFrameBytes];
        std::size_t  dlc = 0;
        if (!recvFrame (d, dlc, left <= 0 ? 1 : left, err)) { ++st_.timeouts; return false; }
        if (kindOf (d) != FrameKind::FlowControl)
        {
            ++st_.staleSkipped;    // 不是 FC：当迟到帧丢掉，接着等
            continue;
        }
        ++st_.flowRecv;
        return parseFlowControl (d, fc, err);
    }
}

// ---------------------------------------------------------------------------
// M8：功能寻址（广播）
//
// 三个"为什么"：
//   ① 为什么必须是单帧（≤7 字节）：7DF 上所有 ECU 都在听，网关没法跟"所有的 ECU"
//      要流控——流控帧总得有个收件人。所以功能请求只允许 SF，超过就是配置/用法错了。
//   ② 为什么响应也必须是单帧：同理，ECU 发 FF 之后等不到一个唯一的流控方向，
//      多帧响应在功能寻址上是不成立的（真 ECU 也不会这么干）。
//   ③ 为什么"发"和"收"要拆开：广播只该在总线上出现一次。拆开之后网关发一次、
//      再挨条通道去收，账才对得上（1 条广播 → N 条应答）。
// ---------------------------------------------------------------------------
bool IsoTpClient::sendFunctional (std::uint32_t funcId,
                                  const std::vector<std::uint8_t> &uds,
                                  std::string &err)
{
    if (uds.empty ())
    {
        err = "功能寻址的空请求没有意义";
        return false;
    }
    // 单帧的 PCI 高 4 位是 0，低 4 位是长度，所以最多 7 字节：8 - 1 = 7
    if (uds.size () > 7)
    {
        err = "功能寻址的请求必须是单帧（最多 7 字节），现在 " +
              std::to_string (uds.size ()) + " 字节";
        return false;
    }
    if (!isValidCanId (funcId))
    {
        err = "广播 ID 不合法（" + formatCanId (funcId) + "）";
        return false;
    }

    std::uint8_t d[kFdFrameBytes] = {0};
    d[0] = static_cast<std::uint8_t> (uds.size ());          // SF 的 PCI
    std::memcpy (d + 1, uds.data (), uds.size ());
    for (std::size_t i = uds.size () + 1; i < cfg_.frameBytes; ++i) d[i] = cfg_.padByte;

    ++st_.funcRequests;
    return sendFrameAs (funcId, d, err);
}

bool IsoTpClient::recvFunctional (std::vector<std::uint8_t> &resp, int timeoutMs, std::string &err)
{
    resp.clear ();

    std::uint8_t d[kFdFrameBytes];
    std::size_t  dlc = 0;
    if (!recvFrame (d, dlc, timeoutMs, err)) return false;

    const auto k = kindOf (d);
    if (k != FrameKind::SingleFrame)
    {
        // 首帧/连续帧/流控：在广播场景下都没法处理（见函数头 ②）。
        // 不装作收到了，也不假装没看见——记一笔，然后告诉调用方"这次没收到可用响应"。
        ++st_.funcMultiSkip;
        err = std::string ("功能寻址收到 ") +
              (k == FrameKind::FirstFrame ? "首帧" :
               k == FrameKind::ConsecutiveFrame ? "连续帧" : "流控帧") +
              "（多帧响应在功能寻址上无法定向，跳过）";
        return false;
    }

    IsoTpAssembler asm_ (cfg_.maxMsg, cfg_.frameBytes);
    const auto r = asm_.onFrame (d, resp, err, dlc);
    if (r != IsoTpAssembler::Result::Complete)
    {
        err = "功能寻址的响应解不开";
        return false;
    }
    ++st_.funcResponses;
    return true;
}

bool IsoTpClient::request (const std::vector<std::uint8_t> &uds,
                           std::vector<std::uint8_t> &resp,
                           std::string &err)
{
    ++st_.requests;
    resp.clear ();

    // 发之前先清仓：共享总线上，缓冲区里可能躺着上一轮/别人家的旧帧
    drainStale ();

    std::vector<std::vector<std::uint8_t>> frames;
    if (!segmentMessage (uds, frames, err, cfg_.padByte, cfg_.frameBytes)) return false;

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
    IsoTpAssembler asm_ (cfg_.maxMsg, cfg_.frameBytes);
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (tim_.p2Ms * 2);
    while (std::chrono::steady_clock::now () < deadline)
    {
        std::uint8_t d[kFdFrameBytes];
        std::size_t  dlc = 0;
        if (!recvFrame (d, dlc, static_cast<int> (tim_.p2Ms), err)) { ++st_.timeouts; return false; }

        if (kindOf (d) == FrameKind::FlowControl)
        {
            // 我们没发 FF 却收到 FC：是上一轮的残留或别人家的，跳过
            ++st_.flowRecv;
            continue;
        }

        // 没在等 FF 的时候收到连续帧 → 同样是迟到帧（上一条响应的尾巴），丢掉
        if (kindOf (d) == FrameKind::ConsecutiveFrame && !asm_.receiving ())
        {
            ++st_.staleSkipped;
            continue;
        }

        const auto r = asm_.onFrame (d, resp, err, dlc);
        if (r == IsoTpAssembler::Result::Complete) return true;
        if (r == IsoTpAssembler::Result::Error) { ++st_.seqErrors; return false; }

        // 响应是 FF：必须回流控帧，否则 ECU 会一直停在那里
        if (kindOf (d) == FrameKind::FirstFrame)
        {
            std::uint8_t fcData[kFdFrameBytes];
            buildFlowControl (0, 0, cfg_.padByte, fcData, cfg_.frameBytes);
            if (!sendFrame (fcData, err)) return false;
            ++st_.flowSent;
        }
    }

    err = "等响应超时";
    ++st_.timeouts;
    return false;
}

} // namespace doip
