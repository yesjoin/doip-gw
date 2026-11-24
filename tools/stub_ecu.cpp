// ============================================================================
// stub_ecu.cpp —— M6 的第二台 ECU：一个"真的在总线上"的极简节点
//
// 为什么要它：路由表要证明"TA 不同 → 打到不同的 ECU"。只有一台 ECU 时，
// 无论路由把请求发到哪，读到的都是同一份数据，看不出对错。
//
// 它是**真节点**（真 SocketCAN、真 ISO-TP 收发、真多帧），只是 UDS 服务少：
//   3E 00      → 7E 00
//   22 F1 86   → 62 F1 86 01
//   22 F1 90   → 62 F1 90 + 自定义 VIN（17 字节，所以要走多帧）
//   22 F1 91   → 62 F1 91 + 自定义硬件版本
//   其它       → 7F <sid> 31
//
// 一个设计上的复用点：**拆帧/组帧用的是和网关同一个 IsoTpStack**。
//   ECU 侧和 tester 侧的差别只在"谁等谁"：ECU 收 FF 要回流控，发 FF 要等流控。
//   协议本身只有一个，方向不同而已 —— 这正好是 M4 那条"别照抄方向"的反面印证。
//
// 用法：
//   stub-ecu --iface vcan0 --rx 7A0 --tx 7A8 --vin LSVZZ0000B7654321 --hw HW02 --seconds 20
// ============================================================================
#include "IsoTpStack.h"

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace doip;

namespace
{

int openCan (const std::string &iface, std::string &err)
{
    const int fd = ::socket (PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd < 0) { err = "socket(PF_CAN) 失败"; return -1; }

    ifreq ifr;
    std::memset (&ifr, 0, sizeof (ifr));
    std::strncpy (ifr.ifr_name, iface.c_str (), IFNAMSIZ - 1);
    if (::ioctl (fd, SIOCGIFINDEX, &ifr) < 0)
    {
        err = "找不到网卡 " + iface;
        ::close (fd);
        return -1;
    }

    sockaddr_can addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind (fd, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        err = "bind 失败";
        ::close (fd);
        return -1;
    }
    return fd;
}

void sendFrame (int fd, std::uint32_t id, const std::uint8_t d[8])
{
    can_frame f;
    std::memset (&f, 0, sizeof (f));
    f.can_id  = id;
    f.can_dlc = 8;
    std::memcpy (f.data, d, 8);
    ::write (fd, &f, sizeof (f));
}

// 发一条 UDS：单帧一发；多帧先发 FF，等 tester 的流控，再按 STmin 发 CF
bool sendUds (int fd, std::uint32_t txId, std::uint32_t rxId,
              const std::vector<std::uint8_t> &uds, std::string &err)
{
    std::vector<std::vector<std::uint8_t>> frames;
    if (!segmentMessage (uds, frames, err, 0x00)) return false;

    sendFrame (fd, txId, frames[0].data ());
    if (frames.size () == 1) return true;

    // 等流控（tester 会回 0x30 xx xx）
    FlowControl fc;
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::milliseconds (300);
    while (true)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) { err = "等 tester 流控超时"; return false; }
        pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        if (::poll (&p, 1, 20) <= 0) continue;

        can_frame f;
        std::memset (&f, 0, sizeof (f));
        if (::read (fd, &f, sizeof (f)) < static_cast<ssize_t> (sizeof (f))) continue;
        if ((f.can_id & CAN_EFF_MASK) != rxId) continue;      // 不是给我的，丢掉
        std::uint8_t d[8];
        std::memcpy (d, f.data, 8);
        if (kindOf (d) != FrameKind::FlowControl) continue;
        if (!parseFlowControl (d, fc, err)) return false;
        break;
    }
    if (fc.status == FlowStatus::Overflow) { err = "tester 流控溢出"; return false; }

    const std::uint32_t stmin = fc.stMin == 0 ? 10u : (fc.stMin < 0x80 ? fc.stMin : 10u);
    for (std::size_t i = 1; i < frames.size (); ++i)
    {
        if (stmin > 0) ::usleep (stmin * 1000);
        sendFrame (fd, txId, frames[i].data ());
    }
    return true;
}

std::vector<std::uint8_t> answer (const std::vector<std::uint8_t> &uds,
                                  const std::string &vin, const std::string &hw)
{
    std::vector<std::uint8_t> r;
    if (uds.empty ()) return r;

    if (uds[0] == 0x3E)
    {
        r.push_back (0x7E);
        if (uds.size () > 1) r.push_back (uds[1]);   // 3E 80 要回 7E 80
        return r;
    }
    if (uds[0] == 0x22 && uds.size () >= 3)
    {
        const std::uint16_t did = static_cast<std::uint16_t> ((uds[1] << 8) | uds[2]);
        r = {0x62, uds[1], uds[2]};
        if (did == 0xF190)
            for (char c : vin) r.push_back (static_cast<std::uint8_t> (c));
        else if (did == 0xF191)
            for (char c : hw) r.push_back (static_cast<std::uint8_t> (c));
        else if (did == 0xF186)
            r.push_back (0x02);                       // 当前会话：编程会话（和项目一取不同值）
        else
            return {0x7F, 0x22, 0x31};                // requestOutOfRange
        return r;
    }
    r = {0x7F, uds[0], 0x31};
    return r;
}

std::string hex (const std::vector<std::uint8_t> &b)
{
    std::string s;
    char t[4];
    for (std::size_t i = 0; i < b.size (); ++i)
    {
        std::snprintf (t, sizeof (t), "%02X", b[i]);
        if (i) s += ' ';
        s += t;
    }
    return s;
}

} // namespace

int main (int argc, char **argv)
{
    std::string iface = "vcan0";
    std::uint32_t tx = 0x7A8;      // 我发的（ECU → tester）
    std::uint32_t rx = 0x7A0;      // 我收的（tester → ECU）
    std::string vin = "LSVZZ0000B7654321";
    std::string hw  = "HW02";
    int seconds = 20;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)       iface = argv[++i];
        else if (a == "--tx" && i + 1 < argc)     tx = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--rx" && i + 1 < argc)     rx = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--vin" && i + 1 < argc)    vin = argv[++i];
        else if (a == "--hw" && i + 1 < argc)     hw = argv[++i];
        else if (a == "--seconds" && i + 1 < argc) seconds = std::atoi (argv[++i]);
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--rx 7A0] [--tx 7A8] "
                          "[--vin LSVZZ0000B7654321] [--hw HW02] [--seconds 20]\n", argv[0]);
            return 2;
        }
    }
    if (vin.size () != 17)
    {
        std::fprintf (stderr, "VIN 必须是 17 个字符（现在是 %zu）\n", vin.size ());
        return 2;
    }

    std::string err;
    const int fd = openCan (iface, err);
    if (fd < 0)
    {
        std::fprintf (stderr, "起不来：%s\n", err.c_str ());
        return 1;
    }

    std::printf ("极简 ECU：%s 上收 %03X / 发 %03X，VIN=%s，HW=%s，跑 %d 秒\n",
                 iface.c_str (), static_cast<unsigned> (rx), static_cast<unsigned> (tx),
                 vin.c_str (), hw.c_str (), seconds);

    IsoTpAssembler asm_ (4095);
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::seconds (seconds);
    std::size_t answered = 0;

    while (std::chrono::steady_clock::now () < deadline)
    {
        pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        if (::poll (&p, 1, 50) <= 0) continue;

        can_frame f;
        std::memset (&f, 0, sizeof (f));
        if (::read (fd, &f, sizeof (f)) < static_cast<ssize_t> (sizeof (f))) continue;
        if ((f.can_id & CAN_EFF_MASK) != rx) continue;        // 不是给我的
        if (f.can_dlc == 0 || f.can_dlc > 8) continue;

        std::uint8_t d[8];
        std::memcpy (d, f.data, f.can_dlc);
        for (std::uint8_t i = f.can_dlc; i < 8; ++i) d[i] = 0;

        std::vector<std::uint8_t> req;
        std::string e2;
        const auto r = asm_.onFrame (d, req, e2, f.can_dlc);

        if (r == IsoTpAssembler::Result::Error)
        {
            std::printf ("  [收到坏帧：%s]\n", e2.c_str ());
            asm_.reset ();
            continue;
        }
        if (r == IsoTpAssembler::Result::NeedMore)
        {
            // 收到首帧就要立刻回流控，否则 tester 会一直停在那里
            if (kindOf (d) == FrameKind::FirstFrame)
            {
                std::uint8_t fc[8];
                buildFlowControl (0, 10, 0x00, fc);
                sendFrame (fd, tx, fc);
            }
            continue;
        }

        // r == Complete：答它
        const auto resp = answer (req, vin, hw);
        std::printf ("  ← %s  →  %s\n", hex (req).c_str (), hex (resp).c_str ());
        if (!sendUds (fd, tx, rx, resp, e2))
        {
            std::printf ("  [回不出去：%s]\n", e2.c_str ());
        }
        else
        {
            ++answered;
        }
        asm_.reset ();
    }

    std::printf ("一共答了 %zu 条\n", answered);
    ::close (fd);
    return 0;
}
