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
//
// M8 新增 --func-rx 7DF：除了自己的物理请求 ID，**再多听一个广播 ID**。
//   这是"功能寻址"在 ECU 这一侧的真相：不是我多了一条协议，是我多开了一个耳朵。
//   注意两件事：
//     ① 广播来的请求只能是单帧（网关没法给"所有 ECU"发流控）；
//     ② 应答也必须能塞进单帧（≤7 字节），塞不进去就不答——
//        这不是偷懒，是协议限制：多帧响应要等一个唯一的流控方向。
//
// M9 新增 --fd：这一台按 **CAN FD** 说话（帧长 64，单帧最多 62 字节）。
//   同一个程序、同一个 ISO-TP 逻辑，只是把"每帧能装多少"换了个数——
//   这正是 M9 要证明的事：FD 不是另一套协议，是同一套协议换了个信封大小。
//   副作用很直观：22 F1 A2（200 字节）在经典帧下要 29 帧，在 FD 下只要 4 帧。
// ============================================================================
#include "CanId.h"
#include "DidTable.h"
#include "FirmwareManifest.h"
#include "FlashPreconditions.h"
#include "FlashTarget.h"
#include "SessionGuard.h"
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
#include <memory>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace doip;

namespace
{

int openCan (const std::string &iface, bool fd, std::string &err)
{
    const int fd_ = ::socket (PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) { err = "socket(PF_CAN) 失败"; return -1; }

    ifreq ifr;
    std::memset (&ifr, 0, sizeof (ifr));
    std::strncpy (ifr.ifr_name, iface.c_str (), IFNAMSIZ - 1);
    if (::ioctl (fd_, SIOCGIFINDEX, &ifr) < 0)
    {
        err = "找不到网卡 " + iface;
        ::close (fd_);
        return -1;
    }

    sockaddr_can addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind (fd_, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        err = "bind 失败";
        ::close (fd_);
        return -1;
    }

    // ★ M9：FD 必须显式打开这个 socket 选项，否则 FD 帧会被内核当成噪声丢掉
    if (fd)
    {
        const int on = 1;
        if (::setsockopt (fd_, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &on, sizeof (on)) < 0)
        {
            err = "这个网卡不支持 CAN FD（vcan 的 MTU 要 >= 72）";
            ::close (fd_);
            return -1;
        }
    }
    return fd_;
}

void sendFrame (int fd, std::uint32_t id, const std::uint8_t d[64], std::size_t len, bool useFd)
{
    // ★ M9：FD 帧和经典帧是两个结构体。FD 下 len 可以是 8..64 任意值（本项目固定 64）。
    if (useFd)
    {
        canfd_frame f;
        std::memset (&f, 0, sizeof (f));
        f.can_id = idForSend (id);
        f.len    = static_cast<std::uint8_t> (len > kFdFrameBytes ? kFdFrameBytes : len);
        std::memcpy (f.data, d, f.len);
        const ssize_t n = ::write (fd, &f, sizeof (f));
        if (n < 0)
        {
            std::fprintf (stderr, "[stub-ecu] CAN FD 写失败（%s）\n", formatCanId (id).c_str ());
        }
        return;
    }

    can_frame f;
    std::memset (&f, 0, sizeof (f));
    // M7：29 位 ID 要置 CAN_EFF_FLAG，标准帧不能带（置了内核会按 29 位处理）
    f.can_id  = idForSend (id);
    f.can_dlc = static_cast<std::uint8_t> (len > 8 ? 8 : len);
    std::memcpy (f.data, d, f.can_dlc);
    // 写失败（总线掉了 / fd 关了）这里没法重试，返回负数就算了：
    // 但返回值必须"看"一眼，否则 glibc 的 warn_unused_result 会在 -O2 + -Werror 下直接编译失败
    const ssize_t n = ::write (fd, &f, sizeof (f));
    if (n < 0) {
        std::fprintf (stderr, "[stub-ecu] CAN 写失败（%s）\n", formatCanId (id).c_str ());
    }
}

// 发一条 UDS：单帧一发；多帧先发 FF，等 tester 的流控，再按 STmin 发 CF
bool sendUds (int fd, std::uint32_t txId, std::uint32_t rxId,
              const std::vector<std::uint8_t> &uds, std::size_t frameBytes,
              std::string &err)
{
    const bool useFd = frameBytes > kClassicFrameBytes;

    std::vector<std::vector<std::uint8_t>> frames;
    if (!segmentMessage (uds, frames, err, 0x00, frameBytes)) return false;

    sendFrame (fd, txId, frames[0].data (), frames[0].size (), useFd);
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

        // 用 canfd_frame 读：FD socket 上经典帧只回 16 字节，FD 帧回 72 字节，
        // 两种结构体前 8 字节布局一致，长度读同一个位置就行
        canfd_frame f;
        std::memset (&f, 0, sizeof (f));
        const ssize_t n = ::read (fd, &f, sizeof (f));
        if (n != static_cast<ssize_t> (sizeof (can_frame)) &&
            n != static_cast<ssize_t> (sizeof (canfd_frame))) continue;
        if (idFromRecv (f.can_id) != rxId) continue;      // 不是给我的，丢掉（先剥标志位再比）
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
        sendFrame (fd, txId, frames[i].data (), frames[i].size (), useFd);
    }
    return true;
}

// M18：验签的两本账（这一步只有 stub 用，放文件级就够；不进 FlashTarget，因为它不管验签）
static std::uint32_t gVerifyPass = 0;
static std::uint32_t gVerifyFail = 0;

// M19：前置检查的两本账（可刷 / 不可刷）。和验签一样属于"stub 的观察"，不进纯逻辑层。
static std::uint32_t gPrecheckPass = 0;
static std::uint32_t gPrecheckFail = 0;

// M15：刷写服务（0x31 / 0x34 / 0x36 / 0x37）—— 只做物理寻址，不参与广播。
//   返回 false = "这不是刷写服务"，交给 M6 起就有的 answer() 去处理。
//   刷写是**有状态的会话**，所以它必须待在主循环里（一个 FlashTarget 跟着这台 ECU 活）。
bool flashService (FlashTarget &t, const std::vector<std::uint8_t> &req,
                   std::uint32_t batteryMv, std::uint32_t minBatteryMv,
                   std::vector<std::uint8_t> &resp, std::string &why)
{
    if (req.empty ()) return false;
    FlashReply r;
    switch (req[0])
    {
        case 0x31:   // RoutineControl：只认 0x01 启动 + FF00 擦除 / FF01 校验 / FF02 验签
        {
            if (req.size () < 4 || req[1] != 0x01) return false;
            const std::uint16_t rid = static_cast<std::uint16_t> ((req[2] << 8) | req[3]);
            if (rid == 0xFF00)      r = t.handleErase ();
            else if (rid == 0xFF01) r = t.checkIntegrity (std::vector<std::uint8_t> (req.begin () + 4, req.end ()));
            else if (rid == 0xFF02)
            {
                // M18：验签。分两类错误：
                //   格式不对（长度/magic/版本/不认识这把钥匙）→ 我这边按 NRC 回（请求本身不合法）；
                //   内容不对（标签/长度/哈希）→ 正响应带状态 01（请求合法，是包不对）。
                // 这两个分类别混：NRC 0x31 会让诊断仪以为"服务用错了"，而状态 01 才是"重刷一份包"。
                const auto c = fw::verify (t.image (), std::vector<std::uint8_t> (req.begin () + 4, req.end ()));
                if (t.image ().empty ())
                {
                    r.positive = false;
                    r.uds      = {0x7F, 0x31, kNrcConditionsNotCorrect};
                    r.reason   = "验签：还没有镜像可验（先 0x34/0x36）";
                }
                else
                {
                    std::uint8_t nrcCode = 0;
                    if (c.verdict == fw::Verdict::BadLength) nrcCode = kNrcIncorrectLength;
                    else if (c.verdict == fw::Verdict::BadMagic || c.verdict == fw::Verdict::UnknownKey)
                        nrcCode = kNrcRequestOutOfRange;

                    if (nrcCode != 0)
                    {
                        r.positive = false;
                        r.uds      = {0x7F, 0x31, nrcCode};
                        r.reason   = "验签：" + c.reason;
                        ++gVerifyFail;   // 格式错也算"这次没验过"
                    }
                    else
                    {
                        r.positive = true;
                        r.uds      = {0x71, 0x01, 0xFF, 0x02, static_cast<std::uint8_t> (c.ok () ? 0x00 : 0x01)};
                        r.reason   = "验签：" + c.reason;
                        if (c.ok ()) ++gVerifyPass; else ++gVerifyFail;
                    }
                }
            }
            else                    return false;
            break;
        }
        case 0x34:
            if (req.size () < 3) return false;
            // M19：电压不够就别开始 —— "检查过"和"检查结果被遵守"是两件事，
            // 所以 0x34 自己也要看一眼（0x22 是"现在不能"，不是"你请求错了"）。
            if (batteryMv < minBatteryMv)
            {
                resp = {0x7F, 0x34, kNrcConditionsNotCorrect};
                why  = "0x34 被拒：电压 " + std::to_string (batteryMv) + " mV 低于门槛 " +
                       std::to_string (minBatteryMv) + " mV，先充电再刷";
                return true;
            }
            r = t.requestDownload (req[1], req[2],
                                   std::vector<std::uint8_t> (req.begin () + 3, req.end ()));
            break;
        case 0x36:
            if (req.size () < 2) return false;
            r = t.transferData (req[1], std::vector<std::uint8_t> (req.begin () + 2, req.end ()));
            break;
        case 0x37:
            r = t.requestTransferExit ();
            break;
        default:
            return false;
    }
    resp = r.uds;
    why  = r.reason;
    return true;
}

// M16：会话层（0x10 / 0x27 / 0x3E）。M17 加 0x11，只做物理寻址；广播上的会话请求没有意义。
//   返回 false = "不是会话服务"，交给刷写或 M6 起的 answer()。
bool sessionService (SessionGuard &g, const std::vector<std::uint8_t> &req,
                     std::uint32_t nowMs, bool flashBusy,
                     std::vector<std::uint8_t> &resp, std::string &why)
{
    if (req.empty ()) return false;

    if (req[0] == 0x10)
    {
        if (req.size () < 2)
        {
            resp = {0x7F, 0x10, kNrcIncorrectLength};
            why  = "0x10 连子功能字节都没有";
            return true;
        }
        auto r = g.handleSessionControl (req[1], nowMs);
        resp = r.uds; why = r.reason;
        return true;
    }
    if (req[0] == 0x27)
    {
        if (req.size () < 2)
        {
            resp = {0x7F, 0x27, kNrcIncorrectLength};
            why  = "0x27 连子功能字节都没有";
            return true;
        }
        if (req[1] == 0x01)
        {
            auto r = g.requestSeed (nowMs);
            resp = r.uds; why = r.reason;
            return true;
        }
        if (req[1] == 0x02)
        {
            auto r = g.sendKey (std::vector<std::uint8_t> (req.begin () + 2, req.end ()), nowMs);
            resp = r.uds; why = r.reason;
            return true;
        }
        resp = {0x7F, 0x27, kNrcSubFunctionNotSupported};
        why  = "0x27 的子功能只认 01 要种子 / 02 交密钥";
        return true;
    }
    if (req[0] == 0x3E)
    {
        auto r = g.testerPresent (req.size () > 1 ? req[1] : 0x00, nowMs);
        resp = r.uds; why = r.reason;
        return true;
    }
    // M17：0x11 ECUReset。默认会话里也允许（它就是"恢复原样"的动作），
    //   但"刷到一半"要挡回 0x22 —— 半截镜像当完整镜像用是变砖路径。
    if (req[0] == 0x11)
    {
        if (req.size () < 2)
        {
            resp = {0x7F, 0x11, kNrcIncorrectLength};
            why  = "0x11 连子功能字节都没有";
            return true;
        }
        auto r = g.handleEcuReset (req[1], nowMs, flashBusy);
        resp = r.uds; why = r.reason;
        return true;
    }
    return false;
}

// M19：前置条件检查（0x31 01 0203）。四条全过 → 71 01 02 03 00；任何一条不过 → … 01。
//   注意它回的是"正响应 + 状态"，不是 NRC：请求合法，答案是"不能刷"。
bool precheckService (const SessionGuard &g, const FlashTarget &f, std::uint32_t batteryMv,
                      const std::vector<std::uint8_t> &req,
                      std::vector<std::uint8_t> &resp, std::string &why)
{
    if (req.size () < 4 || req[0] != 0x31 || req[1] != 0x01 || req[2] != 0x02 || req[3] != 0x03)
        return false;

    Preconditions p;
    p.batteryMv          = batteryMv;
    p.programmingSession = (g.level () == SessionGuard::kSessionProgramming);
    p.unlocked           = g.unlocked ();
    p.downloadActive     = f.active ();

    const auto r = checkProgrammingPreconditions (p);
    if (r.ok) ++gPrecheckPass; else ++gPrecheckFail;
    resp = {0x71, 0x01, 0x02, 0x03, static_cast<std::uint8_t> (r.ok ? 0x00 : 0x01)};
    why  = std::string ("前置条件：") + (r.ok ? "全部满足 → 00" : "不满足 → 01") + "（" + r.summary () + "）";
    return true;
}

// M19：0x2E WriteDataByIdentifier。门禁由 flashGateDenied 一并挡住（同一道门）。
bool didWriteService (DidTable &d, const std::vector<std::uint8_t> &req,
                      std::vector<std::uint8_t> &resp, std::string &why)
{
    if (req.empty () || req[0] != 0x2E) return false;
    if (req.size () < 3)
    {
        resp = {0x7F, 0x2E, kNrcIncorrectLength};
        why  = "0x2E 连 DID 都没给全";
        return true;
    }
    const std::uint16_t did = static_cast<std::uint16_t> ((req[1] << 8) | req[2]);
    return d.write (did, std::vector<std::uint8_t> (req.begin () + 3, req.end ()), resp, why);
}

// M16：刷写门禁。只有"编程会话 + 已解锁"才放行；不放行时按标准给 0x7F / 0x33。
bool flashGateDenied (const SessionGuard &g, const std::vector<std::uint8_t> &req,
                      std::vector<std::uint8_t> &resp, std::string &why)
{
    if (req.empty ()) return false;
    // M19：0x2E 写指纹也归这道门管——它和刷写是同一类"会改这台 ECU"的动作
    bool isFlashSid = (req[0] == 0x34 || req[0] == 0x36 || req[0] == 0x37 || req[0] == 0x2E);
    if (!isFlashSid && req[0] == 0x31)
    {
        // 只挡 FF00 擦除 / FF01 校验，别的例程照旧走老 answer()（回 7F 31 31）
        isFlashSid = req.size () >= 4 && req[1] == 0x01 &&
                     ((req[2] == 0xFF && req[3] == 0x00) || (req[2] == 0xFF && req[3] == 0x01) ||
                      (req[2] == 0xFF && req[3] == 0x02));
    }
    if (!isFlashSid) return false;
    if (g.flashAllowed ()) return false;

    auto d = g.denyFlash (req[0]);
    resp = d.uds; why = d.reason;
    return true;
}

std::vector<std::uint8_t> answer (const std::vector<std::uint8_t> &uds,
                                  const std::string &vin, const std::string &hw,
                                  const DidTable *dids)
{
    std::vector<std::uint8_t> r;
    std::string readWhy;
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
        else if (did == 0xF1A0 || did == 0xF1A1 || did == 0xF1A2)
        {
            // M9 的"长响应"：字节值 = 下标 & 0xFF（远程一眼就能校验，手算也对得上）
            //   0xF1A0 → 59 + 3 = 62 字节：**正好是一张 FD 单帧装得下的上限**
            //   0xF1A1 → 100 + 3 = 103 字节：FD 两帧 / 经典帧 15 帧
            //   0xF1A2 → 197 + 3 = 200 字节：FD 四帧 / 经典帧 29 帧
            const std::size_t n = (did == 0xF1A0) ? 59 : (did == 0xF1A1) ? 100 : 197;
            for (std::size_t i = 0; i < n; ++i)
                r.push_back (static_cast<std::uint8_t> (i & 0xFF));
        }
        else if (did == 0xF186)
            r.push_back (0x02);                       // 当前会话：编程会话（和项目一取不同值）
        else if (dids != nullptr && dids->read (did, r, readWhy))   // M19：F187/F188/F18C/F1A5/F184
            return r;
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
    std::uint32_t funcRx = 0;      // M8：额外的广播监听 ID（0 = 不听广播）
    bool useFd = false;            // M9：这一台按 CAN FD 说话（帧长 64）
    int  delayMs = 0;              // M10：应答前先睡一会儿（模拟"这台 ECU 慢"）
    std::string vin = "LSVZZ0000B7654321";
    std::string hw  = "HW02";
    int seconds = 20;
    // M15：刷写模式。打开之后这台 ECU 才认 0x31/0x34/0x36/0x37；
    //   不打开时它的行为与 M9 完全一致（老脚本不会因为新代码变红）。
    bool flashOn = false;
    bool secureOn = false;              // M16：门禁（0x10 02 + 0x27 解锁后才允许刷写）
    std::uint32_t flashBlock = 34;      // 通告给客户端的一条 0x36 总长（含 0x36 + BSC）
    std::uint32_t flashMax   = 65536;   // 能收的镜像上限
    // M19：能读的"身份"与电压。电压默认 12.4V（一个健康的 12V 电池静置值）。
    std::string  partNo   = "PART-ABC1234";
    std::string  swVer    = "SW-1.0.3";
    std::string  serial   = "ECU-A-0007";
    std::uint32_t batteryMv = 12400;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)       iface = argv[++i];
        else if (a == "--tx" && i + 1 < argc)     tx = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--rx" && i + 1 < argc)     rx = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--func-rx" && i + 1 < argc) funcRx = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--vin" && i + 1 < argc)    vin = argv[++i];
        else if (a == "--hw" && i + 1 < argc)     hw = argv[++i];
        else if (a == "--fd")                     useFd = true;
        else if (a == "--delay-ms" && i + 1 < argc) delayMs = std::atoi (argv[++i]);
        else if (a == "--seconds" && i + 1 < argc) seconds = std::atoi (argv[++i]);
        else if (a == "--flash")                  flashOn = true;
        else if (a == "--secure")                 secureOn = true;
        else if (a == "--flash-block" && i + 1 < argc) flashBlock = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else if (a == "--flash-max" && i + 1 < argc)   flashMax   = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else if (a == "--part-no" && i + 1 < argc)     partNo     = argv[++i];
        else if (a == "--sw-version" && i + 1 < argc)  swVer      = argv[++i];
        else if (a == "--serial" && i + 1 < argc)      serial     = argv[++i];
        else if (a == "--battery-mv" && i + 1 < argc)  batteryMv  = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--rx 7A0] [--tx 7A8] [--func-rx 7DF] [--fd] "
                          "[--delay-ms 0] [--vin LSVZZ0000B7654321] [--hw HW02] [--seconds 20]\n"
                          "          [--flash] [--flash-block 34] [--flash-max 65536] [--secure]\n"
                          "          [--part-no PART-ABC1234] [--sw-version SW-1.0.3] [--serial ECU-A-0007] [--battery-mv 12400]\n"
                          "     --flash：打开 0x31 01 FF00/FF01、0x34、0x36、0x37（刷写链路，只做物理寻址）\n"
                          "     --secure：给刷写加门禁（先 0x10 02、再 0x27 解锁；S3 超时回落默认会话）\n"
                          "     --battery-mv：这台 ECU 报的电压（0x22 F1A5），低于 11500 时 0x34 会被挡\n", argv[0]);
            return 2;
        }
    }
    if (funcRx != 0 && funcRx == rx)
    {
        std::fprintf (stderr, "广播监听 ID 和自己的物理接收 ID 相同（%s），没有意义\n",
                      formatCanId (rx).c_str ());
        return 2;
    }
    if (funcRx != 0 && funcRx == tx)
    {
        std::fprintf (stderr, "广播监听 ID 和自己的发送 ID 相同（%s），会自己听自己\n",
                      formatCanId (tx).c_str ());
        return 2;
    }
    if (vin.size () != 17)
    {
        std::fprintf (stderr, "VIN 必须是 17 个字符（现在是 %zu）\n", vin.size ());
        return 2;
    }

    static constexpr std::uint32_t kMinBatteryMv = 11500;   // 12V 系统：低于 11.5V 不刷
    DidTable dids (partNo, swVer, serial, 0x00000000u, batteryMv);

    std::string err;
    const int fd = openCan (iface, useFd, err);
    if (fd < 0)
    {
        std::fprintf (stderr, "起不来：%s\n", err.c_str ());
        return 1;
    }

    const std::size_t frameBytes = useFd ? kFdFrameBytes : kClassicFrameBytes;

    std::printf ("极简 ECU：%s 上收 %s / 发 %s，%s，VIN=%s，HW=%s，跑 %d 秒\n",
                 iface.c_str (), formatCanId (rx).c_str (), formatCanId (tx).c_str (),
                 useFd ? "CAN FD（帧长 64，单帧最多 62 字节）" : "经典 CAN（帧长 8，单帧 7 字节）",
                 vin.c_str (), hw.c_str (), seconds);
    if (delayMs > 0)
    {
        // M10：故意慢一点，用来证明"一台慢 ECU 不拖累别的通道"
        std::printf ("           每条应答前先睡 %d ms（模拟慢 ECU）\n", delayMs);
    }
    if (funcRx != 0)
    {
        std::printf ("           另外还听广播 %s（功能寻址，只能单帧收 / 单帧答）\n",
                     formatCanId (funcRx).c_str ());
    }

    // M15：刷写模式。状态跟着这台 ECU 活；广播来的请求不走刷写（刷写只做物理寻址）。
    std::unique_ptr<FlashTarget> flash;
    if (flashOn)
    {
        flash.reset (new FlashTarget (flashBlock, flashMax));
        std::printf ("           刷写：0x31 01 FF00/FF01/FF02 + 0x34/0x36/0x37；"
                     "通告块长 %u 字节（含 0x36+BSC，数据 %u），镜像上限 %u 字节\n",
                     static_cast<unsigned> (flashBlock),
                     static_cast<unsigned> (flashBlock > 2 ? flashBlock - 2 : 1),
                     static_cast<unsigned> (flashMax));
        std::printf ("           验签：0x31 01 FF02 收 76 字节清单（DGIM + 版本 + 长度 + SHA-256 + keyId + 标签），"
                     "认识的钥匙是 0x0001/0x0002\n");
    }

    // M16：门禁。开着 --secure 时，0x10 / 0x27 / 0x3E 由 SessionGuard 回答，
    // 刷写四个服务只有"编程会话 + 已解锁"才放行（0x7F 会话不对 / 0x33 没解锁）。
    std::unique_ptr<SessionGuard> guard;
    if (secureOn)
    {
        guard.reset (new SessionGuard (5000, 3, 10000));
        std::printf ("           门禁：先 0x10 02（编程会话）+ 0x27 解锁，才放行 0x31/0x34/0x36/0x37；"
                     "S3 5000 ms 没动静回落默认会话，错 3 次锁 10000 ms\n");
        std::printf ("           复位：0x11 01 硬复位（清镜像）/ 02 点火循环 / 03 软复位（留镜像）；"
                     "默认会话也能复位，刷写中途回 0x22\n");
        std::printf ("           身份：0x22 读 F187 零件号 / F188 软件版本 / F18C 序列号 / F1A5 电压（%u mV）/ F184 指纹；"
                     "指纹可用 0x2E 写（要编程会话 + 解锁）\n",
                     static_cast<unsigned> (batteryMv));
        std::printf ("           前置：0x31 01 0203 检查能不能刷（电压 ≥ %u mV、编程会话、已解锁、不在下载中）；"
                     "电压不够时 0x34 直接回 0x22\n",
                     static_cast<unsigned> (kMinBatteryMv));
    }

    IsoTpAssembler asm_ (4095, frameBytes);
    // 会话/S3 要的是"从启动到现在多少毫秒"，取一次起点做差就行
    const auto epoch = std::chrono::steady_clock::now ();
    const auto msNow = [&epoch] () {
        return static_cast<std::uint32_t> (
            std::chrono::duration_cast<std::chrono::milliseconds> (
                std::chrono::steady_clock::now () - epoch).count ());
    };
    const auto deadline = std::chrono::steady_clock::now () + std::chrono::seconds (seconds);
    std::size_t answered = 0;

    while (std::chrono::steady_clock::now () < deadline)
    {
        pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        if (::poll (&p, 1, 50) <= 0) continue;

        // 用 canfd_frame 读：FD socket 上经典帧只回 16 字节、FD 帧回 72 字节，
        // 两种结构体前 8 字节布局一致，长度读同一个位置就行
        canfd_frame f;
        std::memset (&f, 0, sizeof (f));
        const ssize_t nread = ::read (fd, &f, sizeof (f));
        if (nread != static_cast<ssize_t> (sizeof (can_frame)) &&
            nread != static_cast<ssize_t> (sizeof (canfd_frame))) continue;

        const std::uint32_t gotId = idFromRecv (f.can_id);      // 先剥标志位再比
        const bool onFunc = (funcRx != 0 && gotId == funcRx);   // M8：这一帧是广播来的吗
        if (gotId != rx && !onFunc) continue;                   // 不是给我的

        const std::size_t dlen = f.len;
        if (dlen == 0 || dlen > frameBytes) continue;

        std::uint8_t d[kFdFrameBytes] = {0};
        std::memcpy (d, f.data, dlen);

        // 广播来的请求必须是单帧：网关没法给"所有 ECU"发流控。
        // 收到 FF 说明对端用法错了（或者别的工具在刷）——印一句，不答。
        if (onFunc && kindOf (d) != FrameKind::SingleFrame)
        {
            std::printf ("  [广播 %s 上收到非单帧，按协议无法应答，跳过]\n",
                         formatCanId (funcRx).c_str ());
            continue;
        }

        std::vector<std::uint8_t> req;
        std::string e2;
        const auto r = asm_.onFrame (d, req, e2, dlen);

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
                std::uint8_t fc[kFdFrameBytes] = {0};
                buildFlowControl (0, 10, 0x00, fc, frameBytes);
                sendFrame (fd, tx, fc, frameBytes, useFd);
            }
            continue;
        }

        // r == Complete：答它
        // M10：慢 ECU 就在这里慢——它慢的只是自己那条通道，别的通道照常跑
        if (delayMs > 0) ::usleep (static_cast<useconds_t> (delayMs) * 1000);

        const std::uint32_t nowMs = msNow ();
        std::vector<std::uint8_t> resp;
        std::string why;
        bool handled = false;

        if (guard)
        {
            if (guard->tick (nowMs))
            {
                std::printf ("  [会话] S3 超时（%u ms 没动静）→ 回到默认会话，解锁一起清掉\n",
                             static_cast<unsigned> (guard->s3Ms ()));
            }
            guard->noteActivity (nowMs);   // 任何请求都算活着，不只是 0x3E
            if (!onFunc && sessionService (*guard, req, nowMs, flash && flash->active (),
                                           resp, why))
            {
                handled = true;
            }
            if (!handled && flash && !onFunc &&
                precheckService (*guard, *flash, batteryMv, req, resp, why))
            {
                handled = true;    // 0x31 01 0203：正响应 + 状态 00/01
            }
            if (!handled && flash && !onFunc &&
                flashGateDenied (*guard, req, resp, why))
            {
                handled = true;    // 被门挡住：回了 0x7F / 0x33，下面不再走刷写
            }
        }
        if (!handled && flash && !onFunc &&
            flashService (*flash, req, batteryMv, kMinBatteryMv, resp, why))
        {
            handled = true;
        }
        if (!handled && didWriteService (dids, req, resp, why))   // M19：0x2E
        {
            handled = true;
        }
        if (!handled) resp = answer (req, vin, hw, &dids);

        // 0x3E 80（suppressPosRsp）就是"我只要保活、别回包"：不回，但账照记
        if (handled && resp.empty ())
        {
            std::printf ("  ← %s  →  （suppressPosRsp：不回包，只重置 S3）\n", hex (req).c_str ());
            asm_.reset ();
            continue;
        }

        // 功能寻址的应答也必须塞进单帧。经典帧 7 字节；FD 帧能到 62 字节。
        // 比如读 VIN 是 20 字节：经典帧下"没有答案"，FD 下可以一张单帧答完。
        const std::size_t sfMax = useFd ? (frameBytes - 2) : 7;
        if (onFunc && resp.size () > sfMax)
        {
            std::printf ("  ← 广播 %s，响应 %zu 字节塞不进单帧（上限 %zu），按协议不答\n",
                         hex (req).c_str (), resp.size (), sfMax);
            asm_.reset ();
            continue;
        }

        std::printf ("  ← %s%s  →  %s\n", onFunc ? "[广播] " : "", hex (req).c_str (),
                     hex (resp).c_str ());
        if (handled) std::printf ("     [会话/刷写] %s\n", why.c_str ());
        if (!sendUds (fd, tx, rx, resp, frameBytes, e2))
        {
            std::printf ("  [回不出去：%s]\n", e2.c_str ());
        }
        else
        {
            ++answered;
        }

        // M17：51 xx 已经发出去了，现在才允许"复位"。
        // 顺序在代码里是物理的：先 send，后动状态 —— 反了就永远等不到应答。
        if (guard)
        {
            const std::uint8_t kind = guard->takePendingReset ();
            if (kind)
            {
                const char *name = (kind == 0x01) ? "硬复位（断电重启）"
                                 : (kind == 0x02) ? "点火循环（keyOffOn）"
                                                  : "软复位";
                if (kind == 0x01 && flash)
                {
                    flash->powerCycle ();
                    std::printf ("     [复位] %s：镜像已清（RAM 掉电），要重新 0x31 FF00 才能再下载\n", name);
                }
                else
                {
                    std::printf ("     [复位] %s：会话/解锁/锁计数全清，镜像保留\n", name);
                }
            }
        }
        asm_.reset ();
    }

    std::printf ("一共答了 %zu 条\n", answered);
    if (flash)
    {
        std::printf ("刷写：收下 %u 块，镜像 %zu 字节，CRC-32=0x%08X\n",
                     static_cast<unsigned> (flash->receipts ()), flash->image ().size (),
                     static_cast<unsigned> (flash->crc32 ()));
        std::printf ("验签：通过 %u 次 / 不过 %u 次（格式错也算不过）\n",
                     static_cast<unsigned> (gVerifyPass), static_cast<unsigned> (gVerifyFail));
        std::printf ("前置：检查 %u 次 → 可刷 %u 次 / 不可刷 %u 次；指纹 0x%08X\n",
                     static_cast<unsigned> (gPrecheckPass + gPrecheckFail),
                     static_cast<unsigned> (gPrecheckPass), static_cast<unsigned> (gPrecheckFail),
                     static_cast<unsigned> (dids.fingerprint ()));
    }
    if (guard)
    {
        std::printf ("会话：切换 %u 次，种子 %u 次，解锁成功 %u 次 / 拒 %u 次，锁定 %u 次，"
                     "S3 超时 %u 次，保活 %u 次\n",
                     static_cast<unsigned> (guard->sessionChanges ()),
                     static_cast<unsigned> (guard->seedRequests ()),
                     static_cast<unsigned> (guard->keysAccepted ()),
                     static_cast<unsigned> (guard->keysRejected ()),
                     static_cast<unsigned> (guard->lockouts ()),
                     static_cast<unsigned> (guard->s3Timeouts ()),
                     static_cast<unsigned> (guard->testerPresents ()));
        std::printf ("复位：硬 %u 次 / 点火循环 %u 次 / 软 %u 次\n",
                     static_cast<unsigned> (guard->resetHard ()),
                     static_cast<unsigned> (guard->resetKeyOffOn ()),
                     static_cast<unsigned> (guard->resetSoft ()));
    }
    ::close (fd);
    return 0;
}
