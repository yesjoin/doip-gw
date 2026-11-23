// ============================================================================
// DoIpDiscovery.cpp —— M1 实现
//
// 文件分两半：
//   上半 = respondTo / buildAnnouncement（纯逻辑，不碰 socket）
//   下半 = UdpDiscoveryServer（收发包的壳子）
// 分两半不是为了好看，是为了"规则能在内存里测完"。
// ============================================================================
#include "DoIpDiscovery.h"

#if defined (__unix__) || defined (__APPLE__)
#    define DOIP_HAS_POSIX 1
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define DOIP_HAS_POSIX 0
#endif

#include <cstring>

namespace doip
{
namespace
{

// EntityConfig → 车辆声明结构体。encode 会负责补齐 VIN 到 17 位、EID/GID 到 6 字节。
VehicleAnnouncement announcementFrom (const EntityConfig &cfg)
{
    VehicleAnnouncement a;
    a.vin            = cfg.vin;
    a.logicalAddress = cfg.logicalAddress;
    a.eid            = cfg.eid;
    a.gid            = cfg.gid;
    a.furtherAction  = cfg.furtherAction;
    a.syncStatus     = cfg.syncStatus;
    return a;
}

// 把配置里的 EID 补成 6 字节，用来和请求里的 EID 逐字节比。
// 为什么不直接比 cfg.eid：配置可能写得短（比如只填 3 字节），
// 那样和合法的 6 字节请求永远比不上，表现为"永远不回应" —— 这种 bug 很难看出来。
std::vector<std::uint8_t> normalized6 (const std::vector<std::uint8_t> &v)
{
    std::vector<std::uint8_t> out = v;
    out.resize (6, 0x00);
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// 纯逻辑：回不回
// ---------------------------------------------------------------------------
DiscoveryReply respondTo (const Message &req, const EntityConfig &cfg)
{
    DiscoveryReply r;
    const PayloadType t = toType (req.header.payloadType);

    if (t == PayloadType::VehicleIdRequest)
    {
        r.replied = true;
        r.reason  = "0x0001 无查询条件 → 无条件应答";
    }
    else if (t == PayloadType::VehicleIdRequestEid)
    {
        if (req.payload.size () != 6)
        {
            r.reason = "0x0002 的载荷应是 6 字节 EID，实际 " +
                       std::to_string (req.payload.size ()) + " 字节 → 沉默";
            return r;
        }
        if (normalized6 (cfg.eid) == req.payload)
        {
            r.replied = true;
            r.reason  = "0x0002 EID 匹配 → 应答";
        }
        else
        {
            r.reason = "0x0002 EID 不匹配（问的不是我）→ 沉默";
            return r;
        }
    }
    else if (t == PayloadType::VehicleIdRequestVin)
    {
        if (req.payload.size () != 17)
        {
            r.reason = "0x0003 的载荷应是 17 位 VIN，实际 " +
                       std::to_string (req.payload.size ()) + " 字节 → 沉默";
            return r;
        }
        const std::string asked (req.payload.begin (), req.payload.end ());
        if (asked == cfg.vin)
        {
            r.replied = true;
            r.reason  = "0x0003 VIN 匹配 → 应答";
        }
        else
        {
            r.reason = "0x0003 VIN 不匹配 → 沉默";
            return r;
        }
    }
    else
    {
        // 0x8001 / 0x0007 / 0x0005… 都不是发现请求。
        // 这里必须沉默而不是回"类型不对" —— 发现阶段还没建立任何上下文，
        // 贸然回应只会制造噪声（广播场景下就是风暴）。
        r.reason = std::string ("不是发现请求（") + nameOf (t) + "）→ 沉默";
        return r;
    }

    if (r.replied)
    {
        r.bytes = build (PayloadType::VehicleAnnouncement,
                         encodePayload (announcementFrom (cfg)));
    }
    return r;
}

std::vector<std::uint8_t> buildAnnouncement (const EntityConfig &cfg)
{
    return build (PayloadType::VehicleAnnouncement, encodePayload (announcementFrom (cfg)));
}

// ---------------------------------------------------------------------------
// UDP 服务器
// ---------------------------------------------------------------------------
UdpDiscoveryServer::UdpDiscoveryServer (const EntityConfig &cfg, std::uint16_t port)
    : cfg_ (cfg), port_ (port)
{
}

UdpDiscoveryServer::~UdpDiscoveryServer ()
{
    close ();
}

bool UdpDiscoveryServer::open (std::string &err)
{
#if DOIP_HAS_POSIX
    close ();

    fd_ = ::socket (AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0)
    {
        err = "socket() 失败";
        return false;
    }

    // SO_REUSEADDR：允许多个进程/多轮测试绑同一个端口，不至于"上次没退干净"就绑不上。
    int one = 1;
    ::setsockopt (fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    sockaddr_in addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons (port_);
    // 必须 0.0.0.0（INADDR_ANY）。
    // 绑 127.0.0.1 只能收到发往本机回环的包，广播包（255.255.255.255）根本进不来 ——
    // 这是 DoIP 发现功能最经典的"就是收不到"故障。
    addr.sin_addr.s_addr = htonl (INADDR_ANY);

    if (::bind (fd_, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        err = "bind 失败（端口 " + std::to_string (port_) + " 被占用？）";
        close ();
        return false;
    }

    // 传 0 时由系统分配端口，这里问回来真实端口（自测要靠它）。
    sockaddr_in actual;
    std::memset (&actual, 0, sizeof (actual));
    socklen_t len = sizeof (actual);
    if (::getsockname (fd_, reinterpret_cast<sockaddr *> (&actual), &len) == 0)
    {
        port_ = ntohs (actual.sin_port);
    }
    return true;
#else
    err = "本平台没有 POSIX socket，UdpDiscoveryServer 不可用（M1 只支持 Linux/macOS）";
    return false;
#endif
}

void UdpDiscoveryServer::close ()
{
#if DOIP_HAS_POSIX
    if (fd_ >= 0)
    {
        ::close (fd_);
        fd_ = -1;
    }
#endif
}

void UdpDiscoveryServer::runFor (std::chrono::milliseconds dur)
{
#if DOIP_HAS_POSIX
    if (fd_ < 0) return;

    const auto deadline = std::chrono::steady_clock::now () + dur;
    stop_ = false;

    while (!stop_)
    {
        const auto now = std::chrono::steady_clock::now ();
        if (now >= deadline) break;

        // 每次最多等 200ms，这样 requestStop() 能及时生效
        auto left = std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now);
        if (left > std::chrono::milliseconds (200)) left = std::chrono::milliseconds (200);

        pollfd p;
        p.fd      = fd_;
        p.events  = POLLIN;
        p.revents = 0;

        const int n = ::poll (&p, 1, static_cast<int> (left.count ()));
        if (n <= 0) continue;                    // 超时：回去看 deadline
        if ((p.revents & POLLIN) == 0) continue;

        std::uint8_t buf[1500];
        sockaddr_in peer;
        std::memset (&peer, 0, sizeof (peer));
        socklen_t plen = sizeof (peer);

        const ssize_t got = ::recvfrom (fd_, buf, sizeof (buf), 0,
                                        reinterpret_cast<sockaddr *> (&peer), &plen);
        if (got <= 0) continue;

        ++datagrams_;

        Message req;
        ParseResult pr = parseMessage (buf, static_cast<std::size_t> (got), req);
        if (pr.error != ParseError::None)
        {
            // 坏报文：安静丢弃。理由见头文件 —— UDP 上回 NACK 会变广播风暴。
            if (logger)
            {
                logger (std::string ("收到坏报文（") + nameOf (pr.error) + "），安静丢弃");
            }
            continue;
        }

        DiscoveryReply rep = respondTo (req, cfg_);
        if (logger)
        {
            logger (std::string ("收到 ") + nameOf (toType (req.header.payloadType)) +
                    "（" + std::to_string (req.payload.size ()) + " 字节载荷）→ " + rep.reason);
        }

        if (!rep.replied) continue;

        // 用同一个 socket 回，源端口才是 13400（客户端等着这个端口）
        if (::sendto (fd_, rep.bytes.data (), rep.bytes.size (), 0,
                      reinterpret_cast<sockaddr *> (&peer), plen) > 0)
        {
            ++answered_;
        }
        else if (logger)
        {
            logger ("sendto 失败");
        }
    }
#endif
}

} // namespace doip
