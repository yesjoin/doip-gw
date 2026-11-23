// ============================================================================
// doip_client.cpp —— 站在诊断仪那边，走一遍 M2 的最小流程
//
// 用法：doip-client [--host 127.0.0.1] [--port 13400] [--sa 0E00] [--type 00] [--alive]
//
// 流程：TCP 连上 → 发 0x0005 路由激活 → 读 0x0006 → （可选）发 0x0007 读 0x0008
// 打印的每一行都和 doip-serve 那侧对得上，方便"两边对照看"。
// ============================================================================
#include "DoIpCodec.h"
#include "DoIpRouting.h"   // 为了 nameOf(ActivationResponseCode)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace doip;

static bool sendVec (int fd, const std::vector<std::uint8_t> &b)
{
    std::size_t sent = 0;
    while (sent < b.size ())
    {
        const ssize_t n = ::send (fd, b.data () + sent, b.size () - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t> (n);
    }
    return true;
}

// 收一条完整报文；返回 false 表示超时或对面关了
static bool recvMessage (int fd, std::vector<std::uint8_t> &whole, int ms, std::string &why)
{
    whole.clear ();
    while (true)
    {
        pollfd p;
        p.fd      = fd;
        p.events  = POLLIN;
        p.revents = 0;
        if (::poll (&p, 1, ms) <= 0)
        {
            why = "超时";
            return false;
        }
        std::uint8_t buf[2048];
        const ssize_t got = ::recv (fd, buf, sizeof (buf), 0);
        if (got <= 0)
        {
            why = "对端关闭了连接";
            return false;
        }
        whole.insert (whole.end (), buf, buf + got);

        Message m;
        ParseResult pr = parseMessage (whole.data (), whole.size (), m);
        if (pr.error == ParseError::None) return true;
        if (pr.error != ParseError::NeedMoreData)
        {
            why = "报文格式不对";
            return false;
        }
    }
}

int main (int argc, char **argv)
{
    std::string host = "127.0.0.1";
    std::uint16_t port = 13400;
    std::uint16_t sa   = 0x0E00;
    std::uint8_t type  = 0x00;
    bool alive = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--host" && i + 1 < argc)       host = argv[++i];
        else if (a == "--port" && i + 1 < argc)  port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--sa" && i + 1 < argc)    sa = static_cast<std::uint16_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--type" && i + 1 < argc)  type = static_cast<std::uint8_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--alive")                 alive = true;
        else
        {
            std::fprintf (stderr, "用法：%s [--host 127.0.0.1] [--port 13400] [--sa 0E00] [--type 00] [--alive]\n", argv[0]);
            return 2;
        }
    }

    const int fd = ::socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::fprintf (stderr, "socket() 失败\n"); return 1; }

    sockaddr_in addr;
    std::memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons (port);
    if (::inet_pton (AF_INET, host.c_str (), &addr.sin_addr) != 1)
    {
        std::fprintf (stderr, "host 不合法：%s\n", host.c_str ());
        ::close (fd);
        return 2;
    }

    if (::connect (fd, reinterpret_cast<sockaddr *> (&addr), sizeof (addr)) < 0)
    {
        std::fprintf (stderr, "连不上 %s:%u（实体端起了吗？）\n", host.c_str (), static_cast<unsigned> (port));
        ::close (fd);
        return 1;
    }
    std::printf ("已连接 %s:%u\n", host.c_str (), static_cast<unsigned> (port));

    // 1) 路由激活
    RoutingActivationRequest req;
    req.sourceAddress  = sa;
    req.activationType = type;
    const std::vector<std::uint8_t> reqBytes =
        build (PayloadType::RoutingActivationReq, encodePayload (req));
    std::printf ("→ 0x0005 路由激活：SA=0x%04X type=0x%02X（%zu 字节）\n",
                 req.sourceAddress, req.activationType, reqBytes.size ());
    if (!sendVec (fd, reqBytes))
    {
        std::fprintf (stderr, "发送失败\n");
        ::close (fd);
        return 1;
    }

    std::vector<std::uint8_t> got;
    std::string why;
    if (!recvMessage (fd, got, 3000, why))
    {
        std::printf ("← 没拿到应答：%s\n", why.c_str ());
        ::close (fd);
        return 1;
    }

    Message m;
    parseMessage (got.data (), got.size (), m);
    if (m.header.payloadType != 0x0006)
    {
        std::printf ("← 不是 0x0006，而是 0x%04X（%zu 字节）\n",
                     static_cast<unsigned> (m.header.payloadType), got.size ());
        ::close (fd);
        return 1;
    }

    RoutingActivationResponse res;
    if (!decodePayload (m.payload, res, why))
    {
        std::printf ("← 0x0006 解不开：%s\n", why.c_str ());
        ::close (fd);
        return 1;
    }
    std::printf ("← 0x0006 应答：tester=0x%04X entity=0x%04X code=0x%02X (%s)\n",
                 res.testerAddress, res.entityAddress,
                 static_cast<unsigned> (res.responseCode),
                 nameOf (static_cast<ActivationResponseCode> (res.responseCode)));

    if (res.responseCode != static_cast<std::uint8_t> (ActivationResponseCode::Success))
    {
        std::printf ("激活没成功，后面的事不用做了。\n");
        ::close (fd);
        return 1;
    }

    // 2) 心跳（可选）
    if (alive)
    {
        std::printf ("→ 0x0007 心跳请求\n");
        sendVec (fd, build (PayloadType::AliveCheckReq, {}));

        std::vector<std::uint8_t> hb;
        if (!recvMessage (fd, hb, 2000, why))
        {
            std::printf ("← 心跳没回应：%s\n", why.c_str ());
            ::close (fd);
            return 1;
        }
        Message hm;
        parseMessage (hb.data (), hb.size (), hm);
        AliveCheckResponse acr;
        if (hm.header.payloadType == 0x0008 && decodePayload (hm.payload, acr, why))
        {
            std::printf ("← 0x0008 心跳应答：source=0x%04X\n", acr.sourceAddress);
        }
        else
        {
            std::printf ("← 收到 0x%04X，不是预期的心跳应答\n",
                         static_cast<unsigned> (hm.header.payloadType));
        }
    }

    std::printf ("\n激活完成。正常情况下这个连接能一直活着，直到你关掉它。\n");
    ::close (fd);
    return 0;
}
