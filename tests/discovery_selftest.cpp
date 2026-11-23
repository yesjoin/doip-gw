// ============================================================================
// discovery_selftest.cpp —— M1 自测
//
// 分两段：
//   A 纯逻辑：谁该回、谁该沉默（不起网络，几十毫秒跑完）
//   B 真 socket：绑端口、收包、回包、源端口对不对（loopback，约 1.5 秒）
//
// 期望值全部是手算的：
//   0x0004 的载荷固定 33 字节 → 报文 41 字节，长度字段 0x21。
// ============================================================================
#include "DoIpDiscovery.h"

#if defined (__unix__) || defined (__APPLE__)
#    define TEST_HAS_POSIX 1
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#else
#    define TEST_HAS_POSIX 0
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace doip;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond)
    {
        std::printf ("[PASS] %s\n", what.c_str ());
        ++g_pass;
    }
    else
    {
        std::printf ("[FAIL] %s\n", what.c_str ());
        ++g_fail;
    }
}

// 组一条请求报文再解析回来，得到 Message（顺便验证一次 M0 的往返）
static Message makeReq (PayloadType t, const std::vector<std::uint8_t> &payload)
{
    std::vector<std::uint8_t> bytes = build (t, payload);
    Message m;
    parseMessage (bytes.data (), bytes.size (), m);
    return m;
}

#if TEST_HAS_POSIX
// ---- 测试用的小客户端（真实客户端也是这么干的，只是端口绑 13400）----
static int makeClient (int timeoutMs)
{
    int fd = ::socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    ::setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    return fd;
}

static bool sendBytes (int fd, std::uint16_t port, const std::vector<std::uint8_t> &b)
{
    sockaddr_in to;
    std::memset (&to, 0, sizeof (to));
    to.sin_family      = AF_INET;
    to.sin_port        = htons (port);
    to.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    return ::sendto (fd, b.data (), b.size (), 0,
                     reinterpret_cast<sockaddr *> (&to), sizeof (to)) > 0;
}

// 收一条；超时返回 false（"沉默"就是靠这个验证的）
static bool recvBytes (int fd, std::vector<std::uint8_t> &out, std::uint16_t &srcPort)
{
    std::uint8_t buf[1500];
    sockaddr_in from;
    std::memset (&from, 0, sizeof (from));
    socklen_t flen = sizeof (from);
    const ssize_t n = ::recvfrom (fd, buf, sizeof (buf), 0,
                                  reinterpret_cast<sockaddr *> (&from), &flen);
    if (n <= 0) return false;
    out.assign (buf, buf + n);
    srcPort = ntohs (from.sin_port);
    return true;
}
#endif

int main ()
{
    // =======================================================================
    std::printf ("=== A 应答逻辑：谁该回，谁该沉默 ===\n");
    EntityConfig cfg;   // 默认身份：VIN LSVAA20A8F2100001，逻辑地址 0x0001

    // ---- 0x0001 无条件应答 ----
    Message req1 = makeReq (PayloadType::VehicleIdRequest, {});
    DiscoveryReply r1 = respondTo (req1, cfg);
    check (r1.replied, "0x0001（有人吗）→ 应答");
    check (r1.reason.find ("无条件") != std::string::npos, "理由写清「无条件应答」");
    check (r1.bytes.size () == 41, "应答报文 = 8 头 + 33 载荷 = 41 字节");
    check (r1.bytes[2] == 0x00 && r1.bytes[3] == 0x04, "类型字段是 00 04（大端）");
    check (r1.bytes[7] == 0x21, "长度字段 0x21（33 字节）");

    Message resp;
    ParseResult pr = parseMessage (r1.bytes.data (), r1.bytes.size (), resp);
    check (pr.error == ParseError::None && pr.consumed == 41, "应答报文能被 M0 解析器解回来");

    VehicleAnnouncement va;
    std::string err;
    check (decodePayload (resp.payload, va, err), "应答载荷能解码成车辆声明");
    check (va.vin == cfg.vin, "VIN 原样带出（17 位）");
    check (va.logicalAddress == 0x0001, "逻辑地址 0x0001");
    check (va.eid.size () == 6 && va.eid[0] == 0x00 && va.eid[5] == 0x55, "EID 6 字节完整");
    check (va.gid.size () == 6 && va.gid[0] == 0x66, "GID 6 字节完整");
    check (va.furtherAction == 0x10, "further action = 0x10（提示客户端去做路由激活）");
    check (va.syncStatus == 0x00, "同步状态 0x00");

    // ---- 0x0002 带 EID：匹配才回 ----
    std::vector<std::uint8_t> myEid = cfg.eid;
    Message req2 = makeReq (PayloadType::VehicleIdRequestEid, myEid);
    DiscoveryReply r2 = respondTo (req2, cfg);
    check (r2.replied, "0x0002 + 我的 EID → 应答");
    check (r2.reason.find ("匹配") != std::string::npos, "理由写清「EID 匹配」");

    std::vector<std::uint8_t> otherEid = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};
    Message req2b = makeReq (PayloadType::VehicleIdRequestEid, otherEid);
    DiscoveryReply r2b = respondTo (req2b, cfg);
    check (!r2b.replied, "0x0002 + 别人的 EID → 沉默");
    check (r2b.reason.find ("不匹配") != std::string::npos, "理由写清「EID 不匹配」");
    check (r2b.bytes.empty (), "沉默时一个字节都不发");

    Message req2c = makeReq (PayloadType::VehicleIdRequestEid, {0x00, 0x11, 0x22, 0x33, 0x44});
    DiscoveryReply r2c = respondTo (req2c, cfg);
    check (!r2c.replied, "0x0002 载荷只有 5 字节 → 沉默（不合格的请求）");
    check (r2c.reason.find ("6 字节") != std::string::npos, "理由点明「应是 6 字节 EID」");

    // ---- 0x0003 带 VIN ----
    std::vector<std::uint8_t> myVin (cfg.vin.begin (), cfg.vin.end ());
    Message req3 = makeReq (PayloadType::VehicleIdRequestVin, myVin);
    DiscoveryReply r3 = respondTo (req3, cfg);
    check (r3.replied, "0x0003 + 我的 VIN → 应答");
    check (r3.reason.find ("VIN 匹配") != std::string::npos, "理由写清「VIN 匹配」");

    std::vector<std::uint8_t> otherVin = myVin;
    otherVin[16] = 'X';
    Message req3b = makeReq (PayloadType::VehicleIdRequestVin, otherVin);
    check (!respondTo (req3b, cfg).replied, "0x0003 + 差一位的 VIN → 沉默");

    std::vector<std::uint8_t> lowerVin = myVin;
    for (auto &c : lowerVin) if (c >= 'A' && c <= 'Z') c = static_cast<std::uint8_t> (c - 'A' + 'a');
    check (!respondTo (makeReq (PayloadType::VehicleIdRequestVin, lowerVin), cfg).replied,
           "VIN 比较大小写敏感（小写不算匹配）");

    Message req3c = makeReq (PayloadType::VehicleIdRequestVin, std::vector<std::uint8_t> (16, 'A'));
    check (!respondTo (req3c, cfg).replied, "0x0003 载荷 16 字节 → 沉默");

    // ---- 不是发现请求的，一律沉默 ----
    Message diagReq = makeReq (PayloadType::DiagnosticMessage,
                               std::vector<std::uint8_t> {0x0E, 0x00, 0x00, 0x01, 0x22, 0xF1, 0x90});
    DiscoveryReply rd = respondTo (diagReq, cfg);
    check (!rd.replied, "0x8001 诊断报文 → 沉默（不是发现请求）");
    check (rd.reason.find ("不是发现请求") != std::string::npos, "理由说明「不是发现请求」");

    check (!respondTo (makeReq (PayloadType::AliveCheckReq, {}), cfg).replied,
           "0x0007 心跳请求 → 沉默");
    check (!respondTo (makeReq (PayloadType::RoutingActivationReq,
                                std::vector<std::uint8_t> (11, 0x00)), cfg).replied,
           "0x0005 路由激活 → 沉默（那是 M2 的事）");
    check (!respondTo (makeReq (PayloadType::VehicleAnnouncement,
                                std::vector<std::uint8_t> (33, 0x00)), cfg).replied,
           "0x0004 声明报文（别人在广播）→ 沉默，不互相刷屏");

    // ---- 配置写短了也不能"永远不回应" ----
    EntityConfig shortEid = cfg;
    shortEid.eid = {0x11, 0x22, 0x33};                 // 只填 3 字节
    std::vector<std::uint8_t> paddedEid = {0x11, 0x22, 0x33, 0x00, 0x00, 0x00};
    check (respondTo (makeReq (PayloadType::VehicleIdRequestEid, paddedEid), shortEid).replied,
           "配置只填 3 字节 EID，补零后仍能与 6 字节请求匹配");

    EntityConfig shortVin = cfg;
    shortVin.vin = "LSVAA20A8F2100";                    // 15 字符
    DiscoveryReply rv = respondTo (makeReq (PayloadType::VehicleIdRequest, {}), shortVin);
    check (rv.bytes.size () == 41, "VIN 只有 15 字符，应答仍是 41 字节（补空格，不错位）");
    VehicleAnnouncement va2;
    Message sm;
    parseMessage (rv.bytes.data (), rv.bytes.size (), sm);
    check (decodePayload (sm.payload, va2, err) && va2.vin.size () == 17, "补空格后 VIN 仍是 17 位");

    // ---- 声明与应答同构 ----
    std::vector<std::uint8_t> ann = buildAnnouncement (cfg);
    check (ann.size () == 41, "主动声明也是 41 字节");
    check (ann == r1.bytes, "声明报文与 0x0001 的应答逐字节相同（同一份「我是谁」）");

    // =======================================================================
    std::printf ("\n=== B 真 socket：绑端口、收包、回包 ===\n");
#if TEST_HAS_POSIX
    UdpDiscoveryServer srv (cfg, 0);      // 0 = 让系统分端口，避免和真实 13400 抢
    bool opened = srv.open (err);
    check (opened, "服务器绑定成功（bind 0.0.0.0）");
    if (!opened)
    {
        std::printf ("       %s\n", err.c_str ());
        std::printf ("\n通过 %d 项，失败 %d 项\n", g_pass, g_fail);
        return g_fail == 0 ? 0 : 1;
    }

    const std::uint16_t port = srv.port ();
    check (port != 0, "getsockname 拿到了真实端口");

    std::thread th ([&srv] { srv.runFor (std::chrono::seconds (3)); });

    int cfd = makeClient (500);
    check (cfd >= 0, "测试客户端 socket 建好了");
    if (cfd < 0)
    {
        th.join ();
        std::printf ("\n通过 %d 项，失败 %d 项\n", g_pass, g_fail);
        return g_fail == 0 ? 0 : 1;
    }

    // ---- 正常请求 ----
    std::vector<std::uint8_t> reqBytes = build (PayloadType::VehicleIdRequest, {});
    check (sendBytes (cfd, port, reqBytes), "把 0x0001 发到服务器端口");

    std::vector<std::uint8_t> got;
    std::uint16_t srcPort = 0;
    bool received = recvBytes (cfd, got, srcPort);
    check (received, "500ms 内收到应答");
    check (srcPort == port, "应答来自服务器同一端口（不是随便挑个源端口）");
    if (received)
    {
        Message rm;
        ParseResult rp = parseMessage (got.data (), got.size (), rm);
        check (rp.error == ParseError::None, "收到的应答能被解析");
        check (rm.header.payloadType == 0x0004, "应答类型是 0x0004");
        VehicleAnnouncement v;
        check (decodePayload (rm.payload, v, err), "应答载荷能解码");
        check (v.vin == cfg.vin, "网络上一来一回，VIN 没变形");
        check (v.logicalAddress == 0x0001, "逻辑地址也没变形");
    }

    check (srv.datagrams () >= 1, "服务器记录到收了 1 个数据报");
    check (srv.answered () >= 1, "服务器记录到回了 1 个应答");

    // ---- 不匹配的 EID：该沉默 ----
    std::vector<std::uint8_t> eidBytes = build (PayloadType::VehicleIdRequestEid, otherEid);
    sendBytes (cfd, port, eidBytes);
    std::vector<std::uint8_t> none1;
    std::uint16_t sp1 = 0;
    check (!recvBytes (cfd, none1, sp1), "别人的 EID → 500ms 内收不到任何东西（正确沉默）");
    check (srv.datagrams () >= 2, "但服务器确实收到了这个包（是「收到但不回」，不是「没收到」）");

    // ---- 坏报文：7 字节，连头都不全 ----
    std::vector<std::uint8_t> junk (7, 0x41);
    sendBytes (cfd, port, junk);
    std::vector<std::uint8_t> none2;
    std::uint16_t sp2 = 0;
    check (!recvBytes (cfd, none2, sp2), "7 字节垃圾 → 沉默且服务器不崩");
    check (srv.datagrams () >= 3, "坏包也被计数（说明没在解析前就崩掉）");

    // ---- 未知类型 0x1234：不认识的，沉默 ----
    std::vector<std::uint8_t> unknownType = build (PayloadType::VehicleIdRequest, {});
    unknownType[2] = 0x12;
    unknownType[3] = 0x34;
    sendBytes (cfd, port, unknownType);
    std::vector<std::uint8_t> none3;
    std::uint16_t sp3 = 0;
    check (!recvBytes (cfd, none3, sp3), "类型 0x1234 → 沉默（发现层不该回 NACK）");

    // ---- 连续两次请求，各收一条 ----
    std::vector<std::uint8_t> g1, g2;
    std::uint16_t p1 = 0, p2 = 0;
    sendBytes (cfd, port, reqBytes);
    const bool rA = recvBytes (cfd, g1, p1);
    sendBytes (cfd, port, reqBytes);
    const bool rB = recvBytes (cfd, g2, p2);
    check (rA && rB, "连续两次 0x0001，各收到一条应答（不串包、不合并）");
    check (g1.size () == 41 && g2.size () == 41, "两条应答都是 41 字节");

    ::close (cfd);
    th.join ();
    check (true, "runFor 到时间自己退出了（线程已回收，不靠杀进程）");
    check (srv.datagrams () >= 6, "全程共处理了至少 6 个数据报");
#else
    std::printf ("[SKIP] 本平台没有 POSIX socket，B 段跳过\n");
#endif

    // =======================================================================
    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M1 全绿 —— 广播一句「有人吗」，实体自己会答「我是谁」。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
