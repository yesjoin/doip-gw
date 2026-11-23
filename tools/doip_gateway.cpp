// ============================================================================
// doip_gateway.cpp —— M4/M5 的成品：以太网进、CAN 出的诊断网关
//
// 用法：
//   doip-gateway --iface vcan0 --port 13400 --seconds 20 [--tx 7E0] [--rx 7E8] [--vin ...]
//
// M5 加的一件事：同一个端口号上再开 UDP 车辆发现。
//   真实 DoIP 实体的发现请求（UDP 13400）和路由激活（TCP 13400）是同一个端口号，
//   只是协议不同，所以这里 UDP/TCP 绑同一个 --port 不会冲突。
//   不加这一步，第三方客户端根本"看不见"网关，只能靠手工填 IP。
// ============================================================================
#include "DoIpDiscovery.h"
#include "DoIpGateway.h"
#include "DoIpTcpServer.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

using namespace doip;

int main (int argc, char **argv)
{
    std::string iface = "vcan0";
    std::uint16_t port = 13400;
    int seconds = 20;
    IsoTpConfig iso;
    IsoTpTiming tim;

    // 实体的 VIN 必须和 CAN 侧 ECU 的 VIN 一致，否则同一辆车会报出两个 VIN。
    EntityConfig ent;
    ent.vin = "LSVAA0000A1234567";

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)        iface = argv[++i];
        else if (a == "--port" && i + 1 < argc)     port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--seconds" && i + 1 < argc)  seconds = std::atoi (argv[++i]);
        else if (a == "--tx" && i + 1 < argc)       iso.txId = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--rx" && i + 1 < argc)       iso.rxId = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--stmin" && i + 1 < argc)    tim.stminDefault = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else if (a == "--vin" && i + 1 < argc)      ent.vin = argv[++i];
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--port 13400] [--seconds 20] "
                          "[--tx 7E0] [--rx 7E8] [--stmin 10] [--vin LSVAA0000A1234567]\n", argv[0]);
            return 2;
        }
    }

    DiagnosticGateway gw (iface, iso, tim);
    std::string err;
    if (!gw.start (err))
    {
        std::fprintf (stderr, "CAN 侧起不来：%s\n", err.c_str ());
        return 1;
    }

    TcpServerConfig cfg;
    cfg.port             = port;
    cfg.entityAddress    = 0x0001;
    cfg.maxConnections   = 8;                       // 网关要比单 ECU 接得住更多 tester
    cfg.idleBeforeAliveCheck = std::chrono::milliseconds (3000);
    cfg.aliveCheckTimeout    = std::chrono::milliseconds (1500);

    DoIpTcpServer srv (cfg);
    if (!srv.open (err))
    {
        std::fprintf (stderr, "TCP 侧起不来：%s\n", err.c_str ());
        return 1;
    }

    std::printf ("DoIP→ISO-TP 网关：TCP %u ↔ %s（发 0x%03X，收 0x%03X），跑 %d 秒\n",
                 static_cast<unsigned> (srv.port ()), iface.c_str (),
                 static_cast<unsigned> (iso.txId), static_cast<unsigned> (iso.rxId), seconds);

    // ---- M5：UDP 车辆发现（和 TCP 用同一个端口号，协议不同不冲突） ----
    UdpDiscoveryServer udp (ent, port);
    bool udpOn = false;
    std::thread udpThread;
    if (udp.open (err))
    {
        udpOn = true;
        udp.logger = [] (const std::string &line) { std::printf ("  [UDP] %s\n", line.c_str ()); };
        udpThread = std::thread ([&udp, seconds] { udp.runFor (std::chrono::seconds (seconds)); });
        std::printf ("UDP %u 车辆发现已开：VIN=%s，逻辑地址=0x%04X（第三方客户端可以直接扫到）\n\n",
                     static_cast<unsigned> (udp.port ()), ent.vin.c_str (),
                     static_cast<unsigned> (ent.logicalAddress));
    }
    else
    {
        std::printf ("[警告] UDP %u 起不来（%s），只能手工填 IP 连接\n\n",
                     static_cast<unsigned> (port), err.c_str ());
    }

    srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };
    srv.diagnosticSink = [&gw] (const DiagnosticRequest &req,
                                std::vector<std::uint8_t> &resp,
                                std::string &e) { return gw (req, resp, e); };

    srv.runFor (std::chrono::seconds (seconds));

    if (udpOn)
    {
        udp.requestStop ();
        if (udpThread.joinable ()) udpThread.join ();
    }

    std::printf ("\n--- 以太网侧 ---\n");
    if (udpOn)
        std::printf ("发现：收到 %zu 条 UDP，回了 %zu 条\n", udp.datagrams (), udp.answered ());
    std::printf ("接入 %zu，激活 %zu，诊断请求 %zu（ACK %zu / NACK %zu）\n",
                 srv.connectionsAccepted (), srv.activationsOk (), srv.diagnosticRequests (),
                 srv.diagnosticAcks (), srv.diagnosticNacks ());
    std::printf ("--- CAN 侧 ---\n");
    std::printf ("转发 %zu 条，失败 %zu 条，最长排队 %zu ms\n",
                 gw.handled (), gw.failed (), gw.maxWaitMs ());
    std::printf ("ISO-TP：发帧 %llu，收帧 %llu，流控 收 %llu / 发 %llu，超时 %llu，序号错 %llu，迟到帧丢弃 %llu\n",
                 static_cast<unsigned long long> (gw.stats ().framesSent),
                 static_cast<unsigned long long> (gw.stats ().framesRecv),
                 static_cast<unsigned long long> (gw.stats ().flowRecv),
                 static_cast<unsigned long long> (gw.stats ().flowSent),
                 static_cast<unsigned long long> (gw.stats ().timeouts),
                 static_cast<unsigned long long> (gw.stats ().seqErrors),
                 static_cast<unsigned long long> (gw.stats ().staleSkipped));
    return 0;
}
