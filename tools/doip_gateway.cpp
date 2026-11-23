// ============================================================================
// doip_gateway.cpp —— M4 的成品：以太网进、CAN 出的诊断网关
//
// 用法：
//   doip-gateway --iface vcan0 --port 13400 --seconds 20 [--tx 7E0] [--rx 7E8]
//
// 另一边（项目一）：
//   ~/uds-ecu/build/uds-demo --ecu --iface vcan0 --wait-s 60
// 然后：
//   ./build/doip-client --port 13400 --sa 0E00 --diag "22 F1 90"
//   → 以太网上是 0x8001，CAN 上是 7E0 的首帧 + 连续帧，回来的是 20 字节 VIN。
// ============================================================================
#include "DoIpGateway.h"
#include "DoIpTcpServer.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace doip;

int main (int argc, char **argv)
{
    std::string iface = "vcan0";
    std::uint16_t port = 13400;
    int seconds = 20;
    IsoTpConfig iso;
    IsoTpTiming tim;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)        iface = argv[++i];
        else if (a == "--port" && i + 1 < argc)     port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--seconds" && i + 1 < argc)  seconds = std::atoi (argv[++i]);
        else if (a == "--tx" && i + 1 < argc)       iso.txId = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--rx" && i + 1 < argc)       iso.rxId = std::strtoul (argv[++i], nullptr, 16);
        else if (a == "--stmin" && i + 1 < argc)    tim.stminDefault = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--port 13400] [--seconds 20] "
                          "[--tx 7E0] [--rx 7E8] [--stmin 10]\n", argv[0]);
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

    std::printf ("DoIP→ISO-TP 网关：TCP %u ↔ %s（发 0x%03X，收 0x%03X），跑 %d 秒\n\n",
                 static_cast<unsigned> (srv.port ()), iface.c_str (),
                 static_cast<unsigned> (iso.txId), static_cast<unsigned> (iso.rxId), seconds);

    srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };
    srv.diagnosticSink = [&gw] (const DiagnosticRequest &req,
                                std::vector<std::uint8_t> &resp,
                                std::string &e) { return gw (req, resp, e); };

    srv.runFor (std::chrono::seconds (seconds));

    std::printf ("\n--- 以太网侧 ---\n");
    std::printf ("接入 %zu，激活 %zu，诊断请求 %zu（ACK %zu / NACK %zu）\n",
                 srv.connectionsAccepted (), srv.activationsOk (), srv.diagnosticRequests (),
                 srv.diagnosticAcks (), srv.diagnosticNacks ());
    std::printf ("--- CAN 侧 ---\n");
    std::printf ("转发 %zu 条，失败 %zu 条，最长排队 %zu ms\n",
                 gw.handled (), gw.failed (), gw.maxWaitMs ());
    std::printf ("ISO-TP：发帧 %llu，收帧 %llu，流控 收 %llu / 发 %llu，超时 %llu，序号错 %llu\n",
                 static_cast<unsigned long long> (gw.stats ().framesSent),
                 static_cast<unsigned long long> (gw.stats ().framesRecv),
                 static_cast<unsigned long long> (gw.stats ().flowRecv),
                 static_cast<unsigned long long> (gw.stats ().flowSent),
                 static_cast<unsigned long long> (gw.stats ().timeouts),
                 static_cast<unsigned long long> (gw.stats ().seqErrors));
    return 0;
}
