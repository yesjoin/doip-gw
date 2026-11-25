// ============================================================================
// doip_serve.cpp —— M2 的实体端（TCP 13400）
//
// 用法：doip-serve --port 13400 --seconds 10 [--idle-ms 2000] [--timeout-ms 1000]
//
// 它把每条事件打出来：接了谁、谁激活了、心跳发了没、为什么断。
// 调 M2/M3/M4 的时候，这个小窗口比 Wireshark 顺手 —— 因为它说的是人话。
// ============================================================================
#include "DoIpTcpServer.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace doip;

int main (int argc, char **argv)
{
    TcpServerConfig cfg;
    int seconds = 10;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc)            cfg.port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--seconds" && i + 1 < argc)    seconds = std::atoi (argv[++i]);
        else if (a == "--entity" && i + 1 < argc)     cfg.entityAddress = static_cast<std::uint16_t> (std::strtoul (argv[++i], nullptr, 16));
        else if (a == "--idle-ms" && i + 1 < argc)    cfg.idleBeforeAliveCheck = std::chrono::milliseconds (std::atoi (argv[++i]));
        else if (a == "--timeout-ms" && i + 1 < argc) cfg.aliveCheckTimeout = std::chrono::milliseconds (std::atoi (argv[++i]));
        else
        {
            std::fprintf (stderr, "用法：%s --port N --seconds N [--entity 0001] [--idle-ms N] [--timeout-ms N]\n", argv[0]);
            return 2;
        }
    }

    DoIpTcpServer srv (cfg);
    std::string err;
    if (!srv.open (err))
    {
        std::fprintf (stderr, "起不来：%s\n", err.c_str ());
        return 1;
    }

    std::printf ("DoIP 实体在 TCP %u 上等诊断客户端，地址 0x%04X，跑 %d 秒\n",
                 static_cast<unsigned> (srv.port ()), cfg.entityAddress, seconds);
    std::printf ("心跳：静默 %lld ms 发 0x0007，%lld ms 内不回 0x0008 就断\n\n",
                 static_cast<long long> (cfg.idleBeforeAliveCheck.count ()),
                 static_cast<long long> (cfg.aliveCheckTimeout.count ()));

    srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };
    // M3：挂一个**假 ECU**。它答 3E 00 / 22 F1 86，其余回 7F xx 31。
    // 目的只有一个：让"以太网这一侧"先端到端跑通。M4 把这一行换成真的 ISO-TP。
    srv.diagnosticSink = stubEcuAnswer;
    srv.runFor (std::chrono::seconds (seconds));

    std::printf ("\n接入 %zu 个连接，成功激活 %zu 次，心跳超时断开 %zu 次。\n",
                 srv.connectionsAccepted (), srv.activationsOk (), srv.aliveCheckTimeouts ());
    std::printf ("诊断请求 %zu 条：ACK %zu，NACK %zu。\n",
                 srv.diagnosticRequests (), srv.diagnosticAcks (), srv.diagnosticNacks ());
    // M13：地址仲裁的账。0x03 = 同址冲突，0x01 = 激活名额满。
    std::printf ("地址冲突 %zu 次（0x03），激活名额已满 %zu 次（0x01）。\n",
                 srv.addressConflicts (), srv.activationCapacityRejects ());
    return 0;
}
