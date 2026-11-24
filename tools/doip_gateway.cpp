// ============================================================================
// doip_gateway.cpp —— M6 的成品：多 ECU 路由的诊断网关
//
// 用法：
//   doip-gateway --iface vcan0 --port 13400 --seconds 20
//                --route 0002:7E0:7E8:ECU_A --route 0003:7A0:7A8:ECU_B
//
// 不给 --route 时默认一条：TA=0x0001 → 7E0/7E8（和 M5 的行为一致）。
//
// 同一个端口号上还开 UDP 车辆发现：真实实体的发现（UDP）和激活（TCP）
// 是同一个端口号，只是协议不同，绑一起不冲突。
// ============================================================================
#include "DoIpDiscovery.h"
#include "DoIpGateway.h"
#include "DoIpTcpServer.h"
#include "RouteTable.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using namespace doip;

namespace
{

// "0002:7E0:7E8:ECU_B" → RouteEntry。名字可省，只用前三段也行。
bool parseRoute (const std::string &spec, RouteEntry &e, std::string &err)
{
    std::vector<std::string> parts;
    std::string cur;
    for (char c : spec)
    {
        if (c == ':') { parts.push_back (cur); cur.clear (); }
        else cur.push_back (c);
    }
    parts.push_back (cur);

    if (parts.size () < 3 || parts.size () > 4)
    {
        err = "路由格式应为 TA:TX:RX[:名字]（十六进制），比如 0002:7E0:7E8:ECU_B";
        return false;
    }
    char *end = nullptr;
    e.logicalAddress = static_cast<std::uint16_t> (std::strtoul (parts[0].c_str (), &end, 16));
    if (end == parts[0].c_str ()) { err = "TA 不是合法十六进制：" + parts[0]; return false; }
    e.txId = static_cast<std::uint32_t> (std::strtoul (parts[1].c_str (), &end, 16));
    if (end == parts[1].c_str ()) { err = "请求 ID 不是合法十六进制：" + parts[1]; return false; }
    e.rxId = static_cast<std::uint32_t> (std::strtoul (parts[2].c_str (), &end, 16));
    if (end == parts[2].c_str ()) { err = "响应 ID 不是合法十六进制：" + parts[2]; return false; }
    e.name = parts.size () == 4 ? parts[3] : "";
    return true;
}

} // namespace

int main (int argc, char **argv)
{
    std::string iface = "vcan0";
    std::uint16_t port = 13400;
    int seconds = 20;
    IsoTpTiming tim;

    // 实体的 VIN 必须和 CAN 侧 ECU 的 VIN 一致，否则同一辆车会报出两个 VIN。
    EntityConfig ent;
    ent.vin = "LSVAA0000A1234567";

    std::vector<std::string> routeSpecs;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)        iface = argv[++i];
        else if (a == "--port" && i + 1 < argc)     port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--seconds" && i + 1 < argc)  seconds = std::atoi (argv[++i]);
        else if (a == "--stmin" && i + 1 < argc)    tim.stminDefault = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else if (a == "--vin" && i + 1 < argc)      ent.vin = argv[++i];
        else if (a == "--route" && i + 1 < argc)    routeSpecs.push_back (argv[++i]);
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--port 13400] [--seconds 20] [--stmin 10]\n"
                          "          [--vin LSVAA0000A1234567] [--route TA:TX:RX[:名字]]...\n"
                          "      例：%s --route 0002:7E0:7E8:ECU_A --route 0003:7A0:7A8:ECU_B\n",
                          argv[0], argv[0]);
            return 2;
        }
    }

    if (routeSpecs.empty ()) routeSpecs.push_back ("0001:7E0:7E8:ECU_A");

    // ---- 建路由表：任何一条不合法就直接退出，不带病运行 ----
    RouteTable table;
    for (const auto &spec : routeSpecs)
    {
        RouteEntry e;
        std::string err;
        if (!parseRoute (spec, e, err))
        {
            std::fprintf (stderr, "路由 %s 解析失败：%s\n", spec.c_str (), err.c_str ());
            return 2;
        }
        if (!table.add (e, err))
        {
            std::fprintf (stderr, "路由 %s 不合法：%s\n", spec.c_str (), err.c_str ());
            return 2;
        }
    }

    DiagnosticGateway gw (iface, table, tim);
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

    // 谁能当诊断目标 = 路由表里有谁。表里没有的 TA 一律 0x8003 0x03。
    cfg.targetKnown = [&table] (std::uint16_t ta) { return table.known (ta); };

    DoIpTcpServer srv (cfg);
    if (!srv.open (err))
    {
        std::fprintf (stderr, "TCP 侧起不来：%s\n", err.c_str ());
        return 1;
    }

    std::printf ("DoIP→ISO-TP 网关：TCP %u ↔ %s，跑 %d 秒\n", static_cast<unsigned> (srv.port ()),
                 iface.c_str (), seconds);
    std::printf ("路由表（%zu 条）：\n", table.size ());
    for (const auto &e : table.entries ())
    {
        // 宽度要在日志里看得出来：7E0 打成 0x7E0，18DAF100 打成 0x18DAF100
        std::printf ("  TA=0x%04X → %s / %s  %s\n", static_cast<unsigned> (e.logicalAddress),
                     formatCanId (e.txId).c_str (), formatCanId (e.rxId).c_str (),
                     e.name.empty () ? "" : e.name.c_str ());
    }

    // ---- M5 起就有的 UDP 车辆发现（和 TCP 同端口号）----
    UdpDiscoveryServer udp (ent, port);
    bool udpOn = false;
    std::thread udpThread;
    if (udp.open (err))
    {
        udpOn = true;
        udp.logger = [] (const std::string &line) { std::printf ("  [UDP] %s\n", line.c_str ()); };
        udpThread = std::thread ([&udp, seconds] { udp.runFor (std::chrono::seconds (seconds)); });
        std::printf ("UDP %u 车辆发现已开：VIN=%s，实体地址=0x%04X\n\n",
                     static_cast<unsigned> (udp.port ()), ent.vin.c_str (),
                     static_cast<unsigned> (ent.logicalAddress));
    }
    else
    {
        std::printf ("[警告] UDP %u 起不来（%s），只能手工填 IP 连接\n\n",
                     static_cast<unsigned> (port), err.c_str ());
    }

    srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };
    srv.diagnosticSink = [&gw] (const DiagnosticRequest &req, std::vector<std::uint8_t> &resp,
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
    std::printf ("转发 %zu 条，失败 %zu 条（其中目标地址不认识 %zu 条），最长排队 %zu ms\n",
                 gw.handled (), gw.failed (), gw.unknownTargets (), gw.maxWaitMs ());
    for (const auto &cs : gw.channelStats ())
    {
        std::printf ("  TA=0x%04X（%s/%s）：转发 %zu 条，失败 %zu 条，发帧 %llu，收帧 %llu，"
                     "超时 %llu，序号错 %llu，迟到帧丢弃 %llu\n",
                     static_cast<unsigned> (cs.ta),
                     formatCanId (cs.txId).c_str (), formatCanId (cs.rxId).c_str (),
                     cs.handled, cs.failed,
                     static_cast<unsigned long long> (cs.stats.framesSent),
                     static_cast<unsigned long long> (cs.stats.framesRecv),
                     static_cast<unsigned long long> (cs.stats.timeouts),
                     static_cast<unsigned long long> (cs.stats.seqErrors),
                     static_cast<unsigned long long> (cs.stats.staleSkipped));
    }
    return 0;
}
