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

// "TA:TX:RX:名字" → 按冒号切开。物理路由和功能路由共用这一步。
void splitSpec (const std::string &spec, std::vector<std::string> &parts)
{
    std::string cur;
    for (char c : spec)
    {
        if (c == ':') { parts.push_back (cur); cur.clear (); }
        else cur.push_back (c);
    }
    parts.push_back (cur);
}

// "0002:7E0:7E8:ECU_B" → RouteEntry。名字可省，只用前三段也行。
bool parseRoute (const std::string &spec, RouteEntry &e, std::string &err)

{
    std::vector<std::string> parts;
    splitSpec (spec, parts);

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

// "0xE400:0x7DF:ALL" → FunctionalRoute（M8）。这里只有两段 ID 可选，因为广播没有"响应 ID"。
bool parseFunctional (const std::string &spec, FunctionalRoute &f, std::string &err)
{
    std::vector<std::string> parts;
    splitSpec (spec, parts);
    if (parts.size () < 2 || parts.size () > 3)
    {
        err = "功能路由格式应为 功能地址:广播ID[:名字]，比如 0xE400:0x7DF:ALL";
        return false;
    }
    char *end = nullptr;
    f.logicalAddress = static_cast<std::uint16_t> (std::strtoul (parts[0].c_str (), &end, 16));
    if (end == parts[0].c_str ()) { err = "功能地址不是合法十六进制：" + parts[0]; return false; }
    f.txId = static_cast<std::uint32_t> (std::strtoul (parts[1].c_str (), &end, 16));
    if (end == parts[1].c_str ()) { err = "广播 ID 不是合法十六进制：" + parts[1]; return false; }
    f.name = parts.size () == 3 ? parts[2] : "";
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
    std::vector<std::string> funcSpecs;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--iface" && i + 1 < argc)        iface = argv[++i];
        else if (a == "--port" && i + 1 < argc)     port = static_cast<std::uint16_t> (std::atoi (argv[++i]));
        else if (a == "--seconds" && i + 1 < argc)  seconds = std::atoi (argv[++i]);
        else if (a == "--stmin" && i + 1 < argc)    tim.stminDefault = static_cast<std::uint32_t> (std::atoi (argv[++i]));
        else if (a == "--vin" && i + 1 < argc)      ent.vin = argv[++i];
        else if (a == "--route" && i + 1 < argc)    routeSpecs.push_back (argv[++i]);
        else if (a == "--func" && i + 1 < argc)     funcSpecs.push_back (argv[++i]);
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--port 13400] [--seconds 20] [--stmin 10]\n"
                          "          [--vin LSVAA0000A1234567] [--route TA:TX:RX[:名字]]...\n"
                          "          [--func 功能地址:广播ID[:名字]]...\n"
                          "      例：%s --route 0002:7E0:7E8:ECU_A --route 0003:7A0:7A8:ECU_B\n"
                          "          --func 0xE400:0x7DF:ALL\n",
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
    for (const auto &spec : funcSpecs)
    {
        FunctionalRoute f;
        std::string err;
        if (!parseFunctional (spec, f, err))
        {
            std::fprintf (stderr, "功能路由 %s 解析失败：%s\n", spec.c_str (), err.c_str ());
            return 2;
        }
        if (!table.addFunctional (f, err))
        {
            std::fprintf (stderr, "功能路由 %s 不合法：%s\n", spec.c_str (), err.c_str ());
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

    // 谁能当诊断目标 = 物理表里有谁 + 功能表里有谁。都不在的 TA 一律 0x8003 0x03。
    cfg.targetKnown = [&table] (std::uint16_t ta) { return table.reachable (ta); };

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
    if (table.sizeFunctional () > 0)
    {
        std::printf ("功能路由（%zu 条，广播）：\n", table.sizeFunctional ());
        for (const auto &f : table.functionalEntries ())
        {
            std::printf ("  TA=0x%04X → %s（所有 ECU 都在听）  %s\n",
                         static_cast<unsigned> (f.logicalAddress),
                         formatCanId (f.txId).c_str (),
                         f.name.empty () ? "" : f.name.c_str ());
        }
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

    // M8：统一走"多响应"下游。
    //   物理地址 → 一条（和 M6 完全一样的行为）
    //   功能地址 → 广播收集（条数由谁在听决定）
    // 服务器那边因此只有一套逻辑，不用"看 TA 决定走哪个 sink"。
    srv.diagnosticSinkMulti = [&gw] (const DiagnosticRequest &req) -> DiagnosticMultiResult
    {
        if (gw.table ().knownFunctional (req.targetAddress)) return gw.broadcast (req);

        DiagnosticMultiResult r;
        std::vector<std::uint8_t> resp;
        std::string e2;
        if (!gw (req, resp, e2))
        {
            r.nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
            r.reason   = e2;
            return r;
        }
        r.ok = true;
        r.replies.push_back (DiagnosticReply{req.targetAddress, resp});
        return r;
    };

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
    if (gw.functionalRequests () > 0)
    {
        std::printf ("功能寻址：广播 %zu 次，收回应答 %zu 条，无人应答 %zu 次\n",
                     gw.functionalRequests (), gw.functionalReplies (), gw.silentBroadcasts ());
    }
    for (const auto &cs : gw.channelStats ())
    {
        std::printf ("  TA=0x%04X（%s/%s）：转发 %zu 条，失败 %zu 条，发帧 %llu，收帧 %llu，"
                     "超时 %llu，序号错 %llu，迟到帧丢弃 %llu，广播应答 %llu\n",
                     static_cast<unsigned> (cs.ta),
                     formatCanId (cs.txId).c_str (), formatCanId (cs.rxId).c_str (),
                     cs.handled, cs.failed,
                     static_cast<unsigned long long> (cs.stats.framesSent),
                     static_cast<unsigned long long> (cs.stats.framesRecv),
                     static_cast<unsigned long long> (cs.stats.timeouts),
                     static_cast<unsigned long long> (cs.stats.seqErrors),
                     static_cast<unsigned long long> (cs.stats.staleSkipped),
                     static_cast<unsigned long long> (cs.stats.funcResponses));
    }
    return 0;
}
