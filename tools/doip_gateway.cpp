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
#include "ActivationAuth.h"   // M27：--tester-key 的解析与 token

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

    if (parts.size () < 3 || parts.size () > 5)
    {
        err = "路由格式应为 TA:TX:RX[:名字][:fd]（十六进制），比如 0002:7E0:7E8:ECU_B";
        return false;
    }
    char *end = nullptr;
    e.logicalAddress = static_cast<std::uint16_t> (std::strtoul (parts[0].c_str (), &end, 16));
    if (end == parts[0].c_str ()) { err = "TA 不是合法十六进制：" + parts[0]; return false; }
    e.txId = static_cast<std::uint32_t> (std::strtoul (parts[1].c_str (), &end, 16));
    if (end == parts[1].c_str ()) { err = "请求 ID 不是合法十六进制：" + parts[1]; return false; }
    e.rxId = static_cast<std::uint32_t> (std::strtoul (parts[2].c_str (), &end, 16));
    if (end == parts[2].c_str ()) { err = "响应 ID 不是合法十六进制：" + parts[2]; return false; }
    e.name = parts.size () >= 4 ? parts[3] : "";
    // M9：第 5 段写 fd 就把这条通道按 CAN FD 开（帧长 64）；不写就是经典帧（帧长 8）
    if (parts.size () == 5)
    {
        if (parts[4] == "fd" || parts[4] == "FD" || parts[4] == "1") e.fd = true;
        else
        {
            err = "第 5 段只认 fd（表示这条通道用 CAN FD），收到的是：" + parts[4];
            return false;
        }
    }
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
    bool stream = true;          // M12：默认流式；--no-stream 用来做 A/B 对照
    std::uint8_t powerMode = kPowerReady;   // M14：0x4003 的答案
    auth::Secret testerKey{};    // M27：预共享密钥；没给就是"不验票"
    bool haveKey = false;
    bool stampSa = false;        // M28：把"谁"写成 CAN 源地址（默认关 = 透明桥接）
    std::string slotLedgerPath;  // M29：位子租约账落盘的路径（不写 = 不落盘）

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
        else if (a == "--no-stream")                stream = false;   // M12：退回 M11 的"攒齐再发"
        else if (a == "--stamp-sa")                 stampSa = true;   // M28：在位子上写源地址
        else if (a == "--slot-ledger" && i + 1 < argc) slotLedgerPath = argv[++i];   // M29：位子账
        else if (a == "--tester-key" && i + 1 < argc)
        {
            // M27：64 位十六进制 = 32 字节预共享密钥。
            //   长度不对或里面有非 hex 字符，直接退出 —— 密钥这种东西不能"猜一个差不多的"。
            const std::string hex = argv[++i];
            if (!auth::parseSecret (hex, testerKey))
            {
                std::fprintf (stderr, "--tester-key 要 64 位十六进制（32 字节），收到 %zu 个字符\n",
                             hex.size ());
                return 2;
            }
            haveKey = true;
        }
        else if (a == "--power-mode" && i + 1 < argc)
        {
            // M14：0 = 还没上电 / 1 = 准备好 / 2 = 能答但给不出这个信息。
            //   留这个开关是为了能演"车没上电"—— 诊断仪问出 0x00 时该去叫技师，
            //   这条链路本身是通的，别去怀疑网络。
            const int m = std::atoi (argv[++i]);
            if (m < 0 || m > 2)
            {
                std::fprintf (stderr, "--power-mode 只认 0 / 1 / 2，收到 %d\n", m);
                return 2;
            }
            powerMode = static_cast<std::uint8_t> (m);
        }
        else
        {
            std::fprintf (stderr,
                          "用法：%s [--iface vcan0] [--port 13400] [--seconds 20] [--stmin 10]\n"
                          "          [--vin LSVAA0000A1234567] [--route TA:TX:RX[:名字]]...\n"
                          "          [--func 功能地址:广播ID[:名字]]... [--no-stream] [--power-mode 0|1|2]\n"
                          "          [--tester-key 64位十六进制] [--stamp-sa] [--slot-ledger 路径]\n"
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
    gw.setStampSource (stampSa);   // M28
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
    // M13：连接与激活分开计。8 条 TCP 挂着等，但只有 4 台能同时激活 ——
    // 第 5 台会拿到 0x01，而不是连 TCP 都连不上（那样这个码永远出不来）。
    cfg.maxActivated     = 4;
    cfg.idleBeforeAliveCheck = std::chrono::milliseconds (3000);
    cfg.aliveCheckTimeout    = std::chrono::milliseconds (1500);

    // M27：给了密钥就开票。没给 = 维持 M26 的行为（谁都能激活），
    //   因为本项目的大量 e2e 都在"不验票"的前提下跑；要验票必须显式说一声。
    if (haveKey)
    {
        cfg.authKey      = testerKey;
        cfg.authRequired = true;
    }
    // M28：开了位子，网关才给每条激活的连接发号；ECU 那边也要按掩码收帧。
    cfg.stampSlots = stampSa;

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
    // M13：把两个容量摆在明面上，否则 0x01 出现时没人知道"满"的是哪个数。
    std::printf ("tester 地址仲裁：最多同时激活 %zu 台（连接上限 %zu）\n",
                 cfg.maxActivated, cfg.maxConnections);
    // M27：把"门关没关"摆在明面上。没开票的网关在日志里必须看得出来，
    //   否则现场会以为"已经验过了"，其实一直在裸奔。
    if (cfg.authRequired)
        std::printf ("路由激活凭据：开（0x0005 的 OEM 4 字节须等于 HMAC-SHA256 头 4 字节，绑 SA）\n"
                     "  没带票/票不对 → 0x04 缺认证；*挡住了不等于安全* —— 4 字节静态票可重放，真车靠 TLS\n");
    else
        std::printf ("路由激活凭据：关（谁都能激活，教学默认；加 --tester-key 打开）\n");
    // M28：把"改不改源地址"摆在明面上 —— 它破坏透明桥接，必须显式说一声。
    if (cfg.stampSlots)
        std::printf ("源地址改写：开（每台诊断仪分一个 1 字节位子，29 位 ID 的最低字节写成 0xF1..0xF8；\n"
                     "  11 位 ID 没有源地址那一格 → 原样发。诊断仪在总线上看到的源地址不再是自己的声明）\n");
    else
        std::printf ("源地址改写：关（所有诊断仪在总线上都是路由表里写的那个源地址）\n");
    // M29：位子账说清楚 —— 账是"谁在什么时候占着哪个位子"，对账工具靠它把 ECU 的位子还原成 SA。
    if (!slotLedgerPath.empty ())
        std::printf ("位子账：写到 %s（退出时落盘；doip-audit 拿它和 ECU 的流水对账）\n",
                     slotLedgerPath.c_str ());
    std::printf ("路由表（%zu 条）：\n", table.size ());
    for (const auto &e : table.entries ())
    {
        // 宽度要在日志里看得出来：7E0 打成 0x7E0，18DAF100 打成 0x18DAF100
        std::printf ("  TA=0x%04X → %s / %s%s  %s\n", static_cast<unsigned> (e.logicalAddress),
                     formatCanId (e.txId).c_str (), formatCanId (e.rxId).c_str (),
                     e.fd ? "（FD，帧长 64）" : "",
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

        // ★ M14：把 M13 的账搬到了 UDP 上。
        //   取数方式是"现数"：cur_open_sockets 必须是这一刻的真实值。
        //   而 srv.openSockets() 读的是原子量，UDP 线程调它不会撞上 I/O 线程改 conns_。
        const TcpServerConfig capCfg = cfg;    // 按值带走，避免以后 cfg 改坏时指到野引用
        udp.powerMode = PowerModeInfo{powerMode};
        udp.entityStatus = [&srv, capCfg] () -> EntityStatusInfo
        {
            // 节点类型写"网关"：本实体确实把诊断往 CAN 子网转，不是只答自己。
            const EntityStatusInfo s = entityStatusFromCounts (
                capCfg.maxConnections, srv.openSockets (), capCfg.maxPayload, kNodeTypeGateway);
            return s;
        };

        udpThread = std::thread ([&udp, seconds] { udp.runFor (std::chrono::seconds (seconds)); });
        std::printf ("UDP %u 车辆发现已开：VIN=%s，实体地址=0x%04X\n",
                     static_cast<unsigned> (udp.port ()), ent.vin.c_str (),
                     static_cast<unsigned> (ent.logicalAddress));
        // M14：把"我能被问出来什么"摆在明面上，否则 0x4001 的答案只能靠抓包猜。
        std::printf ("实体状态（0x4001/0x4003，同在 UDP %u）：node type=网关，最大 socket %zu，"
                     "最大载荷 %u 字节，电源模式=%s\n",
                     static_cast<unsigned> (udp.port ()), cfg.maxConnections,
                     static_cast<unsigned> (cfg.maxPayload),
                     powerMode == kPowerReady ? "ready" :
                     powerMode == kPowerNotReady ? "not ready（演车没上电）" : "not supported");
        std::printf ("\n");
    }
    else
    {
        std::printf ("[警告] UDP %u 起不来（%s），只能手工填 IP 连接\n\n",
                     static_cast<unsigned> (port), err.c_str ());
    }

    srv.logger = [] (const std::string &line) { std::printf ("  %s\n", line.c_str ()); };

    // ★ M10：异步投递。
    //   注意这里**没有**任何"等"的动作：投完立刻 return，I/O 线程继续 poll。
    //   于是"一台慢 ECU 拖住整个网关"这件事从根上消失了 —— 慢只慢它自己那条通道。
    srv.asyncSubmit = [&gw] (const DiagnosticRequest &req, DiagnosticMultiResult &immediate) -> std::uint64_t
    {
        return gw.submit (req, immediate);
    };
    srv.asyncTake = [&gw] (AsyncResult &out) -> bool
    {
        std::uint64_t id = 0;
        DiagnosticMultiResult r;
        if (!gw.takeResult (id, r)) return false;
        out.jobId = id;
        out.r     = std::move (r);
        return true;
    };
    srv.asyncAbandon = [&gw] (std::uint64_t id) { gw.abandon (id); };

    // ★ M12：把"网关收到一条答案"接到"服务器往诊断仪发一条"。
    //   只在 stream=true 时接；--no-stream 不接，就是 M11 的攒批行为，
    //   用来对照"首条答案到底被最慢那台拖了多久"。
    if (stream)
    {
        gw.setReplySink ([&srv] (std::uint64_t id, const DiagnosticReply &rep) {
            srv.onStreamReply (id, rep);   // 只入队，不写 socket（此时网关握着全部总线锁）
        });
    }
    std::printf ("交付方式：%s\n", stream ? "流式（收一条转一条）" : "攒批（等一轮全收齐，--no-stream）");

    srv.runFor (std::chrono::seconds (seconds));

    if (udpOn)
    {
        udp.requestStop ();
        if (udpThread.joinable ()) udpThread.join ();
    }

    std::printf ("\n--- 以太网侧 ---\n");
    if (udpOn)
        std::printf ("发现：收到 %zu 条 UDP，回了 %zu 条（其中实体状态/电源模式 %zu 条）\n",
                     udp.datagrams (), udp.answered (), udp.entityQueries ());
    // M14：TCP 上误发 0x4001/0x4003 的次数。非 0 说明对面客户端写错了族 —— 不是网关的错。
    std::printf ("TCP 上收到 UDP 专属请求 %zu 次（0x4001/0x4003，只记账不回答）\n",
                 srv.udpOnlyRejects ());
    std::printf ("接入 %zu，激活 %zu，诊断请求 %zu（ACK %zu / NACK %zu）\n",
                 srv.connectionsAccepted (), srv.activationsOk (), srv.diagnosticRequests (),
                 srv.diagnosticAcks (), srv.diagnosticNacks ());
    // M10 的两个数：结果孤儿（连接已断）与忙拒（同一连接上一条还没回）
    std::printf ("在途丢弃 %zu 条（结果回来时连接已断），忙拒 %zu 条（上一条请求还没回）\n",
                 srv.orphanResults (), srv.busyRejects ());
    std::printf ("作废 %zu 条（连接断开时还在途，结果不转交给下一台诊断仪）\n",
                 gw.abandonedJobs ());
    // M13：两个码第一次有了账。0x03 是"同址冲突"，0x01 是"名额满了"——
    // 前者要去找另一台诊断仪，后者要扩容，现场看一眼日志就知道该动哪边。
    std::printf ("地址冲突 %zu 次（0x03：同一 SA 已在别的连接上激活），"
                 "激活名额已满 %zu 次（0x01）\n",
                 srv.addressConflicts (), srv.activationCapacityRejects ());
    // M27：凭据的两本账。通过的次数 = 有几个"能证明自己是谁"的诊断仪。
    if (cfg.authRequired)
        std::printf ("凭据：通过 %zu 次，挡回 %zu 次（0x04）\n",
                     srv.authPasses (), srv.authRejects ());
    // M28：位子账。**没还的**才叫问题 —— 这里报的是"此刻还占着几个"，
    //   正常收尾应该是 0（每条连接断开都还了）。不是 0 就说明有人没还。
    if (cfg.stampSlots)
        std::printf ("位子：此刻还占着 %zu 个（断开就回收；位子不是人，是位子）\n", srv.slotsUsed ());
    // M29：位子租约账。这里报"账上有几条租约、有几条还没还"，
    //   然后（如果给了路径）落盘。**没还的租约**说明有人没走正常收尾路径，
    //   对账时这些位子可能被判歧义 —— 所以这个数要能被看见。
    if (cfg.stampSlots)
    {
        std::printf ("位子账：%zu 条租约（未归还 %zu，多还 %zu 次，超容量丢弃 %zu 条）\n",
                     srv.slotLedger ().size (), srv.slotLedger ().openCount (),
                     srv.slotLedger ().orphanReleases (), srv.slotLedger ().dropped ());
        if (!slotLedgerPath.empty ())
        {
            std::string why;
            if (srv.saveSlotLedger (slotLedgerPath, why))
                std::printf ("位子账已写入 %s（供 doip-audit 对账）\n", slotLedgerPath.c_str ());
            else
                std::printf ("位子账写失败：%s\n", why.c_str ());
        }
    }
    else if (!slotLedgerPath.empty ())
    {
        // 没开改写就没有位子这回事：照样写一份空账，明确说"这次运行没有位子"，
        //   而不是让对账工具拿一个不存在的文件去猜。
        std::string why;
        if (srv.saveSlotLedger (slotLedgerPath, why))
            std::printf ("位子账已写入 %s（空账：本次没开 --stamp-sa）\n", slotLedgerPath.c_str ());
        else
            std::printf ("位子账写失败：%s\n", why.c_str ());
    }
    if (stream)
    {
        std::printf ("流式交付 %zu 条（收到就转，不等一轮收齐；同一 job 交卷时只补差额）；"
                     "流式时连接已断 %zu 条（丢弃不转交）\n",
                     srv.streamedReplies (), srv.streamDropped ());
    }
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
        std::printf ("  TA=0x%04X（%s/%s%s）：转发 %zu 条，失败 %zu 条，发帧 %llu，收帧 %llu，"
                     "超时 %llu，序号错 %llu，迟到帧丢弃 %llu，广播应答 %llu，排队峰值 %zu，最长排队 %zu ms\n",
                     static_cast<unsigned> (cs.ta),
                     formatCanId (cs.txId).c_str (), formatCanId (cs.rxId).c_str (),
                     cs.fd ? "，FD" : "",
                     cs.handled, cs.failed,
                     static_cast<unsigned long long> (cs.stats.framesSent),
                     static_cast<unsigned long long> (cs.stats.framesRecv),
                     static_cast<unsigned long long> (cs.stats.timeouts),
                     static_cast<unsigned long long> (cs.stats.seqErrors),
                     static_cast<unsigned long long> (cs.stats.staleSkipped),
                     static_cast<unsigned long long> (cs.stats.funcResponses),
                     cs.queuePeak, cs.maxQueueWaitMs);
    }
    return 0;
}
