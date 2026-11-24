// ============================================================================
// route_selftest.cpp —— M6 + M7 自测（纯逻辑，不需要 vcan0）
//
// 三段：
//   A 路由表：什么能进表、什么必须拒绝、查得到/查不到
//   B 通道语义：目标地址什么时候算"可达"，以及几个判据的先后关系
//   C ID 宽度：11 位 / 29 位的判断、发帧置位 / 收帧剥位、超范围配置必须拒
//
// B 段为什么放在这个文件：M6 把"TA 是不是我"从"只有实体自己"改成了"查路由表"。
// 这条规则属于**通道判定**，不是网关内部实现——所以要用通道的接口来验，
// 而不是只测网关（网关那层碰 socket，测起来慢）。
// ============================================================================
#include "DoIpDiagnostic.h"
#include "RouteTable.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond) { std::printf ("[PASS] %s\n", what.c_str ()); ++g_pass; }
    else      { std::printf ("[FAIL] %s\n", what.c_str ()); ++g_fail; }
}

static RouteEntry mk (std::uint16_t ta, std::uint32_t tx, std::uint32_t rx, const std::string &n)
{
    RouteEntry e;
    e.logicalAddress = ta;
    e.txId = tx;
    e.rxId = rx;
    e.name = n;
    return e;
}

// 组一条 0x8001 的载荷：SA(2) + TA(2) + UDS
static std::vector<std::uint8_t> payload (std::uint16_t sa, std::uint16_t ta,
                                          const std::vector<std::uint8_t> &uds)
{
    std::vector<std::uint8_t> p = {
        static_cast<std::uint8_t> (sa >> 8), static_cast<std::uint8_t> (sa & 0xFF),
        static_cast<std::uint8_t> (ta >> 8), static_cast<std::uint8_t> (ta & 0xFF)};
    p.insert (p.end (), uds.begin (), uds.end ());
    return p;
}

int main ()
{
    // =======================================================================
    std::printf ("=== A 路由表：能进表的和不能进表的 ===\n");

    RouteTable t;
    std::string err;

    check (t.size () == 0, "空表 size = 0");
    check (t.lookup (0x0001) == nullptr, "空表查任何地址都是 nullptr");

    check (t.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err), "合法路由能加进去（TA=2 / 7E0 / 7E8）");
    check (t.size () == 1, "加一条后 size = 1");

    const RouteEntry *e = t.lookup (0x0002);
    check (e != nullptr, "查得到刚加的那条");
    check (e && e->txId == 0x7E0 && e->rxId == 0x7E8, "查出来的 TX/RX 是对的");
    check (e && e->name == "ECU_A", "名字也带出来了（日志要用）");

    check (t.add (mk (0x0003, 0x7A0, 0x7A8, "ECU_B"), err), "第二条也能加（TA=3 / 7A0 / 7A8）");
    check (t.size () == 2, "两条路由");
    check (t.known (0x0003), "known(3) = true");
    check (!t.known (0x0004), "known(4) = false（没注册过）");
    check (t.lookup (0x0004) == nullptr, "查 0x0004 得到 nullptr —— 这正是要回 0x8003 0x03 的信号");

    // ---- 拒绝：每一条都是"配置写错"，必须在加表时失败 ----
    check (!t.add (mk (0x0002, 0x700, 0x708, "x"), err), "重复的目标地址 → 拒绝");
    check (!t.add (mk (0x0000, 0x700, 0x708, "x"), err), "目标地址 0x0000 → 拒绝（标准保留值）");
    check (!t.add (mk (0x0005, 0x000, 0x708, "x"), err), "请求 ID = 0 → 拒绝");
    check (!t.add (mk (0x0005, 0x700, 0x000, "x"), err), "响应 ID = 0 → 拒绝");
    check (!t.add (mk (0x0005, 0x700, 0x700, "x"), err), "请求/响应 ID 相同 → 拒绝（回环会认错自己的帧）");
    check (!t.add (mk (0x0005, 0x7E0, 0x7E8, "x"), err), "同一对 CAN ID 被两条路由占 → 拒绝");
    check (t.size () == 2, "被拒之后表里还是 2 条（没有半成品）");

    // 29 位 ID 也走 table（按数值比），这里只确认不会被"截断"成 11 位
    RouteTable t2;
    check (t2.add (mk (0x0010, 0x18DA10F1, 0x18DAF110, "ECU29"), err), "29 位 ID 也能进表");
    check (t2.lookup (0x0010) && t2.lookup (0x0010)->txId == 0x18DA10F1, "29 位 ID 原样保存");

    // =======================================================================
    std::printf ("\n=== C ID 宽度：11 位 / 29 位 / 发帧标志位（M7）===\n");

    // C1：宽度判定 —— 0x7FF 是 11 位的顶，0x800 只能靠 29 位帧发出去
    check (!isExtendedId (0x7E0), "0x7E0 是标准帧（11 位）");
    check (!isExtendedId (0x7FF), "0x7FF 还是标准帧 —— 边界值不能判错");
    check (isExtendedId (0x800), "0x800 已经必须用扩展帧");
    check (isExtendedId (0x18DAF100), "0x18DAF100 是扩展帧");
    check (isExtendedId (kCanIdMax), "0x1FFFFFFF（29 位上限）也算扩展帧");

    // C2：合法性 —— 0 不合法，超过 29 位不合法
    check (!isValidCanId (0), "ID = 0 不合法");
    check (isValidCanId (1), "ID = 1 合法");
    check (isValidCanId (kCanIdMax), "0x1FFFFFFF 合法（正好是上限）");
    check (!isValidCanId (0x20000000), "0x20000000 超过 29 位 → 不合法");

    // C3：发帧要置位、收帧要剥位。这是 SocketCAN 最经典的一对反向操作。
    check (idForSend (0x7E0) == 0x7E0, "标准帧：发的时候原样，不带任何标志位");
    check (idForSend (0x18DA00F1) == (0x18DA00F1u | kCanEffFlag),
           "扩展帧：发的时候必须置 CAN_EFF_FLAG（否则内核回 EINVAL，帧发不出去）");
    check (idFromRecv (kCanEffFlag | 0x18DAF100) == 0x18DAF100,
           "收帧：先把 CAN_EFF_FLAG 剥掉再比，否则和 0x18DAF100 永远不相等");
    check (idFromRecv (0x40000000u | 0x7E8) == 0x7E8,
           "收帧：RTR 等高位标志也一起剥掉（不能把远程帧当成一个真 ID）");

    // C4：日志里宽度要看得出（3 位 vs 8 位）
    check (formatCanId (0x7E0) == "0x7E0", "标准 ID 打成 3 位：0x7E0");
    check (formatCanId (0x18DAF100) == "0x18DAF100", "扩展 ID 打成 8 位：0x18DAF100");

    // C5：超范围配置必须在加表时就被拒，而且错因要说"超 29 位"，不是笼统的"写错了"
    {
        RouteTable t5;
        check (!t5.add (mk (0x0020, 0x20000000, 0x20000001, "x"), err),
               "ID 超过 29 位 → 加表时直接拒绝");
        check (err.find ("29") != std::string::npos, "错误信息点名 29 位上限（不然人会去查总线）");
        check (t5.size () == 0, "被拒之后表还是空的");

        check (t5.add (mk (0x0021, kCanIdMax, kCanIdMax - 1, "EDGE"), err),
               "0x1FFFFFFF 作为边界值能进表");
        check (t5.lookup (0x0021) && t5.lookup (0x0021)->txId == kCanIdMax, "边界值原样保存");
    }

    // C6：一张表里混着 11 位和 29 位两条 ECU —— 这是 M7 要支持的常态
    {
        RouteTable t6;
        check (t6.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err), "混表：标准帧那条能加");
        check (t6.add (mk (0x0003, 0x18DA00F1, 0x18DAF100, "ECU_B29"), err), "混表：扩展帧那条也能加");
        check (t6.size () == 2, "混表里两条并存");
        check (!isExtendedId (t6.lookup (0x0002)->txId), "混表：第一条确实是 11 位");
        check (isExtendedId (t6.lookup (0x0003)->txId), "混表：第二条确实是 29 位");
    }

    // =======================================================================
    std::printf ("\n=== D 功能寻址：谁在听广播（M8）===\n");

    // D1：功能地址段。ISO 13400 把 0xE000–0xE3FF 留给 ISO/SAE 功能组，
    //     0xE400–0xEFFF 才是厂商自定义功能组（0xE400 是业界最常用的那个）。
    check (!isFunctionalAddressRange (0x0DFF), "0x0DFF 还是物理地址段");
    check (isFunctionalAddressRange (0xE000), "0xE000 起进入功能地址段");
    check (isFunctionalAddressRange (0xEFFF), "0xEFFF 是功能段的上边界");
    check (!isFunctionalAddressRange (0xF000), "0xF000 已经不是功能段");
    check (!isVendorFunctionalAddress (0xE000), "0xE000 是 ISO/SAE 保留的功能组，厂商不能随便用");
    check (!isVendorFunctionalAddress (0xE3FF), "0xE3FF 仍在保留区");
    check (isVendorFunctionalAddress (0xE400), "0xE400 才是厂商自定义功能组的起点");
    check (isVendorFunctionalAddress (0xEFFF), "0xEFFF 仍是厂商自定义段");

    // D2：正常的一对（功能地址 + 广播 ID）
    {
        RouteTable t;
        FunctionalRoute f;
        f.logicalAddress = 0xE400;
        f.txId           = 0x7DF;
        f.name           = "ALL";
        check (t.addFunctional (f, err), "0xE400 → 0x7DF 能进功能表");
        check (t.sizeFunctional () == 1, "功能表里一条");
        check (t.size () == 0, "功能路由不会跑进物理表（两张表是分开的）");
        check (t.lookupFunctional (0xE400) != nullptr, "按功能地址能查到它");
        check (t.lookupFunctional (0xE400)->txId == 0x7DF, "查到的广播 ID 是 0x7DF");
    }

    // D3：该拒的都要拒，且错误信息要说清"为什么"
    {
        RouteTable t;
        FunctionalRoute f;
        f.logicalAddress = 0x0002;      // 物理地址段
        f.txId           = 0x7DF;
        check (!t.addFunctional (f, err), "物理地址不能当功能地址");
        check (err.find ("功能地址段") != std::string::npos, "错误信息点明功能地址段");

        FunctionalRoute g;
        g.logicalAddress = 0xE000;      // ISO/SAE 保留
        g.txId           = 0x7DF;
        check (!t.addFunctional (g, err), "0xE000 是 WWH-OBD 保留的功能组，拒绝");
        check (err.find ("0xE400") != std::string::npos, "错误信息告诉人该从 0xE400 起");

        FunctionalRoute h;
        h.logicalAddress = 0xE400;
        h.txId           = 0u;
        check (!t.addFunctional (h, err), "广播 ID = 0 不合法");

        h.txId = 0x20000000u;           // 超过 29 位
        check (!t.addFunctional (h, err), "广播 ID 超过 29 位 → 拒绝");
        check (err.find ("29") != std::string::npos, "错误信息点名 29 位上限");

        FunctionalRoute a, b;
        a.logicalAddress = 0xE400; a.txId = 0x7DF;
        b.logicalAddress = 0xE400; b.txId = 0x7E0;
        check (t.addFunctional (a, err), "第一条功能路由进表");
        check (!t.addFunctional (b, err), "同一个功能地址不能注册两次");
        check (t.sizeFunctional () == 1, "被拒之后没有半成品");

        // 两条功能路由共用一个广播 ID：等于两个功能组抢同一个喇叭
        RouteTable t2;
        FunctionalRoute c;
        c.logicalAddress = 0xE401; c.txId = 0x7DF;
        check (t2.addFunctional (a, err), "t2：0xE400 → 0x7DF");
        check (!t2.addFunctional (c, err), "t2：同一个广播 ID 不能再给第二个功能地址");
        check (t2.sizeFunctional () == 1, "t2：被拒之后还是一条");
    }

    // D4：物理表和功能表不能互相踩 —— 这两条是 M8 最容易配错的地方
    {
        RouteTable t;
        check (t.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err), "先加一条物理路由");

        FunctionalRoute f;
        f.logicalAddress = 0xE400;
        f.txId           = 0x7E0;       // 拿物理请求 ID 当广播 ID
        check (!t.addFunctional (f, err), "广播 ID 不能和物理路由的 ID 撞");
        check (err.find ("物理路由") != std::string::npos, "错误信息点明是物理路由占着");

        FunctionalRoute g;
        g.logicalAddress = 0xE400;
        g.txId           = 0x7DF;
        check (t.addFunctional (g, err), "换回 0x7DF 就能进表");

        // 反过来：物理路由想占用广播 ID（比如把某台 ECU 的 rx 写成 0x7DF）
        check (!t.add (mk (0x0003, 0x7D0, 0x7DF, "BAD"), err),
               "物理路由的 ID 不能占用广播 ID");
        check (err.find ("广播") != std::string::npos, "错误信息点明广播 ID");

        // 功能地址也不能出现在物理表里
        check (!t.add (mk (0xE400, 0x7A0, 0x7A8, "CONFUSED"), err),
               "功能地址不能写进物理路由");
    }

    // D5：一张表里"物理 + 功能"并存，reachable() 是网关用来判断"这地址我能不能到"的
    {
        RouteTable t;
        check (t.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err), "物理那条");
        FunctionalRoute f;
        f.logicalAddress = 0xE400;
        f.txId           = 0x7DF;
        check (t.addFunctional (f, err), "功能那条");
        check (t.reachable (0x0002), "物理地址 reachable");
        check (t.reachable (0xE400), "功能地址也 reachable（否则一上来就被 0x03 拒了）");
        check (!t.reachable (0x0009), "表里没有的地址 reachable = false");
        check (t.known (0x0002) && !t.known (0xE400), "known() 只认物理表（功能地址不算物理目标）");
        check (!t.knownFunctional (0x0002), "knownFunctional() 只认功能表");
    }

    // D6：29 位广播 ID（0x18DB33F1）也能进功能表 —— M7 的宽度和 M8 的广播是能叠的
    {
        RouteTable t;
        FunctionalRoute f;
        f.logicalAddress = 0xE401;
        f.txId           = 0x18DB33F1u;
        check (t.addFunctional (f, err), "29 位广播 ID 0x18DB33F1 能进功能表");
        check (isExtendedId (t.lookupFunctional (0xE401)->txId), "它确实是扩展帧");
        check (formatCanId (t.lookupFunctional (0xE401)->txId) == "0x18DB33F1", "日志里打成 8 位");
    }

    // =======================================================================
    std::printf ("\n=== B 通道语义：谁会被告知\"目标地址未知\" ===\n");

    const std::uint16_t SA = 0x0E00, ENTITY = 0x0001;
    const std::vector<std::uint8_t> uds = {0x22, 0xF1, 0x90};

    // B1：没配 targetKnown —— 退回 M3 的老语义：只认实体自己的地址
    {
        DiagnosticChannel ch{DiagnosticPolicy{ENTITY, 512, nullptr}};
        auto o1 = ch.handle (payload (SA, ENTITY, uds), true, SA);
        check (o1.action == DiagAction::AckAndForward, "老语义：TA=实体地址 → 受理");

        auto o2 = ch.handle (payload (SA, 0x0002, uds), true, SA);
        check (o2.action == DiagAction::Nack &&
               o2.code == static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress),
               "老语义：TA=别的地址 → 0x8003 0x03");
    }

    // B2：配了 targetKnown（模拟网关查路由表）
    {
        RouteTable t3;
        t3.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err);
        t3.add (mk (0x0003, 0x7A0, 0x7A8, "ECU_B"), err);

        const auto known = [&t3] (std::uint16_t ta) { return t3.known (ta); };
        DiagnosticChannel ch{DiagnosticPolicy{ENTITY, 512, known}};

        auto a = ch.handle (payload (SA, 0x0002, uds), true, SA);
        check (a.action == DiagAction::AckAndForward, "TA=0x0002（表里有）→ 受理，交给下游");
        check (a.targetAddress == 0x0002 && a.uds == uds, "受理时把 TA 和 UDS 原样带下去（网关靠 TA 选通道）");

        auto b = ch.handle (payload (SA, 0x0003, uds), true, SA);
        check (b.action == DiagAction::AckAndForward, "TA=0x0003（表里有）→ 受理");

        auto c = ch.handle (payload (SA, 0x0004, uds), true, SA);
        check (c.action == DiagAction::Nack &&
               c.code == static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress),
               "TA=0x0004（表里没有）→ 0x8003 0x03");

        // 实体自己的地址此时**不在表里**：网关不提供 UDS 服务，照 0x03 拒
        auto d = ch.handle (payload (SA, ENTITY, uds), true, SA);
        check (d.action == DiagAction::Nack &&
               d.code == static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress),
               "实体自身地址不在表里 → 也是 0x03（网关没有自己的 UDS 服务，不假装有）");
    }

    // B3：判据顺序 —— 顺序错了码就错了，客户端会照着错码去排查
    {
        RouteTable t4;
        t4.add (mk (0x0002, 0x7E0, 0x7E8, "ECU_A"), err);
        const auto known = [&t4] (std::uint16_t ta) { return t4.known (ta); };
        DiagnosticChannel ch{DiagnosticPolicy{ENTITY, 512, known}};

        auto u = ch.handle (payload (SA, 0x0004, uds), false, SA);   // 没激活 + 未知地址
        check (u.code == static_cast<std::uint8_t> (DiagNack::InvalidSourceAddress),
               "没激活 + 未知地址 → 先报 0x02（没激活是更前置的问题）");

        auto s = ch.handle (payload (0x0E01, 0x0004, uds), true, SA); // 冒用 SA + 未知地址
        check (s.code == static_cast<std::uint8_t> (DiagNack::InvalidSourceAddress),
               "SA 对不上 + 未知地址 → 也先报 0x02（身份先于地址）");

        std::vector<std::uint8_t> big (600, 0xAA);
        auto l = ch.handle (payload (SA, 0x0004, big), true, SA);    // 未知地址 + 超长
        check (l.code == static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress),
               "未知地址 + 超长 → 先报 0x03（地址这关过不了，长度还轮不到）");

        auto m = ch.handle (payload (SA, 0x0002, big), true, SA);    // 已知地址 + 超长
        check (m.code == static_cast<std::uint8_t> (DiagNack::MessageTooLarge),
               "已知地址 + 超长 → 才轮到 0x04");
    }

    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
        std::printf ("M6+M7+M8 全绿 —— 地址不认识就拒绝，ID 宽度不许猜，广播 ID 不许抢。\n");
    return g_fail == 0 ? 0 : 1;
}
