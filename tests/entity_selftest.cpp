// ============================================================================
// entity_selftest.cpp —— M14 的纯逻辑自测（实体状态 / 电源模式）
//
// 这一层只有"编码 7 个字节 + 两条请求的判断"，但错法很具体：
//   · 4 字节字段按小端写 → 诊断仪读出来是 4096 变成 0x00100000；
//   · 只认 7 字节 → 碰上只发 3 字节的实体就"解不开"；
//   · 0x4001 带载荷还照回 → 等于默许"请求里塞垃圾"，以后没人按标准写；
//   · max/cur 超过 255 不压 → 1 字节里回绕，日志和实际对不上；
//   · 电源模式 0x03 猜成 ready → 让人以为车能做诊断，实际连不上。
// 每条都在下面走到。
//
// 用法：./entity-selftest        全绿时退出码 0
// ============================================================================
#include "DoIpEntityStatus.h"

#include <cstdio>
#include <string>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ());     \
        }                                                              \
    } while (0)

int main ()
{
    // ---- A. 编码布局：7 字节，字段顺序和大端都不能错 ----
    {
        EntityStatusInfo s;
        s.nodeType       = kNodeTypeGateway;
        s.maxOpenSockets = 8;
        s.curOpenSockets = 3;
        s.maxDataSize    = 4096;             // 0x00001000
        auto p = encodePayload (s);
        CHECK (p.size () == kEntityStatusFull, "0x4002 载荷是 7 字节");
        CHECK (p[0] == 0x00, "第 1 字节：node type = 0x00 网关");
        CHECK (p[1] == 0x08, "第 2 字节：最大 socket 数 = 8");
        CHECK (p[2] == 0x03, "第 3 字节：当前开着 3 条");
        // 4096 大端 = 00 00 10 00。写成小端就成了 00 10 00 00，值是 1048576。
        CHECK (p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x10 && p[6] == 0x00,
               "第 4–7 字节：max data size 4096 按大端 = 00 00 10 00");
    }

    // ---- B. 往返：编码再解码，四个字段一个不差 ----
    {
        EntityStatusInfo s;
        s.nodeType       = kNodeTypeNode;
        s.maxOpenSockets = 4;
        s.curOpenSockets = 1;
        s.maxDataSize    = 65535;
        EntityStatusInfo back;
        std::string err;
        CHECK (decodePayload (encodePayload (s), back, err), "自己编码的载荷解得开");
        CHECK (back.nodeType == kNodeTypeNode, "node type 回来是 0x01 节点");
        CHECK (back.maxOpenSockets == 4 && back.curOpenSockets == 1, "socket 两个数回来不变");
        CHECK (back.maxDataSize == 65535, "max data size 回来不变");
        CHECK (err.empty (), "正常解码不产生错误文本");
    }

    // ---- C. 3 字节短式：老实现只发这三个字段，要把"没告知"当成 0 ----
    {
        EntityStatusInfo back;
        std::string err;
        CHECK (decodePayload ({0x00, 0x08, 0x02}, back, err), "3 字节短载荷也要认得");
        CHECK (back.maxDataSize == 0, "短载荷没有第 4 字段 → maxDataSize = 0（未告知，不猜 4096）");
        CHECK (back.maxOpenSockets == 8 && back.curOpenSockets == 2, "前三个字段照读");
    }

    // ---- D. 长度不对：2 / 5 / 8 字节都解不开，不"尽量猜" ----
    {
        EntityStatusInfo back;
        std::string err;
        CHECK (!decodePayload ({0x00, 0x08}, back, err), "2 字节 → 解不开");
        CHECK (!decodePayload ({0x00, 0x08, 0x00, 0x00, 0x00}, back, err), "5 字节 → 解不开");
        CHECK (!decodePayload ({0, 0, 0, 0, 0x10, 0x00, 0x00, 0x00}, back, err), "8 字节 → 解不开");
        CHECK (!err.empty (), "失败时要带上原因（现场靠这句话定位）");
    }

    // ---- E. 电源模式：三个定义值 + 保留值拒绝 ----
    {
        PowerModeInfo m;
        std::string err;
        m.mode = kPowerReady;
        CHECK (encodePayload (m).size () == 1, "0x4004 载荷是 1 字节");
        CHECK (encodePayload (m)[0] == 0x01, "ready 编成 0x01");

        PowerModeInfo back;
        CHECK (decodePayload ({0x00}, back, err) && back.mode == kPowerNotReady, "0x00 → not ready");
        CHECK (decodePayload ({0x01}, back, err) && back.mode == kPowerReady, "0x01 → ready");
        CHECK (decodePayload ({0x02}, back, err) && back.mode == kPowerNotSupported, "0x02 → not supported");
        CHECK (!decodePayload ({0x03}, back, err), "0x03 是保留值 → 解不开（不猜成 ready）");
        CHECK (!decodePayload ({}, back, err), "空载荷 → 解不开");
        CHECK (!decodePayload ({0x01, 0x00}, back, err), "2 字节 → 解不开");
    }

    // ---- F. 0x4001 正常：回 0x4002，报文头对，载荷 7 字节 ----
    {
        EntityStatusInfo s;
        s.maxOpenSockets = 8;
        s.curOpenSockets = 0;
        s.maxDataSize    = 4096;
        PowerModeInfo pm;

        Message req;
        req.header.payloadType   = static_cast<std::uint16_t> (PayloadType::EntityStatusReq);
        req.header.payloadLength = 0;

        EntityReply r = respondToEntityQuery (req, s, pm);
        CHECK (r.replied, "0x4001 无载荷 → 一定要回");
        CHECK (r.bytes.size () == kHeaderSize + kEntityStatusFull, "整条报文 = 8 字节头 + 7 字节载荷");

        Message got;
        ParseResult pr = parseMessage (r.bytes.data (), r.bytes.size (), got);
        CHECK (pr.error == ParseError::None, "回出去的东西自己能解开");
        CHECK (toType (got.header.payloadType) == PayloadType::EntityStatusRes, "载荷类型是 0x4002 不是 0x4001");
        CHECK (got.header.payloadLength == kEntityStatusFull, "头里的长度字段 = 7");
        CHECK (got.payload.size () == kEntityStatusFull, "载荷真的 7 字节（长度字段不能只写对一半）");
    }

    // ---- G. 0x4001 带载荷：沉默（UDP 上不 NACK） ----
    {
        EntityStatusInfo s;
        PowerModeInfo pm;
        Message req;
        req.header.payloadType   = static_cast<std::uint16_t> (PayloadType::EntityStatusReq);
        req.header.payloadLength = 1;
        req.payload              = {0xAA};
        EntityReply r = respondToEntityQuery (req, s, pm);
        CHECK (!r.replied, "0x4001 带 1 字节垃圾 → 沉默");
        CHECK (r.bytes.empty (), "沉默时一个字节都不许发（UDP 上不能造 NACK）");
        CHECK (r.reason.find ("0 字节") != std::string::npos, "原因里说清楚'应该是 0 字节'");
    }

    // ---- H. 0x4003 → 0x4004，三种答案都如实带出去 ----
    {
        EntityStatusInfo s;
        Message req;
        req.header.payloadType = static_cast<std::uint16_t> (PayloadType::PowerModeReq);

        const std::uint8_t modes[] = {kPowerNotReady, kPowerReady, kPowerNotSupported};
        for (auto m : modes)
        {
            PowerModeInfo pm;
            pm.mode = m;
            EntityReply r = respondToEntityQuery (req, s, pm);
            CHECK (r.replied, "0x4003 无载荷 → 回（不管答案是哪种）");

            Message got;
            ParseResult pr = parseMessage (r.bytes.data (), r.bytes.size (), got);
            CHECK (pr.error == ParseError::None, "0x4004 自己能解开");
            CHECK (toType (got.header.payloadType) == PayloadType::PowerModeRes,
                   "回的是 0x4004，不是把请求原样弹回去");
            PowerModeInfo back;
            std::string err;
            CHECK (decodePayload (got.payload, back, err) && back.mode == m,
                   "答案原样到对面（not ready 不能被偷偷改成 ready）");
        }
    }

    // ---- I. 0x4003 带载荷：同样沉默 ----
    {
        EntityStatusInfo s;
        PowerModeInfo pm;
        Message req;
        req.header.payloadType = static_cast<std::uint16_t> (PayloadType::PowerModeReq);
        req.payload            = {0x00};
        EntityReply r = respondToEntityQuery (req, s, pm);
        CHECK (!r.replied && r.bytes.empty (), "0x4003 带 1 字节 → 沉默，且不发任何字节");
    }

    // ---- J. 其它类型：一条都不许答（发现请求也不归它管） ----
    {
        EntityStatusInfo s;
        PowerModeInfo pm;
        const PayloadType others[] = {PayloadType::VehicleIdRequest, PayloadType::RoutingActivationReq,
                                      PayloadType::AliveCheckReq, PayloadType::DiagnosticMessage};
        for (auto t : others)
        {
            Message req;
            req.header.payloadType = static_cast<std::uint16_t> (t);
            EntityReply r = respondToEntityQuery (req, s, pm);
            CHECK (!r.replied, std::string ("不是实体状态请求就不回：") + nameOf (t));
        }
    }

    // ---- K. 计数折成快照：超过 255 要压住，不能回绕 ----
    {
        auto s = entityStatusFromCounts (8, 3, 4096);
        CHECK (s.maxOpenSockets == 8 && s.curOpenSockets == 3, "正常值原样进快照");
        CHECK (s.nodeType == kNodeTypeGateway, "默认按网关报（本实体确实往 CAN 子网转）");

        auto big = entityStatusFromCounts (300, 300, 4096);
        CHECK (big.maxOpenSockets == 255, "上限 300 → 压到 255（不是回绕成 44）");
        CHECK (big.curOpenSockets == 255, "当前 300 → 也压到 255");

        auto zero = entityStatusFromCounts (8, 0, 4096);
        CHECK (zero.curOpenSockets == 0, "没有连接时报 0");
    }

    // ---- L. 边界数据：4 字节最大值往返 ----
    {
        EntityStatusInfo s;
        s.maxOpenSockets = 255;
        s.curOpenSockets = 255;
        s.maxDataSize    = 0xFFFFFFFFu;
        auto p = encodePayload (s);
        CHECK (p[3] == 0xFF && p[4] == 0xFF && p[5] == 0xFF && p[6] == 0xFF,
               "0xFFFFFFFF 大端是四个 FF");
        EntityStatusInfo back;
        std::string err;
        CHECK (decodePayload (p, back, err) && back.maxDataSize == 0xFFFFFFFFu, "最大值往返不变");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
