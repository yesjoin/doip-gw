// ============================================================================
// DoIpCodec.cpp —— M0 的实现
//
// 这个文件里最值得看的是两个小函数：put16 / read16 和 put32 / read32。
// 大端的意思就是：**高字节先走**。
//   0x0E00 这个逻辑地址，线上是 0E 00 两个字节，不是 00 0E。
// 把它写成一对函数，而不是到处 `data[i] << 8 | data[i+1]`，是为了：
//   ① 只有一处会写错；② 写错了改一处；③ 测试只测这一处。
// ============================================================================
#include "DoIpCodec.h"

#include <cstring>

namespace doip
{
namespace
{

// ---- 大端读写：整个协议只允许从这里进出 ----
void put16 (std::vector<std::uint8_t> &b, std::uint16_t v)
{
    b.push_back (static_cast<std::uint8_t> ((v >> 8) & 0xFF));
    b.push_back (static_cast<std::uint8_t> (v & 0xFF));
}

void put32 (std::vector<std::uint8_t> &b, std::uint32_t v)
{
    b.push_back (static_cast<std::uint8_t> ((v >> 24) & 0xFF));
    b.push_back (static_cast<std::uint8_t> ((v >> 16) & 0xFF));
    b.push_back (static_cast<std::uint8_t> ((v >> 8) & 0xFF));
    b.push_back (static_cast<std::uint8_t> (v & 0xFF));
}

std::uint16_t read16 (const std::uint8_t *p)
{
    return static_cast<std::uint16_t> ((static_cast<std::uint16_t> (p[0]) << 8) |
                                       static_cast<std::uint16_t> (p[1]));
}

std::uint32_t read32 (const std::uint8_t *p)
{
    return (static_cast<std::uint32_t> (p[0]) << 24) |
           (static_cast<std::uint32_t> (p[1]) << 16) |
           (static_cast<std::uint32_t> (p[2]) << 8) |
           (static_cast<std::uint32_t> (p[3]));
}

} // namespace

// ---------------------------------------------------------------------------
const char *nameOf (PayloadType t)
{
    switch (t)
    {
    case PayloadType::GenericHeaderNack:     return "0x0000 Generic header negative acknowledge";
    case PayloadType::VehicleIdRequest:      return "0x0001 Vehicle identification request";
    case PayloadType::VehicleIdRequestEid:   return "0x0002 Vehicle identification request with EID";
    case PayloadType::VehicleIdRequestVin:   return "0x0003 Vehicle identification request with VIN";
    case PayloadType::VehicleAnnouncement:   return "0x0004 Vehicle announcement / identification response";
    case PayloadType::RoutingActivationReq:  return "0x0005 Routing activation request";
    case PayloadType::RoutingActivationRes:  return "0x0006 Routing activation response";
    case PayloadType::AliveCheckReq:         return "0x0007 Alive check request";
    case PayloadType::AliveCheckRes:         return "0x0008 Alive check response";
    case PayloadType::EntityStatusReq:       return "0x4001 DoIP entity status request";
    case PayloadType::EntityStatusRes:       return "0x4002 DoIP entity status response";
    case PayloadType::PowerModeReq:          return "0x4003 Diagnostic power mode information request";
    case PayloadType::PowerModeRes:          return "0x4004 Diagnostic power mode information response";
    case PayloadType::DiagnosticMessage:     return "0x8001 Diagnostic message";
    case PayloadType::DiagnosticPositiveAck: return "0x8002 Diagnostic message positive acknowledgement";
    case PayloadType::DiagnosticNegativeAck: return "0x8003 Diagnostic message negative acknowledgement";
    }
    return "unknown";
}

bool isKnown (std::uint16_t raw)
{
    switch (raw)
    {
    case 0x0000: case 0x0001: case 0x0002: case 0x0003: case 0x0004:
    case 0x0005: case 0x0006: case 0x0007: case 0x0008:
    case 0x4001: case 0x4002: case 0x4003: case 0x4004:
    case 0x8001: case 0x8002: case 0x8003:
        return true;
    default:
        return false;
    }
}

PayloadType toType (std::uint16_t raw)
{
    return static_cast<PayloadType> (raw);
}

const char *nameOf (GenericNack c)
{
    switch (c)
    {
    case GenericNack::IncorrectPattern:     return "incorrect pattern format（版本或反码不对）";
    case GenericNack::UnknownPayloadType:   return "unknown payload type（载荷类型不认识）";
    case GenericNack::MessageTooLarge:      return "message too large（载荷超过本实体上限）";
    case GenericNack::OutOfMemory:          return "out of memory（内存不足）";
    case GenericNack::InvalidPayloadLength: return "invalid payload length（长度字段与实际不符）";
    }
    return "unknown";
}

const char *nameOf (ParseError e)
{
    switch (e)
    {
    case ParseError::None:               return "ok";
    case ParseError::NeedMoreData:       return "need more data（半包，接着等）";
    case ParseError::BadPattern:         return "bad pattern（版本/反码不对）";
    case ParseError::UnknownPayloadType: return "unknown payload type（类型不认识）";
    case ParseError::PayloadTooLarge:    return "payload too large（超上限）";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------
ParseResult parseMessage (const std::uint8_t *data, std::size_t size,
                          Message &out,
                          std::uint32_t maxPayload)
{
    ParseResult r;

    // ① 头都没凑齐：什么都判断不了。
    //    注意这里**不能**回 NACK —— 你连版本字节都还没读到，
    //    凭啥说人家"格式不对"？TCP 上正确的动作是等更多数据。
    if (size < kHeaderSize)
    {
        r.error = ParseError::NeedMoreData;
        return r;
    }

    const std::uint8_t  ver     = data[0];
    const std::uint8_t  verInv  = data[1];
    const std::uint16_t type    = read16 (data + 2);
    const std::uint32_t len     = read32 (data + 4);

    // ② 版本 + 反码：这一对互相取反，是 DoIP 的"魔数"。
    //    只认 0x02 / 0x03 两个版本；反码对不上就说明这串字节能不一定是 DoIP。
    if (verInv != inverseOf (ver) || (ver != kVersion2012 && ver != kVersion2019))
    {
        r.error    = ParseError::BadPattern;
        r.consumed = kHeaderSize;
        r.nackCode = static_cast<std::uint8_t> (GenericNack::IncorrectPattern);
        return r;
    }

    // ③ 类型不认识：头是好的，但载荷语义未知，无法跳过。
    //    按规范回 NACK 0x01，随后这条连接上的字节流不能再信（M3 会处理成"断开重连"）。
    if (!isKnown (type))
    {
        r.error    = ParseError::UnknownPayloadType;
        r.consumed = kHeaderSize;
        r.nackCode = static_cast<std::uint8_t> (GenericNack::UnknownPayloadType);
        return r;
    }

    // ④ 长度超上限：**在 malloc 之前就拦住**。
    //    这一条是防护，不是格式错误 —— 恶意客户端只要写长度 0xFFFFFFFF，
    //    不检查的话你就先申请 4GB 然后再想"要不要处理"。
    if (len > maxPayload)
    {
        r.error    = ParseError::PayloadTooLarge;
        r.consumed = kHeaderSize;
        r.nackCode = static_cast<std::uint8_t> (GenericNack::MessageTooLarge);
        return r;
    }

    // ⑤ 载荷还没到齐：帧头说 16 字节，实际只给了 6 字节 —— 这就是"半包"。
    //    它**不是错误**，是 TCP 的日常。consumed = 0 表示"一个字节都别丢"。
    if (size < kHeaderSize + static_cast<std::size_t> (len))
    {
        r.error = ParseError::NeedMoreData;
        return r;
    }

    out.header.version        = ver;
    out.header.versionInverse = verInv;
    out.header.payloadType    = type;
    out.header.payloadLength  = len;
    out.payload.assign (data + kHeaderSize, data + kHeaderSize + len);

    r.error    = ParseError::None;
    r.consumed = kHeaderSize + len;
    return r;
}

// ---------------------------------------------------------------------------
// 组包
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> build (PayloadType type,
                                 const std::vector<std::uint8_t> &payload,
                                 std::uint8_t version)
{
    std::vector<std::uint8_t> b;
    b.reserve (kHeaderSize + payload.size ());
    b.push_back (version);
    b.push_back (inverseOf (version));
    put16 (b, static_cast<std::uint16_t> (type));
    put32 (b, static_cast<std::uint32_t> (payload.size ()));
    b.insert (b.end (), payload.begin (), payload.end ());
    return b;
}

std::vector<std::uint8_t> buildGenericNack (GenericNack code)
{
    std::vector<std::uint8_t> p;
    p.push_back (static_cast<std::uint8_t> (code));
    return build (PayloadType::GenericHeaderNack, p);
}

// ---------------------------------------------------------------------------
// 0x0004 车辆声明 / 识别应答
//   线上布局（33 字节）：
//     VIN(17) | 逻辑地址(2) | EID(6) | GID(6) | further action(1) | 同步状态(1)
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const VehicleAnnouncement &v)
{
    std::vector<std::uint8_t> p;
    p.reserve (33);

    // VIN 固定 17 字符：多了截、少了补空格。规范上 VIN 就该是 17 位，
    // 这里补空格只是为了不让"少一位"变成线上长度错位。
    std::string vin = v.vin;
    if (vin.size () > 17) vin.resize (17);
    while (vin.size () < 17) vin.push_back (' ');
    p.insert (p.end (), vin.begin (), vin.end ());

    put16 (p, v.logicalAddress);

    std::vector<std::uint8_t> eid = v.eid;
    eid.resize (6, 0x00);
    p.insert (p.end (), eid.begin (), eid.end ());

    std::vector<std::uint8_t> gid = v.gid;
    gid.resize (6, 0x00);
    p.insert (p.end (), gid.begin (), gid.end ());

    p.push_back (v.furtherAction);
    p.push_back (v.syncStatus);
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, VehicleAnnouncement &out, std::string &err)
{
    if (p.size () != 33)
    {
        err = "0x0004 应为 33 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.vin.assign (p.begin (), p.begin () + 17);
    out.logicalAddress = read16 (p.data () + 17);
    out.eid.assign (p.begin () + 19, p.begin () + 25);
    out.gid.assign (p.begin () + 25, p.begin () + 31);
    out.furtherAction = p[31];
    out.syncStatus    = p[32];
    return true;
}

// ---------------------------------------------------------------------------
// 0x0005 路由激活请求
//   11 字节 = SA(2) + 类型(1) + reserved(4) + OEM(4)   ← ISO 13400-2:2019
//    7 字节 = SA(2) + 类型(1) + reserved(4)            ← 早期版本/部分客户端
// 接收侧两种都收（第三方客户端 doipclient 发的是 7 字节那种），发送侧只发 11 字节。
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const RoutingActivationRequest &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.sourceAddress);
    p.push_back (v.activationType);
    put32 (p, v.reserved);
    put32 (p, v.oemSpecific);
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, RoutingActivationRequest &out, std::string &err)
{
    if (p.size () != 11 && p.size () != 7)
    {
        err = "0x0005 应为 11 或 7 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.sourceAddress  = read16 (p.data ());
    out.activationType = p[2];
    out.reserved       = read32 (p.data () + 3);
    out.oemSpecific    = (p.size () == 11) ? read32 (p.data () + 7) : 0;
    return true;
}

// ---------------------------------------------------------------------------
// 0x0006 路由激活应答（13 字节）
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const RoutingActivationResponse &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.testerAddress);
    put16 (p, v.entityAddress);
    p.push_back (v.responseCode);
    put32 (p, v.reserved);
    put32 (p, v.oemSpecific);
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, RoutingActivationResponse &out, std::string &err)
{
    if (p.size () != 13)
    {
        err = "0x0006 应为 13 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.testerAddress = read16 (p.data ());
    out.entityAddress = read16 (p.data () + 2);
    out.responseCode  = p[4];
    out.reserved      = read32 (p.data () + 5);
    out.oemSpecific   = read32 (p.data () + 9);
    return true;
}

// ---------------------------------------------------------------------------
// 0x0008 心跳检查应答（2 字节）
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const AliveCheckResponse &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.sourceAddress);
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, AliveCheckResponse &out, std::string &err)
{
    if (p.size () != 2)
    {
        err = "0x0008 应为 2 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.sourceAddress = read16 (p.data ());
    return true;
}

// ---------------------------------------------------------------------------
// 0x8001 诊断报文（源地址 2 + 目标地址 2 + UDS 原样）
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const DiagnosticMessage &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.sourceAddress);
    put16 (p, v.targetAddress);
    p.insert (p.end (), v.uds.begin (), v.uds.end ());
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticMessage &out, std::string &err)
{
    if (p.size () < 4)
    {
        err = "0x8001 至少 4 字节（源地址 + 目标地址），实际 " + std::to_string (p.size ());
        return false;
    }
    out.sourceAddress = read16 (p.data ());
    out.targetAddress = read16 (p.data () + 2);
    out.uds.assign (p.begin () + 4, p.end ());
    return true;
}

// ---------------------------------------------------------------------------
// 0x8002 诊断正应答（5 字节）
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const DiagnosticPositiveAck &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.sourceAddress);
    put16 (p, v.targetAddress);
    p.push_back (v.ackCode);   // 正应答码固定 0x00
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticPositiveAck &out, std::string &err)
{
    if (p.size () != 5)
    {
        err = "0x8002 应为 5 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.sourceAddress = read16 (p.data ());
    out.targetAddress = read16 (p.data () + 2);
    out.ackCode       = p[4];
    return true;
}

// ---------------------------------------------------------------------------
// 0x8003 诊断负应答（≥5 字节，第 6 字节起可带回原载荷）
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encodePayload (const DiagnosticNegativeAck &v)
{
    std::vector<std::uint8_t> p;
    put16 (p, v.sourceAddress);
    put16 (p, v.targetAddress);
    p.push_back (v.nackCode);
    p.insert (p.end (), v.previous.begin (), v.previous.end ());
    return p;
}

bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticNegativeAck &out, std::string &err)
{
    if (p.size () < 5)
    {
        err = "0x8003 至少 5 字节，实际 " + std::to_string (p.size ());
        return false;
    }
    out.sourceAddress = read16 (p.data ());
    out.targetAddress = read16 (p.data () + 2);
    out.nackCode      = p[4];
    out.previous.assign (p.begin () + 5, p.end ());
    return true;
}

} // namespace doip
