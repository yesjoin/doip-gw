#pragma once
// ============================================================================
// DoIpCodec.h —— DoIP 报文的字节层：8 字节头 + 各 payload 的编解码
//
// M0 的范围故意很窄：只做"字节 → 结构 → 字节"这件纯逻辑的事。
// 不碰 socket、不碰总线。理由：
//   诊断链路出问题时，九成情况是你"看不懂那串十六进制"。
//   这个文件就是那把尺子 —— 先有尺子，再谈连接。
//
// 一条铁律：**DoIP 报文里所有多字节字段一律大端（网络序，高字节在前）。**
//   这和 CAN 侧完全不是一回事：
//     - DoIP / TCP：大端，长度字段在高位
//     - DBC Intel：小端，低位字节在前
//     - DBC Motorola：从 MSB 起排，锯齿式 +15
//   三套字节序观念在同一个网关里共存，混一次就查半天。
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>

namespace doip
{

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------
constexpr std::uint8_t kVersion2012 = 0x02;   // ISO 13400-2:2012
constexpr std::uint8_t kVersion2019 = 0x03;   // ISO 13400-2:2019
constexpr std::size_t  kHeaderSize  = 8;

// 网关自定的载荷上限。真实实现里这决定"要么能处理、要么回 NACK 0x02"，
// 而不是先 malloc 一个 4GB 缓冲再被 OOM 打死。
constexpr std::uint32_t kDefaultMaxPayload = 4096;

// 版本反码：byte0 与 byte1 必须互补，用来在乱码流里快速判断"这到底是不是 DoIP"。
constexpr std::uint8_t inverseOf (std::uint8_t v)
{
    return static_cast<std::uint8_t> (0xFF - v);
}

// ---------------------------------------------------------------------------
// 载荷类型（ISO 13400-2 表）
// ---------------------------------------------------------------------------
enum class PayloadType : std::uint16_t
{
    GenericHeaderNack     = 0x0000,  // 通用头负应答（连报文都读不懂时用它说话）
    VehicleIdRequest      = 0x0001,  // 车辆识别请求
    VehicleIdRequestEid   = 0x0002,  // 带 EID 的识别请求
    VehicleIdRequestVin   = 0x0003,  // 带 VIN 的识别请求
    VehicleAnnouncement   = 0x0004,  // 车辆声明 / 识别应答
    RoutingActivationReq  = 0x0005,  // 路由激活请求
    RoutingActivationRes  = 0x0006,  // 路由激活应答
    AliveCheckReq         = 0x0007,  // 心跳检查请求
    AliveCheckRes         = 0x0008,  // 心跳检查应答
    EntityStatusReq       = 0x4001,  // 实体状态请求（本项目不实现，只认名字）
    EntityStatusRes       = 0x4002,
    PowerModeReq          = 0x4003,  // 电源模式请求（同上）
    PowerModeRes          = 0x4004,
    DiagnosticMessage     = 0x8001,  // 诊断报文（真正干活的）
    DiagnosticPositiveAck = 0x8002,  // 诊断报文正应答
    DiagnosticNegativeAck = 0x8003,  // 诊断报文负应答
};

const char *nameOf (PayloadType t);
bool        isKnown (std::uint16_t raw);
PayloadType toType (std::uint16_t raw);   // 未知值也会映射成一个值，用 isKnown 判断

// ---------------------------------------------------------------------------
// 通用头负应答的 5 个码（0x0000）
//   只有这 5 种"我看不懂你这个报文"的情形。注意它和 0x8003 不是一回事：
//   0x0000 说的是"头有问题"，0x8003 说的是"头没问题，但这条诊断我办不了"。
// ---------------------------------------------------------------------------
enum class GenericNack : std::uint8_t
{
    IncorrectPattern      = 0x00,  // 版本 / 版本反码不对
    UnknownPayloadType    = 0x01,  // 载荷类型不认识
    MessageTooLarge       = 0x02,  // 载荷太长（超过本实体上限）
    OutOfMemory           = 0x03,  // 内存不够（本实现不用，留位）
    InvalidPayloadLength  = 0x04,  // 长度字段和实际不符
};

const char *nameOf (GenericNack c);

// ---------------------------------------------------------------------------
// 头部
// ---------------------------------------------------------------------------
struct Header
{
    std::uint8_t  version       = kVersion2012;
    std::uint8_t  versionInverse = inverseOf (kVersion2012);
    std::uint16_t payloadType   = 0;
    std::uint32_t payloadLength = 0;
};

struct Message
{
    Header                    header;
    std::vector<std::uint8_t> payload;

    std::size_t totalSize () const { return kHeaderSize + payload.size (); }
};

// ---------------------------------------------------------------------------
// 解析结果
//   把"半包"和"错误"分开，是 M0 最重要的一个设计：
//     NeedMoreData —— 数据不够，**等**（TCP 上这是常态，不是故障）
//     其它错误      —— 头已经完整读到了，但有毛病，**回 NACK 然后丢弃**
//   混成一种的话，M3 做流式解析时一定出现"每隔一帧丢一帧"。
// ---------------------------------------------------------------------------
enum class ParseError : std::uint8_t
{
    None = 0,
    NeedMoreData,        // 还没凑齐，别当错误
    BadPattern,          // 版本/反码不对      → NACK 0x00
    UnknownPayloadType,  // 载荷类型不认识    → NACK 0x01
    PayloadTooLarge,     // 载荷超上限        → NACK 0x02
};

const char *nameOf (ParseError e);

struct ParseResult
{
    ParseError  error    = ParseError::None;
    std::size_t consumed = 0;   // 成功：8 + payloadLength；失败：能安全丢掉的字节数
    std::uint8_t nackCode = 0;  // error 非 None 且有头可读时，建议回的 0x0000 码
};

// 从 data[0..size) 解一条报文。
// 成功时 out 被填满，consumed = totalSize()；调用方循环 `pos += consumed` 就能解粘包。
ParseResult parseMessage (const std::uint8_t *data, std::size_t size,
                          Message &out,
                          std::uint32_t maxPayload = kDefaultMaxPayload);

// 组一条完整报文（头 + 载荷），版本默认 2012。
std::vector<std::uint8_t> build (PayloadType type,
                                 const std::vector<std::uint8_t> &payload,
                                 std::uint8_t version = kVersion2012);

// 组一条 0x0000 通用头负应答（载荷只有 1 字节码）。
std::vector<std::uint8_t> buildGenericNack (GenericNack code);

// ---------------------------------------------------------------------------
// 载荷结构（M0 只做本项目真正会用到的几种）
// ---------------------------------------------------------------------------

// 0x0004 车辆声明 / 识别应答（33 字节）
struct VehicleAnnouncement
{
    std::string               vin;            // 17 字符
    std::uint16_t             logicalAddress = 0;
    std::vector<std::uint8_t> eid;            // 6 字节实体标识
    std::vector<std::uint8_t> gid;            // 6 字节组标识
    std::uint8_t              furtherAction = 0x00;   // 还需要客户端做什么
    std::uint8_t              syncStatus   = 0x00;   // VIN/GID 同步状态
};

// 0x0005 路由激活请求（11 字节）
struct RoutingActivationRequest
{
    std::uint16_t sourceAddress  = 0;     // 客户端（tester）逻辑地址
    std::uint8_t  activationType = 0x00;  // 0x00 默认 / 0x01 WWH-OBD / 0xE0 中央安全
    std::uint32_t reserved       = 0;     // ISO 保留，填 0
    std::uint32_t oemSpecific    = 0;     // OEM 自定义，填 0
};

// 0x0006 路由激活应答（13 字节）
struct RoutingActivationResponse
{
    std::uint16_t testerAddress = 0;
    std::uint16_t entityAddress = 0;
    std::uint8_t  responseCode  = 0x10;   // 0x10 = 路由激活成功
    std::uint32_t reserved      = 0;
    std::uint32_t oemSpecific   = 0;
};

// 0x0008 心跳检查应答（2 字节）
struct AliveCheckResponse
{
    std::uint16_t sourceAddress = 0;
};

// 0x8001 诊断报文（≥4 字节）
struct DiagnosticMessage
{
    std::uint16_t             sourceAddress = 0;
    std::uint16_t             targetAddress = 0;
    std::vector<std::uint8_t> uds;           // 原样的 UDS 字节，不解析
    // ★ M28：这个字段**不是报文的一部分**，也不进编码/解码。
    //   它是网关内部从连接上下文带下来的"谁"（槽号 0 = 不知道）。
    //   放这里是因为它必须跟着请求一路走：TCP 进来 → 网关排队 → CAN 发出，
    //   只有一路带着它，下游（worker）才有东西可写成 CAN 源地址。
    std::uint8_t              actorSlot = 0;
};

// 0x8002 诊断正应答（5 字节）
struct DiagnosticPositiveAck
{
    std::uint16_t sourceAddress = 0;
    std::uint16_t targetAddress = 0;
    std::uint8_t  ackCode       = 0x00;
};

// 0x8003 诊断负应答（≥5 字节，可带回原报文前若干字节）
struct DiagnosticNegativeAck
{
    std::uint16_t             sourceAddress = 0;
    std::uint16_t             targetAddress = 0;
    std::uint8_t              nackCode      = 0;
    std::vector<std::uint8_t> previous;      // 可选：原始诊断载荷的前 N 字节
};

// 编码：结构 → payload 字节（不含 8 字节头）
std::vector<std::uint8_t> encodePayload (const VehicleAnnouncement &v);
std::vector<std::uint8_t> encodePayload (const RoutingActivationRequest &v);
std::vector<std::uint8_t> encodePayload (const RoutingActivationResponse &v);
std::vector<std::uint8_t> encodePayload (const AliveCheckResponse &v);
std::vector<std::uint8_t> encodePayload (const DiagnosticMessage &v);
std::vector<std::uint8_t> encodePayload (const DiagnosticPositiveAck &v);
std::vector<std::uint8_t> encodePayload (const DiagnosticNegativeAck &v);

// 解码：payload 字节 → 结构。长度不对就填 err 并返回 false（不做"猜"）。
bool decodePayload (const std::vector<std::uint8_t> &p, VehicleAnnouncement &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, RoutingActivationRequest &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, RoutingActivationResponse &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, AliveCheckResponse &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticMessage &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticPositiveAck &out, std::string &err);
bool decodePayload (const std::vector<std::uint8_t> &p, DiagnosticNegativeAck &out, std::string &err);

} // namespace doip
