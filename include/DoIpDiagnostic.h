#pragma once
// ============================================================================
// DoIpDiagnostic.h —— M3：诊断报文通道（0x8001 收下 → 校验 → 回执 → 交下游）
//
// M2 里 0x8001 只被"看一眼就扔"，因为那时还没有通道。M3 把它补成一条真正的通路：
//
//   客户端 ── 0x8001（SA/TA/UDS）──►  本实体
//                                     │ ① 这条连接激活了吗？SA 是它吗？
//                                     │ ② 目标地址是我吗？
//                                     │ ③ UDS 长度超上限了吗？
//                                     ▼
//         ◄── 0x8002 正应答（收下了）──
//         ◄── 0x8001 响应（UDS 应答）──   ← 下游给什么就送什么
//
// 三个设计决定：
//   ① **先回应答，再算业务**：0x8002 的含义是"报文收到且已受理"，不是"诊断做完了"。
//      做完的结果另用一条 0x8001 送回去。混成一条会让客户端分不清"没收到"和"收到了但超时"。
//   ② **通道不碰 UDS 语义**：UDS 正/负响应（0x62/0x7F）是 ECU 的事，这里只搬字节。
//      DoIP 层去解析 UDS 会让"哪一层出错"变得说不清。
//   ③ **下游是可替换的函数**：M3 用假 ECU 桩，M4 换成真的 ISO-TP，通道代码一个字不改。
//
// 码值来源（不是猜的）：
//   0x8002 ack code 只有 0x00 = ACK；
//   0x8003 nack code：0x02 源地址非法 / 0x03 目标地址未知 / 0x04 报文太大 /
//                     0x05 内存不足 / 0x06 目标不可达 / 0x07 网络未知 / 0x08 传输层错误
// ============================================================================
#include "DoIpCodec.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace doip
{

// 0x8003 的 nack 码（本项目只用到其中几个，但整张表都写出来，省得下次再查）
enum class DiagNack : std::uint8_t
{
    InvalidSourceAddress    = 0x02,   // 源地址不在本连接的注册信息里
    UnknownTargetAddress    = 0x03,   // 目标地址我不认识（不归我，也不在路由表里）
    MessageTooLarge         = 0x04,   // UDS 数据超过本实体上限
    OutOfMemory             = 0x05,   // 内存不足（本实现留位）
    TargetUnreachable       = 0x06,   // 目标存在但此刻不可达
    UnknownNetwork          = 0x07,   // 目标网络未知（多网段网关才用）
    TransportProtocolError  = 0x08,   // 下游传输层出错
};

const char *nameOf (DiagNack c);

struct DiagnosticPolicy
{
    std::uint16_t entityAddress = 0x0001;
    std::size_t   maxUds        = 512;    // 超过 → 0x8003 0x04

    // M6：什么算"本实体能到达的目标地址"。
    //   为空时按老规则：只认 entityAddress 自己（M3 的语义）。
    //   网关会把它接到路由表上：TA 在表里 → 能到；不在 → 0x8003 0x03。
    //   放在策略层而不是"等 CAN 失败再报 0x08"，因为 0x03 是**地址判定**，
    //   不是传输故障——地址错要在发出去之前就说清楚。
    std::function<bool (std::uint16_t)> targetKnown;
};

enum class DiagAction : std::uint8_t
{
    AckAndForward,      // 回 0x8002 0x00，然后把 UDS 交给下游
    Nack,               // 回 0x8003
};

struct DiagOutcome
{
    DiagAction                action = DiagAction::Nack;
    std::uint8_t              code   = 0;      // AckAndForward：0x8002 的 ackCode；Nack：0x8003 的 nackCode
    std::uint16_t             sourceAddress = 0;   // 来自请求
    std::uint16_t             targetAddress = 0;   // 来自请求
    std::vector<std::uint8_t> uds;
    std::string               reason;
};

// 一条诊断请求的判定。纯逻辑：不碰 socket、不碰下游。
class DiagnosticChannel
{
public:
    explicit DiagnosticChannel (const DiagnosticPolicy &p = DiagnosticPolicy{});

    // activated / activatedSource 来自这条连接的 RoutingActivation。
    DiagOutcome handle (const std::vector<std::uint8_t> &payload,
                        bool activated,
                        std::uint16_t activatedSource);

private:
    DiagnosticPolicy p_;
};

// 请求和响应用同一个结构：SA + TA + UDS 字节。名字换成"请求"只是为了读着顺。
using DiagnosticRequest = DiagnosticMessage;

// 下游：请求 → 响应字节。返回 false 表示"传输层出错"（会回 0x8003 0x08）。
using DiagnosticSink =
    std::function<bool (const DiagnosticRequest &, std::vector<std::uint8_t> &, std::string &)>;

// ---------------------------------------------------------------------------
// M8：一次请求可能回来**多条**响应（功能寻址）
//
// 为什么单响应的 sink 不够用：
//   打到 0xE400 的那一条请求，总线上有两台 ECU 各答一句。DoIP 里这是两条 0x8001，
//   而且 SA 各不相同（谁答的，SA 就是谁的逻辑地址）——只回一条就等于替其中一台说了话。
// 所以这里不是"把两条拼起来"（拼起来诊断仪就没法知道第二台也答了），
// 而是**带地址的响应列表**：SA 由网关填（应答通道的 TA），UDS 由下游填。
// ---------------------------------------------------------------------------
struct DiagnosticReply
{
    std::uint16_t             sourceAddress = 0;   // 这条应答是谁说的（通道 TA）
    std::vector<std::uint8_t> uds;
};

struct DiagnosticMultiResult
{
    bool                            ok       = false;
    std::uint8_t                    nackCode = static_cast<std::uint8_t> (DiagNack::TransportProtocolError);
    std::string                     reason;
    std::vector<DiagnosticReply>    replies;
};

using DiagnosticMultiSink = std::function<DiagnosticMultiResult (const DiagnosticRequest &)>;

// M3 用的"假 ECU"：**故意不是真的**。M4 会把它换成项目一的 ISO-TP 通道。
// 它答三件事，让链路能端到端跑通：
//   0x3E 00（TesterPresent）  → 7E 00
//   0x22 F1 86（读 DID）      → 62 F1 86 01
//   其它                      → 7F <sid> 31（requestOutOfRange）
bool stubEcuAnswer (const DiagnosticRequest &req,
                    std::vector<std::uint8_t> &udsOut,
                    std::string &err);

} // namespace doip
