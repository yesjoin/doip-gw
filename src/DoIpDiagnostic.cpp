// ============================================================================
// DoIpDiagnostic.cpp —— M3 实现
//
// 判据顺序就是代码顺序，改顺序等于改协议：
//   ① 未激活 → 0x8003 0x02（源地址不在连接表里）
//   ② 载荷 < 4 字节 → 连 SA/TA 都没有，回不到任何有效地址（由服务器回 0x0000 0x04 并断开）
//   ③ SA ≠ 本连接激活的 SA → 0x8003 0x02
//   ④ TA ≠ 我 → 0x8003 0x03
//   ⑤ UDS 超长 → 0x8003 0x04
// ============================================================================
#include "DoIpDiagnostic.h"

#include <algorithm>

namespace doip
{
namespace
{

// DoIP 全大端：readU16 只在这里用一次，不引依赖
std::uint16_t readU16 (const std::vector<std::uint8_t> &b, std::size_t off)
{
    return static_cast<std::uint16_t> ((static_cast<std::uint16_t> (b[off]) << 8) |
                                       static_cast<std::uint16_t> (b[off + 1]));
}

} // namespace

const char *nameOf (DiagNack c)
{
    switch (c)
    {
    case DiagNack::InvalidSourceAddress:   return "0x02 源地址非法";
    case DiagNack::UnknownTargetAddress:   return "0x03 目标地址未知";
    case DiagNack::MessageTooLarge:        return "0x04 诊断报文太大";
    case DiagNack::OutOfMemory:            return "0x05 内存不足";
    case DiagNack::TargetUnreachable:      return "0x06 目标不可达";
    case DiagNack::UnknownNetwork:         return "0x07 网络未知";
    case DiagNack::TransportProtocolError: return "0x08 传输层错误";
    }
    return "未知码";
}

DiagnosticChannel::DiagnosticChannel (const DiagnosticPolicy &p) : p_ (p) {}

DiagOutcome DiagnosticChannel::handle (const std::vector<std::uint8_t> &payload,
                                       bool activated,
                                       std::uint16_t activatedSource)
{
    DiagOutcome o;
    o.action = DiagAction::Nack;

    // ① 没激活就发诊断：这条连接没有"注册过的源地址"，按 0x02 回
    if (!activated)
    {
        o.code   = static_cast<std::uint8_t> (DiagNack::InvalidSourceAddress);
        o.reason = "这条连接还没激活，源地址不在连接表里";
        return o;
    }

    // ② 载荷结构：SA(2) + TA(2) + UDS(≥0)。不足 4 字节连地址都读不出。
    if (payload.size () < 4)
    {
        // code 留 0，由服务器用 0x0000 0x04（Invalid payload length）处理并断开：
        // 这种报文连"这是谁的诊断"都说不清，继续留在流里只会污染后面。
        o.code   = 0;
        o.reason = "0x8001 载荷不足 4 字节，读不出源/目标地址";
        return o;
    }

    o.sourceAddress = readU16 (payload, 0);
    o.targetAddress = readU16 (payload, 2);
    o.uds.assign (payload.begin () + 4, payload.end ());

    // ③ 源地址必须是这条连接激活的那个 —— 否则任何人都能冒用别人的身份发诊断
    if (o.sourceAddress != activatedSource)
    {
        o.code   = static_cast<std::uint8_t> (DiagNack::InvalidSourceAddress);
        o.reason = "源地址和本连接激活的地址不一致（冒用他人身份）";
        return o;
    }

    // ④ 目标必须是我。M4 会在这里换成"查路由表"，M3 只有自己一个节点。
    if (o.targetAddress != p_.entityAddress)
    {
        o.code   = static_cast<std::uint8_t> (DiagNack::UnknownTargetAddress);
        o.reason = "目标地址不是我，也没有路由可达";
        return o;
    }

    // ⑤ 上限检查放在分配/转发之前（M0 那条"先查长度再 malloc"的同一个原则）
    if (o.uds.size () > p_.maxUds)
    {
        o.code   = static_cast<std::uint8_t> (DiagNack::MessageTooLarge);
        o.reason = "UDS 数据 " + std::to_string (o.uds.size ()) + " 字节，超过上限 " +
                   std::to_string (p_.maxUds);
        return o;
    }

    o.action = DiagAction::AckAndForward;
    o.code   = 0x00;                      // 0x8002 只有这一个码：ACK
    o.reason = "受理，交给下游";
    return o;
}

// ---------------------------------------------------------------------------
// 假 ECU。**故意写得像真的一样，但它确实不是真的。**
// 这样 M3 就能先把"以太网侧通道"验完，M4 只换这一个函数。
// ---------------------------------------------------------------------------
bool stubEcuAnswer (const DiagnosticRequest &req,
                    std::vector<std::uint8_t> &udsOut,
                    std::string &err)
{
    udsOut.clear ();

    if (req.uds.empty ())
    {
        err = "UDS 数据为空，假 ECU 不猜";
        return false;
    }

    const std::uint8_t sid = req.uds[0];

    if (sid == 0x3E && req.uds.size () >= 2 && req.uds[1] == 0x00)
    {
        udsOut = {0x7E, 0x00};                      // TesterPresent 正响应
        return true;
    }

    if (sid == 0x22 && req.uds.size () >= 3 && req.uds[1] == 0xF1 && req.uds[2] == 0x86)
    {
        udsOut = {0x62, 0xF1, 0x86, 0x01};          // 和项目一那个 ECU 同一个答案
        return true;
    }

    // 其余一律 requestOutOfRange —— 一棵"什么都答得上"的假 ECU 会掩盖真问题
    udsOut = {0x7F, sid, 0x31};
    return true;
}

} // namespace doip
