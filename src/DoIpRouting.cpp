// ============================================================================
// DoIpRouting.cpp —— 路由激活的判据
//
// 判据顺序是有讲究的，不是随便排的：
//   ① SA 合法吗（0 是保留，等于实体自己是无意义）
//   ② 激活类型支持吗
//   ③ 这个 socket 上是否已经绑了别的 SA
// 先判"你是谁"，再判"你要干什么"，最后判"和现状冲突吗"。
// 顺序反过来会出现"用一个合法 SA 加了不支持的类型，却报 0x02"这种误导性错误。
// ============================================================================
#include "DoIpRouting.h"

#include <cstdio>

namespace doip
{
namespace
{

// 日志里逻辑地址要写成 0x0E00，不能写成十进制 3584 ——
// 排查现场时你手里拿的是十六进制，两边对不上就是白费时间。
std::string hex4 (std::uint16_t v)
{
    char b[16];
    std::snprintf (b, sizeof (b), "0x%04X", static_cast<unsigned> (v));
    return std::string (b);
}

std::string hex2 (std::uint8_t v)
{
    char b[16];
    std::snprintf (b, sizeof (b), "0x%02X", static_cast<unsigned> (v));
    return std::string (b);
}

} // namespace

const char *nameOf (ActivationResponseCode c)
{
    switch (c)
    {
    case ActivationResponseCode::UnknownSourceAddress:    return "0x00 源地址不认识";
    case ActivationResponseCode::AllSocketsRegistered:    return "0x01 本实体 socket 已占满";
    case ActivationResponseCode::SourceDiffersFromActive: return "0x02 与本 socket 已激活的源地址不一致";
    case ActivationResponseCode::AlreadyOnAnotherSocket:  return "0x03 该源地址已在别的 socket 上注册";
    case ActivationResponseCode::MissingAuthentication:   return "0x04 缺少认证";
    case ActivationResponseCode::RejectedConfirmation:    return "0x05 确认被拒";
    case ActivationResponseCode::UnsupportedType:         return "0x06 不支持的激活类型";
    case ActivationResponseCode::Success:                 return "0x10 路由激活成功";
    case ActivationResponseCode::ConfirmationRequired:    return "0x11 需确认后才激活";
    }
    return "unknown";
}

RoutingActivation::RoutingActivation (std::uint16_t entityAddress)
    : entity_ (entityAddress)
{
}

ActivationOutcome RoutingActivation::handle (const RoutingActivationRequest &req)
{
    ActivationOutcome out;
    out.replied = true;   // 路由激活请求一定要给答复（哪怕是拒绝），否则客户端只能干等超时

    // ① 源地址合法性：0x0000 是保留值；等于实体自己的地址说明客户端把方向搞反了。
    if (req.sourceAddress == 0x0000)
    {
        out.code  = static_cast<std::uint8_t> (ActivationResponseCode::UnknownSourceAddress);
        out.reason = "源地址 0x0000 是保留值 → 拒绝";
        return out;
    }
    if (req.sourceAddress == entity_)
    {
        out.code  = static_cast<std::uint8_t> (ActivationResponseCode::UnknownSourceAddress);
        out.reason = "源地址等于实体自己的地址（" + hex4 (entity_ ) + "）→ 拒绝，方向搞反了";
        return out;
    }

    // ② 激活类型：0xE0（中央安全）要证书，本项目不做。
    const std::uint8_t t = req.activationType;
    if (t != static_cast<std::uint8_t> (ActivationType::Default) &&
        t != static_cast<std::uint8_t> (ActivationType::WwhObd))
    {
        out.code  = static_cast<std::uint8_t> (ActivationResponseCode::UnsupportedType);
        out.reason = "激活类型 " + hex2 (t) + " 不支持（只支持 0x00 / 0x01）→ 拒绝";
        return out;
    }

    // ③ 同一个 socket 上不能中途换人。
    //    这条看着"不方便"，但它是安全边界：一个 socket 代表一段已认证的上下文。
    if (activated_ && source_ != req.sourceAddress)
    {
        out.code  = static_cast<std::uint8_t> (ActivationResponseCode::SourceDiffersFromActive);
        out.reason = "本 socket 已为 " + hex4 (source_) +
                     " 激活，不能改成 " + hex4 (req.sourceAddress) + " → 拒绝";
        return out;
    }

    // 到这里通过。注意：同一个 SA 重复发请求是**幂等**的，再回一次 0x10，
    // 不算错误 —— 客户端断线重连后重发请求是常见行为。
    activated_ = true;
    source_    = req.sourceAddress;
    out.code      = static_cast<std::uint8_t> (ActivationResponseCode::Success);
    out.activated = true;
    out.reason    = "源地址 " + hex4 (req.sourceAddress) + " 路由激活成功";
    return out;
}

void RoutingActivation::reset ()
{
    activated_ = false;
    source_    = 0;
}

} // namespace doip
