#pragma once
// ============================================================================
// DoIpRouting.h —— M2：路由激活状态机（纯逻辑，不碰 socket）
//
// 为什么把它单独拎出来：
//   路由激活是本项目第一个真正的**状态机**，而状态机的错最难查 ——
//   它的 bug 不表现为"报错"，而表现为"看起来更顺"。
//
//   典型的一条：TCP 断了但激活状态还留着。
//   客户端重连后直接就能发诊断，看起来"很贴心"，实际是安全漏洞级别的问题：
//   一个从没通过认证的连接，继承了上一个连接的权限。
//
//   所以这条规则的实现必须只有一处（reset()），并且必须被试死：
//   「断连即清空」是 M2 的验收硬指标第 5 条。
//
// 本文件只做三件事：判 SA、判激活类型、判"这个 socket 上是否已经激活过别的 SA"。
// 收发包、超时、alive check 都在 DoIpTcpServer 里。
// ============================================================================
#include "DoIpCodec.h"

#include <cstdint>
#include <string>

namespace doip
{

// 路由激活请求里的"激活类型"字节
enum class ActivationType : std::uint8_t
{
    Default         = 0x00,   // 默认（本项目支持）
    WwhObd          = 0x01,   // WWH-OBD（本项目也放行）
    CentralSecurity = 0xE0,   // 中央安全 —— 需要证书体系，本项目不做
};

// 路由激活应答里的"响应码"
enum class ActivationResponseCode : std::uint8_t
{
    UnknownSourceAddress    = 0x00,   // 源地址不认识
    AllSocketsRegistered    = 0x01,   // 本实体的 TCP socket 都被占用了（多连接场景，M4 用）
    SourceDiffersFromActive = 0x02,   // 和这个 socket 上已激活的源地址不一致
    AlreadyOnAnotherSocket  = 0x03,   // 该源地址已在别的 socket 上注册（M4 用）
    MissingAuthentication   = 0x04,   // 缺少认证（本项目不做）
    RejectedConfirmation    = 0x05,   // 确认被拒（本项目不做）
    UnsupportedType         = 0x06,   // 不支持的激活类型
    Success                 = 0x10,   // 成功
    ConfirmationRequired    = 0x11,   // 需确认后才激活（本项目不做，直接成功）
};

const char *nameOf (ActivationResponseCode c);

// 一次请求的结论
struct ActivationOutcome
{
    bool         replied   = false;      // 要不要回应答（路由激活必回，所以常态 true）
    std::uint8_t code      = 0x10;       // 写进 0x0006 的响应码
    bool         activated = false;      // 处理完之后这个 socket 是否处于激活态
    std::string  reason;                 // 人话，给日志和自测看
};

// 一个 TCP 连接上的路由激活状态。每个连接一个实例。
class RoutingActivation
{
public:
    explicit RoutingActivation (std::uint16_t entityAddress = 0x0001);

    // 处理一条 0x0005 请求
    ActivationOutcome handle (const RoutingActivationRequest &req);

    // 连接断了：**唯一的清空入口**。不要在别处手写 activated_ = false。
    void reset ();

    bool          activated () const { return activated_; }
    std::uint16_t activatedSource () const { return source_; }
    std::uint16_t entityAddress () const { return entity_; }

private:
    std::uint16_t entity_;
    bool          activated_ = false;
    std::uint16_t source_    = 0;
};

} // namespace doip
