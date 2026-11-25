#pragma once
// ============================================================================
// DoIpDiscovery.h —— M1：UDP 13400 车辆发现
//
// 这一层回答一个问题："网上有 DoIP 实体吗？你是谁？"
// 客户端不需要知道实体 IP —— 它往 255.255.255.255:13400 发一句"有人吗"，
// 所有实体各自回一句"我是 XX，VIN 是 XX"。
//
// 设计上最要紧的一条：**应答逻辑和收发包分开。**
//   respondTo()  纯函数：一条请求进来，回不回、回什么，不碰 socket
//   UdpDiscoveryServer 只负责"收数据报 → 调 respondTo → 发回去"
// 这样 90% 的规则（谁该回、谁该沉默）都能在内存里测，不用起网络。
//
// 两个必须记住的 UDP 特性：
//   ① **收到坏报文不回 NACK。** M0 里那套 NACK 是给 TCP 用的。
//      UDP 可能收到广播，一个坏广播 + N 个实体各自回 NACK = 广播风暴。
//      正确动作是安静丢弃。
//   ② **应答必须从 13400 端口发出。** 客户端的 socket 绑在 13400 上等回复，
//      你从别的端口回，它可能根本收不到（或直接判为非法）。
//      所以收发必须用**同一个** socket。
// ============================================================================
#include "DoIpCodec.h"
#include "DoIpEntityStatus.h"   // M14：同一个 UDP 端口上还住着 0x4001 / 0x4003

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace doip
{

// 一个 DoIP 实体的自我介绍。改这里就等于改"我是谁"。
struct EntityConfig
{
    std::string               vin            = "LSVAA20A8F2100001";   // 规范要求 17 位
    std::uint16_t             logicalAddress = 0x0001;
    std::vector<std::uint8_t> eid            = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};  // 实体标识 6B
    std::vector<std::uint8_t> gid            = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};  // 组标识 6B
    std::uint8_t              furtherAction  = 0x10;   // 0x00 无需进一步动作 / 0x10 需要路由激活
    std::uint8_t              syncStatus     = 0x00;   // VIN 与 GID 是否同步
};

// 一条发现请求的处理结论
struct DiscoveryReply
{
    bool                      replied = false;
    std::vector<std::uint8_t> bytes;    // 完整报文（8 字节头 + 33 字节载荷）
    std::string               reason;   // 为什么回、为什么不回（人话，用来打印和自测）
};

// 纯逻辑：请求进来，决定回不回。
//   0x0001            → 无条件回
//   0x0002 + 匹配 EID → 回；不匹配 → 沉默
//   0x0003 + 匹配 VIN → 回；不匹配 → 沉默
//   其它类型          → 沉默（那不是发现请求）
DiscoveryReply respondTo (const Message &req, const EntityConfig &cfg);

// 主动声明（不用等别人问）：同样的 0x0004 载荷，广播出去。
std::vector<std::uint8_t> buildAnnouncement (const EntityConfig &cfg);

// ---------------------------------------------------------------------------
// UDP 13400 服务器
// ---------------------------------------------------------------------------
class UdpDiscoveryServer
{
public:
    // port = 0 表示让系统分配（自测用，避免和真实 13400 抢端口）
    explicit UdpDiscoveryServer (const EntityConfig &cfg, std::uint16_t port = 13400);
    ~UdpDiscoveryServer ();

    UdpDiscoveryServer (const UdpDiscoveryServer &)            = delete;
    UdpDiscoveryServer &operator= (const UdpDiscoveryServer &) = delete;

    // 建 socket → SO_REUSEADDR → 绑 0.0.0.0:port
    // 注意必须绑 0.0.0.0：绑 127.0.0.1 的话广播包根本进不来。
    bool open (std::string &err);
    void close ();
    bool isOpen () const { return fd_ >= 0; }

    // 实际绑定的端口（构造时传 0 的话，这里能拿到系统分配的）
    std::uint16_t port () const { return port_; }

    // 跑 dur 那么久（或直到 requestStop）。期间：收数据报 → 解析 → 回应答
    void runFor (std::chrono::milliseconds dur);
    void requestStop () { stop_ = true; }

    std::size_t datagrams () const { return datagrams_; }   // 收到几个
    std::size_t answered () const { return answered_; }    // 回了几个
    // M14：其中有多少条是实体状态/电源模式（和发现请求分开记账，
    //   否则"回了 5 个"说不清是 5 次发现还是 5 次状态查询）
    std::size_t entityQueries () const { return entityQueries_; }

    // 日志钩子：工具用它把每条请求打印出来（默认为空）
    std::function<void (const std::string &)> logger;

    // ★ M14：实体状态的取数口。**为空 = 本实体不实现 0x4001/0x4003**（M1 的
    //   doip-discover --serve 就留空，它只做发现）。
    //   做成回调而不是塞一个结构体，是因为 cur_open_sockets 是**活的**：
    //   每问一次要现数，缓存下来就必然过时。
    //   ★ 这个回调会被 **UDP 线程**调用，而连接是 TCP 线程在管的 ——
    //     所以网关那边只能用原子量去读，不许直接遍历别人的容器。
    std::function<EntityStatusInfo ()> entityStatus;
    // 0x4003 的答案。默认 ready；工具里 --power-mode 0 可以演"车还没上电"。
    PowerModeInfo powerMode;

private:
    EntityConfig cfg_;
    std::uint16_t port_;      // 请求的端口
    int fd_ = -1;
    bool stop_ = false;
    std::size_t datagrams_ = 0;
    std::size_t answered_  = 0;
    std::size_t entityQueries_ = 0;   // M14
};

} // namespace doip
