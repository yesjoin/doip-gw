#pragma once
// ============================================================================
// CanId.h —— M7：CAN ID 的"宽度"问题，收敛到一个文件
//
// 为什么单独开个头文件：
//   CAN 有**两种帧**：标准帧（11 位 ID，0x001–0x7FF）和扩展帧（29 位 ID，0x001–0x1FFFFFFF）。
//   同一个数值 0x7E0 在两种帧里都合法，但**"用哪种帧发"不是靠猜的，是靠 ID 的位数定的**。
//
//   SocketCAN 的规矩很别扭：
//     - 发：29 位 ID 必须把 can_id 的最高位（bit31，CAN_EFF_FLAG = 0x80000000）置 1，
//           否则内核直接回 EINVAL（"Invalid argument"），现象是"帧根本没出去"。
//     - 收：内核回给你的 can_id 也带着这个位，所以比较之前必须先剥掉（& CAN_EFF_MASK）。
//   这两条方向相反、又都不报"你用错了"，是 CAN 编程里最常见的一个坑。
//
//   所以本项目把所有"宽度"判断收进这里：路由表只存 32 位原值，
//   真正发帧时才由 idForSend() 决定要不要置标志位。
// ============================================================================
#include <cstdint>
#include <string>

namespace doip
{

// 29 位扩展 ID 的上限（ISO 11898-1）
constexpr std::uint32_t kCanIdMax = 0x1FFFFFFFu;

// Linux 内核里 CAN_EFF_FLAG 的值，这里自己写一份，
// 好处是 CanId.h 不依赖 <linux/can.h>，纯逻辑测试也能直接编。
constexpr std::uint32_t kCanEffFlag = 0x80000000u;

// 11 位标准帧能表示的最大 ID。超过它就必须用扩展帧。
constexpr std::uint32_t kStdIdMax = 0x7FFu;

inline bool isExtendedId (std::uint32_t id) { return id > kStdIdMax; }

inline bool isValidCanId (std::uint32_t id) { return id >= 1 && id <= kCanIdMax; }

// 发帧前调用：扩展 ID 要置 CAN_EFF_FLAG。标准 ID 原样返回。
inline std::uint32_t idForSend (std::uint32_t id)
{
    return isExtendedId (id) ? (id | kCanEffFlag) : id;
}

// 收帧后调用：把内核带回来的标志位剥掉，拿到纯 ID 再比较。
// 用 kCanIdMax 而不是只清 bit31：RTR / ERR 标志也在高位，一起剥干净，
// 免得"收到了一个远程帧"被当成某个真实的 29 位 ID。
inline std::uint32_t idFromRecv (std::uint32_t raw) { return raw & kCanIdMax; }

// 打印用：11 位打 3 位十六进制（7E0），29 位打 8 位（18DAF100）。
// 不这样分，日志里 0x018DAF100 会看成"17 位 ID"，人眼没法快速判断宽度。
std::string formatCanId (std::uint32_t id);

} // namespace doip
