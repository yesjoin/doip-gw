#pragma once
// ============================================================================
// UdsNrc.h —— 0x7F 后面的否定码（M15 的刷写和 M16 的会话共用的那一张表）
//
// 为什么单独抽一个头：M15 写 FlashTarget.h 时先在文件里放了一份码常量，
// M16 的 SessionGuard.h 又要用同一批码 —— 两个头一起被 stub-ecu 包含，
// 编译器直接报 redefinition（"两个模块各写一份码表"的典型症状）。
// 码表是"协议的一部分"，不是某个模块的私有常量，所以它应该只有一个出处。
//
// 只列本项目真正会发的码。标准里的 0x11/0x12/0x14/0x21/0x31/0x33/0x35/0x36/0x37
// 这些都在里面（没用到的不写，免得"以为实现了"）。
// ============================================================================
#include <cstdint>

namespace doip
{

constexpr std::uint8_t kNrcGeneralReject                  = 0x10;
constexpr std::uint8_t kNrcSubFunctionNotSupported       = 0x12;
constexpr std::uint8_t kNrcIncorrectLength                = 0x13;  // 长度 / 格式不对
constexpr std::uint8_t kNrcConditionsNotCorrect           = 0x22;  // 状态不对（还没擦、还没进会话）
constexpr std::uint8_t kNrcRequestSequenceError           = 0x24;  // 顺序错（没协商就传、没传完就收尾）
constexpr std::uint8_t kNrcRequestOutOfRange              = 0x31;  // 地址 / 长度 / 参数越界
constexpr std::uint8_t kNrcSecurityAccessDenied           = 0x33;  // 会话对了，但没解锁
constexpr std::uint8_t kNrcInvalidKey                     = 0x35;  // 密钥不对（还能再试）
constexpr std::uint8_t kNrcExceededAttempts               = 0x36;  // 错太多次，锁
constexpr std::uint8_t kNrcRequiredDelayNotExpired        = 0x37;  // 锁还没到点
constexpr std::uint8_t kNrcTransferDataSuspended          = 0x71;  // 超出声明的长度
constexpr std::uint8_t kNrcGeneralProgrammingFail         = 0x72;
constexpr std::uint8_t kNrcWrongBlockSequence             = 0x73;  // BSC 跳号
constexpr std::uint8_t kNrcServiceNotSupportedInActiveSession = 0x7F;  // 会话不对

} // namespace doip