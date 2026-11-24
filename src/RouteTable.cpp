// ============================================================================
// RouteTable.cpp —— M6：路由表的四道校验
//
// 校验顺序（和 add() 里的代码顺序一致）：
//   ① 目标地址不能是 0（0x0000 是标准里的保留值，不能当地址用）
//   ② 请求 ID / 响应 ID 都不能是 0（CAN 上没有 0 号 ID 这种"合法 ECU"）
//   ③ 请求 ID / 响应 ID 都不能超过 29 位上限 0x1FFFFFFF（M7 补的）
//   ④ 请求 ID 和响应 ID 不能相同（同一个 ID 收发，回环会把自己发的帧当响应）
//   ⑤ 地址唯一、ID 对唯一（重复 = 配置写错，直接拒绝）
//
// 为什么要在"加表"时就拒绝，而不是运行时再兜底：
//   路由错的表现是"诊断仪读到了另一台 ECU 的数据"——这种错**不会报错**，
//   只会给出一个看起来合理但属于别人的答案。宁可启动就失败，也不要悄悄答错。
//
//   ③ 是 M7 加的：超过 29 位的 ID 放进 SocketCAN 时，内核只回一句 EINVAL，
//   而上层看到的是"请求超时"。与其让人去查总线，不如在配置处就骂回来。
// ============================================================================
#include "RouteTable.h"

#include <cstdio>

namespace doip
{
namespace
{
std::string hex4 (std::uint16_t v)
{
    char b[8];
    std::snprintf (b, sizeof (b), "0x%04X", static_cast<unsigned> (v));
    return std::string (b);
}
} // namespace

bool RouteTable::add (const RouteEntry &e, std::string &err)
{
    if (e.logicalAddress == 0)
    {
        err = "路由的目标地址不能是 0x0000";
        return false;
    }
    if (e.txId == 0 || e.rxId == 0)
    {
        err = "CAN 请求/响应 ID 不能是 0";
        return false;
    }
    if (!isValidCanId (e.txId) || !isValidCanId (e.rxId))
    {
        // 这里把宽度一起说出来：0x20000000 是"超过 29 位"，不是"写错了"——
        // 两种错因给的提示应该不一样，不然人只会去翻文档
        err = "CAN ID 超出 29 位上限（" + formatCanId (e.txId) + " / " + formatCanId (e.rxId) +
              "），29 位最大是 0x1FFFFFFF";
        return false;
    }
    if (e.txId == e.rxId)
    {
        err = "请求 ID 和响应 ID 不能相同（会把自己的帧当响应）";
        return false;
    }

    for (const auto &x : entries_)
    {
        if (x.logicalAddress == e.logicalAddress)
        {
            err = "目标地址 " + hex4 (e.logicalAddress) + " 已经注册过了";
            return false;
        }
        if (x.txId == e.txId && x.rxId == e.rxId)
        {
            err = "这对 CAN ID 已经被另一条路由占用（两台 ECU 不能共用一个通道）：" +
                  formatCanId (e.txId) + " / " + formatCanId (e.rxId);
            return false;
        }
    }

    entries_.push_back (e);
    return true;
}

const RouteEntry *RouteTable::lookup (std::uint16_t ta) const
{
    for (const auto &x : entries_)
    {
        if (x.logicalAddress == ta) return &x;
    }
    return nullptr;
}

} // namespace doip
