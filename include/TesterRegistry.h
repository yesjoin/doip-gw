// ============================================================================
// TesterRegistry.h —— M13：实体级的 tester 地址仲裁（纯逻辑，无 socket）
//
// 先纠正一个容易传错的说法：
//   **tester 的逻辑地址不是网关分配的。** ISO 13400-2 把 0x0E00–0x0FFF
//   整段留给了"外部测试设备"，其中 0x0E00–0x0E7F 是法规诊断仪（排放检测那类），
//   0x0E80–0x0EFF 是厂商/售后增强诊断仪。地址由 tester 自己选、自己带来，
//   DoIP 实体要做的是**查重**和**限流**，不是发号。
//
// 为什么必须有一个"实体级"的账：
//   M2 起，激活状态是**跟着连接走**的（RoutingActivation 每个连接一份）。
//   这本身没错，但它只管"这条连接里 SA 不许中途换人"。
//   于是两个 TCP 连接可以各自把同一个 SA（比如 0x0E00）激活一次，
//   网关看着一切正常，可总线那头是两台诊断仪用同一个地址在说话 ——
//   ECU 无法区分，网关也只能靠 jobId 才没把答案送错人。
//   真网关不允许这件事，用的就是 0x0006 里的两个码：
//     0x03 = 这个 SA 已经在**另一个** TCP_DATA socket 上注册且激活了
//     0x01 = 本实体能同时承载的 TCP_DATA socket 都已被注册并激活（没有空位）
//
// 有意的设计取舍：
//   ① 仲裁是**实体级**的，所以它不能塞进 RoutingActivation（那是连接级的）；
//   ② 它只做 uint16 → uint64 的两张表，没有任何 socket / 锁依赖，
//      所以能在 tests 里一秒测完"抢地址"的全部组合；
//   ③ 查重优先于限流：两个条件同时成立时先报 0x03。
//      理由是 0x03 说的是"你这个人有问题"（地址被占），0x01 说的是"我这边满了"，
//      前者更具体，也更容易让现场一次改对。
// ============================================================================
#ifndef DOIP_TESTER_REGISTRY_H
#define DOIP_TESTER_REGISTRY_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace doip
{

// 0x0006 里的应答码（只列这里会用到的两个 + 成功）
inline constexpr std::uint8_t kActCodeSuccess            = 0x10;
inline constexpr std::uint8_t kActCodeAllSocketsBusy     = 0x01;
inline constexpr std::uint8_t kActCodeSourceDiffers      = 0x02;
inline constexpr std::uint8_t kActCodeAlreadyOnOtherSock = 0x03;

class TesterRegistry
{
public:
    struct Result
    {
        bool         ok     = false;
        std::uint8_t code   = kActCodeSuccess;   // 失败时是 0x01 / 0x02 / 0x03
        std::string  reason;                     // 人话，给日志和自测看
    };

    explicit TesterRegistry (std::size_t maxActive = 4) : max_ (maxActive) {}

    // 这台 tester（连接 connId）想用 sa。三种结果：
    //   成功（含同一连接重复注册，幂等）→ ok
    //   本连接已经绑了别的地址            → 0x02
    //   地址被别的连接占着                → 0x03
    //   没有空位了                        → 0x01
    Result tryRegister (std::uint16_t sa, std::uint64_t connId)
    {
        Result r;

        auto byConn = byConn_.find (connId);
        if (byConn != byConn_.end ())
        {
            if (byConn->second == sa)
            {
                // 同一个连接对同一个地址重复激活：幂等，回 0x10。
                // 客户端断线重连后重发请求是常态，不能把它当错误。
                r.ok     = true;
                r.code   = kActCodeSuccess;
                r.reason = "本连接已为该地址激活过 → 幂等，仍回成功";
                return r;
            }
            r.code   = kActCodeSourceDiffers;
            r.reason = "本连接已绑定另一个地址，不能中途换人 → 拒绝";
            return r;
        }

        auto bySa = bySa_.find (sa);
        if (bySa != bySa_.end () && bySa->second != connId)
        {
            ++conflicts_;
            r.code   = kActCodeAlreadyOnOtherSock;
            r.reason = "该地址已在另一条连接上注册并激活 → 拒绝（否则两台 tester 会同址说话）";
            return r;
        }

        if (byConn_.size () >= max_)
        {
            ++capacityRejects_;
            r.code   = kActCodeAllSocketsBusy;
            r.reason = "可同时激活的连接已占满（" + std::to_string (max_) + "）→ 拒绝";
            return r;
        }

        byConn_[connId] = sa;
        bySa_[sa]       = connId;
        r.ok     = true;
        r.code   = kActCodeSuccess;
        r.reason = "登记成功";
        return r;
    }

    // 连接断了：把它占的地址还回去。返回"原来确实登记过"。
    bool release (std::uint64_t connId)
    {
        auto it = byConn_.find (connId);
        if (it == byConn_.end ()) return false;
        bySa_.erase (it->second);
        byConn_.erase (it);
        return true;
    }

    // 没登记过 → 0
    std::uint16_t addressOf (std::uint64_t connId) const
    {
        auto it = byConn_.find (connId);
        return it == byConn_.end () ? 0 : it->second;
    }

    // 没被占用 → 0
    std::uint64_t ownerOf (std::uint16_t sa) const
    {
        auto it = bySa_.find (sa);
        return it == bySa_.end () ? 0 : it->second;
    }

    std::size_t active () const { return byConn_.size (); }
    std::size_t maxActive () const { return max_; }
    void        setMaxActive (std::size_t m) { max_ = m; }

    // 两个观测量：只涨不回退（clear 才归零），退场日志用它们说话
    std::size_t conflicts () const { return conflicts_; }
    std::size_t capacityRejects () const { return capacityRejects_; }

    void clear ()
    {
        byConn_.clear ();
        bySa_.clear ();
        conflicts_       = 0;
        capacityRejects_ = 0;
    }

private:
    std::size_t max_;
    std::unordered_map<std::uint64_t, std::uint16_t> byConn_;   // 连接 → 地址
    std::unordered_map<std::uint16_t, std::uint64_t> bySa_;     // 地址 → 连接
    std::size_t conflicts_       = 0;
    std::size_t capacityRejects_ = 0;
};

} // namespace doip

#endif // DOIP_TESTER_REGISTRY_H
