// ============================================================================
// SessionGuard.h —— M16：会话层（0x10 会话切换 + 0x27 安全访问 + S3 超时）
//
// 为什么刷写必须先有这一层：
//   M15 的 0x31/0x34/0x36/0x37 一旦收到就干活，等于"谁连上来都能改 ECU 的程序"。
//   真实 ECU 的门是两道：先 0x10 进"编程会话"，再 0x27 拿种子换密钥解锁。
//   少任何一道，烧写例程都会被拒（0x7F 会话不对 / 0x33 没解锁）。
//
// 为什么是纯逻辑（header-only，带 nowMs 参数）：
//   会话超时（S3）是"时间"问题，但判据本身是"上次活动到现在多久"。
//   把时间当参数传进来，就能在内存里把 5 秒、10 秒、锁定 10 秒全部瞬间跑完，
//   不用真的 sleep —— 也不需要 vcan0。
//
// 三个最容易被糊过去的点（都在自测里钉住）：
//   ① 0x10 换会话会把"解锁"清掉：解锁只在当前会话里有效，换会话就得重新 0x27；
//   ② 3 次错密钥 → 0x36 并锁 10 秒，锁定期内再来是 0x37（不是继续 0x35，也不是 0x36）；
//   ③ S3 超时回落默认会话，且**回落也要把锁解开** —— 否则"放着不管"反而成了绕过门禁的办法。
//
// 密钥算法（故意做得能手算）：
//   key = (seed + 0x12345678) ^ 0xA5A5A5A5   （32 位，按位加会溢出就自然截断）
//   真实车厂的算法是保密的（常常放在刷写包里），本项目只需要"能算、能算错、能锁"。
// ============================================================================
#ifndef DOIP_SESSION_GUARD_H
#define DOIP_SESSION_GUARD_H

#include "UdsNrc.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace doip {

inline std::string hex2 (std::uint8_t v)
{
    char buf[8];
    std::snprintf (buf, sizeof buf, "%02X", static_cast<unsigned> (v));
    return std::string (buf);
}

inline std::string hex8 (std::uint32_t v)
{
    char buf[16];
    std::snprintf (buf, sizeof buf, "%08X", static_cast<unsigned> (v));
    return std::string (buf);
}

struct SessionReply
{
    bool                     positive = false;
    std::vector<std::uint8_t> uds;        // 要发出去的字节；空 = 不回（suppress 位）
    std::string              reason;
};

class SessionGuard
{
    public:
        static constexpr std::uint8_t kSessionDefault     = 0x01;
        static constexpr std::uint8_t kSessionProgramming = 0x02;
        static constexpr std::uint8_t kSessionExtended    = 0x03;

        // S3 = 5 秒（标准默认）；错 3 次锁 10 秒
        explicit SessionGuard (std::uint32_t s3Ms = 5000,
                               std::uint32_t maxAttempts = 3,
                               std::uint32_t delayMs = 10000,
                               std::uint32_t nowMs = 0)
            : s3Ms_ (s3Ms), maxAttempts_ (maxAttempts), delayMs_ (delayMs),
              lastActivityMs_ (nowMs)
        {
        }

        // ---- 0x10 DiagnosticSessionControl ----
        SessionReply handleSessionControl (std::uint8_t sub, std::uint32_t nowMs)
        {
            touch (nowMs);
            if (sub != kSessionDefault && sub != kSessionProgramming && sub != kSessionExtended)
            {
                return neg (0x10, kNrcSubFunctionNotSupported,
                            "0x10 的子功能只认 01 默认 / 02 编程 / 03 扩展");
            }

            level_ = sub;
            // 换会话就把解锁清掉：解锁只在当前会话里有效（自测第一条就是这条）
            unlocked_ = false;
            haveSeed_ = false;
            seed_     = 0;
            attempts_ = 0;
            ++sessionChanges_;
            return ok ({0x50, sub, 0x00, 0x32, 0x01, 0xF4},
                       "进入会话 0x" + hex2 (sub) + "（P2=50ms，P2*=5000ms）");
        }

        // ---- 0x27 SecurityAccess：01 要种子 / 02 交密钥 ----
        SessionReply requestSeed (std::uint32_t nowMs)
        {
            touch (nowMs);
            if (level_ == kSessionDefault)
            {
                return neg (0x27, kNrcServiceNotSupportedInActiveSession,
                            "默认会话里不许做安全访问（先 0x10 进 02/03）");
            }
            if (lockActive (nowMs))
            {
                return neg (0x27, kNrcRequiredDelayNotExpired,
                            "还锁着，剩 " + std::to_string (lockRemainingMs (nowMs)) + " ms");
            }
            clearExpiredLock (nowMs);
            if (unlocked_)
            {
                // 已经解锁：种子回 0（标准里这就是"你不用再交钥匙了"）
                return ok ({0x67, 0x01, 0x00, 0x00, 0x00, 0x00}, "已解锁，种子回 0");
            }
            seed_     = nextSeed ();
            haveSeed_ = true;
            ++seedRequests_;
            return ok ({0x67, 0x01,
                        static_cast<std::uint8_t> ((seed_ >> 24) & 0xFF),
                        static_cast<std::uint8_t> ((seed_ >> 16) & 0xFF),
                        static_cast<std::uint8_t> ((seed_ >> 8) & 0xFF),
                        static_cast<std::uint8_t> (seed_ & 0xFF)},
                       "发种子 0x" + hex8 (seed_));
        }

        SessionReply sendKey (const std::vector<std::uint8_t> &key, std::uint32_t nowMs)
        {
            touch (nowMs);
            if (level_ == kSessionDefault)
            {
                return neg (0x27, kNrcServiceNotSupportedInActiveSession,
                            "默认会话里不许做安全访问");
            }
            if (key.size () != 4)
            {
                return neg (0x27, kNrcIncorrectLength, "0x27 02 的密钥必须是 4 字节");
            }
            if (lockActive (nowMs))
            {
                return neg (0x27, kNrcRequiredDelayNotExpired,
                            "还锁着，剩 " + std::to_string (lockRemainingMs (nowMs)) + " ms");
            }
            clearExpiredLock (nowMs);
            if (!haveSeed_)
            {
                return neg (0x27, kNrcRequestSequenceError, "还没要种子就交密钥（先 0x27 01）");
            }

            const std::uint32_t want = expectedKey (seed_);
            const std::uint32_t got  = (static_cast<std::uint32_t> (key[0]) << 24) |
                                       (static_cast<std::uint32_t> (key[1]) << 16) |
                                       (static_cast<std::uint32_t> (key[2]) << 8) |
                                       static_cast<std::uint32_t> (key[3]);
            if (got == want)
            {
                unlocked_ = true;
                haveSeed_ = false;
                seed_     = 0;
                attempts_ = 0;
                ++keysAccepted_;
                return ok ({0x67, 0x02}, "密钥正确，解锁（本会话内有效）");
            }

            ++attempts_;
            ++keysRejected_;
            if (attempts_ >= maxAttempts_)
            {
                lockUntilMs_ = nowMs + delayMs_;
                ++lockouts_;
                return neg (0x27, kNrcExceededAttempts,
                            "错第 " + std::to_string (attempts_) + " 次：锁 " +
                            std::to_string (delayMs_) + " ms");
            }
            return neg (0x27, kNrcInvalidKey,
                        "密钥不对（第 " + std::to_string (attempts_) + "/" +
                        std::to_string (maxAttempts_) + " 次，正确值 0x" + hex8 (want) + "）");
        }

        // ---- 0x3E TesterPresent：00 回 7E 00；80 是 suppressPosRsp，不回 ----
        SessionReply testerPresent (std::uint8_t sub, std::uint32_t nowMs)
        {
            touch (nowMs);
            if (sub == 0x00)
            {
                ++testerPresents_;
                return ok ({0x7E, 0x00}, "保活：S3 计时器已重置");
            }
            if (sub == 0x80)
            {
                ++testerPresents_;
                return {true, {}, "保活（suppressPosRspMsgIndicationBit）：不回包，只重置计时"};
            }
            return neg (0x3E, kNrcSubFunctionNotSupported, "0x3E 的子功能只认 00 / 80");
        }

        // ---- S3 计时：ECU 主循环定期调；超时回落默认会话并把锁解开 ----
        // 返回 true = 这一拍发生了超时回落（调用方打一行日志）
        bool tick (std::uint32_t nowMs)
        {
            if (level_ == kSessionDefault) return false;
            if (nowMs - lastActivityMs_ < s3Ms_) return false;

            level_    = kSessionDefault;
            unlocked_ = false;
            haveSeed_ = false;
            seed_     = 0;
            attempts_ = 0;
            ++s3Timeouts_;
            return true;
        }

        // 任何一条请求都算"tester 还活着"（标准里 S3 就是这么重置的）。
        // 单独的 3E 是显式保活，但读 VIN 这种普通请求同样会重置计时 —— 两者都调这里。
        void noteActivity (std::uint32_t nowMs) { touch (nowMs); }

        // ---- 刷写门禁：0x31/0x34/0x36/0x37 只在这一个格子里放行 ----
        bool flashAllowed () const
        {
            return level_ == kSessionProgramming && unlocked_;
        }

        // 不放行时该回什么：会话不对是 0x7F，会话对了但没解锁是 0x33（两个码别混）
        SessionReply denyFlash (std::uint8_t sid) const
        {
            if (level_ != kSessionProgramming)
                return neg (sid, kNrcServiceNotSupportedInActiveSession,
                            "当前是会话 0x" + hex2 (level_) + "，刷写只在 02 编程会话里做");
            return neg (sid, kNrcSecurityAccessDenied,
                        "编程会话到了，但还没 0x27 解锁（" + hex2 (sid) + " 被拒）");
        }

        // ---- 观测量（自测和日志都用这些，别从内部字段抄）----
        std::uint8_t  level ()           const { return level_; }
        bool          unlocked ()        const { return unlocked_; }
        std::uint32_t seed ()            const { return seed_; }
        std::uint32_t attempts ()        const { return attempts_; }
        std::uint32_t s3Ms ()            const { return s3Ms_; }
        std::uint32_t delayMs ()         const { return delayMs_; }
        std::uint32_t lastActivityMs ()  const { return lastActivityMs_; }
        std::uint32_t sessionChanges ()  const { return sessionChanges_; }
        std::uint32_t seedRequests ()    const { return seedRequests_; }
        std::uint32_t keysAccepted ()    const { return keysAccepted_; }
        std::uint32_t keysRejected ()    const { return keysRejected_; }
        std::uint32_t lockouts ()        const { return lockouts_; }
        std::uint32_t s3Timeouts ()      const { return s3Timeouts_; }
        std::uint32_t testerPresents ()  const { return testerPresents_; }

        bool lockActive (std::uint32_t nowMs) const
        {
            return lockUntilMs_ != 0 && nowMs < lockUntilMs_;
        }

        std::uint32_t lockRemainingMs (std::uint32_t nowMs) const
        {
            if (!lockActive (nowMs)) return 0;
            return lockUntilMs_ - nowMs;
        }

        std::string levelName () const
        {
            switch (level_)
            {
                case kSessionDefault:     return "默认";
                case kSessionProgramming: return "编程";
                case kSessionExtended:    return "扩展";
                default:                  return "未知";
            }
        }

        // ---- 密钥公式（测试脚本要复刻这一行，所以是 public static）----
        static std::uint32_t expectedKey (std::uint32_t seed)
        {
            return (seed + 0x12345678u) ^ 0xA5A5A5A5u;
        }

    private:
        void touch (std::uint32_t nowMs) { lastActivityMs_ = nowMs; }


        // 锁到期：把错误计数一起清掉。否则锁一过就是"第 4 次错"，立刻又锁 ——
        // 判定看着像"锁永远解不开"，其实只是账没清。
        void clearExpiredLock (std::uint32_t nowMs)
        {
            if (lockUntilMs_ != 0 && nowMs >= lockUntilMs_)
            {
                lockUntilMs_ = 0;
                attempts_    = 0;
            }
        }

        SessionReply ok (std::vector<std::uint8_t> uds, const std::string &why)
        {
            SessionReply r;
            r.positive = true;
            r.uds      = std::move (uds);
            r.reason   = why;
            return r;
        }

        static SessionReply neg (std::uint8_t sid, std::uint8_t nrc, const std::string &why)
        {
            SessionReply r;
            r.positive = false;
            r.uds      = {0x7F, sid, nrc};
            r.reason   = "NRC 0x" + hex2 (nrc) + "：" + why;
            return r;
        }

        // 种子：确定性的混淆（同一个计数器永远给同一个种子，脚本才好复现）
        std::uint32_t nextSeed ()
        {
            std::uint32_t x = 0x9E3779B9u ^ (++seedCounter_ * 0x85EBCA6Bu);
            x ^= x >> 16; x *= 0x7FEB352Du;
            x ^= x >> 15; x *= 0x846CA68Bu;
            x ^= x >> 16;
            return x == 0 ? 0x00000001u : x;
        }

        std::uint32_t s3Ms_;
        std::uint32_t maxAttempts_;
        std::uint32_t delayMs_;

        std::uint8_t  level_           = kSessionDefault;
        bool          unlocked_        = false;
        bool          haveSeed_        = false;
        std::uint32_t seed_            = 0;
        std::uint32_t seedCounter_     = 0;
        std::uint32_t attempts_        = 0;
        std::uint32_t lockUntilMs_     = 0;
        std::uint32_t lastActivityMs_  = 0;

        std::uint32_t sessionChanges_  = 0;
        std::uint32_t seedRequests_    = 0;
        std::uint32_t keysAccepted_    = 0;
        std::uint32_t keysRejected_    = 0;
        std::uint32_t lockouts_        = 0;
        std::uint32_t s3Timeouts_      = 0;
        std::uint32_t testerPresents_  = 0;
};

} // namespace doip

#endif
