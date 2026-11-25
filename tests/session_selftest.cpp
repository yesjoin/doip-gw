// ============================================================================
// session_selftest.cpp —— M16 的纯逻辑自测（SessionGuard：0x10 / 0x27 / 0x3E / S3）
//
// 会话层最容易糊过去的三件事：
//   · 换会话没把解锁清掉 —— 于是"解锁一次、随便切会话"就能一直刷；
//   · 错密钥一直回 0x35 —— 客户端可以无限试，等于没有锁；
//   · S3 超时把锁也解了 —— "放着不管"反而成了绕过门禁的办法。
// 下面每条都正着反着走一遍，时间当成参数传，不用真的 sleep。
//
// 密钥公式（也是手算题的答案）：
//   key = (seed + 0x12345678) ^ 0xA5A5A5A5
//   例：seed = 0x00000001 → 0x12345679 ^ 0xA5A5A5A5 = 0xB791F3DC
//
// 用法：./session-selftest        全绿退出码 0
// ============================================================================
#include "SessionGuard.h"

#include <cstdio>
#include <string>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ()); \
        }                                                              \
    } while (0)

static std::vector<std::uint8_t> keyBytes (std::uint32_t k)
{
    return {static_cast<std::uint8_t> ((k >> 24) & 0xFF),
            static_cast<std::uint8_t> ((k >> 16) & 0xFF),
            static_cast<std::uint8_t> ((k >> 8) & 0xFF),
            static_cast<std::uint8_t> (k & 0xFF)};
}

int main ()
{
    // ---- A. 默认会话：门是关着的 ----
    {
        SessionGuard g;
        CHECK (g.level () == SessionGuard::kSessionDefault, "新起来就是默认会话 0x01");
        CHECK (!g.flashAllowed (), "默认会话不许刷写");

        auto r = g.requestSeed (0);
        CHECK (!r.positive && r.uds.size () == 3 && r.uds[2] == kNrcServiceNotSupportedInActiveSession,
               "默认会话里 0x27 01 → 7F 27 7F（不是 0x33）");

        auto deny = g.denyFlash (0x34);
        CHECK (!deny.positive && deny.uds.size () == 3 && deny.uds[0] == 0x7F &&
               deny.uds[1] == 0x34 && deny.uds[2] == kNrcServiceNotSupportedInActiveSession,
               "默认会话里 0x34 → 7F 34 7F");
    }

    // ---- B. 0x10 进编程会话：正响应带回 P2 / P2* ----
    {
        SessionGuard g;
        auto r = g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        CHECK (r.positive, "0x10 02 → 正响应");
        CHECK (r.uds.size () == 6 && r.uds[0] == 0x50 && r.uds[1] == 0x02, "50 02 …");
        CHECK (r.uds[2] == 0x00 && r.uds[3] == 0x32, "P2 = 0x0032 = 50ms");
        CHECK (r.uds[4] == 0x01 && r.uds[5] == 0xF4, "P2* = 0x01F4 × 10ms = 5000ms");
        CHECK (g.level () == SessionGuard::kSessionProgramming, "会话记成 02");
        CHECK (!g.unlocked (), "刚进会话还没解锁");

        auto deny = g.denyFlash (0x36);
        CHECK (!deny.positive && deny.uds[2] == kNrcSecurityAccessDenied,
               "编程会话但没解锁 → 0x33（和 0x7F 是两个意思）");

        r = g.handleSessionControl (0x04, 0);
        CHECK (!r.positive && r.uds[2] == kNrcSubFunctionNotSupported, "0x10 04 → 0x12 子功能不支持");
    }

    // ---- C. 密钥公式：手算题的那一行 ----
    {
        CHECK (SessionGuard::expectedKey (0x00000001u) == 0xB791F3DCu,
               "key(0x00000001) = (1+0x12345678)^0xA5A5A5A5 = 0xB791F3DC");
        CHECK (SessionGuard::expectedKey (0x00000000u) == (0x12345678u ^ 0xA5A5A5A5u),
               "key(0) = 0x12345678 ^ 0xA5A5A5A5");
    }

    // ---- D. 种子：每次都不一样，且不为 0 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);

        auto r1 = g.requestSeed (0);
        CHECK (r1.positive && r1.uds.size () == 6 && r1.uds[0] == 0x67 && r1.uds[1] == 0x01,
               "0x27 01 → 67 01 + 4 字节种子");
        CHECK (g.seed () != 0, "种子不为 0（0 这个值专门表示已解锁）");
        const std::uint32_t s1 = g.seed ();

        auto r2 = g.requestSeed (0);
        const std::uint32_t s2 = g.seed ();
        CHECK (s1 != s2, "再要一次，种子变了（一次性）");
        CHECK (s2 == (static_cast<std::uint32_t> (r2.uds[2]) << 24 |
                      static_cast<std::uint32_t> (r2.uds[3]) << 16 |
                      static_cast<std::uint32_t> (r2.uds[4]) << 8 |
                      static_cast<std::uint32_t> (r2.uds[5])),
               "回包里的种子和内部记的是同一个");
        CHECK (g.seedRequests () == 2, "种子请求计数 2");
    }

    // ---- E. 没要种子就交密钥 → 0x24；密钥长度不对 → 0x13 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        auto r = g.sendKey ({0x11, 0x22, 0x33, 0x44}, 0);
        CHECK (!r.positive && r.uds[2] == kNrcRequestSequenceError, "没 0x27 01 就 0x27 02 → 0x24");

        g.requestSeed (0);
        r = g.sendKey ({0x11, 0x22, 0x33}, 0);
        CHECK (!r.positive && r.uds[2] == kNrcIncorrectLength, "密钥 3 字节 → 0x13");
    }

    // ---- F. 正确密钥解锁；解锁后再要种子回 0 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        g.requestSeed (0);
        const std::uint32_t k = SessionGuard::expectedKey (g.seed ());

        auto r = g.sendKey (keyBytes (k), 0);
        CHECK (r.positive && r.uds.size () == 2 && r.uds[0] == 0x67 && r.uds[1] == 0x02,
               "对密钥 → 67 02");
        CHECK (g.unlocked (), "解锁了");
        CHECK (g.flashAllowed (), "编程会话 + 解锁 = 允许刷写");
        CHECK (g.keysAccepted () == 1 && g.seed () == 0, "记账：收下 1 次，种子清零");

        r = g.requestSeed (0);
        CHECK (r.uds == std::vector<std::uint8_t> ({0x67, 0x01, 0x00, 0x00, 0x00, 0x00}),
               "已解锁再要种子 → 67 01 00 00 00 00");
    }

    // ---- G. 换会话把解锁清掉（这是最容易被糊过去的一条）----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        g.requestSeed (0);
        g.sendKey (keyBytes (SessionGuard::expectedKey (g.seed ())), 0);
        CHECK (g.flashAllowed (), "先确认已经解锁");

        g.handleSessionControl (SessionGuard::kSessionExtended, 0);
        CHECK (g.level () == SessionGuard::kSessionExtended, "切到扩展会话 0x03");
        CHECK (!g.unlocked (), "解锁被清掉（解锁只在当前会话里有效）");
        CHECK (!g.flashAllowed (), "扩展会话也不能刷写（刷写只认 02）");
        CHECK (g.sessionChanges () == 2, "会话切换计数 2");
    }

    // ---- H. 错密钥：0x35 → 0x35 → 0x36 并锁 10 秒；锁定期内 0x37 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        g.requestSeed (0);
        const std::uint32_t wrong = SessionGuard::expectedKey (g.seed ()) ^ 0x00000001u;

        auto r = g.sendKey (keyBytes (wrong), 0);
        CHECK (!r.positive && r.uds[2] == kNrcInvalidKey, "错第 1 次 → 0x35");
        CHECK (g.attempts () == 1 && !g.lockActive (0), "还能再试，没锁");

        r = g.sendKey (keyBytes (wrong), 0);
        CHECK (!r.positive && r.uds[2] == kNrcInvalidKey, "错第 2 次 → 0x35");

        r = g.sendKey (keyBytes (wrong), 0);
        CHECK (!r.positive && r.uds[2] == kNrcExceededAttempts, "错第 3 次 → 0x36");
        CHECK (g.lockActive (0), "锁上了");
        CHECK (g.lockRemainingMs (0) == 10000, "锁 10 秒");
        CHECK (g.lockouts () == 1 && g.keysRejected () == 3, "记账：锁 1 次、拒 3 次");

        r = g.requestSeed (5000);
        CHECK (!r.positive && r.uds[2] == kNrcRequiredDelayNotExpired,
               "锁定期内再要种子 → 0x37（不是 0x36、也不是给种子）");
        CHECK (g.lockRemainingMs (5000) == 5000, "剩 5 秒");

        // 锁到期：能重新要种子（而且要到一个新的）
        r = g.requestSeed (10001);
        CHECK (r.positive && g.seed () != 0, "锁到期后能重新要种子");
        CHECK (g.attempts () == 0, "错误计数一起清零（否则第 4 次错立刻又锁上）");
        CHECK (!g.lockActive (10001), "锁已释放");
    }

    // ---- I. S3：5 秒没动静回落默认会话，且锁一起解开 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        g.requestSeed (0);
        g.sendKey (keyBytes (SessionGuard::expectedKey (g.seed ())), 0);
        CHECK (g.s3Ms () == 5000, "S3 = 5000ms");

        CHECK (!g.tick (4999), "4.999 秒还没到点：不动");
        CHECK (g.tick (5001), "超过 5 秒 → 回落（返回 true 让调用方打日志）");
        CHECK (g.level () == SessionGuard::kSessionDefault, "回到默认会话");
        CHECK (!g.unlocked (), "解锁也没了");
        CHECK (!g.flashAllowed (), "门重新关上");
        CHECK (g.s3Timeouts () == 1, "超时计数 1");
        CHECK (!g.tick (5002), "已经是默认会话：不会再报超时");
    }

    // ---- J. 0x3E 保活真能拖住 S3 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 0);
        auto r = g.testerPresent (0x00, 4000);
        CHECK (r.positive && r.uds == std::vector<std::uint8_t> ({0x7E, 0x00}), "3E 00 → 7E 00");

        CHECK (!g.tick (8000), "4 秒时说了句话，8 秒还没到 5 秒窗口的尾巴：不超时");
        CHECK (g.level () == SessionGuard::kSessionProgramming, "还在编程会话");
        CHECK (g.tick (9001), "9.001 秒（最后一次活动 4 秒 + 5 秒）→ 超时");

        r = g.testerPresent (0x80, 9001);
        CHECK (r.positive && r.uds.empty (), "3E 80（suppressPosRsp）→ 不回包，但照样算活动");
        CHECK (g.lastActivityMs () == 9001, "suppress 也重置了计时（不然它反而会把自己踢掉）");

        r = g.testerPresent (0x01, 9001);
        CHECK (!r.positive && r.uds[2] == kNrcSubFunctionNotSupported, "3E 01 → 0x12");
        CHECK (g.testerPresents () == 2, "保活计数 2（00 与 80 各算一次；0x01 是错的子功能，不算）");
    }

    // ---- K. 会话不对时 0x27 02 也走 0x7F（不是 0x33）----
    {
        SessionGuard g;
        auto r = g.sendKey ({0x00, 0x00, 0x00, 0x00}, 0);
        CHECK (!r.positive && r.uds[2] == kNrcServiceNotSupportedInActiveSession,
               "默认会话里 0x27 02 → 0x7F");
        CHECK (g.denyFlash (0x36).uds[2] == kNrcServiceNotSupportedInActiveSession,
               "没进编程会话时 0x36 也是 0x7F");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
