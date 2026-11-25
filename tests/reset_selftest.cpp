// ============================================================================
// reset_selftest.cpp —— M17 的纯逻辑自测（0x11 ECUReset × 会话状态机 × 镜像）
//
// 0x11 是全项目第一条"答完之后立刻改变整机状态"的服务，最容易糊过去的四件事：
//   · 先复位再回包 —— 客户端永远收不到 51 xx，只会看到超时，然后去怀疑网关；
//   · 复位没把会话/解锁清掉 —— 复位完还能接着刷，等于没复位；
//   · 复位没把锁清掉 —— 断电了锁还在，现场像"锁焊死了"；
//   · 刷到一半允许复位 —— 半截镜像被当完整镜像用，真机上就是变砖。
// 下面每条都正着反着走一遍，时间还是当参数传，不 sleep、不要 vcan0。
//
// 镜像有两套语义（也是本题的"手算"部分）：
//   01 硬复位 → RAM 掉电，镜像没了，且回到"未擦除"（要重新 0x31 FF00）；
//   02/03     → 软复位，镜像留着，但会话与解锁照样清。
//
// 用法：./reset-selftest        全绿退出码 0
// ============================================================================
#include "FlashTarget.h"
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

// 把一台 ECU 推到"编程会话 + 已解锁"，后面很多组都从这里出发
static void unlock (SessionGuard &g, std::uint32_t nowMs)
{
    g.handleSessionControl (SessionGuard::kSessionProgramming, nowMs);
    auto seed = g.requestSeed (nowMs);
    const std::uint32_t s = (static_cast<std::uint32_t> (seed.uds[2]) << 24) |
                            (static_cast<std::uint32_t> (seed.uds[3]) << 16) |
                            (static_cast<std::uint32_t> (seed.uds[4]) << 8) |
                            static_cast<std::uint32_t> (seed.uds[5]);
    g.sendKey (keyBytes (SessionGuard::expectedKey (s)), nowMs);
}

int main ()
{
    // ---- A. 三个子功能与一个错子功能 ----
    {
        SessionGuard g;
        auto r1 = g.handleEcuReset (0x01, 0, false);
        CHECK (r1.positive && r1.uds.size () == 2 && r1.uds[0] == 0x51 && r1.uds[1] == 0x01,
               "0x11 01 → 51 01（两字节，不带任何附加参数）");
        CHECK (g.takePendingReset () == 0x01, "取到待执行复位 = 01");
        CHECK (g.takePendingReset () == 0x00, "取过一次就清零（同一个复位不会执行两遍）");

        auto r2 = g.handleEcuReset (0x02, 0, false);
        CHECK (r2.positive && r2.uds[1] == 0x02, "0x11 02 → 51 02（点火循环）");
        auto r3 = g.handleEcuReset (0x03, 0, false);
        CHECK (r3.positive && r3.uds[1] == 0x03, "0x11 03 → 51 03（软复位）");
        CHECK (g.resets () == 3, "三次复位都记账（含前两次取走的）");

        auto bad = g.handleEcuReset (0x04, 0, false);
        CHECK (!bad.positive && bad.uds.size () == 3 && bad.uds[2] == kNrcSubFunctionNotSupported,
               "0x11 04 → 7F 11 12（子功能只认 01/02/03）");
        CHECK (g.resets () == 3, "被拒的子功能不算一次复位");
    }

    // ---- B. 默认会话里也允许复位（这是"弄乱了以后一键复原"）----
    {
        SessionGuard g;
        CHECK (g.level () == SessionGuard::kSessionDefault, "从默认会话出发");
        auto r = g.handleEcuReset (0x01, 0, false);
        CHECK (r.positive && r.uds[1] == 0x01,
               "默认会话里 0x11 01 照样接受（不像 0x27 那样回 7F）");
        CHECK (g.level () == SessionGuard::kSessionDefault, "复位后仍在默认会话");
    }

    // ---- C. 复位清会话 / 解锁 / 种子 / 计数 ----
    {
        SessionGuard g;
        unlock (g, 100);
        CHECK (g.level () == SessionGuard::kSessionProgramming && g.unlocked (), "先到编程会话并解锁");
        CHECK (g.flashAllowed (), "此时刷写放行");

        auto r = g.handleEcuReset (0x03, 200, false);
        CHECK (r.positive, "软复位被接受");
        CHECK (g.level () == SessionGuard::kSessionDefault, "复位后回到默认会话");
        CHECK (!g.unlocked (), "复位把解锁清掉");
        CHECK (!g.flashAllowed (), "复位后刷写又关门");
        CHECK (g.seed () == 0 && g.attempts () == 0, "种子与错误计数清零");

        auto k = g.sendKey (keyBytes (0xA5A5A5A5), 300);
        CHECK (!k.positive && k.uds[2] == kNrcServiceNotSupportedInActiveSession,
               "复位后直接交密钥 → 7F 27 7F（得先回编程会话、再要种子）");
    }

    // ---- D. 断电把锁一起清掉（真实里锁计数常存 NVM，这里整套都在 RAM）----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionProgramming, 1000);
        auto seed = g.requestSeed (1000);
        CHECK (seed.positive, "编程会话里能要种子");
        g.sendKey (keyBytes (0x00000000), 1000);   // 错
        g.sendKey (keyBytes (0x00000000), 1000);   // 错
        auto third = g.sendKey (keyBytes (0x00000000), 1000);
        CHECK (!third.positive && third.uds[2] == kNrcExceededAttempts, "第 3 次错 → 0x36");
        CHECK (g.lockActive (1000), "锁生效");
        CHECK (g.lockRemainingMs (1000) == 10000, "锁 10000 ms");

        auto r = g.handleEcuReset (0x01, 1100, false);
        CHECK (r.positive && r.uds[1] == 0x01, "锁定期内也能硬复位（复位不是请求，是命令）");
        CHECK (!g.lockActive (1100), "复位后锁没了（断电了，锁自然也断）");
        CHECK (g.attempts () == 0, "复位后错误计数也归零");

        g.handleSessionControl (SessionGuard::kSessionProgramming, 1200);
        auto again = g.requestSeed (1200);
        CHECK (again.positive, "复位再进编程会话，立刻能要种子（不用等 10 秒）");
    }

    // ---- E. 刷写中途复位 → 0x22，且什么都不动 ----
    {
        SessionGuard g;
        unlock (g, 100);
        auto r = g.handleEcuReset (0x01, 200, true);
        CHECK (!r.positive && r.uds.size () == 3 && r.uds[2] == kNrcConditionsNotCorrect,
               "0x34 之后 0x37 之前：复位 → 7F 11 22");
        CHECK (g.level () == SessionGuard::kSessionProgramming, "被拒的复位不改会话");
        CHECK (g.unlocked (), "被拒的复位不清解锁");
        CHECK (g.takePendingReset () == 0x00, "被拒的复位不会留下待执行动作");
    }

    // ---- F. 镜像：硬复位清、软复位留 ----
    {
        FlashTarget f (34, 65536);
        CHECK (f.handleErase ().positive, "先擦除");
        f.requestDownload (0x00, 0x44, {0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08});
        f.transferData (0x01, {'1', '2', '3', '4', '5', '6', '7', '8'});
        auto ex = f.requestTransferExit ();
        CHECK (ex.positive && ex.uds.size () == 5, "8 字节刷完，0x77 带 CRC");
        const std::uint32_t crc = f.crc32 ();
        CHECK (f.image ().size () == 8, "镜像 8 字节");

        // 软复位不动镜像：只是会话层清，FlashTarget 根本没被碰
        CHECK (f.image ().size () == 8 && f.crc32 () == crc, "软复位前镜像在");
        CHECK (!f.active (), "0x37 之后已不在下载态（这条也是 0x11 能被接受的前提）");

        f.powerCycle ();
        CHECK (f.image ().empty (), "硬复位（powerCycle）把镜像清掉");
        CHECK (!f.erased (), "硬复位后回到未擦除");
        CHECK (f.lastBsc () == 0 && f.expectedSize () == 0, "BSC 与声明长度归零");
        CHECK (f.receipts () == 1, "收块计数是终身账，不随复位清");

        auto again = f.requestDownload (0x00, 0x44, {0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08});
        CHECK (!again.positive && again.uds[2] == kNrcConditionsNotCorrect,
               "硬复位后再 0x34 → 0x22（必须先重新 0x31 FF00）");
    }

    // ---- G. 复位后 S3 从头算 ----
    {
        SessionGuard g;
        g.handleSessionControl (SessionGuard::kSessionExtended, 1000);
        CHECK (!g.tick (1000), "刚进会话不超时");
        g.handleEcuReset (0x03, 4000, false);
        CHECK (!g.tick (4001), "复位把活动时间重置到 4000，4001 不该超时");
        CHECK (g.s3Timeouts () == 0, "复位不算一次 S3 超时");
        // 复位后就是默认会话，S3 在这里本来也不生效（tick 直接返回 false）
        CHECK (!g.tick (9999), "默认会话里 tick 不产生超时");
    }

    // ---- H. 三种复位分开记账 ----
    {
        SessionGuard g;
        g.handleEcuReset (0x01, 0, false);
        g.handleEcuReset (0x01, 0, false);
        g.handleEcuReset (0x02, 0, false);
        g.handleEcuReset (0x03, 0, false);
        CHECK (g.resets () == 4, "一共 4 次");
        CHECK (g.resetHard () == 2 && g.resetKeyOffOn () == 1 && g.resetSoft () == 1,
               "硬 2 / 点火循环 1 / 软 1（账要能对得上）");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
