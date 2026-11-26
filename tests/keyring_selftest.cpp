// ============================================================================
// keyring_selftest.cpp —— M22 的纯逻辑自测（钥匙表：装、退役、吊销、查）
//
// 四组，各自回答一个问题：
//   A 安装：能不能装、能不能装第二次、id 0、表满；
//   B 状态：Active ⇄ Retiring 双向、Revoked 是终态；
//   C 查表：找得到 / 找不到 / dump 的形状（0x22 F1B0 报的就是它）；
//   D 和清单联起来：退役钥匙签的包照验（带 keyState），吊销钥匙签的包直接拒。
//
// 为什么把 D 放进这个套件而不是 integrity：这一步真正新增的语义是
//   "同一份清单，钥匙状态不同 → 结论不同"，它必须和钥匙表一起验才说得清。
//
// 用法：./keyring-selftest        全绿退出码 0
// ============================================================================
#include "FirmwareManifest.h"
#include "KeyRing.h"
#include "Sha256.h"

#include <cstdio>
#include <string>
#include <vector>

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

int main ()
{
    // ---- A. 安装 ----
    {
        keys::KeyRing ring;
        CHECK (ring.size () == 0 && ring.dump () == "（空表）", "A1 新表是空的，dump 说「空表」");

        CHECK (ring.install (0x0001, fw::demoKey (0x0001)) == keys::Install::Ok, "A2 装 1 号：装上");
        CHECK (ring.size () == 1, "A3 表里现在一把");

        CHECK (ring.install (0x0001, fw::demoKey (0x0002)) == keys::Install::Exists,
               "A4 同一个 id 装第二把 → Exists（不许覆盖：覆盖等于让别人改你的钥匙）");
        CHECK (ring.find (0x0001)->key == fw::demoKey (0x0001),
               "A5 被拒的覆盖没有改动原来的材料");

        CHECK (ring.install (0x0000, fw::demoKey (0x0003)) == keys::Install::BadId,
               "A6 keyId 0 不能占槽（0 的意思是「没有钥匙」）");

        // 表满：8 把是上限，第 9 把必须被拒
        keys::KeyRing full;
        for (std::uint16_t id = 1; id <= keys::KeyRing::kMaxKeys; ++id)
            full.install (id, fw::demoKey (id));
        CHECK (full.size () == keys::KeyRing::kMaxKeys, "A7 装满 8 把");
        CHECK (full.install (0x0010, fw::demoKey (0x0010)) == keys::Install::Full,
               "A8 第 9 把 → Full（定长表：装钥匙时不会 OOM，只会有明确的上限）");
    }

    // ---- B. 状态机 ----
    {
        keys::KeyRing ring;
        ring.install (0x0001, fw::demoKey (0x0001));

        CHECK (ring.at (0).state == keys::State::Active, "B1 新装进来的钥匙是启用态");
        CHECK (ring.setState (0x0001, keys::State::Retiring) == keys::Transition::Ok &&
                   ring.at (0).state == keys::State::Retiring,
               "B2 启用 → 退役");
        CHECK (ring.setState (0x0001, keys::State::Active) == keys::Transition::Ok &&
                   ring.at (0).state == keys::State::Active,
               "B3 退役 → 启用（回滚：现场遇到在途包被打死时会用）");
        CHECK (ring.setState (0x0001, keys::State::Revoked) == keys::Transition::Ok, "B4 启用 → 吊销");
        CHECK (ring.setState (0x0001, keys::State::Active) == keys::Transition::Immutable &&
                   ring.at (0).state == keys::State::Revoked,
               "B5 吊销是终态：出不去（要恢复只能装新 keyId 的新钥匙）");
        CHECK (ring.setState (0x0099, keys::State::Revoked) == keys::Transition::NotFound,
               "B6 表里没有的 id → NotFound");
    }

    // ---- C. 查表与计数 ----
    {
        keys::KeyRing ring;
        ring.install (0x0001, fw::demoKey (0x0001));
        ring.install (0x0002, fw::demoKey (0x0002));
        ring.install (0x0003, fw::demoKey (0x0003));
        ring.setState (0x0002, keys::State::Retiring);
        ring.setState (0x0003, keys::State::Revoked);

        CHECK (ring.find (0x0002) != nullptr && ring.find (0x0002)->state == keys::State::Retiring,
               "C1 找到 2 号，状态是退役");
        CHECK (ring.find (0x0004) == nullptr, "C2 找不到 4 号");
        CHECK (ring.count (keys::State::Active) == 1 && ring.count (keys::State::Retiring) == 1 &&
                   ring.count (keys::State::Revoked) == 1,
               "C3 三种状态各一把（审计要能一眼数出来）");
        CHECK (ring.dump () == "0x0001 启用 / 0x0002 退役 / 0x0003 吊销",
               "C4 dump 的形状固定（这是 0x22 F1B0 报出去的东西的人话版）");
        CHECK (keys::stateCode (keys::State::Active) == 0x00 &&
                   keys::stateCode (keys::State::Retiring) == 0x01 &&
                   keys::stateCode (keys::State::Revoked) == 0x02,
               "C5 状态码 00/01/02：顺序与枚举一致（协议里报的就是这三个数）");
    }

    // ---- D. 钥匙状态 × 清单 ----
    {
        std::vector<std::uint8_t> image = {1, 2, 3, 4, 5, 6, 7, 8};
        keys::KeyRing ring;
        ring.install (0x0001, fw::demoKey (0x0001));
        ring.install (0x0002, fw::demoKey (0x0002));

        const auto m1 = fw::buildManifest (8u, Sha256::of (image), 0x0001, fw::demoKey (0x0001));
        CHECK (fw::verify (image, m1, ring).ok (), "D1 启用钥匙签的包 → 验得过（对照）");

        ring.setState (0x0001, keys::State::Retiring);
        const auto retired = fw::verify (image, m1, ring);
        CHECK (retired.ok (), "D2 钥匙退役了，**已经签好的包照验**（在途包不能突然判死）");
        CHECK (retired.ok () && retired.keyState == keys::State::Retiring,
               "D3 结论里带着「这把是退役钥匙」（调用方要记账）");

        ring.setState (0x0001, keys::State::Revoked);
        const auto revoked = fw::verify (image, m1, ring);
        CHECK (revoked.verdict == fw::Verdict::RevokedKey,
               "D4 钥匙吊销 → RevokedKey（不是 BadTag：包可能完全没被改过）");
        CHECK (!revoked.ok (), "D5 吊销钥匙签的包一律验不过");
        CHECK (revoked.reason.find ("吊销") != std::string::npos,
               "D6 理由里点名「吊销」，日志里能直接看到是钥匙的问题");

        // 表里根本没有这个 id：也要和吊销分开
        const auto m3 = fw::buildManifest (8u, Sha256::of (image), 0x0003, fw::demoKey (0x0003));
        CHECK (fw::verify (image, m3, ring).verdict == fw::Verdict::UnknownKey,
               "D7 表里没有这个 keyId → UnknownKey（与吊销分开：一个不认识，一个认识但不能用）");

        // 新装一把 3 号，同一份清单立刻就能过
        CHECK (ring.install (0x0003, fw::demoKey (0x0003)) == keys::Install::Ok, "D8 补装 3 号");
        CHECK (fw::verify (image, m3, ring).ok (),
               "D9 装上之后同一份清单就验得过（钥匙表是活的，不是编译期常量）");

        // 老路径（不传表）不受影响
        CHECK (fw::verify (image, m1).ok () && !fw::verify (image, m1, ring).ok (),
               "D10 同一份清单：演示表说验得过、这台车的表说吊销 —— 结论取决于「谁的表」");
    }

    // ---- D 的补充：老路径必须仍然可用（M18–M21 的 46 项全靠它）----
    {
        std::vector<std::uint8_t> image = {9, 8, 7};
        const auto m2 = fw::buildManifestV2 (3u, Sha256::of (image), 0x0002,
                                            "PART-ABC1234", "SW-1.0.3", fw::demoKey (0x0002));
        CHECK (fw::verify (image, m2).ok (), "D11 不传钥匙表时用演示表（1/2 号启用），v2 照旧能验");
        CHECK (fw::checkEnvelope (m2).ok (), "D12 checkEnvelope 的老重载也还在");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
