// ============================================================================
// activationauth_selftest.cpp —— M27 的纯逻辑自测（激活凭据）
//
// 四组：
//   A 官方向量：RFC 4231 的 6 条已知答案。**先钉尺子，再谈功能** ——
//     自己写的 HMAC 跑得过自己的测试不算数，跑得过官方向量才算；
//   B 为什么是 HMAC：和 sha256(secret||msg) 不一样，且 key/消息改一点输出全变；
//   C token：4 字节、绑 SA、固定时间比较（对/错/差一个 bit）；
//   D 解析：64 位十六错了不认、大写小写都收。
//
// 用法：./activationauth-selftest        全绿退出码 0
// ============================================================================
#include "ActivationAuth.h"
#include "Sha256.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                                                  \
    do {                                                                                   \
        if (cond) { ++gPass; }                                                             \
        else {                                                                             \
            ++gFail;                                                                       \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ());    \
        }                                                                                  \
    } while (0)

// RFC 4231 里那几条"以大写十六进制写在纸上"的答案，直接搬过来。
static const char *kRfc4231[] = {
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
};

int main ()
{
    std::printf ("=== A HMAC-SHA256 官方向量（RFC 4231）===\n");

    {
        // 1) key = 0x0b × 20，data = "Hi There"
        std::vector<std::uint8_t> key (20, 0x0b);
        const std::string data = "Hi There";
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (),
                                                   data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[0], "TC1：20 字节 0x0b 的 key");
    }
    {
        // 2) key = "Jefe"，data = "what do ya want for nothing?"  ← 真实世界里最像我们用法的一条
        const std::string key = "Jefe";
        const std::string data = "what do ya want for nothing?";
        const Sha256::Digest d = auth::hmacSha256 (
            reinterpret_cast<const std::uint8_t *> (key.data ()), key.size (),
            data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[1], "TC2：短 key（Jefe）");
    }
    {
        // 3) key = 0xaa × 20，data = 0xdd × 50
        std::vector<std::uint8_t> key (20, 0xaa), data (50, 0xdd);
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (),
                                                   data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[2], "TC3：长消息（50 字节 0xdd）");
    }
    {
        // 4) key = 0x01..0x19（25 字节），data = 0xcd × 50
        std::vector<std::uint8_t> key (25), data (50, 0xcd);
        for (int i = 0; i < 25; ++i) key[i] = static_cast<std::uint8_t> (i + 1);
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (),
                                                   data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[3], "TC4：25 字节递增 key");
    }
    {
        // 6) key = 0xaa × 131（比 64 字节的块还长）→ 必须先压成 32
        //    这条专门钉住我们代码里 `if (keyLen > 64)` 那个分支
        std::vector<std::uint8_t> key (131, 0xaa);
        const std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (),
                                                   data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[4], "TC6：131 字节 key（超块长要先压）");
    }
    {
        // 7) 同上，消息也超块长
        std::vector<std::uint8_t> key (131, 0xaa);
        const std::string data =
            "This is a test using a larger than block-size key and a larger than "
            "block-size data. The key needs to be hashed before being used by the "
            "HMAC algorithm.";
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (),
                                                   data.data (), data.size ());
        CHECK (Sha256::hex (d) == kRfc4231[5], "TC7：key 和消息都超块长");
    }
    {
        // 同一输入跑两遍必须一模一样 —— 不然"重放"都对不上账
        std::vector<std::uint8_t> key (20, 0x0b);
        const std::string data = "Hi There";
        const Sha256::Digest a = auth::hmacSha256 (key.data (), key.size (), data.data (), data.size ());
        const Sha256::Digest b = auth::hmacSha256 (key.data (), key.size (), data.data (), data.size ());
        CHECK (a == b, "同一输入两次 → 同一摘要");
    }
    {
        // key 改 1 个字节，输出必须完全不同（不是"差一点"）
        std::vector<std::uint8_t> key (20, 0x0b);
        key[0] = 0x0c;
        const std::string data = "Hi There";
        const Sha256::Digest d = auth::hmacSha256 (key.data (), key.size (), data.data (), data.size ());
        CHECK (Sha256::hex (d) != kRfc4231[0], "key 改 1 字节 → 摘要不同");
    }

    std::printf ("\n=== B 为什么是 HMAC（不是 sha256(secret||msg)）===\n");
    {
        auth::Secret secret;
        CHECK (auth::parseSecret (
                   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", secret),
               "64 位十六进制的 secret 能解析");
        const std::uint16_t sa = 0x0E00;
        const std::uint32_t tok = auth::tokenFor (secret, sa);

        // 朴素做法：sha256(secret || 消息) 的头 4 字节
        const std::string msg = "doip-ra|" + auth::saText (sa);
        std::vector<std::uint8_t> naiveIn;
        naiveIn.insert (naiveIn.end (), secret.begin (), secret.end ());
        naiveIn.insert (naiveIn.end (), msg.begin (), msg.end ());
        const Sha256::Digest naive = Sha256::of (naiveIn);
        const std::uint32_t naiveTok = (static_cast<std::uint32_t> (naive[0]) << 24) |
                                       (static_cast<std::uint32_t> (naive[1]) << 16) |
                                       (static_cast<std::uint32_t> (naive[2]) << 8) |
                                       static_cast<std::uint32_t> (naive[3]);
        CHECK (tok != naiveTok, "HMAC 与 sha256(secret||msg) 不是同一个值（域分离）");
        std::printf ("      secret=…eeff，SA=0E00 → token=%s（朴素算法会给 %s）\n",
                     auth::tokenText (tok).c_str (), auth::tokenText (naiveTok).c_str ());
    }
    {
        // 同一把 secret、换 SA → token 变（"票"是绑地址的）
        auth::Secret secret;
        auth::parseSecret ("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", secret);
        CHECK (auth::tokenFor (secret, 0x0E00) != auth::tokenFor (secret, 0x0E01),
               "同一 secret、不同 SA → 不同 token");
        CHECK (auth::tokenFor (secret, 0x0E00) == auth::tokenFor (secret, 0x0E00),
               "同一 secret、同一 SA → 稳定");
    }
    {
        // 换一把 secret → 同一 SA 的 token 也变
        auth::Secret a, b;
        auth::parseSecret ("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", a);
        // 只把开头那个字节从 0x00 改成 0x01 —— 64 位长度不变，改的是内容
        CHECK (auth::parseSecret (
                   "01112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", b),
               "第二把 secret 也解析得出来");
        CHECK (auth::tokenFor (a, 0x0E00) != auth::tokenFor (b, 0x0E00),
               "secret 差一个字节 → token 不同");
    }

    std::printf ("\n=== C 校验（固定时间比较）===\n");
    {
        auth::Secret secret;
        auth::parseSecret ("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", secret);
        const std::uint16_t sa = 0x0E00;
        const std::uint32_t right = auth::tokenFor (secret, sa);

        CHECK (auth::tokenMatches (secret, sa, right), "带对的票 → 通过");
        CHECK (!auth::tokenMatches (secret, sa, 0u), "带全 0 的票 → 不通过（老客户端就是这样）");
        CHECK (!auth::tokenMatches (secret, sa, right ^ 1u), "最低位差 1 → 不通过");
        CHECK (!auth::tokenMatches (secret, sa, right ^ 0x80000000u), "最高位差 1 → 不通过");
        CHECK (!auth::tokenMatches (secret, 0x0E01, right), "借别人的票（SA 不符）→ 不通过");
        CHECK (auth::tokenText (right).size () == 8, "token 文本固定 8 位（日志能对齐）");
    }

    std::printf ("\n=== D 解析密钥 ===\n");
    {
        auth::Secret s;
        CHECK (!auth::parseSecret ("", s), "空串 → 不认");
        CHECK (!auth::parseSecret (std::string (63, '0'), s), "63 位 → 不认（长度不对不猜）");
        CHECK (!auth::parseSecret (std::string (65, '0'), s), "65 位 → 不认");
        CHECK (!auth::parseSecret (std::string (64, 'z'), s), "非十六进制 → 不认");
        CHECK (auth::parseSecret (std::string (64, 'A'), s) && s[0] == 0xAA,
               "大写十六进制也收（人抄密钥时大小写不统一）");
        CHECK (auth::parseSecret (std::string (64, '0'), s) && s[31] == 0x00,
               "全 0 的密钥在语法上合法（弱是另一回事，不在这里拦）");
    }

    std::printf ("\n=== 汇总：通过 %d 项，失败 %d 项 ===\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
