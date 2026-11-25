// ============================================================================
// policy_selftest.cpp —— M20 自测：版本比较 + 身份比对 + 凭证生命周期
//
// A. 版本：parse 的形状、数值比较（含 1.10.0 vs 1.9.0 这个字符串比较的陷阱）
// B. 比对：零件号不符、降级、同版本重刷、升级、版本格式不对
// C. 凭证：一次一用、失败不给、clear 后失效、计数
// ============================================================================
#include "FlashPolicy.h"

#include <cstdio>
#include <string>

namespace {

int gChecks = 0;
int gFails  = 0;

void check (bool ok, const std::string &what)
{
    ++gChecks;
    if (!ok) ++gFails;
    std::printf ("%s %s\n", ok ? "[ OK ]" : "[FAIL]", what.c_str ());
}

} // namespace

int main ()
{
    std::printf ("=== M20 版本比较 / 身份比对 / 凭证 自测 ===\n\n");
    using doip::policy::Version;
    using doip::policy::Verdict;
    using doip::policy::checkIdentity;

    // ---------------- A. 版本 ----------------
    std::printf ("A. 版本号解析与比较\n");
    {
        const auto v = Version::parse ("SW-1.0.3");
        check (v.valid && v.n[0] == 1 && v.n[1] == 0 && v.n[2] == 3,
               "A1 \"SW-1.0.3\" → 1.0.3（前缀不算，只认数字）");
        check (v.str () == "1.0.3", "A2 规范化成 1.0.3（打印用）");

        check (Version::parse ("1.0.3").valid, "A3 不带前缀 \"1.0.3\" 也认");
        check (!Version::parse ("SW-1.0").valid, "A4 \"SW-1.0\" 只有两段 → 不认（结构错）");
        check (!Version::parse ("SW-1.0.3.4").valid, "A5 四段 → 不认");
        check (!Version::parse ("SW-a.b.c").valid, "A6 字母 → 不认");
        check (!Version::parse ("").valid, "A7 空串 → 不认");

        const auto a = Version::parse ("1.9.0");
        const auto b = Version::parse ("1.10.0");
        check (a.valid && b.valid, "A8 1.9.0 与 1.10.0 都能解析");
        check (b.compare (a) == 1, "A9 **数值上 1.10.0 > 1.9.0**（这是字符串比较会判错的地方）");
        check (std::string ("1.10.0") < std::string ("1.9.0"),
               "A10 对照：字符串比较确实会说 1.10.0 < 1.9.0 —— 所以不能用字符串比版本");

        check (Version::parse ("1.0.3").compare (Version::parse ("1.0.3")) == 0,
               "A11 同版本 compare = 0");
        check (Version::parse ("2.0.0").compare (Version::parse ("1.99.99")) == 1,
               "A12 主版本优先：2.0.0 > 1.99.99");
        check (!Version::parse ("99999.0.0").valid, "A13 超长数字被拒（不让畸形输入撑爆）");
    }

    // ---------------- B. 身份比对 ----------------
    std::printf ("\nB. 包与车能不能对上\n");
    {
        const std::string PART = "PART-ABC1234";
        const std::string SW   = "SW-1.0.3";

        auto r = checkIdentity (PART, SW, PART, "SW-1.0.4", false);
        check (r.ok () && r.verdict == Verdict::Ok, "B1 升级 1.0.3 → 1.0.4 放行（" + r.reason + "）");

        r = checkIdentity (PART, SW, PART, SW, false);
        check (r.ok () && r.reason.find ("同版本") != std::string::npos,
               "B2 同版本重刷放行，且日志说明是修复场景（" + r.reason + "）");

        r = checkIdentity (PART, SW, PART, "SW-1.0.2", false);
        check (!r.ok () && r.verdict == Verdict::Downgrade,
               "B3 降级 1.0.3 → 1.0.2 被拒（" + r.reason + "）");

        r = checkIdentity (PART, SW, PART, "SW-1.0.2", true);
        check (r.ok () && r.reason.find ("allowDowngrade") != std::string::npos,
               "B4 开了 allowDowngrade → 降级也放行，但日志写明（" + r.reason + "）");

        r = checkIdentity (PART, SW, "PART-XYZ9999", "SW-1.0.4", false);
        check (!r.ok () && r.verdict == Verdict::PartMismatch,
               "B5 零件号不符 → 拒，而且优先于版本判断（" + r.reason + "）");

        r = checkIdentity (PART, SW, PART, "SW-latest", false);
        check (!r.ok () && r.verdict == Verdict::BadTargetVersion,
               "B6 目标版本不是三段数字 → 结构错（" + r.reason + "）");

        r = checkIdentity (PART, "SW-1.9.0", PART, "SW-1.10.0", false);
        check (r.ok (), "B7 车上 1.9.0、包里 1.10.0 → **升级放行**（字符串比较会误判成降级）");

        r = checkIdentity (PART, "SW-1.9.0", PART, "SW-1.8.0", false);
        check (!r.ok () && r.verdict == Verdict::Downgrade, "B8 车上 1.9.0、包里 1.8.0 → 降级拒");

        r = checkIdentity (PART, "SW-broken", PART, "SW-1.0.4", false);
        check (!r.ok () && r.verdict == Verdict::BadCurrentVersion,
               "B9 车自己报的版本解析不了 → 拒（配置错，先查车）");
    }

    // ---------------- C. 凭证 ----------------
    std::printf ("\nC. 检查结果当凭证：一次一用\n");
    {
        doip::policy::Gate g;
        check (!g.checked () && !g.ok (), "C1 刚建出来：未检查，也就没有资格");
        check (!g.consumeOk (), "C2 未检查就取凭证 → false（0x34 该回 0x22）");

        g.set (false, "零件号不符：车上 A，包里 B");
        check (g.checked () && !g.ok (), "C3 检查不通过：checked 但 ok=false");
        check (!g.consumeOk (), "C4 不通过的凭证取不出来（拦在 0x34）");

        g.set (true, "升级：1.0.3 → 1.0.4");
        check (g.ok () && g.note ().find ("通过") != std::string::npos, "C5 通过：note 以「通过」开头");

        check (g.consumeOk (), "C6 第一次取 → 成功");
        check (!g.checked () && !g.ok (), "C7 取走之后立刻作废（一次一用）");
        check (g.note ().find ("已用掉") != std::string::npos,
               "C8 note 记着「已用掉」（日志能看出凭证去哪儿了）");
        check (!g.consumeOk (), "C9 第二次取 → false（同一张凭证不能刷两次）");

        g.set (true, "同版本重刷：1.0.3");
        g.clear ();
        check (!g.ok () && g.note () == "未检查", "C10 clear 之后回到未检查（擦除/复位/换会话都走这个）");

        // 计数是观测量：清凭证不清账
        check (g.checks () == 3, "C11 账：检查 3 次（不通过 1 + 通过 2）");
        check (g.consumes () == 1, "C12 账：凭证被用掉 1 次");
    }

    std::printf ("\n结果：%d 项，失败 %d 项\n", gChecks, gFails);
    return gFails == 0 ? 0 : 1;
}
