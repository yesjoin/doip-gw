// ============================================================================
// oppermission_selftest.cpp —— M30：按操作分权限（读 < 写 < 刷写）
//
// 钉三件事：
//   ① 分类只看服务号，且"不认识"一律按最高档（安全默认，不给中间档）；
//   ② 档位是阶梯：给写的人当然能读，给刷写的人读写都能做；
//   ③ 没配置的 SA 拿默认档；SA = 0 不是一台诊断仪，不许授予。
// ============================================================================
#include "OpPermission.h"

#include <cstdio>
#include <initializer_list>
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

static ops::Tier cls (std::initializer_list<std::uint8_t> b, ops::OpInfo *info = nullptr)
{
    std::vector<std::uint8_t> v (b);
    ops::OpInfo tmp;
    const ops::Tier t = ops::classify (v.data (), v.size (), tmp);
    if (info != nullptr) *info = tmp;
    return t;
}

int main ()
{
    std::printf ("=== A 分类：只看服务号 ===\n");
    {
        CHECK (cls ({0x22, 0xF1, 0x90}) == ops::Tier::Read, "A1 0x22 读 DID → 读档");
        CHECK (cls ({0x19, 0x02}) == ops::Tier::Read, "A2 0x19 读 DTC → 读档");
        CHECK (cls ({0x3E, 0x80}) == ops::Tier::Read, "A3 0x3E 保活 → 读档（它什么也不改）");

        CHECK (cls ({0x10, 0x02}) == ops::Tier::Write, "A4 0x10 切会话 → 写档（会话是状态）");
        CHECK (cls ({0x27, 0x01}) == ops::Tier::Write, "A5 0x27 安全访问 → 写档（它是为写开门）");
        CHECK (cls ({0x2E, 0xF1, 0x84, 0x00}) == ops::Tier::Write, "A6 0x2E 写 DID → 写档");
        CHECK (cls ({0x11, 0x01}) == ops::Tier::Write, "A7 0x11 复位 → 写档");
        CHECK (cls ({0x14, 0xFF, 0xFF, 0xFF}) == ops::Tier::Write, "A8 0x14 清 DTC → 写档");
        CHECK (cls ({0x28, 0x01, 0x01}) == ops::Tier::Write, "A9 0x28 通信控制 → 写档");
        CHECK (cls ({0x2F, 0xF1, 0x90, 0x03}) == ops::Tier::Write, "A10 0x2F IO 控制 → 写档");
        CHECK (cls ({0x85, 0x02}) == ops::Tier::Write, "A11 0x85 DTC 设置 → 写档");

        CHECK (cls ({0x31, 0x01, 0x02, 0x07}) == ops::Tier::Flash, "A12 0x31 例程（装钥匙）→ 刷写档");
        CHECK (cls ({0x31, 0x01, 0xFF, 0x01}) == ops::Tier::Flash,
               "A13 0x31 校验也是刷写档：一个服务里混着擦除和校验，只看服务号分不开");
        CHECK (cls ({0x34, 0x00, 0x44}) == ops::Tier::Flash, "A14 0x34 请求下载 → 刷写档");
        CHECK (cls ({0x36, 0x01}) == ops::Tier::Flash, "A15 0x36 传块 → 刷写档");
        CHECK (cls ({0x37}) == ops::Tier::Flash, "A16 0x37 退出传输 → 刷写档");

        ops::OpInfo info;
        CHECK (cls ({0x39}, &info) == ops::Tier::Flash && info.sid == 0x39,
               "A17 不认识的服务号（0x39）→ 刷写档（安全默认），且记下它是 0x39");
        CHECK (std::string (info.what).find ("不认识") != std::string::npos, "A18 不认识的要说「不认识」");

        ops::OpInfo resp;
        CHECK (cls ({0x62, 0xF1, 0x90}, &resp) == ops::Tier::Flash &&
                   std::string (resp.what).find ("响应码") != std::string::npos,
               "A19 响应码（≥0x40）当请求发 → 刷写档，并在日志里说清是「响应码当请求」");

        ops::OpInfo empty;
        CHECK (cls ({}, &empty) == ops::Tier::Flash && empty.sid == 0, "A20 空载荷 → 刷写档（没有服务号可放）");

        // 分类不往下看：同一服务、不同参数，档位必须一样（这一层就是不看参数）
        CHECK (cls ({0x22, 0xF1, 0x90}) == cls ({0x22, 0x00, 0x01}),
               "A21 0x22 读哪个 DID 不影响档位（参数是下一层的事）");
        CHECK (cls ({0x31, 0x01, 0x02, 0x07}) == cls ({0x31, 0x01, 0xFF, 0x01}),
               "A22 0x31 哪个子功能也不影响档位（擦除和校验同档）");
    }

    std::printf ("\n=== B 档位名 ===\n");
    {
        ops::Tier t{};
        CHECK (ops::parseTier ("read", t) && t == ops::Tier::Read, "B1 read");
        CHECK (ops::parseTier ("write", t) && t == ops::Tier::Write, "B2 write");
        CHECK (ops::parseTier ("flash", t) && t == ops::Tier::Flash, "B3 flash");
        CHECK (ops::parseTier ("none", t) && t == ops::Tier::None, "B4 none（连读都不给）");
        CHECK (ops::parseTier ("READ", t) && t == ops::Tier::Read, "B5 大小写不敏感");
        CHECK (ops::parseTier ("  flash  ", t) && t == ops::Tier::Flash, "B6 容忍首尾空白");
        CHECK (!ops::parseTier ("admin", t), "B7 不认识的档名必须拒绝（猜一个差不多的等于没设）");
        CHECK (!ops::parseTier ("", t), "B8 空串拒绝");
        CHECK (!ops::parseTier ("rw", t), "B9 缩写拒绝：档名要么写全，要么不写");
        CHECK (std::string (ops::tierName (ops::Tier::Read)) == "读" &&
                   std::string (ops::tierName (ops::Tier::Write)) == "写" &&
                   std::string (ops::tierName (ops::Tier::Flash)) == "刷写",
               "B10 三个档位名给日志和横幅共用");
    }

    std::printf ("\n=== C 表与判定：阶梯 ===\n");
    {
        ops::PermissionTable tb;
        CHECK (tb.defaultTier () == ops::Tier::Read, "C1 默认档是「读」（没配置的人最小可用）");

        CHECK (tb.decide (0x0E00, ops::Tier::Read).permit, "C2 默认档能读");
        CHECK (!tb.decide (0x0E00, ops::Tier::Write).permit, "C3 默认档不能写");
        CHECK (!tb.decide (0x0E00, ops::Tier::Flash).permit, "C4 默认档更不能刷");

        CHECK (tb.grant (0x0E01, ops::Tier::Write), "C5 授予成功");
        ops::PermissionTable::Decision d = tb.decide (0x0E01, ops::Tier::Write);
        CHECK (d.permit && d.have == ops::Tier::Write && d.need == ops::Tier::Write,
               "C6 写档能做写，判定里带着「要什么 / 有什么」");
        CHECK (tb.decide (0x0E01, ops::Tier::Read).permit, "C7 写档当然能读（阶梯）");
        CHECK (!tb.decide (0x0E01, ops::Tier::Flash).permit, "C8 写档不能刷写");

        CHECK (tb.grant (0x0E02, ops::Tier::Flash), "C9 授予刷写档");
        CHECK (tb.decide (0x0E02, ops::Tier::Flash).permit, "C10 刷写档能刷");
        CHECK (tb.decide (0x0E02, ops::Tier::Write).permit, "C11 刷写档也能写");
        CHECK (tb.decide (0x0E02, ops::Tier::Read).permit, "C12 刷写档也能读");

        const std::size_t n = tb.size ();
        CHECK (n == 2, "C13 两条授权");
        CHECK (tb.grant (0x0E01, ops::Tier::Read), "C14 同一台再给一次 = 改档");
        CHECK (tb.size () == n, "C15 改档不叠成两行");
        CHECK (tb.levelOf (0x0E01) == ops::Tier::Read && !tb.decide (0x0E01, ops::Tier::Write).permit,
               "C16 后写的生效（降档也是真的降）");

        CHECK (!tb.grant (0, ops::Tier::Flash), "C17 SA=0 不是一台诊断仪，不许授予");
        CHECK (tb.levelOf (0) == ops::Tier::Read, "C18 SA=0 也不该被当成「有授权」（只是默认档）");

        tb.grant (0x0E03, ops::Tier::None);
        CHECK (!tb.decide (0x0E03, ops::Tier::Read).permit, "C19 none 档连读都不给（另一个方向的最小）");
        CHECK (!tb.decide (0x0E03, ops::Tier::None).permit, "C20 need=None 也永远不放行");

        ops::PermissionTable t2;
        t2.setDefault (ops::Tier::None);
        CHECK (!t2.decide (0x0E99, ops::Tier::Read).permit, "C21 默认档改成 none → 没配置的人连读都进不来");

        ops::PermissionTable t3;
        t3.setDefault (ops::Tier::Flash);
        CHECK (t3.decide (0x0E99, ops::Tier::Flash).permit, "C22 默认档拉满时一切放行（「谁都不配」才是全开）");

        // 顺序与内容：横幅要按授予顺序打
        ops::PermissionTable t4;
        t4.grant (0x0E07, ops::Tier::Flash);
        t4.grant (0x0E05, ops::Tier::Read);
        CHECK (t4.saAt (0) == 0x0E07 && t4.tierAt (0) == ops::Tier::Flash && t4.saAt (1) == 0x0E05 &&
                   t4.tierAt (1) == ops::Tier::Read,
               "C23 表按授予顺序保存（横幅能照原样打出来）");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
