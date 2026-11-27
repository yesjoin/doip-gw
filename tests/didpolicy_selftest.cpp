// ============================================================================
// didpolicy_selftest.cpp —— M31：DID 白名单（读什么也分档）
//
// 钉四件事：
//   ① 只有 0x22 且长度 ≥3 才算"读 DID"，别的服务一个字节都不动；
//   ② 级别映射到 M30 的三档，且"抬档"只能往上，不会把写档的请求降下来；
//   ③ 没登记的 DID 拿默认级别（默认是"受限"——安全默认）；
//   ④ DID = 0 不许进表（0 与"没登记"同义），名字表只给日志看。
// ============================================================================
#include "DidPolicy.h"

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

static bool isRead (std::initializer_list<std::uint8_t> b, dids::DidInfo *out = nullptr)
{
    std::vector<std::uint8_t> v (b);
    dids::DidInfo tmp;
    const bool r = dids::classify (v.data (), v.size (), tmp);
    if (out != nullptr) *out = tmp;
    return r;
}

static ops::Tier need (const dids::DidPolicy &t, std::initializer_list<std::uint8_t> b,
                       ops::Tier base, dids::DidInfo *out = nullptr)
{
    std::vector<std::uint8_t> v (b);
    dids::DidInfo tmp;
    const ops::Tier r = dids::needFor (t, v.data (), v.size (), base, tmp);
    if (out != nullptr) *out = tmp;
    return r;
}

static std::uint8_t T (ops::Tier t) { return static_cast<std::uint8_t> (t); }

// M32：响应方向的判定。0x62 <DID> 才算"读 DID 响应"，别的（7F / 50 / 71 / …）原样走。
static bool isResp (std::initializer_list<std::uint8_t> b, dids::DidInfo *out = nullptr)
{
    std::vector<std::uint8_t> v (b);
    dids::DidInfo tmp;
    const bool r = dids::classifyResponse (v.data (), v.size (), tmp);
    if (out != nullptr) *out = tmp;
    return r;
}

static ops::Tier needResp (const dids::DidPolicy &t, std::initializer_list<std::uint8_t> b,
                           dids::DidInfo *out = nullptr)
{
    std::vector<std::uint8_t> v (b);
    dids::DidInfo tmp;
    const ops::Tier r = dids::needForResponse (t, v.data (), v.size (), tmp);
    if (out != nullptr) *out = tmp;
    return r;
}

int main ()
{
    // ---- A 级别名与解析（10 项）----
    {
        CHECK (std::string (dids::levelName (dids::Level::Open)) == "公开", "A1 公开叫公开");
        CHECK (std::string (dids::levelName (dids::Level::Guarded)) == "受限", "A2 受限叫受限");
        CHECK (std::string (dids::levelName (dids::Level::Secret)) == "锁死", "A3 锁死叫锁死");

        dids::Level l = dids::Level::Secret;
        CHECK (dids::parseLevel ("open", l) && l == dids::Level::Open, "A4 open 解析成公开");
        CHECK (dids::parseLevel ("Guarded", l) && l == dids::Level::Guarded, "A5 大小写不敏感");
        CHECK (dids::parseLevel ("  SECRET\t", l) && l == dids::Level::Secret, "A6 容忍首尾空白");
        CHECK (!dids::parseLevel ("locked", l), "A7 拼错的级别不猜（locked 不认）");
        CHECK (!dids::parseLevel ("", l), "A8 空串不认");
        CHECK (!dids::parseLevel ("public", l), "A9 只认 open/guarded/secret 三个词");
    }

    // ---- B 级别 → 档（4 项）----
    {
        CHECK (dids::tierOf (dids::Level::Open) == ops::Tier::Read, "B1 公开 → 读档");
        CHECK (dids::tierOf (dids::Level::Guarded) == ops::Tier::Write, "B2 受限 → 写档");
        CHECK (dids::tierOf (dids::Level::Secret) == ops::Tier::Flash, "B3 锁死 → 刷写档");
        // 阶梯必须跟 M30 一致：Open < Guarded < Secret 的数字序与 Read < Write < Flash 对齐。
        CHECK (T (dids::tierOf (dids::Level::Open)) < T (dids::tierOf (dids::Level::Guarded)) &&
               T (dids::tierOf (dids::Level::Guarded)) < T (dids::tierOf (dids::Level::Secret)),
               "B4 三级是阶梯，与 M30 三档同序");
    }

    // ---- C 只认 0x22 且长度 ≥3（8 项）----
    {
        dids::DidInfo d;
        CHECK (isRead ({0x22, 0xF1, 0x90}, &d) && d.did == 0xF190, "C1 22 F1 90 → DID 0xF190");
        CHECK (d.isRead, "C2 认出来的要标成 isRead");
        CHECK (isRead ({0x22, 0xF1, 0xB0}, &d) && d.did == 0xF1B0, "C3 高字节在前（F1B0 不是 B0F1）");
        CHECK (isRead ({0x22, 0x00, 0x01}, &d) && d.did == 0x0001, "C4 DID 可以是小的");
        CHECK (!isRead ({0x22, 0xF1}), "C5 只有 2 字节 → 没有 DID，不算读 DID");
        CHECK (!isRead ({0x22}), "C6 只有服务号 → 不算");
        CHECK (!isRead ({0x2E, 0xF1, 0x84}), "C7 0x2E 写 DID 不走这一层（写本来就要写档）");
        CHECK (!isRead ({0x19, 0x01}), "C8 0x19 读 DTC 不是 DID 读");
    }

    // ---- D 表：默认档与覆盖（8 项）----
    {
        dids::DidPolicy t;
        CHECK (t.defaultLevel () == dids::Level::Guarded, "D1 默认是「受限」（安全默认）");
        CHECK (t.levelOf (0xF190) == dids::Level::Guarded, "D2 没登记的拿默认");
        CHECK (t.set (0xF190, dids::Level::Open), "D3 能登记");
        CHECK (t.levelOf (0xF190) == dids::Level::Open, "D4 登记后按登记");
        CHECK (t.size () == 1, "D5 表里一行");
        CHECK (t.set (0xF190, dids::Level::Secret) && t.size () == 1 &&
               t.levelOf (0xF190) == dids::Level::Secret,
               "D6 同一 DID 再配 = 改级，不叠成两行");
        CHECK (!t.set (0, dids::Level::Open) && t.size () == 1, "D7 DID=0 不许进表");
        t.setDefault (dids::Level::Open);
        CHECK (t.defaultLevel () == dids::Level::Open &&
               t.levelOf (0xF1FF) == dids::Level::Open,
               "D8 改默认档后，没登记的跟着变");
    }

    // ---- E 抬档（9 项）----
    {
        dids::DidPolicy t;
        t.set (0xF190, dids::Level::Open);
        t.set (0xF184, dids::Level::Guarded);
        t.set (0xF1B0, dids::Level::Secret);

        CHECK (need (t, {0x22, 0xF1, 0x90}, ops::Tier::Read) == ops::Tier::Read,
               "E1 读公开 DID：读档就够，不抬");
        CHECK (need (t, {0x22, 0xF1, 0x84}, ops::Tier::Read) == ops::Tier::Write,
               "E2 读受限 DID：抬到写档");
        CHECK (need (t, {0x22, 0xF1, 0xB0}, ops::Tier::Read) == ops::Tier::Flash,
               "E3 读锁死 DID：抬到刷写档");
        CHECK (need (t, {0x22, 0xF1, 0xFF}, ops::Tier::Read) == ops::Tier::Write,
               "E4 没登记的 DID → 默认受限 → 写档");
        CHECK (need (t, {0x10, 0x02}, ops::Tier::Write) == ops::Tier::Write,
               "E5 不是 DID 读：原样返回");
        CHECK (need (t, {0x22, 0xF1}, ops::Tier::Read) == ops::Tier::Read,
               "E6 半条 0x22（没有 DID）：不抬");
        // 抬档只往上：写档的人读公开 DID，需求仍是写（base 不动）。
        CHECK (need (t, {0x22, 0xF1, 0x90}, ops::Tier::Write) == ops::Tier::Write,
               "E7 抬档不回退：base 更高时保持 base");
        // 刷写档读锁死 DID，需求就是刷写档（不升到不存在的东西）。
        CHECK (need (t, {0x22, 0xF1, 0xB0}, ops::Tier::Flash) == ops::Tier::Flash,
               "E8 抬到顶就停在刷写档");
        // 元信息：给日志用的 what 里要有 DID 与级别。
        dids::DidInfo d;
        need (t, {0x22, 0xF1, 0xB0}, ops::Tier::Read, &d);
        CHECK (d.isRead && d.level == dids::Level::Secret &&
               d.what.find ("0xF1B0") != std::string::npos &&
               d.what.find ("锁死") != std::string::npos,
               "E9 判定结果自带 DID 与级别（日志能点名）");
    }

    // ---- F 与 PermissionTable 拼起来用（6 项）----
    {
        dids::DidPolicy dt;
        dt.set (0xF190, dids::Level::Open);
        dt.set (0xF1B0, dids::Level::Secret);

        ops::PermissionTable pt;
        pt.grant (0x0E00, ops::Tier::Read);
        pt.grant (0x0E01, ops::Tier::Write);
        pt.grant (0x0E02, ops::Tier::Flash);

        // 读档读 VIN：抬完还是读 → 放行
        CHECK (pt.decide (0x0E00, need (dt, {0x22, 0xF1, 0x90}, ops::Tier::Read)).permit,
               "F1 读档 + 公开 DID → 放行");
        // 读档读钥匙表：抬到刷写 → 挡
        const ops::PermissionTable::Decision d1 =
            pt.decide (0x0E00, need (dt, {0x22, 0xF1, 0xB0}, ops::Tier::Read));
        CHECK (!d1.permit && d1.need == ops::Tier::Flash && d1.have == ops::Tier::Read,
               "F2 读档 + 锁死 DID → 挡，且判定里写着「要刷写 / 只有读」");
        // 写档读钥匙表：仍不够
        CHECK (!pt.decide (0x0E01, need (dt, {0x22, 0xF1, 0xB0}, ops::Tier::Read)).permit,
               "F3 写档 + 锁死 DID → 还是挡");
        // 刷写档读钥匙表：够
        CHECK (pt.decide (0x0E02, need (dt, {0x22, 0xF1, 0xB0}, ops::Tier::Read)).permit,
               "F4 刷写档 + 锁死 DID → 放行");
        // 没登记的 DID = 受限，写档够、读档不够
        CHECK (!pt.decide (0x0E00, need (dt, {0x22, 0xF1, 0xFF}, ops::Tier::Read)).permit &&
               pt.decide (0x0E01, need (dt, {0x22, 0xF1, 0xFF}, ops::Tier::Read)).permit,
               "F5 没登记的 DID：读档不够、写档够");
        // 关掉这一层（不调 needFor）就等于 M30：读档读什么都行
        CHECK (pt.decide (0x0E00, ops::Tier::Read).permit,
               "F6 不抬高（这一层关着）→ 读档读任何 DID 都过，与 M30 一致");
    }

    // ---- G 名字表（3 项）----
    {
        CHECK (std::string (dids::didName (0xF1B0)) == "钥匙表", "G1 0xF1B0 备注是钥匙表");
        CHECK (std::string (dids::didName (0xF190)) == "VIN", "G2 0xF190 备注是 VIN");
        CHECK (std::string (dids::didName (0x1234)) == "未登记", "G3 没备注的说不认识");
        CHECK (dids::hex4 (0xF1B0) == "0xF1B0", "G4 日志里的 DID 打成四位十六进制");
    }

    // ---- H 响应方向（M32，14 项）----
    {
        dids::DidInfo d;
        CHECK (isResp ({0x62, 0xF1, 0x90}, &d) && d.did == 0xF190, "H1 62 F1 90 → DID 0xF190");
        CHECK (d.isRead, "H2 响应认出来的要标 isRead");
        CHECK (isResp ({0x62, 0xF1, 0xB0}, &d) && d.did == 0xF1B0, "H3 高字节在前");
        CHECK (!isResp ({0x62, 0xF1}), "H4 只有 2 字节 → 没有 DID，不算");
        CHECK (!isResp ({0x62}), "H5 只有服务号 → 不算");
        // 负响应 / 会话控制 / 普通正响应都不是 0x62 <DID>，一个都不该拦。
        CHECK (!isResp ({0x7F, 0x22, 0x33}), "H6 负响应 7F 22 33 不算读 DID 响应");
        CHECK (!isResp ({0x50, 0x02}), "H7 会话控制 50 02 不算");
        CHECK (!isResp ({0x71, 0x01, 0x02}), "H8 普通正响应 71 不算");
        CHECK (!isResp ({0x22, 0xF1, 0x90}), "H9 0x22 是请求，classifyResponse 不认它");

        dids::DidPolicy t;
        t.set (0xF190, dids::Level::Open);
        t.set (0xF184, dids::Level::Guarded);
        t.set (0xF1B0, dids::Level::Secret);

        CHECK (needResp (t, {0x62, 0xF1, 0x90}) == ops::Tier::Read,
               "H10 公开 DID 的响应 → 读档");
        CHECK (needResp (t, {0x62, 0xF1, 0x84}) == ops::Tier::Write,
               "H11 受限 DID 的响应 → 写档");
        CHECK (needResp (t, {0x62, 0xF1, 0xB0}) == ops::Tier::Flash,
               "H12 锁死 DID 的响应 → 刷写档");
        CHECK (needResp (t, {0x62, 0xF1, 0xFF}) == ops::Tier::Write,
               "H13 没登记的 DID → 默认受限 → 写档");

        // 不是 DID 读响应：返回 Read 且 isRead=false。调用方必须先看 isRead。
        dids::DidInfo dn;
        CHECK (needResp (t, {0x7F, 0x22, 0x33}, &dn) == ops::Tier::Read && !dn.isRead,
               "H14 非 DID 响应返回 Read 且 isRead=false（原样走）");
    }

    // ---- I 响应方向拼 PermissionTable（M32，4 项）----
    {
        dids::DidPolicy dt;
        dt.set (0xF190, dids::Level::Open);
        dt.set (0xF1B0, dids::Level::Secret);

        ops::PermissionTable pt;
        pt.grant (0x0E00, ops::Tier::Read);
        pt.grant (0x0E02, ops::Tier::Flash);

        // 读档收公开 DID 的响应：够
        CHECK (pt.decide (0x0E00, needResp (dt, {0x62, 0xF1, 0x90})).permit,
               "I1 读档 + 公开 DID 响应 → 放行");
        // 读档收锁死 DID 的响应：抬到刷写 → 挡（这条 0x62 不发出去）
        const ops::PermissionTable::Decision d1 =
            pt.decide (0x0E00, needResp (dt, {0x62, 0xF1, 0xB0}));
        CHECK (!d1.permit && d1.need == ops::Tier::Flash && d1.have == ops::Tier::Read,
               "I2 读档 + 锁死 DID 响应 → 挡，判定里写着「要刷写 / 只有读」");
        // 刷写档收锁死 DID 的响应：够
        CHECK (pt.decide (0x0E02, needResp (dt, {0x62, 0xF1, 0xB0})).permit,
               "I3 刷写档 + 锁死 DID 响应 → 放行");
        // 非 DID 响应（如负响应）isRead=false，调用方直接放行，不经过 decide。
        dids::DidInfo dn;
        needResp (dt, {0x7F, 0x22, 0x33}, &dn);
        CHECK (!dn.isRead, "I4 负响应 isRead=false，响应方向不拦它");
    }

    std::printf ("通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
