// ============================================================================
// registry_selftest.cpp —— M13 的纯逻辑自测（TesterRegistry）
//
// 这个账本只做两张表，但写错的方式很多：
//   · 同一连接重复激活被当成错误 → 断线重连就失败；
//   · 两个连接用同一个 SA 都"成功" → 两台 tester 同址说话；
//   · 释放时只删了一张表 → 地址永远要不回来（泄漏）；
//   · 满了以后报错，却没把"没空位"和"地址被占"分开 → 现场不知道该找谁。
// 所以这里把每种组合都走一遍，包括"释放后地址能要回来"。
//
// 用法：./registry-selftest        全绿时退出码 0
// ============================================================================
#include "TesterRegistry.h"

#include <cstdio>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, what);     \
        }                                                              \
    } while (0)

int main ()
{
    // ---- A. 空账本：谁都还没来 ----
    {
        TesterRegistry r;
        CHECK (r.active () == 0, "空账本：0 个激活");
        CHECK (r.addressOf (1) == 0, "没登记过的连接 → 0");
        CHECK (r.ownerOf (0x0E00) == 0, "没人用的地址 → 0");
        CHECK (r.conflicts () == 0 && r.capacityRejects () == 0, "空账本：两个计数都是 0");
    }

    // ---- B. 一次正常登记 ----
    {
        TesterRegistry r;
        auto x = r.tryRegister (0x0E00, 1);
        CHECK (x.ok && x.code == 0x10, "第一条 tester 0x0E00 → 成功 0x10");
        CHECK (r.active () == 1, "登记后 1 个激活");
        CHECK (r.addressOf (1) == 0x0E00, "连接 1 的地址是 0x0E00");
        CHECK (r.ownerOf (0x0E00) == 1, "0x0E00 的占用者是连接 1");
    }

    // ---- C. 同一连接、同一地址重复激活：幂等 ----
    {
        TesterRegistry r;
        r.tryRegister (0x0E00, 1);
        auto x = r.tryRegister (0x0E00, 1);
        CHECK (x.ok && x.code == 0x10, "同连接同地址重发 → 仍回 0x10（断线重连是常态）");
        CHECK (r.active () == 1, "重复激活不增加计数");
    }

    // ---- D. 同一连接换地址：0x02 ----
    {
        TesterRegistry r;
        r.tryRegister (0x0E00, 1);
        auto x = r.tryRegister (0x0E01, 1);
        CHECK (!x.ok && x.code == 0x02, "同一连接换地址 → 0x02");
        CHECK (r.addressOf (1) == 0x0E00, "被拒之后原绑定不变");
        CHECK (r.ownerOf (0x0E01) == 0, "被拒的地址没有被偷偷登记");
    }

    // ---- E. 另一个连接抢同一个地址：0x03，且计数涨 ----
    {
        TesterRegistry r;
        r.tryRegister (0x0E00, 1);
        auto x = r.tryRegister (0x0E00, 2);
        CHECK (!x.ok && x.code == 0x03, "另一个连接抢 0x0E00 → 0x03（同址说话必须拒）");
        CHECK (r.conflicts () == 1, "冲突计数 = 1");
        CHECK (r.ownerOf (0x0E00) == 1, "地址仍然属于先来的那条连接");
        CHECK (r.active () == 1, "被拒的连接没有占住名额");
    }

    // ---- F. 资格满了：0x01（和 0x03 是两件事） ----
    {
        TesterRegistry r (2);
        r.tryRegister (0x0E00, 1);
        r.tryRegister (0x0E01, 2);
        auto x = r.tryRegister (0x0E02, 3);
        CHECK (!x.ok && x.code == 0x01, "第三个 tester（上限 2）→ 0x01 没有空位");
        CHECK (r.capacityRejects () == 1, "容量拒绝计数 = 1");
        CHECK (r.conflicts () == 0, "这不是地址冲突，别记到 0x03 的账上");
    }

    // ---- G. 释放之后，地址能要回来 ----
    {
        TesterRegistry r (2);
        r.tryRegister (0x0E00, 1);
        r.tryRegister (0x0E01, 2);
        CHECK (r.release (1), "释放连接 1 → 确实释放了");
        CHECK (r.active () == 1, "释放后剩 1 个");
        CHECK (r.ownerOf (0x0E00) == 0, "0x0E00 已经不是谁的");
        auto x = r.tryRegister (0x0E00, 3);
        CHECK (x.ok, "新连接拿旧地址 → 成功（地址不是永久绑定）");
        CHECK (r.addressOf (3) == 0x0E00, "新连接 3 拿到 0x0E00");
    }

    // ---- H. 释放一个没登记的连接：什么也不该发生 ----
    {
        TesterRegistry r;
        r.tryRegister (0x0E00, 1);
        CHECK (!r.release (99), "释放没登记过的连接 → false");
        CHECK (r.active () == 1, "活着的连接不受影响");
        CHECK (r.addressOf (1) == 0x0E00, "它的地址还在");
    }

    // ---- I. 先释放、再重复释放 ----
    {
        TesterRegistry r;
        r.tryRegister (0x0E05, 7);
        CHECK (r.release (7), "第一次释放成功");
        CHECK (!r.release (7), "第二次释放 → false（幂等，不报错）");
        CHECK (r.active () == 0, "两条表都清干净了");
        CHECK (r.ownerOf (0x0E05) == 0, "地址表也清了（只删一张表就是泄漏）");
    }

    // ---- J. 计数是观测量，不回退 ----
    {
        TesterRegistry r (1);
        r.tryRegister (0x0E00, 1);
        r.tryRegister (0x0E00, 2);     // 0x03
        r.tryRegister (0x0E01, 3);     // 先撞车？不，0x0E01 没被占，但名额满了 → 0x01
        CHECK (r.conflicts () == 1, "冲突 1 次");
        CHECK (r.capacityRejects () == 1, "容量拒绝 1 次");
        r.release (1);
        CHECK (r.conflicts () == 1, "释放之后计数不回退（它是历史，不是状态）");
        r.clear ();
        CHECK (r.conflicts () == 0 && r.capacityRejects () == 0, "clear 之后归零");
        CHECK (r.active () == 0, "clear 之后没有激活");
    }

    // ---- K. 边界值：最大 tester 段地址、64 位连接号 ----
    {
        TesterRegistry r;
        auto x = r.tryRegister (0x0EFF, 0xFFFFFFFFFFFFFFFFull);
        CHECK (x.ok, "0x0EFF 与 64 位连接号都能登记");
        CHECK (r.addressOf (0xFFFFFFFFFFFFFFFFull) == 0x0EFF, "按 64 位连接号查得回来");
        CHECK (r.ownerOf (0x0EFF) == 0xFFFFFFFFFFFFFFFFull, "按地址查得回连接号");
    }

    // ---- L. 上限可改：运行期放宽容量的入口 ----
    {
        TesterRegistry r (1);
        r.tryRegister (0x0E00, 1);
        auto x = r.tryRegister (0x0E01, 2);
        CHECK (!x.ok && x.code == 0x01, "上限 1 时第二个被拒");
        r.setMaxActive (2);
        auto y = r.tryRegister (0x0E01, 2);
        CHECK (y.ok, "把上限改成 2 之后再试 → 成功");
        CHECK (r.active () == 2, "现在 2 个激活");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
