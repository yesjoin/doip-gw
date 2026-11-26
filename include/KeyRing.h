// ============================================================================
// KeyRing.h —— M22：钥匙不止一把，而且每把钥匙有自己的"处境"
//
// M18–M21 里钥匙是写死的：`demoKey(0x0001)` / `demoKey(0x0002)` 两把，
// `lookupKey()` 一个 switch 就查完了。这在演示里够用，在真项目里不够 ——
//   ① 换钥匙：厂商按期轮换，新包用新钥匙签，老包还在路上；
//   ② 钥匙泄露：必须**立刻**拒收，而不是等下个版本的车再改代码；
//   ③ 审计：现场要能回答"这台车现在认哪几把钥匙"。
//
// 所以钥匙要变成一张**表**，每把有 id、材料、状态：
//
//   Unknown ──install──► Active ──retire──► Retiring ──revoke──► Revoked
//                           ▲                   │                  │
//                           └──── revive ───────┘            终态，出不去
//
// 为什么要有 Retiring（退役）这一档，而不是"删掉"：
//   删掉等于把在途的包全判死 —— 已经签好、还没刷的包会突然验不过。
//   退役态让老钥匙**还能验**（日志记一笔"退役钥匙"），但不再有新包用它签。
//
// 为什么 Revoked 是终态：
//   吊销的前提是"这把钥匙已经不可信了"。把它复活，等于把泄露的钥匙重新启用。
//   要恢复，只能装一把**新 keyId** 的新钥匙 —— 换 id 才能换材料。
//
// 为什么同 id 不许覆盖安装：
//   覆盖意味着"知道旧钥匙的人可以把 Active 槽位换成自己的材料"，
//   这就把"钥匙管理"变成了"谁先来谁说了算"。装新钥匙请用新 id。
//
// 表是定长的（8 把）：嵌入式车控里动态分配在这个场景没有收益，
//   定长换来的是"永远不会在装钥匙的时候 OOM"。
// ============================================================================
#ifndef DOIP_KEY_RING_H
#define DOIP_KEY_RING_H

#include "Sha256.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace doip {
namespace keys {

enum class State : std::uint8_t
{
    Active   = 0x00,   // 可以签、可以验
    Retiring = 0x01,   // 只验不签（在途包还能过）
    Revoked  = 0x02    // 拒收，终态
};

inline const char *stateName (State s)
{
    switch (s)
    {
        case State::Active:   return "启用";
        case State::Retiring: return "退役";
        case State::Revoked:  return "吊销";
    }
    return "?";
}

// 0x22 F1B0 里报出去的字节就是这个值（00/01/02），所以顺序不能随手改
inline std::uint8_t stateCode (State s) { return static_cast<std::uint8_t> (s); }

struct Entry
{
    std::uint16_t   id = 0;
    Sha256::Digest  key {};
    State           state = State::Active;
};

// 装钥匙的结论。分开的理由和 M20 那条一样：
//   "结构/请求不对" 与 "内容不允许" 是两类事，调用方要用不同的码回答。
enum class Install
{
    Ok,         // 装上了
    Exists,     // 这个 id 已经有一把（不管什么状态）—— 不许覆盖，也不许用它复活
    BadId,      // id 0 是"没有钥匙"的意思，不能占槽
    Full        // 表满了
};

inline const char *installName (Install r)
{
    switch (r)
    {
        case Install::Ok:     return "装上了";
        case Install::Exists: return "这个 id 已经有钥匙了（不许覆盖）";
        case Install::BadId:  return "keyId 0 不能占槽";
        case Install::Full:   return "钥匙表满了";
    }
    return "?";
}

// 改状态的三种结论
enum class Transition
{
    Ok,
    NotFound,    // 表里没有这把
    Immutable    // Revoked 出不去（终态）
};

class KeyRing
{
    public:
        static constexpr std::size_t kMaxKeys = 8;

        // 装一把新钥匙（只能装到空槽，只能装成 Active）
        Install install (std::uint16_t id, const Sha256::Digest &key)
        {
            if (id == 0) return Install::BadId;
            if (find (id) != nullptr) return Install::Exists;
            if (n_ >= kMaxKeys) return Install::Full;
            entries_[n_].id    = id;
            entries_[n_].key   = key;
            entries_[n_].state = State::Active;
            ++n_;
            return Install::Ok;
        }

        // 改状态：Active ⇄ Retiring 双向（回滚现场很常见），两者都能 → Revoked
        Transition setState (std::uint16_t id, State want)
        {
            Entry *e = find (id);
            if (e == nullptr) return Transition::NotFound;
            if (e->state == State::Revoked) return Transition::Immutable;   // 终态出不去
            e->state = want;
            return Transition::Ok;
        }

        // 两个 find：改状态要拿到可写的 Entry，查表只要读。
        //   写两遍循环比 const_cast 更直白 —— 这类"只差 const"的代码量换来的是没人误改。
        Entry *find (std::uint16_t id)
        {
            for (std::size_t i = 0; i < n_; ++i)
                if (entries_[i].id == id) return &entries_[i];
            return nullptr;
        }

        const Entry *find (std::uint16_t id) const
        {
            for (std::size_t i = 0; i < n_; ++i)
                if (entries_[i].id == id) return &entries_[i];
            return nullptr;
        }

        std::size_t size () const { return n_; }

        std::size_t count (State s) const
        {
            std::size_t c = 0;
            for (std::size_t i = 0; i < n_; ++i)
                if (entries_[i].state == s) ++c;
            return c;
        }

        const Entry &at (std::size_t i) const { return entries_[i]; }

        // 给日志用："0x0001 启用 / 0x0002 退役"
        std::string dump () const
        {
            if (n_ == 0) return "（空表）";
            std::string s;
            char buf[32];
            for (std::size_t i = 0; i < n_; ++i)
            {
                std::snprintf (buf, sizeof buf, "0x%04X %s", static_cast<unsigned> (entries_[i].id),
                               stateName (entries_[i].state));
                if (i) s += " / ";
                s += buf;
            }
            return s;
        }

    private:
        std::array<Entry, kMaxKeys> entries_ {};
        std::size_t                 n_ = 0;
};

} // namespace keys
} // namespace doip

#endif
