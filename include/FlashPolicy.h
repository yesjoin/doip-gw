// ============================================================================
// FlashPolicy.h —— M20：把"读到的身份"变成"能不能刷"的决定
//
// M19 已经读得出 F187 零件号 / F188 软件版本。读到了不等于用上了：
// 一台车可以报出正确的零件号，然后照样被刷进另一台车的程序。
// M20 补的是**比对**这一层，三件事：
//
//   ① 版本必须按数值比，不能按字符串比 ——
//      "SW-1.10.0" 与 "SW-1.9.0"：数值上 1.10.0 更大（升级），
//      字符串上 "1.10.0" < "1.9.0"（因为 '1' < '9'），会被误判成降级。
//      这就是为什么版本号要 parse 成三个整数再比。
//
//   ② 三种结论要分开：零件号不符（刷错车）、版本降级（刷回旧程序）、同版本重刷（修复）。
//      前两个拒，第三个放行 —— 现场最常见的就是"同版本重刷一遍试试"。
//
//   ③ 检查结果要变成**凭证**，而且一次一用（Gate）：
//      "上周检查通过"不能用来刷今天的包。擦除 / 复位 / 换会话 / 收尾都要把凭证作废。
//
// 结构错（长度不对、版本号不是三个数字）给 NRC；
// 内容是"对不上"给正响应 01。这条分工从 M18 一路延续。
// ============================================================================
#ifndef DOIP_FLASH_POLICY_H
#define DOIP_FLASH_POLICY_H

#include <cstdint>
#include <cstdio>
#include <string>

namespace doip {
namespace policy {

// ---------------------------------------------------------------------------
// 版本号：三段十进制，允许前缀（"SW-1.0.3" / "1.0.3" 都认）
// ---------------------------------------------------------------------------
struct Version
{
    int  n[3]  = {0, 0, 0};
    bool valid = false;

    static Version parse (const std::string &s)
    {
        Version v;
        std::size_t i = 0;
        while (i < s.size () && (s[i] < '0' || s[i] > '9')) ++i;   // 跳过 "SW-" 这类前缀
        for (int k = 0; k < 3; ++k)
        {
            if (i >= s.size () || s[i] < '0' || s[i] > '9') return v;
            int val = 0;
            while (i < s.size () && s[i] >= '0' && s[i] <= '9')
            {
                val = val * 10 + (s[i] - '0');
                ++i;
                if (val > 9999) return v;        // 别让畸形输入撑爆
            }
            v.n[k] = val;
            if (k < 2)
            {
                if (i >= s.size () || s[i] != '.') return v;
                ++i;
            }
        }
        if (i != s.size ()) return v;            // 后面还有东西 → 不是三段
        v.valid = true;
        return v;
    }

    // -1 / 0 / +1；只在 valid 时用
    int compare (const Version &o) const
    {
        for (int k = 0; k < 3; ++k)
        {
            if (n[k] != o.n[k]) return n[k] < o.n[k] ? -1 : 1;
        }
        return 0;
    }

    std::string str () const
    {
        char buf[32];
        std::snprintf (buf, sizeof buf, "%d.%d.%d", n[0], n[1], n[2]);
        return std::string (buf);
    }
};

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------
enum class Verdict
{
    Ok,               // 零件号对得上，版本不降级（或允许降级）
    PartMismatch,     // 这台车的零件号和包的目标零件号不是一回事
    Downgrade,        // 目标版本比现在低，而且没开 allowDowngrade
    BadTargetVersion, // 目标版本不是三段数字（结构错）
    BadCurrentVersion // 车自己报的版本解析不了（配置错）
};

inline const char *verdictName (Verdict v)
{
    switch (v)
    {
        case Verdict::Ok:               return "可以刷";
        case Verdict::PartMismatch:     return "零件号不符";
        case Verdict::Downgrade:        return "目标版本比现在低";
        case Verdict::BadTargetVersion: return "目标版本号格式不对";
        case Verdict::BadCurrentVersion:return "本车版本号解析不了";
    }
    return "?";
}

struct Result
{
    Verdict     verdict = Verdict::Ok;
    std::string reason;      // 给日志：人话 + 两边具体值

    bool ok () const { return verdict == Verdict::Ok; }
};

inline Result checkIdentity (const std::string &curPart, const std::string &curSw,
                             const std::string &targetPart, const std::string &targetSw,
                             bool allowDowngrade)
{
    Result r;

    if (curPart != targetPart)
    {
        r.verdict = Verdict::PartMismatch;
        r.reason  = "零件号不符：车上 " + curPart + "，包里 " + targetPart;
        return r;
    }

    const Version tv = Version::parse (targetSw);
    if (!tv.valid)
    {
        r.verdict = Verdict::BadTargetVersion;
        r.reason  = "目标版本「" + targetSw + "」不是三段数字（要像 SW-1.0.3）";
        return r;
    }

    const Version cv = Version::parse (curSw);
    if (!cv.valid)
    {
        r.verdict = Verdict::BadCurrentVersion;
        r.reason  = "本车版本「" + curSw + "」解析不了，先查配置";
        return r;
    }

    const int cmp = tv.compare (cv);
    if (cmp < 0 && !allowDowngrade)
    {
        r.verdict = Verdict::Downgrade;
        r.reason  = "降级：车上 " + cv.str () + "，包里 " + tv.str () + "（没开 allowDowngrade）";
        return r;
    }

    r.verdict = Verdict::Ok;
    if (cmp == 0)
        r.reason = "同版本重刷：" + cv.str () + "（修复场景，放行）";
    else if (cmp > 0)
        r.reason = "升级：" + cv.str () + " → " + tv.str ();
    else
        r.reason = "降级：" + cv.str () + " → " + tv.str () + "（allowDowngrade 已开，放行）";
    return r;
}

// ---------------------------------------------------------------------------
// 凭证（Gate）：检查通过 ≠ 有资格刷
//   0x31 01 0204 通过 → checked=true, ok=true
//   0x34 拿走一次 → consumeOk() 成功并立刻作废（"一次一用"）
//   擦除 / 复位 / 换会话 / 收尾 → clear()（"上周检查的不能刷今天的包"）
// ---------------------------------------------------------------------------
class Gate
{
    public:
        void clear ()
        {
            checked_ = false;
            ok_      = false;
            note_    = "未检查";
        }

        void set (bool ok, const std::string &note)
        {
            checked_ = true;
            ok_      = ok;
            note_    = (ok ? "通过（" : "不通过（") + note + "）";
            ++checks_;
        }

        bool checked () const { return checked_; }
        bool ok () const      { return checked_ && ok_; }
        const std::string &note () const { return note_; }

        // 0x34 取凭证：有且通过 → 拿走并作废；否则 false
        bool consumeOk ()
        {
            if (!checked_ || !ok_) return false;
            const std::string keep = note_;
            clear ();
            note_ = "已用掉（" + keep + "）";
            ++consumes_;
            return true;
        }

        std::uint32_t checks () const   { return checks_; }
        std::uint32_t consumes () const { return consumes_; }

    private:
        bool          checked_ = false;
        bool          ok_      = false;
        std::string   note_    = "未检查";
        std::uint32_t checks_  = 0;
        std::uint32_t consumes_= 0;
};

} // namespace policy
} // namespace doip

#endif
