// ============================================================================
// KeyRingStore.h —— M23：钥匙表要能活过一次重启
//
// M22 把钥匙做成了表，但表在 RAM 里：进程一重启就回到"1、2 号都启用"。
// 对真车这是**事故级**的：现场刚把泄露的 1 号钥匙吊销，断电重启后它又活了。
// 吊销记录不能丢，这是"吊销"这件事能不能成立的前提。
//
// 所以这一层只干一件事：把 KeyRing 存到盘上、从盘上读回来。
//
// 但"存盘"这件事真正的难点不是写，是**读坏了怎么办**：
//   ① 断电写到一半 → 文件是半截；
//   ② 有人改了文件 → 把 "02 吊销"改成 "00 启用"；
//   ③ 文件被清空 / 格式不对 → 解析崩。
// 三种里最可怕的是②：读坏了当成"空的"或"默认的"，等于**把吊销的钥匙复活**。
// 所以这里的策略是**宁可起不来，也不猜**：
//   · 校验和不符 → Corrupt，调用方拿到一张空表（谁都验不过），**不套默认两把**；
//   · 只有"文件不存在"才是 Missing，那才是第一次上电，可以铺默认两把。
// "文件有、但读不懂"和"文件没有"是两件事，混在一起就会出上面那种事故。
//
// 写入用 **临时文件 + rename**：rename 在同一文件系统内是原子的，
//   要么看到旧文件、要么看到新文件，不会看到半截。直接覆盖写就没有这个保证。
//
// 落盘格式（文本，一行一条，最后一行校验和）：
//
//   DOIPKEYRING 2
//   VER 0007
//   K 0001 00 <64 hex>
//   K 0002 02 <64 hex>
//   SUM 3f7c1a0e5b2d9c48
//
// M25 加了一行 VER（世代，见 KeyRingStamp.h）。格式从 1 升到 2，但**读的时候两种都认**：
//   · 看到 `DOIPKEYRING 2` → 必须紧跟一行 `VER <4hex>`；
//   · 看到 `DOIPKEYRING 1` → 没有 VER，世代按 0 算（M23 写出来的旧文件因此还能用）。
// 这是"写新读旧"：盘上只会被写成 2，但老文件不需要人手迁移 ——
//   要人手迁移的那一刻，现场就已经断电了。
//
// 为什么用文本：现场排障 `cat` 一眼能看；二进制省下的那点字节在这个场景没有收益，
//   而"人能直接读一行"有收益。SUM 取 SHA-256 前 8 字节（16 个 hex 字符）——
//   不为抗攻击，只为抓"半截 / 被手改"。
// ============================================================================
#ifndef DOIP_KEY_RING_STORE_H
#define DOIP_KEY_RING_STORE_H

#include "KeyRing.h"
#include "KeyRingStamp.h"
#include "Sha256.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace doip {
namespace keys {

// 载入的三种结论。Missing 与 Corrupt 必须分开 —— 见文件头 ①②③。
enum class LoadStatus
{
    Ok,        // 读懂了，表就是文件里的样子
    Missing,   // 文件不存在：第一次上电
    Corrupt    // 文件在，但读不懂（半截 / 被改 / 版本不对）
};

inline const char *loadStatusName (LoadStatus s)
{
    switch (s)
    {
        case LoadStatus::Ok:      return "读到了";
        case LoadStatus::Missing: return "没有文件（第一次上电）";
        case LoadStatus::Corrupt: return "文件坏了";
    }
    return "?";
}

struct LoadResult
{
    LoadStatus   status = LoadStatus::Missing;
    KeyRing      ring;                 // Corrupt 时是空表，**不是**默认两把
    Generation   generation = 0;       // M25：v1 旧文件读进来是 0（见文件头）
    std::string  why;                  // 给人看的一句话
};

// 校验和：对"SUM 行之前的全部内容（含行尾换行）"取 SHA-256 前 16 个 hex
inline std::string checksumOf (const std::string &body)
{
    return Sha256::hex (Sha256::ofText (body)).substr (0, 16);
}

inline std::string encode (const KeyRing &ring, Generation generation = 0)
{
    std::string body = "DOIPKEYRING 2\n";
    char buf[96];
    std::snprintf (buf, sizeof buf, "VER %04X\n", static_cast<unsigned> (generation));
    body += buf;
    for (std::size_t i = 0; i < ring.size (); ++i)
    {
        const Entry &e = ring.at (i);
        std::snprintf (buf, sizeof buf, "K %04X %02X %s\n", static_cast<unsigned> (e.id),
                       static_cast<unsigned> (stateCode (e.state)), Sha256::hex (e.key).c_str ());
        body += buf;
    }
    return body + "SUM " + checksumOf (body) + "\n";
}

inline int nibble (char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool parseHex (const std::string &s, std::uint64_t &out)
{
    out = 0;
    if (s.empty () || s.size () > 16) return false;
    for (char c : s)
    {
        const int v = nibble (c);
        if (v < 0) return false;
        out = (out << 4) | static_cast<std::uint64_t> (v);
    }
    return true;
}

inline LoadResult decode (const std::string &text)
{
    LoadResult r;
    r.status = LoadStatus::Corrupt;

    // 按行切（只认 \n；\r 顺手剥掉，免得有人用 Windows 编辑器改过）
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text)
    {
        if (c == '\n')
        {
            if (!cur.empty () && cur.back () == '\r') cur.pop_back ();
            lines.push_back (cur);
            cur.clear ();
        }
        else
            cur += c;
    }
    if (!cur.empty ())
    {
        if (cur.back () == '\r') cur.pop_back ();
        lines.push_back (cur);
    }

    // 行数下界：版本行 + SUM 行。一个合法的**空表**就是两行（v2 是三行：多一行 VER）。
    if (lines.size () < 2)
    {
        r.why = "文件里连两行都没有（" + std::to_string (lines.size ()) + " 行）";
        return r;
    }

    // 版本行：写永远写 2，读 1 和 2 都认。
    //   v1 = M23 的文件，没有 VER 行，世代按 0 算；v2 = 现在，VER 行必须紧跟版本行。
    std::size_t firstKeyLine = 1;
    Generation gen = 0;
    if (lines[0] == "DOIPKEYRING 2")
    {
        if (lines.size () < 3)
        {
            r.why = "v2 文件至少要三行（版本行 / VER / SUM），现在 " +
                    std::to_string (lines.size ()) + " 行";
            return r;
        }
        const std::string &ver = lines[1];
        std::uint64_t gv = 0;
        if (ver.size () != 8 || ver.compare (0, 4, "VER ") != 0 || !parseHex (ver.substr (4), gv))
        {
            r.why = "第二行不是「VER <4 hex>」（读到「" + ver + "」）";
            return r;
        }
        if (gv > 0xFFFF)
        {
            r.why = "VER 超出 16 位";
            return r;
        }
        gen = static_cast<Generation> (gv);
        firstKeyLine = 2;
    }
    else if (lines[0] == "DOIPKEYRING 1")
    {
        firstKeyLine = 1;   // 旧文件：没有 VER，世代 0
    }
    else
    {
        r.why = "版本行不对（读到「" + lines[0] + "」，只认 DOIPKEYRING 1 / 2）";
        return r;
    }

    // 最后一行必须是 SUM —— 半截文件最常见的样子就是"最后一行是半条 K"
    const std::string &last = lines.back ();
    if (last.size () != 20 || last.compare (0, 4, "SUM ") != 0)
    {
        r.why = "最后一行不是校验和（读到「" + last + "」）：文件可能是半截的";
        return r;
    }

    std::string body;
    for (std::size_t i = 0; i + 1 < lines.size (); ++i) body += lines[i] + "\n";
    const std::string want = last.substr (4);
    const std::string got  = checksumOf (body);
    if (want != got)
    {
        r.why = "校验和不符（文件里 " + want + "，算出来 " + got + "）：被改过，或者写了一半";
        return r;
    }

    // 校验和对上了，再逐条查内容合法性。
    //   校验和只能证明"这段字节没变过"，不能证明"内容是合法的" —— 两件事要分开查。
    KeyRing ring;
    std::vector<std::uint16_t> seen;
    for (std::size_t i = firstKeyLine; i + 1 < lines.size (); ++i)
    {
        const std::string &ln = lines[i];
        if (ln.size () != 2 + 4 + 1 + 2 + 1 + 64 || ln.compare (0, 2, "K ") != 0)
        {
            r.why = "第 " + std::to_string (i + 1) + " 行不是「K iddd ss <64 hex>」的形状";
            return r;
        }
        std::uint64_t idv = 0, stv = 0;
        if (!parseHex (ln.substr (2, 4), idv) || !parseHex (ln.substr (7, 2), stv))
        {
            r.why = "第 " + std::to_string (i + 1) + " 行的 id 或状态不是十六进制";
            return r;
        }
        if (idv == 0 || idv > 0xFFFF)
        {
            r.why = "第 " + std::to_string (i + 1) + " 行的 keyId 非法（0 不能占槽）";
            return r;
        }
        if (stv > 0x02)
        {
            r.why = "第 " + std::to_string (i + 1) + " 行的状态不是 00/01/02";
            return r;
        }
        for (std::uint16_t prev : seen)
            if (prev == static_cast<std::uint16_t> (idv))
            {
                r.why = "第 " + std::to_string (i + 1) + " 行的 keyId 重复";
                return r;
            }
        if (seen.size () >= KeyRing::kMaxKeys)
        {
            r.why = "表里超过 " + std::to_string (KeyRing::kMaxKeys) + " 把钥匙";
            return r;
        }

        Sha256::Digest key {};
        for (int b = 0; b < 32; ++b)
        {
            std::uint64_t v = 0;
            if (!parseHex (ln.substr (10 + static_cast<std::size_t> (b) * 2, 2), v))
            {
                r.why = "第 " + std::to_string (i + 1) + " 行的钥匙材料不是十六进制";
                return r;
            }
            key[static_cast<std::size_t> (b)] = static_cast<std::uint8_t> (v);
        }

        // 先装成 Active，再改到目标状态 —— install 只装 Active，
        //   这里不另开一个"直接塞状态"的入口，免得表外多一条能造状态的路径。
        if (ring.install (static_cast<std::uint16_t> (idv), key) != Install::Ok)
        {
            r.why = "第 " + std::to_string (i + 1) + " 行装不进表";
            return r;
        }
        if (stv != 0x00 &&
            ring.setState (static_cast<std::uint16_t> (idv), static_cast<State> (stv)) !=
                Transition::Ok)
        {
            r.why = "第 " + std::to_string (i + 1) + " 行恢复不到目标状态";
            return r;
        }
        seen.push_back (static_cast<std::uint16_t> (idv));
    }

    r.status     = LoadStatus::Ok;
    r.ring       = ring;
    r.generation = gen;
    r.why        = "读到 " + std::to_string (ring.size ()) + " 把：" + ring.dump ();
    return r;
}

inline LoadResult load (const std::string &path)
{
    LoadResult r;
    std::FILE *fp = std::fopen (path.c_str (), "rb");
    if (fp == nullptr)
    {
        r.status = LoadStatus::Missing;
        r.why    = "打不开（当作第一次上电）：" + path;
        return r;
    }
    std::string text;
    char buf[512];
    std::size_t n = 0;
    while ((n = std::fread (buf, 1, sizeof buf, fp)) > 0) text.append (buf, n);
    const bool readErr = std::ferror (fp) != 0;
    std::fclose (fp);
    if (readErr)
    {
        r.status = LoadStatus::Corrupt;
        r.why    = "读文件时出错：" + path;
        return r;
    }
    r = decode (text);
    if (r.status == LoadStatus::Corrupt) r.why = path + "：" + r.why;
    return r;
}

// 写盘：临时文件 → rename（原子）→ 读回来核对。
//   写完立刻读回来是有必要的：写成功不等于写对了（磁盘满、路径被换、编码截断都可能）。
//   M25：世代也要跟着写、跟着核对 —— 版本没落盘，重启后"改过几次"就归零了。
inline bool save (const KeyRing &ring, const std::string &path, std::string &why,
                  Generation generation = 0)
{
    const std::string tmp = path + ".tmp";
    const std::string text = encode (ring, generation);
    std::FILE *fp = std::fopen (tmp.c_str (), "wb");
    if (fp == nullptr)
    {
        why = "建不了临时文件 " + tmp;
        return false;
    }
    const bool wrote = std::fwrite (text.data (), 1, text.size (), fp) == text.size ();
    const bool flushed = std::fflush (fp) == 0;
    const int  closed = std::fclose (fp);
    if (!wrote || !flushed || closed != 0)
    {
        std::remove (tmp.c_str ());
        why = "写 " + tmp + " 没写全（write/flush/close 有一步失败）";
        return false;
    }

    // rename 失败时旧文件还在 —— 这正是我们要的：宁可留旧表，不毁新表
    if (std::rename (tmp.c_str (), path.c_str ()) != 0)
    {
        std::remove (tmp.c_str ());
        why = "rename 到 " + path + " 失败（旧文件保持原样）";
        return false;
    }

    const LoadResult back = load (path);
    if (back.status != LoadStatus::Ok || encode (back.ring, back.generation) != text)
    {
        why = "写完读回来对不上：" + back.why;
        return false;
    }
    why = "已写入 " + path + "（" + std::to_string (ring.size ()) + " 把，版本 " +
          std::to_string (static_cast<unsigned> (generation)) + "）";
    return true;
}

} // namespace keys
} // namespace doip

#endif
