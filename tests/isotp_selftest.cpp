// ============================================================================
// isotp_selftest.cpp —— M4 纯逻辑自测（不碰 socket，不需要 vcan0）
//
// 为什么先测这一层：
//   ISO-TP 的错法很"安静"——首帧长度少写一位、连续帧序号差 1、BS 边界差一张，
//   本机上短报文照样通，一上 40 字节就成片丢。所以这里逐字节钉死。
//
// 最后一段做"往返"：我们拆出来的帧，喂给重组器，必须还原成原消息。
// 这是最便宜的一致性检查 —— 拆和装两边各有 bug 时，往往刚好对不上。
// ============================================================================
#include "IsoTpStack.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond) { std::printf ("[PASS] %s\n", what.c_str ()); ++g_pass; }
    else      { std::printf ("[FAIL] %s\n", what.c_str ()); ++g_fail; }
}

static std::vector<std::uint8_t> bytes (std::size_t n, std::uint8_t base = 0x10)
{
    std::vector<std::uint8_t> v (n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t> (base + i);
    return v;
}

int main ()
{
    // =======================================================================
    std::printf ("=== A 拆帧：SF / FF / CF ===\n");

    std::vector<std::vector<std::uint8_t>> f;
    std::string err;

    // 单帧
    check (segmentMessage ({0x22, 0xF1, 0x86}, f, err), "3 字节 → 单帧");
    check (f.size () == 1 && f[0].size () == 8, "单帧就是一张 8 字节帧");
    check (f[0][0] == 0x03, "单帧长度字段 = 3（高半字节 0）");
    check (f[0][1] == 0x22 && f[0][3] == 0x86, "载荷从第 2 字节开始");
    check (f[0][4] == 0x00, "不足 8 字节补 0（本工程 pad=0x00）");

    // 7 字节：仍然单帧（边界）
    check (segmentMessage (bytes (7), f, err), "7 字节仍是单帧");
    check (f.size () == 1 && f[0][0] == 0x07, "长度字段 = 7");

    // 8 字节：跨到首帧（边界）
    std::vector<std::uint8_t> m8 = bytes (8);
    check (segmentMessage (m8, f, err), "8 字节开始用首帧");
    check (f.size () == 2, "8 字节 = 首帧 + 1 张连续帧");
    check (kindOf (f[0].data ()) == FrameKind::FirstFrame, "第一张是首帧");
    check (f[0][0] == 0x10 && f[0][1] == 0x08, "首帧：0x10 + 12 位长度 0x008");
    check (f[0][2] == m8[0] && f[0][7] == m8[5], "首帧带走前 6 字节");
    check (f[1][0] == 0x21, "连续帧：0x20 | SN=1");
    check (f[1][1] == m8[6] && f[1][2] == m8[7], "连续帧装第 7、8 字节");
    check (consecutiveFrameCount (8) == 1, "consecutiveFrameCount(8) = 1");

    // 40 字节：验收硬指标第 3 条的那个长度
    std::vector<std::uint8_t> m40 = bytes (40);
    check (segmentMessage (m40, f, err), "40 字节能拆");
    check (f.size () == 6, "40 字节 = 1 首帧 + 5 连续帧");
    check (consecutiveFrameCount (40) == 5, "consecutiveFrameCount(40) = 5");
    check (f[0][0] == 0x10 && f[0][1] == 0x28, "首帧长度字段 = 0x028（40）");
    check (f[1][1] == m40[6] && f[5][6] == m40[39], "最后一帧最后一字节是第 40 字节");

    // 120 字节：序号要绕回
    check (segmentMessage (bytes (120), f, err), "120 字节能拆");
    check (f.size () == 1 + 17, "120 字节 = 1 + 17 帧");
    check (f[16][0] == 0x21, "第 16 张连续帧的 SN 回到 1（15 之后回 1，不是 0）");

    // 边界错误
    check (!segmentMessage ({}, f, err), "空消息拒绝");
    check (!segmentMessage (bytes (4096), f, err), "4096 字节拒绝（超过 12 位长度）");

    // 补零字节可配
    check (segmentMessage ({0x3E, 0x00}, f, err, 0xAA) && f[0][3] == 0xAA, "pad=0xAA 时补 0xAA");

    // 帧类型判定
    std::uint8_t a0[8] = {0x02}, a1[8] = {0x10}, a2[8] = {0x21}, a3[8] = {0x30};
    check (kindOf (a0) == FrameKind::SingleFrame, "0x02 → 单帧");
    check (kindOf (a1) == FrameKind::FirstFrame, "0x10 → 首帧");
    check (kindOf (a2) == FrameKind::ConsecutiveFrame, "0x21 → 连续帧");
    check (kindOf (a3) == FrameKind::FlowControl, "0x30 → 流控帧");

    // =======================================================================
    std::printf ("\n=== B 重组：SF / FF+CF / 序号错 ===\n");
    IsoTpAssembler asm_;
    std::vector<std::uint8_t> out;

    std::uint8_t sf[8] = {0x03, 0x62, 0xF1, 0x86, 0x00, 0, 0, 0};
    check (asm_.onFrame (sf, out, err) == IsoTpAssembler::Result::Complete, "单帧 3 字节 → 完成");
    check (out.size () == 3 && out[0] == 0x62, "内容正确");

    std::uint8_t sf0[8] = {0x00};
    check (asm_.onFrame (sf0, out, err) == IsoTpAssembler::Result::Error, "单帧长度 0 → 错误");

    std::uint8_t sf8[8] = {0x08};
    check (asm_.onFrame (sf8, out, err) == IsoTpAssembler::Result::Error, "单帧长度 8 → 错误（超 7）");

    // ★ DLC 不补零：项目一的 ECU 实际就这样发（7E8#027E00 只有 3 字节）
    std::uint8_t sfShort[8] = {0x02, 0x7E, 0x00, 0, 0, 0, 0, 0};
    check (asm_.onFrame (sfShort, out, err, 3) == IsoTpAssembler::Result::Complete,
           "DLC=3 的单帧也能解（不假定 8 字节）");
    check (out.size () == 2 && out[0] == 0x7E, "内容 7E 00");

    std::uint8_t sfLie[8] = {0x02, 0x7E, 0, 0, 0, 0, 0, 0};
    check (asm_.onFrame (sfLie, out, err, 2) == IsoTpAssembler::Result::Error,
           "声称 2 字节但帧里只有 1 个可用字节 → 错误（不拿补零凑数）");

    // FF 20 字节 + 2 张 CF
    std::uint8_t ff[8] = {0x10, 0x14, 0x62, 0xF1, 0x90, 0x4C, 0x53, 0x56};
    check (asm_.onFrame (ff, out, err) == IsoTpAssembler::Result::NeedMore, "首帧 → 还要更多");
    check (asm_.expected () == 20 && asm_.received () == 6, "首帧声明 20 字节，已收 6");
    check (asm_.receiving (), "处于重组中");

    std::uint8_t cf1[8] = {0x21, 0x41, 0x41, 0x30, 0x30, 0x30, 0x30, 0x41};
    check (asm_.onFrame (cf1, out, err) == IsoTpAssembler::Result::NeedMore, "CF1 序号对 → 继续");
    std::uint8_t cf2[8] = {0x22, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    check (asm_.onFrame (cf2, out, err) == IsoTpAssembler::Result::Complete, "CF2 → 完成");
    check (out.size () == 20, "总长 20");
    check (out[0] == 0x62 && out[3] == 0x4C, "开头 62 F1 90 4C（VIN 首字母）");

    // 序号错
    asm_.reset ();
    check (asm_.onFrame (ff, out, err) == IsoTpAssembler::Result::NeedMore, "再来一次首帧");
    std::uint8_t bad[8] = {0x24, 0, 0, 0, 0, 0, 0, 0};
    check (asm_.onFrame (bad, out, err) == IsoTpAssembler::Result::Error, "SN=4 但期望 1 → 错误");
    check (err.find ("序号") != std::string::npos, "错误信息说清了「序号」");

    // 没有首帧就来 CF
    asm_.reset ();
    check (asm_.onFrame (cf1, out, err) == IsoTpAssembler::Result::Error, "没有首帧的 CF → 错误");

    // 首帧声称 <=7
    std::uint8_t ffSmall[8] = {0x10, 0x05, 1, 2, 3, 4, 5, 0};
    check (asm_.onFrame (ffSmall, out, err) == IsoTpAssembler::Result::Error, "首帧总长 5 → 错误");

    // 首帧超上限
    IsoTpAssembler small (64);
    std::uint8_t ffBig[8] = {0x11, 0x00, 0, 0, 0, 0, 0, 0};     // 0x100 = 256 字节
    check (small.onFrame (ffBig, out, err) == IsoTpAssembler::Result::Error, "首帧总长 256 > 上限 64 → 错误");

    // 流控帧进了重组器
    asm_.reset ();
    check (asm_.onFrame (a3, out, err) == IsoTpAssembler::Result::Error, "流控帧进重组器 → 状态机错位");

    // =======================================================================
    std::printf ("\n=== C 流控帧 ===\n");
    FlowControl fc;
    std::uint8_t goodFc[8] = {0x30, 0x08, 0x0A, 0, 0, 0, 0, 0};
    check (parseFlowControl (goodFc, fc, err), "0x30 8 10 能解析");
    check (fc.status == FlowStatus::ContinueToSend, "FS=0 继续发送");
    check (fc.blockSize == 8 && fc.stMin == 0x0A, "BS=8，STmin=10ms");

    std::uint8_t waitFc[8] = {0x31};
    check (parseFlowControl (waitFc, fc, err) && fc.status == FlowStatus::Wait, "0x31 → 等一会");

    std::uint8_t ovfFc[8] = {0x32};
    check (parseFlowControl (ovfFc, fc, err) && fc.status == FlowStatus::Overflow, "0x32 → 溢出");

    check (!parseFlowControl (sf, fc, err), "不是 0x3x 的帧不能当流控");

    std::uint8_t built[8];
    buildFlowControl (0, 0, 0x00, built);
    check (built[0] == 0x30 && built[1] == 0 && built[2] == 0, "组出来的流控帧：0x30 BS=0 STmin=0");

    // =======================================================================
    std::printf ("\n=== D 往返：拆出来的帧，必须能装回去 ===\n");
    for (std::size_t n : {3u, 7u, 8u, 20u, 40u, 120u})
    {
        std::vector<std::uint8_t> msg = bytes (n);
        std::vector<std::vector<std::uint8_t>> frames;
        check (segmentMessage (msg, frames, err), "消息 " + std::to_string (n) + " 字节可拆");

        IsoTpAssembler back;
        std::vector<std::uint8_t> got;
        bool done = false;
        for (auto &fr : frames)
        {
            const auto r = back.onFrame (fr.data (), got, err);
            if (r == IsoTpAssembler::Result::Complete) { done = true; break; }
            if (r == IsoTpAssembler::Result::Error) break;
        }
        check (done && got == msg, "消息 " + std::to_string (n) + " 字节拆了再装，字节完全一致");
    }

    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M4 纯逻辑全绿 —— 7 字节是单帧边界，40 字节是首帧 + 5 张连续帧。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
