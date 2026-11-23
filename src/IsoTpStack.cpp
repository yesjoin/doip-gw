// ============================================================================
// IsoTpStack.cpp —— M4 纯逻辑部分
// ============================================================================
#include "IsoTpStack.h"

#include <algorithm>

namespace doip
{

FrameKind kindOf (const std::uint8_t data[8])
{
    switch ((data[0] >> 4) & 0x0F)
    {
    case 0x0: return FrameKind::SingleFrame;
    case 0x1: return FrameKind::FirstFrame;
    case 0x2: return FrameKind::ConsecutiveFrame;
    case 0x3: return FrameKind::FlowControl;
    default:  return FrameKind::SingleFrame;   // 0x4..0xF 保留，按 SF 处理但长度会判错
    }
}

std::size_t consecutiveFrameCount (std::size_t msgBytes)
{
    if (msgBytes <= 6) return 0;
    const std::size_t rest = msgBytes - 6;
    return (rest + 6) / 7;                      // 每张 CF 装 7 字节
}

bool segmentMessage (const std::vector<std::uint8_t> &msg,
                     std::vector<std::vector<std::uint8_t>> &frames,
                     std::string &err,
                     std::uint8_t padByte)
{
    frames.clear ();
    if (msg.empty ()) { err = "消息为空，不拆帧"; return false; }
    if (msg.size () > 4095) { err = "超过 4095 字节（FF 长度字段只有 12 位）"; return false; }

    auto makePad = [padByte] (std::vector<std::uint8_t> &f) {
        f.resize (8, padByte);
    };

    // ---- 单帧：1..7 字节 ----
    if (msg.size () <= 7)
    {
        std::vector<std::uint8_t> f;
        f.push_back (static_cast<std::uint8_t> (msg.size ()));
        f.insert (f.end (), msg.begin (), msg.end ());
        makePad (f);
        frames.push_back (f);
        return true;
    }

    // ---- 首帧：长度(12 位) + 前 6 字节 ----
    std::vector<std::uint8_t> ff;
    ff.push_back (static_cast<std::uint8_t> (0x10 | ((msg.size () >> 8) & 0x0F)));
    ff.push_back (static_cast<std::uint8_t> (msg.size () & 0xFF));
    ff.insert (ff.end (), msg.begin (), msg.begin () + 6);
    makePad (ff);
    frames.push_back (ff);

    // ---- 连续帧：SN 1..15，15 之后回 1 ----
    std::size_t pos = 6;
    std::uint8_t seq = 1;
    while (pos < msg.size ())
    {
        std::vector<std::uint8_t> cf;
        cf.push_back (static_cast<std::uint8_t> (0x20 | seq));
        const std::size_t n = std::min<std::size_t> (7, msg.size () - pos);
        cf.insert (cf.end (), msg.begin () + static_cast<std::ptrdiff_t> (pos),
                   msg.begin () + static_cast<std::ptrdiff_t> (pos + n));
        makePad (cf);
        frames.push_back (cf);
        pos += n;
        seq = (seq == 15) ? 1 : static_cast<std::uint8_t> (seq + 1);
    }
    return true;
}

// ---------------------------------------------------------------------------
IsoTpAssembler::IsoTpAssembler (std::size_t maxMsg) : maxMsg_ (maxMsg) {}

void IsoTpAssembler::reset ()
{
    active_ = false;
    total_  = 0;
    got_    = 0;
    nextSeq_ = 1;
    buf_.clear ();
}

IsoTpAssembler::Result IsoTpAssembler::onFrame (const std::uint8_t data[8],
                                                std::vector<std::uint8_t> &out,
                                                std::string &err,
                                                std::uint8_t dlc)
{
    if (dlc == 0 || dlc > 8)
    {
        err = "帧长度 " + std::to_string (dlc) + " 不合法（1..8）";
        return Result::Error;
    }
    const FrameKind k = kindOf (data);

    if (k == FrameKind::SingleFrame)
    {
        const std::size_t len = data[0] & 0x0F;
        if (len == 0 || len > 7)
        {
            err = "单帧长度 " + std::to_string (len) + " 不合法（1..7）";
            return Result::Error;
        }
        if (len > static_cast<std::size_t> (dlc) - 1)
        {
            // 声明 2 字节但帧里只有 1 个可用字节 —— 这种包不能用补零去凑
            err = "单帧声称 " + std::to_string (len) + " 字节，但帧里只有 " +
                  std::to_string (dlc - 1) + " 个字节";
            return Result::Error;
        }
        out.assign (data + 1, data + 1 + len);
        reset ();
        return Result::Complete;
    }

    if (k == FrameKind::FirstFrame)
    {
        if (dlc < 2)
        {
            err = "首帧只有 1 字节，读不出长度";
            return Result::Error;
        }
        const std::size_t total = (static_cast<std::size_t> (data[0] & 0x0F) << 8) | data[1];
        if (total <= 7)
        {
            // 首帧声称的总长 <=7，其实是对方该用单帧 —— 这种"说小了"的包不能信
            err = "首帧总长 " + std::to_string (total) + " 小于等于 7，协议上该用单帧";
            return Result::Error;
        }
        if (total > maxMsg_)
        {
            err = "首帧总长 " + std::to_string (total) + " 超过本端上限 " + std::to_string (maxMsg_);
            return Result::Error;
        }
        reset ();
        active_  = true;
        total_   = total;
        // 首帧能带几个字节由 DLC 决定（不补零的 ECU 可能只带 4 个）
        const std::size_t first = dlc - 2;
        buf_.assign (data + 2, data + 2 + first);
        got_     = first;
        nextSeq_ = 1;
        return Result::NeedMore;
    }

    if (k == FrameKind::ConsecutiveFrame)
    {
        if (!active_)
        {
            err = "没有首帧就收到连续帧（上一包丢了？）";
            return Result::Error;
        }
        const std::uint8_t sn = data[0] & 0x0F;
        if (sn != nextSeq_)
        {
            err = "连续帧序号错：期望 " + std::to_string (nextSeq_) + "，收到 " + std::to_string (sn);
            reset ();
            return Result::Error;
        }
        const std::size_t n = std::min<std::size_t> (
            std::min<std::size_t> (7, total_ - got_), dlc > 0 ? dlc - 1 : 0);
        buf_.insert (buf_.end (), data + 1, data + 1 + n);
        got_ += n;
        nextSeq_ = (nextSeq_ == 15) ? 1 : static_cast<std::uint8_t> (nextSeq_ + 1);

        if (got_ >= total_)
        {
            out = buf_;
            reset ();
            return Result::Complete;
        }
        return Result::NeedMore;
    }

    // 流控帧不该出现在"收消息"的路径上
    err = "收到流控帧，但当前在收消息（状态机错位）";
    return Result::Error;
}

// ---------------------------------------------------------------------------
bool parseFlowControl (const std::uint8_t data[8], FlowControl &out, std::string &err)
{
    if (kindOf (data) != FrameKind::FlowControl)
    {
        err = "不是流控帧（高半字节应 0x3）";
        return false;
    }
    const std::uint8_t fs = data[0] & 0x0F;
    if (fs > 2)
    {
        err = "流控状态 " + std::to_string (fs) + " 未定义";
        return false;
    }
    out.status    = static_cast<FlowStatus> (fs);
    out.blockSize = data[1];
    out.stMin     = data[2];
    return true;
}

void buildFlowControl (std::uint8_t blockSize, std::uint8_t stMin, std::uint8_t padByte,
                       std::uint8_t data[8])
    {
    data[0] = 0x30;          // 0x3 FC + FS=0 继续发送
    data[1] = blockSize;
    data[2] = stMin;
    for (int i = 3; i < 8; ++i) data[i] = padByte;
}

} // namespace doip
