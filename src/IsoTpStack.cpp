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

std::size_t consecutiveFrameCount (std::size_t msgBytes, std::size_t frameBytes)
{
    // M9：经典帧 FF 带 6、CF 带 7；FD 帧 FF 带 frameBytes-2、CF 带 frameBytes-1。
    // 单帧能装下就是 0 个 CF（FD 的转义单帧能装 frameBytes-2 字节）。
    const std::size_t sfMax = frameBytes <= kClassicFrameBytes ? 7 : frameBytes - 2;
    if (msgBytes <= sfMax) return 0;
    const std::size_t first = frameBytes - 2;
    const std::size_t rest  = msgBytes - first;
    return (rest + (frameBytes - 1) - 1) / (frameBytes - 1);
}

bool segmentMessage (const std::vector<std::uint8_t> &msg,
                     std::vector<std::vector<std::uint8_t>> &frames,
                     std::string &err,
                     std::uint8_t padByte,
                     std::size_t frameBytes)
{
    frames.clear ();
    if (msg.empty ()) { err = "消息为空，不拆帧"; return false; }
    if (msg.size () > 4095) { err = "超过 4095 字节（FF 长度字段只有 12 位）"; return false; }
    if (frameBytes < kClassicFrameBytes || frameBytes > kFdFrameBytes)
    {
        err = "帧长必须是 8..64（现在是 " + std::to_string (frameBytes) + "）";
        return false;
    }

    auto makePad = [padByte, frameBytes] (std::vector<std::uint8_t> &f) {
        f.resize (frameBytes, padByte);
    };

    // 单帧能装多少：经典帧 7；FD 帧 62（因为要留 2 字节给 0x00 + 长度）
    const std::size_t sfMax = (frameBytes == kClassicFrameBytes) ? 7 : frameBytes - 2;

    // ---- 普通单帧：0x0N + 数据（N ≤ 7，经典帧和 FD 帧都一样）----
    if (msg.size () <= 7)
    {
        std::vector<std::uint8_t> f;
        f.push_back (static_cast<std::uint8_t> (msg.size ()));
        f.insert (f.end (), msg.begin (), msg.end ());
        makePad (f);
        frames.push_back (f);
        return true;
    }

    // ---- 转义单帧（FD 才有）：0x00 + 长度 + 数据 ----
    // 为什么需要它：0x0N 里的 N 只有 4 位，最多说 15；而 FD 一帧能带 62 字节，
    // 所以要留一个"逃逸"：PCI 写 0x00，长度写在下个字节里。
    if (msg.size () <= sfMax)
    {
        std::vector<std::uint8_t> f;
        f.push_back (0x00);
        f.push_back (static_cast<std::uint8_t> (msg.size ()));
        f.insert (f.end (), msg.begin (), msg.end ());
        makePad (f);
        frames.push_back (f);
        return true;
    }

    // ---- 首帧：长度(12 位) + 前 (帧长 - 2) 字节 ----
    // 经典帧 = 前 6 字节；FD 帧 = 前 62 字节。这一个数字换了，后面的 CF 数就整片变少。
    const std::size_t firstCap = frameBytes - 2;
    std::vector<std::uint8_t> ff;
    ff.push_back (static_cast<std::uint8_t> (0x10 | ((msg.size () >> 8) & 0x0F)));
    ff.push_back (static_cast<std::uint8_t> (msg.size () & 0xFF));
    ff.insert (ff.end (), msg.begin (), msg.begin () + static_cast<std::ptrdiff_t> (firstCap));
    makePad (ff);
    frames.push_back (ff);

    // ---- 连续帧：SN 1..15，15 之后回 1；每张带 (帧长 - 1) 字节 ----
    std::size_t pos = firstCap;
    std::uint8_t seq = 1;
    const std::size_t cfCap = frameBytes - 1;
    while (pos < msg.size ())
    {
        std::vector<std::uint8_t> cf;
        cf.push_back (static_cast<std::uint8_t> (0x20 | seq));
        const std::size_t n = std::min<std::size_t> (cfCap, msg.size () - pos);
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
IsoTpAssembler::IsoTpAssembler (std::size_t maxMsg, std::size_t frameBytes)
    : maxMsg_ (maxMsg), frameBytes_ (frameBytes)
{
}

void IsoTpAssembler::reset ()
{
    active_ = false;
    total_  = 0;
    got_    = 0;
    nextSeq_ = 1;
    buf_.clear ();
}

IsoTpAssembler::Result IsoTpAssembler::onFrame (const std::uint8_t data[64],
                                                std::vector<std::uint8_t> &out,
                                                std::string &err,
                                                std::size_t len)
{
    if (len == 0 || len > frameBytes_)
    {
        err = "帧长度 " + std::to_string (len) + " 不合法（1.." +
              std::to_string (frameBytes_) + "）";
        return Result::Error;
    }
    const FrameKind k = kindOf (data);

    if (k == FrameKind::SingleFrame)
    {
        // M9：0x00 是"转义单帧"，长度写在第 2 字节。除此之外仍是 0x0N。
        std::size_t sfLen = 0;
        std::size_t off   = 1;
        if (data[0] == 0x00)
        {
            if (len < 2)
            {
                err = "转义单帧只有 1 字节，读不出长度";
                return Result::Error;
            }
            sfLen = data[1];
            off   = 2;
            if (sfLen <= 7)
            {
                // 8 字节以内的消息必须用 0x0N：把长度塞进转义里说明对端实现有问题
                err = "转义单帧声称 " + std::to_string (sfLen) + " 字节（≤7），协议上该用 0x0N";
                return Result::Error;
            }
            if (sfLen > frameBytes_ - 2)
            {
                err = "转义单帧声称 " + std::to_string (sfLen) + " 字节，超过本帧上限 " +
                      std::to_string (frameBytes_ - 2);
                return Result::Error;
            }
        }
        else
        {
            sfLen = data[0] & 0x0F;
            if (sfLen == 0 || sfLen > 7)
            {
                err = "单帧长度 " + std::to_string (sfLen) + " 不合法（1..7）";
                return Result::Error;
            }
        }
        if (sfLen > len - off)
        {
            // 声明 2 字节但帧里只有 1 个可用字节 —— 这种包不能用补零去凑
            err = "单帧声称 " + std::to_string (sfLen) + " 字节，但帧里只有 " +
                  std::to_string (len - off) + " 个字节";
            return Result::Error;
        }
        out.assign (data + off, data + off + sfLen);
        reset ();
        return Result::Complete;
    }

    if (k == FrameKind::FirstFrame)
    {
        if (len < 2)
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
        // 首帧能带几个字节由这一帧的真实长度决定（经典帧 6、FD 帧 62、不补零的 ECU 可能更少）
        const std::size_t first = len - 2;
        if (first > total)
        {
            err = "首帧带了 " + std::to_string (first) + " 字节，超过它声称的总长 " +
                  std::to_string (total);
            return Result::Error;
        }
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
            std::min<std::size_t> (frameBytes_ - 1 > 0 ? frameBytes_ - 1 : 0, total_ - got_),
            len > 0 ? len - 1 : 0);
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
                       std::uint8_t *data, std::size_t frameBytes)
{
    if (frameBytes < kClassicFrameBytes) frameBytes = kClassicFrameBytes;
    if (frameBytes > kFdFrameBytes) frameBytes = kFdFrameBytes;

    data[0] = 0x30;          // 0x3 FC + FS=0 继续发送
    data[1] = blockSize;
    data[2] = stMin;
    for (std::size_t i = 3; i < frameBytes; ++i) data[i] = padByte;
}

} // namespace doip
