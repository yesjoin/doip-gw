#pragma once
// ============================================================================
// FlashTarget.h —— M15：UDS 刷写链路的"被刷端"（纯逻辑）
//
// 前面 14 个里程碑都是"一问一答"：发 22 F1 90，回 62 F1 90 <17 字节>。
// 刷写第一次要求**有状态的会话**：先擦、再协商、再一块一块传、最后收尾校验。
// 中间任何一步乱序，ECU 都必须能说清楚"你哪一步错了"，而不是闷头写坏数据。
//
// 五个服务的分工（ISO 14229-1，服务格式固定，标准里并没有"刷写服务"这种东西）：
//   0x31 01 FF00  擦除（清掉旧镜像，回到"可下载"）
//   0x34          请求下载：协商地址/长度，并告诉客户端"一块最大多少"
//   0x36          传数据：BSC（块序号）+ 数据
//   0x37          传完收尾：核对"收够了没有"
//   0x31 01 FF01  完整性校验：客户端把期望的 CRC 带过来，ECU 自己算一遍比对
//
// 三条最容易写错的规矩，先写死在这里：
//   ① **BSC 从 0x01 开始，每块 +1，0xFF 之后回绕到 0x00。**
//      不是"从 0 开始"，也不是"0xFF 之后回 0x01"。写错了到第 256 块才炸，
//      而且只在长镜像上炸 —— 短镜像永远测不出来。
//   ② **0x76 回的是"收到的那块"BSC，不是"下一块"。**
//      回下一块在某些 ECU 上碰巧也能跑（客户端不看应答），但一旦做了重发就全乱。
//   ③ **maxNumberOfBlockLength 含 0x36 与 BSC。**
//      它说的是"一条 0x36 请求的最大总长"，不是"数据段能装多少"。
//      客户端按后者算，每块都超 2 字节 → 每次都吃 NRC 0x13。
//
// 重发怎么办（链路层丢应答是常态）：**同一个 BSC 再来一次，按幂等处理**——
// 不重复写、只把 0x76 再回一遍。跳号（比如 1 之后来 3）才是 0x73。
// 这是"客户端要能重试"和"镜像不能被写两遍"之间唯一可行的折中。
// ============================================================================
#include "UdsNrc.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace doip
{

// 0x7F 后面的否定码在 UdsNrc.h 里（M16 的会话层也要用同一批，放一个出处）

// 一条请求的结论（ECU 侧）
struct FlashReply
{
    bool                      positive = false;
    std::vector<std::uint8_t> uds;      // 完整 UDS 应答（正 = 服务号+0x40，负 = 7F 服务号 码）
    std::string               reason;   // 人话，日志和断言都用它
};

// CRC-32（IEEE 802.3，和 zlib / python 的 crc32 一致）。
// 不用查表不是偷懒：表只有 1KB，但"镜像 4KB、表 1KB"会让手算示例变难；
// 位运算版在 4KB 上是微秒级，够用。
inline std::uint32_t crc32Of (const std::uint8_t *data, std::size_t n)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i)
    {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
        {
            const std::uint32_t mask = (crc & 1u) ? 0xEDB88320u : 0u;
            crc = (crc >> 1) ^ mask;
    }
    }
    return ~crc;
}

inline std::uint32_t crc32Of (const std::vector<std::uint8_t> &v)
{
    return crc32Of (v.data (), v.size ());
}

// ---------------------------------------------------------------------------
// 被刷端的状态机
// ---------------------------------------------------------------------------
class FlashTarget
{
public:
    // maxBlockLength 是**通告给客户端的**一条 0x36 请求总长（含 0x36 + BSC）。
    explicit FlashTarget (std::uint32_t maxBlockLength = 34,
                          std::uint32_t maxImageSize   = 1u << 20,
                          bool          requireErase   = true)
        : maxBlockLength_ (maxBlockLength < 4 ? 4 : maxBlockLength),
          maxImageSize_ (maxImageSize),
          requireErase_ (requireErase)
    {
    }

    // ---- 0x31 01 FF00：擦除 ----
    FlashReply handleErase ()
    {
        image_.clear ();
        expectedSize_ = 0;
        active_       = false;
        lastBsc_      = 0;
        erased_       = true;
        receipts_     = 0;
        return okay ({0x71, 0x01, 0xFF, 0x00}, "0x31 01 FF00：擦除完成，镜像清空，回到可下载状态");
    }

    // ---- 0x34：请求下载 ----
    //   dataFormatIdentifier 本项目只支持 0x00（不压缩、不加密）
    //   addressAndLengthFormatIdentifier：高半字节 = memorySize 的字节数，
    //                                     低半字节 = memoryAddress 的字节数
    //   载荷 = [dfi, alfid, address..., size...]
    FlashReply requestDownload (std::uint8_t dfi, std::uint8_t alfid,
                                const std::vector<std::uint8_t> &addressAndSize)
    {
        if (requireErase_ && !erased_)
            return nrc (0x34, kNrcConditionsNotCorrect, "还没擦除就要求下载（先 0x31 01 FF00）");
        if (active_)
            return nrc (0x34, kNrcConditionsNotCorrect, "上一段下载还没收尾（0x37）就又要求下载");
        if (dfi != 0x00)
            return nrc (0x34, kNrcRequestOutOfRange, "dataFormatIdentifier 只支持 0x00（不压缩/不加密）");

        const std::uint8_t sizeLen = static_cast<std::uint8_t> ((alfid >> 4) & 0x0F);
        const std::uint8_t addrLen = static_cast<std::uint8_t> (alfid & 0x0F);
        if (sizeLen < 1 || sizeLen > 4 || addrLen < 1 || addrLen > 4)
            return nrc (0x34, kNrcRequestOutOfRange,
                        "addressAndLengthFormatIdentifier 的字节数只能是 1–4（高半=长度，低半=地址）");
        if (addressAndSize.size () != static_cast<std::size_t> (sizeLen + addrLen))
            return nrc (0x34, kNrcIncorrectLength,
                        "0x34 载荷应为 2 + 地址 " + std::to_string (addrLen) +
                        " + 长度 " + std::to_string (sizeLen) + " 字节，实际 " +
                        std::to_string (addressAndSize.size () + 2) + " 字节");

        // 地址本项目不用（只在日志里报出来），长度必须可解析且合理
        std::uint32_t address = 0;
        for (std::size_t i = 0; i < addrLen; ++i)
            address = (address << 8) | addressAndSize[i];

        std::uint32_t size = 0;
        for (std::size_t i = 0; i < sizeLen; ++i)
            size = (size << 8) | addressAndSize[addrLen + i];

        if (size == 0)
            return nrc (0x34, kNrcRequestOutOfRange, "memorySize = 0，没东西可写");
        if (size > maxImageSize_)
            return nrc (0x34, kNrcRequestOutOfRange,
                        "memorySize " + std::to_string (size) + " 超过本 ECU 上限 " +
                        std::to_string (maxImageSize_));

        image_.clear ();
        image_.reserve (size);
        expectedSize_ = size;
        active_       = true;
        lastBsc_      = 0;      // 第一块的 BSC 是 0x01（0 表示"还没收到任何块"）
        receipts_     = 0;
        address_      = address;

        // 正响应：0x74 + lengthFormatIdentifier + maxNumberOfBlockLength
        //   lengthFormatIdentifier 高半 = 这个长度字段占几个字节，我们发 2 字节 → 0x20
        //   ★ 这个数**含 0x36 和 BSC**：客户端算数据长度时要减 2
        std::vector<std::uint8_t> r = {0x74, 0x20,
                                       static_cast<std::uint8_t> ((maxBlockLength_ >> 8) & 0xFF),
                                       static_cast<std::uint8_t> (maxBlockLength_ & 0xFF)};
        return okay (r, "0x34 接受下载：地址 0x" + hex32 (address) + "，长度 " + std::to_string (size) +
                      " 字节，一块最多 " + std::to_string (maxBlockLength_) +
                      " 字节（含 0x36+BSC，" + std::to_string (payloadPerBlock ()) + " 字节数据）");
    }

    // ---- 0x36：传一块 ----
    FlashReply transferData (std::uint8_t bsc, const std::vector<std::uint8_t> &data)
    {
        if (!active_)
            return nrc (0x36, kNrcRequestSequenceError, "没有在下载中就发 0x36（顺序错，先 0x34）");
        if (data.size () + 2 > maxBlockLength_)
            return nrc (0x36, kNrcIncorrectLength,
                        "这一块 " + std::to_string (data.size () + 2) + " 字节（含 0x36+BSC）超过通告的 " +
                        std::to_string (maxBlockLength_) + " 字节");

        // 重发同一块：幂等。不重复写，只把 0x76 再回一遍。
        //   为什么必须允许：链路丢的是"应答"，客户端不知道到底写没写进去，
        //   它只能重发；这时如果 ECU 回 0x73，整个刷写就卡死。
        if (lastBsc_ != 0 && bsc == lastBsc_)
        {
            return okay ({0x76, bsc}, "重复块 BSC=0x" + hex8 (bsc) + "：幂等，不重复写，只重回应答");
        }

        const std::uint8_t expected = (lastBsc_ == 0) ? 0x01
                                       : (lastBsc_ == 0xFF) ? 0x00
                                       : static_cast<std::uint8_t> (lastBsc_ + 1);
        if (bsc != expected)
            return nrc (0x36, kNrcWrongBlockSequence,
                        "BSC 跳号：期望 0x" + hex8 (expected) + "，收到 0x" + hex8 (bsc));

        if (image_.size () + data.size () > expectedSize_)
            return nrc (0x36, kNrcTransferDataSuspended,
                        "这一块会把镜像写到 " + std::to_string (image_.size () + data.size ()) +
                        " 字节，超过声明的 " + std::to_string (expectedSize_));

        image_.insert (image_.end (), data.begin (), data.end ());
        lastBsc_ = bsc;
        ++receipts_;
        return okay ({0x76, bsc}, "收下 BSC=0x" + hex8 (bsc) + "，" + std::to_string (data.size ()) +
                      " 字节（累计 " + std::to_string (image_.size ()) + "/" +
                      std::to_string (expectedSize_) + "）");
    }

    // ---- 0x37：传完收尾 ----
    FlashReply requestTransferExit ()
    {
        if (!active_)
            return nrc (0x37, kNrcRequestSequenceError, "没有在下载中就发 0x37");
        if (image_.size () != expectedSize_)
            return nrc (0x37, kNrcRequestSequenceError,
                        "数据没传完：收到 " + std::to_string (image_.size ()) + "/" +
                        std::to_string (expectedSize_) + " 字节就要求收尾");

        active_ = false;
        // 正响应带回 CRC-32（可选参数，本项目带：让"完整性"这件事在收尾时就看得见）
        const std::uint32_t crc = crc32Of (image_);
        std::vector<std::uint8_t> r = {0x77,
                                       static_cast<std::uint8_t> ((crc >> 24) & 0xFF),
                                       static_cast<std::uint8_t> ((crc >> 16) & 0xFF),
                                       static_cast<std::uint8_t> ((crc >> 8) & 0xFF),
                                       static_cast<std::uint8_t> (crc & 0xFF)};
        return okay (r, "0x37 收尾：共 " + std::to_string (image_.size ()) + " 字节，CRC-32 = 0x" + hex32 (crc));
    }

    // ---- 0x31 01 FF01：完整性校验 ----
    //   客户端把"它自己算出来的 CRC"带过来；ECU 用收到的字节再算一遍比对。
    //   这一步之前很多人以为"传完了就等于刷对了" —— 传完只证明长度对，不证明内容对。
    FlashReply checkIntegrity (const std::vector<std::uint8_t> &expectedCrc)
    {
        if (expectedCrc.size () != 4)
            return nrc (0x31, kNrcIncorrectLength,
                        "校验例程要求 4 字节 CRC-32，实际 " + std::to_string (expectedCrc.size ()) + " 字节");
        if (image_.empty ())
            return nrc (0x31, kNrcConditionsNotCorrect, "还没有镜像可校验（先 0x34/0x36）");

        std::uint32_t expect = 0;
        for (std::size_t i = 0; i < 4; ++i) expect = (expect << 8) | expectedCrc[i];
        const std::uint32_t actual = crc32Of (image_);
        const bool pass = (expect == actual);
        return okay ({0x71, 0x01, 0xFF, 0x01, static_cast<std::uint8_t> (pass ? 0x00 : 0x01)},
                     std::string ("0x31 01 FF01：") + (pass ? "校验通过" : "校验失败") +
                     "（期望 0x" + hex32 (expect) + "，实算 0x" + hex32 (actual) + "）");
    }

    // ---- 观测量（日志与断言用）----
    const std::vector<std::uint8_t> &image () const { return image_; }
    std::uint32_t expectedSize () const { return expectedSize_; }
    std::uint32_t maxBlockLength () const { return maxBlockLength_; }
    std::uint32_t payloadPerBlock () const { return maxBlockLength_ - 2; }   // 减掉 0x36 + BSC
    std::uint8_t  lastBsc () const { return lastBsc_; }
    bool          active () const { return active_; }
    bool          erased () const { return erased_; }
    std::uint32_t crc32 () const { return crc32Of (image_); }
    std::uint32_t receipts () const { return receipts_; }

private:
    FlashReply okay (std::vector<std::uint8_t> bytes, std::string why)
    {
        FlashReply r;
        r.positive = true;
        r.uds      = std::move (bytes);
        r.reason   = std::move (why);
        return r;
    }

    FlashReply nrc (std::uint8_t sid, std::uint8_t code, std::string why)
    {
        FlashReply r;
        r.positive = false;
        r.uds      = {0x7F, sid, code};
        r.reason   = "NRC 0x" + hex8 (code) + "：" + why;
        return r;
    }

    static std::string hex8 (std::uint8_t v)
    {
        static const char *d = "0123456789ABCDEF";
        std::string s (2, '0');
        s[0] = d[(v >> 4) & 0x0F];
        s[1] = d[v & 0x0F];
        return s;
    }

    static std::string hex32 (std::uint32_t v)
    {
        static const char *d = "0123456789ABCDEF";
        std::string s (8, '0');
        for (int i = 0; i < 8; ++i) s[7 - i] = d[(v >> (i * 4)) & 0x0F];
        return s;
    }

    std::uint32_t             maxBlockLength_;
    std::uint32_t             maxImageSize_;
    bool                      requireErase_;
    std::vector<std::uint8_t> image_;
    std::uint32_t             expectedSize_ = 0;
    std::uint32_t             address_      = 0;
    std::uint8_t              lastBsc_      = 0;
    bool                      active_       = false;
    bool                      erased_       = false;
    std::uint32_t             receipts_     = 0;
};

} // namespace doip
