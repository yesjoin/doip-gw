#pragma once
// ============================================================================
// IsoTpStack.h —— M4：ISO 15765-2 的**发送方**分片与接收方重组（纯逻辑）
//
// 为什么要自己写一份，而不是把项目一的 IsoTp 搬过来？
//   项目一那份是**ECU 侧**：被动收帧、等上层问"要不要回流控"。
//   网关这侧是**tester 侧**：主动拆帧、主动发首帧、等对方的流控帧。
//   方向反过来，状态机就不一样了 —— 这不是复制粘贴能解决的。
//
// 本文件只做两件事，不碰 socket、不 sleep：
//   · segmentMessage()：一条消息 → 一串帧（SF / FF / CF）
//   · IsoTpAssembler：一串帧 → 一条消息（收响应时用）
// 收发与定时（STmin、N_P2）在 IsoTpClient 里。
//
// M9 补的一层：**帧不再固定 8 字节**。
//   CAN FD 一帧能装 64 字节，于是 ISO-TP 的分片规则整个换了一次：
//     · 单帧仍用 0x0N（N ≤ 7）；但 8..62 字节要改用"转义单帧"：0x00 + 长度字节 + 数据
//     · 首帧不带 6 字节而是带 (帧长 - 2) 字节；连续帧每张带 (帧长 - 1) 字节
//   顺序号、流控、4095 字节上限都没变 —— 变的是"每张帧能塞多少"和"单帧怎么声明长度"。
//
// 三个要点（M4 就定下，M9 依然成立）：
//   ① SF 在经典帧里只装 7 字节；FD 里靠转义能装到 62
//   ② FF 的长度字段只有 12 位 → 单条消息上限 4095 字节
//   ③ CF 的序号 SN 从 1 开始，15 之后回到 1（不是回到 0，这点两侧必须一致）
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace doip
{

inline constexpr std::size_t kClassicFrameBytes = 8;    // 经典 CAN：8 字节
inline constexpr std::size_t kFdFrameBytes      = 64;   // CAN FD：最多 64 字节

struct IsoTpConfig
{
    std::uint32_t txId    = 0x7E0;    // 我们发（tester → ECU）
    std::uint32_t rxId    = 0x7E8;    // 我们收（ECU → tester）
    std::uint8_t  padByte = 0x00;     // 不足一帧时补的字节
    std::size_t   maxMsg  = 4095;     // FF 长度字段 12 位的硬上限
    std::size_t   frameBytes = kClassicFrameBytes;   // M9：8 = 经典 CAN，64 = CAN FD
};

enum class FrameKind : std::uint8_t
{
    SingleFrame      = 0x0,
    FirstFrame       = 0x1,
    ConsecutiveFrame = 0x2,
    FlowControl      = 0x3,
};

FrameKind kindOf (const std::uint8_t data[8]);

// 一条消息 → 一串帧。空消息、超过 maxMsg、frameBytes 非法都返回 false。
// frameBytes 默认 8，所以 M4～M8 的老调用一个字都不用改。
bool segmentMessage (const std::vector<std::uint8_t> &msg,
                     std::vector<std::vector<std::uint8_t>> &frames,
                     std::string &err,
                     std::uint8_t padByte = 0x00,
                     std::size_t frameBytes = kClassicFrameBytes);

// 把一条消息切帧后，需要几个"连续帧"—— 自测和日志都用得上
std::size_t consecutiveFrameCount (std::size_t msgBytes,
                                   std::size_t frameBytes = kClassicFrameBytes);

// 接收侧重组。tester 收响应时：SF 一帧搞定；FF 之后由调用方回流控，再喂 CF。
class IsoTpAssembler
{
public:
    enum class Result
    {
        NeedMore,     // 还没收全（或者刚收到 FF，等调用方回流控帧）
        Complete,     // out 里是完整消息
        Error,        // 序号错 / 长度不对 / 装不下
    };

    explicit IsoTpAssembler (std::size_t maxMsg = 4095,
                             std::size_t frameBytes = kClassicFrameBytes);

    // len 是这一帧真实的字节数（1..frameBytes）。**不能假定满帧**：
    // 很多 ECU 的单帧不补零，DLC 就是实际长度（比如 7E8#027E00 只有 3 字节）。
    Result onFrame (const std::uint8_t data[64], std::vector<std::uint8_t> &out, std::string &err,
                    std::size_t len = kClassicFrameBytes);

    bool     receiving () const { return active_; }
    std::size_t expected () const { return total_; }
    std::size_t received () const { return got_; }
    void     reset ();

private:
    std::size_t               maxMsg_;
    std::size_t               frameBytes_;
    bool                      active_ = false;
    std::size_t               total_  = 0;
    std::size_t               got_    = 0;
    std::uint8_t              nextSeq_ = 1;
    std::vector<std::uint8_t> buf_;
};

// 流控帧的三种流状态
enum class FlowStatus : std::uint8_t
{
    ContinueToSend = 0x0,
    Wait           = 0x1,
    Overflow       = 0x2,
};

struct FlowControl
{
    FlowStatus   status   = FlowStatus::ContinueToSend;
    std::uint8_t blockSize = 0;       // 0 = 不用再等流控
    std::uint8_t stMin     = 0;       // 0..127 = 毫秒；0xF1..0xF9 = 100..900 微秒
};

// 解析 0x30 帧；不是流控帧返回 false
bool parseFlowControl (const std::uint8_t data[8], FlowControl &out, std::string &err);

// 组一张流控帧（我们收 FF 时要回它）。M9：FD 下要把帧填满 64 字节，
// 否则对端按 8 字节的 FC 处理也能通，但总线上会少一截（排错时容易误判）。
void buildFlowControl (std::uint8_t blockSize, std::uint8_t stMin, std::uint8_t padByte,
                       std::uint8_t *data, std::size_t frameBytes = kClassicFrameBytes);

} // namespace doip
