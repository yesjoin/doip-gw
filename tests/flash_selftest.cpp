// ============================================================================
// flash_selftest.cpp —— M15 的纯逻辑自测（FlashTarget：被刷端的状态机）
//
// 刷写的错法几乎都不是"写错一个字节"，而是"顺序/计数/长度"这三类：
//   · 没擦就下载、没协商就传、没传完就收尾；
//   · BSC 从 0 开始、或者 0xFF 之后回 0x01（短镜像永远测不出，长镜像第 256 块炸）；
//   · maxNumberOfBlockLength 当成"数据段上限"，每块多带 2 字节；
//   · 重发被当成跳号，链路丢一次应答就永久卡死；
//   · 传完了就以为对了（长度对 ≠ 内容对）。
// 下面每条都走一遍，包括回绕那一条。
//
// 用法：./flash-selftest        全绿时退出码 0
// ============================================================================
#include "FlashTarget.h"

#include <cstdio>
#include <string>

using namespace doip;

static int gPass = 0;
static int gFail = 0;

#define CHECK(cond, what)                                              \
    do {                                                               \
        if (cond) { ++gPass; }                                         \
        else {                                                         \
            ++gFail;                                                   \
            std::printf ("[FAIL] 第 %d 行：%s\n", __LINE__, std::string (what).c_str ()); \
        }                                                              \
    } while (0)

// 按 alfid=0x44（4 字节地址 + 4 字节长度）组 0x34 的地址/长度段
static std::vector<std::uint8_t> addrAndSize (std::uint32_t addr, std::uint32_t size)
{
    std::vector<std::uint8_t> v;
    for (int i = 3; i >= 0; --i) v.push_back (static_cast<std::uint8_t> ((addr >> (i * 8)) & 0xFF));
    for (int i = 3; i >= 0; --i) v.push_back (static_cast<std::uint8_t> ((size >> (i * 8)) & 0xFF));
    return v;
}

static std::vector<std::uint8_t> pattern (std::size_t n, std::uint8_t seed = 0)
{
    std::vector<std::uint8_t> v;
    v.reserve (n);
    for (std::size_t i = 0; i < n; ++i) v.push_back (static_cast<std::uint8_t> ((i + seed) & 0xFF));
    return v;
}

int main ()
{
    // ---- A. CRC-32 的已知值：算错了后面所有校验都是假绿 ----
    {
        const char *s = "123456789";
        const std::uint32_t crc = crc32Of (reinterpret_cast<const std::uint8_t *> (s), 9);
        CHECK (crc == 0xCBF43926u, "CRC-32(\"123456789\") = 0xCBF43926（IEEE 标准校验值）");
        std::vector<std::uint8_t> empty;
        CHECK (crc32Of (empty) == 0u, "空数据的 CRC-32 = 0");
    }

    // ---- B. 没擦就下载：0x22（状态不对，不是"参数不对"） ----
    {
        FlashTarget t;
        auto r = t.requestDownload (0x00, 0x44, addrAndSize (0, 100));
        CHECK (!r.positive, "没擦除就 0x34 → 拒绝");
        CHECK (r.uds.size () == 3 && r.uds[0] == 0x7F && r.uds[1] == 0x34, "否定响应格式：7F 34 xx");
        CHECK (r.uds[2] == kNrcConditionsNotCorrect, "码是 0x22（conditionsNotCorrect）");
    }

    // ---- C. 擦除 → 0x34 成功，通告的块长要含 SID 和 BSC ----
    {
        FlashTarget t (34);
        auto e = t.handleErase ();
        CHECK (e.positive && e.uds.size () == 4 && e.uds[0] == 0x71, "0x31 01 FF00 → 71 01 FF 00");
        CHECK (t.erased () && !t.active (), "擦除后：已擦、无在途下载");

        auto r = t.requestDownload (0x00, 0x44, addrAndSize (0x00440000, 100));
        CHECK (r.positive, "擦除后 0x34 → 接受");
        CHECK (r.uds.size () == 4 && r.uds[0] == 0x74, "正响应是 0x74 + 1 + 2 字节");
        CHECK (r.uds[1] == 0x20, "lengthFormatIdentifier = 0x20（2 字节长度字段）");
        CHECK (r.uds[2] == 0x00 && r.uds[3] == 0x22, "maxNumberOfBlockLength = 34（0x0022，含 0x36+BSC）");
        CHECK (t.payloadPerBlock () == 32, "每块数据上限 = 34 - 2 = 32 字节");
        CHECK (t.expectedSize () == 100 && t.active (), "登记了长度，进入下载态");
    }

    // ---- D. 0x34 的参数检查：每条都回对码，不要一律 0x10 ----
    {
        FlashTarget t (34);
        t.handleErase ();
        auto r = t.requestDownload (0x01, 0x44, addrAndSize (0, 10));
        CHECK (!r.positive && r.uds[2] == kNrcRequestOutOfRange, "dfi≠0 → 0x31");

        r = t.requestDownload (0x00, 0x00, addrAndSize (0, 10));
        CHECK (!r.positive && r.uds[2] == kNrcRequestOutOfRange, "alfid=0x00（0 字节地址/长度）→ 0x31");

        std::vector<std::uint8_t> shortOne = {0x00, 0x44, 0x00, 0x00};
        r = t.requestDownload (0x00, 0x44, shortOne);
        CHECK (!r.positive && r.uds[2] == kNrcIncorrectLength, "地址/长度段少字节 → 0x13");

        r = t.requestDownload (0x00, 0x44, addrAndSize (0, 0));
        CHECK (!r.positive && r.uds[2] == kNrcRequestOutOfRange, "memorySize=0 → 0x31");

        r = t.requestDownload (0x00, 0x44, addrAndSize (0, 1u << 21));
        CHECK (!r.positive && r.uds[2] == kNrcRequestOutOfRange, "超过 ECU 上限 → 0x31");
    }

    // ---- E. 没协商就传 / 没协商就收尾：0x24（顺序错） ----
    {
        FlashTarget t;
        t.handleErase ();
        auto r = t.transferData (0x01, pattern (10));
        CHECK (!r.positive && r.uds[2] == kNrcRequestSequenceError, "没有 0x34 就 0x36 → 0x24");
        r = t.requestTransferExit ();
        CHECK (!r.positive && r.uds[2] == kNrcRequestSequenceError, "没有 0x34 就 0x37 → 0x24");
    }

    // ---- F. BSC：从 1 起、跳号 0x73、重发幂等 ----
    {
        FlashTarget t (10);     // 一块最多 8 字节数据
        t.handleErase ();
        t.requestDownload (0x00, 0x44, addrAndSize (0, 40));

        auto a = t.transferData (0x01, pattern (8, 0));
        CHECK (a.positive && a.uds[0] == 0x76 && a.uds[1] == 0x01, "第一块 BSC=0x01 接受，0x76 回 01");
        CHECK (t.lastBsc () == 0x01, "记账：上一块是 0x01");

        auto b = t.transferData (0x02, pattern (8, 8));
        CHECK (b.positive && b.uds[1] == 0x02, "第二块 BSC=0x02 接受");

        const std::size_t before = t.image ().size ();
        auto dup = t.transferData (0x02, pattern (8, 8));
        CHECK (dup.positive && dup.uds[1] == 0x02, "重发同一块 → 仍回 0x76 02（幂等）");
        CHECK (t.image ().size () == before, "重发没有把同一块写第二遍（镜像长度不变）");

        auto jump = t.transferData (0x05, pattern (8, 0));
        CHECK (!jump.positive && jump.uds[2] == kNrcWrongBlockSequence, "跳到 0x05 → 0x73 跳号");
        CHECK (t.lastBsc () == 0x02, "被拒的块不改记账");

        auto next = t.transferData (0x03, pattern (8, 16));
        CHECK (next.positive, "被拒之后下一块（0x03）仍然能接（不会被永久卡死）");
    }

    // ---- G. 块长 / 总长越界 ----
    {
        FlashTarget t (10);
        t.handleErase ();
        t.requestDownload (0x00, 0x44, addrAndSize (0, 100));

        auto big = t.transferData (0x01, pattern (9));       // 9 + 2 = 11 > 10
        CHECK (!big.positive && big.uds[2] == kNrcIncorrectLength, "块 11 字节（含 SID+BSC）> 通告 10 → 0x13");

        auto ok8 = t.transferData (0x01, pattern (8));
        CHECK (ok8.positive, "8 字节数据（正好 10）→ 接受");

        auto over = t.transferData (0x02, pattern (8));
        CHECK (over.positive, "第二块照常");
        // 现在已收 16 字节，声明 100；再灌到超过 100 为止，然后看 0x71
        std::uint8_t bsc = 0x03;
        bool allAccepted = true;
        while (t.image ().size () + 8 <= 100)
        {
            if (!t.transferData (bsc, pattern (8)).positive) allAccepted = false;
            if (bsc == 0xFF) bsc = 0x00; else ++bsc;
        }
        CHECK (allAccepted, "填到不超过声明长度：每块都接受");
        // 还差 4 字节（100-96），发 8 字节就会超
        auto tooMuch = t.transferData (bsc, pattern (8));
        CHECK (!tooMuch.positive && tooMuch.uds[2] == kNrcTransferDataSuspended,
               "超出声明长度的块 → 0x71（transferDataSuspended）");
        auto tail = t.transferData (bsc, pattern (4));
        CHECK (tail.positive, "最后一块短包（4 字节）→ 接受");
        CHECK (t.image ().size () == 100, "镜像正好 100 字节");
    }

    // ---- H. 0x37：没传完 0x24，传完 0x77 + CRC ----
    {
        FlashTarget t (10);
        t.handleErase ();
        t.requestDownload (0x00, 0x44, addrAndSize (0, 20));
        t.transferData (0x01, pattern (8));

        auto early = t.requestTransferExit ();
        CHECK (!early.positive && early.uds[2] == kNrcRequestSequenceError, "只传了 8/20 就 0x37 → 0x24");

        t.transferData (0x02, pattern (8, 8));
        t.transferData (0x03, pattern (4, 16));
        auto exitOk = t.requestTransferExit ();
        CHECK (exitOk.positive && exitOk.uds[0] == 0x77, "20/20 之后 0x37 → 0x77");
        CHECK (exitOk.uds.size () == 5, "0x77 带回 4 字节 CRC");
        const std::uint32_t crc = (static_cast<std::uint32_t> (exitOk.uds[1]) << 24) |
                                  (static_cast<std::uint32_t> (exitOk.uds[2]) << 16) |
                                  (static_cast<std::uint32_t> (exitOk.uds[3]) << 8) |
                                  (static_cast<std::uint32_t> (exitOk.uds[4]));
        CHECK (crc == crc32Of (t.image ()), "应答里的 CRC 和镜像实算一致");
        CHECK (!t.active (), "收尾之后退出下载态（再发 0x36 会是 0x24）");
        CHECK (t.transferData (0x04, pattern (4)).uds[2] == kNrcRequestSequenceError,
               "收尾后再传 → 0x24（先 0x34）");
    }

    // ---- I. BSC 回绕：0xFF 之后是 0x00（不是 0x01、不是报错） ----
    {
        FlashTarget t (10);
        t.handleErase ();
        // 260 块 × 8 字节 + 4 = 2084 字节，够跨过 0xFF
        t.requestDownload (0x00, 0x44, addrAndSize (0, 260 * 8));

        std::uint8_t bsc = 0x01;
        bool sawZero = false;
        bool allOk = true;
        for (int i = 0; i < 260; ++i)
        {
            auto r = t.transferData (bsc, pattern (8, static_cast<std::uint8_t> (i)));
            if (!r.positive) allOk = false;
            if (i == 255)
            {
                CHECK (bsc == 0x00, "第 256 块用的是 BSC=0x00（0xFF 之后回绕到 0x00）");
                sawZero = true;
            }
            if (bsc == 0xFF) bsc = 0x00; else ++bsc;
        }
        CHECK (allOk, "260 块全部接受（回绕不是错误）");
        CHECK (sawZero, "回绕这一块真的跑到了");
        CHECK (t.image ().size () == 260 * 8, "260 块正好 2080 字节");
        auto exitOk = t.requestTransferExit ();
        CHECK (exitOk.positive, "260 块之后能正常收尾");
    }

    // ---- J. 完整性校验：长度对 ≠ 内容对 ----
    {
        FlashTarget t (10);
        t.handleErase ();
        t.requestDownload (0x00, 0x44, addrAndSize (0, 16));
        t.transferData (0x01, pattern (8));
        t.transferData (0x02, pattern (8, 8));

        const std::uint32_t good = t.crc32 ();
        std::vector<std::uint8_t> crcBytes = {static_cast<std::uint8_t> ((good >> 24) & 0xFF),
                                              static_cast<std::uint8_t> ((good >> 16) & 0xFF),
                                              static_cast<std::uint8_t> ((good >> 8) & 0xFF),
                                              static_cast<std::uint8_t> (good & 0xFF)};
        auto pass = t.checkIntegrity (crcBytes);
        CHECK (pass.positive && pass.uds.size () == 5 && pass.uds[4] == 0x00, "CRC 正确 → 71 01 FF 01 00");

        crcBytes[3] ^= 0x01;
        auto failReply = t.checkIntegrity (crcBytes);
        CHECK (failReply.positive && failReply.uds[4] == 0x01, "CRC 错 → 状态字节 0x01（不是否定响应）");

        auto shortCrc = t.checkIntegrity ({0x00, 0x00});
        CHECK (!shortCrc.positive && shortCrc.uds[2] == kNrcIncorrectLength, "只带 2 字节 CRC → 0x13");

        FlashTarget fresh;
        fresh.handleErase ();
        auto none = fresh.checkIntegrity (crcBytes);
        CHECK (!none.positive && none.uds[2] == kNrcConditionsNotCorrect, "没有镜像就校验 → 0x22");
    }

    // ---- K. 擦除是"回到起点"：再擦一次能把在途下载清掉 ----
    {
        FlashTarget t (10);
        t.handleErase ();
        t.requestDownload (0x00, 0x44, addrAndSize (0, 100));
        t.transferData (0x01, pattern (8));
        CHECK (t.active (), "0x34 之后进入下载态");

        auto e2 = t.handleErase ();
        CHECK (e2.positive, "下载中途再擦除 → 允许（现场就是这么重来的）");
        CHECK (!t.active () && t.image ().empty () && t.lastBsc () == 0, "擦除把在途状态和镜像一起清掉");
        CHECK (t.transferData (0x01, pattern (8)).uds[2] == kNrcRequestSequenceError,
               "擦除之后再 0x36 → 0x24（必须先 0x34）");
    }

    std::printf ("\n通过 %d 项，失败 %d 项\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
