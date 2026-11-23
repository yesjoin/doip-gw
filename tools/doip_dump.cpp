// ============================================================================
// doip_dump.cpp —— 把一串十六进制翻译成人话
//
// 用途：Wireshark 里看到一个 DoIP 报文，复制它的字节粘贴过来，
//       立刻知道版本对不对、类型是什么、载荷多长、里面装的是什么。
//
// 用法：
//   ./build/doip-dump 02FD800100000007 0E00 0001 22F190
//   ./build/doip-dump "02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90"
// ============================================================================
#include "DoIpCodec.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace doip;

// 把命令行里所有参数拼成一串，去掉空格 / 冒号 / 减号 / 逗号 / 0x 前缀
static bool parseHexArgs (int argc, char **argv, std::vector<std::uint8_t> &out)
{
    std::string all;
    for (int i = 1; i < argc; ++i) all += argv[i];

    std::string hex;
    for (std::size_t i = 0; i < all.size (); ++i)
    {
        const char c = all[i];
        if (c == ' ' || c == ':' || c == '-' || c == ',' || c == '_') continue;
        if (c == '0' && (i + 1 < all.size ()) && (all[i + 1] == 'x' || all[i + 1] == 'X')) { ++i; continue; }
        hex.push_back (c);
    }

    if (hex.empty () || (hex.size () % 2) != 0)
    {
        std::fprintf (stderr, "十六进制字符数必须是偶数（现在 %zu 个）：%s\n", hex.size (), hex.c_str ());
        return false;
    }

    for (std::size_t i = 0; i < hex.size (); i += 2)
    {
        auto digit = [] (char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = digit (hex[i]);
        const int lo = digit (hex[i + 1]);
        if (hi < 0 || lo < 0)
        {
            std::fprintf (stderr, "不是合法的十六进制：%c%c\n", hex[i], hex[i + 1]);
            return false;
        }
        out.push_back (static_cast<std::uint8_t> ((hi << 4) | lo));
    }
    return true;
}

// UDS 服务号 → 人话（只列项目一里做过的那几个，够用）
static const char *udsServiceName (std::uint8_t sid)
{
    switch (sid)
    {
    case 0x10: return "DiagnosticSessionControl（会话）";
    case 0x11: return "ECUReset（复位）";
    case 0x14: return "ClearDiagnosticInformation（清故障码）";
    case 0x19: return "ReadDTCInformation（读故障码）";
    case 0x22: return "ReadDataByIdentifier（读 DID）";
    case 0x27: return "SecurityAccess（安全访问）";
    case 0x2E: return "WriteDataByIdentifier（写 DID）";
    case 0x31: return "RoutineControl（例程）";
    case 0x34: return "RequestDownload（请求下载）";
    case 0x36: return "TransferData（传数据）";
    case 0x37: return "RequestTransferExit（结束传输）";
    case 0x3E: return "TesterPresent（心跳）";
    case 0x7F: return "NegativeResponse（负应答）";
    default:   return nullptr;
    }
}

static void printHex (const std::vector<std::uint8_t> &b)
{
    for (std::size_t i = 0; i < b.size (); ++i) std::printf ("%02X%s", b[i], (i + 1 < b.size ()) ? " " : "");
}

int main (int argc, char **argv)
{
    if (argc < 2)
    {
        std::fprintf (stderr,
                     "用法：%s <十六进制字节>\n"
                     "例：  %s \"02 FD 80 01 00 00 00 07 0E 00 00 01 22 F1 90\"\n", argv[0], argv[0]);
        return 2;
    }

    std::vector<std::uint8_t> bytes;
    if (!parseHexArgs (argc, argv, bytes)) return 2;

    std::printf ("输入 %zu 字节：", bytes.size ());
    printHex (bytes);
    std::printf ("\n\n");

    Message m;
    ParseResult r = parseMessage (bytes.data (), bytes.size (), m);

    if (r.error != ParseError::None)
    {
        std::printf ("解析失败：%s\n", nameOf (r.error));
        if (r.error == ParseError::NeedMoreData)
        {
            std::printf ("  → 这不是错误。数据不够而已：%zu 字节还没凑成一条完整报文。\n", bytes.size ());
        }
        else
        {
            std::printf ("  → 建议回 0x0000 通用负应答，码值 0x%02X%s\n",
                         r.nackCode,
                         (r.nackCode == 0x00) ? "（格式不对）"
                         : (r.nackCode == 0x01) ? "（类型不认识）"
                         : (r.nackCode == 0x02) ? "（太长）" : "");
            if (r.nackCode == 0x00)
            {
                std::printf ("  → 特别提示：版本 %02X 的反码应该是 %02X。\n",
                             bytes[0], static_cast<unsigned> (inverseOf (bytes[0])));
            }
        }
        return 1;
    }

    const PayloadType t = toType (m.header.payloadType);

    std::printf ("头部\n");
    std::printf ("  版本       0x%02X（%s）\n", m.header.version,
                 m.header.version == kVersion2012 ? "ISO 13400-2:2012"
                 : m.header.version == kVersion2019 ? "ISO 13400-2:2019" : "不认识");
    std::printf ("  版本反码   0x%02X（%s）\n", m.header.versionInverse,
                 m.header.versionInverse == inverseOf (m.header.version) ? "对得上" : "对不上");
    std::printf ("  载荷类型   %s\n", nameOf (t));   // 名字里已经带了码值（如 "0x8001 Diagnostic message"）
    std::printf ("  载荷长度   %u 字节\n", static_cast<unsigned> (m.header.payloadLength));
    std::printf ("\n载荷\n");

    std::string err;
    switch (t)
    {
    case PayloadType::VehicleIdRequest:
        std::printf ("  （空载荷：就是一句「这网上有 DoIP 实体吗」）\n");
        break;

    case PayloadType::VehicleIdRequestEid:
    case PayloadType::VehicleIdRequestVin:
        std::printf ("  查询条件   ");
        printHex (m.payload);
        std::printf ("\n");
        break;

    case PayloadType::VehicleAnnouncement:
    {
        VehicleAnnouncement v;
        if (!decodePayload (m.payload, v, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  VIN        %s\n", v.vin.c_str ());
        std::printf ("  实体逻辑地址 0x%04X\n", v.logicalAddress);
        std::printf ("  EID        "); printHex (v.eid); std::printf ("\n");
        std::printf ("  GID        "); printHex (v.gid); std::printf ("\n");
        std::printf ("  further action 0x%02X\n", v.furtherAction);
        std::printf ("  VIN/GID 同步状态 0x%02X\n", v.syncStatus);
        break;
    }

    case PayloadType::RoutingActivationReq:
    {
        RoutingActivationRequest a;
        if (!decodePayload (m.payload, a, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  客户端地址   0x%04X\n", a.sourceAddress);
        std::printf ("  激活类型     0x%02X%s\n", a.activationType,
                     a.activationType == 0x00 ? "（默认）"
                     : a.activationType == 0x01 ? "（WWH-OBD）"
                     : a.activationType == 0xE0 ? "（中央安全）" : "");
        std::printf ("  ISO 保留     0x%08X\n", a.reserved);
        std::printf ("  OEM 自定义   0x%08X\n", a.oemSpecific);
        break;
    }

    case PayloadType::RoutingActivationRes:
    {
        RoutingActivationResponse a;
        if (!decodePayload (m.payload, a, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  tester 地址  0x%04X\n", a.testerAddress);
        std::printf ("  实体地址     0x%04X\n", a.entityAddress);
        std::printf ("  响应码       0x%02X%s\n", a.responseCode,
                     a.responseCode == 0x10 ? "（路由激活成功）"
                     : a.responseCode == 0x11 ? "（需确认后才能激活）"
                     : a.responseCode == 0x00 ? "（源地址不认识）"
                     : a.responseCode == 0x02 ? "（这个 socket 上已激活过别的源地址）"
                     : a.responseCode == 0x03 ? "（该源地址已在别的 socket 上注册）"
                     : a.responseCode == 0x06 ? "（不支持的激活类型）" : "");
        break;
    }

    case PayloadType::AliveCheckReq:
        std::printf ("  （空载荷：问客户端「你还活着吗」）\n");
        break;

    case PayloadType::AliveCheckRes:
    {
        AliveCheckResponse a;
        if (!decodePayload (m.payload, a, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  客户端地址   0x%04X（还活着）\n", a.sourceAddress);
        break;
    }

    case PayloadType::DiagnosticMessage:
    {
        DiagnosticMessage d;
        if (!decodePayload (m.payload, d, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  源地址       0x%04X\n", d.sourceAddress);
        std::printf ("  目标地址     0x%04X\n", d.targetAddress);
        std::printf ("  UDS 数据     "); printHex (d.uds); std::printf ("（%zu 字节）\n", d.uds.size ());
        if (!d.uds.empty ())
        {
            const char *n = udsServiceName (d.uds[0]);
            std::printf ("  服务         0x%02X %s\n", d.uds[0], n ? n : "（不认识的服务号）");
            if (d.uds[0] == 0x22 && d.uds.size () >= 3)
            {
                std::printf ("  读的 DID     0x%02X%02X\n", d.uds[1], d.uds[2]);
            }
        }
        break;
    }

    case PayloadType::DiagnosticPositiveAck:
    {
        DiagnosticPositiveAck a;
        if (!decodePayload (m.payload, a, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  源地址 / 目标地址 0x%04X → 0x%04X\n", a.sourceAddress, a.targetAddress);
        std::printf ("  应答码       0x%02X（正应答，服务器收下了）\n", a.ackCode);
        break;
    }

    case PayloadType::DiagnosticNegativeAck:
    {
        DiagnosticNegativeAck a;
        if (!decodePayload (m.payload, a, err)) { std::printf ("  %s\n", err.c_str ()); break; }
        std::printf ("  源地址 / 目标地址 0x%04X → 0x%04X\n", a.sourceAddress, a.targetAddress);
        std::printf ("  NACK 码      0x%02X\n", a.nackCode);
        if (!a.previous.empty ())
        {
            std::printf ("  带回的原报文 "); printHex (a.previous); std::printf ("\n");
        }
        break;
    }

    case PayloadType::GenericHeaderNack:
        std::printf ("  码值         0x%02X %s\n", m.payload.empty () ? 0 : m.payload[0],
                     m.payload.empty () ? "（载荷为空，不合规）" : nameOf (static_cast<GenericNack> (m.payload[0])));
        break;

    default:
        std::printf ("  （本工具暂不翻译这个类型）\n");
        break;
    }

    const std::size_t rest = bytes.size () - r.consumed;
    if (rest > 0)
    {
        std::printf ("\n注意：后面还有 %zu 字节没被这条报文吃掉 —— 可能粘着下一条报文（TCP 常见）。\n", rest);
    }
    else
    {
        std::printf ("\n字节数正好对齐（%zu = 8 头 + %zu 载荷），没有多余字节。\n",
                     bytes.size (), m.payload.size ());
    }
    return 0;
}
