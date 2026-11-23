// ============================================================================
// codec_selftest.cpp —— M0 的内存自测
//
// 原则（从项目二的缺陷账本换来的）：
//   **期望值必须在纸上算出来再写进代码，不能跑一遍看输出、把输出抄成期望值。**
//   抄代码做的测试，只证明"代码等于它自己"。
//
// 所以下面凡是写死的字节（02 FD 00 01 ...）都是我手算的，不是打印出来的。
// ============================================================================
#include "DoIpCodec.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace doip;

static int g_pass = 0;
static int g_fail = 0;

static void check (bool cond, const std::string &what)
{
    if (cond)
    {
        std::printf ("[PASS] %s\n", what.c_str ());
        ++g_pass;
    }
    else
    {
        std::printf ("[FAIL] %s\n", what.c_str ());
        ++g_fail;
    }
}

// 拼一段诊断报文：源地址 + 目标地址 + UDS
static std::vector<std::uint8_t> diagBytes (std::uint16_t sa,
                                            std::uint16_t ta,
                                            const std::vector<std::uint8_t> &uds)
{
    DiagnosticMessage m;
    m.sourceAddress = sa;
    m.targetAddress = ta;
    m.uds           = uds;
    return build (PayloadType::DiagnosticMessage, encodePayload (m));
}

int main ()
{
    // -----------------------------------------------------------------------
    std::printf ("=== A 版本反码：DoIP 的魔数 ===\n");
    check (inverseOf (0x02) == 0xFD, "0x02 的反码是 0xFD");
    check (inverseOf (0x03) == 0xFC, "0x03 的反码是 0xFC");
    check (inverseOf (0xFF) == 0x00, "0xFF 的反码是 0x00（补码的边界）");

    // -----------------------------------------------------------------------
    std::printf ("\n=== B 头部字节布局（大端）===\n");
    std::vector<std::uint8_t> req = build (PayloadType::VehicleIdRequest, {});
    check (req.size () == 8, "0x0001 空载荷 → 报文正好 8 字节");
    check (req[0] == 0x02 && req[1] == 0xFD, "前两字节是 02 FD（版本 + 反码）");
    check (req[2] == 0x00 && req[3] == 0x01, "类型字段是 00 01（大端，不是 01 00）");

    // 长度字段：一个 11 字节载荷 → 线上必须是 00 00 00 0B
    RoutingActivationRequest ra;
    ra.sourceAddress  = 0x0E00;
    ra.activationType = 0x00;
    std::vector<std::uint8_t> raMsg = build (PayloadType::RoutingActivationReq, encodePayload (ra));
    check (raMsg.size () == 19, "0x0005 报文 = 8 头 + 11 载荷 = 19 字节");
    check (raMsg[4] == 0x00 && raMsg[5] == 0x00 && raMsg[6] == 0x00 && raMsg[7] == 0x0B,
           "长度字段 4 字节是 00 00 00 0B（大端：高字节在前）");

    // 33 字节载荷 → 00 00 00 21
    VehicleAnnouncement ann;
    ann.vin            = "LSVAA20A8F2100001";
    ann.logicalAddress = 0x0001;
    ann.eid            = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    ann.gid            = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    std::vector<std::uint8_t> annMsg = build (PayloadType::VehicleAnnouncement, encodePayload (ann));
    check (annMsg[7] == 0x21 && annMsg[4] == 0x00, "33 字节载荷 → 长度字段 00 00 00 21");

    // -----------------------------------------------------------------------
    std::printf ("\n=== C 正常解析 + 载荷解码 ===\n");
    Message m;
    ParseResult r = parseMessage (req.data (), req.size (), m);
    check (r.error == ParseError::None, "8 字节的 0x0001 能解出来");
    check (r.consumed == 8, "消耗 8 字节");
    check (m.payload.empty (), "载荷是空的");
    check (m.header.payloadType == 0x0001, "类型解回 0x0001");
    check (m.totalSize () == 8, "totalSize() = 8");

    std::vector<std::uint8_t> dm = diagBytes (0x0E00, 0x0001, {0x22, 0xF1, 0x90});
    // 手算：头 02 FD 80 01 00 00 00 07 + 载荷 0E 00 00 01 22 F1 90
    check (dm.size () == 15, "0x8001（3 字节 UDS）→ 15 字节");
    check (dm[2] == 0x80 && dm[3] == 0x01, "类型字段是 80 01");
    check (dm[7] == 0x07, "长度字段末字节 = 7（4 + 3 字节 UDS）");
    check (dm[8] == 0x0E && dm[9] == 0x00, "源地址 0x0E00 线上是 0E 00");
    check (dm[10] == 0x00 && dm[11] == 0x01, "目标地址 0x0001 线上是 00 01");
    check (dm[12] == 0x22 && dm[13] == 0xF1 && dm[14] == 0x90, "UDS 字节原样搬运 22 F1 90");

    Message m2;
    r = parseMessage (dm.data (), dm.size (), m2);
    check (r.error == ParseError::None && r.consumed == 15, "0x8001 报文能解出来，消耗 15 字节");

    DiagnosticMessage d;
    std::string err;
    check (decodePayload (m2.payload, d, err), "0x8001 载荷能解码");
    check (d.sourceAddress == 0x0E00, "源地址解回 0x0E00");
    check (d.targetAddress == 0x0001, "目标地址解回 0x0001");
    check (d.uds.size () == 3 && d.uds[0] == 0x22, "UDS 解回 3 字节，首字节 0x22");

    // -----------------------------------------------------------------------
    std::printf ("\n=== D 半包：数据不够时要等，不是报错 ===\n");
    Message m3;
    r = parseMessage (dm.data (), 7, m3);          // 只给 7 字节，头差 1 字节
    check (r.error == ParseError::NeedMoreData, "7 字节 → 半包（连头都没凑齐）");
    check (r.consumed == 0, "半包时一个字节都不能丢（consumed = 0）");

    r = parseMessage (dm.data (), 0, m3);
    check (r.error == ParseError::NeedMoreData, "0 字节 → 半包");

    r = parseMessage (dm.data (), 11, m3);         // 头说 7 字节载荷，只给了 3 字节
    check (r.error == ParseError::NeedMoreData, "头完整但载荷缺 4 字节 → 半包");
    check (r.consumed == 0, "仍是 consumed = 0");

    r = parseMessage (dm.data (), 15, m3);         // 刚好凑齐
    check (r.error == ParseError::None, "刚好凑齐 → 解析成功（前面的半包不是死循环）");

    // 两条报文拼在一起（这就是 TCP 粘包的形状）：循环 parse 能全解
    std::vector<std::uint8_t> two = req;
    two.insert (two.end (), dm.begin (), dm.end ());
    check (two.size () == 23, "两条报文拼起来 = 8 + 15 = 23 字节");
    std::size_t pos = 0;
    Message a, b;
    r = parseMessage (two.data (), two.size (), a);
    check (r.consumed == 8, "循环第 1 次：吃掉 8 字节");
    pos += r.consumed;
    r = parseMessage (two.data () + pos, two.size () - pos, b);
    check (r.consumed == 15, "循环第 2 次：吃掉 15 字节");
    check (b.header.payloadType == 0x8001, "第 2 条确实是 0x8001");
    check (pos + r.consumed == 23, "两次合计 23 字节，不多不少");

    // -----------------------------------------------------------------------
    std::printf ("\n=== E 格式错误：头读到了但内容不对 ===\n");
    std::vector<std::uint8_t> badInv = build (PayloadType::VehicleIdRequest, {});
    badInv[1] = 0x00;                              // 反码故意写错
    Message m4;
    r = parseMessage (badInv.data (), badInv.size (), m4);
    check (r.error == ParseError::BadPattern, "反码不对 → BadPattern");
    check (r.consumed == 8, "头已完整，可以丢掉这 8 字节");
    check (r.nackCode == 0x00, "建议回 NACK 0x00（格式不对）");

    std::vector<std::uint8_t> badVer = build (PayloadType::VehicleIdRequest, {}, 0x05);
    r = parseMessage (badVer.data (), badVer.size (), m4);
    check (r.error == ParseError::BadPattern, "版本 0x05（反码写对了）仍然 BadPattern —— 只认 02/03");

    std::vector<std::uint8_t> unk = build (PayloadType::VehicleIdRequest, {});
    unk[2] = 0x12;
    unk[3] = 0x34;                                 // 类型改成 0x1234（不存在）
    r = parseMessage (unk.data (), unk.size (), m4);
    check (r.error == ParseError::UnknownPayloadType, "类型 0x1234 → UnknownPayloadType");
    check (r.nackCode == 0x01, "建议回 NACK 0x01（类型不认识）");
    check (r.consumed == 8, "类型不认识时也只能丢掉头（载荷语义未知）");

    std::vector<std::uint8_t> huge = build (PayloadType::VehicleIdRequest, {});
    huge[4] = 0xFF; huge[5] = 0xFF; huge[6] = 0xFF; huge[7] = 0xFF;   // 声称号称 4GB
    r = parseMessage (huge.data (), huge.size (), m4);
    check (r.error == ParseError::PayloadTooLarge, "声称 4GB → PayloadTooLarge（malloc 之前拦住）");
    check (r.nackCode == 0x02, "建议回 NACK 0x02（太长）");

    r = parseMessage (huge.data (), huge.size (), m4, 100);
    check (r.error == ParseError::PayloadTooLarge, "上限可调：maxPayload=100 也拦住");

    std::vector<std::uint8_t> ok5 = build (PayloadType::RoutingActivationReq, encodePayload (ra));
    r = parseMessage (ok5.data (), ok5.size (), m4, 100);
    check (r.error == ParseError::None, "11 字节载荷在上限 100 下正常通过");

    // -----------------------------------------------------------------------
    std::printf ("\n=== F 通用头负应答 0x0000 ===\n");
    std::vector<std::uint8_t> nack = buildGenericNack (GenericNack::IncorrectPattern);
    check (nack.size () == 9, "负应答 = 8 头 + 1 字节码 = 9 字节");
    check (nack[2] == 0x00 && nack[3] == 0x00, "类型是 00 00");
    check (nack[7] == 0x01, "长度字段是 1");
    check (nack[8] == 0x00, "码值是 0x00（格式不对）");

    std::vector<std::uint8_t> nack1 = buildGenericNack (GenericNack::UnknownPayloadType);
    check (nack1[8] == 0x01, "换一个码：0x01（类型不认识）");
    Message m5;
    r = parseMessage (nack1.data (), nack1.size (), m5);
    check (r.error == ParseError::None && m5.payload.size () == 1, "负应答自己也能被解出来（1 字节载荷）");

    // -----------------------------------------------------------------------
    std::printf ("\n=== G 路由激活 0x0005 / 0x0006 ===\n");
    std::vector<std::uint8_t> raP = encodePayload (ra);
    check (raP.size () == 11, "0x0005 载荷 11 字节");
    check (raP[0] == 0x0E && raP[1] == 0x00, "源地址 0x0E00 在载荷前两字节（大端）");
    check (raP[2] == 0x00, "激活类型 0x00 在第 3 字节");

    RoutingActivationRequest ra2;
    check (decodePayload (raP, ra2, err), "0x0005 载荷能解码");
    check (ra2.sourceAddress == 0x0E00 && ra2.activationType == 0x00, "源地址 / 激活类型往返一致");

    raP.pop_back ();
    check (!decodePayload (raP, ra2, err), "0x0005 只有 10 字节 → 拒绝（不猜）");

    RoutingActivationResponse rr;
    rr.testerAddress = 0x0E00;
    rr.entityAddress = 0x0001;
    rr.responseCode  = 0x10;      // 路由激活成功
    std::vector<std::uint8_t> rrP = encodePayload (rr);
    check (rrP.size () == 13, "0x0006 载荷 13 字节");
    check (rrP[4] == 0x10, "响应码 0x10 在第 5 字节（成功）");
    RoutingActivationResponse rr2;
    check (decodePayload (rrP, rr2, err), "0x0006 载荷能解码");
    check (rr2.responseCode == 0x10 && rr2.entityAddress == 0x0001, "响应码 / 实体地址往返一致");

    // -----------------------------------------------------------------------
    std::printf ("\n=== H 心跳检查应答 0x0008 ===\n");
    AliveCheckResponse ac;
    ac.sourceAddress = 0x0E00;
    std::vector<std::uint8_t> acP = encodePayload (ac);
    check (acP.size () == 2, "0x0008 载荷 2 字节");
    check (acP[0] == 0x0E && acP[1] == 0x00, "客户端地址 0E 00");
    acP.push_back (0xFF);
    AliveCheckResponse ac2;
    check (!decodePayload (acP, ac2, err), "0x0008 多 1 字节 → 拒绝（严格长度）");

    // -----------------------------------------------------------------------
    std::printf ("\n=== I 车辆声明 0x0004 ===\n");
    check (annMsg.size () == 41, "0x0004 报文 = 8 + 33 = 41 字节");
    check (encodePayload (ann).size () == 33, "0x0004 载荷正好 33 字节");
    check (annMsg[7] == 0x21, "报文长度字段 0x21 = 33");

    VehicleAnnouncement ann2;
    std::vector<std::uint8_t> annP = encodePayload (ann);
    check (annP[0] == 'L', "第 1 字节是 VIN 首字符 L");
    check (annP[17] == 0x00 && annP[18] == 0x01, "VIN 之后（偏移 17）是逻辑地址 00 01");
    check (annP[19] == 0x00 && annP[24] == 0x55, "偏移 19..24 是 EID 六字节");
    check (annP[25] == 0x66 && annP[30] == 0xBB, "偏移 25..30 是 GID 六字节");
    check (annP[31] == 0x00 && annP[32] == 0x00, "偏移 31 是 further action、32 是同步状态");
    check (decodePayload (annP, ann2, err), "0x0004 载荷能解码");
    check (ann2.vin == ann.vin && ann2.logicalAddress == 0x0001, "VIN / 逻辑地址往返一致");
    check (ann2.eid[5] == 0x55 && ann2.gid[0] == 0x66, "EID / GID 往返一致");

    VehicleAnnouncement shortVin;
    shortVin.vin = "LSVAA20A8F210000";           // 故意 16 位
    check (encodePayload (shortVin).size () == 33, "VIN 只有 16 位也生成 33 字节（补空格，不错位）");

    // -----------------------------------------------------------------------
    std::printf ("\n=== J 诊断应答 0x8002 / 0x8003 ===\n");
    DiagnosticPositiveAck pa;
    pa.sourceAddress = 0x0001;
    pa.targetAddress = 0x0E00;
    std::vector<std::uint8_t> paP = encodePayload (pa);
    check (paP.size () == 5, "0x8002 载荷 5 字节");
    check (paP[4] == 0x00, "正应答码是 0x00");
    paP.pop_back ();
    DiagnosticPositiveAck pa2;
    check (!decodePayload (paP, pa2, err), "0x8002 只有 4 字节 → 拒绝");

    DiagnosticNegativeAck na;
    na.sourceAddress = 0x0001;
    na.targetAddress = 0x0E00;
    na.nackCode      = 0x04;                     // 「目标不可达」这一类
    na.previous      = {0x22, 0xF1, 0x90};
    std::vector<std::uint8_t> naP = encodePayload (na);
    check (naP.size () == 8, "0x8003 带 3 字节原报文 → 5 + 3 = 8 字节");
    DiagnosticNegativeAck na2;
    check (decodePayload (naP, na2, err), "0x8003 载荷能解码");
    check (na2.nackCode == 0x04 && na2.previous.size () == 3, "NACK 码 / 带回的原报文都对");
    naP.resize (4);
    check (!decodePayload (naP, na2, err), "0x8003 只有 4 字节 → 拒绝");

    // -----------------------------------------------------------------------
    std::printf ("\n=== K 名字表：出问题时能打印人话 ===\n");
    check (std::string (nameOf (PayloadType::DiagnosticMessage)).find ("0x8001") != std::string::npos,
           "0x8001 有名字");
    check (isKnown (0x8001) && isKnown (0x0000), "0x8001 / 0x0000 都在已知表里");
    check (!isKnown (0x1234), "0x1234 不在已知表里");
    check (std::string (nameOf (ParseError::NeedMoreData)).find ("半包") != std::string::npos,
           "NeedMoreData 说人话：半包");
    check (std::string (nameOf (GenericNack::MessageTooLarge)).find ("too large") != std::string::npos,
           "NACK 0x02 说人话");

    // -----------------------------------------------------------------------
    std::printf ("\n--------------------------------\n");
    std::printf ("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0)
    {
        std::printf ("M0 全绿 —— 现在你手里有一把能读懂 DoIP 抓包的尺子。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
