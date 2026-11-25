// ============================================================================
// DidTable.h —— M19：这台 ECU "报得出什么"（0x22 读）与"别人能改什么"（0x2E 写）
//
// 为什么刷写之前要先能读这些：
//   诊断仪在刷之前要回答三个问题：这台是不是我要刷的那台（零件号）、
//   现在装的是什么版本（软件版本 / 指纹）、电够不够。前两个靠读 DID，第三个靠电压 DID。
//   没有这些，"刷"就只能靠人肉核对 —— 而人肉核对正是刷错车的起点。
//
// 四个只读 DID + 一个可写 DID（本项目口径）：
//   F187  零件号（ASCII）          只读
//   F188  软件版本（ASCII）        只读
//   F18C  序列号（ASCII）          只读
//   F1A5  电池电压（u16 mV，大端）  只读
//   F184  刷写指纹（u32，4 字节）  **可写**（0x2E，需要编程会话 + 解锁）
//
// 为什么指纹要可写：
//   指纹是"这份程序是谁、什么时候写进去的"，只能在写入之后由 tester 写进去。
//   它必须受门禁保护 —— 否则谁都能改掉"刷写记录"。所以 0x2E 和刷写用同一道门。
//
// 写的时候三个错别混：
//   DID 不存在 / 只读  → 0x31 requestOutOfRange
//   数据长度不对        → 0x13 incorrectMessageLength
//   会话不对 / 没解锁   → 0x7F / 0x33（由 SessionGuard 判，不在这一层）
// ============================================================================
#ifndef DOIP_DID_TABLE_H
#define DOIP_DID_TABLE_H

#include "UdsNrc.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace doip {

class DidTable
{
    public:
        static constexpr std::uint16_t kDidPartNumber   = 0xF187;
        static constexpr std::uint16_t kDidSwVersion    = 0xF188;
        static constexpr std::uint16_t kDidSerial       = 0xF18C;
        static constexpr std::uint16_t kDidBatteryVolt  = 0xF1A5;
        static constexpr std::uint16_t kDidFingerprint  = 0xF184;

        DidTable (std::string partNumber, std::string swVersion, std::string serial,
                  std::uint32_t fingerprint, std::uint32_t batteryMv)
            : partNumber_ (std::move (partNumber)), swVersion_ (std::move (swVersion)),
              serial_ (std::move (serial)), fingerprint_ (fingerprint), batteryMv_ (batteryMv)
        {
        }

        // 读：返回 true = 这个 DID 我认识（resp 已填好 62 DID ...）；false = 不认识
        bool read (std::uint16_t did, std::vector<std::uint8_t> &resp, std::string &why) const
        {
            resp = {0x62, static_cast<std::uint8_t> (did >> 8), static_cast<std::uint8_t> (did & 0xFF)};
            switch (did)
            {
                case kDidPartNumber:
                    appendText (resp, partNumber_);
                    why = "读零件号：" + partNumber_;
                    return true;
                case kDidSwVersion:
                    appendText (resp, swVersion_);
                    why = "读软件版本：" + swVersion_;
                    return true;
                case kDidSerial:
                    appendText (resp, serial_);
                    why = "读序列号：" + serial_;
                    return true;
                case kDidBatteryVolt:
                    resp.push_back (static_cast<std::uint8_t> ((batteryMv_ >> 8) & 0xFF));
                    resp.push_back (static_cast<std::uint8_t> (batteryMv_ & 0xFF));
                    why = "读电池电压：" + std::to_string (batteryMv_) + " mV";
                    return true;
                case kDidFingerprint:
                    for (int i = 3; i >= 0; --i)
                        resp.push_back (static_cast<std::uint8_t> ((fingerprint_ >> (i * 8)) & 0xFF));
                    why = "读刷写指纹：0x" + hex8 (fingerprint_);
                    return true;
                default:
                    return false;
            }
        }

        // 写（0x2E）：返回 true = 这条请求归我管（成功或按 NRC 拒了）
        bool write (std::uint16_t did, const std::vector<std::uint8_t> &payload,
                    std::vector<std::uint8_t> &resp, std::string &why)
        {
            if (did != kDidFingerprint)
            {
                // 只读 DID 也想写：这不是"数据错"，是"你找错对象了"
                resp = {0x7F, 0x2E, kNrcRequestOutOfRange};
                why  = "DID 0x" + hex4 (did) + " 不是可写的（本项目只有 F184 指纹可写）";
                return true;
            }
            if (payload.size () != 4)
            {
                resp = {0x7F, 0x2E, kNrcIncorrectLength};
                why  = "写 F184 要 4 字节，实际 " + std::to_string (payload.size ()) + " 字节";
                return true;
            }
            fingerprint_ = (static_cast<std::uint32_t> (payload[0]) << 24) |
                           (static_cast<std::uint32_t> (payload[1]) << 16) |
                           (static_cast<std::uint32_t> (payload[2]) << 8) |
                           static_cast<std::uint32_t> (payload[3]);
            resp = {0x6E, 0x00, 0x00};   // 先占位，下面按 did 填
            resp[1] = static_cast<std::uint8_t> (did >> 8);
            resp[2] = static_cast<std::uint8_t> (did & 0xFF);
            why = "写 F184 成功，指纹变成 0x" + hex8 (fingerprint_);
            return true;
        }

        std::uint32_t batteryMv () const { return batteryMv_; }
        std::uint32_t fingerprint () const { return fingerprint_; }
        const std::string &partNumber () const { return partNumber_; }
        const std::string &swVersion () const { return swVersion_; }

    private:
        static void appendText (std::vector<std::uint8_t> &out, const std::string &t)
        {
            for (char c : t) out.push_back (static_cast<std::uint8_t> (c));
        }

        static std::string hex8 (std::uint32_t v)
        {
            char buf[16];
            std::snprintf (buf, sizeof buf, "%08X", static_cast<unsigned> (v));
            return std::string (buf);
        }

        static std::string hex4 (std::uint16_t v)
        {
            char buf[8];
            std::snprintf (buf, sizeof buf, "%04X", static_cast<unsigned> (v));
            return std::string (buf);
        }

        std::string   partNumber_;
        std::string   swVersion_;
        std::string   serial_;
        std::uint32_t fingerprint_;
        std::uint32_t batteryMv_;
};

} // namespace doip

#endif
