// ============================================================================
// Sha256.h —— M18：SHA-256（纯逻辑，header-only）
//
// 为什么刷写链路上要再多一层哈希：
//   M15 的 0x37 带 CRC-32，它回答的是"传的过程有没有出错"。
//   CRC 是线性的：改两个字节、再补一个"补偿值"，CRC 一样能对上 —— 它防手滑，不防有人动手。
//   SHA-256 是单向的：改任何一个字节，输出整条都不一样，想要"对得上"就得重新算预映像。
//
// 为什么不自己造一个"看起来像哈希"的东西：
//   哈希函数最怕的不是慢，是"差不多"。自己写的混淆跑得过自己的测试，
//   跑不过官方的已知答案（known-answer test）。所以先用三条标准向量把尺子钉死：
//     sha256("")    = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//     sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
//     sha256(56 字节的 "abcdbcde…") = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
//
// 用法：Sha256::of(bytes) 一次算完；分块用 reset/update/finish（自测里验两者等价）。
// ============================================================================
#ifndef DOIP_SHA256_H
#define DOIP_SHA256_H

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace doip {

class Sha256
{
    public:
        using Digest = std::array<std::uint8_t, 32>;

        Sha256 () { reset (); }

        void reset ()
        {
            static const std::uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                                0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
            std::memcpy (h_, iv, sizeof iv);
            length_ = 0;
            used_   = 0;
            std::memset (buf_, 0, sizeof buf_);
        }

        void update (const void *data, std::size_t n)
        {
            const std::uint8_t *p = static_cast<const std::uint8_t *> (data);
            length_ += n;
            while (n > 0)
            {
                const std::size_t room = 64 - used_;
                const std::size_t take = (n < room) ? n : room;
                std::memcpy (buf_ + used_, p, take);
                used_ += take;
                p     += take;
                n     -= take;
                if (used_ == 64)
                {
                    compress (buf_);
                    used_ = 0;
                }
            }
        }

        void update (const std::vector<std::uint8_t> &v)
        {
            if (!v.empty ()) update (v.data (), v.size ());
        }

        // 收尾：补 0x80 + 长度（大端 64 位），返回 32 字节摘要。调用后内部状态保留，
        // 想再算一份请 reset()（或者直接用 of()）。
        Digest finish ()
        {
            const std::uint64_t bits = length_ * 8u;
            const std::size_t   pad  = (used_ < 56) ? (56 - used_) : (120 - used_);
            static const std::uint8_t one = 0x80;
            update (&one, 1);
            // 补 0：这里不能走 update（会改 length_），直接写缓冲
            std::uint8_t zero = 0;
            for (std::size_t i = 0; i + 1 < pad; ++i) update (&zero, 1);
            std::uint8_t lenBytes[8];
            for (int i = 0; i < 8; ++i)
                lenBytes[i] = static_cast<std::uint8_t> ((bits >> (56 - i * 8)) & 0xFF);
            // 长度字段同样不能计入 length_，所以直接塞进缓冲并压缩
            std::memcpy (buf_ + used_, lenBytes, 8);
            used_ += 8;
            if (used_ == 64)
            {
                compress (buf_);
                used_ = 0;
            }

            Digest d;
            for (int i = 0; i < 8; ++i)
                for (int b = 0; b < 4; ++b)
                    d[i * 4 + b] = static_cast<std::uint8_t> ((h_[i] >> (24 - b * 8)) & 0xFF);
            return d;
        }

        static Digest of (const std::vector<std::uint8_t> &v)
        {
            Sha256 s;
            s.update (v);
            return s.finish ();
        }

        static Digest of (const std::uint8_t *p, std::size_t n)
        {
            Sha256 s;
            s.update (p, n);
            return s.finish ();
        }

        static Digest ofText (const std::string &t)
        {
            return of (reinterpret_cast<const std::uint8_t *> (t.data ()), t.size ());
        }

        static std::string hex (const Digest &d)
        {
            std::string s (64, '0');
            static const char *digits = "0123456789abcdef";
            for (int i = 0; i < 32; ++i)
            {
                s[i * 2]     = digits[(d[i] >> 4) & 0x0F];
                s[i * 2 + 1] = digits[d[i] & 0x0F];
            }
            return s;
        }

    private:
        void compress (const std::uint8_t *p)
        {
            static const std::uint32_t k[64] = {
                0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
                0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
                0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
                0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
                0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
                0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
                0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
                0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
                0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
                0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
                0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

            std::uint32_t w[64];
            for (int i = 0; i < 16; ++i)
                w[i] = (static_cast<std::uint32_t> (p[i * 4]) << 24) |
                       (static_cast<std::uint32_t> (p[i * 4 + 1]) << 16) |
                       (static_cast<std::uint32_t> (p[i * 4 + 2]) << 8) |
                       static_cast<std::uint32_t> (p[i * 4 + 3]);
            for (int i = 16; i < 64; ++i)
            {
                const std::uint32_t s0 = rotr (w[i - 15], 7) ^ rotr (w[i - 15], 18) ^ (w[i - 15] >> 3);
                const std::uint32_t s1 = rotr (w[i - 2], 17) ^ rotr (w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
            std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
            for (int i = 0; i < 64; ++i)
            {
                const std::uint32_t S1 = rotr (e, 6) ^ rotr (e, 11) ^ rotr (e, 25);
                const std::uint32_t ch = (e & f) ^ ((~e) & g);
                const std::uint32_t t1 = h + S1 + ch + k[i] + w[i];
                const std::uint32_t S0 = rotr (a, 2) ^ rotr (a, 13) ^ rotr (a, 22);
                const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                const std::uint32_t t2 = S0 + maj;
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
            h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
            h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
        }

        static std::uint32_t rotr (std::uint32_t v, int n)
        {
            return (v >> n) | (v << (32 - n));
        }

        std::uint32_t h_[8];
        std::uint64_t length_;
        std::size_t   used_;
        std::uint8_t  buf_[64];
};

} // namespace doip

#endif
