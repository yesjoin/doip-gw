#!/usr/bin/env python3
# ============================================================================
# m15_check.py —— M15 的裸 socket 场景：把一条真实的刷写链路从头跑到尾
#
# 为什么还是裸 socket：这条链路要故意发错（跳号、重发、块超长、没传完就收尾），
# 第三方诊断库会替你把这些"错误用法"修正掉，恰好验不到被测端的判断。
#
# 用法：python3 m15_check.py <port> [期望通告块长]
# 输出 KEY=VALUE 行，由 m15_e2e.sh 逐条断言；内部自查失败时最后打 FAIL=1。
#
# 链路：TCP 13474 → 网关 → CAN（7A0/7A8）→ stub-ecu --flash
# ============================================================================
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
BLOCK = int(sys.argv[2]) if len(sys.argv) > 2 else 34
SA = 0x0E00
TA = 0x0003

FAIL = 0


def emit(key, value):
    print("%s=%s" % (key, value))


def check(cond, key, value):
    global FAIL
    emit(key, value)
    if not cond:
        FAIL += 1


def msg(ptype, payload=b""):
    return bytes([0x02, 0xFD]) + struct.pack("!H", ptype) + struct.pack("!I", len(payload)) + payload


def parse(data):
    if data is None or len(data) < 8:
        return None
    ptype = struct.unpack("!H", data[2:4])[0]
    plen = struct.unpack("!I", data[4:8])[0]
    return ptype, data[8:8 + plen]


class Tester:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=3.0)
        self.s.settimeout(3.0)

    def activate(self):
        self.s.sendall(msg(0x0005, struct.pack("!H", SA) + b"\x00" + b"\x00" * 8))
        r = parse(self.s.recv(4096))
        if r is None or r[0] != 0x0006:
            return None
        return r[1][4]     # 0x0006 的成功码在 payload[4]（M14 的坑，这里直接用对的位）

    def uds(self, req, timeout=3.0):
        self.s.settimeout(timeout)
        self.s.sendall(msg(0x8001, struct.pack("!HH", SA, TA) + req))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = parse(self.s.recv(8192))
            except socket.timeout:
                return None
            if r is None:
                return None
            if r[0] == 0x8002:      # 诊断报文肯定应答：继续等真正的响应
                continue
            if r[0] == 0x0007:      # 网关的心跳检查：必须回 0x0008，否则 3 秒后它主动断链
                self.s.sendall(msg(0x0008, struct.pack("!H", SA) + b"\x00\x00"))
                continue
            # 0x8001 是"诊断报文"本身，请求和响应都用这个类型；
            # 0x8003 是"诊断报文否定应答"（带一个错误码），别把它当成响应体。
            if r[0] == 0x8001:
                return r[1][4:]
            if r[0] == 0x8003:
                return None
        return None

    def close(self):
        self.s.close()


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# 镜像：100 字节，内容必须"不像"顺序表（顺序表下 CRC 错了也看不出来）
IMG = bytes([(i * 37 + 11) & 0xFF for i in range(100)])

def nrc(resp, sid):
    """否定响应判定 → 返回码，否则 -1"""
    if resp is None or len(resp) < 3 or resp[0] != 0x7F or resp[1] != sid:
        return -1
    return resp[2]

def crc_bytes(v):
    return struct.pack("!I", v & 0xFFFFFFFF)

def addrsize(addr, size):
    return struct.pack("!II", addr, size)

# ---------------------------------------------------------------------------
# A. 刷写模式不能砸掉老服务：读 VIN 还是原来那条（M6 的能力没退化）
# ---------------------------------------------------------------------------
vin = t.uds(bytes([0x22, 0xF1, 0x90]))   # VIN 的 DID 是 F190（F186 是别的东西）
vin_s = ""
if vin is not None and len(vin) >= 20:
    vin_s = vin[3:20].decode("ascii", "replace")
check(vin_s == "LSVZZ0000B7654321", "VIN_STILL_WORKS", vin_s if vin_s else "NONE")

# ---------------------------------------------------------------------------
# B. 顺序错误：没协商就传 / 没协商就收尾（0x24，不是 0x22 也不是 0x31）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x36, 0x01, 0xAA]))
check(nrc(r, 0x36) == 0x24, "NRC_36_NO_34", "%02X" % (nrc(r, 0x36) & 0xFF))
r = t.uds(bytes([0x37]))
check(nrc(r, 0x37) == 0x24, "NRC_37_NO_34", "%02X" % (nrc(r, 0x37) & 0xFF))

# ---------------------------------------------------------------------------
# C. 没擦除就下载 → 0x22；没镜像就校验 → 0x22
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x34, 0x00, 0x44]) + addrsize(0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_34_NOT_ERASED", "%02X" % (nrc(r, 0x34) & 0xFF))
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + crc_bytes(zlib.crc32(IMG)))
check(nrc(r, 0x31) == 0x22, "NRC_VERIFY_EMPTY", "%02X" % (nrc(r, 0x31) & 0xFF))

# ---------------------------------------------------------------------------
# D. 擦除：71 01 FF 00（正响应就是回显例程 + 状态字节）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r is not None and r[:4] == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE",
      r.hex().upper() if r else "NONE")

# ---------------------------------------------------------------------------
# E. 0x34 的参数检查：dfi≠0 → 0x31；alfid=0 → 0x31；长度段缺字节 → 0x13
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x34, 0x01, 0x44]) + addrsize(0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x31, "NRC_34_DFI", "%02X" % (nrc(r, 0x34) & 0xFF))
r = t.uds(bytes([0x34, 0x00, 0x00]) + addrsize(0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x31, "NRC_34_ALFID0", "%02X" % (nrc(r, 0x34) & 0xFF))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!I", 0x00400000) + b"\x00\x00\x00")
check(nrc(r, 0x34) == 0x13, "NRC_34_LEN", "%02X" % (nrc(r, 0x34) & 0xFF))

# ---------------------------------------------------------------------------
# F. 正常协商：74 20 00 22（lengthFormatIdentifier=0x20，块长 34 大端）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x34, 0x00, 0x44]) + addrsize(0x00400000, len(IMG)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD_ACK",
      r.hex().upper() if r else "NONE")
blk = struct.unpack("!H", r[2:4])[0] if (r is not None and len(r) >= 4) else 0
check(blk == BLOCK, "MAX_BLOCK_LENGTH", "%02X" % (blk & 0xFF))

# ---------------------------------------------------------------------------
# G. 跳号：BSC 期望 0x01，发 0x05 → 0x73
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x36, 0x05]) + b"\xCC" * 8)
check(nrc(r, 0x36) == 0x73, "NRC_36_WRONG_BSC", "%02X" % (nrc(r, 0x36) & 0xFF))

# ---------------------------------------------------------------------------
# H. 第一块 + 原样重发：两次都 76 01，且镜像里没有写两遍（用最后的 CRC 判）
#    —— 这就是"链路丢了一次应答、客户端重发"的真实场景
# ---------------------------------------------------------------------------
PER = BLOCK - 2
blocks = [IMG[i:i + PER] for i in range(0, len(IMG), PER)]
b1 = bytes([0x36, 0x01]) + blocks[0]
r = t.uds(b1)
check(r is not None and r[:2] == bytes([0x76, 0x01]), "BLOCK_1", r.hex().upper() if r else "NONE")
r = t.uds(b1)
check(r is not None and r[:2] == bytes([0x76, 0x01]), "BLOCK_1_RETRY", r.hex().upper() if r else "NONE")

# ---------------------------------------------------------------------------
# I. 块超长：数据 33 字节 → 35 > 通告 34 → 0x13（且不该把这块吃下去）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x36, 0x02]) + b"\xDD" * (PER + 1))
check(nrc(r, 0x36) == 0x13, "NRC_36_TOO_LONG", "%02X" % (nrc(r, 0x36) & 0xFF))

# ---------------------------------------------------------------------------
# J. 剩下的块按序发；中途先试一次"没传完就收尾" → 0x24
# ---------------------------------------------------------------------------
ok = True
for idx in range(1, len(blocks)):
    bsc = idx + 1                # 100 字节 = 4 块，走不到 0xFF→0x00 的回绕（回绕在自测里验）
    r = t.uds(bytes([0x36, bsc]) + blocks[idx])
    if r is None or r[:2] != bytes([0x76, bsc]):
        ok = False
    if idx == 1:
        r37 = t.uds(bytes([0x37]))
        check(nrc(r37, 0x37) == 0x24, "NRC_37_PREMATURE", "%02X" % (nrc(r37, 0x37) & 0xFF))
check(ok, "BLOCK_SEQUENCE", "1" if ok else "0")

# ---------------------------------------------------------------------------
# K. 收尾：0x77 + 4 字节 CRC-32，必须等于 tester 自己算的那一个
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x37]))
crc_ecu = struct.unpack("!I", r[1:5])[0] if (r is not None and len(r) >= 5 and r[0] == 0x77) else 0
check(r is not None and r[0] == 0x77, "TRANSFER_EXIT", r.hex().upper() if r else "NONE")
check(crc_ecu == zlib.crc32(IMG), "EXIT_CRC", "%08X" % crc_ecu)
check(r is not None and len(r) == 5, "EXIT_CRC_LEN", "%d" % (len(r) if r else 0))

# ---------------------------------------------------------------------------
# L. 收尾之后再传 → 0x24（会话已经关了，要重来先 0x34）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x36, 0x05]) + b"\xEE" * 4)
check(nrc(r, 0x36) == 0x24, "NRC_36_AFTER_EXIT", "%02X" % (nrc(r, 0x36) & 0xFF))

# ---------------------------------------------------------------------------
# M. 完整性校验：错 CRC 回 71 01 FF 01 01，对 CRC 回 ...00
#    注意"错"的那个仍然要求是正响应带状态字节——校验失败不是否定响应
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + crc_bytes(zlib.crc32(IMG) ^ 0x00000001))
check(r is not None and r[0] == 0x71 and len(r) >= 5 and r[4] == 0x01, "VERIFY_BAD",
      r.hex().upper() if r else "NONE")
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + crc_bytes(zlib.crc32(IMG)))
check(r is not None and r[0] == 0x71 and len(r) >= 5 and r[4] == 0x00, "VERIFY_OK",
      r.hex().upper() if r else "NONE")
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + b"\x00\x00")
check(nrc(r, 0x31) == 0x13, "NRC_VERIFY_LEN", "%02X" % (nrc(r, 0x31) & 0xFF))

# ---------------------------------------------------------------------------
# N. 再刷一遍：擦除能把状态清干净，短镜像照样能跑完（"现场重来"）
# ---------------------------------------------------------------------------
t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
IMG2 = bytes([(i * 13 + 7) & 0xFF for i in range(8)])
r = t.uds(bytes([0x34, 0x00, 0x44]) + addrsize(0x00400000, len(IMG2)))
r = t.uds(bytes([0x36, 0x01]) + IMG2)
check(r is not None and r[:2] == bytes([0x76, 0x01]), "REF_36", r.hex().upper() if r else "NONE")
r = t.uds(bytes([0x37]))
check(r is not None and len(r) == 5 and struct.unpack("!I", r[1:5])[0] == zlib.crc32(IMG2),
      "REF_CRC", r.hex().upper() if r else "NONE")

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
