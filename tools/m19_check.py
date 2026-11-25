#!/usr/bin/env python3
# ============================================================================
# m19_check.py —— M19 的"刷之前先验收条件"场景：0x22 读身份、0x2E 写指纹、0x31 01 0203 检查
#
# 两条腿跑同一个脚本，靠电压参数区分：
#   腿一（12400 mV）：身份读得出来、指纹写得进去、前置检查 00、0x34 放行；
#   腿二（11000 mV）：电压读出来就是 11000、前置检查 01、0x34 直接 7F 34 22。
#
# 考点（这些"错"长得像，但协议上不是一回事）：
#   ① 读不认识的 DID            → 7F 22 31（找错对象）
#   ② 写只读 DID / 写错长度     → 7F 2E 31 / 7F 2E 13
#   ③ 默认会话写指纹            → 7F 2E 7F（会话不对）
#   ④ 编程会话没解锁就写        → 7F 2E 33（钥匙没插）
#   ⑤ 前置条件不满足            → 71 01 02 03 01（**正响应**：请求合法，答案是"不能"）
#   ⑥ 电压不够还发 0x34         → 7F 34 22（条件不满足，不是请求错）
#
# 用法：python3 m19_check.py <port> <battery_mv>
# ============================================================================
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
BATT = int(sys.argv[2]) if len(sys.argv) > 2 else 12400
MIN_BATT = 11500
LOW = BATT < MIN_BATT
SA = 0x0E00
TA = 0x0003
FAIL = 0

PART = "PART-ABC1234"
SWV  = "SW-1.0.3"
SER  = "ECU-A-0007"


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
    def __init__(self, sa=SA):
        self.sa = sa
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=3.0)
        self.s.settimeout(3.0)

    def activate(self):
        self.s.sendall(msg(0x0005, struct.pack("!H", self.sa) + b"\x00" + b"\x00" * 8))
        r = parse(self.s.recv(4096))
        return r[1][4] if (r is not None and r[0] == 0x0006) else None

    def uds(self, req, timeout=3.0):
        self.s.settimeout(timeout)
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, TA) + req))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = parse(self.s.recv(8192))
            except socket.timeout:
                return None
            if r is None:
                return None
            if r[0] == 0x8002:
                continue
            if r[0] == 0x0007:
                self.s.sendall(msg(0x0008, struct.pack("!H", self.sa) + b"\x00\x00"))
                continue
            if r[0] == 0x8001:
                return r[1][4:]
            if r[0] == 0x8003:
                return None
        return None

    def close(self):
        self.s.close()


def nrc(resp, sid):
    if resp is None or len(resp) < 3 or resp[0] != 0x7F or resp[1] != sid:
        return -1
    return resp[2]


def hexs(b):
    return b.hex().upper() if b else "NONE"


def key_of(seed):
    return ((seed + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF


def unlock(t):
    r = t.uds(bytes([0x10, 0x02]))
    if r is None or r[:2] != bytes([0x50, 0x02]):
        return False
    r = t.uds(bytes([0x27, 0x01]))
    if r is None or len(r) != 6:
        return False
    seed = struct.unpack("!I", r[2:6])[0]
    r = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", key_of(seed)))
    return r == bytes([0x67, 0x02])


def check_status(resp):
    """0x31 01 0203 的状态码：00 可刷 / 01 不可刷 / -1 不是这个回答"""
    if resp is None or len(resp) != 5 or resp[:4] != bytes([0x71, 0x01, 0x02, 0x03]):
        return -1
    return resp[4]


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# ---------------------------------------------------------------------------
# A. 身份：刷之前先确认"这台是谁、装的是什么、电够不够"
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x22, 0xF1, 0x90]))
check(r is not None and r[:3] == bytes([0x62, 0xF1, 0x90]) and r[3:].decode(errors="replace") == "LSVZZ0000B7654321",
      "VIN", r[3:].decode(errors="replace") if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0x87]))
check(r is not None and r[:3] == bytes([0x62, 0xF1, 0x87]) and r[3:].decode(errors="replace") == PART,
      "PART_NO", r[3:].decode(errors="replace") if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0x88]))
check(r is not None and r[:3] == bytes([0x62, 0xF1, 0x88]) and r[3:].decode(errors="replace") == SWV,
      "SW_VERSION", r[3:].decode(errors="replace") if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0x8C]))
check(r is not None and r[:3] == bytes([0x62, 0xF1, 0x8C]) and r[3:].decode(errors="replace") == SER,
      "SERIAL", r[3:].decode(errors="replace") if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0xA5]))
check(r == bytes([0x62, 0xF1, 0xA5]) + struct.pack("!H", BATT), "BATTERY", hexs(r[3:]) if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0x84]))
check(r == bytes([0x62, 0xF1, 0x84, 0, 0, 0, 0]), "FINGERPRINT_INIT", hexs(r) if r else "NONE")

r = t.uds(bytes([0x22, 0xF1, 0xA4]))
check(nrc(r, 0x22) == 0x31, "NRC_UNKNOWN_DID", "%02X" % (nrc(r, 0x22) & 0xFF))

# ---------------------------------------------------------------------------
# B. 0x2E 的三道拦：会话 / 解锁 / 数据本身
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x2E, 0xF1, 0x84, 0xA1, 0xB2, 0xC3, 0xD4]))
check(nrc(r, 0x2E) == 0x7F, "NRC_2E_DEFAULT", "%02X" % (nrc(r, 0x2E) & 0xFF))

# 默认会话问"能不能刷"：请求合法，答案是"不能"（状态 01）
r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
check(check_status(r) == 0x01, "PRECHECK_DEFAULT", hexs(r) if r else "NONE")

r = t.uds(bytes([0x10, 0x02]))
check(r is not None and r[:2] == bytes([0x50, 0x02]), "SESSION_PROG", hexs(r) if r else "NONE")

r = t.uds(bytes([0x2E, 0xF1, 0x84, 0xA1, 0xB2, 0xC3, 0xD4]))
check(nrc(r, 0x2E) == 0x33, "NRC_2E_LOCKED", "%02X" % (nrc(r, 0x2E) & 0xFF))

r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
check(check_status(r) == 0x01, "PRECHECK_LOCKED", hexs(r) if r else "NONE")

ok = unlock(t)
check(ok, "UNLOCK", "OK" if ok else "FAIL")

r = t.uds(bytes([0x2E, 0xF1, 0x84, 0xA1, 0xB2, 0xC3]))
check(nrc(r, 0x2E) == 0x13, "NRC_2E_LEN", "%02X" % (nrc(r, 0x2E) & 0xFF))

r = t.uds(bytes([0x2E, 0xF1, 0x87, 0x41, 0x42, 0x43, 0x44]))
check(nrc(r, 0x2E) == 0x31, "NRC_2E_READONLY", "%02X" % (nrc(r, 0x2E) & 0xFF))

# ---------------------------------------------------------------------------
# C. 前置条件：解锁之后、电压正常 → 00（腿二这里必须是 01）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
st = check_status(r)
if LOW:
    check(st == 0x01, "PRECHECK_LOW", hexs(r) if r else "NONE")
else:
    check(st == 0x00, "PRECHECK_OK", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# D. 写指纹：成功后 0x22 读回同一个值（跨请求保存，不是回显）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x2E, 0xF1, 0x84, 0xA1, 0xB2, 0xC3, 0xD4]))
check(r == bytes([0x6E, 0xF1, 0x84]), "WRITE_FP", hexs(r) if r else "NONE")
r = t.uds(bytes([0x22, 0xF1, 0x84]))
check(r == bytes([0x62, 0xF1, 0x84, 0xA1, 0xB2, 0xC3, 0xD4]), "FP_READBACK", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# E. 0x34：电压够就放行，不够就 0x22（而且不能把下载状态弄脏）
# ---------------------------------------------------------------------------
IMG = bytes([(i * 29 + 5) & 0xFF for i in range(8)])

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE", hexs(r) if r else "NONE")

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
if LOW:
    check(nrc(r, 0x34) == 0x22, "NRC_34_LOW_VOLT", hexs(r) if r else "NONE")
    # 被拒之后还没进入下载：再问一次前置条件，仍然是"不在下载中"，只是电压不过
    r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
    check(check_status(r) == 0x01, "PRECHECK_AFTER_DENY", hexs(r) if r else "NONE")
else:
    check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r) if r else "NONE")
    # 正在下载时问"能不能刷" → 01（四条里"不在下载中"这条不过）
    r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
    check(check_status(r) == 0x01, "PRECHECK_MIDDLE", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x36, 0x01]) + IMG)
    check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r) if r else "NONE")
    r = t.uds(bytes([0x37]))
    check(r is not None and len(r) == 5 and r[0] == 0x77 and
          struct.unpack("!I", r[1:5])[0] == (zlib.crc32(IMG) & 0xFFFFFFFF),
          "EXIT_CRC", "%08X" % (struct.unpack("!I", r[1:5])[0] if (r and len(r) == 5) else 0))

    # 下载收尾之后，前置条件又回到 00（"不在下载中"这条重新成立）
    r = t.uds(bytes([0x31, 0x01, 0x02, 0x03]))
    check(check_status(r) == 0x00, "PRECHECK_AFTER", hexs(r) if r else "NONE")

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
