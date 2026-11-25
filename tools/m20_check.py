#!/usr/bin/env python3
# ============================================================================
# m20_check.py —— M20 的"包与车对不对得上"场景：0x31 01 0204 + 0x34 凭证
#
# 两条腿：
#   腿一（车 SW-1.0.3，不许降级）：零件号错 → 01、降级 1.0.2 → 01、同版本 → 00、
#        升级 1.10.0 → 00（字符串比较会把 1.10.0 判成比 1.0.3 小？不会；真正的陷阱在腿二）、
#        长度错 13、版本号格式错 31；
#        凭证：没检查就 0x34 → 22、检查过再用 → 74、擦除后凭证作废 → 22、收尾后作废 → 22。
#   腿二（车 SW-1.9.0，allowDowngrade 开）：目标 1.10.0 → 00（**数值比较**：字符串会说 1.10.0 < 1.9.0）、
#        目标 1.8.0 → 00（放行降级，日志写明）。
#
# 用法：python3 m20_check.py <port> <leg>     leg = 1 | 2
# ============================================================================
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1
SA = 0x0E00
TA = 0x0003
FAIL = 0

PART = "PART-ABC1234"
IMG = bytes([(i * 29 + 5) & 0xFF for i in range(8)])


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


def compat(t, part, sw):
    """0x31 01 0204：零件号 12 字节 + 版本 8 字节"""
    return t.uds(bytes([0x31, 0x01, 0x02, 0x04]) + part.encode().ljust(12, b" ") + sw.encode())


def status(resp):
    if resp is None or len(resp) != 5 or resp[:4] != bytes([0x71, 0x01, 0x02, 0x04]):
        return -1
    return resp[4]


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# 车自己报的身份
cur = t.uds(bytes([0x22, 0xF1, 0x87]))
cur_sw = t.uds(bytes([0x22, 0xF1, 0x88]))
check(cur is not None and cur[3:].decode(errors="replace").strip() == PART,
      "CAR_PART", cur[3:].decode(errors="replace") if cur else "NONE")
car_sw = cur_sw[3:].decode(errors="replace").strip() if cur_sw else "NONE"
check(car_sw == ("SW-1.9.0" if LEG == 2 else "SW-1.0.3"), "CAR_SW", car_sw)

ok = unlock(t)
check(ok, "UNLOCK", "OK" if ok else "FAIL")

# ---------------------------------------------------------------------------
# A. 没做兼容性检查就想下载：凭证不存在 → 0x22
# ---------------------------------------------------------------------------
batt = t.uds(bytes([0x22, 0xF1, 0xA5]))
check(batt is not None and len(batt) == 5, "BATTERY", hexs(batt[3:]) if batt else "NONE")

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_1", hexs(r) if r else "NONE")

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_NO_CREDENTIAL", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# B. 结构错：长度不对 / 版本号不是三段 → NRC
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0x02, 0x04]) + PART.encode()[:11])
check(nrc(r, 0x31) == 0x13, "NRC_LEN", hexs(r) if r else "NONE")

r = compat(t, PART, "SW-latest")
check(nrc(r, 0x31) == 0x31, "NRC_BAD_VERSION", hexs(r) if r else "NONE")

# 结构错之后不能残留凭证：直接 0x34 仍然是 22
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_AFTER_BAD", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# C. 内容不符：零件号 / 版本
# ---------------------------------------------------------------------------
r = compat(t, "PART-XYZ9999", car_sw)
check(status(r) == 0x01, "PART_MISMATCH", hexs(r) if r else "NONE")

if LEG == 1:
    r = compat(t, PART, "SW-1.0.2")
    check(status(r) == 0x01, "DOWNGRADE", hexs(r) if r else "NONE")

    r = compat(t, PART, "SW-1.0.3")
    check(status(r) == 0x00, "SAME_VERSION", hexs(r) if r else "NONE")
else:
    # 数值比较的陷阱：字符串会说 1.10.0 < 1.9.0
    check("1.10.0" < "1.9.0", "STRING_TRAP", "1" if "1.10.0" < "1.9.0" else "0")
    r = compat(t, PART, "SW-1.10.0")
    check(status(r) == 0x00, "UPGRADE_110", hexs(r) if r else "NONE")

    r = compat(t, PART, "SW-1.8.0")
    check(status(r) == 0x00, "DOWNGRADE_ALLOWED", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# D. 凭证一次一用：通过 → 0x34 拿走 → 再用一次就 22
# ---------------------------------------------------------------------------
r = compat(t, PART, "SW-1.10.0" if LEG == 2 else "SW-1.0.4")
check(status(r) == 0x00, "COMPAT_OK", hexs(r) if r else "NONE")

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r) if r else "NONE")

r = t.uds(bytes([0x36, 0x01]) + IMG)
check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r) if r else "NONE")
r = t.uds(bytes([0x37]))
check(r is not None and len(r) == 5 and r[0] == 0x77 and
      struct.unpack("!I", r[1:5])[0] == (zlib.crc32(IMG) & 0xFFFFFFFF),
      "EXIT_CRC", "%08X" % (struct.unpack("!I", r[1:5])[0] if (r and len(r) == 5) else 0))

# 收尾后凭证作废：再发 0x34（先擦除一次，让状态机允许）→ 22，原因是"没有凭证"
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_2", hexs(r) if r else "NONE")
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_AFTER_EXIT", hexs(r) if r else "NONE")

# ---------------------------------------------------------------------------
# E. 擦除也作废凭证：检查 → 擦除 → 0x34 就应该 22
# ---------------------------------------------------------------------------
r = compat(t, PART, "SW-1.10.0" if LEG == 2 else "SW-1.0.4")
check(status(r) == 0x00, "COMPAT_OK_2", hexs(r) if r else "NONE")
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_CLEARS", hexs(r) if r else "NONE")
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_AFTER_ERASE", hexs(r) if r else "NONE")

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
