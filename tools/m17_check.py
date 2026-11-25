#!/usr/bin/env python3
# ============================================================================
# m17_check.py —— M17 的复位场景：0x11 ECUReset × 会话门禁 × 镜像语义
#
# 这一节的考点是"复位把什么带走了、又把什么留下了"：
#   ① 默认会话里 0x11 也允许（它就是"弄乱了以后一键复原"的动作）；
#   ② 刷到一半（0x34 之后、0x37 之前）复位 → 0x22，而且不许把下载搞坏；
#   ③ 软复位（03）：会话/解锁清掉，**镜像留着**；
#   ④ 硬复位（01）：镜像清掉、回到"未擦除"（要重新 0x31 FF00 才能再下载）；
#   ⑤ 子功能错 → 0x12；连子功能都没有 → 0x13。
#
# 用法：python3 m17_check.py <port> [legacy]
# 输出 KEY=VALUE 行，由 m17_e2e.sh 逐条断言。
# ============================================================================
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
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
            if r[0] == 0x8002:      # 诊断报文肯定应答：继续等响应
                continue
            if r[0] == 0x0007:      # 网关心跳：必须回，否则 3 秒后断链
                self.s.sendall(msg(0x0008, struct.pack("!H", self.sa) + b"\x00\x00"))
                continue
            if r[0] == 0x8001:      # 诊断报文本身（响应同类型）
                return r[1][4:]
            if r[0] == 0x8003:      # 否定应答
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
    # 和 SessionGuard::expectedKey 同一行：key = (seed + 0x12345678) ^ 0xA5A5A5A5
    return ((seed + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF


def unlock(t):
    """推到"编程会话 + 已解锁"。返回 True/False，方便断言用。"""
    r = t.uds(bytes([0x10, 0x02]))
    if r is None or r[:2] != bytes([0x50, 0x02]):
        return False, "10"
    r = t.uds(bytes([0x27, 0x01]))
    if r is None or r[:2] != bytes([0x67, 0x01]) or len(r) != 6:
        return False, "seed"
    seed = struct.unpack("!I", r[2:6])[0]
    r = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", key_of(seed)))
    if r is None or r != bytes([0x67, 0x02]):
        return False, "key"
    return True, "ok"


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# 第二条腿（--flash 不带 --secure）：0x11 在老 ECU 上是"不支持"
if len(sys.argv) > 2 and sys.argv[2] == "legacy":
    r = t.uds(bytes([0x11, 0x01]))
    check(nrc(r, 0x11) == 0x31, "LEGACY_11", "%02X" % (nrc(r, 0x11) & 0xFF))
    t.close()
    emit("FAIL", FAIL)
    sys.exit(1 if FAIL else 0)

IMG = bytes([(i * 29 + 5) & 0xFF for i in range(8)])
CRC = zlib.crc32(IMG) & 0xFFFFFFFF

# ---------------------------------------------------------------------------
# A. 默认会话：老服务照旧、刷写仍被门挡；0x11 默认会话里**允许**
# ---------------------------------------------------------------------------
vin = t.uds(bytes([0x22, 0xF1, 0x90]))
vin_s = vin[3:20].decode("ascii", "replace") if (vin is not None and len(vin) >= 20) else ""
check(vin_s == "LSVZZ0000B7654321", "VIN_DEFAULT", vin_s if vin_s else "NONE")

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x7F, "NRC_34_DEFAULT", "%02X" % (nrc(r, 0x34) & 0xFF))

r = t.uds(bytes([0x11]))
check(nrc(r, 0x11) == 0x13, "NRC_11_LEN", "%02X" % (nrc(r, 0x11) & 0xFF))

r = t.uds(bytes([0x11, 0x04]))
check(nrc(r, 0x11) == 0x12, "NRC_11_SUB", "%02X" % (nrc(r, 0x11) & 0xFF))

r = t.uds(bytes([0x11, 0x01]))
check(r == bytes([0x51, 0x01]), "RESET_IN_DEFAULT", hexs(r))

# ---------------------------------------------------------------------------
# B. 推刷写，停在"下载中途"：这时候复位必须被拒（0x22）
# ---------------------------------------------------------------------------
ok, why = unlock(t)
check(ok, "UNLOCK_1", "OK" if ok else why)

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE", hexs(r))

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r))

r = t.uds(bytes([0x36, 0x01]) + IMG)
check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r))

r = t.uds(bytes([0x11, 0x01]))
check(nrc(r, 0x11) == 0x22, "NRC_11_BUSY", "%02X" % (nrc(r, 0x11) & 0xFF))

# 被拒的复位不能把下载搞坏：0x37 照样收得了尾，CRC 也对
r = t.uds(bytes([0x37]))
check(r is not None and r[:1] == bytes([0x77]), "EXIT", hexs(r))
check(r is not None and len(r) == 5 and struct.unpack("!I", r[1:5])[0] == CRC,
      "EXIT_CRC", "%08X" % (struct.unpack("!I", r[1:5])[0] if (r and len(r) == 5) else 0))

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + struct.pack("!I", CRC))
check(r == bytes([0x71, 0x01, 0xFF, 0x01, 0x00]), "VERIFY_OK", hexs(r))

# ---------------------------------------------------------------------------
# C. 软复位（03）：会话与解锁清掉，镜像留着
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x11, 0x03]))
check(r == bytes([0x51, 0x03]), "RESET_SOFT", hexs(r))

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x7F, "NRC_34_AFTER_SOFT", "%02X" % (nrc(r, 0x34) & 0xFF))

r = t.uds(bytes([0x10, 0x02]))
check(r is not None and r[:2] == bytes([0x50, 0x02]), "SESSION_PROG_AGAIN", hexs(r))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x33, "NRC_34_AFTER_SOFT_PROG", "%02X" % (nrc(r, 0x34) & 0xFF))

ok, why = unlock(t)
check(ok, "UNLOCK_2", "OK" if ok else why)

# 软复位没有碰镜像：同一份 CRC 还能校验通过
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + struct.pack("!I", CRC))
check(r == bytes([0x71, 0x01, 0xFF, 0x01, 0x00]), "IMAGE_AFTER_SOFT", hexs(r))

# ---------------------------------------------------------------------------
# D. 硬复位（01）：镜像清掉、回到"未擦除"
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x11, 0x01]))
check(r == bytes([0x51, 0x01]), "RESET_HARD", hexs(r))

ok, why = unlock(t)
check(ok, "UNLOCK_3", "OK" if ok else why)

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x01]) + struct.pack("!I", CRC))
check(nrc(r, 0x31) == 0x22, "IMAGE_AFTER_HARD", "%02X" % (nrc(r, 0x31) & 0xFF))

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(nrc(r, 0x34) == 0x22, "NRC_34_AFTER_HARD", "%02X" % (nrc(r, 0x34) & 0xFF))

# ---------------------------------------------------------------------------
# E. 点火循环（02）：回 51 02（本实现等效硬复位，界面上只是名字不同）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x11, 0x02]))
check(r == bytes([0x51, 0x02]), "RESET_KEYOFF", hexs(r))

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
