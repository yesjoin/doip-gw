#!/usr/bin/env python3
# ============================================================================
# m22_check.py —— M22 的场景：钥匙表（读表 / 装钥匙 / 退役 / 吊销）
#
# 两条腿：
#   腿一（默认表 1/2 号启用，刷写 + 门禁开着）：
#        · 0x22 F1B0 读表：默认两把启用；
#        · 0206 装 3 号（demo 材料）→ 00；同 id 再装 → 01（不许覆盖）；33 字节 → 13；keyId 0 → 01；
#        · 0207 3 号退役 → 00、切回启用 → 00；状态 03 → 31；表里没有的 id → 01；
#        · 把 1 号退役 → 用 1 号签的 v1 包**照验**（00），日志记"退役钥匙"；
#        · 把 1 号吊销 → 同一份包立刻被拒（7F 31 31）；再想复活 → 01（终态）；
#        · 3 号签的 v2 包 → 00；0205 用 3 号预检 → 00 → 0x34 放行；
#        · 硬复位后：装钥匙被门挡（7F 31 7F），但**读表**照样能读（默认会话也能问）。
#   腿二（启动就 --revoke-key 1）：表里 1 号是吊销态；1 号签的包直接拒，2 号签的包照验。
#
# 用法：python3 m22_check.py <port> <leg>     leg = 1 | 2
# ============================================================================
import hashlib
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


# ---- 材料与清单（和 C++ 侧同一份公式，用 hashlib 独立算）----
def demo_key(key_id):
    return hashlib.sha256(("doip-gw demo key %d" % key_id).encode()).digest()


def fixed(text, n):
    b = text.encode()
    return (b + b" " * n)[:n]


def manifest_v1(image, key_id):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x01, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id)
    return body + hashlib.sha256(body + key).digest()


def manifest_v2(image, key_id, part, sw):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x02, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id) \
           + fixed(part, 12) + fixed(sw, 16)
    return body + hashlib.sha256(body + key).digest()


# ---- 服务 ----
def read_table(t):
    """0x22 F1B0 → 按 id 排好的 "0001=00,0002=01"；读不到返回 NONE"""
    r = t.uds(bytes([0x22, 0xF1, 0xB0]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB0]):
        return "NONE"
    rows = r[3:]
    out = []
    for i in range(0, len(rows) - 2, 3):
        out.append(((rows[i] << 8) | rows[i + 1], rows[i + 2]))
    return ",".join("%04X=%02X" % (k, v) for k, v in sorted(out))


def install(t, key_id, key):
    """0x31 01 02 06 + <id u16><32 字节材料>"""
    return t.uds(bytes([0x31, 0x01, 0x02, 0x06]) + struct.pack("!H", key_id) + key)


def set_state(t, key_id, want):
    """0x31 01 02 07 + <id u16><目标状态>"""
    return t.uds(bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want]))


def precheck(t, manifest):
    return t.uds(bytes([0x31, 0x01, 0x02, 0x05]) + manifest)


def verify_pkg(t, manifest):
    return t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest)


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

cur = t.uds(bytes([0x22, 0xF1, 0x87]))
cur_sw = t.uds(bytes([0x22, 0xF1, 0x88]))
car_part = cur[3:].decode(errors="replace").strip() if cur else "NONE"
car_sw = cur_sw[3:].decode(errors="replace").strip() if cur_sw else "NONE"
check(car_part == "PART-ABC1234", "CAR_PART", car_part)
check(car_sw == "SW-1.0.3", "CAR_SW", car_sw)

if LEG == 1:
    tbl = read_table(t)
    check(tbl == "0001=00,0002=00", "TABLE_BOOT", tbl)

    ok = unlock(t)
    check(ok, "UNLOCK", "OK" if ok else "FAIL")

    # -----------------------------------------------------------------------
    # A. 装钥匙：00 装上 / 01 不许覆盖 / 13 长度错 / 01 keyId 0
    # -----------------------------------------------------------------------
    r = install(t, 0x0003, demo_key(3))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x00]), "INSTALL_3", hexs(r) if r else "NONE")
    check(read_table(t) == "0001=00,0002=00,0003=00", "TABLE_AFTER_INSTALL", read_table(t))

    r = install(t, 0x0003, demo_key(4))          # 同 id、不同材料
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x01]), "INSTALL_DUP", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x31, 0x01, 0x02, 0x06]) + struct.pack("!H", 0x0003) + demo_key(3)[:31])
    check(nrc(r, 0x31) == 0x13, "NRC_INSTALL_LEN", hexs(r) if r else "NONE")

    r = install(t, 0x0000, demo_key(5))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x01]), "INSTALL_ZERO_ID", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # B. 改状态：退役 ⇄ 启用 / 状态 03 → 31 / 不存在的 id → 01
    # -----------------------------------------------------------------------
    r = set_state(t, 0x0003, 0x01)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "RETIRE_3", hexs(r) if r else "NONE")
    check(read_table(t) == "0001=00,0002=00,0003=01", "TABLE_RETIRED_3", read_table(t))

    r = set_state(t, 0x0003, 0x00)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "REVIVE_3", hexs(r) if r else "NONE")
    check(read_table(t) == "0001=00,0002=00,0003=00", "TABLE_REVIVED_3", read_table(t))

    r = set_state(t, 0x0003, 0x03)
    check(nrc(r, 0x31) == 0x31, "STATE_BAD", hexs(r) if r else "NONE")

    r = set_state(t, 0x0009, 0x00)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x01]), "STATE_MISSING", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # C. 退役钥匙签的包照验；吊销之后立刻被拒；吊销是终态
    # -----------------------------------------------------------------------
    r = set_state(t, 0x0001, 0x01)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "RETIRE_1", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
    check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_1", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 3, car_part, "SW-1.0.4"))
    check(r == bytes([0x71, 0x01, 0x02, 0x05, 0x00]), "PRECHECK_3", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
    check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x36, 0x01]) + IMG)
    check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x37]))
    crc = struct.unpack("!I", r[1:5])[0] if (r is not None and len(r) == 5) else 0
    check(crc == (zlib.crc32(IMG) & 0xFFFFFFFF), "EXIT_CRC", "%08X" % crc)

    r = verify_pkg(t, manifest_v1(IMG, 1))
    check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x00]), "VERIFY_RETIRED_KEY",
          hexs(r) if r else "NONE")

    r = set_state(t, 0x0001, 0x02)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "REVOKE_1", hexs(r) if r else "NONE")

    r = verify_pkg(t, manifest_v1(IMG, 1))
    check(nrc(r, 0x31) == 0x31, "VERIFY_REVOKED_KEY", hexs(r) if r else "NONE")

    r = set_state(t, 0x0001, 0x00)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x01]), "REVIVE_REVOKED", hexs(r) if r else "NONE")

    r = verify_pkg(t, manifest_v2(IMG, 3, car_part, "SW-1.0.4"))
    check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x00]), "VERIFY_NEW_KEY", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # D. 复位后：装钥匙被门挡（默认会话），读表照样能读
    # -----------------------------------------------------------------------
    r = t.uds(bytes([0x11, 0x01]))
    check(r == bytes([0x51, 0x01]), "RESET_HARD", hexs(r) if r else "NONE")

    r = install(t, 0x0004, demo_key(4))
    check(nrc(r, 0x31) == 0x7F, "INSTALL_GATE", hexs(r) if r else "NONE")

    tbl = read_table(t)
    check(tbl == "0001=02,0002=00,0003=00", "TABLE_AFTER_RESET", tbl)

    ok = unlock(t)
    check(ok, "UNLOCK_2", "OK" if ok else "FAIL")

    r = install(t, 0x0004, demo_key(4))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x00]), "INSTALL_AFTER_UNLOCK",
          hexs(r) if r else "NONE")

else:
    # -----------------------------------------------------------------------
    # 腿二：启动就吊销 1 号
    # -----------------------------------------------------------------------
    tbl = read_table(t)
    check(tbl == "0001=02,0002=00", "TABLE_BOOT_REVOKED", tbl)

    ok = unlock(t)
    check(ok, "UNLOCK", "OK" if ok else "FAIL")

    # 预检不看镜像，所以吊销对它的影响能直接看出来（不用先推镜像）
    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.0.4"))
    check(nrc(r, 0x31) == 0x31, "PRECHECK_BOOT_REVOKED", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 2, car_part, "SW-1.0.4"))
    check(r == bytes([0x71, 0x01, 0x02, 0x05, 0x00]), "PRECHECK_BOOT_OK", hexs(r) if r else "NONE")

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
