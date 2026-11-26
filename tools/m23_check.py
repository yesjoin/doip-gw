#!/usr/bin/env python3
# ============================================================================
# m23_check.py —— M23 的场景：钥匙表落盘（重启后吊销还在、坏文件不猜）
#
# 四个阶段（每个阶段是**另一个进程**，这正是这一步要验的东西）：
#   1 第一次上电：没有文件 → 铺默认两把并写盘；装 3 号；吊销 1 号；装 4 号
#   2 重启：同一个文件 → 1 号还是吊销、3/4 号还在
#   3 文件被写坏（砍掉尾巴）→ 启动判 Corrupt：表空、谁都验不过、装钥匙被拒（7F 31 22）
#   4 --reset-key-store → 重建默认两把，1 号包又能验过
#
# 用法：python3 m23_check.py <port> <phase>     phase = 1 | 2 | 3 | 4
# ============================================================================
import hashlib
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
PHASE = int(sys.argv[2]) if len(sys.argv) > 2 else 1
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


def demo_key(key_id):
    return hashlib.sha256(("doip-gw demo key %d" % key_id).encode()).digest()


def fixed(text, n):
    b = text.encode()
    return (b + b" " * n)[:n]


def manifest_v2(image, key_id, part, sw):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x02, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id) \
           + fixed(part, 12) + fixed(sw, 16)
    return body + hashlib.sha256(body + key).digest()


def manifest_v1(image, key_id):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x01, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id)
    return body + hashlib.sha256(body + key).digest()


def read_table(t):
    """0x22 F1B0 → "0001=00,0002=02"；空表返回 ""（不是 NONE）"""
    r = t.uds(bytes([0x22, 0xF1, 0xB0]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB0]):
        return "NONE"
    rows = r[3:]
    out = []
    for i in range(0, len(rows) - 2, 3):
        out.append(((rows[i] << 8) | rows[i + 1], rows[i + 2]))
    return ",".join("%04X=%02X" % (k, v) for k, v in sorted(out))


def install(t, key_id, key):
    return t.uds(bytes([0x31, 0x01, 0x02, 0x06]) + struct.pack("!H", key_id) + key)


def set_state(t, key_id, want):
    return t.uds(bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want]))


def precheck(t, manifest):
    return t.uds(bytes([0x31, 0x01, 0x02, 0x05]) + manifest)


def verify_pkg(t, manifest):
    return t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest)


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

if PHASE == 1:
    # 第一次上电：文件不存在 → 默认两把，而且立刻写盘
    tbl = read_table(t)
    check(tbl == "0001=00,0002=00", "P1_TABLE_BOOT", tbl)

    ok = unlock(t)
    check(ok, "P1_UNLOCK", "OK" if ok else "FAIL")

    r = install(t, 0x0003, demo_key(3))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x00]), "P1_INSTALL_3", hexs(r))
    check(read_table(t) == "0001=00,0002=00,0003=00", "P1_TABLE_AFTER_INSTALL", read_table(t))

    r = set_state(t, 0x0001, 0x02)
    check(r == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "P1_REVOKE_1", hexs(r))
    check(read_table(t) == "0001=02,0002=00,0003=00", "P1_TABLE_AFTER_REVOKE", read_table(t))

    r = install(t, 0x0004, demo_key(4))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x00]), "P1_INSTALL_4", hexs(r))

elif PHASE == 2:
    # 重启：同一个文件 —— 吊销必须还在，否则"吊销"这件事根本不成立
    tbl = read_table(t)
    check(tbl == "0001=02,0002=00,0003=00,0004=00", "P2_TABLE_AFTER_REBOOT", tbl)
    check(read_table(t) == "0001=02,0002=00,0003=00,0004=00", "P2_TABLE_STABLE", read_table(t))

    # FF02 / 0205 都是"刷写流程里的动作"，要先 0x10 02 + 解锁 —— 顺序不能反
    ok = unlock(t)
    check(ok, "P2_UNLOCK", "OK" if ok else "FAIL")

    r = install(t, 0x0003, demo_key(3))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x01]), "P2_INSTALL_EXISTING", hexs(r))

    # 1 号被吊销 → 它签的包不能验过（这是"吊销落盘"的实际后果）
    # 0205 只验信封（不看镜像），所以不用先推镜像就能问"这把钥匙认不认"
    r = precheck(t, manifest_v2(IMG, 0x0001, "PART-ABC1234", "SW-1.0.3"))
    check(r == bytes([0x7F, 0x31, 0x31]), "P2_PRECHECK_REVOKED_KEY", hexs(r))

    r = precheck(t, manifest_v2(IMG, 0x0004, "PART-ABC1234", "SW-1.0.3"))
    check(r == bytes([0x71, 0x01, 0x02, 0x05, 0x00]), "P2_PRECHECK_NEW_KEY", hexs(r))

elif PHASE == 3:
    # 文件被写坏：表必须空（谁都验不过），而且不许在半截的表上再写
    tbl = read_table(t)
    check(tbl == "", "P3_TABLE_EMPTY", tbl if tbl != "" else "(空)")

    ok = unlock(t)
    check(ok, "P3_UNLOCK", "OK" if ok else "FAIL")

    r = precheck(t, manifest_v2(IMG, 0x0001, "PART-ABC1234", "SW-1.0.3"))
    check(r == bytes([0x7F, 0x31, 0x31]), "P3_PRECHECK_ANY_KEY", hexs(r))
    r = install(t, 0x0005, demo_key(5))
    check(r == bytes([0x7F, 0x31, 0x22]), "P3_INSTALL_LOCKED", hexs(r))
    r = set_state(t, 0x0001, 0x00)
    check(r == bytes([0x7F, 0x31, 0x22]), "P3_STATE_LOCKED", hexs(r))
    check(read_table(t) == "", "P3_TABLE_STILL_EMPTY", read_table(t) if read_table(t) != "" else "(空)")

elif PHASE == 4:
    # --reset-key-store：人明确要求重建之后，才回到默认两把
    tbl = read_table(t)
    check(tbl == "0001=00,0002=00", "P4_TABLE_RESET", tbl)
    ok = unlock(t)
    check(ok, "P4_UNLOCK", "OK" if ok else "FAIL")
    r = precheck(t, manifest_v2(IMG, 0x0001, "PART-ABC1234", "SW-1.0.3"))
    check(r == bytes([0x71, 0x01, 0x02, 0x05, 0x00]), "P4_PRECHECK_AFTER_RESET", hexs(r))
    r = install(t, 0x0003, demo_key(3))
    check(r == bytes([0x71, 0x01, 0x02, 0x06, 0x00]), "P4_INSTALL_AFTER_RESET", hexs(r))

t.close()

print("PHASE=%d" % PHASE)
print("FAIL=%d" % FAIL)
sys.exit(0 if FAIL == 0 else 1)
