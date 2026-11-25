#!/usr/bin/env python3
# ============================================================================
# m18_check.py —— M18 的验签场景：0x31 01 FF02 + 76 字节清单
#
# 考点是"哪一类错该回哪种回答"，以及"换包"这件事到底抓不抓得住：
#   ① 清单结构错（长度 / magic / 版本 / 不认识钥匙）→ NRC（请求本身不合法）；
#   ② 清单内容错（标签 / 长度 / 哈希）→ 正响应 71 01 FF 02 01（请求合法，是包不对）；
#   ③ 别人把镜像整个换一份、清单还是原来那份 → 哈希不符（CRC 抓不到的那一类）；
#   ④ 没有镜像时验签 → 0x22（和 M15 的空镜像校验同一个条件）。
#
# 清单由本脚本自己拼（hashlib），ECU 用 C++ 的 Sha256 自己算 ——
# 两边公式一致才算数，这比"两边都调同一个库"更有说服力。
#
# 用法：python3 m18_check.py <port>
# ============================================================================
import hashlib
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


# ---- 清单（和 include/FirmwareManifest.h 同一份公式）----------------------
def demo_key(key_id):
    return hashlib.sha256(("doip-gw demo key %d" % key_id).encode()).digest()


def manifest(image, key_id, key):
    body = b"DGIM" + bytes([0x01, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id)
    assert len(body) == 44, len(body)
    tag = hashlib.sha256(body + key).digest()
    return body + tag


def retag(body, key):
    return body[:44] + hashlib.sha256(body[:44] + key).digest()


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


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

IMG = bytes([(i * 29 + 5) & 0xFF for i in range(8)])
IMG2 = bytes([(i * 7 + 0xA0) & 0xFF for i in range(8)])

# ---------------------------------------------------------------------------
# A. 没解锁时验签也要被门挡住（FF02 和 FF00/FF01 一样是刷写例程）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest(IMG, 1, demo_key(1)))
check(nrc(r, 0x31) == 0x7F, "NRC_FF02_DEFAULT", "%02X" % (nrc(r, 0x31) & 0xFF))

ok = unlock(t)
check(ok, "UNLOCK", "OK" if ok else "FAIL")

# ---------------------------------------------------------------------------
# B. 推镜像（8 字节） —— 和 M15 完全一样的路径
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE", hexs(r))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r))
r = t.uds(bytes([0x36, 0x01]) + IMG)
check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r))
r = t.uds(bytes([0x37]))
check(r is not None and r[:1] == bytes([0x77]), "EXIT_CRC",
      "%08X" % (struct.unpack("!I", r[1:5])[0] if (r and len(r) == 5) else 0))
check(r is not None and len(r) == 5 and struct.unpack("!I", r[1:5])[0] == (zlib.crc32(IMG) & 0xFFFFFFFF),
      "CRC_MATCH", "1" if (r and len(r) == 5 and struct.unpack("!I", r[1:5])[0] == (zlib.crc32(IMG) & 0xFFFFFFFF)) else "0")

M = manifest(IMG, 1, demo_key(1))

# ---------------------------------------------------------------------------
# C. 正例：清单与镜像一致 → 71 01 FF 02 00
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + M)
check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x00]), "VERIFY_OK", hexs(r))

# ---------------------------------------------------------------------------
# D. 内容错 → 正响应 01（请求合法，是包不对）
# ---------------------------------------------------------------------------
# 标签用 2 号钥匙算，keyId 却写 1 号
bad_tag = M[:44] + hashlib.sha256(M[:44] + demo_key(2)).digest()
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + bad_tag)
check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x01]), "BAD_TAG", hexs(r))

# 长度写错、但用 1 号钥匙重新盖了标签（"签错了长度"这种真实失误）
body = M[:6] + struct.pack("!I", 9) + M[10:44]
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + retag(body, demo_key(1)))
check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x01]), "LEN_MISMATCH", hexs(r))

# 哈希写错（同样重新盖标签）
body = M[:10] + bytes([M[10] ^ 0x01]) + M[11:44]
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + retag(body, demo_key(1)))
check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x01]), "SHA_MISMATCH", hexs(r))

# ---------------------------------------------------------------------------
# E. 结构错 → NRC（请求本身不合法）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + M[:-1])
check(nrc(r, 0x31) == 0x13, "NRC_LEN", "%02X" % (nrc(r, 0x31) & 0xFF))

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + b"XGIM" + M[4:])
check(nrc(r, 0x31) == 0x31, "NRC_MAGIC", "%02X" % (nrc(r, 0x31) & 0xFF))

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + M[:4] + bytes([0x02, 0x00]) + M[6:])
check(nrc(r, 0x31) == 0x31, "NRC_VERSION", "%02X" % (nrc(r, 0x31) & 0xFF))

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest(IMG, 0x00FF, demo_key(1)))
check(nrc(r, 0x31) == 0x31, "NRC_UNKNOWN_KEY", "%02X" % (nrc(r, 0x31) & 0xFF))

# ---------------------------------------------------------------------------
# F. 换包：别人把镜像整个换一份，清单还是原来那份
#    这是 CRC 抓不住、哈希能抓住的那一类（原清单对不上新镜像）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG2)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD_2", hexs(r))
r = t.uds(bytes([0x36, 0x01]) + IMG2)
check(r == bytes([0x76, 0x01]), "BLOCK_2", hexs(r))
r = t.uds(bytes([0x37]))
check(r is not None and len(r) == 5, "EXIT_CRC_2",
      "%08X" % (struct.unpack("!I", r[1:5])[0] if (r and len(r) == 5) else 0))

r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + M)   # 还是原来那份清单
check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x01]), "PACKAGE_SWAP", hexs(r))

# ---------------------------------------------------------------------------
# G. 没有镜像时验签 → 0x22（硬复位把镜像清掉，M17 的语义在这里复用）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x11, 0x01]))
check(r == bytes([0x51, 0x01]), "RESET_HARD", hexs(r))
ok = unlock(t)
check(ok, "UNLOCK_2", "OK" if ok else "FAIL")
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + M)
check(nrc(r, 0x31) == 0x22, "NRC_EMPTY", "%02X" % (nrc(r, 0x31) & 0xFF))

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
