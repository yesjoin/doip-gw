#!/usr/bin/env python3
# ============================================================================
# m21_check.py —— M21 的场景：包自己带身份（0x31 01 0205 预检 + FF02 身份核对）
#
# 两条腿：
#   腿一（车 PART-ABC1234 / SW-1.0.3，--require-compat，不许降级）：
#        · 0205 只收 v2：v1（76 字节）→ 7F 31 31；长度错 → 13；版本与长度不配对 → 31；
#          标签错 → 31（都是"包不对"，不是"请求错"）；
#        · 身份不符（零件号 / 降级）→ 正响应 01；凭证不成立，0x34 仍 22；
#        · 前一条包通过了，后一条包不通过 → 前一次的通过**作废**（不是留着的旧凭证）；
#        · 预检通过 → 0x34 拿走 → 真的下载；
#        · FF02 整包验签：v2 身份对 → 00；v2 包是真的但身份不符 → **02**；v1 → 00（只没身份）；
#        · 硬复位清掉镜像之后，0205 照样能预检（它不看镜像）。
#   腿二（车 SW-1.9.0，--allow-downgrade）：
#        · 1.9.0 → 1.10.0 判升级（数值比较）；1.9.0 → 1.8.0 降级放行；
#        · 目标版本写成 SW-latest → 01（包里的版本号不成三段 = 包有问题，不是请求有问题）。
#
# 用法：python3 m21_check.py <port> <leg>     leg = 1 | 2
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


# ---- 清单（和 include/FirmwareManifest.h 同一份公式，用 hashlib 独立拼）----
def demo_key(key_id):
    return hashlib.sha256(("doip-gw demo key %d" % key_id).encode()).digest()


def fixed(text, n):
    b = text.encode()
    return (b + b" " * n)[:n]          # 右补空格；超长就截断（C++ 侧同样截断）


def manifest_v1(image, key_id):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x01, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id)
    assert len(body) == 44, len(body)
    return body + hashlib.sha256(body + key).digest()


def manifest_v2(image, key_id, part, sw):
    key = demo_key(key_id)
    body = b"DGIM" + bytes([0x02, 0x00]) + struct.pack("!I", len(image)) \
           + hashlib.sha256(image).digest() + struct.pack("!H", key_id) \
           + fixed(part, 12) + fixed(sw, 16)
    assert len(body) == 72, len(body)
    return body + hashlib.sha256(body + key).digest()


def retag(body, key_id):
    """按前 72 字节重新盖标签（模拟"签得挺认真，但内容是自己编的"）"""
    return body[:72] + hashlib.sha256(body[:72] + demo_key(key_id)).digest()


def precheck(t, manifest):
    """0x31 01 0205：把整份清单发上去做预检"""
    return t.uds(bytes([0x31, 0x01, 0x02, 0x05]) + manifest)


def pre_status(resp):
    if resp is None or len(resp) != 5 or resp[:4] != bytes([0x71, 0x01, 0x02, 0x05]):
        return -1
    return resp[4]


def download(t):
    return t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

cur = t.uds(bytes([0x22, 0xF1, 0x87]))
cur_sw = t.uds(bytes([0x22, 0xF1, 0x88]))
car_part = cur[3:].decode(errors="replace").strip() if cur else "NONE"
car_sw = cur_sw[3:].decode(errors="replace").strip() if cur_sw else "NONE"
check(car_part == "PART-ABC1234", "CAR_PART", car_part)
check(car_sw == ("SW-1.9.0" if LEG == 2 else "SW-1.0.3"), "CAR_SW", car_sw)

ok = unlock(t)
check(ok, "UNLOCK", "OK" if ok else "FAIL")

if LEG == 1:
    # -----------------------------------------------------------------------
    # A. 0205 只收 v2：v1 / 长度错 / 版本与长度不配对 / 标签错，全是 NRC
    # -----------------------------------------------------------------------
    r = precheck(t, manifest_v1(IMG, 1))
    check(nrc(r, 0x31) == 0x31, "NRC_V1", hexs(r) if r else "NONE")

    # 版本字节改成 01（长度还是 104）——长度与版本必须成对
    body = manifest_v2(IMG, 1, car_part, car_sw)
    v1_as_v2 = retag(body[:4] + bytes([0x01, 0x00]) + body[6:72], 1)
    r = precheck(t, v1_as_v2)
    check(nrc(r, 0x31) == 0x31, "NRC_VERSION", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, car_sw)[:100])
    check(nrc(r, 0x31) == 0x13, "NRC_LEN", hexs(r) if r else "NONE")

    body = manifest_v2(IMG, 1, car_part, car_sw)
    bad_tag = body[:72] + hashlib.sha256(body[:72] + demo_key(2)).digest()   # 2 号钥匙盖的章
    r = precheck(t, bad_tag)
    check(nrc(r, 0x31) == 0x31, "NRC_TAG", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # B. 身份不符：包是真的，但不是给这台车的 → 正响应 01，凭证不成立
    # -----------------------------------------------------------------------
    r = precheck(t, manifest_v2(IMG, 1, "PART-XYZ9999", car_sw))
    check(pre_status(r) == 0x01, "PART_MISMATCH", hexs(r) if r else "NONE")

    r = download(t)
    check(nrc(r, 0x34) == 0x22, "NRC_AFTER_PART_FAIL", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.0.2"))
    check(pre_status(r) == 0x01, "DOWNGRADE", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # C. 预检通过 → 后一条包不通过 → 前一次的通过必须作废
    # -----------------------------------------------------------------------
    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.0.4"))
    check(pre_status(r) == 0x00, "PRECHECK_OK", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, "PART-XYZ9999", "SW-1.0.4"))
    check(pre_status(r) == 0x01, "PRECHECK_AFTER_OK_FAIL", hexs(r) if r else "NONE")

    r = download(t)
    check(nrc(r, 0x34) == 0x22, "NRC_STALE_CREDENTIAL", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # D. 再来一次真的：先擦除（0x34 要求擦过）→ 预检通过 → 0x34 拿走凭证 → 下载 → 收尾
    # -----------------------------------------------------------------------
    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
    check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_1", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.0.4"))
    check(pre_status(r) == 0x00, "PRECHECK_OK_2", hexs(r) if r else "NONE")

    r = download(t)
    check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x36, 0x01]) + IMG)
    check(r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x37]))
    crc = struct.unpack("!I", r[1:5])[0] if (r is not None and len(r) == 5) else 0
    check(crc == (zlib.crc32(IMG) & 0xFFFFFFFF), "EXIT_CRC", "%08X" % crc)

    # -----------------------------------------------------------------------
    # E. FF02 整包验签：v2 身份对 → 00；包真但身份不符 → 02；v1 → 00
    # -----------------------------------------------------------------------
    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest_v2(IMG, 1, car_part, "SW-1.0.4"))
    check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x00]), "VERIFY_V2_OK", hexs(r) if r else "NONE")

    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest_v2(IMG, 1, "PART-XYZ9999", "SW-1.0.4"))
    check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x02]), "VERIFY_V2_ID_MISMATCH",
          hexs(r) if r else "NONE")

    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x02]) + manifest_v1(IMG, 1))
    check(r == bytes([0x71, 0x01, 0xFF, 0x02, 0x00]), "VERIFY_V1_OK", hexs(r) if r else "NONE")

    # -----------------------------------------------------------------------
    # F. 硬复位清掉镜像之后，0205 照样能预检（它不看镜像，只看信封）
    # -----------------------------------------------------------------------
    r = t.uds(bytes([0x11, 0x01]))
    check(r == bytes([0x51, 0x01]), "RESET_HARD", hexs(r) if r else "NONE")
    ok = unlock(t)
    check(ok, "UNLOCK_2", "OK" if ok else "FAIL")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.0.4"))
    check(pre_status(r) == 0x00, "PRECHECK_AFTER_RESET", hexs(r) if r else "NONE")

else:
    # -----------------------------------------------------------------------
    # 腿二：数值比较 + 允许降级 + 包里的版本号不成三段
    #   先擦除：擦除会作废凭证（M20 就定的），所以预检要放在擦除之后。
    # -----------------------------------------------------------------------
    r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
    check(r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_1", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.10.0"))
    check(pre_status(r) == 0x00, "PRECHECK_110", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.8.0"))
    check(pre_status(r) == 0x00, "PRECHECK_DOWNGRADE", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-latest"))
    check(pre_status(r) == 0x01, "PRECHECK_BAD_VERSION", hexs(r) if r else "NONE")

    r = precheck(t, manifest_v2(IMG, 1, car_part, "SW-1.10.0"))
    check(pre_status(r) == 0x00, "PRECHECK_110_2", hexs(r) if r else "NONE")

    r = download(t)
    check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD", hexs(r) if r else "NONE")

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
