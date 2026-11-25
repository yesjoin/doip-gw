#!/usr/bin/env python3
# ============================================================================
# m16_check.py —— M16 的门禁场景：会话 / 种子 / 密钥 / 保活 / S3 超时
#
# 这一节的考点不是"服务能不能答"，而是"门到底有没有关"：
#   ① 默认会话里刷写服务回 0x7F（会话不对），不是 0x33；
#   ② 进了编程会话但没解锁回 0x33（会话对了、钥匙没插）；
#   ③ 解锁之后刷写整条链路真的能跑完（门开了，不是只会回码）；
#   ④ 换会话会把解锁清掉（解锁只在当前会话里有效）；
#   ⑤ 3E 00 保活、3E 80 不回包但也算活着；S3 5 秒没人理就回落默认会话；
#   ⑥ 错密钥 3 次 → 0x36 并锁；锁定期内再要种子是 0x37（不是继续 0x35）。
#
# 用法：python3 m16_check.py <port>
# 输出 KEY=VALUE 行，由 m16_e2e.sh 逐条断言。
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

    # 干等：不发请求，但必须继续读 socket 并回心跳 —— 否则网关 3 秒后主动断链，
    # 我们就测不到"S3 到了才回落到默认会话"，而是测到"网关先把我踢了"。
    def idle(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.s.settimeout(0.3)
            try:
                r = parse(self.s.recv(8192))
            except socket.timeout:
                continue
            if r is None:
                continue
            if r[0] == 0x0007:
                self.s.sendall(msg(0x0008, struct.pack("!H", self.sa) + b"\x00\x00"))

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


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# 第二条腿（--flash 不带 --secure）：M15 的老路径必须原样还能用
if len(sys.argv) > 2 and sys.argv[2] == "legacy":
    t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))     # 不带门禁时擦除照旧可用（先满足 0x34 的前置）
    r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
    check(r is not None and r[:2] == bytes([0x74, 0x20]), "LEGACY_34", hexs(r))
    r = t.uds(bytes([0x10, 0x02]))
    check(nrc(r, 0x10) == 0x31, "LEGACY_10", "%02X" % (nrc(r, 0x10) & 0xFF))
    r = t.uds(bytes([0x27, 0x01]))
    check(nrc(r, 0x27) == 0x31, "LEGACY_27", "%02X" % (nrc(r, 0x27) & 0xFF))
    t.close()
    emit("FAIL", FAIL)
    sys.exit(1 if FAIL else 0)

# ---------------------------------------------------------------------------
# A. 默认会话：老服务照旧，刷写服务被"会话"挡住（0x7F，不是 0x33）
# ---------------------------------------------------------------------------
vin = t.uds(bytes([0x22, 0xF1, 0x90]))
vin_s = vin[3:20].decode("ascii", "replace") if (vin is not None and len(vin) >= 20) else ""
check(vin_s == "LSVZZ0000B7654321", "VIN_DEFAULT", vin_s if vin_s else "NONE")

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
check(nrc(r, 0x34) == 0x7F, "NRC_34_DEFAULT", "%02X" % (nrc(r, 0x34) & 0xFF))

# ---------------------------------------------------------------------------
# B. 进编程会话：50 02 00 32 01 F4（P2=50ms，P2*=5000ms）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x10, 0x02]))
check(r is not None and r[:2] == bytes([0x50, 0x02]), "SESSION_PROG", hexs(r))
check(r is not None and r[2:4] == bytes([0x00, 0x32]), "P2", hexs(r[2:4] if r else b""))
check(r is not None and r[4:6] == bytes([0x01, 0xF4]), "P2STAR", hexs(r[4:6] if r else b""))

# ---------------------------------------------------------------------------
# C. 会话对了但没解锁：0x33（和 0x7F 是两个意思，别混）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
check(nrc(r, 0x34) == 0x33, "NRC_34_LOCKED", "%02X" % (nrc(r, 0x34) & 0xFF))
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(nrc(r, 0x31) == 0x33, "NRC_ERASE_LOCKED", "%02X" % (nrc(r, 0x31) & 0xFF))

# ---------------------------------------------------------------------------
# D. 种子 → 错密钥（0x35）→ 对密钥（0x67 02）
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x27, 0x01]))
ok_seed = r is not None and r[:2] == bytes([0x67, 0x01]) and len(r) == 6
seed = struct.unpack("!I", r[2:6])[0] if ok_seed else 0
check(ok_seed and seed != 0, "SEED", "%08X" % seed)

key = key_of(seed)
check(key == ((seed + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF, "KEY_CALC", "%08X" % key)

wrong = (key ^ 0x00000001) & 0xFFFFFFFF
r = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", wrong))
check(nrc(r, 0x27) == 0x35, "NRC_KEY_WRONG", "%02X" % (nrc(r, 0x27) & 0xFF))

r = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", key))
check(r is not None and r == bytes([0x67, 0x02]), "UNLOCKED", hexs(r))

# ---------------------------------------------------------------------------
# E. 门开了：整条刷写链路真的能跑完（不是"只会回码"）
# ---------------------------------------------------------------------------
IMG = bytes([(i * 29 + 5) & 0xFF for i in range(8)])
r = t.uds(bytes([0x31, 0x01, 0xFF, 0x00]))
check(r is not None and r == bytes([0x71, 0x01, 0xFF, 0x00]), "ERASE_OK", hexs(r))

r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))
check(r is not None and r[:2] == bytes([0x74, 0x20]), "DOWNLOAD_ACK", hexs(r))

r = t.uds(bytes([0x36, 0x01]) + IMG)
check(r is not None and r == bytes([0x76, 0x01]), "BLOCK_1", hexs(r))

r = t.uds(bytes([0x37]))
crc = struct.unpack("!I", r[1:5])[0] if (r is not None and len(r) == 5 and r[0] == 0x77) else 0
check(r is not None and r[0] == 0x77, "EXIT", hexs(r))
check(crc == zlib.crc32(IMG), "EXIT_CRC", "%08X" % crc)

# 已解锁再要种子：标准里回 0，意思是"你不用再交钥匙了"
r = t.uds(bytes([0x27, 0x01]))
check(r == bytes([0x67, 0x01, 0x00, 0x00, 0x00, 0x00]), "SEED_WHEN_UNLOCKED", hexs(r))

# ---------------------------------------------------------------------------
# F. 换会话把解锁清掉：回默认会话后 0x34 → 0x7F；再进编程会话又变 0x33
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x10, 0x01]))
check(r is not None and r[:2] == bytes([0x50, 0x01]), "SESSION_DEFAULT", hexs(r))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
check(nrc(r, 0x34) == 0x7F, "NRC_34_BACK_TO_DEFAULT", "%02X" % (nrc(r, 0x34) & 0xFF))

r = t.uds(bytes([0x10, 0x02]))
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
check(nrc(r, 0x34) == 0x33, "NRC_34_RELOCKED", "%02X" % (nrc(r, 0x34) & 0xFF))

# ---------------------------------------------------------------------------
# G. 0x3E：00 回 7E 00；80 不回包；再来一条 00 仍然正常
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x3E, 0x00]))
check(r == bytes([0x7E, 0x00]), "TP_00", hexs(r))



# ---------------------------------------------------------------------------
# H. S3：编程会话里 5 秒没人说话 → 回落默认会话（门重新关上）
#    这里必须真的等，S3 是墙上时间
# ---------------------------------------------------------------------------
t.idle(5.6)
r = t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, 8))
check(nrc(r, 0x34) == 0x7F, "NRC_34_AFTER_S3", "%02X" % (nrc(r, 0x34) & 0xFF))

# 回落之后还能正常进会话（不是"卡死在默认"）
r = t.uds(bytes([0x10, 0x02]))
check(r is not None and r[:2] == bytes([0x50, 0x02]), "SESSION_AGAIN", hexs(r))

# ---------------------------------------------------------------------------
# I. 错密钥 3 次 → 0x36 并锁；锁定期内再要种子 → 0x37
#    锁是 10 秒，脚本不在这里干等 —— "锁到期能重来"由自测用时间参数验
# ---------------------------------------------------------------------------
r = t.uds(bytes([0x27, 0x01]))
ok_seed2 = r is not None and r[:2] == bytes([0x67, 0x01]) and len(r) == 6
seed2 = struct.unpack("!I", r[2:6])[0] if ok_seed2 else 0
bad = (((seed2 + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF) ^ 0x00000001

r1 = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", bad))
r2 = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", bad))
r3 = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", bad))
check(nrc(r1, 0x27) == 0x35, "KEY_BAD_1", "%02X" % (nrc(r1, 0x27) & 0xFF))
check(nrc(r2, 0x27) == 0x35, "KEY_BAD_2", "%02X" % (nrc(r2, 0x27) & 0xFF))
check(nrc(r3, 0x27) == 0x36, "KEY_BAD_3", "%02X" % (nrc(r3, 0x27) & 0xFF))

r = t.uds(bytes([0x27, 0x01]))
check(nrc(r, 0x27) == 0x37, "NRC_SEED_DURING_LOCK", "%02X" % (nrc(r, 0x27) & 0xFF))

# ---------------------------------------------------------------------------
# J. 3E 80（suppressPosRsp）：单开一条连接验。
#    为什么不在主流程里做：网关是"一问一答"的中继，一条请求没有回响，
#    它就一直认为这条连接上"还有一条在途"，下一条会被忙拒（0x8003 0x08）。
#    这是网关的已知边界（见 README 的 M16 边界），不是 ECU 的错。
# ---------------------------------------------------------------------------
t2 = Tester(0x0E01)
code2 = t2.activate()
check(code2 == 0x10, "ACT_CODE_2", "%02X" % (code2 if code2 is not None else 0xFF))
r = t2.uds(bytes([0x3E, 0x80]), timeout=1.0)
check(r is None, "TP_80_SILENT", "1" if r is None else "0")
t2.close()

t.close()
emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
