#!/usr/bin/env python3
# ============================================================================
# m25_check.py —— M25 的场景：清单指纹 + 变更世代
#
# 要证明的三件事：
#   ① **计数一样不等于表一样**：A 装了 5 号、B 装了 6 号，两台都是"总 4 / 启用 4"，
#      M24 的摘要（F1B1）说"一致"，指纹（F1B2）说"不是"，而且点得出是谁；
#   ② **世代要活过重启**：改过两次就是 2，重启后还是 2（v2 文件里那行 VER）；
#   ③ **内容一样、历史不一样**：退役再改回来，指纹回到原值，但世代更高 ——
#      这是"这台被人动过"，不是"这台和别台一样"。
#
# 用法：python3 m25_check.py <port> <leg>     leg = 1 | 2 | 3
#   1 = 全新表：假一致怎么被抓、世界线怎么分叉（并把每台的指纹记到 /tmp/m25_fp.txt）
#   2 = 同一批文件重启：世代活过来了；退役再改回来，内容回原样但世代更高
#   3 = 把 A 的文件改写成 v1（旧格式）：读得进来，世代归 0，指纹不变
# ============================================================================
import hashlib
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1
SA = 0x0E00
FUNC_TA = 0xE400
ECUS = [0x0003, 0x0006, 0x0007]
FAIL = 0
QUIET = 0.45
FP_FILE = "/tmp/m25_fp.txt"


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
        # 一条 recv 里可能躺着好几条 DoIP 消息（M24 踩过：三台一起答就被合并）
        self.buf = b""

    def _fill(self, timeout):
        self.s.settimeout(max(0.01, timeout))
        try:
            d = self.s.recv(8192)
        except socket.timeout:
            return False
        if not d:
            return False
        self.buf += d
        return True

    def next_msg(self, timeout):
        deadline = time.time() + timeout
        while True:
            if len(self.buf) >= 8:
                plen = struct.unpack("!I", self.buf[4:8])[0]
                if len(self.buf) >= 8 + plen:
                    head = self.buf[:8 + plen]
                    self.buf = self.buf[8 + plen:]
                    return parse(head)
            left = deadline - time.time()
            if left <= 0:
                return None
            if not self._fill(left):
                return None

    def activate(self):
        self.s.sendall(msg(0x0005, struct.pack("!H", self.sa) + b"\x00" + b"\x00" * 8))
        r = self.next_msg(3.0)
        return r[1][4] if (r is not None and r[0] == 0x0006) else None

    def _drain(self, stop_after, quiet):
        out = []
        while True:
            if stop_after is not None and len(out) >= stop_after:
                break
            r = self.next_msg(quiet)
            if r is None:
                break
            if r[0] == 0x8002:
                continue
            if r[0] == 0x0007:
                self.s.sendall(msg(0x0008, struct.pack("!H", self.sa) + b"\x00\x00"))
                continue
            if r[0] == 0x8001:
                payload = r[1]
                out.append((struct.unpack("!H", payload[0:2])[0], payload[4:]))
            if r[0] == 0x8003:
                out.append((0xFFFF, r[1]))
        return out

    def uds(self, ta, req):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ta) + req))
        got = self._drain(1, 3.0)
        return got[0][1] if got else None

    def broadcast(self, req, expect=None):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, FUNC_TA) + req))
        out = {}
        nack = None
        for sa, uds in self._drain(expect, QUIET):
            if sa == 0xFFFF:
                nack = uds
            else:
                out[sa] = uds
        return out, nack

    def close(self):
        self.s.close()


def hexs(b):
    return b.hex().upper() if b else "NONE"


def key_of(seed):
    return ((seed + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF


def unlock(t, ta):
    r = t.uds(ta, bytes([0x10, 0x02]))
    if r is None or r[:2] != bytes([0x50, 0x02]):
        return False
    r = t.uds(ta, bytes([0x27, 0x01]))
    if r is None or len(r) != 6:
        return False
    seed = struct.unpack("!I", r[2:6])[0]
    r = t.uds(ta, bytes([0x27, 0x02]) + struct.pack("!I", key_of(seed)))
    return r == bytes([0x67, 0x02])


def demo_key(key_id):
    return hashlib.sha256(("doip-gw demo key %d" % key_id).encode()).digest()


def install(key_id):
    return bytes([0x31, 0x01, 0x02, 0x06]) + struct.pack("!H", key_id) + demo_key(key_id)


def set_state(key_id, want):
    return bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want])


def digest(t, ta):
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB1]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB1]) or len(r) < 7:
        return "NONE"
    return "%d/%d/%d/%d" % (r[3], r[4], r[5], r[6])


def stamp(t, ta):
    """0x22 F1B2 → (世代, 指纹 4hex)；读不到返回 (None, 'NONE')"""
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB2]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB2]) or len(r) < 7:
        return None, "NONE"
    gen = (r[3] << 8) | r[4]
    fp = "%02X%02X" % (r[5], r[6])
    return gen, fp


def fleet(fn, t):
    return ";".join("%04X:%s" % (sa, fn(t, sa)) for sa in ECUS)




def fleet_of(resp):
    return ",".join("%04X=%s" % (sa, hexs(resp[sa])) for sa in ECUS if sa in resp)


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

if LEG == 1:
    # ---- 1. 出厂状态：四个计数一样、指纹一样 ----
    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB1]), expect=len(ECUS))
    check(all(v == bytes([0x62, 0xF1, 0xB1, 0x02, 0x02, 0x00, 0x00]) for v in r.values()),
          "DIGEST_BOOT", fleet_of(r))

    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB2]), expect=len(ECUS))
    check(len(r) == 3, "BC_STAMP_COUNT", str(len(r)))

    check(all(v[3] == 0 and v[4] == 0 for v in r.values()), "STAMP_BOOT_GEN0",
          fleet_of(r))          # 世代都是 0（没改过）
    check(len({v[5:] for v in r.values()}) == 1, "STAMP_BOOT_SAME_FP", fleet_of(r))

    # ---- 2. 三台都装 3 号：世代到 1，指纹一起变 ----
    for sa in ECUS:
        check(unlock(t, sa), "UNLOCK_%04X" % sa, "OK")
    ok_n = 0
    for sa in ECUS:
        if t.uds(sa, install(0x0003)) == bytes([0x71, 0x01, 0x02, 0x06, 0x00]):
            ok_n += 1
    check(ok_n == 3, "INSTALL_3_ALL", "成 %d / 3" % ok_n)

    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB2]), expect=len(ECUS))
    check(all(v[3] == 0 and v[4] == 1 for v in r.values()), "STAMP_AFTER3_GEN1", fleet_of(r))
    check(len({v[5:] for v in r.values()}) == 1, "STAMP_AFTER3_SAME_FP", fleet_of(r))

    # ---- 3. 假一致：A 装 5 号、B 装 6 号、C 装 5 号 ----
    #   三台都变成 4 把、都全部启用 → 摘要一模一样；指纹 B 与 A/C 不同。
    t.uds(0x0003, install(0x0005))
    t.uds(0x0006, install(0x0006))
    t.uds(0x0007, install(0x0005))

    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB1]), expect=len(ECUS))
    check(all(v == bytes([0x62, 0xF1, 0xB1, 0x04, 0x04, 0x00, 0x00]) for v in r.values()),
          "DIGEST_LIE_EQUAL", fleet_of(r))     # ← 摘要说"三台一样"

    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB2]), expect=len(ECUS))
    check(all(v[3] == 0 and v[4] == 2 for v in r.values()), "STAMP_GEN_SAME", fleet_of(r))
    # 整条 UDS 是 62 F1 B2 <gen 2> <fp 2>；hex 串里指纹是最后 4 个字符
    fpt = {sa: hexs(v)[10:] for sa, v in r.items()}
    check(fpt[0x0003] == fpt[0x0007] and fpt[0x0006] != fpt[0x0003],
          "STAMP_FP_SPLIT", fleet_of(r))       # ← 指纹说"不是"
    odd = [sa for sa in ECUS if fpt[sa] != fpt[0x0003]]
    check(odd == [0x0006], "STAMP_POINT_OUT",
          ("一致" if not odd else "不一致，%s 的指纹与 0x0003 不同" % ",".join("%04X" % s for s in odd)))

    with open(FP_FILE, "w") as f:
        f.write(";".join("%04X=%s" % (sa, fpt[sa]) for sa in ECUS) + "\n")

if LEG == 2:
    # ---- 4. 重启：世代与指纹都活过来了 ----
    with open(FP_FILE) as f:
        want = dict(x.split("=") for x in f.read().strip().split(";"))
    st = {sa: stamp(t, sa) for sa in ECUS}
    check(all(st[sa][0] == 2 for sa in ECUS), "STAMP_RESTART_GEN2",
          ";".join("%04X:%d" % (sa, st[sa][0]) for sa in ECUS))
    check(all(st[sa][1] == want["%04X" % sa] for sa in ECUS), "STAMP_RESTART_FP_SAME",
          ";".join("%04X:%s" % (sa, st[sa][1]) for sa in ECUS))

    r, _ = t.broadcast(bytes([0x22, 0xF1, 0xB1]), expect=len(ECUS))
    check(all(v == bytes([0x62, 0xF1, 0xB1, 0x04, 0x04, 0x00, 0x00]) for v in r.values()),
          "DIGEST_RESTART", fleet_of(r))

    # ---- 5. 内容回原样，历史不同：A 把 3 号退役再改回启用 ----
    check(unlock(t, 0x0003), "UNLOCK_0003", "OK")
    r2 = t.uds(0x0003, set_state(0x0003, 0x01))
    check(r2 == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "RETIRE_3_ON_0003", hexs(r2))
    gen_a, fp_a = stamp(t, 0x0003)
    check(gen_a == 3, "GEN_AFTER_RETIRE", str(gen_a))
    check(fp_a != want["0003"], "FP_AFTER_RETIRE_DIFFERS", fp_a)

    r2 = t.uds(0x0003, set_state(0x0003, 0x00))
    check(r2 == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "REVIVE_3_ON_0003", hexs(r2))
    gen_a2, fp_a2 = stamp(t, 0x0003)
    check(fp_a2 == want["0003"], "FP_BACK_TO_SAME", fp_a2)      # 内容真的回原样了
    check(gen_a2 == 4, "GEN_STILL_HIGHER", str(gen_a2))         # 但历史不一样

    others = ";".join("%04X:%d" % (sa, stamp(t, sa)[0]) for sa in (0x0006, 0x0007))
    check(stamp(t, 0x0006)[0] == 2 and stamp(t, 0x0007)[0] == 2, "OTHERS_UNTOUCHED", others)

if LEG == 3:
    # ---- 6. v1 旧文件：读得进来、世代归 0、指纹不变 ----
    with open(FP_FILE) as f:
        want = dict(x.split("=") for x in f.read().strip().split(";"))
    gen_a, fp_a = stamp(t, 0x0003)
    check(gen_a == 0, "V1_GEN_ZERO", str(gen_a))          # 旧文件没有 VER → 0
    check(fp_a == want["0003"], "V1_FP_SAME", fp_a)       # 内容没变，指纹当然一样
    check(digest(t, 0x0003) == "4/4/0/0", "V1_DIGEST", digest(t, 0x0003))

t.close()

print("LEG=%d" % LEG)
print("FAIL=%d" % FAIL)
sys.exit(0 if FAIL == 0 else 1)
