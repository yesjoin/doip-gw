#!/usr/bin/env python3
# ============================================================================
# m26_check.py —— M26 的场景：变更流水（谁改的 / 什么时候 / 动了哪把）
#
# 要证明的四件事：
#   ① **没有变更这件事要能说出口**：出厂表 F1B3 回 62 F1 B3 00，不是一条假记录；
#   ② **一条流水记全六件事**：世代、指纹、动作、通道、keyId、第几次上电 + 秒；
#   ③ **广播改和逐台改分得开**：同一张表，chan=02 与 chan=01 是两种风险；
#   ④ **流水活过重启，而且时间不骗人**：重启后旧的还是"第 1 次上电"，
#      新的那笔才是"第 2 次上电" —— 这就是"没有 RTC 时唯一诚实的时间"。
#
# 用法：python3 m26_check.py <port> <leg>     leg = 1 | 2 | 3
#   1 = 全新表：出厂无流水 → 装一把 → 广播退役 → 逐台复活
#   2 = 同一批文件重启：条数/世代/上电序各自对得上；再改一笔，新账记第 2 次上电
#   3 = 把 A 的文件降级成 v2：表和世代还在，流水没了（这件事必须被说出来）
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
FP_FILE = "/tmp/m26_state.txt"


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


def overview(t, ta):
    """0x22 F1B3 → (条数, 最近动作, 最近 keyId)；没有变更时 (0, 0, 0)"""
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB3]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB3]):
        return None
    if len(r) == 4 and r[3] == 0:
        return (0, 0, 0)
    if len(r) < 7:
        return None
    return (r[3], r[4], (r[5] << 8) | r[6])


def detail(t, ta, idx):
    """0x31 01 02 0B <idx> → dict；越界/格式不对返回 None"""
    r = t.uds(ta, bytes([0x31, 0x01, 0x02, 0x0B, idx]))
    if r is None or len(r) != 19 or r[:4] != bytes([0x71, 0x01, 0x02, 0x0B]):
        return None
    return {
        "idx": r[4],
        "gen": (r[5] << 8) | r[6],
        "fp": "%04X" % ((r[7] << 8) | r[8]),
        "act": r[9],
        "chan": r[10],
        "key": (r[11] << 8) | r[12],
        "boot": (r[13] << 8) | r[14],
        "sec": struct.unpack("!I", r[15:19])[0],
    }


def stamp(t, ta):
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB2]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB2]) or len(r) < 7:
        return None, "NONE"
    return (r[3] << 8) | r[4], "%02X%02X" % (r[5], r[6])


def digest(t, ta):
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB1]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB1]) or len(r) < 7:
        return "NONE"
    return "%d/%d/%d/%d" % (r[3], r[4], r[5], r[6])


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

if LEG == 1:
    # ---- 1. 出厂：没有变更这件事要能说出口 ----
    check(overview(t, 0x0003) == (0, 0, 0), "BOOT_NO_CHANGE", "62F1B300")

    # ---- 2. 三台都装 3 号（物理寻址，要各自解锁）----
    for sa in ECUS:
        check(unlock(t, sa), "UNLOCK_%04X" % sa, "OK")
    ok_n = 0
    for sa in ECUS:
        if t.uds(sa, install(0x0003)) == bytes([0x71, 0x01, 0x02, 0x06, 0x00]):
            ok_n += 1
    check(ok_n == 3, "INSTALL_ALL", "成 %d / 3" % ok_n)

    ov = {sa: overview(t, sa) for sa in ECUS}
    check(all(ov[sa] == (1, 0x01, 0x0003) for sa in ECUS), "AFTER_INSTALL_OVERVIEW",
          ";".join("%04X:%d/%02X/%04X" % (sa, ov[sa][0], ov[sa][1], ov[sa][2]) for sa in ECUS))

    d = detail(t, 0x0003, 1)
    check(d is not None and d["gen"] == 1 and d["act"] == 0x01 and d["chan"] == 0x01
          and d["key"] == 0x0003 and d["boot"] == 1 and d["sec"] < 600,
          "DETAIL_INSTALL",
          ("gen=%d,act=%02X,chan=%02X,key=%04X,boot=%d,sec=%d" %
           (d["gen"], d["act"], d["chan"], d["key"], d["boot"], d["sec"])) if d else "NONE")

    # ---- 3. 一条广播改三台：通道要记成"广播"，不是"物理" ----
    r, nack = t.broadcast(set_state(0x0003, 0x01), expect=len(ECUS))
    check(len(r) == 3 and all(v == bytes([0x71, 0x01, 0x02, 0x07, 0x00]) for v in r.values()),
          "BC_RETIRE_OK", ";".join("%04X=%s" % (sa, hexs(v)) for sa, v in r.items()))

    ov = {sa: overview(t, sa) for sa in ECUS}
    check(all(ov[sa] == (2, 0x02, 0x0003) for sa in ECUS), "AFTER_BC_OVERVIEW",
          ";".join("%04X:%d/%02X/%04X" % (sa, ov[sa][0], ov[sa][1], ov[sa][2]) for sa in ECUS))

    chans = []
    chans_ok = True
    for sa in ECUS:
        dd = detail(t, sa, 1)
        if dd is None:
            chans_ok = False
            chans.append("%04X:NONE" % sa)
            continue
        chans.append("%04X:%02X" % (sa, dd["chan"]))
        chans_ok = chans_ok and dd["chan"] == 0x02 and dd["act"] == 0x02
    check(chans_ok, "BC_CHANNEL_02", ";".join(chans))

    # ---- 4. 逐台复活 3 号：动作记成"复活"（03），不是"装入" ----
    check(t.uds(0x0003, set_state(0x0003, 0x00)) == bytes([0x71, 0x01, 0x02, 0x07, 0x00]),
          "REVIVE_OK", "71 01 02 07 00")
    d = detail(t, 0x0003, 1)
    check(d is not None and d["act"] == 0x03 and d["gen"] == 3 and d["chan"] == 0x01
          and d["sec"] > 0, "DETAIL_REVIVE",
          ("act=%02X,gen=%d,chan=%02X,sec=%d" %
           (d["act"], d["gen"], d["chan"], d["sec"])) if d else "NONE")

    # ---- 5. 流水里的指纹 = 现在报出来的指纹（对账口径一致）----
    gen, fp = stamp(t, 0x0003)
    d = detail(t, 0x0003, 1)
    check(d is not None and d["fp"] == fp and d["gen"] == gen, "JOURNAL_FP_MATCH",
          "OK" if (d is not None and d["fp"] == fp) else "流水 %s / F1B2 %s" % (d["fp"] if d else "NONE", fp))

    # 老一笔（第 2 条 = 广播退役）也要在，且还记着"第 1 次上电"
    d2 = detail(t, 0x0003, 2)
    check(d2 is not None and d2["act"] == 0x02 and d2["boot"] == 1, "OLD_ENTRY_KEPT",
          ("act=%02X,boot=%d" % (d2["act"], d2["boot"])) if d2 else "NONE")

    with open(FP_FILE, "w") as f:
        f.write("gen=%d;fp=%s;count=%d;count_b=%d\n" % (gen, fp, overview(t, 0x0003)[0],
                                                        overview(t, 0x0006)[0]))

if LEG == 2:
    with open(FP_FILE) as f:
        want = dict(x.split("=") for x in f.read().strip().split(";"))

    # ---- 6. 重启：条数与世代都活过来了 ----
    ov = {sa: overview(t, sa) for sa in ECUS}
    check(ov[0x0003][0] == 3 and ov[0x0006][0] == 2 and ov[0x0007][0] == 2,
          "RESTART_COUNT", ";".join("%04X:%d" % (sa, ov[sa][0]) for sa in ECUS))
    gen, fp = stamp(t, 0x0003)
    check(gen == int(want["gen"]) and fp == want["fp"], "RESTART_STAMP",
          "gen=%s,fp=%s" % (gen, fp))

    # ---- 7. 旧账的时间不能被"现在"污染 ----
    d = detail(t, 0x0003, 1)
    check(d is not None and d["boot"] == 1, "RESTART_OLD_BOOT_STILL_1",
          ("boot=%d" % d["boot"]) if d else "NONE")

    # ---- 8. 再改一笔：新账记"第 2 次上电"，且秒数是这次上电后过的 ----
    check(unlock(t, 0x0003), "UNLOCK_0003", "OK")
    check(t.uds(0x0003, install(0x0004)) == bytes([0x71, 0x01, 0x02, 0x06, 0x00]),
          "INSTALL_4", "71 01 02 06 00")
    d = detail(t, 0x0003, 1)
    check(d is not None and d["boot"] == 2 and d["act"] == 0x01 and d["key"] == 0x0004
          and d["gen"] == int(want["gen"]) + 1, "NEW_ENTRY_BOOT2",
          ("gen=%d,boot=%d,key=%04X,sec=%d" % (d["gen"], d["boot"], d["key"], d["sec"]))
          if d else "NONE")

    # 上一条(第 2 条)还是"第 1 次上电" —— 时间不跟着新账一起往前跑
    d2 = detail(t, 0x0003, 2)
    check(d2 is not None and d2["boot"] == 1, "OLD_STAYS_BOOT1",
          ("boot=%d" % d2["boot"]) if d2 else "NONE")

    check(overview(t, 0x0003)[0] == 4, "COUNT_AFTER4", str(overview(t, 0x0003)[0]))

if LEG == 3:
    # ---- 9. 降级成 v2 之后：表与世代还在，流水没了，而且要说出来 ----
    check(digest(t, 0x0003) == "4/4/0/0", "V2_DIGEST", digest(t, 0x0003))
    gen, fp = stamp(t, 0x0003)
    check(gen == 4, "V2_GEN_KEPT", str(gen))
    check(overview(t, 0x0003) == (0, 0, 0), "V2_NO_JOURNAL", "62F1B300")

t.close()

print("LEG=%d" % LEG)
print("FAIL=%d" % FAIL)
sys.exit(0 if FAIL == 0 else 1)
