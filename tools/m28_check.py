#!/usr/bin/env python3
# ============================================================================
# m28_check.py —— M28 的场景：把"谁"送到 CAN 侧
#
# 要证明的三件事：
#   ① 开了 --stamp-sa，两台诊断仪各拿一个位子：29 位 ID 的最低字节变成 0xF1 / 0xF2，
#      ECU 从收到的首帧里读出"谁"，记进流水第七格 —— 两台**分得开**；
#   ② 11 位 ID（0x7A0）没有源地址那一格：同一套动作在它账上只能记 00（不知道），
#      这不是缺陷，是 11 位寻址的硬件事实；
#   ③ 不开 --stamp-sa（对照腿）：两台诊断仪在 ECU 账上**都是 0xF1**，分不开 ——
#      这就是"为什么要改源地址"的反面证据。
#
# 用法：python3 m28_check.py <port> <leg>     leg = 1（开）| 2（关，对照）
# ============================================================================
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1

SA_A = 0x0E00
SA_B = 0x0E01
ECU_FD = 0x0006     # 29 位寻址（18DA00F1 / 18DAF100）——有源地址那一格
ECU_11 = 0x0003     # 11 位寻址（7A0 / 7A8）——没有那一格
KEY_ID = 0x0001     # 出厂就有的一把
FAIL = 0
PASS = 0
QUIET = 0.45


def emit(key, value):
    print("%s=%s" % (key, value))


def check(cond, key, value):
    global FAIL, PASS
    emit(key, value)
    if cond:
        PASS += 1
    else:
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
    def __init__(self, sa):
        self.sa = sa
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=3.0)
        self.s.settimeout(3.0)
        self.buf = b""      # 每条连接自留一份：类属性会被所有实例共享（踩过）

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
        return out

    def uds(self, ta, req):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ta) + req))
        got = self._drain(1, 3.0)
        return got[0][1] if got else None

    def close(self):
        self.s.close()


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


def set_state(t, ta, key_id, want):
    """0207 改状态；返回是否拿到了 71 01 02 07 00"""
    r = t.uds(ta, bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want]))
    return r is not None and r[:5] == bytes([0x71, 0x01, 0x02, 0x07, 0x00])


def detail(t, ta, idx):
    """0x31 01 02 0B <idx> → dict（含 M28 的第七格 who）；越界/形状不对返回 None"""
    r = t.uds(ta, bytes([0x31, 0x01, 0x02, 0x0B, idx]))
    if r is None or len(r) != 20 or r[:4] != bytes([0x71, 0x01, 0x02, 0x0B]):
        return None
    sec = struct.unpack("!I", r[15:19])[0]
    return {
        "idx": r[4],
        "gen": (r[5] << 8) | r[6],
        "act": r[9],
        "key": (r[11] << 8) | r[12],
        "sec": sec,
        "who": r[19],
    }


def who_of(t, ta, idx):
    d = detail(t, ta, idx)
    return "%02X" % d["who"] if d else "NONE"


def main():
    if LEG == 1:
        # ---- 开了 --stamp-sa ----
        a = Tester(SA_A)
        code_a = a.activate()
        check(code_a == 0x10, "A_ACT", "0x%02X" % (code_a or 0))
        b = Tester(SA_B)
        code_b = b.activate()
        check(code_b == 0x10, "B_ACT", "0x%02X" % (code_b or 0))

        # 两台各自解锁同一台 29 位寻址的 ECU，各改一笔
        ua = unlock(a, ECU_FD)
        check(ua, "A_UNLOCK", "OK" if ua else "NO")
        check(set_state(a, ECU_FD, KEY_ID, 0x01), "A_RETIRE", "01")
        ub = unlock(b, ECU_FD)
        check(ub, "B_UNLOCK", "OK" if ub else "NO")
        check(set_state(b, ECU_FD, KEY_ID, 0x00), "B_REVIVE", "00")

        # 流水：最新那笔是 B（F2），上一笔是 A（F1）
        check(who_of(b, ECU_FD, 1) == "F2", "FD_J1_WHO", who_of(b, ECU_FD, 1))
        check(who_of(b, ECU_FD, 2) == "F1", "FD_J2_WHO", who_of(b, ECU_FD, 2))

        # 11 位那一台：同一套动作，账上只能记 00
        u11 = unlock(a, ECU_11)
        check(u11, "A11_UNLOCK", "OK" if u11 else "NO")
        check(set_state(a, ECU_11, KEY_ID, 0x01), "A11_RETIRE", "01")
        check(who_of(a, ECU_11, 1) == "00", "B11_J1_WHO", who_of(a, ECU_11, 1))

        a.close()
        b.close()

    elif LEG == 2:
        # ---- 不开 --stamp-sa（对照腿）----
        a = Tester(SA_A)
        ca = a.activate()
        check(ca == 0x10, "A_ACT", "0x%02X" % (ca or 0))
        b = Tester(SA_B)
        cb = b.activate()
        check(cb == 0x10, "B_ACT", "0x%02X" % (cb or 0))

        ua = unlock(a, ECU_FD)
        check(ua, "A_UNLOCK", "OK" if ua else "NO")
        check(set_state(a, ECU_FD, KEY_ID, 0x01), "A_RETIRE", "01")
        ub = unlock(b, ECU_FD)
        check(ub, "B_UNLOCK", "OK" if ub else "NO")
        check(set_state(b, ECU_FD, KEY_ID, 0x00), "B_REVIVE", "00")

        # 关键的反面证据：两台在 ECU 账上**都是 F1**，分不开
        check(who_of(b, ECU_FD, 1) == "F1", "PLAIN_J1_WHO", who_of(b, ECU_FD, 1))
        check(who_of(b, ECU_FD, 2) == "F1", "PLAIN_J2_WHO", who_of(b, ECU_FD, 2))
        check(who_of(b, ECU_FD, 1) == who_of(b, ECU_FD, 2), "PLAIN_SAME",
              "两台同值（改源地址之前，ECU 分不出谁是谁）")

        a.close()
        b.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
