#!/usr/bin/env python3
# ============================================================================
# m29_check.py —— M29 的场景：位子 → 真身份
#
# 两段要演的是"账能不能把位子还原成人"：
#   段一（不撞位子）：A 先激活占 1 号位子，B 后激活占 2 号位子，两笔动作各记 F1 / F2。
#     网关账上 1→0x0E00、2→0x0E01，**一一对应**，对账工具该说"可唯一还原"。
#   段二（撞位子）：A 干完就断开（1 号位子归还），B 再来拿到的还是**1 号位子**。
#     ECU 账上两笔都是 F1 —— 网关账上 1 号位子先后住过 0x0E00 和 0x0E02。
#     这时对账工具不许猜，必须报"歧义 + 候选"，--strict 必须失败。
#
# 用法：python3 m29_check.py <port> <leg>     leg = 1（不撞）| 2（撞）
# ============================================================================
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1

SA_A = 0x0E00
SA_B = 0x0E01      # 段一用的第二台
SA_C = 0x0E02      # 段二用的第二台（A 断开之后才来，所以会拿到同一个位子）
ECU_FD = 0x0006    # 29 位寻址（18DA00F1 / 18DAF100）—— 有源地址那一格
KEY_ID = 0x0001
FAIL = 0
PASS = 0


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
        self.buf = b""      # 每条连接一份

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
        try:
            self.s.close()
        except OSError:
            pass


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
    r = t.uds(ta, bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want]))
    return r is not None and r[:5] == bytes([0x71, 0x01, 0x02, 0x07, 0x00])


def detail(t, ta, idx):
    r = t.uds(ta, bytes([0x31, 0x01, 0x02, 0x0B, idx]))
    if r is None or len(r) != 20 or r[:4] != bytes([0x71, 0x01, 0x02, 0x0B]):
        return None
    return {
        "idx": r[4],
        "key": (r[11] << 8) | r[12],
        "who": r[19],
    }


def who_of(t, ta, idx):
    d = detail(t, ta, idx)
    return "%02X" % d["who"] if d else "NONE"


def do_one(t, want):
    """解锁 + 改状态，返回 (解锁 ok, 改状态 ok)"""
    u = unlock(t, ECU_FD)
    s = set_state(t, ECU_FD, KEY_ID, want) if u else False
    return u, s


def main():
    if LEG == 1:
        # ---- 不撞位子：两台同时在，位子 1 / 2 分得开 ----
        a = Tester(SA_A)
        ca = a.activate()
        check(ca == 0x10, "A_ACT", "0x%02X" % (ca or 0))
        ua, sa_ = do_one(a, 0x01)
        check(ua, "A_UNLOCK", "OK" if ua else "NO")
        check(sa_, "A_RETIRE", "01")

        # A 还连着，B 才进来 —— 它只能拿 2 号位子
        b = Tester(SA_B)
        cb = b.activate()
        check(cb == 0x10, "B_ACT", "0x%02X" % (cb or 0))
        ub, sb = do_one(b, 0x00)
        check(ub, "B_UNLOCK", "OK" if ub else "NO")
        check(sb, "B_REVIVE", "00")

        check(who_of(b, ECU_FD, 1) == "F2", "J1_WHO", who_of(b, ECU_FD, 1))
        check(who_of(b, ECU_FD, 2) == "F1", "J2_WHO", who_of(b, ECU_FD, 2))

        a.close()
        b.close()

    elif LEG == 2:
        # ---- 撞位子：A 干完就走，B 来的时候拿到同一个位子 ----
        a = Tester(SA_A)
        ca = a.activate()
        check(ca == 0x10, "A_ACT", "0x%02X" % (ca or 0))
        ua, sa_ = do_one(a, 0x01)
        check(ua, "A_UNLOCK", "OK" if ua else "NO")
        check(sa_, "A_RETIRE", "01")
        a.close()                       # 断开 → 网关归还 1 号位子
        time.sleep(0.4)                 # 让网关的 I/O 线程先处理完断开

        c = Tester(SA_C)
        cc = c.activate()
        check(cc == 0x10, "C_ACT", "0x%02X" % (cc or 0))
        uc, sc = do_one(c, 0x00)
        check(uc, "C_UNLOCK", "OK" if uc else "NO")
        check(sc, "C_REVIVE", "00")

        # 两笔都是 F1 —— ECU 分不出这两笔是谁干的，这正是要对账的原因
        check(who_of(c, ECU_FD, 1) == "F1", "J1_WHO", who_of(c, ECU_FD, 1))
        check(who_of(c, ECU_FD, 2) == "F1", "J2_WHO", who_of(c, ECU_FD, 2))
        check(who_of(c, ECU_FD, 1) == who_of(c, ECU_FD, 2), "SAME_WHO",
              "两笔同位子（ECU 侧无法区分，只能靠网关账判歧义）")

        c.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
