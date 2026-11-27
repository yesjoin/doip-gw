#!/usr/bin/env python3
# ============================================================================
# m31_check.py —— M31 的场景：DID 白名单（0x22 读的"是什么"也分档）
#
# M30 只看服务号：0x22 一律"读档"。可读的东西不是一样重的东西：
#   VIN（F190）读走没关系，钥匙表（F1B0）读走等于把"这台车认哪些钥匙"交出去。
#
# 段一（开白名单，默认级别=受限）
#   读档：22 F190 / F186 通；22 F184（受限）/ F1B0（锁死）/ F1FF（没登记→受限）→ 33；
#         19 01（读 DTC，不是 DID 读）→ 不是 33：白名单不碰 0x19
#   写档：22 F184 通（受限要写档）、22 F1B0 仍 33、22 F1FF 通
#   刷写档：22 F1B0 也通
# 段二（对照腿，只开防火墙不开白名单）：读档读 F184 / F1B0 / F1FF 全都不是 33
# 段三（默认公开）：F1FF 通（默认公开），F1B0 仍 33（显式锁死压得住默认）
#
# 用法：python3 m31_check.py <port> <leg>      leg = 1 | 2 | 3
# ============================================================================
import os
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1
SA_READ = 0x0E00
SA_WRITE = 0x0E01
SA_FLASH = 0x0E02
ECU_FD = int(os.environ.get("M31_TARGET", "0x0006"), 16)
NRC_DENIED = 0x33
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
        return out

    def uds(self, req):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ECU_FD) + req))
        got = self._drain(1, 2.5)
        return got[0][1] if got else None

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def hexs(b):
    return b.hex().upper() if b else "NONE"


def nrc(resp):
    if resp is None or len(resp) != 3 or resp[0] != 0x7F:
        return None
    return resp[2]


def rd(t, did):
    return t.uds(bytes([0x22]) + struct.pack("!H", did))


def want_33(resp, key):
    """必须是网关挡的：7F 22 33"""
    check(resp == bytes([0x7F, 0x22, 0x33]), key + "_NRC", hexs(resp))


def want_not33(resp, key):
    """放行到了 ECU（ECU 自己答什么都行，只要不是网关的 33）"""
    ok = resp is not None and nrc(resp) != NRC_DENIED
    check(ok, key + "_NOT33", "NO33" if ok else "IS33")


def want_data(resp, prefix, key):
    ok = resp is not None and resp[:len(prefix)] == bytes(prefix)
    check(ok, key, hexs((resp or b"")[:len(prefix)]))


def main():
    if LEG == 1:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_data(rd(r, 0xF190), [0x62, 0xF1, 0x90], "R_F190")
        want_data(rd(r, 0xF186), [0x62, 0xF1, 0x86], "R_F186")
        want_33(rd(r, 0xF184), "R_F184")
        want_33(rd(r, 0xF1B0), "R_F1B0")
        want_33(rd(r, 0xF1FF), "R_F1FF")
        # 0x19 不是 DID 读：白名单不许碰它（ECU 答什么就是什么，只要不是 33）
        want_not33(r.uds(bytes([0x19, 0x01])), "R_19")

        w = Tester(SA_WRITE)
        check(w.activate() == 0x10, "W_ACT", "0x10")
        want_not33(rd(w, 0xF184), "W_F184")     # 受限：写档够
        want_33(rd(w, 0xF1B0), "W_F1B0")        # 锁死：写档不够
        want_not33(rd(w, 0xF1FF), "W_F1FF")     # 没登记=受限：写档够

        f = Tester(SA_FLASH)
        check(f.activate() == 0x10, "F_ACT", "0x10")
        want_not33(rd(f, 0xF1B0), "F_F1B0")     # 锁死：刷写档够
        want_not33(rd(f, 0xF1FF), "F_F1FF")

        r.close()
        w.close()
        f.close()

    elif LEG == 2:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_data(rd(r, 0xF190), [0x62, 0xF1, 0x90], "R_F190")
        want_not33(rd(r, 0xF184), "R_F184")
        want_not33(rd(r, 0xF1B0), "R_F1B0")
        want_not33(rd(r, 0xF1FF), "R_F1FF")
        r.close()

    elif LEG == 3:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_data(rd(r, 0xF190), [0x62, 0xF1, 0x90], "R_F190")
        want_not33(rd(r, 0xF1FF), "R_F1FF")     # 没登记 + 默认公开 → 过
        want_33(rd(r, 0xF1B0), "R_F1B0")        # 显式锁死 → 挡
        r.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2 / 3，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
