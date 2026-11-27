#!/usr/bin/env python3
# ============================================================================
# m32_check.py —— M32 的场景：响应方向也按 DID 过滤
#
# M30/M31 挡的是**请求**（诊断仪想读什么）。但数据真正流出去靠的是
# ECU 答回来的 0x62 <DID> <数据>。请求侧被绕过（哪怕配置漏写一条）时，
# 响应侧是最后一道闸 —— 纵深防御的第一条就是"别指望前面那层一定没破"。
#
# 段一（响应侧独立开，请求侧**故意不开**白名单）
#   读档：22 F190（公开）→ 请求放行 → 62 F190 响应也放行（读档够）
#         22 F184（受限）→ 请求放行 → 62 F184 被响应侧挡（要写档）→ 超时
#         22 F1B0（锁死）→ 请求放行 → 62 F1B0 被响应侧挡（要刷写档）→ 超时
#   写档：22 F184 → 62 F184 放行（写档够）
#   刷写档：22 F1B0 → 62 F1B0 放行（刷写档够）
# 段二（对照腿，响应侧关）：读档读 F1B0 → 62 F1B0 原样出来（数据流出去）
# 段三（两条腿都开）：读档读 F1B0 → 7F 22 33（请求侧先挡，到不了响应侧）
#
# 用法：python3 m32_check.py <port> <leg>      leg = 1 | 2 | 3
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
ECU_FD = int(os.environ.get("M32_TARGET", "0x0006"), 16)
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


def rd(t, did):
    return t.uds(bytes([0x22]) + struct.pack("!H", did))


def want_data(resp, prefix, key):
    ok = resp is not None and resp[:len(prefix)] == bytes(prefix)
    check(ok, key, hexs((resp or b"")[:len(prefix)]))


def want_33(resp, key):
    check(resp == bytes([0x7F, 0x22, 0x33]), key, hexs(resp))


def want_timeout(resp, key):
    """响应侧被挡 = 这条 0x62 不发出去，诊断仪收不到 → 超时（None）。"""
    check(resp is None, key, "TIMEOUT" if resp is None else hexs(resp))


def main():
    if LEG == 1:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_data(rd(r, 0xF190), [0x62, 0xF1, 0x90], "R_F190")   # 公开：响应放行
        want_timeout(rd(r, 0xF184), "R_F184")                     # 受限：要写档 → 挡
        want_timeout(rd(r, 0xF1B0), "R_F1B0")                     # 锁死：要刷写档 → 挡

        w = Tester(SA_WRITE)
        check(w.activate() == 0x10, "W_ACT", "0x10")
        want_data(rd(w, 0xF184), [0x62, 0xF1, 0x84], "W_F184")   # 写档够受限 → 放行

        f = Tester(SA_FLASH)
        check(f.activate() == 0x10, "F_ACT", "0x10")
        want_data(rd(f, 0xF1B0), [0x62, 0xF1, 0xB0], "F_F1B0")   # 刷写档够锁死 → 放行

        r.close()
        w.close()
        f.close()

    elif LEG == 2:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_data(rd(r, 0xF190), [0x62, 0xF1, 0x90], "R_F190")
        want_data(rd(r, 0xF1B0), [0x62, 0xF1, 0xB0], "R_F1B0")   # 响应侧关 → 数据流出去
        r.close()

    elif LEG == 3:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        want_33(rd(r, 0xF1B0), "R_F1B0")                          # 请求侧先挡
        r.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2 / 3，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
