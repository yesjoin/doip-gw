#!/usr/bin/env python3
# ============================================================================
# m34_check.py —— M34 的场景助手：制造 N 次挡回，好让网关落一份账
#
# 这个脚本只做一件事：以指定的 SA 连撞 N 次 22 F1B0，然后输出撞中了几次。
# 三次调用 = 三份账；它们各自 5 / 3 / 2 次，供 --merge 合并验证"每份分布"。
#
# 用法：python3 m34_check.py <port> <sa-hex> <times> [ecu-hex]
# ============================================================================
import os
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
SA = int(sys.argv[2], 16)
TIMES = int(sys.argv[3])
ECU_FD = int(sys.argv[4], 16) if len(sys.argv) > 4 else int(os.environ.get("M34_TARGET", "0x0006"), 16)


def msg(ptype, payload=b""):
    return bytes([0x02, 0xFD]) + struct.pack("!H", ptype) + struct.pack("!I", len(payload)) + payload


def parse(data):
    if data is None or len(data) < 8:
        return None
    return struct.unpack("!H", data[2:4])[0], data[8:8 + struct.unpack("!I", data[4:8])[0]]


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

    def uds(self, req, quiet=2.5):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ECU_FD) + req))
        got = self._drain(1, quiet)
        return got[0][1] if got else None


def main():
    t = Tester(SA)
    act = t.activate()
    print("ACT=%s" % ("0x10" if act == 0x10 else "NONE"))

    hit = 0
    for _ in range(TIMES):
        if t.uds(bytes([0x22, 0xF1, 0xB0])) == bytes([0x7F, 0x22, 0x33]):
            hit += 1
    print("HIT_33=%d" % hit)

    t.s.close()
    print("FAIL=%d" % (0 if hit == TIMES else 1))
    return 0 if hit == TIMES else 1


if __name__ == "__main__":
    sys.exit(main())
