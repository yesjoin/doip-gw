#!/usr/bin/env python3
# ============================================================================
# m33_check.py —— M33 的场景：越权账（挡回能落盘、能读回、能被统计）
#
# M30/M31/M32 已经把该挡的都挡住了，但挡回只打在 stdout 一行 —— 进程一停就没了。
# 这一步验的是"事后能查"：账里到底记了谁、记了几次、什么原因。
#
# 段一（请求侧撞墙，三种里落两种）
#   读档 0x0E00 连读 12 次 22 F1B0 → 12 次 7F 22 33（原因：DID 级别不够）
#   读档 0x0E00 发 2E F184       → 7F 2E 33（原因：服务号档不够）
#   读档 0x0E00 发 31 01 02 03   → 7F 31 33（原因：服务号档不够）
#   写档 0x0E01 读 22 F1B0       → 7F 22 33（原因：DID 级别不够，换了台 SA 就是另一条）
#   账应有 4 条记录、合计 15 次；其中 0x0E00 那条 ×12 必须是十进制 12（不是 18）
#
# 段二（响应侧撞墙，落第三种）
#   只开 --did-guard-resp：读档读 F184 两次、F1B0 一次 → 62 都不出来（超时）
#   账应有 2 条记录、合计 3 次，原因是"响应被挡（数据没出去）"
#
# 用法：python3 m33_check.py <port> <leg>      leg = 1 | 2
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
ECU_FD = int(os.environ.get("M33_TARGET", "0x0006"), 16)
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

    def uds(self, req, quiet=2.5):
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ECU_FD) + req))
        got = self._drain(1, quiet)
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


def main():
    if LEG == 1:
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")

        # 连撞 12 次：这一条要验"账里的次数是十进制"，10 以上不能虚高。
        seen33 = 0
        last = None
        for _ in range(12):
            resp = rd(r, 0xF1B0)
            last = resp
            if resp == bytes([0x7F, 0x22, 0x33]):
                seen33 += 1
        check(seen33 == 12, "R_F1B0_33_TIMES", seen33)
        check(last == bytes([0x7F, 0x22, 0x33]), "R_F1B0_LAST", hexs(last))

        # 读档想做写档的事：0x2E 写 DID / 0x31 刷写 → 两种都该挡（原因不同层）
        resp = r.uds(bytes([0x2E, 0xF1, 0x84]) + b"\x00\x00\x00\x01")
        check(resp == bytes([0x7F, 0x2E, 0x33]), "R_2E_NRC", hexs(resp))
        resp = r.uds(bytes([0x31, 0x01, 0x02, 0x03]))
        check(resp == bytes([0x7F, 0x31, 0x33]), "R_31_NRC", hexs(resp))

        # 换一台 SA（写档）读锁死 DID：仍是 DID 抬档挡的，但"有的档"不同 → 另一条记录
        w = Tester(SA_WRITE)
        check(w.activate() == 0x10, "W_ACT", "0x10")
        resp = rd(w, 0xF1B0)
        check(resp == bytes([0x7F, 0x22, 0x33]), "W_F1B0_NRC", hexs(resp))

        r.close()
        w.close()

    elif LEG == 2:
        # 只开响应侧：请求侧全放行，挡发生在 62 回来的那一刻。
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")

        # 公开 DID 照旧能读（62 出来）
        resp = rd(r, 0xF190)
        check(resp is not None and resp[:3] == bytes([0x62, 0xF1, 0x90]), "R_F190",
              hexs((resp or b"")[:3]))

        timedout = 0
        for _ in range(2):
            if rd(r, 0xF184) is None:
                timedout += 1
        check(timedout == 2, "R_F184_TIMEOUT_TIMES", timedout)
        got = rd(r, 0xF1B0)
        check(got is None, "R_F1B0_TIMEOUT", "TIMEOUT" if got is None else hexs(got))

        r.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
