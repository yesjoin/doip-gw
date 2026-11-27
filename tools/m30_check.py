#!/usr/bin/env python3
# ============================================================================
# m30_check.py —— M30 的场景：按操作分权限（读 < 写 < 刷写）
#
# 段一要证明的是"三档真的分开了"：
#   0x0E00 只有读档 → 读得了 VIN、保活得回，但 0x2E / 0x10 / 0x27 / 0x34 / 不认识的服务号
#                      一律被网关替 ECU 回 7F <SID> 33（**请求根本没上总线**）；
#   0x0E01 写档     → 切会话、解锁、写 DID 都通，但 0x34 还是被挡（刷写比写高一档）；
#   0x0E02 刷写档   → 连 0x34 都放过去，ECU 自己回 7F 34 22（"没擦除"）—— 这个 22 就是
#                      "网关放行了、答案来自 ECU"的证据（33 才是网关挡的）。
#
# 段二（对照腿，不开 --enforce-ops）：同一台读档诊断仪发 0x2E / 0x34，
#   **拿不到 33** —— 没有这层的时候，请求照样递到 ECU。这是"为什么要这一层"的反面证据。
#
# 段三（默认档）：开了防火墙但一台都不授权，默认档 = 读 → 谁都能读、谁也写不了。
#
# 用法：python3 m30_check.py <port> <leg>     leg = 1 | 2 | 3
# ============================================================================
import os
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
LEG = int(sys.argv[2]) if len(sys.argv) > 2 else 1

SA_READ = 0x0E00     # 读档
SA_WRITE = 0x0E01    # 写档
SA_FLASH = 0x0E02    # 刷写档（同时也能读能写：阶梯）
ECU_FD = int(os.environ.get("M30_TARGET", "0x0006"), 16)   # 段三那条腿只挂了 0x0003 一台
NRC_DENIED = 0x33
FAIL = 0
PASS = 0

IMG = bytes(range(32))     # 0x34 的载荷随便给一点，重点是"网关放不放"


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
    """7F <SID> <NRC> → NRC；别的形状 → 'NONE'"""
    if resp is None or len(resp) != 3 or resp[0] != 0x7F:
        return None
    return resp[2]


def key_of(seed):
    return ((seed + 0x12345678) ^ 0xA5A5A5A5) & 0xFFFFFFFF


def unlock(t):
    r = t.uds(bytes([0x10, 0x02]))
    if r is None or r[:2] != bytes([0x50, 0x02]):
        return False, hexs(r)
    r = t.uds(bytes([0x27, 0x01]))
    if r is None or len(r) != 6:
        return False, hexs(r)
    seed = struct.unpack("!I", r[2:6])[0]
    r = t.uds(bytes([0x27, 0x02]) + struct.pack("!I", key_of(seed)))
    return (r == bytes([0x67, 0x02])), hexs(r)


def read_vin(t):
    return t.uds(bytes([0x22, 0xF1, 0x90]))


def write_fp(t, v=0xA5A5A5A5):
    return t.uds(bytes([0x2E, 0xF1, 0x84]) + struct.pack("!I", v))


def request_download(t):
    return t.uds(bytes([0x34, 0x00, 0x44]) + struct.pack("!II", 0x00400000, len(IMG)))


def main():
    if LEG == 1:
        # ---------- 读档 ----------
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        vin = read_vin(r)
        check(vin is not None and len(vin) >= 20 and vin[:3] == bytes([0x62, 0xF1, 0x90]),
              "R_VIN", hexs(vin[:3]))
        sess = r.uds(bytes([0x22, 0xF1, 0x86]))
        check((sess or b"")[:3] == bytes([0x62, 0xF1, 0x86]), "R_SESSION", hexs((sess or b"")[:3]))

        d2e = write_fp(r)
        check(nrc(d2e) == NRC_DENIED, "R_2E_NRC", hexs(d2e))
        d10 = r.uds(bytes([0x10, 0x02]))
        check(nrc(d10) == NRC_DENIED, "R_10_NRC", hexs(d10))
        d27 = r.uds(bytes([0x27, 0x01]))
        check(nrc(d27) == NRC_DENIED, "R_27_NRC", hexs(d27))
        d34 = request_download(r)
        check(nrc(d34) == NRC_DENIED, "R_34_NRC", hexs(d34))
        d39 = r.uds(bytes([0x39]))
        check(nrc(d39) == NRC_DENIED, "R_39_NRC", hexs(d39))

        # ---------- 写档 ----------
        w = Tester(SA_WRITE)
        check(w.activate() == 0x10, "W_ACT", "0x10")
        check((read_vin(w) or b"")[:3] == bytes([0x62, 0xF1, 0x90]), "W_VIN", "读也通（阶梯）")
        s10 = w.uds(bytes([0x10, 0x02]))
        check((s10 or b"")[:2] == bytes([0x50, 0x02]), "W_10", hexs((s10 or b"")[:2]))
        ok, _ = unlock(w)
        check(ok, "W_UNLOCK", "OK" if ok else "NO")
        e2e = write_fp(w)
        check(e2e is not None and e2e[:3] == bytes([0x6E, 0xF1, 0x84]), "W_2E", hexs(e2e))
        w34 = request_download(w)
        check(nrc(w34) == NRC_DENIED, "W_34_NRC", hexs(w34))

        # ---------- 刷写档 ----------
        f = Tester(SA_FLASH)
        check(f.activate() == 0x10, "F_ACT", "0x10")
        s10f = f.uds(bytes([0x10, 0x02]))
        check((s10f or b"")[:2] == bytes([0x50, 0x02]), "F_10", hexs((s10f or b"")[:2]))
        okf, _ = unlock(f)
        check(okf, "F_UNLOCK", "OK" if okf else "NO")
        e2ef = write_fp(f, 0x5A5A5A5A)
        check(e2ef is not None and e2ef[:3] == bytes([0x6E, 0xF1, 0x84]), "F_2E", hexs(e2ef))
        f34 = request_download(f)
        # ★ 关键：33 是"网关挡的"，22 是"ECU 挡的"。这里必须是 22 —— 请求真的出去了。
        check(nrc(f34) == 0x22, "F_34_NRC", hexs(f34))

        r.close()
        w.close()
        f.close()

    elif LEG == 2:
        # ---------- 对照腿：不开防火墙 ----------
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        check((read_vin(r) or b"")[:3] == bytes([0x62, 0xF1, 0x90]), "R_VIN", "读照旧")
        d2e = write_fp(r)
        check(nrc(d2e) != NRC_DENIED, "R_2E_NOT33", hexs(d2e))
        check(nrc(d2e) == 0x7F, "R_2E_ECU", hexs(d2e))
        d34 = request_download(r)
        check(nrc(d34) != NRC_DENIED, "R_34_NOT33", hexs(d34))
        check(nrc(d34) == 0x7F, "R_34_ECU", hexs(d34))
        r.close()

    elif LEG == 3:
        # ---------- 默认档 = 读：一台都不授权 ----------
        r = Tester(SA_READ)
        check(r.activate() == 0x10, "R_ACT", "0x10")
        check((read_vin(r) or b"")[:3] == bytes([0x62, 0xF1, 0x90]), "R_VIN", hexs((read_vin(r) or b"")[:3]))
        d2e = write_fp(r)
        check(nrc(d2e) == NRC_DENIED, "R_2E_NRC", hexs(d2e))
        r.close()

    else:
        check(False, "LEG_BAD", "段号只认 1 / 2 / 3，收到 %s" % LEG)

    print("PASS=%d" % PASS)
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
