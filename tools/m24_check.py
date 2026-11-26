#!/usr/bin/env python3
# ============================================================================
# m24_check.py —— M24 的场景：车队钥匙清单（广播表决 + 逐台下发 + 摘要核对）
#
# 一句话：**广播只能"投票"，不能"搬数据"。**
#   · 功能寻址的请求必须是单帧（经典帧 7 字节，FD 62）—— 装钥匙的请求 38 字节，
#     网关会直接回 0x8003 / 0x04（MessageTooLarge），一条都发不出去；
#   · 所以车队的正确顺序是：**先广播问一圈能不能装（020A），再逐台下发（0206），最后广播核对摘要（F1B1）**；
#   · 摘要压在 4 个计数里，正好 7 字节，刚好塞得进一个经典单帧 —— 这不是巧合，是设计；
#   · 表决通过 ≠ 装成功：020A 只看容量，不看会话，真正装的时候门还在（未解锁那台回 7F 31 7F）。
#
# 腿一（三台健康 ECU）：摘要一致 → 广播表决都"能装" → 广播装钥匙被网关拒（太大）
#                        → 逐台装 3 号 → 摘要变成 3/3/0/0 → 只退役一台 → 摘要不一致并点名
#                        → 补齐 → 再吊销 1 号 → 三台 3/1/1/1。
# 腿二（0x0006 的表文件坏了）：广播表决 → 两台 00、一台 02（表坏）
#                        → 逐台装 4 号：两台 00、坏台 7F 31 22 → 摘要不一致并点名 0006。
#
# 用法：python3 m24_check.py <port> <leg>     leg = 1 | 2
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
QUIET = 0.45          # 收多响应的静默窗口（M11 的口径）


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
        # ★ 收报文的缓冲区：一次 recv 里可能躺着好几条 DoIP 消息。
        #   广播的应答几乎是同时到的，内核会把它们塞进同一个 TCP 段里；
        #   直接 `parse(recv())` 只解析第一条，其余的就被静默丢掉了 ——
        #   症状是"网关明明回了 3 条，脚本只看到 1 条"（M24 第一次跑就是这么红的）。
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
        """从缓冲区取一条完整的 DoIP 消息；超时返回 None"""
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
        """收到 stop_after 条 ECU 应答或静默 quiet 秒为止；返回 [(sa, uds)]，NACK 用 sa=0xFFFF"""
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
                out.append((0xFFFF, r[1]))          # 否定应答：整条消息
        return out

    def uds(self, ta, req):
        """物理寻址：等一条 ECU 应答，返回 UDS 字节"""
        self.s.sendall(msg(0x8001, struct.pack("!HH", self.sa, ta) + req))
        got = self._drain(1, 3.0)
        return got[0][1] if got else None

    def broadcast(self, req, expect=None):
        """功能寻址：返回 ({responder_sa: uds}, nack_payload_or_None)"""
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


def read_table(t, ta):
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB0]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB0]):
        return "NONE"
    rows = r[3:]
    out = []
    for i in range(0, len(rows) - 2, 3):
        out.append(((rows[i] << 8) | rows[i + 1], rows[i + 2]))
    return ",".join("%04X=%02X" % (k, v) for k, v in sorted(out))


def digest(t, ta):
    """0x22 F1B1 → 「总/启/退/吊」；读不到返回 NONE"""
    r = t.uds(ta, bytes([0x22, 0xF1, 0xB1]))
    if r is None or r[:3] != bytes([0x62, 0xF1, 0xB1]) or len(r) < 7:
        return "NONE"
    return "%d/%d/%d/%d" % (r[3], r[4], r[5], r[6])


def install(key_id, key):
    return bytes([0x31, 0x01, 0x02, 0x06]) + struct.pack("!H", key_id) + key


def set_state(key_id, want):
    return bytes([0x31, 0x01, 0x02, 0x07]) + struct.pack("!H", key_id) + bytes([want])


def fleet(fn, t):
    return ";".join("%04X:%s" % (sa, fn(t, sa)) for sa in ECUS)


def fleet_of(resp):
    return ",".join("%04X=%s" % (sa, hexs(resp[sa])) for sa in ECUS if sa in resp)


t = Tester()
code = t.activate()
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))

# ---- 下面三条只在腿一验：腿二的三台表已经不是"刚上电"的样子（腿一改过的状态落了盘），
#      而且 0x0006 本来就被写坏了 —— 拿"出厂两把"去断言它，测的就不是这一步的事。
if LEG == 1:
    # 摘要（F1B1，7 字节）可以广播 —— 全零表：2 把都在启用
    r, nack = t.broadcast(bytes([0x22, 0xF1, 0xB1]), expect=len(ECUS))
    check(nack is None and len(r) == 3, "BC_DIGEST_COUNT", str(len(r)))
    check(all(v == bytes([0x62, 0xF1, 0xB1, 0x02, 0x02, 0x00, 0x00]) for v in r.values()),
          "BC_DIGEST_BOOT", fleet_of(r))

    # 装钥匙的请求 38 字节：功能寻址发不出去，网关直接 0x8003 / 0x04
    r, nack = t.broadcast(install(0x0003, demo_key(3)), expect=len(ECUS))
    check(nack is not None and nack[-1] == 0x04, "BC_INSTALL_NACK", hexs(nack))
    check(len(r) == 0, "BC_INSTALL_REPLIES", str(len(r)))

    # 广播表决：现在能不能装一把
    r, _ = t.broadcast(bytes([0x31, 0x01, 0x02, 0x0A]), expect=len(ECUS))
    check(all(v == bytes([0x71, 0x01, 0x02, 0x0A, 0x00]) for v in r.values()),
          "BC_CAP", fleet_of(r))

if LEG == 1:
    check(fleet(read_table, t) == "0003:0001=00,0002=00;0006:0001=00,0002=00;0007:0001=00,0002=00",
          "TABLES_BOOT", fleet(read_table, t))

    # 逐台解锁 → 逐台下发（广播搬不动 38 字节，只能一台一台来）
    for sa in ECUS:
        check(unlock(t, sa), "UNLOCK_%04X" % sa, "OK")

    allok = True
    for sa in ECUS:
        r2 = t.uds(sa, install(0x0003, demo_key(3)))
        allok = allok and r2 == bytes([0x71, 0x01, 0x02, 0x06, 0x00])
    check(allok, "PHYS_INSTALL_3", "三台都 00" if allok else "有台没装上")

    check(fleet(digest, t) == "0003:3/3/0/0;0006:3/3/0/0;0007:3/3/0/0",
          "DIGEST_AFTER_INSTALL", fleet(digest, t))

    # 只退役一台 → 摘要立刻不一致（这就是"广播核对"的意义：它比读全表便宜）
    r2 = t.uds(0x0003, set_state(0x0003, 0x01))
    check(r2 == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "RETIRE_3_ON_0003", hexs(r2))
    d = fleet(digest, t)
    check(d == "0003:3/2/1/0;0006:3/3/0/0;0007:3/3/0/0", "DIGEST_SPLIT", d)

    # 把另外两台补齐（同样的事做两次），摘要回到一致
    for sa in (0x0006, 0x0007):
        r2 = t.uds(sa, set_state(0x0003, 0x01))
        check(r2 == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "RETIRE_3_ON_%04X" % sa, hexs(r2))
    check(fleet(digest, t) == "0003:3/2/1/0;0006:3/2/1/0;0007:3/2/1/0",
          "DIGEST_AGAIN", fleet(digest, t))

    # 三台一起吊销 1 号 → 摘要 3/1/1/1
    for sa in ECUS:
        r2 = t.uds(sa, set_state(0x0001, 0x02))
        check(r2 == bytes([0x71, 0x01, 0x02, 0x07, 0x00]), "REVOKE_1_ON_%04X" % sa, hexs(r2))
    check(fleet(digest, t) == "0003:3/1/1/1;0006:3/1/1/1;0007:3/1/1/1",
          "DIGEST_FINAL", fleet(digest, t))

if LEG == 2:
    # 0x0006 的表文件在启动前被写坏：它谁也不认，也不许写
    r, _ = t.broadcast(bytes([0x31, 0x01, 0x02, 0x0A]), expect=len(ECUS))
    check(r.get(0x0003) == bytes([0x71, 0x01, 0x02, 0x0A, 0x00]) and
          r.get(0x0007) == bytes([0x71, 0x01, 0x02, 0x0A, 0x00]) and
          r.get(0x0006) == bytes([0x71, 0x01, 0x02, 0x0A, 0x02]),
          "BC_CAP_PARTIAL", fleet_of(r))

    # 表决已经告诉你有台装不了 —— 但真下发时"门"还要各自过一遍（这里三台都已解锁）
    for sa in ECUS:
        check(unlock(t, sa), "UNLOCK_%04X" % sa, "OK")

    got = {}
    for sa in ECUS:
        got[sa] = t.uds(sa, install(0x0004, demo_key(4)))
    check(got.get(0x0003) == bytes([0x71, 0x01, 0x02, 0x06, 0x00]) and
          got.get(0x0007) == bytes([0x71, 0x01, 0x02, 0x06, 0x00]) and
          got.get(0x0006) == bytes([0x7F, 0x31, 0x22]),
          "PHYS_INSTALL_4_PARTIAL", fleet_of(got))

    ok_n = sum(1 for sa in ECUS if got.get(sa, b"")[:1] == bytes([0x71]))
    rej_n = sum(1 for sa in ECUS if got.get(sa, b"")[:1] == bytes([0x7F]))
    check(ok_n == 2 and rej_n == 1, "BC_SUMMARY", "成 %d / 拒 %d" % (ok_n, rej_n))

    d = fleet(digest, t)
    check(d == "0003:4/2/1/1;0006:0/0/0/0;0007:4/2/1/1", "DIGEST_PARTIAL", d)

    ref = digest(t, 0x0003)
    odd = [sa for sa in ECUS if digest(t, sa) != ref]
    check(odd == [0x0006], "FLEET_CONSISTENT",
          ("一致" if not odd else "不一致，%s 的摘要与 0x0003 不同" % ",".join("%04X" % s for s in odd)))

t.close()

print("LEG=%d" % LEG)
print("FAIL=%d" % FAIL)
sys.exit(0 if FAIL == 0 else 1)
