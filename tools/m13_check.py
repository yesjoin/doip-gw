#!/usr/bin/env python3
# =============================================================================
# m13_check.py —— M13 多 tester 地址仲裁的场景脚本（纯裸 socket）
#
# 为什么不用 doipclient：
#   这个里程碑要验的是"**同一条连接**换地址被拒、**另一条连接**抢同一地址被拒、
#   名额满了被拒、释放之后又能要回来"——这些都得精确控制"谁在哪条 socket 上、
#   第几次发请求"。第三方库一构造就自动激活一次，完全插不进手。
#
# 场景（maxActivated 默认 4、maxConnections 默认 8）：
#   A  0x0E00 → 0x10            （第 1 台）
#   A  0x0E00 再来一次 → 0x10   （幂等：断线重连是常态）
#   A  改 0x0E09 → 0x02         （同一 socket 不许换人）
#   B  0x0E00 → 0x03            （同址冲突：A 还占着）
#   C  0x0E01 → 0x10  D 0x0E02 → 0x10  E 0x0E03 → 0x10   （凑满 4 台）
#   F  0x0E04 → 0x01            （名额满了，但 TCP 连得上——这就是 0x01 存在的意义）
#   A  断开 → B 重试 0x0E00 → 0x10   （释放之后地址能要回来）
#   G  0x0E05 → 0x01            （还是满的）
#   B  发 22 F1 90 → ACK + 62 F1 90 + VIN   （仲裁没把数据通路弄坏）
#
# 用法：
#   python3 tools/m13_check.py --host 127.0.0.1 --port 13471
# 输出里 CODE_* / DIAG_VIN / FAIL 这几行是给 m13_e2e.sh 抓的。
# =============================================================================
import argparse
import socket
import struct
import sys
import time

FAIL = 0


def check(cond, msg):
    global FAIL
    print(("[PASS] " if cond else "[FAIL] ") + msg)
    if not cond:
        FAIL += 1
    return cond


def send_message(sock, ptype, payload):
    sock.sendall(bytes([0x02, 0xFD]) + struct.pack("!HL", ptype, len(payload)) + payload)


def recv_message(sock):
    """按 8 字节头里的长度字段收一条完整报文（TCP 会半包，别假定一次 recv 够）"""
    buf = b""
    need = 8
    while len(buf) < need:
        chunk = sock.recv(need - len(buf))
        if not chunk:
            break
        buf += chunk
        if len(buf) >= 8:
            need = 8 + struct.unpack("!L", buf[4:8])[0]
    return buf


class Conn:
    def __init__(self, host, port, timeout=2.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def activate(self, sa):
        """发一条 0x0005，返回响应码（0x10 成功 / 0x01 / 0x02 / 0x03…）"""
        send_message(self.sock, 0x0005, struct.pack("!HBL", sa, 0x00, 0) + b"\x00\x00\x00\x00")
        r = recv_message(self.sock)
        if len(r) < 13 or r[2:4] != b"\x00\x06":
            return -1
        return r[12]

    def diag(self, sa, ta, uds):
        """发 0x8001，收齐 ACK(0x8002) 与响应(0x8001)；返回 (ack, uds_bytes)"""
        send_message(self.sock, 0x8001, struct.pack("!HH", sa, ta) + uds)
        ack = None
        reply = None
        deadline = time.time() + 1.5
        while time.time() < deadline and reply is None:
            try:
                r = recv_message(self.sock)
            except socket.timeout:
                break
            if len(r) < 8:
                break
            ptype = struct.unpack("!H", r[2:4])[0]
            payload = r[8:]
            if ptype == 0x8002:
                ack = payload[4] if len(payload) >= 5 else 0xFF
            elif ptype == 0x8001 and len(payload) >= 4:
                reply = payload[4:]
            elif ptype == 0x8003:
                reply = None
                ack = ("NACK", payload[4] if len(payload) >= 5 else 0xFF)
                break
        return ack, reply

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def scenario(host, port):
    codes = {}

    # ---- A：第一台，正常激活 ----
    A = Conn(host, port)
    codes["A"] = A.activate(0x0E00)
    check(codes["A"] == 0x10, "A 用 0x0E00 激活 → 0x10")

    codes["A_REPEAT"] = A.activate(0x0E00)
    check(codes["A_REPEAT"] == 0x10, "同一条连接重复激活同一地址 → 仍 0x10（幂等）")

    codes["A_CHANGE"] = A.activate(0x0E09)
    check(codes["A_CHANGE"] == 0x02, "同一条连接换地址 → 0x02（一个 socket 一段已认证上下文）")

    # ---- B：抢 A 的地址 ----
    B = Conn(host, port)
    codes["B"] = B.activate(0x0E00)
    check(codes["B"] == 0x03, "B 抢 0x0E00（A 还占着）→ 0x03 同址冲突")

    # ---- 凑满 4 台：A(0x0E00) + C + D + E ----
    C = Conn(host, port)
    codes["C"] = C.activate(0x0E01)
    check(codes["C"] == 0x10, "C 用 0x0E01 激活 → 0x10（第 2 台）")

    D = Conn(host, port)
    codes["D"] = D.activate(0x0E02)
    check(codes["D"] == 0x10, "D 用 0x0E02 激活 → 0x10（第 3 台）")

    E = Conn(host, port)
    codes["E"] = E.activate(0x0E03)
    check(codes["E"] == 0x10, "E 用 0x0E03 激活 → 0x10（第 4 台，正好满）")

    # ---- F：第 5 台。TCP 连得上（maxConnections=8），但激活名额满了 ----
    F = Conn(host, port)
    codes["F"] = F.activate(0x0E04)
    check(codes["F"] == 0x01, "F 是第 5 台 → 0x01 激活名额已满（不是 TCP 连不上）")
    F.close()

    # ---- A 断开：地址必须还回去 ----
    A.close()
    time.sleep(0.4)          # 让网关 poll 到 FIN 并 dropConn（那里 release 地址）
    codes["B_RETRY"] = B.activate(0x0E00)
    check(codes["B_RETRY"] == 0x10, "A 断开后 B 重试 0x0E00 → 0x10（地址不是永久绑定）")

    # ---- G：又满 4 台（B+C+D+E） ----
    G = Conn(host, port)
    codes["G"] = G.activate(0x0E05)
    check(codes["G"] == 0x01, "G 再试 → 还是 0x01（4 台仍在）")

    # ---- 仲裁没把数据通路弄坏：B 读 VIN ----
    ack, uds = B.diag(0x0E00, 0x0003, b"\x22\xF1\x90")
    check(ack == 0x00, "B 激活后发 22 F1 90 → 收到 0x8002 ACK（code=0x00）")
    vin = None
    if uds and uds[:2] == b"\x62\xF1":
        vin = "".join(chr(b) if 32 <= b < 127 else "." for b in uds[3:])
    check(vin == "LSVZZ0000B7654321", "响应是 62 F1 90 + VIN（%s），和 ECU 的一致" % (vin or "-"))
    print("DIAG_VIN=%s" % (vin or "-"))
    print("DIAG_ACK=%02X" % (ack if isinstance(ack, int) else 0xFF))

    # ---- 收尾 ----
    for name, c in (("B", B), ("C", C), ("D", D), ("E", E), ("G", G)):
        c.close()

    for k, v in codes.items():
        print("CODE_%s=%02X" % (k, v if v >= 0 else 0))
    print("FAIL=%d" % FAIL)
    return 0 if FAIL == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=13471)
    a = ap.parse_args()
    return scenario(a.host, a.port)


if __name__ == "__main__":
    sys.exit(main())
