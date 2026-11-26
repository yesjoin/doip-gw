#!/usr/bin/env python3
# =============================================================================
# m27_check.py —— M27 的端口侧检查（路由激活凭据）
#
# 用法： python3 tools/m27_check.py <端口> <段号>
#
# 段一：网关没开票 —— 老的 7/11 字节激活照旧成功，UDS 照旧通（不能把老路径搞坏）。
# 段二：网关开了票 —— 对的票进、没票挡、票是别人的挡、7 字节没处放票也挡；
#       被挡的那条连接**发不了诊断请求**（拒了就是真拒了，不是"嘴上拒"）。
#
# 为什么用 python 的 hmac 算票，而不是让 C++ 算完再传进来：
#   两条独立实现算同一个值，撞上了才说明"协议"真的立住了；
#   一条代码自己跟自己比，永远绿。
# =============================================================================
import hashlib
import hmac
import socket
import struct
import sys

# 和 shell 里传给网关的 --tester-key 必须是同一把（64 位十六进制）
SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

ENTITY = 0x0001
TARGET = 0x0003      # 0x0003 → 7A0/7A8（段一/段二都只起这一台）
SA = 0x0E00
SA_OTHER = 0x0E01

pass_n = 0
fail_n = 0


def check(cond, what):
    global pass_n, fail_n
    if cond:
        pass_n += 1
    else:
        fail_n += 1
        print("FAIL %s" % what)


def token(sa):
    """4 字节 = HMAC-SHA256(secret, "doip-ra|<SA 大写 4 位>") 的头 4 字节。"""
    key = bytes.fromhex(SECRET_HEX)
    msg = ("doip-ra|%04X" % sa).encode()
    return int.from_bytes(hmac.new(key, msg, hashlib.sha256).digest()[:4], "big")


class Tester(object):
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
        self.buf = b""

    def send(self, ptype, payload):
        self.sock.sendall(struct.pack("!BBHI", 0x02, 0xFD, ptype, len(payload)) + payload)

    def next_msg(self):
        """一条一条地取：先凑够 8 字节头，再按长度取载荷。"""
        while len(self.buf) < 8:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None, b""
            self.buf += chunk
        ptype = struct.unpack("!H", self.buf[2:4])[0]
        n = struct.unpack("!I", self.buf[4:8])[0]
        while len(self.buf) < 8 + n:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None, b""
            self.buf += chunk
        payload = self.buf[8:8 + n]
        self.buf = self.buf[8 + n:]
        return ptype, payload

    def activate(self, sa=SA, oem=0, short7=False):
        """发 0x0005，回 0x0006 的响应码（hex 两位）。"""
        payload = struct.pack("!HB", sa, 0x00) + b"\x00" * 4
        if not short7:
            payload += struct.pack("!I", oem)
        self.send(0x0005, payload)
        t, p = self.next_msg()
        if t != 0x0006 or len(p) < 13:
            return "none"
        return "%02X" % p[4]

    def diag(self, uds, sa=SA):
        """发 0x8001 诊断请求，回 (类型, 载荷 hex)。

        ★ 这里要跳过 0x8002（诊断请求已收到的正应答）：网关是先 ACK 再转发，
          M12 起答案还可能是流式的多条。只读一条会读到 ACK，把 ACK 当答案 ——
          这正是 M26 踩过的"一次只解析第一条"的同一类坑。
        """
        self.send(0x8001, struct.pack("!HH", sa, TARGET) + bytes.fromhex(uds))
        for _ in range(4):
            t, p = self.next_msg()
            if t is None:
                raise OSError("连接被断开")
            if t == 0x8002:
                continue                     # 正应答，不是答案
            return t, p.hex().upper()
        return None, ""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    seg = sys.argv[2]

    right = token(SA)
    print("TOKEN=%08X" % right)

    if seg == "1":
        # ---- 没开票：行为必须和 M26 一模一样 ----
        t = Tester(port)
        check(t.activate(oem=0) == "10", "没开票时 11 字节零 OEM 激活成功")
        ptype, hex_ = t.diag("22F190")
        check(ptype == 0x8001 and hex_[8:].startswith("62F190"), "激活后读 VIN 通（UDS=%s）" % hex_[8:24])
        t.close()

        t = Tester(port)
        check(t.activate(oem=0, short7=True) == "10", "没开票时 7 字节老变体也成功（互通性没被搞坏）")
        t.close()

    elif seg == "2":
        # ---- 开了票 ----
        t = Tester(port)
        check(t.activate(oem=right) == "10", "带对的票 → 0x10 成功")
        ptype, hex_ = t.diag("22F190")
        check(ptype == 0x8001 and hex_[8:].startswith("62F190"), "带票的连接能正常诊断（UDS=%s）" % hex_[8:24])
        t.close()

        t = Tester(port)
        check(t.activate(oem=0) == "04", "没带票（OEM 全 0）→ 0x04 缺认证")
        # 关键：拒了之后这条连接不能"其实还能用" —— 拿一条诊断请求试一下。
        # 两种拒法都算数：回负应答（0x8003/0x0000），或者干脆断开。
        try:
            ptype, _ = t.diag("22F190")
            check(ptype in (0x8003, 0x0000),
                  "被挡的连接发诊断请求 → 负应答 0x%04X，不是 UDS 回答" % ptype)
        except OSError:
            check(True, "被挡的连接发诊断请求 → 网关直接断开（同样是真拒）")
        t.close()

        t = Tester(port)
        check(t.activate(oem=token(SA_OTHER)) == "04", "拿着别的 SA 的票 → 0x04（票是绑地址的）")
        t.close()

        t = Tester(port)
        check(t.activate(oem=right, short7=True) == "04", "7 字节老变体（没处放票）→ 0x04")
        t.close()

        t = Tester(port)
        check(t.activate(sa=SA_OTHER, oem=token(SA_OTHER)) == "10",
              "换一台诊断仪（0x0E01）带自己的票 → 成功（一台一票）")
        t.close()

    else:
        check(False, "段号只认 1 / 2，收到 %s" % seg)

    print("PASS=%d" % pass_n)
    print("FAIL=%d" % fail_n)
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
