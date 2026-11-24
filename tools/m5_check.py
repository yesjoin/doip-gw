#!/usr/bin/env python3
# =============================================================================
# m5_check.py —— 第三方 DoIP 客户端（Python `doipclient`）对打我们的实体/网关
#
# 为什么非要"第三方"：
#   自己写的客户端和服务器长得像一对孪生兄弟——它俩对标准的理解是同一个人写的，
#   所以哪怕双方都理解错了，也能"通"。第三方客户端是别人按同一份标准独立写的，
#   能通才说明**我们符合标准**，而不是"我们自说自话"。
#
# 用法（先 pip3 install --user doipclient）：
#   discover   --host 127.0.0.1 --port 13458                       # UDP 发现
#   read       --host --port --ta 0x0002 --uds "22 F1 90"          # 激活 + 读一个 DID
#   noact      --host --port --sa 0x0E00 --ta 0x0001               # 不激活直接发诊断（应被 0x02 拒）
#   unknown    --host --port --sa 0x0E00 --ta 0x0004               # 发到"不存在的地址"（应 0x03）
#   concurrent --host --port --ta 0x0002 --uds "22 F1 90"
#              --ta2 0x0003 --uds2 "22 F1 91"                      # 两个客户端并发，各拿各的
#
# read/concurrent 走 doipclient；noact/unknown 必须自己开裸 socket ——
# 第三方库一构造就自动做路由激活，没法"故意不激活"，也没法"故意发到不存在的地址后只读 NACK"。
# =============================================================================
import argparse
import socket
import struct
import sys
import threading

from doipclient import DoIPClient

FAIL = 0


def hx(b):
    return " ".join("%02X" % x for x in b)


def check(cond, msg):
    global FAIL
    print(("[PASS] " if cond else "[FAIL] ") + msg)
    if not cond:
        FAIL += 1
    return cond


def parse_hex(s):
    s = s.replace(",", " ").replace("0x", " ").split()
    return bytes(int(x, 16) for x in s)


def recv_message(sock):
    """按 8 字节头里的长度字段收一条完整 DoIP 报文（TCP 会半包，别假定一次 recv 够）"""
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


def send_message(sock, ptype, payload):
    sock.sendall(bytes([0x02, 0xFD]) + struct.pack("!HL", ptype, len(payload)) + payload)


def raw_activate(sock, sa):
    """裸 socket 做一次路由激活（11 字节：SA + 类型 + reserved 4 + OEM 4）"""
    send_message(sock, 0x0005, struct.pack("!HBL", sa, 0x00, 0) + b"\x00\x00\x00\x00")
    r = recv_message(sock)
    ok = len(r) >= 13 and r[2:4] == b"\x00\x06" and r[12] == 0x10
    print("       路由激活：%s（应答码 0x%02X）"
          % ("成功" if ok else "失败", r[12] if len(r) > 12 else 0))
    return ok


def cmd_discover(a):
    # activation_type=None：只做发现，不做路由激活（否则会被当成诊断客户端）
    c = DoIPClient(a.host, a.ta, tcp_port=a.port, udp_port=a.port, activation_type=None)
    try:
        r = c.request_vehicle_identification()
        check(r is not None, "收到 0x0004 识别应答")
        # doipclient 不同版本返回 str 或 bytes，两种都收（有的版本直接给 "LSVA..."）
        raw = r.vin
        vin = raw.decode("ascii", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
        check(len(vin) == 17, "VIN 是 17 位：%s" % vin)
        check(r.logical_address == a.ta, "逻辑地址 = 0x%04X" % r.logical_address)
        print("VIN=%s" % vin)
    finally:
        c.close()


def cmd_read(a):
    uds = parse_hex(a.uds)
    c = DoIPClient(a.host, a.ta, tcp_port=a.port, client_logical_address=a.sa)
    try:
        c.send_diagnostic(uds)
        resp = c.receive_diagnostic()
        check(resp is not None and len(resp) > 0, "收到诊断响应")
        print("       请求(TA=0x%04X) %s → 响应 %s" % (a.ta, hx(uds), hx(resp)))
        print("RESP_HEX=%s" % hx(resp))
        if a.expect:
            check(resp == parse_hex(a.expect), "响应与期望一致（%s）" % a.expect)
        if uds[:3] == b"\x22\xF1\x90" and resp[:3] == b"\x62\xF1\x90":
            vin = resp[3:20].decode("ascii", "replace")
            print("       VIN = %s" % vin)
            print("VIN=%s" % vin)
            if a.vin:
                check(vin == a.vin, "VIN 与期望一致（%s）" % a.vin)
    finally:
        c.close()


def cmd_noact(a):
    """不激活就发诊断：标准要求回 0x8003 NACK 0x02（源地址未激活）然后断开"""
    uds = parse_hex(a.uds)
    s = socket.create_connection((a.host, a.port), timeout=3)
    try:
        send_message(s, 0x8001, struct.pack("!HH", a.sa, a.ta) + uds)
        resp = recv_message(s)
        check(len(resp) >= 13, "收到响应报文（%d 字节）" % len(resp))
        if len(resp) >= 13:
            check(resp[2:4] == b"\x80\x03", "类型是 0x8003 诊断负应答（实际 %s）" % hx(resp[2:4]))
            check(resp[12] == 0x02, "NACK 码 0x02 = 源地址未激活（实际 0x%02X）" % resp[12])
        check(s.recv(64) == b"", "服务器随后断开连接（recv 返回空）")
    finally:
        s.close()


def cmd_unknown(a):
    """激活成功，但把诊断发到一个路由表里没有的地址：必须 0x8003 0x03"""
    uds = parse_hex(a.uds)
    s = socket.create_connection((a.host, a.port), timeout=3)
    try:
        check(raw_activate(s, a.sa), "先正常激活")
        send_message(s, 0x8001, struct.pack("!HH", a.sa, a.ta) + uds)
        resp = recv_message(s)
        check(len(resp) >= 13, "收到响应报文（%d 字节）" % len(resp))
        if len(resp) >= 13:
            check(resp[2:4] == b"\x80\x03", "类型是 0x8003（实际 %s）" % hx(resp[2:4]))
            check(resp[12] == 0x03, "NACK 码 0x03 = 目标地址未知（实际 0x%02X）" % resp[12])
            print("       负应答 SA=0x%04X TA=0x%04X（照请求反向填）"
                  % (struct.unpack("!H", resp[8:10])[0], struct.unpack("!H", resp[10:12])[0]))
    finally:
        s.close()


def cmd_concurrent(a):
    """两个客户端（可能指向两台不同 ECU）并发，各自只应拿到自己的答案"""
    results = {}

    def worker(sa, ta, uds_hex, key):
        uds = parse_hex(uds_hex)
        c = DoIPClient(a.host, ta, tcp_port=a.port, client_logical_address=sa)
        try:
            for _ in range(a.rounds):
                c.send_diagnostic(uds)
                results.setdefault(key, []).append(c.receive_diagnostic())
        finally:
            c.close()

    t1 = threading.Thread(target=worker, args=(a.sa, a.ta, a.uds, "A"))
    t2 = threading.Thread(target=worker, args=(a.sa + 1, a.ta2, a.uds2, "B"))
    t1.start(), t2.start()
    t1.join(), t2.join()

    for key in ("A", "B"):
        lst = results.get(key, [])
        check(len(lst) == a.rounds, "客户端 %s 拿到 %d/%d 条响应" % (key, len(lst), a.rounds))
    for key, want in (("A", a.expect), ("B", a.expect2)):
        if not want:
            continue
        pref = parse_hex(want)
        lst = results.get(key, [])
        check(all(r[:len(pref)] == pref for r in lst),
              "%s 的每条响应都以 %s 开头（没串包）" % (key, want))
    for key in ("A", "B"):
        if results.get(key):
            print("       %s 最后一条：%s" % (key, hx(results[key][-1])))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--host", default="127.0.0.1")
        sp.add_argument("--port", type=int, default=13400)
        sp.add_argument("--ta", type=lambda x: int(x, 0), default=0x0001)
        sp.add_argument("--sa", type=lambda x: int(x, 0), default=0x0E00)

    d = sub.add_parser("discover"); common(d); d.set_defaults(fn=cmd_discover)
    r = sub.add_parser("read"); common(r)
    r.add_argument("--uds", required=True)
    r.add_argument("--expect", default=None)
    r.add_argument("--vin", default=None)
    r.set_defaults(fn=cmd_read)
    n = sub.add_parser("noact"); common(n)
    n.add_argument("--uds", default="22 F1 90")
    n.set_defaults(fn=cmd_noact)
    u = sub.add_parser("unknown"); common(u)
    u.add_argument("--uds", default="22 F1 90")
    u.set_defaults(fn=cmd_unknown)
    c = sub.add_parser("concurrent"); common(c)
    c.add_argument("--uds", default="22 F1 90")
    c.add_argument("--expect", default="62 F1 90")
    c.add_argument("--ta2", type=lambda x: int(x, 0), default=None)
    c.add_argument("--uds2", default="3E 00")
    c.add_argument("--expect2", default="7E 00")
    c.add_argument("--rounds", type=int, default=2)
    c.set_defaults(fn=cmd_concurrent)

    a = p.parse_args()
    if getattr(a, "ta2", None) is None:
        a.ta2 = a.ta
    a.fn(a)
    print("失败 %d 项" % FAIL if FAIL else "全绿")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
