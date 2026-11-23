#!/usr/bin/env python3
# =============================================================================
# m5_check.py —— M5：用第三方 DoIP 客户端（Python 的 `doipclient`）对打我们的实体/网关
#
# 为什么非要"第三方"：
#   自己写的客户端和服务器长得像一对孪生兄弟——它俩对标准的理解是同一个人写的，
#   所以哪怕双方都理解错了，也能"通"。第三方客户端是别人按同一份标准独立写的，
#   能通才说明**我们符合标准**，而不是"我们自说自话"。
#
# 用法（先 pip3 install --user doipclient）：
#   python3 tools/m5_check.py discover  --host 127.0.0.1 --port 13458
#   python3 tools/m5_check.py read      --host 127.0.0.1 --port 13458 --ta 0x0001 --uds "22 F1 90"
#   python3 tools/m5_check.py noact     --host 127.0.0.1 --port 13458 --sa 0x0E00 --ta 0x0001
#   python3 tools/m5_check.py concurrent --host 127.0.0.1 --port 13458 --ta 0x0001
#
# `read` / `concurrent` 走 doipclient；`noact` 必须自己开裸 socket——因为第三方库
# 一构造就会自动做路由激活，没法"故意不激活"。
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


def cmd_discover(a):
    # activation_type=None：只做发现，不做路由激活（否则会被当成诊断客户端）
    c = DoIPClient(a.host, a.ta, tcp_port=a.port, udp_port=a.port, activation_type=None)
    try:
        r = c.request_vehicle_identification()
        check(r is not None, "收到 0x0004 识别应答")
        vin = r.vin.hex().upper() if isinstance(r.vin, (bytes, bytearray)) else str(r.vin)
        try:
            vin = bytes.fromhex(vin).decode("ascii")
        except Exception:
            pass
        check(len(vin) == 17, "VIN 是 17 位：%s" % vin)
        check(r.logical_address == a.ta, "逻辑地址 = 0x%04X" % r.logical_address)
        print("       EID=%s  GID=%s  furtherAction=0x%02X"
              % (hx(bytes(r.eid)), hx(bytes(r.gid)), r.further_action))
    finally:
        c.close()


def cmd_read(a):
    uds = parse_hex(a.uds)
    c = DoIPClient(a.host, a.ta, tcp_port=a.port, client_logical_address=a.sa)
    try:
        c.send_diagnostic(uds)
        resp = c.receive_diagnostic()
        check(resp is not None and len(resp) > 0, "收到诊断响应")
        print("       请求 %s → 响应 %s" % (hx(uds), hx(resp)))
        print("RESP_HEX=%s" % hx(resp))
        if a.expect:
            check(resp == parse_hex(a.expect), "响应与期望一致（%s）" % a.expect)
        if uds[:3] == b"\x22\xF1\x90" and resp[:3] == b"\x62\xF1\x90":
            vin = resp[3:20].decode("ascii", "replace")
            print("       VIN = %s" % vin)
            print("VIN=%s" % vin)
            if a.vin:
                check(vin == a.vin, "VIN 与 CAN 侧直读一致（%s）" % a.vin)
    finally:
        c.close()


def cmd_noact(a):
    """不激活就发诊断：标准要求回 0x8003 NACK 0x02（源地址未激活）然后断开"""
    uds = parse_hex(a.uds)
    s = socket.create_connection((a.host, a.port), timeout=3)
    try:
        payload = struct.pack("!HH", a.sa, a.ta) + uds
        msg = bytes([0x02, 0xFD, 0x80, 0x01, 0, 0, 0, len(payload)]) + payload
        s.sendall(msg)
        resp = recv_message(s)
        check(len(resp) >= 13, "收到响应报文（%d 字节）" % len(resp))
        if len(resp) >= 13:
            check(resp[2:4] == b"\x80\x03", "类型是 0x8003 诊断负应答（实际 %s）" % hx(resp[2:4]))
            check(resp[12] == 0x02, "NACK 码 0x02 = 源地址未激活（实际 0x%02X）" % resp[12])
        tail = s.recv(64)
        check(tail == b"", "服务器随后断开连接（recv 返回空）")
    finally:
        s.close()


def cmd_concurrent(a):
    """两个客户端不同 SA 同时请求，各自只应拿到自己的答案"""
    vin_resp = b""
    results = {}

    def worker(sa, uds, key):
        c = DoIPClient(a.host, a.ta, tcp_port=a.port, client_logical_address=sa)
        try:
            for _ in range(a.rounds):
                c.send_diagnostic(uds)
                results.setdefault(key, []).append(c.receive_diagnostic())
        finally:
            c.close()

    t1 = threading.Thread(target=worker, args=(a.sa, parse_hex("22 F1 90"), "vin"))
    t2 = threading.Thread(target=worker, args=(a.sa + 1, parse_hex("3E 00"), "tester"))
    t1.start(), t2.start()
    t1.join(), t2.join()

    vin_list = results.get("vin", [])
    t_list = results.get("tester", [])
    check(len(vin_list) == a.rounds, "客户端 A 拿到 %d/%d 条响应" % (len(vin_list), a.rounds))
    check(len(t_list) == a.rounds, "客户端 B 拿到 %d/%d 条响应" % (len(t_list), a.rounds))
    check(all(r[:3] == b"\x62\xf1\x90" for r in vin_list), "A 的每条响应都是 22 F1 90 的正响应（没串包）")
    check(all(r == b"\x7e\x00" for r in t_list), "B 的每条响应都是 7E 00（没串包）")
    if vin_list:
        print("       A 最后一条：%s" % hx(vin_list[-1]))


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
    c = sub.add_parser("concurrent"); common(c)
    c.add_argument("--rounds", type=int, default=3)
    c.set_defaults(fn=cmd_concurrent)

    a = p.parse_args()
    a.fn(a)
    print("失败 %d 项" % FAIL if FAIL else "全绿")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
