#!/usr/bin/env python3
# ============================================================================
# m14_check.py —— M14 的裸 socket 场景（不依赖第三方库）
#
# 为什么自己写 socket 而不用 doipclient：这一步要问的都是 UDP 上的"能力公告"，
# 而且要故意发不合规的东西（带载荷的 0x4001、走 TCP 的 0x4001）。
# 第三方库会"帮你把报文写对"，恰好把这些错误用法屏蔽掉。
#
# 用法：python3 m14_check.py <port> <期望电源模式 0/1/2>
# 输出 KEY=VALUE 行，由 m14_e2e.sh 逐条断言；内部自查失败时最后打 FAIL=1。
# ============================================================================
import socket
import struct
import sys
import time

PORT = int(sys.argv[1])
EXPECT_POWER = int(sys.argv[2])
# 只问电源模式：第二条网关（--power-mode 0）用这个模式快速验"答案跟着配置走"
PARTIAL = len(sys.argv) > 3 and sys.argv[3] == "power-only"

FAIL = 0


def emit(key, value):
    print("%s=%s" % (key, value))


def check(cond, key, value):
    global FAIL
    emit(key, value)
    if not cond:
        FAIL += 1


def msg(ptype, payload=b""):
    # 版本 0x02 + 反码 0xFD + 类型(2, 大端) + 长度(4, 大端) + 载荷
    return bytes([0x02, 0xFD]) + struct.pack("!H", ptype) + struct.pack("!I", len(payload)) + payload


def parse(data):
    """返回 (payload_type, payload) 或 None"""
    if data is None or len(data) < 8:
        return None
    ptype = struct.unpack("!H", data[2:4])[0]
    plen = struct.unpack("!I", data[4:8])[0]
    return ptype, data[8:8 + plen]


def udp_ask(ptype, payload=b"", timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg(ptype, payload), ("127.0.0.1", PORT))
        data, _ = s.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def entity_status(timeout=1.0):
    r = parse(udp_ask(0x4001, timeout=timeout))
    if r is None or r[0] != 0x4002 or len(r[1]) < 3:
        return None
    node = r[1][0]
    mx = r[1][1]
    cur = r[1][2]
    maxdata = 0
    if len(r[1]) >= 7:
        maxdata = struct.unpack("!I", r[1][3:7])[0]
    return {"node": node, "max": mx, "cur": cur, "maxdata": maxdata}


def activate(sock, sa):
    sock.sendall(msg(0x0005, struct.pack("!H", sa) + b"\x00" + b"\x00" * 8))
    sock.settimeout(1.0)
    try:
        data = sock.recv(4096)
    except socket.timeout:
        return None
    r = parse(data)
    if r is None or r[0] != 0x0006 or len(r[1]) < 13:
        return None
    # 0x0006 的载荷：tester(2) + entity(2) + code(1) + reserved(4) + oem(4)
    #   码在第 5 个字节。按 payload[2] 取会拿到实体地址的高字节 0x00，
    #   看上去像"未知源地址"，其实是自己数错了位 —— M14 第一遍就踩在这上面。
    return r[1][4]   # responseCode


# ---------------------------------------------------------------------------
# A. 一条连接都没有的时候：越界的数应该是 0
# ---------------------------------------------------------------------------
st = entity_status()
if st is None:
    emit("STATUS_OK", 0)
    FAIL += 1
else:
    check(st["node"] == 0x00, "NODE_TYPE", "%02X" % st["node"])
    check(st["max"] == 8, "MAX_SOCKETS", "%02X" % st["max"])
    check(st["cur"] == 0, "CUR_IDLE", "%02X" % st["cur"])
    # 网关启动行写的是 4096；这里必须对得上，否则"公告 ≠ 实现"
    check(st["maxdata"] == 4096, "MAX_DATA_SIZE", "%d" % st["maxdata"])

# ---------------------------------------------------------------------------
# B. 电源模式：就能报出配置的那一个值
# ---------------------------------------------------------------------------
r = parse(udp_ask(0x4003))
if r is None or r[0] != 0x4004 or len(r[1]) != 1:
    emit("POWER_OK", 0)
    FAIL += 1
else:
    check(r[1][0] == EXPECT_POWER, "POWER_MODE", "%02X" % r[1][0])

if PARTIAL:
    emit("FAIL", FAIL)
    sys.exit(1 if FAIL else 0)

# ---------------------------------------------------------------------------
# C. 开 3 条 TCP 但一条都不激活：0x4002 的 cur 应是 3
#    这里量的是 socket 数，不是激活数 —— M13 刚把这两个概念拆开
# ---------------------------------------------------------------------------
conns = []
for _ in range(3):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=2.0)
    conns.append(s)
time.sleep(0.4)
st = entity_status()
check(st is not None and st["cur"] == 3, "CUR_AFTER_CONNECT", "%02X" % (st["cur"] if st else 0xFF))

# ---------------------------------------------------------------------------
# D. 激活其中一条：cur 还是 3（激活不改变 socket 数）
# ---------------------------------------------------------------------------
code = activate(conns[0], 0x0E00)
check(code == 0x10, "ACT_CODE", "%02X" % (code if code is not None else 0xFF))
time.sleep(0.2)
st = entity_status()
check(st is not None and st["cur"] == 3, "CUR_AFTER_ACT", "%02X" % (st["cur"] if st else 0xFF))

# ---------------------------------------------------------------------------
# E. 不合规用法：带载荷的 0x4001 / 0x4003 → 必须沉默
#    UDP 上没有 NACK，沉默就是唯一正确的回答
# ---------------------------------------------------------------------------
junk = udp_ask(0x4001, b"\xAA", timeout=0.8)
check(junk is None, "JUNK_STATUS_SILENT", "1" if junk is None else "0")
junk = udp_ask(0x4003, b"\x00", timeout=0.8)
check(junk is None, "JUNK_POWER_SILENT", "1" if junk is None else "0")

# ---------------------------------------------------------------------------
# F. 走 TCP 问 0x4001：不该有 0x4002 回来（标准里它只许走 UDP）
# ---------------------------------------------------------------------------
conns[1].settimeout(0.8)
conns[1].sendall(msg(0x4001))
try:
    data = conns[1].recv(4096)
except socket.timeout:
    data = None
except OSError:
    # 对面把连接关了也是"没答 0x4002"，同样算通过（它没有顺着错误用法走）
    data = None
r = parse(data)
check(r is None, "TCP_STATUS_SILENT", "1" if r is None else "0")

# ---------------------------------------------------------------------------
# G. 同一个实体上，发现请求照旧能答（两条业务共用一个 13400 端口）
# ---------------------------------------------------------------------------
r = parse(udp_ask(0x0001))
vin = ""
if r is not None and r[0] == 0x0004 and len(r[1]) >= 17:
    vin = r[1][:17].decode("ascii", "replace")
check(vin == "LSVAA0000A1234567", "DISCOVERY_VIN", vin if vin else "NONE")

# ---------------------------------------------------------------------------
# H. 关掉连接：cur 回到 0（关了就减，和 M13 释放地址同源）
# ---------------------------------------------------------------------------
for s in conns:
    s.close()
time.sleep(0.5)
st = entity_status()
check(st is not None and st["cur"] == 0, "CUR_AFTER_CLOSE", "%02X" % (st["cur"] if st else 0xFF))

emit("FAIL", FAIL)
sys.exit(1 if FAIL else 0)
