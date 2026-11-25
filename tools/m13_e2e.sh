#!/usr/bin/env bash
# =============================================================================
# m13_e2e.sh —— M13 验收：实体级 tester 地址仲裁（0x01 / 0x03 第一次真的用起来）
#
# 用法： bash tools/m13_e2e.sh [端口]        默认 13471
#
# M2 起，激活状态是"跟着连接走"的：每条 socket 一份 RoutingActivation，
# 它只管"这条连接里 SA 不许中途换人"。
# 这没错，但它管不了另一件事：**两台 tester 各自开一条连接，用同一个 SA 激活**。
# 网关这边一切正常，可总线那头就是两个同址的诊断仪在说话 —— ECU 分不清，
# 只有网关靠 jobId 才没把答案送错人。真网关不允许，用的就是 0x0006 里那两个码：
#   0x03 = 这个 SA 已经在**另一条** TCP_DATA socket 上注册并激活
#   0x01 = 本实体能同时承载的 socket 都已被注册并激活（没有名额）
#
# 这一节的考点：
#   ① 同址冲突真要拒（0x03），换地址也要拒（0x02）；
#   ② "连接 ≠ 激活"：第 5 台 TCP 连得上，但激活拿 0x01；
#   ③ 断开之后地址要还回来（而不是永久占着）；
#   ④ 仲裁不能把数据通路弄坏：激活后的连接照样读得到 VIN。
#
# 拓扑：网关（maxConnections=8 / maxActivated=4）+ 一台经典 ECU（0x0003 → 7A0/7A8）
# 多连接场景由 tools/m13_check.py 用裸 socket 精确控制（第三方库插不进手）。
# =============================================================================
set -u

PORT=${1:-13471}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m13_check.py
SLOG=/tmp/m13_gw.log
OUT=/tmp/m13_check.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }

cleanup
echo "=== 1 启动：网关（8 连接 / 4 激活名额）+ 一台 ECU ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 40 > /tmp/m13_ecu.log 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 20 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "最多同时激活 4 台（连接上限 8）" "$SLOG" \
    && ok "启动就打出两个容量：4 台激活 / 8 条连接" || bad "没打出 tester 地址仲裁的容量"
grep -q "TA=0x0003 → 0x7A0 / 0x7A8" "$SLOG" \
    && ok "ECU_A 的物理通道开好了" || bad "路由表没开"

echo
echo "=== 2 多连接场景（m13_check.py：A 重复 / A 换址 / B 抢址 → 满 → 释放 → 再满 → 读 VIN） ==="
python3 "$CHECK" --host 127.0.0.1 --port "$PORT" > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab CODE_A)" = "10" ]        && ok "A 正常激活 → 0x10" || bad "CODE_A=$(grab CODE_A)"
[ "$(grab CODE_A_REPEAT)" = "10" ] && ok "同连接重复激活 → 幂等 0x10" || bad "CODE_A_REPEAT=$(grab CODE_A_REPEAT)"
[ "$(grab CODE_A_CHANGE)" = "02" ] && ok "同连接换地址 → 0x02" || bad "CODE_A_CHANGE=$(grab CODE_A_CHANGE)"
[ "$(grab CODE_B)" = "03" ]        && ok "B 抢 A 的地址 → 0x03 同址冲突" || bad "CODE_B=$(grab CODE_B)"
[ "$(grab CODE_C)" = "10" ] && [ "$(grab CODE_D)" = "10" ] && [ "$(grab CODE_E)" = "10" ] \
    && ok "C/D/E 各用自己的地址 → 0x10（凑满 4 台）" || bad "C/D/E 有一条没成功"
[ "$(grab CODE_F)" = "01" ]        && ok "第 5 台 → 0x01 名额已满（TCP 仍然连得上）" || bad "CODE_F=$(grab CODE_F)"
[ "$(grab CODE_B_RETRY)" = "10" ]  && ok "A 断开后 B 重试 0x0E00 → 0x10（地址还回来了）" || bad "CODE_B_RETRY=$(grab CODE_B_RETRY)"
[ "$(grab CODE_G)" = "01" ]        && ok "G 再试 → 仍然 0x01" || bad "CODE_G=$(grab CODE_G)"
[ "$(grab DIAG_VIN)" = "LSVZZ0000B7654321" ] \
    && ok "仲裁之后数据通路仍然通：B 读到 ECU_A 的 VIN" || bad "读回 $(grab DIAG_VIN)"

echo
echo "=== 3 等网关退场，核对它的账 ==="
# 网关 --seconds 20 自己退场；场景脚本大约 4 秒跑完，留足余量
for _ in $(seq 1 40); do
    grep -q "地址冲突" "$SLOG" && break
    sleep 0.5
done
tail -6 "$SLOG"

conf=$(grep -o "地址冲突 [0-9]* 次" "$SLOG" | grep -o "[0-9]*" | head -1)
cap=$(grep -o "激活名额已满 [0-9]* 次" "$SLOG" | grep -o "[0-9]*" | head -1)
act=$(grep -o "接入 [0-9]*，激活 [0-9]*" "$SLOG" | tail -1 | sed "s/.*激活 //")

[ "${conf:-0}" = "1" ] && ok "网关账：地址冲突 1 次（0x03，B 那一次）" || bad "地址冲突 ${conf:-?} 次（期望 1）"
[ "${cap:-0}" = "2" ]  && ok "网关账：名额已满 2 次（0x01，F 与 G 各一次）" || bad "名额已满 ${cap:-?} 次（期望 2）"
# 成功激活的次数：A、A 重复、C、D、E、B 重试 = 6
[ "${act:-0}" = "6" ]  && ok "网关账：成功激活 6 次（含一次幂等重发）" || bad "成功激活 ${act:-?} 次（期望 6）"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M13 全绿 —— 地址是实体级仲裁的：同址冲突 0x03、名额满 0x01、断开就还、数据通路不受影响。"
    exit 0
fi
exit 1
