#!/usr/bin/env bash
# =============================================================================
# m14_e2e.sh —— M14 验收：实体状态（0x4001/0x4002）与电源模式（0x4003/0x4004）
#
# 用法： bash tools/m14_e2e.sh [端口]        默认 13472（第二条腿用 端口+1）
#
# M13 建了一张"实体级"的账（谁激活了、几个名额在用），但它只活在网关的日志里。
# 标准里把这些账对外公布的就是 0x4002：节点类型、最大 socket 数、**当前开着的
# socket 数**、最大可处理载荷。0x4003/0x4004 则回答"现在能做诊断吗"。
#
# 这一节的考点：
#   ① 0x4002 的四个字段要和网关自己说的对得上（公告 ≠ 实现就是 bug）；
#   ② cur_open_sockets 数的是 socket，不是激活 —— 开 3 条只激活 1 条，仍是 3；
#   ③ 不合规用法（带载荷的 0x4001、走 TCP 的 0x4001）必须沉默，不能"好心回答"；
#   ④ 同一端口上发现请求照旧能答（两套业务共用一个 13400）；
#   ⑤ 关掉连接 cur 归零（和 M13 释放地址同源：账要还）；
#   ⑥ --power-mode 0 时答案跟着变 0x00（"车没上电"是能演出来的）。
#
# 拓扑：网关 + 一台经典 ECU（0x0003 → 7A0/7A8）。
# 场景由 tools/m14_check.py 用裸 socket 精确控制 —— 第三方库会"帮你写对"，
# 反而把"带载荷的 0x4001""走 TCP 的 0x4001"这些错误用法屏蔽掉。
# =============================================================================
set -u

PORT=${1:-13472}
PORT2=$((PORT + 1))
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m14_check.py
SLOG=/tmp/m14_gw.log
SLOG2=/tmp/m14_gw_power0.log
OUT=/tmp/m14_check.txt
OUT2=/tmp/m14_check_power0.txt

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
echo "=== 1 启动：网关（UDP 上同时答发现 + 实体状态）+ 一台 ECU ==="
stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 \
        --vin LSVZZ0000B7654321 --hw HW02 --seconds 30 > /tmp/m14_ecu.log 2>&1 &
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT" --seconds 16 \
        --route 0003:7A0:7A8:ECU_A > "$SLOG" 2>&1 &
sleep 1.2

grep -q "实体状态（0x4001/0x4003，同在 UDP $PORT）" "$SLOG" \
    && ok "启动就把能公布的能力摆出来（0x4001/0x4003 与发现同端口）" || bad "启动行没提实体状态"
grep -q "node type=网关，最大 socket 8，最大载荷 4096 字节，电源模式=ready" "$SLOG" \
    && ok "公告的四个值和配置一致（8 / 4096 / ready）" || bad "公告的容量和配置对不上"

echo
echo "=== 2 场景（m14_check.py：空闲 → 开 3 条 → 激活 1 条 → 不合规 → 发现 → 断开） ==="
python3 "$CHECK" "$PORT" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "场景脚本自身 0 失败" || bad "场景脚本里有失败项"

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2; }

[ "$(grab NODE_TYPE)" = "00" ]        && ok "0x4002：node type = 0x00 网关（会往 CAN 子网转）" || bad "NODE_TYPE=$(grab NODE_TYPE)"
[ "$(grab MAX_SOCKETS)" = "08" ]      && ok "0x4002：最大 socket 数 = 8" || bad "MAX_SOCKETS=$(grab MAX_SOCKETS)"
[ "$(grab CUR_IDLE)" = "00" ]         && ok "0x4002：没有连接时 cur = 0" || bad "CUR_IDLE=$(grab CUR_IDLE)"
[ "$(grab MAX_DATA_SIZE)" = "4096" ]  && ok "0x4002：最大载荷 4096 字节（和 parseMessage 里卡的是同一个数）" || bad "MAX_DATA_SIZE=$(grab MAX_DATA_SIZE)"
[ "$(grab POWER_MODE)" = "01" ]       && ok "0x4004：电源模式 ready（0x01）" || bad "POWER_MODE=$(grab POWER_MODE)"
[ "$(grab CUR_AFTER_CONNECT)" = "03" ] && ok "开 3 条不激活 → cur = 3（数的是 socket）" || bad "CUR_AFTER_CONNECT=$(grab CUR_AFTER_CONNECT)"
[ "$(grab ACT_CODE)" = "10" ]         && ok "其中一条能正常激活（0x10），实体没被状态查询搞坏" || bad "ACT_CODE=$(grab ACT_CODE)"
[ "$(grab CUR_AFTER_ACT)" = "03" ]    && ok "激活不改变 socket 数：仍 3（连接 ≠ 激活）" || bad "CUR_AFTER_ACT=$(grab CUR_AFTER_ACT)"
[ "$(grab JUNK_STATUS_SILENT)" = "1" ] && ok "带载荷的 0x4001 → 沉默（UDP 上不造 NACK）" || bad "带载荷的 0x4001 被答了"
[ "$(grab JUNK_POWER_SILENT)" = "1" ]  && ok "带载荷的 0x4003 → 沉默" || bad "带载荷的 0x4003 被答了"
[ "$(grab TCP_STATUS_SILENT)" = "1" ]  && ok "走 TCP 问 0x4001 → 不回（标准里只许 UDP）" || bad "TCP 上的 0x4001 被答了"
[ "$(grab DISCOVERY_VIN)" = "LSVAA0000A1234567" ] \
    && ok "同一个端口上发现请求照旧能答（VIN 正确）" || bad "发现 VIN=$(grab DISCOVERY_VIN)"
[ "$(grab CUR_AFTER_CLOSE)" = "00" ]  && ok "连接全关 → cur 归零（账要还）" || bad "CUR_AFTER_CLOSE=$(grab CUR_AFTER_CLOSE)"

echo
echo "=== 3 等网关退场，核对它的账 ==="
for _ in $(seq 1 40); do
    grep -q "TCP 上收到 UDP 专属请求" "$SLOG" && break
    sleep 0.5
done
tail -6 "$SLOG"

ent=$(grep -o "其中实体状态/电源模式 [0-9]* 条" "$SLOG" | grep -o "[0-9]*" | head -1)
tlq=$(grep -o "UDP 专属请求 [0-9]* 次" "$SLOG" | grep -o "[0-9]*" | head -1)
# 场景里的 UDP 请求：5 次 0x4001（空闲/开3条/激活后/带载荷/关掉后）+ 2 次 0x4003（正常/带载荷）= 7 条
[ "${ent:-0}" = "7" ] && ok "网关账：实体状态/电源模式 7 条（和脚本发的条数对得上）" || bad "实体状态 ${ent:-?} 条（期望 7）"
[ "${tlq:-0}" = "1" ] && ok "网关账：TCP 上误发 1 次（只记账不回答）" || bad "TCP 专有请求 ${tlq:-?} 次（期望 1）"

echo
echo "=== 4 第二条腿：--power-mode 0（演'车还没上电'） ==="
cleanup
stdbuf -oL "$GW" --iface "$IFACE" --port "$PORT2" --seconds 8 \
        --route 0003:7A0:7A8:ECU_A --power-mode 0 > "$SLOG2" 2>&1 &
sleep 1.0
python3 "$CHECK" "$PORT2" 0 power-only > "$OUT2" 2>&1
cat "$OUT2"
grep -q "^FAIL=0$" "$OUT2" && ok "电源模式腿：脚本自身 0 失败" || bad "电源模式腿脚本失败"
grep -m1 "^POWER_MODE=" "$OUT2" | grep -q "00" \
    && ok "0x4004 跟着配置变成 0x00 not ready（不是写死的 01）" || bad "POWER_MODE=$(grep -m1 '^POWER_MODE=' "$OUT2" | cut -d= -f2)"

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M14 全绿 —— 实体状态是问得出来的：socket 数数连接不数激活、公告的值和实现一致、不合规用法沉默。"
    exit 0
fi
exit 1
