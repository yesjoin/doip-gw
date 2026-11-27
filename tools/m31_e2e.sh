#!/usr/bin/env bash
# ============================================================================
# m31_e2e.sh —— M31 端到端：DID 白名单（读什么也分档）
#
# 段一  防火墙 + 白名单（默认级别=受限）：三台诊断仪各一档
#       读档读 VIN/会话通，读指纹(F184)/钥匙表(F1B0)/没登记的 F1FF 全 33
#       写档读指纹通、读钥匙表仍 33（锁死要刷写档）
#       刷写档读钥匙表通 —— 证明三类 DID 真的落到了三档
# 段二  对照腿：只开防火墙不开白名单 → 读档读什么都过，一条 33 都没有
# 段三  默认公开：F1FF 通、F1B0 仍 33 —— 默认档可配，显式规则压得住默认
#
# 日志断言：横幅逐条列出 DID→级别；挡回日志点名"DID 0xF1B0（钥匙表，锁死级）"；
#           退账里"因 DID 级别不够而挡回 N 条"这一行是这个新层自己的账。
#
# 用法：bash tools/m31_e2e.sh [port] [port2]
# ============================================================================
set -u
PORT="${1:-13506}"
PORT2="${2:-13507}"
GW=./build/doip-gateway
ECU=./build/stub-ecu
PY=python3
STD="stdbuf -oL -eL"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
FAIL=0
PASS=0

ck() {
    local want="$1" got="$2" what="$3"
    if [ "$want" = "$got" ]; then
        PASS=$((PASS + 1))
        printf '[ok ] %s\n' "$what"
    else
        FAIL=$((FAIL + 1))
        printf '[FAIL] %s（期望 %s，实到 %s）\n' "$what" "$want" "$got"
    fi
}

kv() {
    local file="$1" key="$2"
    sed -n "s/^${key}=//p" "$file" | head -1
}

clean_state() {
    pkill -x doip-gateway 2>/dev/null
    pkill -x stub-ecu 2>/dev/null
    sleep 0.4
}

echo "=== 环境 ==="
[ -d /sys/class/net/vcan0 ] || { echo "[FAIL] vcan0 不存在"; exit 1; }
die() { echo "[FAIL] $1"; clean_state; exit 1; }
[ -x "$GW" ] || die "没有 $GW"
[ -x "$ECU" ] || die "没有 $ECU"

# ============================================================================
echo "=== 段一：白名单开（默认受限），三类 DID 落到三档 ==="
# ============================================================================
clean_state
# 6 号 ECU 带 --flash --secure：够不够档由网关判，ECU 只管答自己的话。
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu1.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 18 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --grant 0E01:write --grant 0E02:flash --default-grant read \
    --did-guard --did-default guarded \
    --did F190:open --did F186:open --did F191:open \
    --did F184:guarded --did F1B0:secret > "$TMP/gw1.log" 2>&1 &
GW1=$!
sleep 1.0

ck "1" "$(grep -c '诊断防火墙：开' "$TMP/gw1.log")" "横幅写明防火墙开"
ck "1" "$(grep -c 'DID 白名单：开' "$TMP/gw1.log")" "横幅写明白名单开"
ck "1" "$(grep -c '0xF190 → 公开（VIN）' "$TMP/gw1.log")" "横幅列出 0xF190 是公开"
ck "1" "$(grep -c '0xF1B0 → 锁死（钥匙表）' "$TMP/gw1.log")" "横幅列出 0xF1B0 是锁死"
ck "1" "$(grep -c '0xF184 → 受限（指纹）' "$TMP/gw1.log")" "横幅列出 0xF184 是受限"
ck "0" "$(grep -q '默认级别：受限' "$TMP/gw1.log"; echo $?)" "横幅写明默认级别"

$PY "$HERE/m31_check.py" "$PORT" 1 > "$TMP/leg1.log" 2>&1
LEG1=$?
cat "$TMP/leg1.log"

ck "0x10" "$(kv "$TMP/leg1.log" R_ACT)" "读档能激活"
ck "62F190" "$(kv "$TMP/leg1.log" R_F190)" "读档读 VIN（公开）通"
ck "62F186" "$(kv "$TMP/leg1.log" R_F186)" "读档读会话（公开）通"
ck "7F2233" "$(kv "$TMP/leg1.log" R_F184_NRC)" "读档读指纹（受限）→ 7F 22 33"
ck "7F2233" "$(kv "$TMP/leg1.log" R_F1B0_NRC)" "读档读钥匙表（锁死）→ 7F 22 33"
ck "7F2233" "$(kv "$TMP/leg1.log" R_F1FF_NRC)" "读档读没登记的 DID → 7F 22 33（默认受限）"
ck "NO33" "$(kv "$TMP/leg1.log" R_19_NOT33)" "0x19 读 DTC 不被白名单碰（不是 33）"

ck "0x10" "$(kv "$TMP/leg1.log" W_ACT)" "写档能激活"
ck "NO33" "$(kv "$TMP/leg1.log" W_F184_NOT33)" "写档读指纹（受限）→ 过了门禁"
ck "7F2233" "$(kv "$TMP/leg1.log" W_F1B0_NRC)" "写档读钥匙表（锁死）→ 7F 22 33"
ck "NO33" "$(kv "$TMP/leg1.log" W_F1FF_NOT33)" "写档读没登记的 DID → 过了门禁"

ck "0x10" "$(kv "$TMP/leg1.log" F_ACT)" "刷写档能激活"
ck "NO33" "$(kv "$TMP/leg1.log" F_F1B0_NOT33)" "刷写档读钥匙表 → 过了门禁"
ck "NO33" "$(kv "$TMP/leg1.log" F_F1FF_NOT33)" "刷写档读没登记的 DID → 过了门禁"

ck "0" "$LEG1" "段一脚本自身全绿"
# 退账是退出时才打的，SIGTERM 不走清理路径 —— 等它自己跑完 --seconds。
wait "$GW1" 2>/dev/null
sleep 0.2

ck "0" "$(grep -q '想「读 DID 0xF1B0（钥匙表，锁死级）」' "$TMP/gw1.log"; echo $?)" "挡回日志点名 DID 与级别"
ck "0" "$(grep -q '」(刷写档)，但它只有「读」（DID 抬档挡的）' "$TMP/gw1.log"; echo $?)" "挡回日志说明是 DID 抬档"
DID_N=$(grep -o '因 DID 级别不够而挡回 [0-9]* 条' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ck "4" "$DID_N" "退账：DID 抬档挡回 4 条（读档 3 + 写档 1）"
DENY_N=$(grep -o '挡回 [0-9]* 条（要读' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ck "4" "$DENY_N" "总挡回也是 4 条（这几条本来就只是读）"
WRITEY_N=$(grep -o '要写 [0-9]*' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
FLASHY_N=$(grep -o '要刷写 [0-9]*' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ck "2" "$WRITEY_N" "「要写」被挡 2 条（读档的 F184/F1FF）"
ck "2" "$FLASHY_N" "「要刷写」被挡 2 条（读档 F1B0 + 写档 F1B0）"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段二：对照腿 —— 只开防火墙，读档读一切都过 ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu2.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT2" --seconds 16 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --default-grant read > "$TMP/gw2.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c 'DID 白名单：关' "$TMP/gw2.log")" "横幅写明白名单关"

$PY "$HERE/m31_check.py" "$PORT2" 2 > "$TMP/leg2.log" 2>&1
LEG2=$?
cat "$TMP/leg2.log"

ck "62F190" "$(kv "$TMP/leg2.log" R_F190)" "对照腿能读 VIN"
ck "NO33" "$(kv "$TMP/leg2.log" R_F184_NOT33)" "读档读指纹 → 过了门禁（没有这一层）"
ck "NO33" "$(kv "$TMP/leg2.log" R_F1B0_NOT33)" "读档读钥匙表 → 过了门禁"
ck "NO33" "$(kv "$TMP/leg2.log" R_F1FF_NOT33)" "读档读没登记的 DID → 过了门禁"
ck "0" "$LEG2" "段二脚本自身全绿"
ck "0" "$(grep -c '因 DID 级别不够' "$TMP/gw2.log")" "关着的时候没有 DID 这一层的账"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段三：默认级别改成公开，显式锁死压得住默认 ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu3.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 14 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --default-grant read \
    --did-guard --did-default open --did F1B0:secret > "$TMP/gw3.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c 'DID 白名单：开' "$TMP/gw3.log")" "段三白名单也开着"
ck "0" "$(grep -q '默认级别：公开' "$TMP/gw3.log"; echo $?)" "横幅写明默认级别是公开"

$PY "$HERE/m31_check.py" "$PORT" 3 > "$TMP/leg3.log" 2>&1
LEG3=$?
cat "$TMP/leg3.log"

ck "62F190" "$(kv "$TMP/leg3.log" R_F190)" "默认公开时 VIN 照旧"
ck "NO33" "$(kv "$TMP/leg3.log" R_F1FF_NOT33)" "没登记的 DID → 过了门禁（默认公开）"
ck "7F2233" "$(kv "$TMP/leg3.log" R_F1B0_NRC)" "显式锁死的 F1B0 → 仍 7F 22 33"
ck "0" "$LEG3" "段三脚本自身全绿"

pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.3

echo ""
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
