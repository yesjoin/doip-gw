#!/usr/bin/env bash
# ============================================================================
# m32_e2e.sh —— M32 端到端：响应方向也按 DID 过滤
#
# 段一  响应侧独立开（请求侧**故意不开**白名单）：纵深防御的核心
#       读档读 F190（公开）→ 62 F190 放行
#       读档读 F184（受限）→ 62 F184 被响应侧挡（要写档）→ 诊断仪超时
#       读档读 F1B0（锁死）→ 62 F1B0 被响应侧挡（要刷写档）→ 诊断仪超时
#       写档读 F184 → 放行；刷写档读 F1B0 → 放行
# 段二  对照腿：响应侧关 → 读档读 F1B0，62 F1B0 原样出来（数据真的流了出去）
# 段三  两条腿都开：读档读 F1B0 → 7F 22 33（请求侧先挡，到不了响应侧）
#
# 日志断言：横幅"（响应）：开/关"独立于请求侧；挡回日志"响应挡回"点名 DID；
#           退账里"DID 白名单（响应）"这一行是响应侧自己的账。
#
# 用法：bash tools/m32_e2e.sh [port] [port2]
# ============================================================================
set -u
PORT="${1:-13508}"
PORT2="${2:-13509}"
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
echo "=== 段一：响应侧独立开（请求侧白名单关）—— 数据出网卡前被拦 ==="
# ============================================================================
clean_state
# 6 号 ECU：带 --flash --secure，答 62 F190 / 62 F184 / 62 F1B0。
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 28 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu1.log" 2>&1 &
sleep 1.2
# 只开 --did-guard-resp，**不开 --did-guard**：请求侧 0x22 一律只算"读"，读档就过；
# 挡发生在响应回来的那一刻 —— 这才是"请求侧被绕过时，响应侧兜住"。
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 20 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --grant 0E01:write --grant 0E02:flash --default-grant read \
    --did-guard-resp --did-default guarded \
    --did F190:open --did F184:guarded --did F1B0:secret > "$TMP/gw1.log" 2>&1 &
GW1=$!
sleep 1.0

ck "1" "$(grep -c '诊断防火墙：开' "$TMP/gw1.log")" "横幅写明防火墙开"
ck "1" "$(grep -c 'DID 白名单（响应）：开' "$TMP/gw1.log")" "横幅写明响应白名单开"
ck "1" "$(grep -c 'DID 白名单：关' "$TMP/gw1.log")" "请求侧白名单关着（这才是纵深防御的测法）"

$PY "$HERE/m32_check.py" "$PORT" 1 > "$TMP/leg1.log" 2>&1
LEG1=$?
cat "$TMP/leg1.log"

ck "0x10" "$(kv "$TMP/leg1.log" R_ACT)" "读档能激活"
ck "62F190" "$(kv "$TMP/leg1.log" R_F190)" "读档读 VIN：62 F190 放行（公开）"
ck "TIMEOUT" "$(kv "$TMP/leg1.log" R_F184)" "读档读指纹：62 F184 被响应侧挡 → 超时"
ck "TIMEOUT" "$(kv "$TMP/leg1.log" R_F1B0)" "读档读钥匙表：62 F1B0 被响应侧挡 → 超时"
ck "0x10" "$(kv "$TMP/leg1.log" W_ACT)" "写档能激活"
ck "62F184" "$(kv "$TMP/leg1.log" W_F184)" "写档读指纹：62 F184 放行（写档够）"
ck "0x10" "$(kv "$TMP/leg1.log" F_ACT)" "刷写档能激活"
ck "62F1B0" "$(kv "$TMP/leg1.log" F_F1B0)" "刷写档读钥匙表：62 F1B0 放行（刷写档够）"
ck "0" "$LEG1" "段一脚本自身全绿"

# 退账是退出时才打的 —— 等它自己跑完 --seconds。
wait "$GW1" 2>/dev/null
sleep 0.2
ck "0" "$(grep -q '响应挡回：要给 SA 0x0E00 的「读响应 DID 0xF184（指纹，受限级）」(写档)' "$TMP/gw1.log"; echo $?)" "挡回日志点名受限 DID 与档位"
ck "0" "$(grep -q '响应挡回：要给 SA 0x0E00 的「读响应 DID 0xF1B0（钥匙表，锁死级）」(刷写档)' "$TMP/gw1.log"; echo $?)" "挡回日志点名锁死 DID 与档位"
RESP_N=$(grep -o 'DID 白名单（响应）：因 DID 级别不够而挡回 [0-9]* 条' "$TMP/gw1.log" | head -1 | grep -o '[0-9]*')
ck "2" "$RESP_N" "退账：响应方向挡回 2 条（读档的 F184 + F1B0）"
# 请求侧一条都没挡（没开白名单）：请求侧那行是「DID 白名单：因…」（白名单后直接冒号），
# 响应侧那行是「DID 白名单（响应）：因…」—— 用请求侧专属前缀把它俩分开。
ck "0" "$(grep -c 'DID 白名单：因 DID 级别不够' "$TMP/gw1.log")" "请求侧这一层没有挡（开都没开）"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段二：对照腿 —— 响应侧关，锁死数据照样流出去 ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu2.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT2" --seconds 16 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --default-grant read > "$TMP/gw2.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c 'DID 白名单（响应）：关' "$TMP/gw2.log")" "横幅写明响应白名单关"

$PY "$HERE/m32_check.py" "$PORT2" 2 > "$TMP/leg2.log" 2>&1
LEG2=$?
cat "$TMP/leg2.log"

ck "62F190" "$(kv "$TMP/leg2.log" R_F190)" "对照腿读 VIN 照旧"
ck "62F1B0" "$(kv "$TMP/leg2.log" R_F1B0)" "读档读钥匙表 → 62 F1B0 原样出来（没有响应侧这道闸）"
ck "0" "$LEG2" "段二脚本自身全绿"
ck "0" "$(grep -c 'DID 白名单（响应）：因' "$TMP/gw2.log")" "关着的时候没有响应侧这一层的账"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.4

# ============================================================================
echo "=== 段三：两条腿都开 —— 请求侧先挡，根本到不了响应侧 ==="
# ============================================================================
$STD "$ECU" --iface vcan0 --rx 18DA00F1 --tx 18DAF100 --vin LSVCC0000C7654321 --hw 03 \
    --battery-mv 12100 --delay-ms 8 --seconds 26 \
    --flash --flash-block 34 --flash-max 65536 --secure > "$TMP/ecu3.log" 2>&1 &
sleep 1.2
$STD "$GW" --iface vcan0 --port "$PORT" --seconds 16 \
    --route 0x0006:18DA00F1:18DAF100:网关ECU --power-mode 1 \
    --enforce-ops --grant 0E00:read --default-grant read \
    --did-guard --did-guard-resp --did-default guarded --did F190:open --did F1B0:secret \
    > "$TMP/gw3.log" 2>&1 &
sleep 1.0

ck "1" "$(grep -c 'DID 白名单：开' "$TMP/gw3.log")" "请求侧白名单开着"
ck "1" "$(grep -c 'DID 白名单（响应）：开' "$TMP/gw3.log")" "响应侧白名单也开着"

$PY "$HERE/m32_check.py" "$PORT" 3 > "$TMP/leg3.log" 2>&1
LEG3=$?
cat "$TMP/leg3.log"

ck "7F2233" "$(kv "$TMP/leg3.log" R_F1B0)" "读档读钥匙表 → 请求侧先挡（7F 22 33，不是超时）"
ck "0" "$LEG3" "段三脚本自身全绿"
pkill -x doip-gateway 2>/dev/null
pkill -x stub-ecu 2>/dev/null
sleep 0.3

echo ""
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
