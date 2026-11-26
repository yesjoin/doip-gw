#!/usr/bin/env bash
# =============================================================================
# m26_e2e.sh —— M26 验收：变更流水（谁改的 / 什么时候 / 动了哪把）
#
# 用法： bash tools/m26_e2e.sh [端口A] [端口B]      默认 13496 / 13497
#
# 这一步要立住的判据：
#   · "没有变更"要能说出口：F1B3 回 62 F1 B3 00，不是一条假记录；
#   · 一条流水记全六件事：世代 / 指纹 / 动作 / 通道 / keyId / 第几次上电 + 秒；
#   · 广播改和逐台改分得开：同一张表，chan=02 和 chan=01 是两种风险；
#   · 时间不骗人：没有 RTC，能报的只有"第几次带变更的上电 + 那次上电后多少秒"。
#
# 段一：三台全新表 → 各自装 3 号 → 一条广播退役 → 逐台复活（三种通道/动作都走一遍）。
# 段二：同一批文件重启 → 条数与上电序活过来；再改一笔，新账记"第 2 次上电"。
# 段三：把 A 的文件降级成 v2 → 表和世代还在、流水没了，而且启动横幅要说出来。
# =============================================================================
set -u

PORT_A=${1:-13496}
PORT_B=${2:-13497}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m26_check.py
STORE_A=/tmp/m26_keys_a.txt
STORE_B=/tmp/m26_keys_b.txt
STORE_C=/tmp/m26_keys_c.txt
ELOG_A=/tmp/m26_ecu_a.log
ELOG_B=/tmp/m26_ecu_b.log
ELOG_C=/tmp/m26_ecu_c.log
SLOG=/tmp/m26_gw.log
OUT=/tmp/m26_check.txt

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skip() { echo "[SKIP] $1"; }

cleanup() {
    pkill -x doip-gateway 2>/dev/null || true
    pkill -x stub-ecu 2>/dev/null || true
    true
}
trap cleanup EXIT

[ -e "/sys/class/net/$IFACE" ] || { skip "没有 $IFACE"; exit 0; }
[ -x "$GW" ]   || { skip "没有 $GW（先 cmake --build build）"; exit 0; }
[ -x "$STUB" ] || { skip "没有 $STUB"; exit 0; }
command -v python3 >/dev/null 2>&1 || { skip "没有 python3"; exit 0; }
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m26_check.py 自身编译不过（先 py_compile）"; exit 1; }

grab() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2-; }

start_fleet() {   # $1=端口 $2=秒数 $3=要不要网关(1/0)
    local port=$1 secs=$2 withgw=${3:-1}
    cleanup
    : > "$ELOG_A"; : > "$ELOG_B"; : > "$ELOG_C"
    stdbuf -oL "$STUB" --iface "$IFACE" --rx 7A0 --tx 7A8 --func-rx 7DF \
            --vin LSVZZ0000B7654321 --hw HW02 --seconds "$secs" \
            --flash --flash-block 34 --flash-max 65536 --secure \
            --key-store "$STORE_A" > "$ELOG_A" 2>&1 &
    if [ "$withgw" = "1" ]; then
        stdbuf -oL "$STUB" --iface "$IFACE" --rx 18DA00F1 --tx 18DAF100 --func-rx 7DF \
                --vin LSVCC0000C7654321 --hw HW03 --seconds "$secs" \
                --flash --flash-block 34 --flash-max 65536 --secure \
                --key-store "$STORE_B" > "$ELOG_B" 2>&1 &
        stdbuf -oL "$STUB" --iface "$IFACE" --rx 7B0 --tx 7B8 --func-rx 7DF \
                --vin LSVBB0000B7654321 --hw HW04 --seconds "$secs" \
                --flash --flash-block 34 --flash-max 65536 --secure \
                --key-store "$STORE_C" > "$ELOG_C" 2>&1 &
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A \
                --route 0006:18DA00F1:18DAF100:ECU_B \
                --route 0007:7B0:7B8:ECU_C \
                --func 0xE400:0x7DF:ALL > "$SLOG" 2>&1 &
    else
        stdbuf -oL "$GW" --iface "$IFACE" --port "$port" --seconds $((secs - 2)) \
                --route 0003:7A0:7A8:ECU_A \
                --func 0xE400:0x7DF:ALL > "$SLOG" 2>&1 &
    fi
    sleep 1.5
}

# =============================================================================
echo "=== 1 段一：全新表 —— 出厂无流水 → 装一把 → 广播退役 → 逐台复活 ==="
cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp" /tmp/m26_state.txt
start_fleet "$PORT_A" 30 1

grep -q "DOIPKEYRING 3" "$STORE_A" && ok "盘上是 v3 文件（M26 起写新格式）" || bad "盘上不是 v3"
grep -q "^BOOT " "$STORE_A" && ok "文件里有 BOOT 行（上电序落盘）" || bad "文件里没有 BOOT 行"
grep -q "流水：最近 0 条（还没有变更）" "$ELOG_A" \
    && ok "出厂横幅说「最近 0 条（还没有变更）」（不假装有账）" || bad "出厂横幅没报流水"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段一脚本自身 0 失败" || bad "段一有失败项"

[ "$(grab BOOT_NO_CHANGE)" = "62F1B300" ] && ok "出厂 F1B3 = 62 F1 B3 00（条数 0，4 字节）" || bad "BOOT_NO_CHANGE=$(grab BOOT_NO_CHANGE)"
[ "$(grab AFTER_INSTALL_OVERVIEW)" = "0003:1/01/0003;0006:1/01/0003;0007:1/01/0003" ] \
    && ok "装一把之后：三台都是「1 条 / 装入 / 0x0003」" || bad "AFTER_INSTALL_OVERVIEW=$(grab AFTER_INSTALL_OVERVIEW)"
case "$(grab DETAIL_INSTALL)" in
    gen=1,act=01,chan=01,key=0003,boot=1,sec=*)
        ok "详情第 1 条：世代 1 / 装入 / 物理寻址 / 0x0003 / 第 1 次上电" ;;
    *)  bad "DETAIL_INSTALL=$(grab DETAIL_INSTALL)" ;;
esac
[ "$(grab BC_RETIRE_OK)" = "0003=7101020700;0006=7101020700;0007=7101020700" ] \
    && ok "一条广播改三台都成功（每台各自解锁过）" || bad "BC_RETIRE_OK=$(grab BC_RETIRE_OK)"
[ "$(grab AFTER_BC_OVERVIEW)" = "0003:2/02/0003;0006:2/02/0003;0007:2/02/0003" ] \
    && ok "广播之后：三台都「2 条 / 退役 / 0x0003」" || bad "AFTER_BC_OVERVIEW=$(grab AFTER_BC_OVERVIEW)"
[ "$(grab BC_CHANNEL_02)" = "0003:02;0006:02;0007:02" ] \
    && ok "通道记成 02（广播）——同一张表，广播改和逐台改分得开" || bad "BC_CHANNEL_02=$(grab BC_CHANNEL_02)"
case "$(grab DETAIL_REVIVE)" in
    act=03,gen=3,chan=01,sec=*)
        ok "逐台复活：动作 03（复活）不是 01（装入），通道 01" ;;
    *)  bad "DETAIL_REVIVE=$(grab DETAIL_REVIVE)" ;;
esac
[ "$(grab JOURNAL_FP_MATCH)" = "OK" ] && ok "流水里的指纹 = F1B2 现在报的指纹（对账口径一致）" || bad "JOURNAL_FP_MATCH=$(grab JOURNAL_FP_MATCH)"
[ "$(grab OLD_ENTRY_KEPT)" = "act=02,boot=1" ] && ok "老一笔（广播退役）还在，且仍记着「第 1 次上电」" || bad "OLD_ENTRY_KEPT=$(grab OLD_ENTRY_KEPT)"
[ "$(grep -c '^L ' "$STORE_A")" = "3" ] && ok "A 的盘上正好 3 行流水" || bad "A 盘上流水行数不对"

wait 2>/dev/null
grep -q "流水：" "$ELOG_B" && ok "0x0006 退账也报了流水" || bad "0x0006 退账没流水"
grep -q "退役 0x0003，广播" "$ELOG_B" && ok "退账里能看见「退役 0x0003，广播」" || bad "退账文案不对"

# =============================================================================
echo
echo "=== 2 段二：重启 —— 条数与上电序活过来，再改一笔记「第 2 次上电」 ==="
FPHINT=$(grep -o 'fp=[0-9A-F]*' /tmp/m26_state.txt | cut -d= -f2)
GENT=$(grep -o 'gen=[0-9]*' /tmp/m26_state.txt | cut -d= -f2)
start_fleet "$PORT_B" 24 1
grep -q "流水：最近 3 条" "$ELOG_A" && ok "重启后 0x0003 横幅说「最近 3 条」" || bad "重启后 A 条数不对"
grep -q "流水：最近 2 条" "$ELOG_B" && ok "重启后 0x0006 横幅说「最近 2 条」（各记各的）" || bad "重启后 B 条数不对"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段二脚本自身 0 失败" || bad "段二有失败项"

[ "$(grab RESTART_COUNT)" = "0003:3;0006:2;0007:2" ] && ok "重启后条数逐台对得上" || bad "RESTART_COUNT=$(grab RESTART_COUNT)"
[ "$(grab RESTART_STAMP)" = "gen=$GENT,fp=$FPHINT" ] \
    && ok "重启后世代与指纹都没变（$GENT / $FPHINT）" || bad "RESTART_STAMP=$(grab RESTART_STAMP)"
[ "$(grab RESTART_OLD_BOOT_STILL_1)" = "boot=1" ] \
    && ok "旧账还记着「第 1 次上电」—— 时间没被现在污染" || bad "RESTART_OLD_BOOT_STILL_1=$(grab RESTART_OLD_BOOT_STILL_1)"
case "$(grab NEW_ENTRY_BOOT2)" in
    gen=4,boot=2,key=0004,sec=*)
        ok "重启后新改一笔：记「第 2 次上电」、动的是 0x0004" ;;
    *)  bad "NEW_ENTRY_BOOT2=$(grab NEW_ENTRY_BOOT2)" ;;
esac
[ "$(grab OLD_STAYS_BOOT1)" = "boot=1" ] && ok "上一条还是「第 1 次上电」（流水不会整体改写）" || bad "OLD_STAYS_BOOT1=$(grab OLD_STAYS_BOOT1)"
[ "$(grab COUNT_AFTER4)" = "4" ] && ok "A 现在 4 条" || bad "COUNT_AFTER4=$(grab COUNT_AFTER4)"
[ "$(grep -c '^L ' "$STORE_A")" = "4" ] && ok "A 盘上 4 行流水（重启前 3 + 新 1）" || bad "A 盘上流水行数不对"

wait 2>/dev/null

# =============================================================================
echo
echo "=== 3 段三：把 A 的文件降级成 v2 —— 表和世代还在，流水没了，横幅要说出来 ==="
python3 - "$STORE_A" <<'PY'
import hashlib
import sys

p = sys.argv[1]
with open(p, "r") as f:
    lines = [ln.rstrip("\n") for ln in f if ln.strip()]
assert lines[0] == "DOIPKEYRING 3", lines[0]
body = "DOIPKEYRING 2\n"
body += "\n".join(ln for ln in lines[1:-1] if ln.startswith("VER ") or ln.startswith("K ")) + "\n"
checksum = hashlib.sha256(body.encode()).hexdigest()[:16]
with open(p + ".v2", "w") as f:
    f.write(body + "SUM " + checksum + "\n")
print("写成 v2：%s.v2（%d 行，没有 BOOT / L）" % (p, body.count("\n") + 1))
PY
cp "$STORE_A.v2" "$STORE_A"

start_fleet "$PORT_A" 16 0
grep -q "没有流水" "$ELOG_A" && ok "横幅说了「改过 4 次但没有流水」—— 丢了就说丢了" || bad "横幅没提示流水丢了"

python3 "$CHECK" "$PORT_A" 3 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段三脚本自身 0 失败" || bad "段三有失败项"
[ "$(grab V2_DIGEST)" = "4/4/0/0" ] && ok "v2 文件：表照读（4/4/0/0）" || bad "V2_DIGEST=$(grab V2_DIGEST)"
[ "$(grab V2_GEN_KEPT)" = "4" ] && ok "v2 文件：世代还在（4）" || bad "V2_GEN_KEPT=$(grab V2_GEN_KEPT)"
[ "$(grab V2_NO_JOURNAL)" = "62F1B300" ] && ok "v2 文件：流水是空的（0 条，不编）" || bad "V2_NO_JOURNAL=$(grab V2_NO_JOURNAL)"

wait 2>/dev/null
cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp" \
      "$STORE_A.v2" /tmp/m26_state.txt

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M26 全绿 —— 没有变更说得出口、六件事记得下、通道分得开、时间不骗人。"
    exit 0
fi
exit 1
