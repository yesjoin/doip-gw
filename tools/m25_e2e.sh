#!/usr/bin/env bash
# =============================================================================
# m25_e2e.sh —— M25 验收：清单指纹 + 变更世代
#
# 用法： bash tools/m25_e2e.sh [端口A] [端口B]      默认 13494 / 13495
#
# 这一步要立住的判据：
#   · 摘要（F1B1）是**数量**，指纹（F1B2）是**内容** —— 三台"总 4 / 启用 4"，
#     摘要说一致，指纹能点出"0x0006 与别人不同"；
#   · 世代是**历史**：改过两次就是 2，重启后还是 2（v2 文件里那行 VER）；
#   · 内容回原样、世代更高 = "这台被人动过" —— 与"这台和别台一样"是两件事；
#   · 写新读旧：v1 旧文件（没有 VER 行）读得进来，世代按 0 算，指纹不变。
#
# 段一：三台全新表 → 假一致（A 装 5 / B 装 6 / C 装 5）。
# 段二：同一批文件重启 → 世代活过来；A 退役再改回来（指纹回原样、世代更高）。
# 段三：把 A 的文件改写成 v1 → 读进来世代 0、指纹不变。
# =============================================================================
set -u

PORT_A=${1:-13494}
PORT_B=${2:-13495}
IFACE=${IFACE:-vcan0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GW=$ROOT/build/doip-gateway
STUB=$ROOT/build/stub-ecu
CHECK=$ROOT/tools/m25_check.py
STORE_A=/tmp/m25_keys_a.txt
STORE_B=/tmp/m25_keys_b.txt
STORE_C=/tmp/m25_keys_c.txt
ELOG_A=/tmp/m25_ecu_a.log
ELOG_B=/tmp/m25_ecu_b.log
ELOG_C=/tmp/m25_ecu_c.log
SLOG=/tmp/m25_gw.log
OUT=/tmp/m25_check.txt

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
python3 -m py_compile "$CHECK" 2>/dev/null || { bad "m25_check.py 自身编译不过（先 py_compile）"; exit 1; }

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
echo "=== 1 段一：三台全新表 —— 摘要说一致，指纹点出 0x0006 ==="
cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp" /tmp/m25_fp.txt
start_fleet "$PORT_A" 30 1

grep -q "清单：" "$ELOG_A" && ok "启动行报了清单（版本 + 指纹）" || bad "启动行没有清单"
grep -q "DOIPKEYRING 2" "$STORE_A" && ok "盘上是 v2 文件（带 VER 行）" || bad "盘上不是 v2"
grep -q "^VER " "$STORE_A" && ok "文件里有 VER 行（世代落盘）" || bad "文件里没有 VER 行"

python3 "$CHECK" "$PORT_A" 1 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段一脚本自身 0 失败" || bad "段一有失败项"

[ "$(grab DIGEST_BOOT)" = "0003=62F1B102020000,0006=62F1B102020000,0007=62F1B102020000" ] \
    && ok "出厂：摘要三台 2/2/0/0" || bad "DIGEST_BOOT=$(grab DIGEST_BOOT)"
case "$(grab STAMP_BOOT_GEN0)" in
    *0003=62F1B20000*0006=62F1B20000*0007=62F1B20000*)
        ok "出厂：三台世代都是 0（没人改过）" ;;
    *)  bad "STAMP_BOOT_GEN0=$(grab STAMP_BOOT_GEN0)" ;;
esac
[ "$(grab STAMP_BOOT_SAME_FP)" != "" ] && ok "出厂：三台指纹一致" || bad "出厂指纹不一致"

[ "$(grab DIGEST_LIE_EQUAL)" = "0003=62F1B104040000,0006=62F1B104040000,0007=62F1B104040000" ] \
    && ok "假一致成立：三台都是 4/4/0/0 —— 摘要完全看不出问题" || bad "DIGEST_LIE_EQUAL=$(grab DIGEST_LIE_EQUAL)"
[ "$(grab STAMP_FP_SPLIT)" != "" ] && ok "指纹分叉：A/C 相同、B 不同" || bad "STAMP_FP_SPLIT 空"
[ "$(grab STAMP_POINT_OUT)" = "不一致，0006 的指纹与 0x0003 不同" ] \
    && ok "点名 0x0006（不是只说「不一致」）" || bad "STAMP_POINT_OUT=$(grab STAMP_POINT_OUT)"

wait 2>/dev/null
grep -q "清单：版本 2" "$ELOG_B" && ok "0x0006 自己记的账是「版本 2」" || bad "0x0006 账不对"

# =============================================================================
echo
echo "=== 2 段二：同一批文件重启 —— 世代活过来，A 退役再改回（指纹回原样、世代更高）==="
start_fleet "$PORT_B" 24 1
grep -q "清单：版本 2" "$ELOG_A" && ok "重启后 0x0003 还是「版本 2」（VER 落盘生效）" || bad "重启后版本没活过来"
grep -q "读到 4 把" "$ELOG_A" && ok "重启后表也还在（4 把）" || bad "重启后表丢了"

python3 "$CHECK" "$PORT_B" 2 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段二脚本自身 0 失败" || bad "段二有失败项"

[ "$(grab STAMP_RESTART_GEN2)" = "0003:2;0006:2;0007:2" ] \
    && ok "三台世代都是 2（装 3 号一次 + 装 5/6 号一次）" || bad "STAMP_RESTART_GEN2=$(grab STAMP_RESTART_GEN2)"
[ "$(grab STAMP_RESTART_FP_SAME)" != "" ] && ok "重启后指纹与重启前逐台一致" || bad "重启后指纹变了"
[ "$(grab GEN_AFTER_RETIRE)" = "3" ] && ok "退役 3 号 → 版本 3" || bad "GEN_AFTER_RETIRE=$(grab GEN_AFTER_RETIRE)"
[ "$(grab FP_BACK_TO_SAME)" != "" ] && ok "再改回启用 → 指纹回到原值（内容真回原样）" || bad "指纹没回原样"
[ "$(grab GEN_STILL_HIGHER)" = "4" ] && ok "但世代是 4：内容一样、历史不一样" || bad "GEN_STILL_HIGHER=$(grab GEN_STILL_HIGHER)"
[ "$(grab OTHERS_UNTOUCHED)" = "0006:2;0007:2" ] && ok "另两台没被人动过（还是 2）" || bad "OTHERS_UNTOUCHED=$(grab OTHERS_UNTOUCHED)"

wait 2>/dev/null

# =============================================================================
echo
echo "=== 3 段三：把 A 的文件改写成 v1 —— 写新读旧，世代归零、指纹不变 ==="
python3 - "$STORE_A" <<'PY'
import hashlib
import sys

p = sys.argv[1]
with open(p, "r") as f:
    lines = [ln.rstrip("\n") for ln in f if ln.strip()]
assert lines[0] == "DOIPKEYRING 2", lines[0]
body = "DOIPKEYRING 1\n" + "\n".join(ln for ln in lines[1:-1] if not ln.startswith("VER ")) + "\n"
checksum = hashlib.sha256(body.encode()).hexdigest()[:16]
with open(p + ".v1", "w") as f:
    f.write(body + "SUM " + checksum + "\n")
print("写成 v1：%s.v1（%d 行，无 VER）" % (p, body.count("\n") + 1))
PY
cp "$STORE_A.v1" "$STORE_A"

start_fleet "$PORT_A" 16 0
grep -q "没有 VER" "$ELOG_A" || true
python3 "$CHECK" "$PORT_A" 3 > "$OUT" 2>&1
cat "$OUT"
grep -q "^FAIL=0$" "$OUT" && ok "段三脚本自身 0 失败" || bad "段三有失败项"
[ "$(grab V1_GEN_ZERO)" = "0" ] && ok "v1 旧文件读进来世代是 0（不猜、也不当一次变更）" || bad "V1_GEN_ZERO=$(grab V1_GEN_ZERO)"
[ "$(grab V1_FP_SAME)" != "" ] && ok "指纹不变（内容没变，只是格式旧）" || bad "V1_FP_SAME 空"
[ "$(grab V1_DIGEST)" = "4/4/0/0" ] && ok "表内容照读：4/4/0/0" || bad "V1_DIGEST=$(grab V1_DIGEST)"

wait 2>/dev/null
cleanup
rm -f "$STORE_A" "$STORE_B" "$STORE_C" "$STORE_A.tmp" "$STORE_B.tmp" "$STORE_C.tmp" \
      "$STORE_A.v1" /tmp/m25_fp.txt

echo
echo "--------------------------------"
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -eq 0 ]; then
    echo "M25 全绿 —— 摘要是数量、指纹是内容、世代是历史；写新读旧。"
    exit 0
fi
exit 1
