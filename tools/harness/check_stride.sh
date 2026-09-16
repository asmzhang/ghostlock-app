#!/usr/bin/env bash
# 用设备事实核对 mm_struct stride（离线原则：能实测就不要推断）。
#
# 为什么需要它：
#   stride 有两个可能来源，而它们**不一致**——
#     · BTF 报的是 struct 大小（5.10 GKI 上是 0x3e0 = 992）
#     · SLUB 实际使用的 stride 是 slabinfo 的 objsize（0x3c0 = 960）
#   用错的那个会让整个 mm_struct 泄漏走偏（0x400 那次就是这么错的）。
#   所以这个值必须由 slabinfo 核对，不能靠推断。
#
# 用法：
#   bash tools/harness/check_stride.sh           # 用当前 offsets.h 里的值比对
#   bash tools/harness/check_stride.sh <期望值>   # 指定期望值（十六进制/十进制）
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(cd "$HERE/../.." && pwd)"
SHARED="$PROJ/src/kernels/offsets.h"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '  \033[36m·\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- 1. 从设备取事实
require_dev || exit 1

LINE=$(timeout 25 adb -s "$DEV" shell 'su -c "grep -m1 ^mm_struct /proc/slabinfo"' 2>/dev/null | tr -d '\r')
if [ -z "$LINE" ]; then
    bad "拿不到 slabinfo（需要 root）"
    exit 1
fi

# 字段：name active_objs num_objs objsize objperslab pagesperslab : tunables ...
OBSIZE=$(printf '%s\n' "$LINE" | awk '{print $4}')
[ -n "$OBSIZE" ] || { bad "无法解析 slabinfo: $LINE"; exit 1; }

printf '\n\033[1m== slabinfo 事实\033[0m\n'
info "$LINE"
info "objsize（SLUB stride）= $OBSIZE = $(printf '0x%X' "$OBSIZE")"

# ---------------------------------------------------------------- 2. 读代码里的值
# 注意：offsets.h 里按内核代际分成 STRUCT_OFFSETS_5_10 / _6_1 / _6_6 / _6_12 几块，
# 每个块都有自己的 .mm_struct_sz。所以必须**按当前设备的内核**选块，
# 否则会像第一次那样取到别的代际的值（0x400）而误报不一致。
RELEASE=$(timeout 20 adb -s "$DEV" shell 'uname -r' 2>/dev/null | tr -d '\r')
case "$RELEASE" in
    5.10.*) BLOCK="STRUCT_OFFSETS_5_10" ;;
    6.1.*)  BLOCK="STRUCT_OFFSETS_6_1" ;;
    6.6.*)  BLOCK="STRUCT_OFFSETS_6_6" ;;
    6.12.*) BLOCK="STRUCT_OFFSETS_6_12" ;;
    *)      BLOCK="" ;;
esac
[ -n "$BLOCK" ] && info "设备内核 $RELEASE → 代码块 $BLOCK" || info "设备内核 $RELEASE（无对应代码块）"

CODE_VAL=""
if [ -n "${1:-}" ]; then
    CODE_VAL="$1"
    info "使用指定期望值：$CODE_VAL"
elif [ -n "$BLOCK" ]; then
    # 只在该块内搜（从块名起，到下一个 #define STRUCT_OFFSETS_ 或文件尾）
    RAW=$(awk -v blk="$BLOCK" '
        $0 ~ ("^#define " blk "") {inside=1}
        inside && /^#define STRUCT_OFFSETS_/ && $0 !~ ("^#define " blk "") {inside=0}
        inside {print}
    ' "$SHARED" 2>/dev/null \
        | grep -oE '\.mm_struct_sz *= *0[xX][0-9a-fA-F]+' | head -1 | grep -oE '0[xX][0-9a-fA-F]+')
    if [ -n "$RAW" ]; then
        CODE_VAL="$RAW"
        info "offsets.h 的 $BLOCK 中 mm_struct_sz = $CODE_VAL"
    fi
fi

if [ -z "$CODE_VAL" ]; then
    bad "找不到代码里的 mm_struct_sz，且未指定期望值"
    exit 2
fi

# 归一化成十进制比较
to_dec() { case "$1" in 0[xX]*) printf '%d' "$1" ;; *) printf '%d' "$1" ;; esac; }
A=$(to_dec "$CODE_VAL"); B=$(to_dec "$OBSIZE")

printf '\n\033[1m== 比对\033[0m\n'
if [ "$A" = "$B" ]; then
    ok "一致：$CODE_VAL == $OBSIZE"
    exit 0
fi

bad "不一致：代码 $CODE_VAL ($A)  vs  slabinfo $OBSIZE ($B)"
printf '\n  说明：BTF 的 struct 大小（如 5.10 上是 0x3e0）**不能**当 stride 用，\n'
printf '        要以 slabinfo 的 objsize 为准。修正 src/kernels/offsets.h 里的\n'
printf '        .mm_struct_sz，并在注释里附上 slabinfo 原始行作为证据。\n'
exit 3
