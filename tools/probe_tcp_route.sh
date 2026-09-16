#!/usr/bin/env bash
# 探测当前设备上 TCP zerocopy 路线是否可用（决定 exploit 该走 TCP 还是 pselect）。
#
# 原理：只做一次 getsockopt(TCP_ZEROCOPY_RECEIVE)，读内核对 optlen 的回写值——
#   内核里有 `if (len > sizeof(zc)) len = sizeof(zc);` 再 put_user(len, optlen)，
#   所以回写值就是内核真实的 sizeof(struct tcp_zerocopy_receive)。
# exploit 需要写到 zc 偏移 0x28/0x30（waiter->task / waiter->lock），故该值需 >= 0x38。
#
# 为什么不能靠编译期判断：设备实测 5.10 上，NDK 头文件是 0x40，内核实际是 0x28。
#
# 用法： bash tools/probe_tcp_route.sh
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/harness" && pwd)/env.sh"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(cd "$HERE/.." && pwd)"
SRC="$HERE/probe_tcp_route.c"
OUT="$PROJ/build/probe_tcp_route"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '  \033[36m·\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- 找编译器
ANDROID_HOME="${ANDROID_HOME:-D:/platform/Android/Sdk}"
NDK_DIR=$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | tail -1)
if [ -z "$NDK_DIR" ]; then bad "找不到 NDK：$ANDROID_HOME/ndk"; exit 1; fi
CC="${NDK_DIR}toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android35-clang"
[ -x "$CC" ] || CC="${NDK_DIR}toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android34-clang"
[ -x "$CC" ] || { bad "找不到 aarch64 clang：$CC"; exit 1; }
info "clang    $(basename "$CC")"

# ---------------------------------------------------------------- 编译
# 注意：clang 是 Windows 可执行文件，**不认** /d/... 这种 POSIX 路径，必须转成盘符格式。
winpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"
    else printf '%s' "$1" | sed -E 's|^/([a-zA-Z])/|\1:/|'
    fi
}
mkdir -p "$(dirname "$OUT")"
if ! "$CC" -O2 -o "$(winpath "$OUT")" "$(winpath "$SRC")" 2>&1; then
    bad "编译失败"
    exit 1
fi
ok "编译完成  $OUT"

# ---------------------------------------------------------------- 上路
require_dev || exit 1
REMOTE=/data/local/tmp/probe_tcp_route
if ! timeout 60 adb -s "$DEV" push "$OUT" "$REMOTE" >/dev/null 2>&1; then
    # 本机 adb 需要 Windows 盘符路径
    WIN_OUT="$(cygpath -w "$OUT" 2>/dev/null || printf '%s' "$OUT")"
    timeout 60 adb -s "$DEV" push "$WIN_OUT" "$REMOTE" >/dev/null 2>&1 || { bad "推送失败"; exit 1; }
fi
timeout 20 adb -s "$DEV" shell "chmod 755 $REMOTE" >/dev/null 2>&1
ok "已推送    $REMOTE"

# ---------------------------------------------------------------- 运行
printf '\n\033[1m== 探测结果\033[0m\n'
timeout 60 adb -s "$DEV" shell "$REMOTE" 2>&1 | tr -d '\r'
