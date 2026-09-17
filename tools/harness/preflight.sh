#!/bin/bash
# 以脚本所在目录为根（离线工具，不需要设备）
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1

# NDK 工具链走统一探测（platform.sh），不写死路径/版本/平台
. ./platform.sh
NDK_ROOT="$(find_ndk || true)"
BINDIR="$(ndk_prebuilt_bin "$NDK_ROOT" 2>/dev/null || true)"
NM=""
for cand in "llvm-nm" "llvm-nm.exe"; do
    [ -n "$BINDIR" ] && [ -x "$BINDIR/$cand" ] && { NM="$BINDIR/$cand"; break; }
done
if [ -z "$NM" ]; then
    echo "找不到 llvm-nm：请设置 ANDROID_NDK_HOME（或 ANDROID_HOME 指向 SDK 根）。" >&2
    echo "  NDK_ROOT=[${NDK_ROOT:-未找到}]  prebuilt bin=[${BINDIR:-未找到}]" >&2
    exit 1
fi

# device kallsyms symbol names (col 2 of "addr name")
awk '{print $2}' dev_kallsyms.txt | sort -u > /tmp/dev_syms.txt
echo "device kallsyms symbols: $(wc -l < /tmp/dev_syms.txt)"

check() { # $1 file  $2 tag
  "$NM" -u "$1" 2>/dev/null | awk '{print $NF}' | grep -v '^$' | sort -u > "/tmp/u_$2.txt"
  total=$(wc -l < "/tmp/u_$2.txt")
  missing=$(comm -23 "/tmp/u_$2.txt" /tmp/dev_syms.txt | wc -l)
  echo
  echo "######## $2  ($1)"
  echo "undefined in module : $total"
  echo "NOT in device kallsyms: $missing"
  if [ "$missing" -gt 0 ]; then comm -23 "/tmp/u_$2.txt" /tmp/dev_syms.txt | sed 's/^/    MISSING: /'; fi
}

check android12-5.10_kernelpatch.ko ours_v0138
check apatch_builtin.ko/android12-5.10_kernelpatch.ko apatch_builtin_v0133
check android12-5.10_kernelsu.ko kernelsu_zip
