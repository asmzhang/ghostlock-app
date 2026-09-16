#!/bin/bash
BIN=/d/platform/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin
NM=$BIN/llvm-nm.exe
# 以脚本所在目录为根（离线工具，不依赖 env.sh / 不需要设备）
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1

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
