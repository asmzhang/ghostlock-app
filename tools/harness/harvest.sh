#!/bin/bash
# 命中后立即取证：把这次命中产生的全部证据拉到本机。
# 用法： <ARCHIVE_DIR>/_harvest.sh [tag]
# 注意：adb.exe 必须用 Windows 盘符路径（POSIX /d/... 会静默失败）。
# 设备与路径来自 env.sh（自动探测 + 以脚本目录为根）
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
require_dev || exit 1
TAG="${1:-hit}"
OUT="${LOGDIR}/harvest_${TAG}"
mkdir -p "$OUT"

echo "=== 先等设备可用；一旦可用就立刻测 su（模块可能随时消失）==="
for i in $(seq 1 40); do
  st=$(tmo 8 adb -s $DEV shell "echo ok" 2>/dev/null | tr -d '\r')
  if [ "$st" = "ok" ]; then
    echo "  device reachable (try $i)"
    echo "--- 立即：/proc/modules ---"
    tmo 15 adb -s $DEV shell "grep -E \"kernelpatch|kernelsu\" /proc/modules 2>/dev/null || echo \"(no module)\""
    echo "--- 立即：su ---"
    tmo 15 adb -s $DEV shell "su -c id 2>&1 | head -3"
    break
  fi
  sleep 5
done
sleep 3

pull() { # $1 = 设备路径, $2 = 本地名
  local src="$1" dst="$OUT/$2"
  tmo 40 adb -s $DEV pull "$src" "$dst" >/dev/null 2>&1 \
    && echo "  OK   $src -> $2 ($(stat -c%s "$dst" 2>/dev/null) B)" \
    || echo "  MISS $src"
}

echo "=== 设备侧状态 ==="
tmo 20 adb -s $DEV shell "cat /proc/uptime; uname -r; echo \"--- modules ---\"; grep -E \"kernelpatch|kernelsu\" /proc/modules || echo \"(no module)\"" 2>&1

echo "=== 拉取证据 ==="
pull /sdcard/ghostlock_klog                klog_sdcard.txt
pull /data/local/tmp/.ghostlock_klog       klog.txt
pull /data/local/tmp/.ghostlock_result     result.txt
pull /data/local/tmp/.ghostlock_ksu.log      ksu_tmp.log
pull /data/local/tmp/.ghostlock_dmesg2.log  dmesg2.log
pull /data/local/tmp/.ghostlock_dmesg.log   dmesg1.log
pull /data/local/tmp/.ghostlock_pstore.log  pstore.log
pull /sdcard/ghostlock_ksu.log              ksu_sdcard.log
pull /sdcard/ghostlock_dmesg.log            dmesg_sdcard.log
pull /sdcard/.ghostlock_probe2              probe2.txt

echo "=== 模块重定位的关键判据（klog /sdcard 副本）==="
if [ -f "$OUT/klog_sdcard.txt" ]; then
  cat "$OUT/klog_sdcard.txt"
elif [ -f "$OUT/klog.txt" ]; then
  cat "$OUT/klog.txt"
else
  echo "  (没有 klog —— exploit 进程没走到 SELF-W2 加载那步)"
fi

echo "=== su 是否可用（kpatch 装好后应立即可用）==="
tmo 20 adb -s $DEV shell "su -c id 2>&1 | head -2" 2>&1

echo "=== 模块加载的判据（dmesg2） ==="
if [ -f "$OUT/dmesg2.log" ]; then
  grep -aE "kernelpatch|kernelsu|Unknown symbol|vermagic|should be|supercall|su allowlist|sucompat|init_module" "$OUT/dmesg2.log" | tail -30
else
  echo "  (没有 dmesg2 —— 说明 root script 没跑到加载那步，或日志写失败)"
fi

echo "=== root script 的加载结果 ==="
grep -aE "mode=apd-insmod|apd insmod rc|raw insmod rc|post-load dmesg|panic_on_oops|panic_on_rcu_stall|module loaded|fixup|uid=" "$OUT/ksu_tmp.log" 2>/dev/null | tail -25

echo
echo "全部证据在 $OUT/"
