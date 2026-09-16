#!/system/bin/sh
# 观测运行：trace_pipe → /data/local/tmp/obs_tr.log + exploit → /data/local/tmp/obs_gl.log
rm -f /data/local/tmp/obs_tr.log /data/local/tmp/obs_gl.log
# 采集 trace（持续读，崩溃前写入的会保留在 sdcard）
cat /sys/kernel/tracing/trace_pipe > /data/local/tmp/obs_tr.log 2>&1 &
TPID=$!
# 跑 exploit
/data/local/tmp/ghostlock > /data/local/tmp/obs_gl.log 2>&1
echo "EXPLOIT_EXIT=$?" >> /data/local/tmp/obs_gl.log
sleep 8
kill $TPID 2>/dev/null
sync
echo "OBS_DONE $(date +%s)" >> /data/local/tmp/obs_tr.log
exit 0
