# Marble root repro + APatch 一步到位（root-repro-b/c，2026-10-21）

Device: marble `3e6f1443`（Redmi Note 12 Turbo, `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）
Branch: `main-510-port` @ 9443450（P6 工作已在 `p6-multicast-2026-10-21` 分支收编）
Binary: `build/ghostlock-marble-9443450.bin`（2791160 B，纯 HEAD 树重建；APK v1.2(592) 内
`lib/arm64-v8a/libghostlock.so` 444120 B 与其 strip 产物逐位一致）

## Verdict

用户指示"先复现 root"（m05327）→ "优先 APatch，一步到位"（m05421）。

1. **root 复现**（root-repro-b round 1，19:06:13，冷机 uptime 61 s）：
   W1=ok → W2=entered（`child is root`）→ W3=ok → hold=ok(pid=27080)。
   命中后 +5 s `su -c id` = uid=0 context=u:r:kernel:s0，getenforce=Permissive，
   panic_on_oops=0（root script 已关）。
2. **APatch 完成**（apatch_finish.ps1，19:38:19）：kernelpatch Live（root script 经
   apd insmod 自动加载）→ soft-reboot → resetprop sys.boot_completed 1 →
   管理器重启 → **`su -c id` = uid=0(root) gid=0(root) context=u:r:magisk:s0**。
3. 复验（root-repro-c round 1，19:34:20，冷机 uptime 59 s）再次全链命中，证明可重复。

## 今日 "5/5 hold=no" 误判澄清

下午多轮 HIT-ROOT hold=no 并非 W3 卡死：`StopAfterHit` 在首次命中后 ~25 s 停止采集，
而 W3 spray+route 每 attempt ~3.5 s × 4 attempts 尚在运行——日志截断造成的假象。
命中后主动轮询 `su`（+5 s）即见 uid=0。此前"两次断在 W3c pselect"的结论同样作废。

## 攻击路径证据链

- root-repro-b round 1：`rounds …/root-repro-b/round-1.full.log`：W1 `post-select
  ret=4` → W2 `child is root` → `W3-0 page prebuilt ok` → `heap spray skipped
  (prebuilt W3-0 page activated)` → `seccomp fully bypassed` → `fork-hold parked
  pid=27080`。
- root child 进程链：15062 (PPID 1) → 26381 (uid=0) → 27080 (fork-hold parked)。
- su 来源判定实验：逐一 kill 26381/27080/15062 后 `su` 仍返回 uid=0 ——
  服务者是 **kernelpatch-lkm 的内核 sucompat hook**（`/data/adb/ap/log/dmesg.log`
  铁证：`kernelpatch-lkm: execve uid=2000 path=... (su_path=/system/bin/su)`），
  与任何 ghostlock 用户态进程无关。

## APatch 语义细节（当日实测）

- package_config 授权表（`/data/adb/ap/package_config`）：`pkg,exclude,allow,uid,to_uid,sctx`
  三行（bin.mt.plus / me.bmax.apatch / com.android.shell 2000）。shell uid 的 su
  由 kpatch sucompat 授予，temp 阶段 context=u:r:kernel:s0，soft-reboot 后变
  u:r:magisk:s0（完整 root 域）。
- **持久性边界**：kernelpatch.ko 是 insmod 的 Live 模块——**硬重启即丢**
  （19:33 实测：reboot 后 /proc/modules 无 kernelpatch，su 消失，需重跑攻击）。
  soft-reboot（framework 重启，内核不动）保活。硬重启持久化需 APatch 管理器
  patch boot image（未做，属后续工作）。
- 备份：`/sdcard/Download/ap-backup-20261021.tgz`（/data/adb/{ap,ksu,ksud}，11.5 MB）。

## 与 10-17 apatch-route 门禁的关系

执行的是同一序列（`tools/trials/apatch_finish.ps1` 未改动）；差别仅是本轮从
干净 9443450 重建的二进制完成攻击段，验证 10-15→10-17 的 18 个 marble 修复
（W3 预构建页、ghost disarm、loader selection 等）在回退后仍然成立。

## 遗留

- pselect miss 家族（W1 ~75% / W2 条件 ~80%）与"miss ⇒ 死机"仍在（O1 探针
  方向已从 futex wait 修正到 pselect 可中断性，未实施）。
- 硬重启后需重跑攻击（~2 轮冷机期望 1 次命中）+ apatch_finish。
