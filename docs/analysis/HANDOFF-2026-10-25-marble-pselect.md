# HANDOFF 2026-10-25 — marble 打偏根治（pselect miss）

本文件是本次会话的收尾交接：读这一份就能继续，不必回读会话记录。

## 1 一句话现状

marble（Redmi Note 12 Turbo，`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）
全链成功率约 **39%**（16/41，Wilson 95%：25%–55%）。唯一死亡形态是 **pselect 打偏**，
打偏后内核在持 `task->pi_lock` 时踩空、`pi_lock` 永久泄漏、整机 wedge。
**崩溃点已钉到指令级，但「为什么读到 0x10」还差一条探针记录**（见 §4）。
设备当前 offline 21+ 小时，需要人工长按电源键。

## 2 目标与验收

- 目标：把 marble 全链成功率从 ~39% 提到可稳定复现（打偏即死 → 打偏可承受）。
- 验收：冷机连续轮次中 `HIT-ROOT`（`KernelSU ready` + `module loaded`）占比显著高于 39%，
  且不再出现「打偏 = 整机死」。
- 硬约束：不刷机、不改内核；只动 userspace exploit 与 profile。

## 3 已证明的事实（不要重复验证）

### 3.1 死亡分布

| 口径 | 样本 | 成功率 | 95% Wilson |
| --- | --- | --- | --- |
| 全链（4 条 route，8 sends） | 41 有效轮 | **39.0%** | 25%–55% |
| 全链（5 条 route 基线，8 sends） | 8 轮 | 37.5% | 14%–69% |
| W1 SELinux 命中 | 15 轮 | 73% | 48%–89% |

- 4 条 route 与 5 条 route 的区间大幅重叠：**没有证明 4 条更好，也没有回归证据**。
  模型推算的 45.6% 未出现 ⇒「per-route 生存率 0.822 且均匀」前提不成立
  （W2/W3 的 pselect 命中率低于 W1）。
- 20 轮量级分不开 37.5% 与 46%（期望 7.5 vs 9.1 次命中）；80% power 需约千轮。
  **4 条 route 的收益只能靠机制论证**（少一次打偏机会），A/B 只作回归守卫。
- 死亡样本的面包屑一律停在 W1 或 W2 的 `psel …` 之后、`route-returned` 之前
  ⇒ 死于 route 内的 pselect，与 W3 leaf 方向无关。

### 3.2 崩溃机制（指令级，已用原厂 `boot.img` 反汇编确认）

崩溃现场（`build/dmesg-oops-2026-10-24.txt`）：

```
pc : rb_insert_color+0x48    lr : rt_mutex_adjust_prio_chain+0x580
调用链：__do_sys_sched_setattr → __sched_setscheduler → rt_mutex_adjust_pi
        → rt_mutex_adjust_prio_chain → rb_insert_color
x0 = ffffffc04cf13c30   x1 = ffffff88aaf28008
面包屑：psel page=ffffff88aaf28000
```

反汇编（`build/extract/release/audit.exe`，`_text = 0xffffffc010000000`）：

- `rb_insert_color+0x48` 是 `ldr x10,[x8,#0x8]`（读 `gparent->rb_right`），
  其中 `x8 = gparent = *(parent)`。崩溃时 `x8 = 0x10` ⇒ 读 `0x18` 触发 translation fault
  ⇒ **`*(parent) == 0x10`**。
- `rt_mutex_adjust_prio_chain+0x578` 是 `lock->waiters` 的入树点
  （`str xzr,[x28]` / `str x28,[x1]` / `str x28,[x27,#0x10]`），返回地址正是 `+0x580`
  ⇒ `parent` 就是 `lock->waiters.rb_node` 指向的节点，即我们写的 `fake_w0` = `page+0x300`。
- 同一函数里另有 2 处 `task->pi_waiters` 入树点（`str x9,[x0,#0x18]!` / `str x0,[x19,#0x888]`）。
- `struct rt_mutex_waiter` 布局确认为 `tree_entry@0x00 / pi_tree_entry@0x18 / task@0x30 /
  lock@0x38 / prio@0x40`，与 `encode_compact_waiter()`（`src/core/memory/payload_builder.cpp:37-49`
  写 `0x18/0x20/0x28`）**完全一致 ⇒ craft 布局本身没错**。

**矛盾点**：payload 在 `src/core/support/util.cpp:466` 用
`put64(p, kernel::W0_OFF + 0x00, 1)` 把 `page+0x300` 写成 `1`，内核却读到 `0x10`。

### 3.3 为什么打偏 = 整机死

- 崩点发生在 `rt_mutex_adjust_prio_chain` **持有 `task->pi_lock`**（`raw_spin_lock_irqsave`）期间。
- oops 只杀线程、不释放该锁 ⇒ `pi_lock` 永久泄漏 ⇒ 之后任何要拿这个 task 的 `pi_lock`
  的路径（调度、`sched_setattr`、唤醒）永久自旋 ⇒ 整机 wedge。
- dmesg 铁证：`note: libghostlock.so[28551] exited with preempt_count 3`。

### 3.4 为什么不会自愈

- `panic_on_oops=0` ⇒ oops 不触发 panic 重启。
- 命中轮已由 `disable_watchdog_modules()`（`src/core/session/victim_process.cpp:95-116`）
  unbind `gh-watchdog` ⇒ 厂商安全网被拆。
- 实测：oops 后设备 `adb` 转 `offline`，**21+ 小时未恢复**，USB 仍在枚举
  （`VID_2717&PID_FF48\3E6F1443` + `MI_00` WPD + `MI_01` ADB 接口，全部 Status OK）
  ⇒ 有电、gadget 活着、内核死了。**只能长按电源键 ~10 秒强制重启。**

## 4 下一步唯一动作（设备恢复后）

设备重启后跑：

```powershell
cd D:\work\1\ghostlock-main
.\build\probe-run.ps1 -Serial 3e6f1443 -RunTimeoutSec 240
```

它会：校验 root → 推 `arm-probes.sh` / `kprobe-dump.sh` / `filter.txt` → arm 5 个探针 →
唤醒解锁并拉起 app → 点击执行 → 轮询判定 → 把 trace / 面包屑 / dmesg / native log
拉到 `build\probe-<ts>\`。

**要看的只有一条记录**（决定性探针 `glk_enq`，在 `rt_mutex_adjust_prio_chain+0x570` 取寄存器）：

```
glk_enq: lock=… node=… link=… root=… w300=… nodepc=… comm="libghostlock.so"
```

| 观察 | 结论 | 修法 |
| --- | --- | --- |
| `root != lock+0x300`，或 `w300 != 1` 且 `root` 也不是我们写的值 | **H1 抢页失手**（页不是我们的） | 提高 reclaim 确定性；`fake_lock` 是算出来的常量，页被抢走就会走进陌生页 |
| `root == lock+0x300` 且 `w300 != 1` | **H2 假 `rt_mutex` 头部写错** | 修假头部布局（`util.cpp:435-438`） |

`glk_enq` 定义（已在 `build/arm-probes.sh` 里）：

```
p:kprobes/glk_enq rt_mutex_adjust_prio_chain+0x570 lock=%x27 node=%x28 link=%x1 \
  root=+0x8(%x27):u64 w300=+0x300(%x27):u64 nodepc=+0x0(%x28):u64 comm=+0x790(%x2):string
```

## 5 工作树状态（未提交）

分支 `main-510-port`，HEAD `9443450`（`Merge origin/main: MEIZU 21 profile route fix (upstream #368)`）。
`main` 已快进到 `5d675e2`，与 `origin/main` 一致。**未做任何 commit/push**（按项目约定）。

- 修改 17 个文件：`AndroidManifest.xml`、`5.10.149-…conf`、`AndroidProfileConfigController.kt`、
  `GhostlockViewModel.kt`、`MainActivity.kt`、`SelectConfig.kt`、`kernel/constants.hpp`、
  `kernel/target_constants.hpp`、`main.cpp`、`profile/binary.cpp`、`profile/model.h`、
  `race/threads.cpp`、`route/select_stack_route.cpp`、
  `session/backend/cve_2026_43499_backend.cpp`、`session/victim_process.cpp`、
  `support/util.cpp`、`tests/host/backend_dataflow_test.cpp`
- 未跟踪 9 项：`app/src/main/kotlin/com/ghostlock/app/retry/`、
  `docs/analysis/{2026-10-22-marble-wrapup,2026-10-22-probe-audit,2026-10-23-app-auto-retry,
  2026-10-23-marble-geometry-audit,2026-10-23-reclaim-coverage-fix,
  marble-pselect-miss-rootfix-plan}.md`、`docs/analysis/device-gates/2026-10-21-marble-root-repro-apatch.md`、
  `tools/extract_rs/src/bin/`

其中含 **`TEMP(...)` 标记的临时探针**（`race/threads.cpp` 心跳、`victim_process.cpp` 的 `w3diag`、
`select_stack_route.cpp` 的 page-id 镜像、`main.cpp` 的 `setvbuf`）。
按项目规范，定稿前必须清掉 `TEMP` 探针并重跑门禁。

## 6 已验证的门禁与产物

| 项 | 结果 |
| --- | --- |
| NDK 构建 | `build\rebuild-native.ps1` → `build/native/ghostlock` **2,794,816 B**，零告警 |
| `cmp_disasm` | **PASS**，8 个攻击函数 IDENTICAL，multicast 两个 SKIP（基线 `build\ghostlock-preflush.bin`） |
| 主机单测 | 本机 llvm-mingw 原生构建 27 个测试二进制：**14 个运行通过**（含改动涉及的 profile / profile_binary / payload_builder / route_policy / route_catalog / component_catalog / backend_contract / route_lifecycle）；其余 13 个因 Windows 缺 POSIX 头（`sys/mman.h`/`sys/select.h`/`sys/wait.h`/`poll.h`）或 LLP64 差异无法构建/运行，均为既有平台限制 |
| clang-tidy | 全量 29 TU，**0 findings**（`build\lint_all.bat`） |
| APK | 22,311,177 B，10-23 16:28:39 装机成功 |

已真机验证：`w3_leaf_to_target8 = 0` 生效（`pinned by profile` ×2、`W3-0: leaf dir` 0 次、
`route_done status=0` ×4），每轮 route 数 5 → 4。

## 7 已证伪的路线（不要再走）

1. **SIGALRM 打断 futex PI 等待**：34 次 wait、0 次 EINTR。PI 等待路径不响应信号。
2. **超时判定 + 安全回收**：心跳探针证明打偏后**整组线程 ≤500 ms 内全冻**
   （心跳停摆），回收线程跑不起来，无从回收。
3. **app 内自动重试层**（`com.ghostlock.app.retry`）：被 MIUI 反复回收；且自身有自锁缺陷
   （`BootReceiver` 见 `attempt < maxAttempts` 就重新 arm）会造成**开机即跑 → 打偏 → 重启 → 再跑**
   的无人值守循环。已用 `pm clear` 解过；**每次 A/B 前必须 `rm files/.ghostlock_retry.conf`**。
4. **4 条 route 带来可测提升**：39.0% vs 37.5%，区间重叠，证明不了。
5. **`kRelinkNodeOffset` 0x200 → 0x300**：地毯在 `page+0x200`、内核走 `page+0x300`，
   但改后 `cmp_disasm` 出 SHAPE-DIFF（仅指令重排、无行为收益），按最小改动原则回退，
   只留注释 + `static_assert(kLockOffset + kRelinkNodeOffset == kCredentialCopyOffset)`。

## 8 运维须知（都是踩过的坑）

- **解锁**：`input swipe` 不可靠（约 35% 轮次停在锁屏/通知栏）。必须
  `input keyevent 224` + `wm dismiss-keyguard`，再校验 `mCurrentFocus` 含 `com.ghostlock.app`。
- **对话框**：每次开机弹「建议启用 Shizuku」——`取消` (311,2190) / `启用` (769,2190)；
  「上次攻击未完成」——`关闭` (540,2176)；「上次执行在 … 阶段失败」——`取消` (311,2190)。
  不点掉会挡住执行按钮。
- **执行按钮**：center `(540, 2233)`，备用 `(540, 2247)`。
- **不要每轮 `pm clear`**：清空后首轮 native 一行都不写（Shizuku UserService 未绑定）。
- **判定不能只看最后一行**：要 `grep -c 'KernelSU ready'` / `'KernelSU module loaded'` /
  `'=== W3: seccomp mode'` / `'route_done status=0'`。`fork-hold parked pid=…` 是**成功末行**，
  不是失败（`hold_reclaim_sockets_until_exit()`，`src/core/support/util.cpp:298`，
  调用点 `src/core/main.cpp:129`）。
- **`.ps1` 必须是 UTF-8 带 BOM**，否则 Windows PowerShell 5.1 按 ANSI 解析，中文正则直接语法错。
- **`make` 不可用**（Makefile 用 `uname -s` / `mkdir -p`，且本机 `make` 不在 PATH）：
  主机单测按 `src/Makefile` 里的每一条编译命令，用 `D:\platform\llvm-mingw\bin\clang++.exe`
  逐条复刻（`-std=c++23 -fno-rtti -Wall -Wextra -Wconversion -Wsign-conversion -Icore`，
  产物落 `build\native-host-tests\`）。Windows 缺 POSIX 头的那部分测试本来就无法在本机构建，
  不要为了跑它们引入额外工具链。
- **clang-tidy 的 `-DTARGET_CONFIG_H`** 必须经 `.bat`（cmd 解析）传
  `-DTARGET_CONFIG_H=\"kernel/target.h\"`；PowerShell 直接传会吃掉引号导致假错误。
- **探针过滤器必须从文件喂**：`cat /data/local/tmp/filter.txt > …/glk_adj/filter`，
  adb+su 内联引号会被吃掉（`parse_error: Invalid value (did you forget quotes)?`）。
- **后台 dumper 必须 `setsid … </dev/null >/dev/null 2>&1 &`**，
  否则 `adb shell` 永远等不到 EOF（曾挂住 17 小时）。

## 9 未决问题

1. **H1 还是 H2**（§4）——这是当前唯一阻塞点。
2. `pi_lock` 泄漏是否可避免：崩点在持锁期间踩空，userspace 无法回滚；
   可行方向是「让 walk 不踩空」（即解决 1），而不是事后恢复。
3. W3 阶段的 wedge（另一类死亡形态，无 oops、无 panic）：本次未推进。
4. `SKB_RECLAIM_SENDS`（现 4→8 硬编码）应改为 profile 字段。
5. 自动重试层是否保留：若要保留，必须加安全阀（仅显式开启才自动重试、命中即 disarm）。
6. `TEMP(...)` 探针清理与最终门禁（§5）。

## 10 参考文档

- `docs/analysis/marble-pselect-miss-rootfix-plan.md`（主计划，含全部进度回填与指令级分析）
- `docs/analysis/2026-10-23-marble-geometry-audit.md`（镜像级几何审计：符号 11/11、结构体 14/14、
  `caps_offset 48→40` 修复）
- `docs/analysis/2026-10-23-reclaim-coverage-fix.md`（`SKB_RECLAIM_SENDS` 4→8 的数据）
- `docs/analysis/2026-10-22-probe-audit.md`（探针所有权/生命周期审计）
- `docs/analysis/2026-10-23-app-auto-retry.md`（自动重试层实现与 MIUI 结论）
