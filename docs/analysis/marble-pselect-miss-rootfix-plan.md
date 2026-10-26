# marble pselect-miss 根治计划（2026-10-22）

状态：计划（用户要求"设计完整推进计划"，尚未获批执行）。
对应分支 `main-510-port` @ 9443450（"MEIZU merge"，marble 最后提交，10-17 18:50）。
前置阅读：`docs/analysis/5.10-marble-final-report.md`（基线）、
`build/marble-5.10.149-review-2026-10-21.md`（P0 回归 + O1–O7）、
`docs/analysis/device-gates/2026-10-21-marble-root-repro-apatch.md`（root 复现与 APatch 链路）。

## 现状与基线

- 分支/commit：`main-510-port` @ 9443450；P6 工作已收编至 `p6-multicast-2026-10-21`
  （3296268），`main-510-port` 工作树干净（仅 7 个 untracked 取证工具，不参与构建）。
- 当前行为（40 轮冷启动基线，`docs/analysis/5.10-marble-final-report.md`）：
  - HIT-ROOT 27/40 = 67.5%；W1 pselect 生还 75%；W2 生还 90%；0.75×0.90 = 0.675
    精确吻合 ⇒ **重试阶梯（w1/w2_attempts=15）从未生效**：打偏 = 线程永不返回，
    syscall 之后的重试循环到不了。
  - 打偏轮日志形态：终止于 `consumer call 1 entering sched_setattr`，随后整机
    wedge（无 panic、无自动重启；基线报告"命中轮同一 boot 再跑会永久卡死"）。
- 已知问题：
  - **O1 判定已完成**：`FUTEX_WAIT_REQUEUE_PI` 不响应 SIGALRM/EINTR
    （2026-10-21 探针 v1/v2/v3 共 46 次观测 0 EINTR；v3 mask bug 与 v4 EAGAIN
    污染均已澄清）。真正卡点是 pselect，非 futex wait。
  - 活体取证第 1 轮（2026-10-21 20:39）：root 态 0.4s 粒度线程监控成功复现
    wedge，但监控写 page cache 无 sync、攻击日志同被冻结吞掉，
    **第一现场未落盘**。设备自行恢复（非 panic），root 随重启丢失。
  - 昨日"5/5 W3 卡死"已澄清为 StopAfterHit 25s 采集截断误判；root-repro-b/c
    冷机 2/2 命中（W3=ok hold=ok → APatch SUCCESS）。
- 设备态：marble 3e6f1443（5.10.149-android12-9-…），Enforcing，root 已随重启
  丢失；APK com.ghostlock.app 幸存；/data/local/tmp 工件幸存（mon.sh 旧版）。

## 目标与约束

**目标**：把 pselect 打偏即死修掉——W1 pselect 生还 75% → ≥90%（等比放大约
HIT-ROOT 67.5% → ~81%+），且不引入新的 panic 形态。前提=不刷机（用户 m05559
裁决，boot patch 路线已作废并清理）。

**约束**：
- 攻击关键路径改动必须走完整门禁：`cmp_disasm` 8 函数 + 真机门禁 + 门禁记录
  （AGENTS.md 验证门槛）。
- 不动 `kernelsnitch/`、`LegacyProfileConverter.kt` v1 转换、"明确保留"清单。
- 全局状态、profile/wire 格式不变（v2，不新增版本号）。
- 真机每轮冷机纪律：尝试前重启；命中后同 boot 不再跑；硬重启丢 kernelpatch
  （root）——每轮取证重 root。

**非目标**：
- 不做管理器跳转 UI（用户 m05701 "那算了"）。
- 不做 boot image 持久化（超出不刷机前提）。
- O1 SIGALRM 探针不再继续（方向已被证伪/搁置）。
- 不在无证据时盲改 select_stack route 的竞争时序。

## 根因假设（按可能性排序，待取证裁决）

1. **fake_lock 页 wait_lock 非零 → rt_mutex walk 自旋**（+0x180 raw_spin_trylock
   循环）——但 selftest 曾观察到 walk 返回 0，与 poison 探针结果矛盾，需现场裁决。
2. **rb 树 walk 走飞不终止**（crafted 树字被并发 clobber 或几何错位 → 无限循环，
   表现为整机冻结而非 panic）。
3. **walk 进未映射 alias**（几何错位 → +0x180 oops，但当前形态无 panic，权重降）。
4. **非 walk 路径**（consumer/owner 线程卡在某原语，host 侧读码未见候选）。

注意：poison 探针（0xdead0000 单槽+全窗）在**布置后**walk 未 fault——说明
"布置时刻" pi_blocked_on 尚未指向窗口；若 wedge 是 walk 吃了窗口，
时序在 CMP 之后。这正是要抓的现场。

## 批次与改动清单

**批次 A — 取证基建（无攻击路径改动，S/M 级）**

| 文件 | 改动 | 理由 |
| --- | --- | --- |
| `build/mon-v2.sh`（新，PC 侧工件） | 监控 v2：只抓 R 态 ghostlock 线程（`/proc/<pid>/task/*/stat` 首字段过滤），每条写后 `sync`；攻击日志目录停更 >10s ⇒ `echo c > /proc/sysrq-trigger`（该节点绕过 sysrq=0，已验证 writable）强转 panic 兜底 | 第 1 轮教训：page cache 被冻结吞数据；sysrq panic 换 SYSTEM_LAST_KMSG 全 CPU backtrace |
| `build/forensics-run.ps1`（新） | 一键：push 监控 → 清 dmesg → 跑一轮 W1（harness 单轮）→ wedge 后收 pstore/dropbox | 复现第 1 轮流程并补落盘纪律 |

验证：`sh -n` 语法检查 + 干跑（无攻击时 watchdog 不误触发）。

**批次 B — 活体取证第 2 轮（真机，无代码改动）**

1. root-repro-d：`trials_ps4.ps1 -Rounds 1 -RebootEveryRound -StopAfterHit`
   （方法论已 2/2）；随后 `apatch_finish.ps1`。
2. 部署监控 v2 → 清 dmesg → 触发 W1 → 等 wedge。
3. 数据面：
   - live 侧：wedge 渐进期 R 态线程 `/proc/<tid>/stack` + `wchan` + `syscall`；
   - panic 兜底：重启后 `dumpsys dropbox --print SYSTEM_LAST_KMSG`（全 CPU
     backtrace，rt_mutex_adjust_prio_chain 指令级定位）。
4. 判读：栈顶函数 → 分流到批次 C/D/E 之一；**若现场否定全部 4 个假设，
   停下来重新设计（回到本计划修订），不带猜改码**。

**批次 C/D/E — 修复（二选一/多，按批次 B 证据定，L 级预设计）**

- **C（walk 自旋/rb 走飞）**：候选最小改动 = craft 前对 fake_lock 页
  wait_lock 槽做强制清零写验证（读回确认），或 crafted 树字加已验证的
  终止屏障；只动 `src/core/memory/payload_builder.cpp` / route craft 路径。
- **D（alias/几何）**：修正 select_stack 侧帧几何或窗口对齐；只动
  `src/core/route/select_stack_route.cpp` / `src/core/race/threads.cpp`。
- **E（其他路径）**：按现场重新设计，出修订计划再动手。
- 任一批次落地前：按"核心攻击代码审查"清单做所有权/UAF/终结点追踪，
  记录进本文件进度节。

**批次 F — 验证收尾**

1. `make -C src native-host-tests`（host 侧 `build/ci_run.ps1` 等价链）+
   NDK 零告警 + `lint-tidy` 0 findings。
2. `cmp_disasm` 8 攻击函数：以 9443450 重建产物
   （`build/ghostlock-marble-9443450.bin`，SHA256 5437DCB4…2792376B/2791160B
   两口径已在档）为基线，要求 IDENTICAL 或已复核注解差异。
3. 真机门禁：冷机单轮 ×3（含 1 轮命中），归档
   `docs/analysis/device-gates/2026-10-2X-marble-*.md`（模板见
   documentation-standards.md，编号沿用）。
4. 效果验证：harness 40 轮冷启动（同基线口径 `-RebootAfterHit`），
   对比 W1 pselect 生还率与 HIT-ROOT；目标 W1 ≥90%、无新 panic 形态。
   小样本判定：若 40 轮 W1 生还率与 75% 基线无统计学差异（二项检验），
   视为无效改动，回滚。

## 数据流/控制流差异

批次 A/B 零代码差异（纯 PC/设备侧工具）。批次 C/D/E 待证据裁决后在此节
补"新旧对照 + 不变量"（不改重试阶梯语义、不改 wire/profile、不动
PiRace::run 的 route_done 超时与 fail_stop_dirty_race 路径）。

**不变量**：
- 打偏判定仍以 consumer_calls/successes>0 为准；
- ghost/stack disarm 触发条件（route_policy.hpp:287）不变；
- W3 leaf 写 fire budget=1 不变（黑节点重入防线）；
- 每次尝试前冷机重启；命中后同 boot 不再跑。

## 兼容性与回滚

- 批次 A 工件全在 `build/`，不入库；失败即删，无系统影响。
- 批次 C/D/E 改动集中单文件级，`git checkout -- <file>` 即回滚；
  cmp_disasm 基线二进制已存档，可逐位复核。
- sysrq panic 兜底只在取证轮启用；基线对比轮（批次 F4）不挂监控，
  排除监控自身扰动。
- 每 root 轮硬重启丢 kernelpatch 已知；root-repro 2/2 可稳定重取。

## 验证矩阵（摘要）

| 批次 | 命令 | 预期 |
| --- | --- | --- |
| A | `sh -n build/mon-v2.sh`；空转 120s | 无误触发 panic |
| B | 单轮 W1 + 监控 v2 | 拿到 wedge 现场（live 或 LAST_KMSG 二者一） |
| C/D/E | host tests + lint + cmp_disasm | 0 findings；8 函数 IDENTICAL/注解 |
| F | 门禁 ×3 + harness 40 轮 | W1 生还 ≥90%，HIT-ROOT ≥81%，无新形态 |

## 明确保留

- `kernelsnitch/`（上游原样移植）、`LegacyProfileConverter.kt` v1 转换、
  profile/wire v2 格式、重试阶梯与 attempts 配置语义、
  O1 探针全部工件（已回退，仅留档 build/）。
- untracked 取证工具（tools/extract_rs/src/bin/{mm_*,p6_*}.rs 等）不动。

## 进度

- [x] 批次 A：监控 v2 + 一键取证脚本（`build/mon-v2.sh` + `build/forensics-run.ps1`，
      LF clean、`sh -n` SYNTAX-OK；干跑被 root 丢失打断，并入批次 B 补做）。
- [~] 批次 B：root → 触发 → 抓现场（进行中；2026-10-22 上午数据如下）。
- [ ] 批次 C/D/E：按证据定修复方案（本节回填差异说明）
- [ ] 批次 F：门禁 + 40 轮对比 + 归档

## 进度回填：2026-10-22 上午（root-repro d–i + forensics-02/03）

**root-repro 轮次**（纯 9443450 构建，冷机单轮）：

| 轮 | 时间 | 结局 | 形态 |
| --- | --- | --- | --- |
| d | 10:02 | 失败 | HIT-ROOT 后 W3 spray 中段 wedge（collision screen 9/3@37% 冻住，无 panic，~90s 自动重启） |
| e | 10:09 | 失败 | W1 miss 标准 panic（已知 32.5% pselect-miss 形态） |
| f | 10:13 | 失败 | W3-0 leaf dir 完全成功 → TIF_SECCOMP spray 完成 → route 启动 CMP EDEADLK(35) 后 wedge 重启 |
| g | 10:18 | 失败 | W3 spray 中段 wedge（collision 6/3@37%，同 d） |
| h | 10:34 | 失败（新形态） | 两次 spray 全部完成、W3-0 leaf 成功，**W3 seccomp clear 写验证失败**（finit_module probe=0xfffffffd=-ESRCH，写没落地；`W3 seccomp bypass failed after 1 chain rounds`） |
| i | 10:39 | **成功** | W3=ok hold=ok(pid=24708)，su 立即就绪 → apatch_finish SUCCESS（u:r:magisk:s0） |

- W1 命中 5/6；成功轮 i 的 collider=10/3@37%（比死亡轮 d 的 9 还多）⇒
  **collider 数量不是 wedge 判别因子**。死亡点分布：spray 碰撞筛选中段（d/g）、
  TIF_SECCOMP route 启动后（f）、写验证（h）——共性 = W3 大规模线程 +
  kernelsnitch pile 窗口，且全部无 panic、无 SYSTEM_LAST_KMSG（活锁非 oops）。
- **W3 wedge 与 pselect-miss 并列为第二死因**（今天命中轮 5 轮里 4 轮死于 W3 段；
  昨天同期 2/2 干净）。样本仍小，且 h 轮证明 spray 完成 ≠ 写落地。

**forensics-02（10:29，无 root 监控）**：W3 spray 阶段抓到两个 R 态自旋者
（tid=20532/26859，comm=libghostlock.so，wchan=0 无 syscall = 纯用户态自旋）；
无 root 读不了 /proc/tid/stack。自旋起点 = W3 spray/kernelsnitch 窗口。

**forensics-03（10:45，root 态监控 mon-root.sh 抓 /proc/tid/stack）**：触发后
~35s 深度 wedge（USB 掉线 35+ 分钟未自恢复，超昨天 12min 纪录；用户 11:22
手动强制重启）。**root 栈数据未落盘**（mon.log 0 字节，page cache 再度丢失；
mon-root.sh 逐行 append 但无 fsync——第二轮教训重演）。forensics-03 run 目录
20261022-104424 幸存：log 终止于 TIF_SECCOMP route `CMP_REQUEUE_PI ret=-1
errno=35; waiting route_done`，与 f 轮同型。

**监控自身扰动嫌疑（新增假设 5）**：mon-root.sh 每 0.4s 对全部 R 态线程读
/proc/<tid>/stack（内核侧需要 task 栈展开，R 态自旋线程上代价高且可能碰
rq lock），forensics-03 的 wedge 比 d/g/f（无监控）更快更深。但 d/g/f 无监控
也 wedge，监控不是唯一触发。后续取证监控降级为只读 wchan+syscall（放弃 stack，
除非已挂 root 且用 panic 兜底轮）。

**批次 B 剩余路径**（修订）：重 root（root-repro 链路当天 2/2）→ 监控 v2
（wchan+syscall only + 攻击日志目录停更 10s ⇒ sysrq panic 兜底，目标是拿
SYSTEM_LAST_KMSG 的全 CPU backtrace，live 栈已两度落空）→ 冷机触发一轮
→ 若 panic 兜底成功，从 LAST_KMSG 定位栈顶函数 → 批次 C/D/E 分流。

## 进度回填：2026-10-22 中午（root-repro k–r + 死点收敛）

**root-repro 轮次**（同批继续）：

| 轮 | 时间 | 结局 | 备注 |
| --- | --- | --- | --- |
| k | 11:31 | PANIC | W2 miss |
| l | 11:33 | PANIC | W2 miss（连续两 miss ~10% 方差内） |
| m | 11:36 | **HIT-ROOT** | W3=ok hold=ok → apatch SUCCESS；11:41（+3min）静默重启 |
| n | 11:42 | PANIC | W2 miss |
| o | 11:45 | PANIC | W1 miss（W1=no） |
| p | 11:47 | **HIT-ROOT** | W3=ok hold=ok；11:50（+3min）静默重启（kmsg 干跑窗口） |
| q | 11:54 | **HIT-ROOT** | W3=ok hold=ok(pid=24771)；11:57:50 静默重启吃掉紧随的取证触发 |
| r | 11:59 | HIT-ROOT(W3=entered) | 12:02 静默重启；log 终止于 `PI route done`（T+22.6s） |

**静默重启用 kmsg 定性（318MB `kmsg-tail.bin` = kmsgd 跨 boot 累积）**：
p-boot kmsg 结束于 t=166.92s，最后几行是监控干跑的 sucompat execve，**戛然而止
无任何错误**；dropbox 空；ramoops 未注册（DT 资源缺失）；cmdline
`kernel.panic_on_rcu_stall=1`（有 stall 必炸但无 stall）⇒ **瞬时断电式重启，
内核零证词**。命中后 2–3min 静默重启今日 4 次（10:04/11:41/11:50/11:57），
共同点 = 命中 + Permissive + kernelpatch Live。

**死点收敛（r/f/j/forensics-03 同一执行点）**：W3 seccomp-mode write 的
route 完整走完（`CMP_REQUEUE_PI EDEADLK(35)` 回滚正常 → pselect clean →
ghost disarm → `route_done clean=1/1` → `[T+…] PI route done`），下一动作是
`verify_seccomp_probe_stage` 的 fork-probe 交换——**此后零日志**，adb 先死
（wedge），~90s–3min 后 PMIC 记 reboot。几何核对：i（成功）与 f/j/r（死亡）
的 W3 目标完全一致（leaf=-8 shift 两者相同，mode delta=0xc8 from W2 target
逐位吻合）⇒ **几何/布局不是判别因子**；h 轮 probe 返回 SIGSYS（写 miss 可
生还）、i 轮返回 EINVAL（写中可生还）、f/j/r 零返回（walk 期 wedge）。

**统一理论（当前最强假设）**：今日 W3 死亡与昨日 W1/W2 pselect-miss wedge
同属一族——**某次 attack_write 的 walk 打偏/悬空，内核在 PI 机制里自旋，
RCU/sched 冻结，~90s 后硬重启**。"静默重启" 是 wedge 的尾段（PMIC 记录），
不是独立现象。f/j/r 与 d/g 只是同一根因打在 W3 的不同子段（写走、碰撞筛选）
上。基线报告的 "打偏让内核卡在 PI 流程" 覆盖两天的全部死亡样本。
⇒ **根治目标不变：让打偏可返回/可检测（O1 方向，pselect + W3 walk 两侧）**。

**取证策略再修订（v3）**：root 窗口 2–3min 内完成一切 ⇒ `fast-forensics.ps1`
（su 确认 → mon-v3 → 触发 → adb 死则等重启拉 mon.log 残余）一键化；监控
干跑永不放在命中 boot 上。已部署 mon-v3（SYNTAX-OK）+ fast-forensics.ps1。

## 进度回填：2026-10-22 14:33（批次 G+H 首轮）

### 代码（已落地、已过门禁、已装机）
- 批次 G 驻留探针：`support::hold_after_route_if_requested()`（util.cpp:608），marker `<home>/.ghostlock_hold_after_route`，300 s / 10 s tick，每行 fsync 进面包屑。
- 批次 H 双 canary：canaryA = 对自己 `sched_setattr`（复现 walk 入口），canaryB = `FUTEX_LOCK_PI` 目标锁。
- 门禁：cmp_disasm vs `build/ghostlock-marble-9443450.bin` —— 8 个攻击函数计数不变（waiter_thread 918→1000 为探针本体，其余 LAYOUT-SHIFT-only）；NDK 零告警 2,792,792 B；clang-tidy 0。
- APK v1.2(592) 已安装（APK 内 libghostlock.so 445,528 B）。

### 首轮结果（run 20261022-143300）
| 项 | 值 |
| --- | --- |
| W1 | attempt 1 命中，T+4841 ms `SELinux permissive` |
| ghost disarm | `ret=-1 errno=110`（ETIMEDOUT） |
| canaryA | `sched_setattr self ret=0 errno=0` **通过** |
| canaryB | `ret=-1 errno=110`（目标锁被 fake owner 持有，无判别力） |
| W2 | `target=0xffffff88fd129a00 mode=2 leaf=0`，route 起于 T+8492 ms |
| 死点 | `consumer call 1 entering sched_setattr tid=23562` 之后零日志 |
| 重启 | ~T+50 s 静默重启；dropbox 无 SYSTEM_LAST_KMSG |

### 结论
1. **"上一阶段 ghost 毒化下一阶段" 被证伪**：W1 成功后 canaryA 完整走一次 `rt_mutex_adjust_pi` 仍返回 0。
2. 死亡发生在**当轮 route 自己的 walk**：consumer → `sched_setattr` → `rt_mutex_adjust_prio_chain`。
3. 无内核证词：kmsgd 自 13:31 起未运行（`/data/local/tmp/glkfx/kmsg-tail.bin` mtime 13:31），root 每轮重启即丢 ⇒ 今日全部死亡都是盲死。
4. 形态判别：oops 会留 `exited with preempt_count` 记录（历史 18 条集中在 10-14/16/20），今日全无 ⇒ 更可能是 `raw_spin_trylock(&lock->wait_lock)` 重试死循环（`waiter->lock` 指向已映射但永不释放的地址）→ 硬挂 → PMIC 复位。

### 下一步（待批）
1. **先恢复内核证词**：任一命中轮拿到 root 后立刻让 kmsgd 常驻并记录 PID；只有 kmsgd 活着，下一次死亡才有判据。
2. **判别实验（对齐 vs 树）**：consumer 触发前把 `frame_shift_extra` 扫三档（-8 / 0 / +8），看死点是否随 shift 迁移。迁移 ⇒ 对齐问题（改 `select_stack_route` 的 waiter_off）；不迁移 ⇒ 树/锁内容问题（改 craft）。
3. 若判为树问题：重点查 **credential 分支**——`layout.right = init_cred_alias` 时 `encode_compact_waiter` 写的是 pc=value、left=target（0x18/0x20/0x28），与 W1 的 Zero 分支（pc=target-8、right=page+0x200）形状不同，而 W1 今天 100% 干净、W2 首轮即死。

## 进度回填：2026-10-22 15:03（批次 G+H 第二轮 + 心跳探针）

### 新增探针：route 窗口心跳（TEMP(wd-01)）
- `src/core/race/threads.cpp`：`run_main_route_threads()` 在 `race.run()` 前后起/停一个 pthread，
  每秒 `spray_breadcrumb("wd t=%ds alive")`（open/write/fsync/close）。用途：区分**单线程活锁**
  （心跳继续）与**整组冻结**（心跳停）——这是"打偏可返回"设计是否成立的前提判据。
- 门禁：`cmp_disasm` vs `build/ghostlock-gh2-preprobe.bin`（同树无探针控制）——只有
  `run_main_route_threads` 414→436（探针本体），其余 6 函数 LAYOUT-SHIFT-only，`owner_thread` IDENTICAL；
  NDK 零告警 2,793,000 B。
- 选型记录：首版用 `std::thread` 使 `prepare_good_kernel_page` 出现 5 处 `[x,#0x470]`→`[x]` 的伪
  SHAPE-DIFF（libc++ thread 运行时改变 LTO 全局寻址形态，体积 +320 KB）；改 `pthread_create` 后消失。

### 第二轮结果（run 20261022-150324，带 hold marker）

| 项 | 值 |
| --- | --- |
| W1 | attempt 1 命中，route `clean=1/1 calls=1 success=1`，`ghost disarm ret=-1 errno=110` |
| 驻留 | `hold t=0…280s` 逐行落盘，设备全程存活（uptime 90→380 s） |
| W2 | `target=0xffffff886ec31a00 mode=2 leaf=0` 一次过 |
| W3-0 | `leaf dir … leaf=1 write lands on [target]` |
| W3 | TIF_SECCOMP + seccomp mode 全过，`finit_module probe=0x16` |
| handoff | root shell worker pid=24087，`kernelpatch 126976 Live (O)` |
| 判定 | **HIT-ROOT 成功**：`su -c 'id -u'`=0、`whoami`=root、`getenforce`=Permissive，uptime 8 min+ 仍存活 |

- 心跳行确认落盘（每 route 一对 `wd t=0s/1s alive`）⇒ 探针机制有效且不扰动攻击链。
- 与 14:33 轮相比只多了 300 s 驻留 + 探针实现；本轮证明**成功轮可以活过 8 分钟**，
  "命中后 27 s–6 min 必死" 不是定律，而与后续是否再触发 walk 相关。
- 仍缺的判据：需要一次 **W2/W3 打偏** 才能读心跳；本轮全过。

## 进度回填：2026-10-22 15:13–15:22（心跳判据到手：冻结 ≤500 ms，回收不可行）

心跳 v2（`wd t=%dms alive` 500 ms tick + `wd route-returned code=%d`）后的三轮：

| 轮 | 结果 | 面包屑证据 |
| --- | --- | --- |
| 15:13（v1） | **W1 route 打偏** | `step7 spray-done` → `wd t=0s` → `wd t=1s` → **无 route-returned**；log 文件 374 B 全 0（page cache 全丢）；设备 15:13:35 掉线、15:14:08 回来；dropbox 857 条中无 SYSTEM_LAST_KMSG |
| 15:16（v2） | **HIT-ROOT** | 5 条 route 全 `route-returned code=0`（W1 / W2 / W3-0 prebuilt / W3 TIF / W3 mode），`su -c 'id -u'`=0，`kernelpatch 126976 Live (O)`；证据归档 `build/510profile/hit-151650/` |
| 15:21（v2） | **W2 route 打偏** | route1 `route-returned code=0` → route2 `step7 spray-done` → `wd t=0ms` → `wd t=500ms` → **无后续**；设备 ~15:22:36 重启；dropbox 无 LAST_KMSG |

### 结论（方向性）
1. **打偏 = 整机在 ≤500 ms 内冻结**：心跳在 500 ms 后不再落盘，之后 30–40 s 设备才真正掉线/重启。
   ⇒ 用户 m06134 选定的"超时判定 + 安全回收"**不可行**——冻结发生在一个 tick 之内，
   用户态没有任何机会跑判定线程、更无法执行 disarm/回收。
2. **内核证词结构性不可得**：本机 ramoops 未注册（DT 资源缺失）、`/proc/last_kmsg` 不存在；
   `panic_on_oops` / `panic_on_rcu_stall` 只能在 root 态设置，而 root 只在命中轮存在、
   重启即丢 ⇒ 打偏轮永远跑在默认 `panic_on_oops=0` 下。两次尝试均无 SYSTEM_LAST_KMSG。
3. **只剩预防一条路**：既然一次打偏就锁死整机，任何"事后补救"都无效，必须让 walk 不踩到
   失效的 craft。当前最强候选是**泄漏页在 walk 前被内核复用/改写**（`waiter->lock` 指向的
   `wait_lock` 非 0 ⇒ `raw_spin_trylock` 无限重试）；每轮唯一变量是泄漏页地址，与"同一 boot 内
   route 1 干净、route 2 打偏"的随机性吻合。
4. **下一步（待批）**：把 `pselect route setup … page=/fake_lock=` 那行镜像进面包屑（route 侧 TEMP 插桩），
   攒 5–8 轮打偏样本，比较打偏轮与干净轮的 page/fake_lock 地址分布与对齐；
   若确认页复用，则在 spray→walk 之间加入页占用保持（不放回 slab）或改用更短窗口的 route。
## 进度回填：2026-10-22 16:00（收尾）

按用户 m07116 选定的「再跑 3 轮再收尾」执行：15:56 / 15:59 / 16:00 三轮，前两轮与第三轮均为 **W1 打偏**
（15:59 轮起跑 ~14 s 设备掉线，未取到证据）。连同 15:13（W1）、15:21（W2）、15:34（W3-TIF），
今日共 **5 个打偏样本，覆盖 W1 / W2 / W3-TIF 三个阶段，全部无 `route-returned`**。

三条假设已证伪：SIGALRM 可中断（34 waits / 0 EINTR）、ghost 跨阶段毒化（canary A ret=0）、
reclaim send 失败（两轮打偏轮均 `ok=4/4 errno=0` 仍锁死）。

**完整收尾结论、证据表与下一步见 `docs/analysis/2026-10-22-marble-wrapup.md`。**

状态：批次 G/H 结案；批次 I（按证据分叉）未启动；用户 m06134 选定的「超时判定 + 安全回收」方向关闭
（打偏 = 整机 ≤500 ms 冻结，用户态无机会执行回收）。

## 进度回填：2026-10-23（镜像级几何审计 + caps 修复）

用户 m08018 问「我们的适配是不是有问题」，m08063 指出原厂线刷包位置，m08099「继续」后执行
**批次 ①：用原厂 boot.img 反汇编核对 profile**。

- 镜像：`V14.0.27.0.TMRCNXM_13.0\images\boot.img`，解压内核 46,701,100 B，kallsyms 恢复
  **140,403** 条符号，`_text = 0xffffffc010000000`。
- 工具：新增 `tools/extract_rs/src/bin/audit.rs`（`TEMP(audit-01)`），按符号名定位并反汇编指定窗口。
- **符号偏移 11/11 一致**（含 `kernel_phys_load=0xa8000000`，由 `uefi.elf` memory map 推出；
  `xbl_config.elf` 的 FDT 没有唯一的 NOMAP/Kernel 区）。
- **结构体偏移 14/14 一致**，每条都有指令作证：`prio@0x84`、`normal_prio@0x8c`、
  `pi_lock@0x86c`、`pi_waiters@0x880`、`pi_top_task@0x890`、`pi_blocked_on@0x898`、
  `real_cred@0x778`、`cred@0x780`、`seccomp@0x848`、`comm@0x790`、`cred.copy_size=0xa8`、
  `user_ns@0x88`、`group_info@0x90`。附带确认 `rt_mutex_waiter.task@0x30`/`lock@0x38`。
- **发现并修复一处真实缺陷**：`cred.caps_offset = 48` + `caps_count = 5` 时，第五个 8 字节
  word 落在 `cred->session_keyring`（0x50）上，写成 `0xffffffffffffffff` —— 一个会被
  `key_put()` 解引用的野指针；而 `cap_inheritable`（0x28）反而没被覆盖。`util.cpp` 的
  `caps_offset + caps_count*8 > copy_size` 边界检查拦不住（88 ≤ 168）。已改为
  `caps_offset = 40`，与 main 上真机验证过的 5.10.236 Xperia profile 取值一致；
  `./gradlew exportKernelProfiles` 通过，导出 bin 里该字段读回 `0x28`。
- **配置瘦身**：marble profile 的 `execution` 块删掉 20 个与共享 preset 逐字相同的键
  （race/handoff/heap/w1/w2/enter_delay_us/timeout_us/w3_settle_us），只留
  cpus 4/5、`w3_attempts=1`/`w3_chain_rounds=1`、`consumer_max_calls/burst_calls=1/1`。173→154 行。
- 仍未证明的两项：`route.select_stack.waiter_shift = -2`（提取器明确报
  `pselect_waiter_shift unavailable`，只有项目自己的反汇编推导 + 真机 A/B）与
  `cred.ref0_offset = 128`（由相邻布局推定）。
- 提取器对本机给出 **`suggested route = multicast_waiter (medium)`**（5.x 已发布 profile 全部走
  multicast），而本机走 select_stack —— 这是下一轮单 route A/B 的首选候选。

**完整证据表见 `docs/analysis/2026-10-23-marble-geometry-audit.md`。**

状态：批次 ① 结案；下一步 = ② multicast 单 route A/B（需补 5.x 模板的 waiter 几何字段）。

## 进度回填：2026-10-23（W3 leaf 方向入 profile：每轮 route 5 → 4）

几何审计确认「几何不是填错」后，最省风险的收益点是**砍掉一条 attack route**。W3 阶段目前发
5 条 route：W1、W2、W3-0（leaf dir 探针）、W3 flags、W3 mode。其中 W3-0 只是用来测
`comm` 槽的写入方向（`leaf_to_target8`），而该方向在本机是常量。

- **方向恒为 0 的证据**：全仓 `docs/` + `build/` 扫描，`lands on [target]` 命中 **134** 次，
  `lands on [target+8]` 仅 **2** 次且都出现在 `.so` 的格式字符串里（`so-strings*.txt`），
  没有一次是运行时命中。`src/core/session/victim_process.cpp:739` 的 `verify_leaf_dir_stage`
  据此每轮都置 `leaf_to_target8 = 0`。
- **W3 两次写不能合并**：反汇编 `__secure_computing` 显示 `ldr w9,[x8,#0x848]`（mode）后
  `cmp w9,#0x2` / `b.ne`、`cmp w9,#0x1` / `b.ne 0x2f75bc`，而 `0x2f75bc` 正是 `brk #0x800`
  （`BUG()`）。mode 归零但 TIF_SECCOMP 仍置位时，下一次系统调用必然 BUG 重启 ⇒
  必须先清 flags 再清 mode，两次写缺一不可。原待办「评估合并 W3 的两条 route」据此**关闭为不可合并**。
- **改动**：新增 profile 字段 `route.select_stack.w3_leaf_to_target8`（0 = `[target]`，
  1 = `[target+8]`，缺省则保留 per-run 探针）。四处同步：`profile/model.h`
  （`KernelMisc` / `SelectStackLayout` / `select_stack_layout()`）、`profile/binary.cpp`
  的 `kRouteSelect[]`、`cve_2026_43499_backend.cpp` 的 `w2p`（跳过 `prepare_prebuilt_leaf_page`）
  与 `w3()`（跳过 `retry_write_stage("W3-0: leaf dir", …)`）、Kotlin 的 `SelectConfig`
  + `AndroidProfileConfigController` 校验/`RouteBranchFields`。marble profile 写
  `w3_leaf_to_target8 = 0`。
- **跳过 leaf 页 spray 的依据**：`consume_prebuilt_leaf_page` 只在
  `cve_2026_43499_backend.cpp:515` 的 W3-0 路径被调用，`select_stack_route.cpp` 不用 prebuilt 页，
  跳掉探针后那张页无人消费，所以连 spray 一起跳是安全的（也省掉整轮 KernelSnitch 扫描）。
- **新增测试**：`backend_dataflow_test.cpp` 的 `test_leaf_direction_pinned()` 断言
  无 pin 时 `unpinned_leaf >= 1`、pin=0 时 `pinned_leaf == 0`、
  `pinned_routes == unpinned_routes - 1`、两次都 `RunCode::Completed`。
- **门禁**：NDK 构建零告警（2,793,800 B）；`cmp_disasm` 对本批前置控制二进制
  （`build/ghostlock-preleafpin.bin`，2,792,688 B）**PASS** —— 8 个攻击函数指令数一致、仅
  LAYOUT-SHIFT；主机测试 27 个全过（`tcp_zerocopy_route_test` 因 arm64 内联汇编在 x86 主机
  固有失败，与本批无关）；`backend_dataflow_test: ok`；`:profile-core:test` 通过；
  `exportKernelProfiles` 64 profile，导出 bin 1998 B（+27 = 名长 + key + 值）；
  clang-tidy 两个改动 TU 均 0 findings。
- **已知与本批无关的红灯**：`:app:testDebugUnitTest` 80 个测试里
  `ProfileMigrationEquivalenceTest."all remote main 6x profiles resolve identically through
  legacy import"` 失败 —— origin/main 合并新增了 `6.1.145-…-9b69cc399ae1` 与
  `6.1.25-…-maybe-dirty` 两个 6.x profile 但没更新 legacy fixture
  `remote-main-6x-offsets.json`，已用单文件 stash 复现证明与本批改动无关。

状态：实现与门禁完成，真机 A/B（5 条 route 的 37.5% 基线 vs 4 条 route）进行中。

### 真机首轮（run 20261023-140625，一次命中）

冷机启动 243 s 后点击执行，**一轮走完全链**：

```
=== W1: SELinux ===      target=0xffffff802aa2fb98 mode=1 leaf=0
=== W2: cred ===         target=0xffffff87f56fe400 mode=2 leaf=0
W3-0 leaf direction pinned by profile (0); skipping leaf page spray
W3-0 leaf direction pinned by profile: [target]
=== W3: TIF_SECCOMP ===  target=0xffffff87f56fdc80 mode=1 leaf=1
=== W3: seccomp mode === target=0xffffff87f56fe4c8 mode=1 leaf=1
apd insmod kmi=android12-5.10 ko=/data/user/0/com.ghostlock.app/files/kernelpatch.ko
native exited code=0
```

- **route 数确认为 4**（W1 / W2 / W3 flags / W3 mode），`W3-0: leaf dir` 探针 route 不再出现，
  `prepare_prebuilt_leaf_page` 的整轮 KernelSnitch 扫描也一并消失。
- 命中后核对：`grep kernelpatch /proc/modules` → `kernelpatch 126976 0 - Live`；
  `su -c whoami` → `root`；`su -c 'id -u'` → `0`；`getenforce` → `Permissive`。
- 面包屑 `w3diag-F-send/recv/forked/exited/replied/gotcode` 六步齐全。

### 顺带查清的一处长期干扰：自动重试层会自锁成重启循环

`pm clear` 前后对比：清理前设备**每次 boot_completed 后 25–60 s 就消失**（连续两次），
清理后 2 分钟稳定并跑出上面这一轮。原因在 retry 层（`RetryStore` + `BootReceiver` +
`RetryAlarmReceiver`）：`files/.ghostlock_retry.conf` 里 `attempt=1 / max=6` 一直存在，
`BootReceiver` 见 `attempt < maxAttempts` 就重新 arm，于是每次开机都会自动跑一轮；
W1 打偏（32.5%）后 panic 重启 → 再自动跑 → 形成无人值守的重启循环。
**做 A/B 前必须先 `adb shell pm clear com.ghostlock.app` 清掉 store 与 alarm**，
否则每轮都会被自动重试污染。该层需要一个安全阀（仅在用户显式开启时自动重试、
命中后立即 disarm），另开批次处理。

状态：真机首轮通过（4 条 route、全链命中）；下一步 = 冷机连续跑 ~20–40 轮做成功率 A/B。
## 进度回填：2026-10-23 16:20（4 条 route 成功率 A/B：13/38 = 34%，与 5 条基线无法区分）

### 4 条 route 确实生效
四个命中轮全部满足：`pinned by profile` 出现 2 次、`W3-0: leaf dir` 出现 **0** 次、
`route_done status=0` 出现 **4** 次。即 W1 / W2 / W3 flags / W3 mode 四条 route，
W3-0 探针 route 与其整轮 KernelSnitch 扫描均已消失。

### 三个批次（同一构建，同一设备 3e6f1443）

| 批次 | 时间窗 | 有效轮 | HIT-ROOT | 说明 |
| --- | --- | --- | --- | --- |
| ab4  | 14:36–15:03 | 11 | 4 | 6 轮 TAP-NO-RUN：锁屏/通知栏遮住执行按钮 |
| ab4c | 15:24–15:41 | 7  | 5 | 未处理对话框，但运行正常 |
| ab4d | 15:44–16:19 | 20 | 4 | 修好锁屏与对话框后 |

合计 **13/38 = 34.2%**（Wilson 95%：21%–50%）。

对照 5 条 route 基线（8 sends 回收）**3/8 = 37.5%**（14%–69%）。
两组区间大幅重叠 ⇒ **本批无法证明 4 条更好，也没有回归证据**。
模型预测的 45.6% 未出现，说明「per-route 生存率 0.822 且均匀」这个前提不成立
（W2/W3 的 pselect 命中率低于 W1）。

### 死点（来自 fsync 面包屑，panic 后唯一可靠通道）

```
wd req target=ffffff802aa2fb98 mode=1          # W1 SELinux
psel page=ffffff87e1d18000 lock=... shift=-2
wd route-returned code=0 elapsed=1212ms        # W1 成功，1.2 s
...
wd req target=ffffff8830c5e400 mode=2          # W2 cred
psel page=ffffff8823ec0000 lock=... shift=-2
                                               # 无 route-returned → 死于 W2 pselect
...
wd req target=ffffff802aa2fb98 mode=1          # 又一次 W1
psel page=ffffff88dbcf8000 lock=... shift=-2
                                               # 无 route-returned → 死于 W1 pselect
```

结论：死亡全部是 **pselect 打偏**，发生在 W1 或 W2 的 route 内，与 W3 leaf 方向无关。

### 新发现的观测缺陷（下一步必须先修）

失败轮的 native 日志是 **0 字节**。stdout 重定向到文件时是块缓冲（4 KiB），
进程 panic 时缓冲区内容全部丢失 ⇒ 每次失败都拿不到现场。
必须先让 native 日志无缓冲（启动时 `setvbuf(stdout, nullptr, _IOLBF, 0)`，
或每条日志后 `fflush(stdout)`），否则后续所有 panic 取证都只能依赖面包屑。

### 状态

4 条 route 改动：功能正确、无回归、每轮少一次 KernelSnitch 扫描（约省 15–20 s）。
成功率瓶颈仍是 pselect 打偏，本批未能通过减少 route 数改善。
下一步：① native 无缓冲日志；② 用完整日志抓 pselect 打偏现场。
## 进度回填：2026-10-23 16:35（native 日志无缓冲 + lint 门禁转绿 + 三条踩坑记录）

### 1. 失败轮日志为 0 字节的根因与修复

A/B 批跑里 16 个失败轮的 `ghostlock-direct-0.log.txt` 全是 **0 字节**，
而 fsync 的面包屑（`files/.ghostlock_spray_probe`）完整记录了死点。
原因：stdout 被 app 重定向到文件 ⇒ 块缓冲（4 KiB），进程 panic 时缓冲区内容全部丢弃。

修复 `src/core/main.cpp`（`main()` 入口第一件事）：

```cpp
std::setvbuf(stdout, nullptr, _IOLBF, 0);
std::setvbuf(stderr, nullptr, _IOLBF, 0);
```

效果：panic 前的每一行日志都会落盘，后续所有现场取证不再只依赖面包屑。

### 2. lint 门禁由红转绿

全量 `build/lint_all.bat` 之前 `TIDY_STATUS=1`，失败点是
`core/session/victim_process.cpp:587`：

```
error: The 1st argument to 'lseek' is -1 but should be >= 0
       [clang-analyzer-unix.StdCLibraryFunctions,-warnings-as-errors]
```

即 handoff worker 的诊断块在 `open()` 失败时对 fd -1 调 `lseek`/`read`。
已加 `if (probe.get() >= 0)` 守卫（失败时 `script_size`/`script_bytes` 保持 -1，
记录语义不变）。修后 **`TIDY_STATUS=0`，29 个 TU 全部零 user-code 诊断**。

### 3. 门禁结果（本批）

| 项 | 结果 |
| --- | --- |
| NDK 构建 | 2,793,864 B，零告警 |
| cmp_disasm（vs `build/ghostlock-preflush.bin`） | **PASS**，6 个攻击函数全部 **IDENTICAL (strict)**，2 个 multicast SKIP |
| 主机单测 | 27 个 PASS；仅 `tcp_zerocopy_route_test` 在 x86 主机因 arm64 内联汇编 `yield` 无法编译（既有、与本批无关） |
| clang-tidy 全量 | **0** |
| APK | 22,311,177 B，包内 `libghostlock.so` 446,272 B |

### 4. 真机复测

装新 APK 后连跑 3 轮：**3/3 HIT-ROOT**（424/447/465 行日志，均 4 条 route、
`ksu_ready=1 module=2 w3=1 w1=4`）。本批未出现失败轮，故「panic 时日志是否完整」
尚未被直接观测；按 `_IOLBF` 语义应在下一次失败时生效。

4 条 route 累计：**16/41 = 39.0%**（Wilson 95%：25%–55%），
与 5 条 route 基线 3/8 = 37.5% 仍无法区分；机制收益（每轮少一次 KernelSnitch 扫描，
约 15–20 s）成立。

### 5. 批量脚本踩坑记录（`build/ab-rounds.ps1` 现有形态已全部规避）

1. **解锁**：`input swipe` 不可靠（约 35% 轮次停在锁屏/通知栏，点击落到遮罩上）。
   必须 `input keyevent 224` + `wm dismiss-keyguard`，再用
   `dumpsys window | grep mCurrentFocus` 校验焦点在 `com.ghostlock.app`。
2. **不要每轮 `pm clear`**：清空后首轮 app 会建出 run 目录但 native 一行都不写
   （Shizuku UserService 尚未绑定）。改为 `run-as … rm -f files/.ghostlock_retry.conf`
   关闭自动重试层即可。
3. **每次开机 app 会弹「建议启用 Shizuku」**（Shizuku 未运行），
   对话框按钮 `取消` 在 (311,2190)、`启用` 在 (769,2190)；
   不点掉则执行按钮被挡住，点击无效。
4. **分类不能只看最后一行**：`fork-hold parked pid=…` 是成功路径的倒数几行
   （父进程在 `run_orchestrated_pipeline` 返回后 park 一个 hold 子进程），
   必须用 `grep -c 'KernelSU ready'` 等内容判据。
5. **脚本编码**：`write` 产出的 UTF-8 无 BOM 的 `.ps1` 被 Windows PowerShell 5.1
   按 ANSI 解析，中文正则字面量会直接导致语法错误；必须写成 UTF-8 **带 BOM**。
## 进度回填：2026-10-23 17:15（拿到完整日志：打偏的真实死点是第一次 nice 提升）

### 为什么之前的失败轮日志都是 0 字节
`pr_info` 在 Android 上走 `__android_log_print`？**不是**：本机构建未定义
`ANDROID_APP_NO_LKM`，宏落到 `#else` 分支的 `printf`，所以输出进 stdout，
由 Kotlin `runExploitBinary` 的 `ProcessBuilder(...).redirectOutput(nativeLog)` 直接
写进 `files/.ghostlock_native.log`。归档目录里那份 `ghostlock-direct-0.log.txt`
是 app 的 tailer 线程每 200 ms 读一遍再 `archive.append()` 抄过去的**副本**。

行缓冲（`setvbuf(_IOLBF)`）只保证字节进入 page cache；panic 重启时 page cache
整块丢失，归档副本只剩定长全 0（实测 374 B、555 B 全是 `0x00`）。真正的幸存
通道是 native 自己写的那份：`run-as com.ghostlock.app cat files/.ghostlock_native.log`。
为让它跨 panic 存活，`src/core/main.cpp` 加了 `log_sync_guard`：后台线程每 200 ms
`fsync(fileno(stdout))`，退出时 join 再 fsync 一次。实测同一轮失败后该文件
**80 行 / 5 366 B 完整保留**，归档副本仍是 555 B 全 0。

### 完整日志给出的死点（run 20261023-171352，W1 第一次尝试）
```
[*] W1: SELinux attempt 1/15
[*] === W1: SELinux === target=0xffffff802aa2fb98 mode=1 leaf=0
[*] [T+1891ms]   heap spray done
[*] [route] creating waiter/owner/consumer
[*] [route] waiter parked; owner started
[*] [route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
[*] pselect route setup shift=-2 page=ffffff88ae818000 fake_lock=ffffff88ae818000 ...
[*] pselect pre-select attempt=1/4 compact=2 +0ms
[*] consumer gate: waiter parked in syscall 72
[*] consumer call 1 entering sched_setattr tid=14622 nice=1
<无后续：panic 重启>
```

### 与命中轮的逐行对比（run 20261023-163415）
| 行 | 命中轮 | 失败轮 |
| --- | --- | --- |
| `CMP_REQUEUE_PI ret=-1 errno=35` | 有 | 有（**EDEADLK 是常态，不是判别因子**） |
| `consumer gate: waiter parked in syscall 72` | 有 | 有 |
| `consumer call 1 entering sched_setattr … nice=1` | 有 | 有 |
| `consumer call 1 sched_ret=0 errno=0 success=1` | 有 | **没有** |
| `pselect post-select attempt=1/4 +201ms ret=4` | 有 | 没有 |

### 结论（本批次最重要的定性修正）
「pselect 打偏」不是「pselect 不返回」，而是 **consumer 的第一次
`sched_setattr(waiter_tid, nice=1)` 在内核里走
`set_user_nice → rt_mutex_adjust_prio → rt_mutex_adjust_prio_chain`
时踩到不可映射内存**，`panic_on_oops` 直接把机器重启。用户在归档日志里看到的
「route 不返回」，是 panic 之前那 200 ms 还没轮到 tailer 抄写造成的假象。

因此可打偏的窗口只有一个：**PI 链遍历那一刻 `task->pi_blocked_on` 链上的对象
是否仍然可读**。命中与失败在 userspace 侧完全同构（同样的 CMP 返回、同样的
gate 判定、同样的 craft 页与几何），差异只在核内对象生命周期。

### 下一步（按证据排序）
1. **核内证据**：marble 的 ramoops 未注册、dropbox 无 `SYSTEM_LAST_KMSG`，
   唯一可得 panic 调用栈的路径是「root 态 + kernelpatch 的 kmsgd 落盘」
   （`/data/local/tmp/glkfx/kmsg-tail.bin` 曾在本机 5.10.157 上给出完整 oops）。
   需要一轮「先 root、再在同一 boot 内跑攻击」的取证轮。
2. **不依赖核内证据的加固**：把 `prepare_kernel_page` 的弱校验（page+2 奇偶）
   换成**写读回环 canary**（craft 后通过 reclaim 的 socket 读回整字比对），
   在提交 route 之前就把「页不属于我们」的样本筛掉并重试，避免把这类样本
   送进 `sched_setattr`。
3. **保持页存活**：确认 `reclaim sends` 打开的 socket 在整个 route 期间不被
   drain/close（8 sends 已把成功率从 20% 抬到 37.5%，说明页存活是主因子）。

## 进度回填：2026-10-24 14:47（首次拿到打偏现场的内核 oops：死因是 craft 的假 rt_mutex 树不合法）

### 怎么拿到的
10-23 21:36 那次命中后设备**一直没有重启**（10-24 14:43 uptime 61,708 s = 17.1 h，`getenforce`=Permissive，`su -c id -u`=0，`kernelpatch 126976 Live`）。
这推翻了「命中后同 boot 必死」的旧结论。root 还在，于是把 10-23 就注册好的 kprobe 探针接上 dumper
（`/sys/kernel/tracing`，`glk_adj` / `glk_prx` / `glk_flt` 三个 kprobe），跑一次真实攻击就抓到了现场。

关键教训：之前「trace 为空」是假象——21:36 的 arm 脚本留下一个 `cat trace_pipe`（PID 23999）一直在偷偷
把事件读走，写进 `/data/local/tmp/glk-trace.log`（17 h 攒了 105,342 行 / 8.1 MB）。杀掉它、换
`build/kprobe-dump.sh`（`setsid` + `</dev/null >/dev/null 2>&1`）才看清。事件过滤器必须从文件喂：
`comm == "libghostlock.so"`，用 adb+su 内联引号会被吃掉（`parse_error: Invalid value`）。

### 抓到的 oops（`build/dmesg-now.txt`，设备侧 dmesg 第 24171 行起）
```
[61924.725961] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000018
[61924.726019] Internal error: Oops: 96000005 [#1] PREEMPT SMP
[61924.726574] CPU: 5 PID: 28551 Comm: libghostlock.so
[61924.726589] pc : rb_insert_color+0x48/0x164
[61924.726594] lr : rt_mutex_adjust_prio_chain+0x580/0x19a0
[61924.726596] sp : ffffffc04cedbc50
[61924.726599] x29: ffffffc04cedbc80 x28: ffffffc04cf13c30
[61924.726603] x27: ffffff88aaf28000 x26: 0000000000000001
[61924.726607] x25: ffffff88c266bfec x24: ffffffdc8d78f000
[61924.726616] x19: ffffff88c266b780 x18: ffffffc04185d040
[61924.726645] x1 : ffffff88aaf28008 x0 : ffffffc04cf13c30
[61924.726649] Call trace:
[61924.726653] rb_insert_color+0x48/0x164
[61924.726656] rt_mutex_adjust_pi+0x174/0x30c
[61924.726663] __sched_setscheduler+0xeb4/0x14f4
[61924.726667] __do_sys_sched_setattr+0x25c/0x3f8
[61924.726698] Code: f9000109 b4fffea9 f9400128 370008c8 (f940050a)
```
（`f940050a` = `ldr x10, [x8, #8]`，而 `x8` = 0x10 ⇒ 访问 0x18 触发 translation fault level 1；
`pstate` 里 `+PAN` 说明是内核态访问用户/无效地址。）

### 这次 oops 证明了什么
1. **`sched_setattr` → `__sched_setscheduler` → `rt_mutex_adjust_pi` → `rt_mutex_adjust_prio_chain`
   这条链确实被触发**，而且走到了 `rt_mutex_adjust_prio_chain+0x580` 里的 `rt_mutex_enqueue`。
   也就是说：**打偏不是「什么都没发生」，而是内核顺着悬空指针走进了我们 craft 出来的对象**。
2. `x1 = ffffff88aaf28008` = 我们 spray 页的 **page_base + 8**，即 `&lock->waiters`（`rt_mutex` 里
   `wait_lock@0x00`、`waiters@0x08`）。⇒ 内核把**我们的 payload 页当成了那个假 `rt_mutex`**。
3. `x0 = ffffffc04cf13c30` = `task->pi_blocked_on`（`x28` 同值），是 vmalloc 栈上的真实 waiter。
   ⇒ 悬空指针指向的 waiter 是内核自己的对象，`waiter->lock` 已经被指到我们的页。
4. 崩在 `rb_insert_color` 的原因：`rt_mutex_top_waiter(lock)` 读 `lock->waiters.rb_leftmost`（页 +0x10），
   该处不是 0，于是算出一个假的 parent（0x10），`rb_insert_color` 顺着它读 `[0x10+8]` → 0x18 → 崩。
   **假 `rt_mutex` 的 `waiters` 必须是一棵合法的空树**（`rb_node=0`、`rb_leftmost=0`），
   现在这两个字段没有被 payload 清零，是页里的残留垃圾。

### 结论与下一步
- 这不是「打偏让内核卡死」的玄学，而是一个**可定位、可修的 craft 缺陷**：假 `rt_mutex` 头部（`wait_lock`/
  `waiters.rb_node`/`waiters.rb_leftmost`/`owner`）没有按 `struct rt_mutex` 的语义填好。
- 下一步（批次 I）：在 payload 页里把假 `rt_mutex` 头部显式清零（`+0x00`、`+0x08`、`+0x10`），
  `owner` 按需要填 0 或指向能终止链条的 task；然后重跑，看 `rt_mutex_adjust_prio_chain` 是否能干净地
  走完并把写落下去。判据仍是 `getenforce` 与 route 日志，探针继续开着抓下一次现场。

### 补充（同日 14:52）：oops 为什么会让整机死掉
`dmesg` 末尾那行 `note: libghostlock.so[28551] exited with preempt_count 3` 是关键。
崩点 `rb_insert_color` 是在 `rt_mutex_adjust_prio_chain` **持有 `task->pi_lock`（raw_spin_lock_irqsave）的情况下**被调用的：
oops 杀死该线程时不会释放这把锁，`pi_lock` 就被永久泄漏。之后任何要拿这个 task 的 pi_lock 的路径
（调度、`sched_setattr`、唤醒）都会永久自旋 —— 这就是「打偏 = 整机 wedge」的机制，也解释了为什么
每次打偏都没有任何后续日志（不是没写，是写日志的线程也卡在同一个锁上）。

因此修好 craft 不只是「提高成功率」，而是**从根上消掉这类 wedge**：只要 walk 不在持锁状态下踩空，
设备就不会死。

### 现场复现所需的两个脚本（已就绪）
- `build/kprobe-dump.sh`：`setsid` 脱离 adb 的 `trace_pipe` 落盘器（逐行 sync，panic 也留得下）。
- `build/arm-probes.sh`：重启后一键重建 4 个探针（`glk_adj` / `glk_prx` / `glk_flt` / `glk_lk`）+
  过滤器 + dumper。其中 `glk_lk` 用两级解引用直接打印「waiter→lock→rt_mutex 头四个字」，
  用来验证 `*(page+0x300)` 到底是不是我们写的 1。

## 进度回填：2026-10-24 16:50（反汇编把崩溃点钉到指令级 + 决定性探针就绪）

### 崩溃指令级定位
用 `build/extract/release/audit.exe` 对原厂 `boot.img`（`_text = 0xffffffc010000000`）反汇编：

- `rb_insert_color`：
  - `+0x00 ldr x9,[x0]` / `+0x04 cbnz x9` / `+0x08 mov x8,x0` / `+0x0c mov w9,#1` / `+0x10 str x9,[x8]`
    即 `if (!parent) { rb_set_parent_color(node, NULL, RB_BLACK); break; }`。
  - `+0x40` 起主循环：`+0x40 ldr x8,[x9]`（`gparent = *(parent)`）、`+0x44 tbnz w8,#0`（parent 黑则退出）、
    `+0x48 ldr x10,[x8,#0x8]`（`gparent->rb_right`）。
  - 崩溃 `pc = rb_insert_color+0x48`、`x8 = 0x10` ⇒ 访问 `0x18` 触发 translation fault。
    **即 `*(parent) == 0x10`**。
- `rt_mutex_adjust_prio_chain` 内有 3 个内联 `rb_insert_color` 调用点：
  1. `+0x578`（返回地址 `+0x580`）：`str xzr,[x28]` / `str x28,[x1]` / `str x28,[x27,#0x10]` = `lock->waiters` 入树，
     `x27` = lock、`x28` = waiter 的 `tree_entry`、`x1` = `rb_link` 目标。
  2. 两处 `str x9,[x0,#0x18]!` / `str x0,[x19,#0x888]` = `task->pi_waiters` 入树（`rb_leftmost` 在 `pi_waiters+0x08`）。
- 由此确认 `struct rt_mutex_waiter` 布局：`tree_entry@0x00`、`pi_tree_entry@0x18`、`task@0x30`、`lock@0x38`、
  `prio@0x40` —— 与 `encode_compact_waiter()` 写 `0x18/0x20/0x28` 完全一致，**craft 布局无误**。
- 崩溃 `lr = +0x580` 指向第 1 个调用点，其 `parent` 即 `lock->waiters.rb_node` 所指节点 = 我们写的 `fake_w0`
  = `page+0x300`。
- **矛盾**：payload 用 `put64(p, kernel::W0_OFF + 0x00, 1)` 把 `page+0x300` 写成 `1`，内核却读到 `0x10`。

### 两个互斥假设（下一步用探针分辨）
| 假设 | 判据 | 修法 |
| --- | --- | --- |
| H1 页不是我们的（抢页失手） | `*(lock+0x08) != lock+0x300`，或 `*(lock+0x300) != 1` 且 `*(lock+0x08)` 也不是我们写的值 | 提高 reclaim 确定性 |
| H2 假 `rt_mutex` 头部写错 | `*(lock+0x08) == lock+0x300` 且 `*(lock+0x300) != 1` | 修假头部布局 |

### 决定性探针 `glk_enq`
```
p:kprobes/glk_enq rt_mutex_adjust_prio_chain+0x570 lock=%x27 node=%x28 link=%x1 \
  root=+0x8(%x27):u64 w300=+0x300(%x27):u64 nodepc=+0x0(%x28):u64 comm=+0x790(%x2):string
```
在 `str x28,[x27,#0x10]`（`+0x570`）之前取寄存器，一条记录即可判定 H1/H2。
已加入 `build/arm-probes.sh`（共 5 个探针，全部套 `comm == "libghostlock.so"` 过滤器）。

### 顺带查清的常量
- `kRelinkNodeOffset = 0x200`：黑色节点地毯落在 `page+0x200`，而内核真正走的是 `page+0x300`（`fake_w0`）；
  且 `0xe80 + 0x200 == kCredentialCopyOffset (0x1080)`，W2 的 cred 拷贝会整块覆盖地毯
  （W2 的 `layout.right` 指向 `init_cred`，所以至今未显现）。
- 试改为 `0x300` 后 `cmp_disasm` 出现 `prepare_good_kernel_page` SHAPE-DIFF（仅指令重排，无行为收益），
  按「攻击关键路径最小改动」原则回退；只保留注释与
  `static_assert(kLockOffset + kRelinkNodeOffset == kCredentialCopyOffset)` 记录该事实。
  重建后 `cmp_disasm` **PASS**（8 个攻击函数 IDENTICAL，multicast 两个 SKIP），二进制与改动前逐字节一致。

### 一键取证脚本
`build/probe-run.ps1`：检查 root → 推 `arm-probes.sh` / `kprobe-dump.sh` / `filter.txt` → arm 5 个探针 →
拉起 app → 点击执行 → 轮询判定（HIT-ROOT / HANDOFF / DEVICE-OFFLINE / TIMEOUT）→
把 trace / breadcrumb / dmesg / native log 拉回 `build\probe-<ts>\`。纯 ASCII，已过 PowerShell 语法检查。

### 设备状态（当前阻塞项）
- 2026-10-24 约 14:47 的 oops 在持有 `task->pi_lock` 时踩空 ⇒ `pi_lock` 永久泄漏 ⇒ 整机 wedge。
  `panic_on_oops=0`，且命中轮已 unbind `gh-watchdog`，因此没有内核侧自动重启路径。
- 15:35 起后台轮询 75 分钟（`build/wait-device.log`）**超时**；`adb reconnect offline` 与 adb server 重启均无效；
  设备持续 `offline` 约 2 小时。
- **结论：需要人工长按电源键强制重启**；重启后直接执行 `build/probe-run.ps1` 定性 H1/H2，再按结论修。
## 进度回填：2026-10-25 15:20（收尾审计 · 规范化 · 提交前门禁）

### 本次收尾做的三件事

1. **临时探针分类处置**（原则：诊断价值 vs 是否改动攻击函数机器码）
   - **删除**：`src/core/main.cpp` 的 `logsync` 线程与 `setvbuf`。前提假设是错的 ——
     `pr_info` 在设备上只走 `__android_log_print`（见 `src/core/kernelsnitch/utils.h`），
     一行都不写 stdout，所以 stdout 的缓冲与 fsync 救不回 native 日志；
     真正能活过重启的是 fsync 面包屑。整个文件已还原到 HEAD。
   - **删除**：`victim_process.cpp` 的 10 条 `w3diag-*` 面包屑（F/M 交换的逐步打点）。
     F 交换是否走完这个问题已经答完，细粒度打点没必要留在每次运行的热路径上。
   - **保留并转为常设诊断**：`race/threads.cpp` 的 `wd req` / `wd route-returned`，
     `select_stack_route.cpp` 的 `psel page=… lock=… w0=… shift=…`，
     `support/util.cpp` 的 `step6 done ok=…`。理由：这台内核打偏即 wedge，
     logd 是第一批死者，**只有 fsync 面包屑能回答「死在哪条 route」**；
     而且这些行在 2026-10-23 的 41 轮 A/B 与 3 轮命中里全部存在，
     即它们属于**已真机验证过的那份二进制**，不是新引入的变量。

2. **审计（所有权 / 生命周期 / UAF，按 AGENTS.md 的核心攻击代码审查要求）**

   | 对象 | 起点 | 所有者 | 访问者 | 终结点 | 结论 |
   | --- | --- | --- | --- | --- | --- |
   | `pinned_leaf_direction` / `pinned_leaf` | `select_stack_layout()` 返回值拷贝 | 栈上 `std::optional<uint8_t>` | 本函数内比较与解引用 | 函数返回 | 值语义，无借用、无悬垂 |
   | prebuilt leaf 页 | `prepare_prebuilt_leaf_page()` 内的 spray | 会话 `heap` | 仅 `consume_prebuilt_leaf_page()`（W3-0 路径，backend:515） | 消费或进程退出 | 固定方向时**不分配也不消费**，两端同时消失，无泄漏、无 UAF |
   | `reclaim_sv[0]` socket | 本函数内创建 | 本函数 | `sendmsg` 循环 | 作用域结束由既有清理关闭 | 短发送只提前 `break`，不新增持有者 |
   | `request`（`WriteRequest`） | 调用方 | 调用方 | `run_main_route_threads` 只读 `.target`/`.mode` | 调用方 | 未延长生命周期 |
   | `heap.current` 的 base/fake_lock/fake_w0/fake_task | payload 准备阶段写入 | 会话 | 面包屑只读 | 会话结束 | 读取点位于 `open_selected_fds` 之前，字段仍有效 |
   | `probe`（handoff 脚本 fd） | `open()` | RAII fd 包装 | `lseek`/`read` | 包装析构 | 新增 `>= 0` 守卫，`open()` 失败时不再对 -1 操作 |
   | 新增全局 | — | — | — | — | **无新增可变全局**；仍只有 `g_exploit_session` 与 `g_direct_map_end` |

   UAF 结论：本次改动不新增任何跨线程共享的裸指针或引用；`w3_stage_context.leaf_to_target8`
   仍是 `int32_t` 值拷贝，与原有 `verify_leaf_dir_stage` 写入路径同型。

3. **门禁（提交前全绿）**

   | 项 | 命令 | 结果 |
   | --- | --- | --- |
   | NDK 构建 | `build\rebuild-native.ps1` | `build/native/ghostlock` 2,793,368 B，**零告警** |
   | `cmp_disasm` | vs `build\ghostlock-preflush.bin` | **PASS**，8 个攻击函数指令数全部一致（仅地址操作数平移），multicast 两个 SKIP |
   | 主机单测 | 本机 llvm-mingw 原生构建 27 个测试二进制（`build\native-host-tests\`） | **14/27 运行通过**；12 个因 Windows 缺 POSIX 头（`sys/mman.h`/`sys/select.h`/`sys/wait.h`/`poll.h`）无法构建、`futex_hash_test` 因 LLP64（`long` 为 4 字节）断言不符 —— 均为既有平台限制。改动涉及的 8 个（profile / profile_binary / payload_builder / route_policy / route_catalog / component_catalog / backend_contract / route_lifecycle）全部通过 |
   | attack data-flow 测试 | `host_attack_dataflow_test` | **本机无法构建**（`core/route/route_api.hpp:7` 需要 `sys/select.h`）；新增的 `test_leaf_direction_pinned` 在 2026-10-23 最后一次运行中为 `backend_dataflow_test: ok`，本次未能重跑 —— **记为门禁缺口** |
   | clang-tidy | `build\lint_all.bat`（29 TU） | **TIDY_STATUS=0** |
   | profile 导出 | `gradlew exportKernelProfiles` | 64 profile；marble bin 1998 B，`caps_offset=40`、`caps_count=5`、`w3_leaf_to_target8=0`、`waiter_shift=-2`、`compact_waiter=2` |

   **基线口径说明（重要）**：本批的 `cmp_disasm` 参照物是 `build\ghostlock-preflush.bin`
   （2026-10-23 16:20 构建，其 APK 装机后连跑 3 轮全 HIT-ROOT；同一份攻击代码跑了 41 轮 A/B），
   **不是** `build\ghostlock-marble-9443450.bin`。后者早于本轮全部诊断插桩与 8-sends，
   与之相比 `run_main_route_threads` 414→461、`prepare_good_kernel_page` 2104→2194，
   差值正是上面「保留并转为常设诊断」的两处面包屑与 reclaim 计数 —— 二者都存在于每一次真机轮次中。

### 被停放（不进本次提交）

- **app 内自动重试层**（`com.ghostlock.app.retry` 六个文件 + Manifest 权限/组件 +
  `GhostlockViewModel`/`MainActivity` 接线）：已知自锁缺陷（`BootReceiver` 见
  `attempt < maxAttempts` 就重新 arm，形成「开机即跑 → 打偏 → 重启 → 再跑」的无人值守循环），
  且被 MIUI 反复回收。原件与补丁存 `build\parked-auto-retry\`。
- 需要它的那天，先补安全阀（仅显式开启才自动重试、命中即 disarm）再走独立 PR。

### 未纳入本批的已知问题

- 设备 `3e6f1443` 自 2026-10-24 14:47 的 oops 后持续 `offline`（USB 仍枚举、有电、内核 wedge），
  需人工长按电源键；因此本批**没有真机门禁**，`cmp_disasm` 是唯一的机器码级证据。
- 打偏根因仍停在 H1（抢页失手）/ H2（假 `rt_mutex` 头部写错）二选一，
  决定性探针 `glk_enq` 已就绪，等设备恢复。
## 进度回填：2026-10-26 11:50（打偏死点再缩小：死在入树之前）

### 探针实测（`glk_enq` 加宽窗口，一次真实打偏）
```
libghostlock.so-8417  glk_lk  task=0xffffff804de65c80 lk=0xffffff886e828000 n1=0xffffff880488d790 n2=0 n3=0
libghostlock.so-8417  glk_adj task=0xffffff804de65c80 blocked=0xffffff886e829e70 olock=0x0 owaiter=0xffffff886e828000
libghostlock.so-8417  glk_flt addr=0x41 esr=0x96000005 r0=0xffffff886e829e70 r28=0xffffff886e829e70 r29=0xffffff886e828100
```
三条事实：

1. `glk_adj` 与 `glk_flt` 之间**没有 `glk_enq`** —— `rt_mutex_adjust_prio_chain+0x570`（`lock->waiters` 入树点）从未执行。崩溃发生在**入树之前**，即读 `lock->waiters.rb_node` / 取 top waiter 那一步，不是此前假设的 `rb_insert_color` 插入。
2. 崩溃地址是 `addr=0x41`，不是随机垃圾（随机填弃会是 `0x4141414141414141` 形态）——像某个字段只有 1 字节有效。
3. `lock` 地址正好等于我们算的页基址（`lk == 0xffffff886e828000`，与面包屑 `psel page=` 一致），但 `*(lock+8)` 是 `0xffffff880488d790`，不是我们写的 `page+0x300`。

### 结论与待验证假设
- 页基址对上了，但页内偏移不是我们写的内容 ⇒ 只有两种可能：① 页不是我们的（抢页失手）；② `SKB_DATA_DELTA = -0xe80` / `SKB_FRAG_BIAS = 0xe80` 这组"用户态 buffer ↔ 内核页"的偏移在这个内核上不成立，`base+8` 落进了填充区。
- `addr=0x41` 更支持 ②：填充区被当作指针读出一个小值。验证办法是加宽探针窗口，同时读 `lock+0x00/0x08/0x10/0x18` 与 `lock+0xe80+0x00/0x08/0x10/0x18`，看真正的假 `rt_mutex` 头部落在哪一组。
- `/proc/kcore` 在本机不存在（`ls` 报 No such file），所以无法直接 dump 内核内存来比对，只能靠 kprobe 逐字段读。

### 32-send 加宽的实测（不构成改善证据）
- `SKB_RECLAIM_SENDS` 8 → 32、`SO_SNDBUF` 1 MiB → 8 MiB、去掉循环内逐条 fsync；门禁：`cmp_disasm` 仅 `prepare_good_kernel_page` 2194 → 2116（循环次数 + 内联调用移除），其余 7 个攻击函数 LAYOUT-SHIFT-only。
- 冷机批测 10 轮：**5 命中 / 5 打偏 = 50%**，对照 8-send 的 16/41 = 39%；Wilson 区间重叠（24%–76% vs 25%–55%），**不能声称改善**。

### 失败代价的变化（真正的收益）
- 打偏不再把整机钉死：设备在约 90 秒内由厂商看门狗自行重启，一轮失败的成本从"几小时 + 人工按电源键"降到"一次重启 + settle"。
- 因此新增 `build/root-until-hit.ps1`：按轮重试直到 `HIT-ROOT` 为止。首次使用 **attempt 1 即命中**，随后 `tools/trials/apatch_finish.ps1` 拿到 `VERDICT: SUCCESS - APatch root available (u:r:magisk:s0)`。
- 尝试给内核设 `panic_on_oops=1`（把 oops 变成 5 秒 panic）的 APatch 模块 `build/panicmod.zip` 安装成功但脚本未被解出（模块目录只有 `module.prop`），实测 `panic_on_oops` 仍为 0；**不需要它**，看门狗已足够。

### 关键对照：成功轮**完全不进** PI 链式调整
同一构建、同一探针（`glk_win` 挂在 `rt_mutex_adjust_prio_chain` 入口）下的两次运行：

| 轮 | 结果 | `glk_adj`/`glk_lk`/`glk_win` 命中数 | 说明 |
| --- | --- | --- | --- |
| 11:44 那次 | 打偏（fault addr=0x41） | 3 条 | 进了链式调整并在入树前崩 |
| 11:51 那次（run 20261026-115126） | **W1 成功**（`route-returned code=0 elapsed=1209ms`） | **0 条** | 内核根本没走这条路径 |

这条对照把问题重新定性：打偏不是"同一条 walk 里的时序竞争"，而是**内核走了另一条分支**——
成功路径根本不进 `rt_mutex_adjust_prio_chain`（写入由别处完成），失败路径才进，而且一进就死。
所以"让 walk 变稳"这个方向本身可能是错的；真正要做的是**查清什么条件下内核会去走这条链式调整**，把那个条件消掉。

## 进度回填：2026-10-26 14:15（20 轮实测：85% 完整成功，0 次打偏）

### 批跑前的 harness 修复（三个坑，全部落在 `build/ab-rounds.ps1`）
1. **开机后 adb 未稳**：`sys.boot_completed=1` 比 USB gadget 稳定早好几秒，期间每条命令都
   `device not found`。新增 `Wait-Stable`（连续 3 次 `adb shell echo ready` 成功）才进 settle。
2. **冷启动焦点丢失**：`am start` 后 4 秒 `mCurrentFocus` 可能还不是本 app，改为等 8 秒 +
   `monkey -p com.ghostlock.app -c android.intent.category.LAUNCHER 1` 兜底。
3. **中文字面量在 Windows PowerShell 5.1 下永远匹配不上**：PS 5.1 按 OEM 码页解 adb stdout，
   脚本里的「执行」与 XML 里的 UTF-8 字节不相等 ⇒ `Launch-Ready` 恒假、每轮 `LAUNCH-FAIL`。
   改为**只匹配 ASCII 的 bounds 串**（`[494,2233][586,2262]` = 执行按钮，
   `[494,2159][586,2221]` = 「上次攻击未完成」对话框的关闭按钮），并在脚本头强制
   `[Console]::OutputEncoding` / `$OutputEncoding` 为 UTF-8。

### 实测（同一份二进制：32-send + 4 条 route）
| 批次 | 轮数 | 触发时 uptime | 完整成功 | 死在 W3 seclamp clear | 打偏 |
| --- | --- | --- | --- | --- | --- |
| recheck-d | 10 | 68.27–69.52 s | 9 | 1 | **0** |
| recheck-e | 10 | 66.61–70.13 s | 8 | 2 | **0** |
| 合计 | 20 | 66.6–70.1 s | **17（85%）** | 3（15%） | **0** |
| 对照 reclaim32-a | 10 | 58.49–65.62 s | 5 | 0 | 5 |

Wilson 95%（17/20）：64%–95%。

### 唯一观察到的差异是点火时机
三轮用同一 APK、同一二进制、同一设备；差别只在 harness 现在等 adb 稳定 + 30 秒静置，
点击落在 uptime ≈ 66.6–70.1 秒，而旧批是 58.5–65.6 秒。**因果未证实**（缺一轮「提早点火」对照，
约 10 分钟），但「等系统空闲下来再开枪」本身零成本、无副作用。

### 剩余失败源已经换人
打偏 0/20 之后，最大的失败源变成 **W3 seclamp clear 写不进去**（3/20 = 15%）：
日志 `temporary root ready; KernelSU module not loaded (W3 seclamp clear failed)`、
`finit_module probe=-ESRCH`，10-22 已记录过的老缺陷，与 pselect/打偏无关。下一步应转去修它。

### 本批未提交改动
`src/core/kernel/constants.hpp`（`SKB_RECLAIM_SENDS` 8→32 + 注释）、
`src/core/support/util.cpp`（`SO_SNDBUF` 1 MiB→8 MiB、`step6 reclaim-sends` 面包屑移出循环）、本文件。
门禁：NDK 构建零告警；`cmp_disasm` 仅 `prepare_good_kernel_page` 2194→2116
（循环次数 + 内联调用移除，已复核），其余 7 个攻击函数 LAYOUT-SHIFT-only。

## 进度回填：2026-10-26 14:31（W3 重试 + 20 轮「零打偏」的记录被打破）

### 改动：`stages.w3_attempts` 1 → 3（只改 profile，不动 native）
3 次 W3 失败现场全部是 `seccomp finit_module probe = 0xfffffffd`，而
`src/core/session/victim_process.cpp:486` 把这个值定义为「探针被信号杀死」（SIGSYS）——
即两条 W3 route 都报了 `route_done status=0`，但 `rb_erase` 什么都没写，seccomp 仍然武装。
`w3_attempts` 的重试循环（`cve_2026_43499_backend.cpp:346-383`）本来就在每次尝试后重新
craft 页并复验，所以把它从 1 提到 3 就等于给这个静默失败加两次独立重抽；`w3_chain_rounds`
保持 1（那一层会 re-park 子进程，代价更大）。APK 602 已装。

### 5 轮实测（`build/ab-w3retry-a.csv`，APK 602）
| 轮 | 结果 | uptime |
| --- | --- | --- |
| 1 | TAP-NO-RUN | 70.15 s |
| 2 | DEVICE-DEAD | 69.39 s |
| 3–5 | HIT-ROOT | 75.23 / 69.70 / 69.41 s |

**这条记录很重要：`DEVICE-DEAD` 出现在 uptime 69.39 秒，正好落在「零打偏」那 20 轮的
66.6–70.1 秒区间里。** 所以「晚点火」不是因果，20 轮 0 次打偏只能算一次好运气（或当时设备
状态更好）。头两轮紧跟在 APK 安装之后，系统还在 dexopt/媒体扫描，这与「负载影响抢页」的
旧假设一致，但同样没有对照。

### 25 轮合并口径（recheck-d 10 + recheck-e 10 + w3retry-a 5）
| 结果 | 次数 | 比例 |
| --- | --- | --- |
| 完整成功（HIT-ROOT） | 20 | 80% |
| 死在 W3 seclamp clear | 3 | 12% |
| 打偏（DEVICE-DEAD） | 1 | 4% |
| 没点着（TAP-NO-RUN） | 1 | 4% |

这是目前最诚实的成功率口径：**约 80%**。W3 重试能否把那 12% 压下去，需要更多轮次才能证明
（3 次命中里一次都没触发重试，样本不足以说明问题）。
