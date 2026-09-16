# A35 载体调查结论 — 2026-09-15 封版

> 目标：Samsung Galaxy A35 5G（SM-A356U / **Exynos 1380 / s5e8835**，内核 `5.15.180-android13-3-32001549`，
> 构建 `A356USQS6CYJ2`），CVE-2026-43499（GhostLock）用户态提权。
> 本文是**封版记录**：结论、证据、已排除项、仍未知项、以及换机型时的复用资产。

## 0. 结论（一句话）

**在 A35 上，GhostLock 现有的"栈载体"设计走不通**：所有**可达**（纯 syscall、无受限设备节点）
的载体都无法覆盖悬垂 `rt_mutex_waiter` 的 `lock` 字段（`+0x38`，深度 `0x2f0`），
而该字段为 NULL 时内核在 `rt_mutex_adjust_prio_chain` 的 `[5]` 步**当场踩空崩溃**。
唯一几何上够得着的载体（`snd_ctl_ioctl`）被设备权限挡死。
此结论与公开生态一致：**Root My Galaxy 明确不支持 Exynos，`ghostlock-oneplus` 的
"不可行"表里点名了 5.15.180 / 5.15.178。**

## 1. 最终进度（8 关过了 4 关）

| # | 关卡 | 状态 | 依据 |
|---|---|---|---|
| 1 | 触发 UAF（单据悬垂） | ✅ | 每轮 `R5 trigger` 成功、走查被启动（C1 出现） |
| 2 | 载体**可达**（无设备节点依赖） | ✅ | `setxattr` / `sendmsg` 均为普通 syscall |
| 3 | 载体**确实执行拷贝** | ✅ | `errno=95`(EOPNOTSUPP) / `errno=105`(ENOBUFS) / `errno=22`(EINVAL) —— 都发生在 `copy_from_user` **之后** |
| 4 | 几何基准成立（`w>0`） | ✅ | `find_bytecopy` + `stack_depth.py`（后者经 futex 链自校验 `0x2b8`） |
| 5 | **字节真的落在目标字段上** | ❌ | 逐槽标记实测 `FAULT=0x0` ⇒ `sendmsg` 载体**没落在 waiter 上**；`setxattr` 最深只到 `+0x2F`，**结构上够不到 `+0x38`** |
| 6 | 走查走到写点 `[7]` | ❌ | 每次都死在 `[5]`（`lock==NULL`） |
| 7 | 写落地 | ❌ | 从未到达 |
| 8 | W1/W2 → root | ❌ | 未开始 |

## 2. 已证实的硬事实（都可复现）

1. **崩溃点**（`/data/log/dumpstate_lastkmsg_*_KP.log.gz` → `store_extra_info.lst`）：
   `PC=_raw_spin_trylock+0x20/0xc0`，`LR=rt_mutex_adjust_prio_chain+0x144/0x9c4`，
   `FAULT=0x0`，`ESR=DABT (0x96000005)`，`STACK=…sched_setattr→rt_mutex_adjust_pi→rt_mutex_adjust_prio_chain`。
   ⇒ 崩在 `[5]`：`raw_spin_trylock(&lock->wait_lock)` 而 **`lock = waiter->lock == NULL`**。
2. **源码级结论**（A35 官方源码，`_ghostlock_refs/samsung_a35/kernel-src/`）：
   - `rt_mutex_adjust_pi()` 传 `orig_lock=NULL, orig_waiter=NULL, top_task=task`
     ⇒ 审计 §1.4 的 #3/#4/#6 全部无害（**"必须实现 f_pi_aux" 的结论是错的**）；
   - `rb_erase_cached()` **无 `RB_CLEAR_NODE`** ⇒ `pc = target−8` 的节点形状有效；
   - `__rb_erase_augmented` Case 1 ⇒ `*(parent+8) = child` ⇒ **写原语形状正确**；
   - **`rt_mutex_top_waiter()` 含 `BUG_ON(w->lock != lock)`** ⇒ 这解释了 ptrace 载体（把
     `lock` 写成自己 page 的假锁）**为什么每轮必崩**；
   - `strncpy_from_user` **先于** xattr 名字校验 ⇒ 非法名字也能完成 stack stamp（实测证实）。
3. **SoC 确认**：`Exynos Reboot: SOC ID E8835000` / `EPBL: 5.15-PT72590-s5e8835` ⇒ **Exynos 1380**。

## 3. 已排除的设计/载体（含死因，勿重试）

| 项 | 死因 |
|---|---|
| ptrace GPR（NT_PRSTATUS）regset | `d0=0x318` 比 waiter（0x2b8）**更深** ⇒ `w` 必为负；且写 `lock=fake_lock` 必触发 `BUG_ON` |
| ptrace FPR（NT_PRFPREG）regset | `fpr_set` 帧仅 0x30，目标是 **tracee 的 thread_struct**，**根本不落栈** |
| pselect6 / core_sys_select | 输入可控区间 = `[depth, depth+3×FDS_BYTES(n))`，栈路径 `FDS_BYTES ≤ 0x28` ⇒ 最深 `0x288` < `0x2b8` |
| TCP_ZEROCOPY_RECEIVE | `0x1c0 + 0x40 = 0x200` |
| sendmsg / sendmmsg | 落点 `0x2c0` **更深 8 字节**（`w<0`）；且实测（逐槽标记）**根本没落在 waiter 上** |
| recvmmsg / ___sys_recvmsg | `0x270 + 0x38 = 0x2a8`，差 `0x10` |
| 其余可达 syscall（clone3/clock_adjtime/sock_set_timeout/bpf_fprog/quota/ip_msfilter…） | 拷贝 0x8~0x58，最深触达 `0x2a8` |
| bpf_prog_get_info_by_fd | 需特权 |
| v4l2_compat_get_array_args | 仅 32 位 compat 路径 |
| **snd_ctl_ioctl**（0x268+0x110 → 0x378，**几何唯一够得着**） | **设备权限**：`/dev/snd/controlC0` 为 `system:audio` + SELinux `audio_device`，shell 被拒 |
| dm_ctl_ioctl（d0=0x2b8 精确） | `/dev/mapper/control` **节点根本不存在** |
| usbdev_ioctl / binder | 设备权限（EACCES） |
| filler / "把 f_pi_target 的树填非空" | **填树动作本身**（第 4 线程 `FUTEX_LOCK_PI`）就会触发同一条崩 |
| δ ∈ {−2,−1,0,+1,+2} 微调落点 | 全部同症状崩溃 |

## 4. 仍未知的（诚实清单）

1. **悬垂 waiter 的绝对深度**（我们假设 0x2b8；`sendmsg` 实测落空说明这个假设或它的用途有问题）；
2. `setxattr` 的 `kname` 落点（假设 0x1e8）**从未被实测**；
3. 唯一够得着的载体被权限挡住之后，是否还存在**其他**可达的深拷贝点（未穷举完）。

## 5. 为什么停止

- 瓶颈性质：**不是"缺技术"，而是"缺一个能覆盖 `+0x38` 的可达载体"**——公开生态对这类机型的答案是"不支持"；
- 边际收益：本会话 12 轮上机，每轮一次 panic；除观测闭环建立后，**其余轮次都在同一处崩溃**；
- 投入产出比：三星在这台机器上三重不利（Exynos 不在任何支持列表 + RKP/KNOX + `/dev` 权限收紧）。

## 6. 可复用资产（换机型直接用）

| 资产 | 位置 | 用途 |
|---|---|---|
| 栈几何/深度计算 | `tools/stack_depth.py` | 算任意机型的 `waiter word`（自校验：futex 链 = 0x2b8） |
| 载体枚举 | `tools/find_bytecopy.py`（已扩表：含 `strncpy_from_user` 等） / `tools/scan_handlers.py` | 离线筛"落点覆盖 waiter"的可达拷贝点 |
| 拷贝长度读取 | `tools/copy_len.py` | 读某拷贝点的目标与长度 |
| **观测闭环** | `/data/log/dumpstate_lastkmsg_*_KP.log.gz`（**其实是 ZIP**）→ `store_extra_info.lst` | 拿 `PC/LR/FAULT/ESR/STACK/逐CPU寄存器`（三星机专用；`pstore`/`dmesg`/`kmsg` 全被拒） |
| **落点探针** | 逐槽填不同未映射标记 → 读 `FAULT` | 一轮实测"载体覆盖到目标字段了吗"，并读出绝对深度 |
| 反向工程产物 | `_ghostlock_refs/samsung_a35/`（`kernel.verified.elf`/`syms.txt`/`kernel-src/`/固件 8.17GB） | 离线分析素材齐全 |

**换机型流程（离线，不碰设备）**：
1. 取候选机型内核镜像 → `kernel_verified.elf` + `syms.txt`（`vmlinux-to-elf`）；
2. 检查 `do_futex` 是否被 PGO 内联（内联 ⇒ 直接判不可行）；
3. `stack_depth.py` 算 `waiter word` ⇒ **range [0,7] 才值得动手**；
4. 通过后再上机。

## 8. 代码改动 × 已支持设备的兼容性（2026-09-15 审阅）

`README_ZH.md` 的"支持的设备"表：**25+ 行，全部是 6.1.x / 6.6.x**（Xiaomi / vivo / OPPO /
Honor / Motorola / RedMagic / Nothing / Infinix …），**无 Exynos、无 5.15** —— 与本文结论一致。

### 8.1 本次改动逐项对照

| 改动 | 触及公共路径 | 对已支持设备 |
|---|---|---|
| 新路由 `do_setxattr_fake_lock_route()` + `fill_tree_thread()` | ❌ 仅 `GHOSTLOCK_ROUTE=setxattr` 可达 | 无 |
| `GHOSTLOCK_LOCK_EMPTY`（假锁=空树+owner=0） | ❌ env 门控，**默认关** ⇒ 假锁内容与原来逐字节一致 | 无 |
| `GHOSTLOCK_PTRACE_TASK` / `..._TASK_ADDR` | ❌ env 门控，默认 = 原 `fake_task` | 无 |
| `GHOSTLOCK_SETX_TARGET/VALUE/DELTA/B/FILL/MARK` | ❌ 新增，默认不存在 | 无 |
| `GHOSTLOCK_W1_SOFTFAIL` | ❌ env 门控，默认仍 `return 1` | 无 |
| **泄漏判定：`ks->state ∈ {MM_FOUND,MM_NOT_FOUND}` → `ks->mm_struct != (size_t)-1`** | ✅ **公共路径** | **修 bug**：原判断恒为假（`clone_leak_child` 会把 state 重置回 `COLLISIONS_FOUND`）⇒ 每轮无条件中止；改后严格放宽 |
| **leak 子进程 watchdog 60s → 900s（可由 `GHOSTLOCK_LEAK_TIMEOUT_MS` 覆盖）** | ✅ **公共路径** | 仅放宽；副作用=投票真卡死时多等 |
| U1/U7/U8 日志行 / U1 打印改用实际 task 指针 | ✅ 仅日志 | 无（不改变逻辑） |
| **`target.h`、`src/kernels/*/offsets.h`（设备几何与 per-kernel 偏移）** | — | **未改动（零字节）** |

### 8.2 残留风险（诚实清单）

1. 工作树中另有**早期会话**的未提交改动：`src/core/offset.h`(+27)、`src/core/klog.c`(+44)、
   `src/core/kernelsnitch/kernelsnitch.h`(+11)，均在公共路径上（几何→环境变量、klog 时间戳、
   cleanup 守卫）。按注释设计为"默认行为不变"，但**未逐行审阅**。
2. 最硬的确认手段：**用一台已支持机型（手边有 marble 5.10，已 root）跑默认路由冒烟测试**，
   对比行为是否与改动前一致。



## 9. 若要恢复此线：唯一还没排除的方向

**换写原语 / 换触发路径**（而不是继续找载体）：
- 例如避开 `[5]` 需要的 `waiter->lock` 字段的那条路径（回源码重新推）；
- 或"两段**不同深度**的拷贝串联覆盖 `+0x38`"（需要两个落点相加恰好覆盖 `0x2f0`）。
两者都需要重新做一轮源码级设计，**期望值低**，但这是本机唯一剩下确有依据的方向。
