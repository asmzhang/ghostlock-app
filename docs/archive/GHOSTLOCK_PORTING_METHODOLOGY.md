# GhostLock (CVE-2026-43499) 跨内核移植与稳定性调优方法论

> 适用范围：popsicle/GhostWrite 系 `rt_mutex` UAF → `rb_erase` 8 字节写原语，在 Android GKI 内核（3.18–6.12）上的移植与调优。
> 目标设备样本：Xiaomi marble / `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`（SM7475）。
> 本文档只记录**经过实测验证**的方法与结论，推导性内容明确标注。

---

## 一、移植的四个维度（缺一不可）

popsicle 类利用的可用性由四个独立参数共同决定。任何一项错位，结果只有三种：不触发、触发即崩、成功。**必须逐项确定，不能整体试错。**

| # | 维度 | 内容 | 确定方法 | 本设备实测值 |
|---|---|---|---|---|
| 1 | **waiter 结构布局** | `rt_mutex_waiter` 字段偏移与大小 | BTF 抽取（首选）或参考实现对照 | 5.10 compact：`tree_entry@0x00, pi_tree_entry@0x18, task@0x30, lock@0x38, prio@0x40, deadline@0x48`，size `0x50` |
| 2 | **栈帧 shift** | fd_set 拷贝相对内核栈上 waiter 槽的偏移 | **只能实测扫描**（反汇编可给初值，不可信） | `-2`（本设备唯一可触发值） |
| 3 | **符号/结构偏移** | `init_task`/`init_cred`/`selinux_enforcing` 等符号 + `task_struct`/`cred` 字段 | System.map（符号）、**BTF（结构，权威）** | `prio@0x84, pi_lock@0x86c, pi_waiters@0x880, pi_top_task@0x890, pi_blocked_on@0x898, cred@0x780, real_cred@0x778, seccomp@0x848` |
| 4 | **fd_set word 映射** | 每个 `word N` → waiter 字段的对应关系 | 反汇编 `core_sys_select` 帧布局 + 日志实测校验 | `word N → waiter + (N-2)*8`；`words_per_set = NFDS/64`（NFDS=320 → 5） |

### 1.1 维度 2（shift）的实测方法

```bash
# 对每个候选值：观察 pselect 是否正常返回 + fd 就绪数 ret
GHOSTLOCK_SHIFT=<v> GHOSTLOCK_W1_ATTEMPTS=1 ./ghostlock
```
判读规则（本设备实测校准）：

| 日志特征 | 含义 | 处置 |
|---|---|---|
| 无 `post-select`，设备重启 | **触发但内核路径崩溃** | 该值对齐正确但路径不安全 → 进入第三节 |
| `post-select ... ret=0` | UAF **未触发**（错位） | 换值 |
| `post-select ... ret>0` 且继续 | **触发且路径安全** | 候选值 |

**本设备扫描矩阵**（5.10.149 / marble，2026-09 实测）：

| shift | -4 | -3 | **-2** | -1 | 0 | +1 | +2 | +3 | +4 |
|---|---|---|---|---|---|---|---|---|---|
| 结果 | 崩 | 崩 | **触发（~8% 成功）** | 未触发 | 未触发 | 崩 | 崩 | 未触发 | 崩 |

> 注意：`fe155cf` 与 `53282cf` 两个提交对 stock 内核应有 `0` 还是 `-2` 结论相反（前者称 -2 是 KP-hook 产物，后者据反汇编称 -2）。**实测裁决：本设备只有 -2 能触发**，0 完全无效。→ **反汇编推导的 shift 不可直接采信，必须实测。**

### 1.2 维度 3 的 BTF 权威校验（跨版本复用）

```bash
cd gki510-arm64 && python dump_btf.py | grep -E "prio|pi_lock|pi_waiters|pi_top_task|pi_blocked_on|cred|seccomp"
```
本设备结果与 `src/kernels/<release>/offsets.h` 中 `STRUCT_OFFSETS_5_10` **逐项一致** → 证明 AI 新写的偏移表在 `task_struct` 部分是正确的，排除该维度嫌疑。

**推广到新内核**：优先从目标内核的 vmlinux BTF 抽 `rt_mutex_waiter` / `task_struct` / `cred` 三个结构；符号偏移用该内核 `System.map`（注意 pre-6.4 与 post-6.4 符号表格式差异）。

---

## 二、稳定性诊断流程（样本分类法）

**不要用"跑了多少次成功几次"这种笼统指标**。用三态分类，每一态指向不同的修复方向：

```
每次运行 → 分类
├─ HIT   : 日志含 "child is root!"          → 成功，记录全部参数
├─ PANIC : 无 "post-select" 且设备重启       → 触发但内核路径崩溃（需 oops）
└─ NOFIRE: 有 "post-select" 且 ret==0        → 参数错位，UAF 未触发
```

**本设备 38 次样本统计**（2026-09-09 ~ 09-10）：

| 分类 | 次数 | 占比 |
|---|---|---|
| HIT | 3 | 7.9% |
| PANIC | 31 | 81.6% |
| NOFIRE | 4 | 10.5% |

**关键相关性（实测）**：
1. **3 次 HIT 全部发生在 attempt 1**——后续 attempt 因堆被污染必崩。⇒ 单次运行的有效尝试只有 1 次，`W1_ATTEMPTS>1` 无收益；**提高命中率只能靠"更多独立运行"或"让第一次更稳"**。
2. **HIT 的 `ret > 0`**（实测 5/7），NOFIRE 恒为 `ret = 0`。⇒ `ret` 可作为运行中的实时状态判别器。
3. 运行时长：HIT 均为 ~9.0–9.3s 完成全链（spray ~1s + W1 pselect ~0.2s + W2 + verify）。

### 2.1 oops 获取的三条通道（按可靠性排序）

| 通道 | 做法 | 可靠性 |
|---|---|---|
| **pstore / ramoops** | root 态 `cat /sys/fs/pstore/* > /sdcard/...`——**跨越重启保留上次 panic 的完整 oops** | ★★★（唯一可追溯历史 panic） |
| **kmsg 常驻记录器** | root worker：`setsid cat /dev/kmsg >> /sdcard/ghostlock_kmsg.log` | ★★（仅覆盖记录器存活期间；随设备重启中断） |
| `dmesg` 快照 | root 态 `dmesg > /sdcard/...` | ★（仅当前 boot） |

**已排除的通道**：`/proc/last_kmsg`（不存在）、shell 直读 `dmesg`（Permission denied）、`logcat -b kernel`（logd 未收 kmsg，buffer 恒空）。

> ⚠️ 教训：**证据必须写 `/sdcard`**。`/data/local/tmp` 在重启后会被回滚刷成旧快照，曾导致命中轮的 `late-load` 日志整份丢失、误判失败原因。

---

## 三、写原语的语义（源码级确认）

以 `pi_tree_entry` 的 `rb_erase_cached` 为例（`tree_entry` 设为叶子仅用于先清空 `lock->waiters`）：

```
栈上 waiter（fd_set 直接给值，布局 A）：
  pi_tree_entry.pc    = value      ← word 2 / 5
  pi_tree_entry.right = 0          ← word 3 / 6
  pi_tree_entry.left  = target     ← word 4 / 7
```

`__rb_erase_augmented` 走 `!child`（right==0）分支：
```c
tmp->__rb_parent_color = pc;      // *(target) := value      ← 主写
parent = __rb_parent(pc);         // = value & ~3
__rb_change_child(node, tmp, parent, root);
                                  // *(value+8) := target    ← 副作用写
```
- **主写** `*(target) := value`
- **副作用写** `*(value+8) := target` → 这也是为什么 W2 的 `value` 必须选**内核里真实、常驻、且前 8 字节被破坏无副作用**的对象（本设备用 `init_cred`：其 `usage` 被打大反而无害）
- ⚠️ 曾误把 `util.c` 页内 `W0_OFF` 模板（布局 B：`pc=target-8, right=value, left=0`）当成 pselect 路径的机制——**实际 pselect 路径用的是 fops.c word 表直接写入的布局 A**，两者主写等价但副作用落点不同（`+8` vs `+0`）。

### 3.1 目标地址的选择规则（W1 的隐含条件）

`selinux_enforcing` 实为 `selinux_state.enforcing`（结构体 **+1** 偏移，非对齐）。写入页对齐地址时**低字节恰为 0** → `enforcing = 0` → permissive。
⇒ **W1 与 `leaf` / `pselect_child_node` 无关，value 只需保证低字节为 0**。移植到新内核时需确认目标符号是独立 `int` 还是结构体字段，否则值的选择条件不同。

---

## 四、工程踩坑清单（复用价值最高）

| # | 坑 | 症状 | 处置 |
|---|---|---|---|
| 1 | **adb.exe 不认 POSIX 路径** | `adb push /d/...` 报 `cannot stat`，脚本里被 `>/dev/null` 吞掉 → **静默失败** | 用 Windows 盘符路径 `D://...` 或相对路径 |
| 2 | **`/data/local/tmp` 重启回滚** | 新推的二进制被刷回旧快照；日志丢失 | 每次运行前 `push + md5sum 校验 + 重推`；证据写 `/sdcard` |
| 3 | oops 全通道被封 | pstore/last_kmsg/dmesg 普通权限均不可读 | 先拿 root，再走 pstore |
| 4 | `logcat -b kernel` 恒空 | logd 未接收 kmsg | 放弃该通道 |
| 5 | **手动 `apd soft-reboot` 时机错误** | 在 magica 链路未走完时执行 → **framework 卡死、adbd 不返回、需硬重启** | 越狱流程必须**全程用 Manager 的按钮**（越狱 → 软重启），不要手工代替 |
| 6 | 长时循环的 adb 命令无超时 | panic 后脚本挂死在一条 `adb shell` 上（设备已恢复但循环不动） | 所有 adb 调用加 `timeout`，循环内加设备存活探测 |

### 4.1 环境参数化（env 覆盖，便于跨设备/跨版本调试）

| 变量 | 作用 |
|---|---|
| `GHOSTLOCK_SHIFT` | 覆盖栈帧 shift（**跨版本移植的第一个旋钮**） |
| `GHOSTLOCK_CORE` / `GHOSTLOCK_CONSUMER_CORE` | 指定主/消费者线程 CPU（默认 0/1；大核对时序无改善，已实测） |
| `GHOSTLOCK_W1_ATTEMPTS` | W1 尝试次数（**实测：>1 无收益**，panic 会中断） |
| `GHOSTLOCK_W2_VAL` | W2 写值（默认 `init_cred`；`fake` 走喷射页副本，必崩——仅作 A/B） |
| `GHOSTLOCK_OWNER` / `GHOSTLOCK_NOWRITE` | 调试开关（⚠️ 这两项在 enqueue 场景下会被 `task_blocks_on_rt_mutex` 覆盖 `waiter->lock/task`，**对 pselect 路径无效**，勿据此下结论） |
| `GHOSTLOCK_KS_VERBOSE` | KernelSnitch 详细日志 |
| `GHOSTLOCK_DISABLE_MODULES` | root script 安全模式（禁用全部模块） |

---

## 五、命中率优化的已知事实与下一步

### 5.1 已排除的假设（实测）

| 假设 | 结论 |
|---|---|
| shift 漂移导致 panic | ❌ 扫描 9 个值：仅 -2 触发，且 -2 下仍有 ~8% 成功 |
| task_struct 偏移表（AI 新写）有误 | ❌ BTF 逐项一致 |
| 小核时序不稳导致崩溃 | ❌ `GHOSTLOCK_CORE=7/4`（大核）无改善，spray 快 3 倍但 W1 照崩 |
| fake_lock->owner 野指针是崩溃根因 | ❌ 改 `init_task` 仍崩（且该字段在 enqueue 路径被覆盖，实验本身无效） |
| word10 prio 打包错误（6.1 遗留） | ❌ 5.10 表已正确（`prio@0x40` 低 32 位） |

### 5.2 当前最强假设（**待 oops 验证**）

PANIC 发生在 `pselect` 阻塞期间、`futex_requeue` 处理我们伪造 waiter 的瞬间。同一参数下崩与不崩的差异来自**内核堆/时序状态**（spray 前的 slab 布局、futex 碰撞分布）。

其可能的分叉点（`marble-kernel/kernel/locking/rtmutex.c` 源码）：
- `try_to_take_rt_mutex` 成功 → waiter 不入队 → `pi_tree_entry` 保留我们的值 → **安全路径**（对应成功）
- `task_blocks_on_rt_mutex` 入队 → `rt_mutex_enqueue` 用 `rb_link_node` **重写 `tree_entry`**（pi_tree_entry 保留）→ 由 `remove_waiter` 的 owner 分支执行主写
- `RT_MUTEX_FULL_CHAINWALK` 触发 `rt_mutex_adjust_prio_chain` 沿真实链遍历 → **崩溃嫌疑点**

**收敛判据**：拿到 oops 中的 `pc` 与 `Call trace`，即可唯一确定分叉点。

### 5.3 下一步（按优先级）

1. **拿到 oops**：`pstore` 通道已写入 root script（`/sdcard/ghostlock_pstore.log`）——下次 HIT 即自动收集**跨越重启的历史 panic 日志**。
2. **按 oops 定位分叉点**并修复（预计方向：让 `is_top_waiter`/`owner` 状态可控，或在 enqueue 前让 `try_to_take` 稳定成功）。
3. **若 oops 不可得**：考虑把"提命中率"转为"提运行次数"——HIT 8% ⇒ 期望 12–13 次独立运行/次成功；配合"崩溃后自动等重启 → 重推 → 重跑"的循环（脚本已就绪，注意加 `timeout`）。
4. **跨版本扩展**：新内核按第一节四维度逐项确定（BTF → shift 扫描 → word 映射校验），用第二节三态分类评估，**不要用整体试错**。

---

## 六、退化定位法：`git diff <最后成功版本>`（零设备成本，优先级最高）

**教训来源**（2026-09-10）：调试中引入两处"我认为有理"的改动，命中率从 **20% → 0**（累计 85+ 轮无果）。设备实验每轮约 78 秒，成本极高——**而参数漂移用 git 一秒即可查出**。

**两处退化**（均由"分析正确但改动武断"造成）：

| 参数 | 成功版本 `50136e4` | 被改成的值 | 后果 |
|---|---|---|---|
| word 表布局 | **布局 A**（`pc=value, right=0, left=target`）| 布局 B（`pc=target-8`）| W2 从 ~20% → **0%（30+ 轮）** |
| `FAKE_WAITER_PRIO` | **140** | 130（"对齐 6.1 参考实现"）| 叠加退化 |

**定位命令（建议每次改动后立即执行）**：

```bash
git diff <last_known_good_commit> -- src/core/ | grep -E "^[+-]#define"   # 所有宏漂移
git diff <last_known_good_commit> --stat -- src/core/                     # 改动概览
git show <good> :src/core/common.h | grep -E "FAKE_WAITER_PRIO|PSELECT_ROUTE_NFDS"
git show <good> :src/core/target.h | grep -E "WAITER_WORD_SHIFT"
```

**三条铁律**：
1. **"分析正确 ≠ 改动正确"**：布局 B 的推理（副作用写砸 `init_cred.uid`）完全成立，但改布局会连带改变 `rb_erase` 的**分支路径**（`!tmp` vs `!child`），实测 W2 全败。**任何改动必须实测验证。**
2. **参考实现属于「另一个内核版本」**：`rmp-payloads-x` 是 6.1/6.12；`prio` 等参数的语义/影响随版本不同，**照搬即退化**。
3. **git 历史 > A/B 实验**：参数漂移用 `git diff` 秒查，快两个数量级。

## 七、布局 A / B 的取舍定理（5.10 实测结论）

`__rb_erase_augmented` 有两条单子分支，对应两种 waiter 布局：

| | 布局 A（`left=target, right=0`）| 布局 B（`left=0, right=value`）|
|---|---|---|
| 分支 | `!child` | `!tmp` |
| 主写 | `*(target) := value` | `*(target) := value`（**相同**）|
| **副作用写** | **`*(value+8) := target`** | **`*(value+0) := target-8`** |
| W1（value=我方页）| 无害 | 无害 |
| **W2（value=init_cred）** | **破坏 `cred.uid`（offset 8）** | 破坏 `cred.usage`（offset 0，无害）|
| **实测 W2 存活率** | **~20%** | **0%（30+ 次）** |

**结论（实测优先于推导）**：
- **只能使用布局 A**：副作用必然破坏 `init_cred.uid` ⇒ 命中后 `system_server` 崩溃（实测 `cmd: Can't find service: activity`）⇒ 设备重启、模块丢失。**这是布局 A 的固有代价。**
- 布局 B "理论更安全"但**实测 W2 完全无法存活**，静态分析无法解释（疑与分支路径对 `rebalance`／父指针状态的连带影响有关）。
- **可操作结论**：命中后"**不重启期间 root 可用**"；重启后需重跑（20% 命中率 ⇒ 期望 1–5 轮 ≈ 5 分钟）。

**待评估的根治路线**：① 命中后经 root script（uid 0）用 **kpatch supercall / KPM** 把 `init_cred.uid` 写回 0；② 额外一次 `W2c` 写 `*(init_cred+8):=0`（成功率降至 ~0.8%，**不可取**）；③ 解 BL 刷 APatch/Magisk 实现真持久。（`/data/adb/service.d` 类自启**需要 kpatch 已加载**，重启后失效，**无法自举**。）

## 八、命中率基线（实测，供跨版本对照）

| 配置 | 命中率 | 备注 |
|---|---|---|
| **布局 A + prio 140**（正确基线）| **1/5 = 20%**（2026-09-10 回退后实测）| 历史 6 次成功均为该配置 |
| 布局 A + prio 140（设备长期运行）| ~2.8%（6/212）| 设备状态劣化所致 |
| 布局 B + prio 130（退化）| **0%**（30+ 轮）| 已回退 |
| 单次 pselect 存活率 | ~18–25% | W1/W2 同源；全链 ≈ p² |

**设备状态劣化（实测）**：W1 存活率在设备长时间运行/反复 panic 后从 ~25% 降至 ~7%；**每 5 轮 `adb reboot` 可维持在 ~20-25%**（`REBOOT_EVERY=5` 已模式化到 `gl_tune.sh`）。
