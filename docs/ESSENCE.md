# 经验精华总纲（GhostLock / CVE-2026-43499 移植）

> **入口文档。动手前先读这一页**，它把散在 `docs/` 里的 25 份文档蒸馏成"能直接用的东西"，
> 并告诉你每份细节文档什么时候该翻。
> 最近更新：2026-09-15（marble root 恢复 + A35 封版 之后）。

> **关于本文提到的其它文档**：`VULN_SCOPE` / `PORTING_PLAYBOOK` / `ADAPT_NEW_KERNEL` / `PLAYBOOK` /
> `FIRMWARE_ACQUISITION` / `archive/GHOSTLOCK_PORTING_METHODOLOGY` 等**已归档**到旧工作树
> `<ARCHIVE>/docs/`；**其精华已全部并入本文**（§2/§6/§7/§8）。

---

## 0. 五条铁律（都是"没做到就会白干一天"级别）

1. **先读文档，再动手。** 2026-09-15 的 A35 调查中，`shift=-2`、**必须走 pselect**、核心对 `4/5`、
   **30 轮**、**独立 watcher** 这些都已写在 `DEVICE_MARBLE.md` / `GHOSTLOCK_SUCCESS_2026-09-11.md` 里，
   但因为没读，绕了整整一天。**动手前的第一件事：`docs/README.md` → 本文 → 本机型的 `DEVICE_*.md`。**
2. **先建观测通道，再上机。** 没有 `PC/LR/FAULT/STACK` 的上机等于瞎跑。
3. **每轮都要有"判据"**（一个可读的量化信号），否则就是碰运气。
4. **③ 不过就放弃 —— 这不是技巧问题，是编译器布局问题。**
   "可适配条件"里第 ③ 条（`stack_fds` 与 `rt_mutex_waiter` 栈偏移**重叠**）是**唯一真门槛**，
   由编译产物（PGO/LTO/BOLT）决定，**不由内核版本号决定**。同一版本号的不同厂商内核，一个行一个不行很正常。
   **③ 不过 ⇒ 换机型，不要在技巧上继续投入。**（2026-09-15 的 A35 正是从零重新发现了这条结论 ✗）
5. **命中后全程禁止 `exec` / `setuid` / `setgid`。** `exec` 会用被污染的 cred 重建进程 ⇒ 新镜像在第一条指令前就死；
   收尾只走软重启路线（`GHOSTLOCK_SUCCESS_2026-09-11.md` §③/§四）。

---

## 1. 一页速查（2026-09-15 状态）

| 项 | 值 |
|---|---|
| **能出 root 的提交** | `347dfec8fa6cd5c204a693565f7e9fd1482ee6ca`（2026-09-11 11:44:52 "root achieved"）|
| **二进制** | `artifacts/2026-09-15/ghostlock-347dfec-100880`，100880 B，md5 `36430a2fbb2c42c243acf9a8698d169e` |
| **可用参数** | `SHIFT=-2`、`CORE=4`、`CCORE=5`（`gl_tuned.env`，在工作区外层）|
| **入口脚本** | `tools/harness/run.sh`（TUNE 模式；`gl_tune.sh` 的后继）+ `tools/harness/watcher.sh` |
| **一轮 / 命中率** | 单轮 60–70s；**单轮命中 5–8%** ⇒ **必须 30 轮**（历史命中：28/7/1/1/22/1/14〔09-15〕/43〔09-16，第二批第 13 轮〕） |
| **命中判据** | `/proc/modules` 出现 `kernelpatch`（watcher）+ `su -c id` 显示 **gid 为垃圾值** |
| **收尾判据** | soft-reboot 后 `su -c id` = `gid=0` + `u:r:magisk:s0` |
| **当前分支** | **主仓 = `<REPO>`（2026-09-16 起以它为主）**：独立 clone，唯一分支 `my2`=`aec194e`（= aa37ddf 压平提交 + 主仓切换文档修订），独立构建指纹与归档成功件三方一致；旧仓 `root/ghostlock-app` = **冻结档案**（main 领先 origin/main 39 个未推送提交 + 32 项未提交改动，原地封存**勿用勿删**——历史文档引用它）；`my2` worktree 已注销退休（目录因句柄锁暂未物理删除，内有退休标记） |

**marble 一遍过（新设备从零）**：见 `MARBLE_RESTORE_2026-09-15.md` §2 的 8 步。

---

## 2. 方法论（跨设备通用，这一节是真正的"精华"）

1. **离线优先**：能靠反汇编/源码/装出来的事实，绝不上机换。工具：
   `tools/stack_depth.py`（栈几何/waiter 深度）、`find_bytecopy.py`（载体枚举，已含 `strncpy_from_user`）、
   `scan_handlers.py`（ioctl 前缀）、`copy_len.py`（拷贝目标与长度）、`kernel_verify`。
2. **观测优先**：先把"崩溃现场"变成可读数据。三星机型走
   `/data/log/dumpstate_lastkmsg_*_KP.log.gz`（**实为 ZIP**）→ `store_extra_info.lst` 里的
   `PC / LR / FAULT / ESR / STACK`。**`pstore` / `dmesg` / `kmsg` 在锁 BL 机型上全被拒。**
3. **A/B 对照**：怀疑回归时，用 `git worktree`（**相对路径**）取另一个版本构建，**同配置**跑，比 klog。
   - 判定纪律：**先确认"二进制真的推上去且 klog 非空"再读结论**，否则"设备存活"是假阳性（本会话踩过两次）。
4. **落点探针**（判定"载荷有没有写到目标位置"）：
   把内容**逐槽填成不同的未映射地址** → 跑一轮 → 读 `FAULT`：
   `0x0` = 没覆盖到；= 某个标记值 ⇒ 覆盖到了，**且标记的槽号直接给出绝对深度**。
5. **失败三分类**：`HIT`（`child is root!`/`self is root`）/ `PANIC`（写发生了但没写对）/ `SAFE-NO-FIRE`（没触发）。
   **调参看三类的分布变化**，不要只盯"中没中"。
6. **一轮一个变量**：改一处、跑一轮、读判据。**不要同轮改两个东西。**
7. **压平移植**（把已验证版本搬到干净上游）：
   `git worktree add <相对路径> <branch>` → `git cherry-pick -n <base>..<good>`（**不提交**）→
   `git diff <good>` **应为空**（证明"逐字节一致、没丢文件"）。

---

## 3. 硬数字（已验证，别再重测）

**marble（Redmi Note 12 Turbo / SM7475 / 5.10.149）**
- `mm_struct` SLUB stride = **0x3c0**（slabinfo 实测；BTF 报的 0x3e0 **不是 stride**）
- `pselect_waiter_shift = -2`（**"0" 是 raw 层、"-2" 是内部值，两层都对**）
- **必须走 pselect**：TCP zerocopy 被内核 `EINVAL` 拒绝（内核真实 `struct tcp_zerocopy_receive` 只有 **0x28** < 需要的 0x38）
- 核心对 **`4/5`**（中核簇 2.5GHz）；`0/1`（小核）实测 8 轮 0 命中
- **设备状态影响命中率 3.5 倍**：刚开机 ~25% → 经历大量 panic 后 ~7%
- 5.10 的 `rt_mutex_waiter` 是 **compact 布局**：`tree_entry@0 / pi_tree@0x18 / task@0x30 / lock@0x38 / prio@0x40`，
  **size 0x50，无 `wake_state`/`ww_ctx`**（6.1 才有）

**A35（SM-A356U / Exynos 1380 / 5.15.180）—— 已封版**
- **结论：栈载体走不通**。可达载体都覆盖不到悬垂 waiter 的 `lock`（`+0x38` / 深度 `0x2f0`）；
  唯一几何够得着的 `snd_ctl_ioctl`（0x268+0x110→0x378）被设备权限挡死
- 崩溃签名：`PC=_raw_spin_trylock+0x20` / `LR=rt_mutex_adjust_prio_chain+0x144` / `FAULT=0x0`
- 公开生态一致：**Exynos 不在任何支持列表**；`ghostlock-oneplus` 不可行表点名 **5.15.180 / 5.15.178**
- 完整证据与 14 条已排除项：`CARRIER_EXHAUSTION_2026-09-15.md`

---

## 4. 纪律与坑（按"代价"排序）

| # | 坑 | 正确做法 |
|---|---|---|
| 1 | **命中后不停 harness** | 立刻 `pkill -f tools/harness/run.sh`，否则下一轮 panic 打掉 root |
| 2 | **长跑任务用 `nohup &`** | 命令被中断会**连带杀死** ⇒ 必须用**工具的托管后台** |
| 3 | **`adb.exe` 传 POSIX 路径**（`/d/...`）| 只认**盘符路径** `D:/...`（否则静默失败/`cannot stat`）|
| 4 | `.ko`/`libksud.so` 位置 | 实际在 **`<REFS_DIR>/`（工作区上一层）**；harness 期望在 `<ARCHIVE_DIR>/` |
| 5 | **harness 中途的累计 `hit=` 不可信** | 要轮次结束才打印 ⇒ 以 **watcher 的 `/proc/modules`** 为准 |
| 6 | `git worktree add /d/...` | 会被拼成 `D:/d/...` ⇒ 用**相对路径** |
| 7 | HEAD / `347dfec` **不自足** | `src/core/root_template.h` 是**生成物** ⇒ 干净 checkout 里先拷它，否则 `expected expression` |
| 8 | 拿 `dev` 的调试输出当"源码事实" | dev 会说"我加了 X"，实际可能没成功 ⇒ **验证文件真实内容** |
| 9 | stdout 不可信（全缓冲，panic 时丢尾）| 关键信息 `write()+fsync()` 并**双写** |
| 10 | 本机 git 会**丢 ref** | 提交后**必须另起命令验证** `git log`；走 `git_commit_repair.sh` 的 SOP |

---

## 5. 文档（13 份 = 总纲 + 原始记录 + 方法与素材原文；历史档案见 §10）

| 文件 | 内容 | 何时读 |
|---|---|---|
| `ESSENCE.md` | ← **本文**：铁律/速查/方法论/硬数字/坑/流程 | **动手前第一份** |
| `DEVICE_MARBLE.md` | marble 全部实测数字的唯一来源（几何/路线/命中率杠杆/失败分类）| 调参前 |
| `GHOSTLOCK_SUCCESS_2026-09-11.md` | 5.10 成功报告 + 复现步骤 + 软重启收尾 + 已证伪结论 | 要复现成功时 |
| `MARBLE_RESTORE_2026-09-15.md` | 配置固化（提交/二进制指纹/参数/8 步/8 坑）| 重装/重拿 root 时 |
| `CARRIER_EXHAUSTION_2026-09-15.md` | **A35 封版**：为什么 5.15 走不通 + 14 条死因表 | 判断"某机型值不值得"时 |

> 另见本目录的 `VULN_SCOPE` / `PORTING_PLAYBOOK` / `ADAPT_NEW_KERNEL` / `PLAYBOOK` / `FIRMWARE_ACQUISITION` /
> `archive/GHOSTLOCK_PORTING_METHODOLOGY`（**方法与素材的完整原文**），以及 `AUDIT_HANDOVER_2026-09-15.md`（审计清单）。
> 真正的历史档案（vivo/A35 全过程、审计稿、`exp/` 实验脚本、raw dump）保留在旧工作树
> `<ARCHIVE>/docs/`；其精华已并入本文。

## 6. 适配一台新设备的顺序（浓缩版，细节见 §5 的手册）

### 6.0 先跑这 4 条命令（30 秒判定"值不值得投入"）

```bash
adb shell 'uname -r'                                     # ① 在受影响区间吗（2.6.39~7.0.x）
adb shell 'zcat /proc/config.gz | grep CONFIG_FUTEX_PI'  # ② 漏洞前提满足吗
adb shell 'ls /sys/kernel/btf/vmlinux'                   # 有 BTF 吗（决定提取难度；无 = BTF-less）
adb shell 'ls /dev/block/by-name/ | grep -E "boot|init_boot|vendor_boot"'   # 镜像从哪来
```
**①② 通过** ⇒ 进入偏移提取与栈布局验证（③④）；**③ 不过 ⇒ 放弃（见 §0 铁律 4）**。

> 提醒：**"已适配 ≠ 只有这些能用；未适配 ≠ 一定不能用"** —— 必须逐内核验证，别看版本号下结论。

### 6.1 素材来源（按省事程度，详见 `VULN_SCOPE.md` §四）

| 方案 | 做法 | 前提 |
|---|---|---|
| **A** 设备已 root | `su -c cat /proc/kallsyms` + `cat /proc/config.gz` | 需**已有**其他 root 途径（未 root 时 kptr_restrict 会把地址清零）|
| **B** 设备自带 BTF | `ls /sys/kernel/btf/vmlinux` ⇒ 直接读结构体布局 | 部分 GKI 带；**marble 实测没有**（BTF-less）|
| **C** OTA/工厂包 | `ghostlock-extract payload.bin`（支持 http OTA 地址）| 能拿到官方包 |
| **D** dd 分区 | `dd if=/dev/block/by-name/…` | 需 root；**Android 13+ 内核可能在 `init_boot`/`vendor_boot`，几个分区都要试** |
| **E** 源码重建 | `config.gz` + 对应源码本地编译 | 成本最高，最后手段 |
| 附加 | 部分机型需 `xbl_config.img` 推导内核物理加载地址（`--xbl-config` / `--phys`）| — |

### 6.2 全流程

```
① 读 VULN_SCOPE + PORTING_PLAYBOOK，判断这台机器值不值得投入
② 拿内核素材（FIRMWARE_ACQUISITION）→ kernel_verify 校验
③ 离线算几何：stack_depth.py（waiter 深度 / waiter word）→ 不在可行区间就**早点止损**
④ 判路线：这代内核走 pselect 还是 TCP（问内核，别靠编译期 sizeof）
⑤ 建观测通道（store_extra_info.lst）
⑥ 上机：30 轮 + 独立 watcher，看三分类分布
⑦ 命中 → 按 GHOSTLOCK_SUCCESS_2026-09-11.md 的 5–9 步收尾（soft-reboot → boot_completed → 终验）
```

---

## 7. 换设备移植的硬约束（从 vivo 2026-09-14 一轮提炼，血亏换来的）

### 7.0 第 0 步（**不做则后面全白干**）：素材必须与设备**同一构建**

`X.Y.Z-androidN-NN-g<提交>-ab<构建id>` 里，**`g<提交>` 与 `ab<构建id>` 都必须和设备一致**；
**只有上游版本号 `X.Y.Z` 相同不算对上**（厂商会自建分支点，如 vivo 的 `-00007`，公开 GKI 里**不存在**）。
源码包则看 `Makefile` 的 `SUBLEVEL` 是否等于设备版本的 `Z`。

```bash
adb shell uname -r ; adb shell getprop ro.build.display.id ; adb shell getprop ro.build.fingerprint
grep -ao "5\.15\.[0-9]*-android13-[0-9]*-[0-9]*-g[0-9a-f]*-ab[0-9]*" <每个 Image/boot.img>
```
> **症状判据**：**"路由跑完、不 panic、但什么都不写"** ⇒ **第一个怀疑对象就是"素材来自另一个构建"**。
> 更毒的是：拿错镜像的 BTF 去"验证"由同一错镜像派生的数值 = **循环论证 = 等于没验**。

### 7.1 内核地址布局（别凭记忆）

| VA_BITS | `PAGE_OFFSET`（线性基址，直接用）| `PAGE_END`（**不是基址**）|
|---|---|---|
| 39 | **0xffffff8000000000** | 0xffffffc000000000 |
| 40 | 0xffffff0000000000 | 0xffffff8000000000 |

`_PAGE_OFFSET(va) = -(1<<va)`、`_PAGE_END(va) = -(1<<(va-1))`、`KIMAGE_VADDR = MODULES_END = PAGE_END + 128MB`。
**vivo 一轮就是"把 `PAGE_END` 当基址"翻的车** ⇒ 扫描窗口整个落到直接映射之外 ✗
验证：窗口必须 **⊆ `[PAGE_OFFSET, PAGE_END)`**，且任何 slab 对象（`mm_struct`/`task_struct`）的线性别名都应落在窗口内。

### 7.2 futex 侧信道的两条硬约束

- **(a) 建堆与测量必须在同一个 mm**：key = `{current->mm, 页对齐地址, addr&0xfff}`。
  子进程建堆、父进程测量 ⇒ 测的是**另一个 mm 的桶（通常空桶）** ⇒ `t_target == t_base`、闭环恒假。
  **"数值恰好等于基线"要先怀疑 mm/进程不匹配**，而不是"对象消失了"。
- **(b) 判据必须同量纲**：空桶（快路径）/ 桩自身（遍历链头即 break）/ 同桶不同 key（遍历整链）是三种代价。
- **真值法（杀手锏，不需要知道 mm）**：扫**桩所在页的全部 1024 个 offset**（同页 ⇒ 同 mm 同 page），
  慢的那些就是真值同桶地址；拿到 **k=3 组**"桩↔同桶"对即可**唯一反解 mm**。
  ⇒ **正确窗口内应恰好 1 个解、错误窗口内 0 个**（工具：`tools/ks_probe.c` / `solve_pairs.c` / `agree_mm.c`）。

### 7.3 CVE 本体的"门槛"（卡住时先查这里）

```c
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;          // ← 漏洞本体（应为 waiter->task->pi_blocked_on）
if (!owner || !is_top_waiter) return;   // ← 写入路径的门槛，卡住时先查
rt_mutex_dequeue_pi(owner, waiter);     // ← 真正的 8 字节写发生在这之后
```
`is_top_waiter` 比的是 **真实锁的 `lock->waiters.rb_leftmost`**（内核在 enqueue 时按 prio 写）；
**我们在假锁里写 `rb_leftmost` 内核根本不读** ⇒ 这解释了"改 `W0_OFF` 零变化" ✓

### 7.4 读数可信度（永远区分"内核写的"与"我自己填的"）

- **读回值类测量必须先放哨兵**，否则分不清来源（`probe_tcp_route.c` 曾把"输入长度"当成"内核实测 sizeof" ✗）。
- **BTF 报的 `size` 常不是 slab stride** ⇒ 用 `/proc/slabinfo`（或 `/sys/kernel/slab/<c>/{object_size,objs_per_slab,order}`，
  **很多机型 shell 读不到**）。
- 无 root 时 `/proc/kallsyms` **读出 0 行**、`/sys/kernel/slab/*` 与 `/proc/slabinfo` **无权限**
  ⇒ **符号地址拿不到，必须靠外部二进制（第 0 步）**。
- **"证据很强" ≠ "已验证"**：给判断时必须显式标注**已验证 / 待验证**（vivo 一轮因此错了三次）。
- 用"全窗口搜索无解"当否证证据之前，**先验证窗口本身**。

### 7.5 本机环境坑

- **capstone 在系统 python 3.12.13**（managed 3.13.12 **没有**）⇒ 反汇编脚本要用系统 python。
- **adb 并发调用会互踩**（`could not read ok from ADB Server`）⇒ 多条 adb **串行**。
- 交叉编译独立探针：`ndk/28.2…/aarch64-linux-android35-clang -O2 -D__ARM=1 -DCORE=6 -Isrc/core -Isrc/core/kernelsnitch -Isrc/kernels -DTARGET_CONFIG_H='"target.h"'`。
- 提交走 `git_commit_repair.sh`，**它只 commit 不 add**（先 `git add -A`），跑完**另起命令验 `git log -1`**。

---

## 8. 适配一个新内核：正确顺序（工具优先）+ 检查清单

### 8.1 原则：**探索一次，固化一次 —— 绝不让同一件事手工做第二遍**

判据（"适配是否真的完成"）：**换个同代际的新变体，还需要人肉介入吗？** 不需要 ⇒ 才算闭环。

**正确顺序**（注意与"5.10 实际走的路"的差别）：

```
① 先用提取器判可行性（remove_waiter 补丁状态 + pselect/futex 栈是否重叠）  ← 全自动；不过就没必要继续
② 让提取器具备**完整推导能力**（含 BTF-less 路径）                        ← ★ 必须在调参之前
③ --register 自动生成偏移表                                              ← 零人工
④ 上机验证；不过再针对性排查                                            ← 人工只做这一步
```
> 5.10 之所以被迫手工试 `shift`（还试错了），根因就是"工具当时推不出来"。
> **把手工发现固化成工具能力，才是把成本变成资产。**

### 8.2 检查清单（哪些已自动 / 哪些必须人工）

| # | 做什么 | 判据 | 自动化 | 参考 |
|---|---|---|---|---|
| 0 | 判可行性：补丁状态 + 栈是否重叠 | `remove_waiter()` 仍用 `current`；`pselect/futex` delta 为非负 | ✅ | — |
| 1 | 提取偏移并 `--register` | 必需符号无解析失败 | ✅ | `e3e05de` |
| 2 | 加**诊断开关**（排在很前面） | 能看到每轮内部状态 | ⚠️ 一次，之后复用 | `8d374f3` |
| 3 | 校验结构体大小 / stride | **用 `slabinfo` 等设备事实验证** | ✅ `check_stride.sh` | `20cc8fd` |
| 4 | 定 reclaim 路线 | **直接探测**（`probe_tcp_route`） | ✅ | `6ded65a` |
| 5 | 调堆喷射 / waiter 字布局 | 稳定命中而非偶发 | ❌ **必须人工** | `50136e4` |
| 6 | 定 shift 等关键参数 | **在 stock 状态下测** | ✅（BTF / BTF-less 两条路）| `fe155cf`/`53282cf` |
| 7 | 固化回提取器（闭环） | 同代际新变体一键推导 | — 原则 | `53282cf` |

⇒ **目前唯一真正必须人工的是 ⑤**（提高命中率只能靠实测定量统计）。

### 8.3 三条会误判的细节

1. **只探测、别读源码**：路线判定用 `getsockopt(TCP_ZEROCOPY_RECEIVE)` 读**内核对 `optlen` 的回写值**
   （内核有 `if (len > sizeof(zc)) len = sizeof(zc); put_user(len, optlen);` ⇒ 回写值就是内核真实 `sizeof`）。
   **头文件 0x40 ≠ 内核 0x28**（marble 实测）⇒ **靠编译期 `sizeof` 判断走不通**。
   判据是**回写值**，不是"看哪些字节被回写"（后者在 `find_vma` 校验失败提前返回时是空的 ✗）。
2. **`stride` 是运行时属性**，镜像里不存在 ⇒ 提取器给不了 ⇒ 用 `slabinfo`（5.10 BTF 报 0x3e0，**实际 0x3c0**）。
   `check_stride.sh` 必须**按 `uname -r` 选对应的 `STRUCT_OFFSETS_*` 块**，否则会取到别的代际而误报 ✓
3. **参数必须在"目标内核的原始状态"下测** —— 5.10 的 `shift` 曾测出 `-2` 是**假象**（那是在带 KPM 的内核上测的，
   KernelPatch 改了栈布局）；stock 上是 `0`。（实测裁决：**只有 `-2` 能触发、`0` 完全无效** ⇒ **反汇编推导的 shift 不可直接采信，必须实测**）（本项目内部值 = raw − 2 ⇒ `-2` 与 `0` **两者都对，层次不同**。）

### 8.4 路线对照（决定"有没有备选"）

| 内核 | 可用路线 |
|---|---|
| **5.10** | **只有 pselect**（TCP 被 `EINVAL` 拒） ⇒ **pselect 不重叠就彻底没戏** |
| 6.1 | TCP（默认）/ pselect（`GHOSTLOCK_TCP_ROUTE=0`）|
| 6.6 / 6.12 | pselect |

### 8.5 命中率两个杠杆 + 验收

- **杠杆一 · CPU 亲和**：取**成员数 ≥ 2 的最高频簇**的前两个核（marble = `4/5`；`0/1` 实测 8 轮 0 命中）。
  **注意最高频核常是单核簇**（marble 的 `cpu7`）⇒ 只按"最高频"取会得到跨簇组合 ✗
  ⚠️ 诚实标注：`4/5` vs `0/1` **尚未达统计显著**（p=10% 时 8 轮全不中概率 ~43%）。
- **杠杆二 · 设备状态**：**刚开机的存活率是跑一阵后的 3.5 倍**（~25% vs ~7%）⇒ 代价 45s 重启，值得。
- **验收三条**：`su -c id` → `gid=0` + `u:r:magisk:s0` ✓；`/proc/modules` → `kernelpatch … Live` ✓；
  管理器进程有 **UID=0 的子进程** ✓

---

## 9. 蒸馏补遗（从早期档案里抽出的、别处没写的干货）

### 9.1 观测通道分三级（**有 root 时，pstore 最好**）
| 通道 | 做法 | 强度 |
|---|---|---|
| **pstore / ramoops** | root 态 `cat /sys/fs/pstore/* > /sdcard/…` —— **跨重启保留上次 panic 的完整 oops** | ★★★ |
| kmsg 常驻记录器 | root worker：`setsid cat /dev/kmsg >> /sdcard/ghostlock_kmsg.log` | ★★（仅覆盖记录器存活期）|
| dmesg 快照 | root 态 `dmesg > /sdcard/…` | ★（仅当前 boot）|
| 三星锁 BL 机型 | `/data/log/dumpstate_lastkmsg_*_KP.log.gz`（**实为 ZIP**）→ `store_extra_info.lst` | ★★★（本文 §2.2）|

> ⚠️ **证据必须写到 `/sdcard`**：`/data/local/tmp` 在重启后会**回滚成旧快照** —— 曾导致命中轮的 late-load 日志整段丢失。
> （因此本文 §1 的"脚本放 `/data/local/tmp`"仅适用于**运行期**；**日志/证据要另写 `/sdcard`**。）

### 9.2 判据必须"端到端可观测"
**真正的判据是 `verify_selinux_stage` 读 `/sys/fs/selinux/enforce` → 0**；
`route_last_step==0` 只能说明"消费者被调用了"，**不能当作"写成功"** ✗

### 9.3 "错误的窗口会产生一致的结果"
在**错误的地址窗口**里做两次独立复算，会**互相印证出同一个错误结论**（"命中集是噪声"）。
⇒ **用"全窗口无解"当否证证据前，先验证窗口本身**（§7.4）。

### 9.4 可用性 = 四个独立参数共同决定
任何一项错位，结果只有三种：**不触发 / 触发即崩 / 成功** ⇒ 所以**必须用三分类看趋势**（§2.5），
**不要用"跑了 N 次成功几次"这种笼统指标**。

### 9.5 代际差异的两个具体数
- `struct tcp_zerocopy_receive` 真实大小：**5.10 = 0x28**（⇒ 连 `0x28/0x30` 都拷不进来 ⇒ TCP 路线死 ✗）、
  **三星 5.15 = 0x40**（`msg_control@0x28` / `msg_controllen@0x30` ⇒ TCP 路线前提成立 ✓）
- `if (zc.reserved) return -EINVAL;` ⇒ **偏移 `0x3c` 必须为 0** ✓

### 9.6 W2 的 `value` 怎么选（有副作用！）
写原语带副作用 `*(value+8) := target` ⇒ **`value` 必须是"内核里真实、常驻、且前 8 字节被破坏无害"的对象**
（这就是 W2 选 `init_cred` 的原因：`.data` 常驻、+8 是 gid 字段、被改坏无害 ✓）。

### 9.7 手动 `apd soft-reboot` 的时机
**必须在 magica 链路走完之后**执行；时机错误 ⇒ framework 卡死、`adbd` 不返回 ⇒ **只能硬重启** ✓

### 9.8 素材获取（补充 §6.1）
- **GKI 设备首选 Google 官方 CDN**：~21MB、符号 **exact** ✓（坑：boot.img 是 **header v4**）
- 厂商开源站：**通常只有源码、没有 `System.map`/`vmlinux`** ⇒ **拿不到符号地址** ✗
- 第三方固件站多有**诱饵特征**（要账号/付费/免责绕圈）⇒ **别在上面花时间**
- 三星的版本串里 **`32001549` 就是构建号**（不是上游的 `5.15.180`）✓
- 三星上 `STRUCT_OFFSETS_5_15` 可**直接沿用**（waiter/lock/task 常量一致 ✓，反汇编确认 `str xzr, [x20, #2224] ; current->pi_blocked_on = NULL` ✓）

### 9.9 工具细节
`tools/agree_mm.c` 必须用 **`-w` 指定窗口**，否则会重现"错窗口"的老坑；
`extract_collisions.py` 解析 `run_v*.log` 时注意 `probe collision <addr> t=` 会被 `collision … t=` 正则**前缀吞并**。

---

## 10. 旧工作树（`<ARCHIVE>`）再蒸馏

### 10.1 经验（本轮新抽出）

1. **审计纪律：每条结论都要给出"可复算的来源"**（源码行 / 反汇编 / 设备实测）。
2. **`shift` 的实测裁决**：只有 `-2` 能触发、`0` 完全无效 ⇒ **反汇编推导的 shift 不可直接采信，必须实测**（见 §8.3）。
3. **布局 A vs B 的副作用落点不同**：⚠️ 曾把 `util.c` 的 `W0_OFF` 模板（布局 B：`pc=target-8, right=value, left=0`）误当成 pselect 路径的机制 —— 实际 pselect 用的是 `fops.c` word 表写入的**布局 A**；两者**主写等价，副作用分别落在 `+8` 与 `+0`** ⇒ **必须显式评估**（不是"没写进去"，是"写多了"）。
4. **`orig_waiter != NULL` 那条入口在本场景不可用**（硬结论）：它要求 `task_has_pi_waiters(task)` 为真，而本场景 B 的 `pi_waiters` 是**空的** ⇒ `task_blocks_on_rt_mutex` 走不通；只能走 **`remove_waiter`** 路径，且需 **`owner(L) == B`** 且 **`is_top_waiter`**。
5. **"栈距离"不是可移植的标定结果** ⇒ 换机必须按目标内核重新推导（A35 封版正是实例）。
6. **手动 `apd soft-reboot` 的正解**：越狱流程**全程用 Manager 的按钮**（越狱 → 软重启），不要手工代替 ✓
7. **`/sdcard` 与 `/data/local/tmp` 分工**：脚本可放 `tmp`，**证据/日志必须写 `/sdcard`**（§9.1）。

### 10.2 脚本（三套，别混淆）

| 集合 | 位置 | 状态 |
|---|---|---|
| **当前有效** | `tools/harness/`（`run.sh` TUNE / `watcher.sh` 独立轮询 / `env.sh` / `check_stride.sh` / `probe_tcp_route.sh` / `preflight.sh` / `stats.sh`）| ✅ 用这套 |
| **历史实验** | 旧工作树 `root/exp/`（数十个 `gl_*.sh`：tune/retry/oops_trap/cal/scan）| 📦 归档，查"试过什么"时翻 |
| **已消失** | 根目录 `gl_tune.sh` / `_watcher.sh`（**未纳入 git**）| ❌ 已被 harness 取代 |

### 10.3 代码演进（`347dfec` → 旧 HEAD：改了什么、为什么）

| 时段 | 改动 | 意图 |
|---|---|---|
| 09-11 12:09+ | 拆 `klog`/`kmod`/`rootscript` 出 `main.c`（−461 行）| 可维护性（**纯重构**）|
| 09-11 16:29–18:35 | vivo 5.15：`PAGE_OFFSET` 参数化、泄漏移到子进程、TCP zc 规则化 | 适配新内核族（**未打通**）|
| 09-14 | A35：`samsung_extract`/`btf_dump`/`kernel_verify` | 适配三星（**已封版**）|
| 全程 | `util.c` 伪造 cred 加固；`main.c` root script 8192 + 多 KSU 管理器 | 对**所有设备**都是修复/增强 ✓ |

### 10.4 流程（三条）

1. **TUNE（探索）**：`ROUNDS=30 REBOOT_EVERY=0 bash tools/harness/run.sh` + **另起** `watcher.sh`；命中即停、参数锁进 `gl_tuned.env`；看三分类分布，不看"成功几次"。
2. **USE（复现）**：读 `gl_tuned.env`（`SHIFT=-2 CORE=4 CCORE=5`）直接跑。
3. **收尾 8 步**：停 harness → 关 `panic_on_oops/rcu_stall` → 管理器重启 → `apd soft-reboot` → 验内核未重启 → `apd resetprop sys.boot_completed 1` → 写 `package_config` + 起 `uid-listener` → 终验 `gid=0` + magisk 域。
