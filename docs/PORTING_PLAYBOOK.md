# 换新设备移植手册（含 2026-09-14 vivo 一轮的全部教训）

> 目标场景：拿到一台**新机器/新固件**，要跑 GhostLock 类（CVE-2026-43499）的内核漏洞利用。
> 本文按**执行顺序**排列，每一节都标了"为什么"和"怎么验"，都是从踩过的坑里提炼的。
> 血泪结论先说：**下面第 0 步不做，后面全白干。**

---

## 第 0 步（最重要）：核实"素材"与"设备"是不是**同一个构建**

### 为什么
2026-09-14 这一轮，在 vivo V27 上花了**大半天**，最后发现：
**手上所有用于推导偏移的素材，都来自另一个内核构建。**

| 素材 | 实际构建 | 设备构建 |
|---|---|---|
| 内核镜像 `Image` / `boot.img` | `5.15.178-android13-8-**00005**-g14ee4828e57f-ab13224150` | `5.15.178-android13-8-**00007**-g362d545d31a5-ab14608873` |
| 源码包 | **5.15.74** | 5.15.178 |
| OTA 残留 | `PD2269F_EX_A_**13**.0.9.56.W30` | `PD2269GF_EX_A_**15**.2.26.1.W20` |

后果：`offsets.h` 里所有**每构建数值**（`off_init_cred`、`off_selinux_enforcing`、页几何…）
都是另一个构建的。**"路由跑完、不 panic、不写入" 这种症状，第一个怀疑对象就应该是它。**
更糟的是：我拿那份错镜像里的 BTF 去"验证"由同一份错镜像派生的数值 —— **循环论证，等于没验**，
而线索（文件头一行的构建号 `-00005`）一直摆在眼前。

### 怎么做
```bash
# 1) 设备侧（都无需 root）
adb shell uname -r                      # 例：5.15.178-android13-8-00007-g362d545d31a5-ab14608873
adb shell getprop ro.build.display.id   # 例：PD2269GF_EX_A_15.2.26.1.W20
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.incremental

# 2) 每个素材文件，找出它内置的构建号，逐个比对
grep -ao "5\.15\.[0-9]*-android13-[0-9]*-[0-9]*-g[0-9a-f]*-ab[0-9]*" <每个 Image/boot.img>
head -6 <源码包>/Makefile               # VERSION/PATCHLEVEL/SUBLEVEL

# 3) 源码包里也搜一遍设备提交 hash（有就说明对上了）
grep -rl "<设备提交hash前12位>" <源码树>
```

### 判据
- `X.Y.Z-androidN-NN-g<提交>-ab<构建id>` 里：
  **`g<提交>` 和 `ab<构建id>` 必须与设备一致**；只有上游版本号（`X.Y.Z`）相同**不算对上**。
- 源码包：`Makefile` 的 `SUBLEVEL` 必须等于设备的 `X.Y.Z` 里的 `Z`。

### 素材来源（按性价比）
| 途径 | 成本 | 说明 |
|---|---|---|
| **公开 GKI CDN** | 免费、~21MB | **首选**。`https://dl.google.com/android/gki/gki-certified-boot-android13-5.15-<分支>_r<N>.zip`，分支按 `uname -r` 里的 `androidN-NN` + 月份推断。**但要逐个下载读它内置的 `-g` 号确认**——厂商自建分支点（如 vivo 的 `-00007`）在公开发布里**不存在**，此时无效 |
| 厂商开源站 | 免费 | 通常只有**源码**，没有 `System.map`/`vmlinux` → **拿不到符号地址** |
| 厂商官方 OTA | 免费 | 大小 ~5GB 的 `-update-full_<ts>.zip`，内含完整 `boot.img`。**注意可能只覆盖旧版本**（vivo 那份 id 空间只有 A12/A13） |
| 第三方固件站 | 多为**付费** | 有全量 ROM（含 boot.img），但需要账号/付款 |
| **设备 BROM dump** | 免费、需按键 | 最准（就是这台机器本人）。MTK 用 `mtkclient`；**可能被 secure boot/SLA 挡掉** |

---

## 第 1 步：确认漏洞面还在不在

```bash
adb shell 'zcat /proc/config.gz | grep -E "FUTEX|ARM64_VA_BITS|VMAP_STACK|RANDOMIZE"'   # 可读
```
- 用设备镜像反汇编确认 **`remove_waiter()` 仍用 `current`**（这是 CVE 的本体）。
  代码在 `kernel/locking/rtmutex.c`，`grep -n "static void __sched remove_waiter" -A 30`。
  关键片段（5.15.178 实测）：
  ```c
  bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
  ...
  rt_mutex_dequeue(lock, waiter);
  current->pi_blocked_on = NULL;          // ← 漏洞本体（应为 waiter->task->pi_blocked_on）
  if (!owner || !is_top_waiter) return;   // ← 写入路径的门槛，卡住时先查这里
  rt_mutex_dequeue_pi(owner, waiter);     // ← 真正的 8 字节写发生在这之后
  ```

## 第 2 步：**先读内核源码，再动反汇编和暴力搜索**

这一轮前半程用"反汇编反推 + 暴力枚举"推公式，方向对但**代价高两个数量级**。
内核源码树通常就在固件包里（`android_NN.0_kernel_<机型>.tar.gz`），一个 grep 就能拿到：
`arch/arm64/include/asm/memory.h`（地址布局）、`kernel/futex*/`（哈希与 key）、
`kernel/locking/rtmutex*.c`（写入语义）、`include/uapi/linux/tcp.h`。

**同时要挑对版本**：源码包里 `Makefile` 的 SUBLEVEL 必须与设备一致（见第 0 步）。

## 第 3 步：确定并**验证**内核地址布局

定义（`arch/arm64/include/asm/memory.h`，**别凭记忆**）：
```c
#define _PAGE_OFFSET(va)  (-(UL(1) << (va)))        // 线性映射【起点】
#define _PAGE_END(va)     (-(UL(1) << ((va) - 1)))  // 线性映射【上界】
#define KIMAGE_VADDR      (MODULES_END)             // = PAGE_END + 128MB
```
| VA_BITS | PAGE_OFFSET（直接用） | PAGE_END（**不是**基址！） |
|---|---|---|
| 39 | **0xffffff8000000000** | 0xffffffc000000000 |
| 40 | 0xffffff0000000000 | 0xffffff8000000000 |

**本轮就是在这里翻的车**：把 `PAGE_END` 当成线性基址，整个扫描窗口落到直接映射之外。

验证方法（不依赖任何素材，纯设备侧）：
- 窗口必须 ⊆ `[PAGE_OFFSET, PAGE_END)`
- 任何 slab 对象（`mm_struct`/`task_struct`）的线性别名都应落在窗口内
- **futex 侧信道类**：见第 4 步的真值法

## 第 4 步：futex 侧信道的两个硬约束

### (a) 建堆与测量必须在**同一个 mm**
futex key = `{current->mm, 页对齐地址, 地址&0xfff}`，`hash = jhash2(key, 4, key&0xfff) & (hashsize-1)`
（`kernel/futex/*.c` 的 `hash_futex()` / `get_futex_key()`）。
若**建堆在子进程、测量/验证在父进程**，父进程测同一用户地址得到的是**另一个 mm 的桶**（通常空桶），
表现为 `t_target == t_base`、闭环验证恒假。**"数值恰好等于基线"要优先怀疑 mm/进程不匹配**，而不是"对象消失了"。

### (b) 判据必须同量纲
- 空桶 → 快路径（`hb_waiters_pending` 为假，跳过加锁与遍历）
- 桩自身 → key 命中，遍历**链头即 break**
- 同桶但 key 不同 → 遍历**整条链**才退出
三者是三种代价。拿"桩自身"当参照去判断"是否同桶"是不同量纲的比较。
**实测参考值（vivo V27, 1024 waiter）**：空桶 1–7 tick、桩自身 ~540、同桶地址 408–627。

### 真值获取法（**不需要知道 mm**）
扫**桩所在页的全部 1024 个 offset**（同页 = 同 mm、同 page，仅 initval 不同）：
慢的那些就是**真值同桶地址**。拿到 k 组"桩↔同桶"对后反解 `mm`：
k=1 → ~`2^64/hashsize` 个候选（无信息）；k=2 → ~`2^64/hashsize²`；**k=3 → 唯一解**。
**正确窗口内应恰好 1 个解，错误窗口内 0 个**——这是判断"窗口/公式对不对"的杀手锏。
工具：`tools/ks_probe.c`（设备侧探针）、`tools/solve_pairs.c`（反解）、`tools/agree_mm.c`（最大一致性 + 随机基线）。

## 第 5 步：结构体偏移——**从设备二进制取，不要信转述的偏移表**

```bash
# 设备镜像里若内嵌 BTF（GKI 通常有），直接解析，一步到位：
grep -a "__start_BTF" <符号表>      # -> VA，再减去 KIMAGE_VADDR 得到文件偏移
python tools/btf_dump.py show task_struct
python tools/btf_dump.py member rt_mutex_waiter task
```
**校验**：BTF 报的 `size` 常**不是** slab stride —— 要用 `/proc/slabinfo`
（或 `/sys/kernel/slab/<cache>/{object_size,objs_per_slab,order}`，**注意很多机型 shell 读不到**）。

## 第 6 步：确认启动链，决定是否必须走漏洞

```bash
adb shell 'for p in ro.boot.flash.locked ro.boot.verifiedbootstate ro.boot.vbmeta.device_state \
  ro.boot.veritymode ro.oem_unlock_supported; do echo "$p=$(getprop $p)"; done'
```
- `flash.locked=1` + `verifiedbootstate=green` + vbmeta `locked` ⇒ **刷机不可行**
- **`ro.oem_unlock_supported` 为空** ⇒ 厂商连解锁开关都不给（vivo 就是），**漏洞是唯一路径**

## 第 7 步：真值源清单（哪些读得到、哪些读不到）

| 源 | 权限 | 用途 |
|---|---|---|
| `/proc/config.gz` | ✅ 可读 | VA_BITS、VMAP_STACK、FUTEX 等 |
| `getprop` | ✅ 可读 | 构建号、fingerprint、bootloader 状态 |
| `/proc/version` | ✅ 可读 | 内核完整版本串 |
| `/proc/kallsyms` | ❌ **读出 0 行** | 本来能给符号地址（最想要的）|
| `/sys/kernel/slab/*` | ❌ 无权限 | 结构体 size/stride |
| `/proc/slabinfo` | ❌ 基本无权限 | 同上 |

⇒ **没有 root，设备上的符号地址拿不到** ⇒ 必须靠外部二进制（第 0 步）。

---

## 方法论（本轮反复吃亏的地方）

1. **"证据很强" ≠ "已验证"**。今天有三次把推断当结论：
   ① "命中集是噪声"（实际是复算跑在**错误的地址窗口**里，两个错误互相印证成假证据）；
   ② "`FAKE_TASK_PI_*` 是 bug"（实际 `_RSO` 已优先取每设备值）；
   ③ "缺的就是 `W0_OFF` 那个数"（实测零变化）。
   **在给出判断时，必须显式标注"已验证"还是"待验证"。**
2. **用"全窗口搜索无解"当否证证据之前，先验证窗口本身。**
3. **读回值类测量必须先放哨兵**，否则分不清"内核写的"和"我自己填的"。
   （`tools/probe_tcp_route.c` 就犯过：把输入长度当成"内核实测 sizeof"，还写进了注释。）
4. **一次只改一个变量**；改完必须用设备侧可观测信号闭环。
5. **先读源码，再反汇编，最后才是暴力枚举。** 顺序反了会浪费一个数量级的时间。
6. **收工前提交**。本机 git 有丢 ref 的病，用
   `<HOME>\.workbuddy\git_commit_repair.sh <repo> <Win路径消息文件>`，
   **且它只 commit 不 add**（要先 `git add -A`），跑完**另起一条命令验证 `git log -1`**。

## 环境（本机）
- 交叉编译独立工具（aarch64）：
  `<NDK>/toolchains/llvm/prebuilt/<prebuilt>/bin/aarch64-linux-android35-clang`
  `-O2 -D__ARM=1 -DCORE=6 -Isrc/core -Isrc/core/kernelsnitch -Isrc/kernels -DTARGET_CONFIG_H='"target.h"'`
- 反汇编需 capstone：**系统 python 3.12.13 有**，managed 3.13.12 没有
- **adb 并发调用会互踩**（`could not read ok from ADB Server`）→ 多条 adb 串行
- USB 直通到 Linux（当 Windows 缺驱动时）：见 `docs/MTK_BROM_DUMP.md`（已归档于旧工作树 `<ARCHIVE>/docs/`）与当日记忆，
  要点：`usbipd` + **必须有 WSL 在跑** + `bind --force` + **用完 `unbind`** 才恢复 Windows 侧

## 2026-09-14 vivo V27 的收尾状态

**已完成（已提交 `b9b74e5`）**
- `mm_struct` 泄漏打通：`agree=19/19`（唯一候选）、`t_probe/t_base=534×`、`prepare_kernel_page ok attempt=1`，
  5/5 稳定复现。两个根因：`page_offset` 取成了 `PAGE_END`；投票跑在错误进程。
- `structures`：`STRUCT_OFFSETS_5_15` 与 5.15.178 源码逐项核对通过；
  `rt_mutex_waiter` 布局从**正确版本源码**读出，与常量一致。

**未完成（已定位，未解决）**：**W1 的写原语**
- 现象：路由完整跑完（`done=1 calls=1 success=1`）、不 panic、**不写入**
- 定位：`GHOSTLOCK_NOWRITE=1`（专门强制在 `!owner || !is_top_waiter` 早退）与正常路径**不可区分**
  ⇒ 正常路径也在那里早退，写入从未执行
- 已排除：`owner` 侧（`GHOSTLOCK_OWNER=fake` 无变化）、帧深度 `δ`（扫过，`-8` 是唯一能让路由跑完的值）、
  页几何 `W0_OFF`（改成参考实现 29 个机型一致的值，**零变化**）
- `is_top_waiter` 比较的是 `lock->waiters.rb_leftmost`（**真实锁**，内核按 prio 在 enqueue 时写），
  而我们 payload 里写的 `rb_leftmost`（假锁）**内核根本不读** —— 这解释了 `W0_OFF` 为什么无效
- **首要嫌疑**：`offsets.h` 里所有每构建数值来自 `-00005` 构建（见第 0 步）
- **下一步**：拿到设备当前构建的内核（第 0 步的途径）→ 重填 `offsets.h` → 再解 W1
