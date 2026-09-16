# 设备实测数据 · marble（Redmi Note 12 Turbo）

> 本文是**这台设备所有实测数字的单一来源**。凡是"换台机器就得重测"的量，
> 都记在这里，避免下次重新测一遍。未标注"实测"的均为推断，请勿直接采信。

## 1. 设备与内核标识

| 项 | 值 |
|---|---|
| 设备 | `marble` / 23049RAD8C（Redmi Note 12 Turbo） |
| SoC | QTI SM7475 |
| 内核 | `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656` |
| 上游支持情况 | **上游 `9f2affc` 不含 5.x**，本适配为我方新增 |

## 2. CPU 拓扑（实测，读 `cpuinfo_max_freq`）

| CPU | 最高频 | 簇 |
|---|---|---|
| cpu0–3 | **1804800**（1.80 GHz） | 小核 |
| cpu4–6 | **2496000**（2.50 GHz） | 中核 |
| cpu7 | **2918400**（2.92 GHz） | 大核（**单核簇**） |

**要点**：最高频的 `cpu7` 是**单核簇**。若只按"最高频"挑核心对，会得到 `7/4`
这种**跨簇**组合 —— 而本漏洞依赖两线程时序对齐，跨簇会引入调度迁移抖动。
**正确目标是中核簇 `cpu4,5,6` 的前两个 → `4 5`。**

`run.sh` 的 `detect_core_pair()` 即按"成员数 ≥ 2 的最高频簇"实现，输出 `4 5` ✓

## 3. 关键偏移与参数

| 量 | 值 | 依据 |
|---|---|---|
| `mm_struct` SLUB stride | **0x3c0**（960） | **slabinfo 实测**：`mm_struct 1088 1088 960 34 8` |
| — BTF 报的 struct 大小 | 0x3e0（992） | **不是 stride，别用** |
| `pselect_waiter_shift` | **-2** | 反汇编推导：raw `0`，ghostlock 内部 `0-2=-2` |
| pselect 各帧大小 | `pselect_wrapper=0xa0`、`core_sys_select=0x1c0`、`futex_wrapper=0x90`、`do_futex=0x70`、`futex_wait_requeue_pi=0x1a0` | 反汇编 |
| fd_set buffer / waiter local | `0x50` / `0x90` | 反汇编 |

**易混淆点**：`fe155cf` 的提交信息写 "0 on stock kernel"，而 `offsets.h` 写 `-2`
—— **两者都对，只是层次不同**：`0` 是 raw shift，`-2` 是 ghostlock 实际使用的值。
**不要以为值被改坏了。**

核对手段：`bash tools/harness/check_stride.sh`（自动按设备内核选对应代码块比对）

## 4. Reclaim 路线判定（实测）

**结论：本机只能用 `pselect`，TCP zerocopy 路线不可用。**

依据 —— 探针实测（`bash tools/probe_tcp_route.sh`，无需 root）：

```
sizeof(struct tcp_zerocopy_receive) 按 NDK 头文件 = 0x40
getsockopt 返回 = -1, errno = 22 (EINVAL)
optlen 回写为 0x28              ← ★ 内核真实的 struct 大小
判定：❌ 够不到 exploit 需要的 0x38 → 必须用 pselect
```

`optlen` 的回写值是权威依据（内核里有 `if (len > sizeof(zc)) len = sizeof(zc);`
再 `put_user(len, optlen)`）。

**两个坑**：
- **头文件 0x40 ≠ 内核 0x28** → 靠编译期 `sizeof` 判断是行不通的，必须问运行中的内核。
- 判定要看 **`optlen` 回写值**，而不是"哪些字节被回写" —— 后者在 `find_vma`
  校验失败提前返回时是空的，会误判。

## 5. 命中率：两个可调的杠杆（实测对照）

### 5.1 CPU 亲和

两组均从**重启后的新鲜状态**起步：

| 组 | 核心对 | 频率 | 结果 |
|---|---|---|---|
| A | `0/1` | 1.80 GHz 小核 | **8 轮全 PANIC，0 命中** |
| B | `4/5` | 2.50 GHz 中核 | **第 1 轮即 SUCCESS** |

**统计局限**：B 组因首轮命中即退出，只跑了 1 轮；且 `gl3_root_success.log`
（9/8）记录了一次 **`cpu pair: main=0 consumer=1` 的成功** —— 说明 0/1 也能中。
若真实命中率 p=10%，A 组 8 轮全不中概率约 43%，并不罕见。
**故"4/5 显著更优"尚未达统计显著**，但也不差、且符合 README 的设计意图。

### 5.2 设备状态（差异达 3.5 倍）

`run.sh:60-66` 记录的实测：

```
W1 survival:  ~25%（right after boot）
           →  ~7%（after a long run of panics/oopses）
```

**这是"同一套参数有时秒中、有时半天不中"的主因** —— 不是参数变了，是状态变了。

## 6. 失败分类与判读

`run.sh` 每轮分三类：

| 分类 | 判定 | 含义 |
|---|---|---|
| **HIT** | 日志出现 `child is root!` / `self is root` | 成功 |
| **PANIC** | 读不到 uptime（设备已重启） | **写发生了但没写对** |
| **SAFE-NO-FIRE** | 进程退出、设备存活 | 没触发 |

**调优应看三分类的分布变化，而不是只盯命中与否** —— 几轮就能看出趋势。

**一个真实诊断例子**（A 组某轮）：

```
fake_parent=0xffffff802aa2fb90
target=0xffffff802aa2fb98        ← 正好差 8 = selinux_enforcing - 8
[*] pselect pre-select compact=1 +1ms
ADB_EXIT=255                     ← 崩在这里
```

**地址算得完全正确**，崩溃发生在 `pselect` 执行 fd_set 拷贝时 →
可断定问题**不在参数、而在时序**，从而把注意力从"调 shift"转到"改亲和/状态"。

## 7. 命中后的两个状态（务必区分）

| 阶段 | `su -c id` 表现 | 说明 |
|---|---|---|
| **命中、未收尾** | `id: gid <垃圾值>: No such file or directory` | W2 副作用污染了 `init_cred` 的 gid 字段；**此时绝不能 exec** |
| **收尾后** | `uid=0 gid=0 ... context=u:r:magisk:s0` | 干净副本，可用 |

**`soft-reboot` 不可省** —— 它正是用来把被污染的 cred 换成干净副本的。

## 8. 收尾流程的已知风险（未复现，存疑）

`docs/PLAYBOOK.md` 第 5 步的收尾脚本含 `apd soft-reboot`。

**历史上见过一次**：收尾后发现框架起不来 ——

```
dmesg: init: Could not ctl.start for 'zygote':
       File /system/bin/app_process64 (labeled "u:object_r:unlabeled:s0")
       has incorrect label or no domain transition ...
init.svc.apexd = stopped
```

**已排除的原因**：`load_policy`（设备脚本里 `GHOSTLOCK_SKIP_FIXUP_BAKED='1'`，
确实跳过了）、`finish.sh`（里面没跑 ghostlock）、C 侧第二条路径。

**但后续一次完整收尾并未复现**（框架完好、`app_process64` 标签仍是
`zygote_exec`）。**故判定为偶发、复现条件未知。** 若再次出现，需专门二分定位。

**恢复手段**：只能重启（`/system` 只读，`restorecon` 改不了标签）—— 代价是丢 root。

## 9. 环境备忘

- **SDK 路径**：`build.sh` 按 `ANDROID_HOME → NDK_ROOT → local.properties 的 sdk.dir
  → LOCALAPPDATA` 依次解析。本机 `local.properties` 里是
  `sdk.dir=D\:\platform\Android\Sdk`，且该文件已被 `.gitignore` 忽略。
- **开发机同时连着多台设备**时，`env.sh` 按 `model:marble` 匹配选设备（`3e6f1443`）；
  更稳妥的做法是显式设 `GHOSTLOCK_DEV=<序列号>`。
- **adb 路径**：本机 `adb.exe` 需传 Windows 盘符（`D:/...`），POSIX `/d/...` 会静默失败。
