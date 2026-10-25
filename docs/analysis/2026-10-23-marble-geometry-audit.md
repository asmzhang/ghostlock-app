# marble 适配审计：用原厂 boot.img 逐字段复核

日期：2026-10-23
对象：`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`（Redmi Note 12 Turbo / marble）
触发问题：「我们的适配是不是有问题」

## 1. 数据来源与方法

| 项 | 值 |
| --- | --- |
| 镜像 | `V14.0.27.0.TMRCNXM_13.0\images\boot.img`（原厂线刷包，201,326,592 B） |
| 解压后内核 | 46,701,100 B |
| kallsyms | 镜像内嵌表恢复成功，**140,403** 条符号；`_text = 0xffffffc010000000` |
| 提取器 | `ghostlock-extract`（`--analysis` / `--format conf`） |
| 反汇编 | `tools/extract_rs/src/bin/audit.rs`（`TEMP(audit-01)`；`cargo run --release --bin audit -- <img> <窗口> <符号…>`，下次适配可复用） |

`--analysis` 结论：`kernel_family unverified`、`rt_mutex_waiter (no rt_mutex_waiter type in BTF)`、
`primitive remove_waiter@0x1e5c28 unpatched`。即**镜像内没有 BTF**，结构体偏移无法由工具推导，
只能由反汇编逐点核对；`/sys/kernel/btf/vmlinux` 在设备上也不存在（CONFIG_DEBUG_INFO_BTF 未开）。

## 2. 符号偏移：10/10 一致

`ghostlock-extract boot.img --uefi uefi.elf --format conf` 与现有 profile 逐字段比对：

| 字段 | 提取器 | profile | |
| --- | --- | --- | --- |
| `init_task` | 41467776 | 41467776 | OK |
| `init_cred` | 41552176 | 41552176 | OK |
| `empty_zero_page` | 43495424 | 43495424 | OK |
| `root_task_group` | 43515968 | 43515968 | OK |
| `selinux_enforcing` | 44235672 | 44235672 | OK |
| `selinux_blob_sizes` | 36570608 | 36570608 | OK |
| `security_hook_heads` | 36568928 | 36568928 | OK |
| `slide_nfulnl_logger` | 41423952 | 41423952 | OK |
| `slide_loggers_0_1` | 41423752 | 41423752 | OK |
| `slide_boot_id` | 44340029 | 44340029 | OK |
| `kernel_phys_load` | 2818572288 | 2818572288 | OK |

`kernel_phys_load` 由 `uefi.elf` 的 platform memory map 推导（`info: kernel_phys_load=0xa8000000`）；
`xbl_config.elf` 的 FDT 里没有唯一的 NOMAP/Kernel 区，走不到那条路径。

## 3. 结构体偏移：反汇编逐点核对

每条都给出「哪条指令证明了这个偏移」。全部取自同一镜像。

| 字段 | profile | 证据 |
| --- | --- | --- |
| `task_struct.prio` | 132 (0x84) | `rt_mutex_setprio`：`ldr w8, [x20, #0x84]` |
| `task_struct.normal_prio` | 140 (0x8c) | `rt_mutex_setprio`：`ldr w25, [x20, #0x8c]` |
| `task_struct.pi_lock` | 2156 (0x86c) | `rt_mutex_adjust_prio_chain`：`add x25, x19, #0x86c` |
| `task_struct.pi_waiters` | 2176 (0x880) | `rt_mutex_adjust_prio_chain`：`add x8, x19, #0x880` |
| `task_struct.pi_top_task` | 2192 (0x890) | `rt_mutex_setprio`：`ldr x8, [x20, #0x890]` / `str x21, [x20, #0x890]` |
| `task_struct.pi_blocked_on` | 2200 (0x898) | `rt_mutex_adjust_prio_chain`：`ldr x28, [x19, #0x898]` |
| `task_struct.real_cred` | 1912 (0x778) | `get_task_cred`：`add x9, x0, #0x778` + `ldar x19, [x9]` |
| `task_struct.cred` | 1920 (0x780) | `prepare_creds`：`ldr x20, [x8, #0x780]` |
| `task_struct.seccomp` | 2120 (0x848) | `__secure_computing`：`ldr w9, [x8, #0x848]` |
| `task_struct.comm` | 1936 (0x790) | `__set_task_comm`：`add x22, x20, #0x790` |
| `cred.copy_size` | 168 (0xa8) | `prepare_creds`：`mov w2, #0xa8` + `bl memcpy`，随后 `str wzr, [x19, #0x98]`（`non_rcu`） |
| `cred.ref0_offset`（user） | 128 (0x80) | 与 `user_ns`/`group_info` 相邻且同序（后两者已证），`cap_capable` 邻居 `ldr x19, [x21, #0x780]` 取到 cred 后按此布局读 |
| `cred.ref1_offset`（user_ns） | 136 (0x88) | `cap_capable`：`ldr x8, [x0, #0x88]` |
| `cred.ref2_offset`（group_info） | 144 (0x90) | `set_groups`：`ldr x0, [x19, #0x90]` / `str x20, [x19, #0x90]` |

由 `prepare_creds` 的 `0xa8` 拷贝长度与 `cap_capable` 的 `cap_effective @ 0x38` 可反推
`struct cred` 的 caps 区起点：

```
0x28 cap_inheritable   (40)
0x30 cap_permitted     (48)
0x38 cap_effective     (56)   <- cap_capable 按 cap>>5 索引后读 [x8, #0x38]
0x40 cap_bset          (64)
0x48 cap_ambient       (72)
0x50 session_keyring
0x58 process_keyring
0x60 thread_keyring
0x68 request_key_auth
0x70 security
0x78 (ucounts / 保留)
0x80 user              (128)
0x88 user_ns           (136)
0x90 group_info        (144)
0x98 non_rcu / rcu_head
0xa8 结束 = 168
```

## 4. 发现：`caps_offset = 48` 把第五个 word 写进了 `session_keyring`

`src/core/support/util.cpp` `fill_profile_cred_copy()` 先 `memset(c, 0, copy_size)`，然后

```cpp
for (uint32_t i = 0; i < v->credential.caps_count; i++) {
    put64(c, v->credential.caps_offset + i * sizeof(uint64_t), v->credential.caps_value);
}
```

即 `caps_count` 的单位是 **8 字节的 `kernel_cap_t`**，不是 32 位字。原配置
`caps_offset = 48, caps_count = 5, caps_value = -1` 实际写入：

| 偏移 | 字段 | 写入值 |
| --- | --- | --- |
| 48 | cap_permitted | `0xffffffffffffffff` |
| 56 | cap_effective | `0xffffffffffffffff` |
| 64 | cap_bset | `0xffffffffffffffff` |
| 72 | cap_ambient | `0xffffffffffffffff` |
| **80** | **session_keyring** | **`0xffffffffffffffff`** |

`cap_inheritable`（40）反而没被覆盖。`util.cpp` 的边界检查
`caps_offset + caps_count * 8 > copy_size` 算出 88 ≤ 168，**拦不住这个越界**，
因为越界目标是同一结构体内的合法字段。

后果：伪造 cred 的 `session_keyring` 变成一个非空野指针。任何 `key_put()` /
`key_fsuid_changed()` / `install_session_keyring_to_cred()` 路径都会解引用它。
本机 `usage_value = 2147483647` 使 `put_cred_rcu()` 永不执行，所以这条路径目前
没有直接触发，属于**潜伏雷**而不是已观测故障的成因。

**修复**：`caps_offset` 48 → 40，五个 word 正好覆盖
`inheritable/permitted/effective/bset/ambient`（0x28..0x50），不碰 keyring。
与 main 上已真机验证（W1 5/5、W2 到 uid=0）的 `5.10.236` Xperia profile 取值一致。

修复已通过 `./gradlew exportKernelProfiles` 端到端确认：导出 bin 中
`caps_offset` 段的 u64 为 `0x28`（40）、`caps_count` 为 5。

## 5. 配置卫生：execution 块瘦身

原 profile 抄了 24 个 `execution` 键，其中 20 个与共享 preset 逐字相同
（`race` 4 项、`handoff` 5 项、`heap` 3 项、`stages.w1_*` 3 项 + `w2_*` 2 项、
`routes.select_stack.enter_delay_us`/`timeout_us`、`w3_settle_us`）。
按 `PROFILE_SCHEMA_ZH.md` 第 5 节与 5.x 模板的「不要把调优抄进 profile」，只保留真差异：

| 保留项 | 值 | 与 preset |
| --- | --- | --- |
| `recommended_cpus` / `selected_cpus` | 4 / 5 | preset 是 0 / 1（机型相关） |
| `stages.w3_attempts` / `w3_chain_rounds` | 1 / 1 | preset 是 6 / 3（本机实测） |
| `routes.select_stack.consumer_max_calls` / `consumer_burst_calls` | 1 / 1 | 同 preset，显式保留以固定 10-16 A/B 结论 |

其余由 `execution-tuning.conf` + `execution-select-stack.conf` 在 resolver 合并。
文件从 173 行降到 154 行。

## 6. 仍然无法用镜像证明的部分

| 项 | 状态 |
| --- | --- |
| `route.select_stack.waiter_shift = -2` | 提取器明确报 `pselect_waiter_shift unavailable; no family fallback is defined for this release`。现有 -2 来自项目自己的反汇编推导 + 真机 A/B（0 时 3/3 打不中，-2 多数命中），**没有第三方交叉验证** |
| `kernelsnitch.mm_struct_sz = 960` / `collisions = 4` | 提取器给的是模板默认 1024/8；960 来自本机 `/proc/slabinfo` 实测，更可信 |
| `cred.usage_value = 2147483647` | 策略选择（防 `cred_free`），不是镜像事实 |
| `task_struct.sched_task_group` 784 / `pid` 1480 / `tgid` 1484 / `atomic_flags` 1424 / `tasks` 1224 | 未逐点核对（本路径不读，优先级低） |
| `cred.ref0_offset`（user）= 128 | 由相邻字段布局推定，非直接指令证据 |

另外顺手核对了 multicast 路由需要的 `rt_mutex_waiter` 字段：
`task_blocks_on_rt_mutex` 里 `stp x20, x19, [x22, #0x30]` 一次写入 `waiter->task`（0x30 = 48）
与 `waiter->lock`（0x38 = 56），随后 `str w8, [x22, #0x40]` 写 `waiter->prio`（0x40 = 64）。
这与 5.x 模板的 `task_offset = 48` / `lock_offset = 56` 一致，说明该模板的
`rt_mutex_waiter` 布局对本机成立。模板里 `waiter_off = 96` / `buffer_size = 264` 是
**栈几何**常量（setsockopt 拷贝基址到 waiter 的距离），不是结构体偏移，镜像里没有可对照的
证据，只能靠真机 A/B。

## 7. 结论

- **符号与几何不是「填错了」**：能从镜像证明的 11 项符号偏移 + 14 项结构体偏移全部与 profile 一致。
- **确实存在一处真实缺陷**：`caps_offset = 48` 让第五个 cap word 落到 `session_keyring`，已修。
- **弱点集中在无法用工具证明的两项**：`waiter_shift` 与 `ref0_offset`，二者目前只有真机行为证据。
- 提取器对本机给出 `suggested route = multicast_waiter (medium)`（5.x 已发布 profile 全部走 multicast），
  与当前使用的 select_stack 不同；这是下一轮单 route A/B 的候选。
