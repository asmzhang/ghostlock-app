# P6 (5.10.157-oriole) PI-futex 原语：结构性反证

日期：2026-10-27　设备：Pixel 6 / oriole `22251FDF60004E`
内核：`5.10.157-android13-4-00001-g5c7ff5dc7aac-ab10381520`（签名工厂镜像 TQ3A.230805.001）

## 1. 目的

2026-10-21 的收尾结论是经验性的：W1 的 craft 打进去后 walk 读不到，`selinux_state` 不变，
统一毒值探针从未触碰 craft 窗口。当时只能记录"看起来 dangle 已经没了"，无法回答
**"是时序没掐准，还是这条路根本不成立"**。

本文用 kprobe 在内核里实测，把这个问题定死。结论先写：**结构性不成立**，不是参数问题。

## 2. 前置条件：P6 的 root

此前所有 P6 实验都受限于没有 root（只能看用户态现象）。本次打通：

- 工厂 `boot.img` → `magiskboot unpack` → 设备端 `boot_patch.sh`（Magisk v28.1）→ `new-boot.img`
  → `fastboot flash boot_a` → 正常重启。
- 卡点不是 Magisk 版本，而是 `超级用户` 页里 `[SharedUID] Shell` 的开关默认关闭，
  logcat 表现为 `W Magisk : su: request rejected (2000)`。开启后 `uid=0 … context=u:r:magisk:s0`。
- **`/system/bin/su` 不存在**，脚本必须走 `/debug_ramdisk/su`。
- 已固化到 `boot_a`，正常重启后 root 仍在，不再依赖 `fastboot boot` 临时镜像。

## 3. 顺带结论：profile 偏移 0x2180 之谜关闭

`kptr_restrict=2` 时 `/proc/kallsyms` 全零；置 0 后取实机地址与 profile 的镜像偏移比对
（KASLR slide `0x128000000`，2 MB 对齐，base `0xffffffd290800000`）：

| 符号 | profile（镜像偏移） | 实机 kallsyms 低 20 位 | 结论 |
| --- | --- | --- | --- |
| `security_hook_heads` | 38910608 = 0x251BA90 | …d1ba90 → 0x1BA90 | 工厂值正确 |
| `selinux_blob_sizes` | 38919744 = 0x251DE40 | …d1de40 → 0x1DE40 | 工厂值正确 |
| `selinux_state`（enforcing +0） | 51992944 = 0x3195970 | …995970 → 0x15970 | 一致 |
| `init_cred` | 50330496 = 0x2FFFB80 | …7ffb80 → 0xFFB80 | 一致 |
| `init_task` | 50507968 = 0x302B0C0 | …82b0c0 → 0x2B0C0 | 一致 |

⇒ profile 里曾差 `0x2180` 的三个值来自 **AOSP 同 tag 镜像**（`…-00003-g776d0a76f6aa-ab10208116`），
签名工厂镜像才是设备真跑的那份。`7df528f` / `232ff44` 的改法正确。

## 4. 方法

tracefs 在 `/sys/kernel/tracing`（不是 `/sys/kernel/debug/tracing`）。注册五个探针：

```
p:glk_fwrp  futex_wait_requeue_pi     uaddr=%x0 flags=%x1 val=%x2 uaddr2=%x5
r:glk_fwrpr futex_wait_requeue_pi     ret=$retval
p:glk_tb    task_blocks_on_rt_mutex   lock=%x0 waiter=%x1 task=%x2
p:glk_rw    remove_waiter             lock=%x0 waiter=%x1
p:glk_apc   rt_mutex_adjust_prio_chain req=%x1 task=%x3
```

被观测量是 `build/futex_probe.c` 编译的 aarch64 静态程序，重放 A/C/D 三组
（绝对超时、相对超时、超时+唤醒）PI-requeue 编排。

## 5. 证据

trace 原文（只摘 futex_probe 进程）：

```
futex_probe-6465 [006] 81.870281: glk_fwrpr: ret=0xffffff92
futex_probe-6467 [002] 81.924624: glk_tb:  lock=0xffffff80269ee510 waiter=0xffffffc01e2cbb78 task=0xffffff8810c7ca00
futex_probe-6468 [005] 81.924928: glk_fwrp: uaddr=0x7fc32f2060 flags=0x1 val=0x0 uaddr2=0x0
futex_probe-6466 [006] 81.976076: glk_tb:  lock=0xffffff88bad71410 waiter=0xffffffc01e2d3b80 task=0xffffff881f5cb780
futex_probe-6466 [006] 81.976085: glk_apc: req=0x1 task=0xffffff80269ee510
futex_probe-6466 [006] 81.976091: glk_rw:  lock=0xffffff88bad71410 waiter=0xffffffc01e2d3b80
futex_probe-6466 [006] 81.976096: glk_apc: req=0x0 task=0xffffff80269ee510
futex_probe-6468 [007] 86.923645: glk_fwrpr: ret=0xffffff92
```

同一轮的用户态时间线：

```
main   CMP_REQUEUE_PI ret=-1 errno=35 t=53          ← EDEADLK，requeue 失败
waiter WAIT_REQUEUE_PI ret=-1 errno=110 after 298 ms t=300
main   C_absolute_300 VERDICT waiter_returned=yes (waited 253 ms past CMP)
```

内核源码逐行对应（`build/rtmutex-android13-5.10.c`）：

- `L962` `task->pi_blocked_on = waiter;` —— 唯一置位点，在 `task_blocks_on_rt_mutex()` 内
- `L897` `task->pi_blocked_on = NULL;` —— 拿锁成功路径
- `L1077` `current->pi_blocked_on = NULL;` —— `remove_waiter()` 内

## 6. 读法与结论

1. `task_blocks_on_rt_mutex` **确实为被 requeue 的 waiter 触发**（`waiter=…e2d3b80`,
   `task=…1f5cb780`）——机制不是"根本没挂上"。
2. **15 µs 后 `remove_waiter` 就把它摘掉**（`81.976076` → `81.976091`），且这一切发生在
   `CMP_REQUEUE_PI` 这一次系统调用内部、发起线程 6466 的上下文里，不是 waiter 醒来后自己清的。
3. 因此 `pi_blocked_on` 的非零窗口约 15 µs，**完全由内核在另一个 CPU 的同一个 syscall 内走完**；
   用户态没有任何时刻能观测或占住这个字段。等 waiter 从 `FUTEX_WAIT_REQUEUE_PI` 返回时，
   字段早已是 NULL——这正是此前"统一毒值探针从未触碰 craft 窗口"的机制解释。

**判定：W1 的 PI-futex 原语在本内核上结构性不可用。** 不是几何/时序参数问题，调参无法解决；
要让 P6 命中必须换一个与 PI 链无关的写原语。

## 7. 影响与处置

- P6 维持"不在支持列表"：`index.conf` 不索引 5.10.157，profile 仅作取证保留。
- 本次不重开 P6。副产品是 P6 具备持久 root，后续任何静态/动态核查可直接使用。
- marble（5.10.149）不受影响：它走 multicast_waiter，不依赖本字段在用户态可观测。

## 8. 复现步骤

```sh
# 1) root（一次性）
fastboot flash boot_a new-boot.img && fastboot reboot
# Magisk 应用 → 设置 → 超级用户 → 打开 [SharedUID] Shell 的开关

# 2) 挂探针
adb push kp_setup2.sh /data/local/tmp/ && adb shell "/debug_ramdisk/su -c 'sh /data/local/tmp/kp_setup2.sh'"

# 3) 重放编排并取 trace
adb shell "/debug_ramdisk/su -c '/data/local/tmp/futex_probe'"
adb shell "/debug_ramdisk/su -c 'grep glk_ /sys/kernel/tracing/trace'"

# 4) 清理
adb shell "/debug_ramdisk/su -c 'cd /sys/kernel/tracing; echo 0 > tracing_on; echo > kprobe_events; echo 2 > /proc/sys/kernel/kptr_restrict'"
```
