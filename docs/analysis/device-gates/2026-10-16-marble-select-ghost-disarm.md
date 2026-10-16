# Gate: select_stack 的 post-race ghost disarm（marble / 5.10.149）

日期：2026-10-16 ｜ 设备：`3e6f1443`（Redmi Note 12 Turbo / marble / QCOM SM7475）
内核：`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656` ｜ 分支：`main-510-port`

## 结论

**打偏（miss）之所以必定带走设备，是因为 select_stack 路由没有 multicast 早就有的 post-race ghost disarm。**

`select_stack` 把伪造的 `rt_mutex_waiter` 留在 waiter 线程自己的内核栈帧里，并让该线程的
`task->pi_blocked_on` 继续指着它。路由结束时线程退出，栈帧被回收/复用，指针变成悬空。
下一个写阶段的 consumer `sched_setattr` 走 PI 链时顺着这个指针读到**已被清零的内存**，
于是 `rb_insert_color` 拿到的 `parent` 是"红色"、`gparent = *(parent) & ~3 = 0`，在
`gparent->rb_right`（偏移 0x8）上取 NULL 解引用。

关键在退出路径：该 oops 带着 `preempt_count 3` 退出（`pi_lock` 与关中断都没放开），
所以 CPU 不会恢复，机器**卡死而不是重启**——这正是「打偏 ⇒ 设备死」的形态。

## 判据表

| 项 | 值 |
| --- | --- |
| native `build/native/ghostlock` | 2785488 B ｜ md5 `D42A353DF02661777F6F13362F21A7E3` |
| `app/src/main/jniLibs/arm64-v8a/libghostlock.so` | 438936 B ｜ md5 `2C4FB0F8D6B35B0A30D207CF7366DD12` |
| APK | `GhostLock-v1.2(575)-arm64-v8a-debug.apk` 22004274 B ｜ md5 `EA6E1CED5107A24C776D3E99A24445DC` |
| host 测试 | `build_fail=0 run_fail=0`（28 个，含新增 `route_needs_stack_disarm` 断言） |
| 新增日志串 | `ghost disarm ret=%ld errno=%d`（旧串 `mcast ghost disarm` 已消失） |

## 逐字证据

### 1. oops 本体（`/data/local/tmp/glkfx/kmsg-tail.bin`）

```
Internal error: Oops: 96000005 [#1] PREEMPT SMP
CPU: 5 PID: 20253 Comm: libghostlock.so
pc : rb_insert_color+0x48/0x164
lr : rt_mutex_adjust_prio_chain+0x580/0x19a0
Call trace:
 rb_insert_color+0x48/0x164
 rt_mutex_adjust_pi+0x174/0x30c
 __sched_setscheduler+0xeb4/0x14f4
 __do_sys_sched_setattr+0x25c/0x3f8
 __arm64_sys_sched_setattr+0x24/0x34
note: libghostlock.so[20253] exited with preempt_count 3
```

`x0 = ffffffc0365dbc30`（vmalloc 区 ⇒ 内核栈），即被插入的那个 node 就在内核栈上。

### 2. 死亡点固定在「上一阶段成功之后」

`build/510profile/rounds-w3fix2/round-1.full.log` 的顺序：

```
W1: SELinux attempt 1/15
pselect post-select attempt=1/4 compact=2 +211ms ret=4      <- W1 存活
[+] SELinux permissive
W2: cred attempt 1/15
pselect pre-select attempt=1/4 compact=2 +0ms                <- 之后没有任何一行
```

W1 的 `execute()` 返回 ⇒ waiter 线程退出 ⇒ 悬空 ghost 留下；W2 的 consumer 第一次
`sched_setattr` 就踩到它。**这正是「W1 能过、W2/W3 必死」的来源。**

### 3. 打偏轮的统一形状

所有打偏轮都止于 `pselect pre-select`，`pselect post-select` 从不出现 ⇒
重试阶梯（`attempts=4` / `w1_attempts=15` / `w2_attempts=15`）在打偏时全部不可达。
历史批次统计里 `benignMiss`（出现 post-select 但没命中）几乎恒为 0，与此一致。

## 机理与改动

上游 multicast 分支早就写着这条隐患（`src/core/race/threads.cpp`）：

> `remove_waiter()` left this thread's pi_blocked_on pointing at the reclaimed stack
> waiter. Force one final slow-path removal while the stack frame is still alive…
> Without this, thread exit leaves a walkable dangling ghost and the next mm_struct
> spray can panic the kernel.

select_stack 用的是同一种"栈上 waiter"原语，却只按 `route_needs_ghost_disarm`
（= multicast 能力）触发，因此从没跑过这一步。

改动两处：

- `src/core/route/route_policy.hpp`：新增 `route_needs_stack_disarm(profile)`，
  对解析出的策略 `kind == RouteKind::SelectStack` 返回 true（沿用 `route_capability`
  的显式比较链，PI 窗口内不做间接分派）。
- `src/core/race/threads.cpp`：退出前的 disarm 条件改为
  `route_needs_ghost_disarm(...) || route_needs_stack_disarm(...)`，日志串统一为
  `ghost disarm ret=… errno=…`。

disarm 本身不改：`dummy_pi = 0x80000000 | getpid()` + 过期 timeout 的 `FUTEX_LOCK_PI`
会强制当前线程走 PI 慢路径，从而在栈帧还活着的时候消费掉自己的 `pi_blocked_on` 幽灵。

### 悬空节点是怎么进入"真实"任务的 PI 树的

`rb_insert_color` 只可能由 `rt_mutex_enqueue_pi(task, waiter)` 走到
（`build/510profile/src/rtmutex-v5.10.149.c:304-323`，被内联进
`rt_mutex_adjust_prio_chain`，与栈回溯一致）：

```c
rb_link_node(&waiter->pi_tree_entry, parent, link);
rb_insert_color_cached(&waiter->pi_tree_entry, &task->pi_waiters, leftmost);
```

`parent` 来自沿 `task->pi_waiters` 的下降；如果树里已经有一个**指向已释放内存的陈旧指针**，
`rb_link_node` 就把 node 的 `__rb_parent_color` 设成那个陈旧指针（偶地址 ⇒ "红色"），
`rb_insert_color` 再取 `gparent = *(parent) & ~3` —— 内存已清零 ⇒ `gparent = 0`
⇒ 在 `gparent->rb_right`（0x8）上炸。这与 oops 的故障地址逐位吻合。

**那么陈旧指针怎么进真实任务的树**：打偏时（fd_set 的拷贝没有落在
`pi_blocked_on` 指向的槽位上）`waiter->lock` 读到的是真实 `rt_mutex`，于是
`lock->owner` 是**真实 task**，`rt_mutex_adjust_prio_chain` 就把我们的**栈上** waiter
`rt_mutex_enqueue_pi()` 进了那个真实任务的 `pi_waiters`。线程一退出、栈一回收，
真实任务的树里就永久留下一个指向空内存的节点 —— 直到 disarm 把它摘掉。

这正是"打偏本身只丢一次写，但下一次 PI walk 必定踩空"的完整链条，
也说明修复必须发生在**线程退出之前**。

## 与既有 gate 的关系

- `docs/analysis/device-gates/2026-10-15-marble-w3-leaf-freeze.md`：同一个 `rb_insert_color`
  形态，触发路径是 W3 的 `right == 0` 回退。那条已修（改为指向页内自洽黑节点）；
  本条是**跨阶段悬空指针**，两条互不替代。
- `docs/analysis/device-gates/2026-10-15-marble-root-shell-seccomp.md`：W3 重新打开的依据。

## 验证

批次 `rounds-disarm`（25 轮，`-RebootAfterHit`）——**结果待填**。

判据：修复后打偏轮应开始出现 `pselect post-select`（良性打偏 > 0），
且 W2/W3 存活率相对 `rounds-w3fix2`（W1 12/20、W2 12/12、W3 8/12）不下降。

## 未决

1. 同一次 pselect 内部的打偏（栈帧与 `pi_blocked_on` 指向的槽位没对齐）不受本改动影响，
   仍是残余 miss 来源。
2. `held[24]` 页保留槽在长批次下是否够用，尚未压到上限。
3. disarm 只覆盖线程退出路径；若将来路由在同一线程内跑多轮写，需要重新评估。
