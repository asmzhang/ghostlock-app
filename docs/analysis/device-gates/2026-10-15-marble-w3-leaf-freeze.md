# Device gate: marble 5.10.149 — W3 的 leaf 写把 PI walk 引进垃圾父链（静默 freeze）

## 结论

W3 是唯一 `fake_right == 0` 的路由：`WriteRequest::leaf` ⇒ `preserve_child == 0` ⇒
`payload_builder.cpp` 不给 `PayloadWriteLayout::right` 赋值，它保持 0。5.10 臂的表因此走
fallback `pc = target - 8`。这个值在**载荷页**上是「把 0 写到目标」的机制，但作为**栈上
waiter** 的 `pi_tree_entry.rb_parent_color` 是另一回事：`rb_insert_color()` 会把
`*(target - 8)` 读成节点，而 slab 里那个字是 8 字节对齐的指针（bit 0 = 0 ⇒ 红），于是走
`gparent = *(*(target - 8))` 的垃圾链，并在 `rt_mutex_enqueue` 持 `lock->wait_lock`、
关中断的状态下自旋。

marble 的 `panic_on_oops` 已被本方案自己关掉，所以这个 oops 不再重启内核，而是**静默
freeze**：日志停在 `consumer call 1 entering sched_setattr`，`post-select` 永不出现，
`.ghostlock_run_state.json` 留在 `w3a: in_progress`。

修法是把 fallback 指向自己种下的黑节点（`fake_lock + RELINK_NODE_OFF`，该字为 1 ⇒
`rb_is_black()` 为真 ⇒ walk 第一次读就停）。设备上 W3 随即全绿，根脚本以
`Seccomp: 0` 跑完并 late-load 了 KernelSU。

## 判据

| 项 | 值 |
| --- | --- |
| native（修前，= capture-w1d 用的二进制） | `build/native/ghostlock` 2785616 B，md5 `F1E669C42A76F20A0B3CAF2F70D1A41F` |
| native（修后） | `build/native/ghostlock` 2785552 B，md5 `54A46EA197373F359F5EF4FF3BDE934B` |
| APK（修后） | `build/app/outputs/apk/debug/GhostLock-v1.2(573)-arm64-v8a-debug.apk` 22178799 B |
| 提交 | `5e48fb6`（黑节点地毯 + 载荷页保活）、`a6c9ce0`（W3 leaf 写的 pc 改指向黑节点） |
| 主机门禁 | `build/run_host_tests_510.sh`：`build_fail=0 run_fail=0`，`waiter_words_test: ok` |
| 判据行（修后必须出现） | `consumer call 1 sched_ret=0 errno=0 success=1` + `pselect post-select … ret=2` + `pselect route done calls=1 success=1 status=0 clean=1/1 step=0` |
| 判据行（修前） | 只有 `consumer call 1 entering sched_setattr tid=… nice=1`，其后无任何输出 |

`in0` 是本修复最干净的观测量：`waiter_shift = -2` 让 waiter 词 2（`tree_pc`）落在
fd_set 的 word 0，也就是路由日志里的 `in0`。

| 路由 | 修前 `in0` | 修后 `in0` |
| --- | --- | --- |
| W1（Zero，`right = page+0x200`） | `ffffff…8200` | 不变 |
| W2（Credential，`right = init_cred` 别名） | `ffffff802a7a0930` | 不变 |
| W3（leaf，`right = 0`） | `target - 8`（`ffffff87e7ba3fc0`） | `page + 0x200`（`ffffff87f5ca8200`） |

## 逐字证据

### 1. 修前：W3 冻结（`build/510profile/capture-w1d/`，native 日志尾部）

```
=== W3: seccomp mode === target=0xffffff87e7ba3fc8 mode=1 leaf=1
[route] waiter parked; owner started
[route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
pselect route setup shift=-2 page=ffffff803da50000 fake_lock=ffffff803da50000 fake_w0=ffffff803da50300 fake_task=ffffff803da50400 in0=ffffff87e7ba3fc0 in3=ffffff87e7ba3fc0 out0=0000000000000000 ex0=0000000000000000 ex1=0000000000000000 ex2=0000000000000000 ex3=0000000000000000
pselect pre-select attempt=1/4 compact=2 +0ms
consumer gate: waiter parked in syscall 72
consumer call 1 entering sched_setattr tid=23487 nice=1
```

同一批次里 W1/W2 的对照（`right != 0`）：

```
pselect route setup shift=-2 page=ffffff880eb68000 fake_lock=ffffff880eb68000 fake_w0=ffffff880eb68300 fake_task=ffffff880eb68400 in0=ffffff87e7ba3778 in3=ffffff87e7ba3778 out0=0000000000000000 …
pselect pre-select attempt=1/4 compact=2 +0ms
consumer gate: waiter parked in syscall 72
consumer call 1 entering sched_setattr tid=20752 nice=1
consumer call 1 sched_ret=0 errno=0 success=1
pselect post-select attempt=1/4 compact=2 +202ms ret=1
pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
```

### 2. 修后：W3 全绿（`build/510profile/probe-w3fix.txt`，attempt 2 = HIT）

```
=== W3: TIF_SECCOMP === target=0xffffff8818981280 mode=1 leaf=1
[route] creating waiter/owner/consumer
consumer thread running on cpu=5
[route] waiter parked; owner started
[route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
pselect route setup shift=-2 page=ffffff87f5ca8000 fake_lock=ffffff87f5ca8000 fake_w0=ffffff87f5ca8300 fake_task=ffffff87f5ca8400 in0=ffffff87f5ca8200 in3=ffffff87f5ca8200 out0=0000000000000000 …
pselect pre-select attempt=1/4 compact=2 +0ms
consumer gate: waiter parked in syscall 72
consumer call 1 entering sched_setattr tid=20439 nice=1
consumer call 1 sched_ret=0 errno=0 success=1
pselect post-select attempt=1/4 compact=2 +204ms ret=2
pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
[route] route_done status=0 clean=1/1 step=0 errno=0 calls=1 success=1
```

### 3. 写真的落地了：根脚本读到 `Seccomp: 0`

```
[*] seccomp=Seccomp:	0 Seccomp_filters:	0
[*] late-load kmi=android12-5.10
[*] late-load exit=0
[*] temp su uid=0; watching kernelsu.ko
[+] KernelSU module loaded
```

W3 的用途就是抹掉 root child 的 seccomp filter；根脚本里读到 `Seccomp: 0` 说明 leaf 写的
目标字确实被写成 0，而不只是「没有崩」。`files/ksud` 的 mtime 也随该轮刷新
（4892712 B，21:45）。

## 机理

1. `src/core/memory/payload_builder.cpp:67-74`：`layout.right` 只在 `request->preserve_child`
   为真时赋值（`Credential` 给 init_cred 别名，否则给 `page_base + RELINK_NODE_OFF`）。
   `payload_write_layout_matches_request()` 把这个当不变量：
   `preserve_child ? right != 0 : right == 0`。
2. `src/core/route/waiter_words.cpp`：5.10 臂把 `tree_pc`（词 2）与 `pi_pc`（词 5）都设为
   `relink_pc`。修前 `right == 0` 时 `relink_pc = target - 8`。
3. `rb_insert_color()` 沿父链上行时读 `*(parent)` 判红黑。`target - 8` 是 task_struct 里的
   一个字（W3 的 target 是 `child_task + task_seccomp_off()`），其 bit 0 随任务内容变化 ⇒
   有时红有时黑 ⇒ 这解释了「同一构建有时活、有时冻结」。
4. 走垃圾父链时 `rt_mutex_enqueue` 已经持有 `lock->wait_lock` 且关中断，所以 CPU 卡死，
   printk 也停 ⇒ kmsg 里查不到 oops（`build/510profile/capture-w1c/appended.txt` 82 KB 里
   只有 KernelSU 的 `tp_marker` 刷屏，零 oops）。
5. 黑节点是 `src/core/support/util.cpp:455` 种下的：
   `put64(p, page_base_off + kernel::RELINK_NODE_OFF + 0x00, 1)`（1 = 自洽黑节点，
   父 0、无子）。`fake_lock == page_base` 的来源见 `util.cpp:396-403`：
   `payload_delta = SKB_DATA_DELTA = -0xe80` 与 `kLockOffset = 0x0e80` 相消。
6. 修法：`relink_pc = right != 0 ? right : lock + target::payload::kRelinkNodeOffset`。
   载荷页 waiter 自己的 `pi_tree_entry.parent = target - 8` 不变，所以写机制不变。

## 与既有 gate 的关系

- `2026-10-15-marble-root-shell-seccomp.md`：结论是「W3 必须开」。本 gate 是它的直接后续
  ——开了 W3 之后 leaf 写会冻结，本 gate 修掉这个冻结。
- `2026-10-14-marble-w1-shortcircuit.md` / `2026-10-14-marble-v4-reclaim-order.md`：
  管的是 W1 的落地率。W3 的 leaf 写与 W1 走同一张词表，本修复只改 `right == 0` 的那一支，
  W1/W2 逐字节不变（`waiter_words_test.cpp` 第一组断言就是这条）。

## 未决

1. W1 打偏仍然会死（重启或 freeze）。本轮只修掉 W3 这一支；W1 的 `right != 0` 路径在
   `capture-w1c` 里没留下 oops，死亡形态仍是静默卡死，成因未定。
2. `rounds-w3fix` 批次（20 轮，`-RebootAfterHit`）结果待记录：修前 W3 是 10/11，
   需要确认修复后 W3 不再出现在失败轮里。
3. `waiter_shift` 仍是 `-2`。`my2:docs/ADAPT_NEW_KERNEL.md` §⑥ 声称 stock 内核上应为 0
   （-2 是在带 KPM 的内核上测出的假象），但本机 W1/W2/W3 三路在 `-2` 下都已成功，
   未做 A/B，不据此改值。
4. `pselect post-select … ret=2` 与历史成功轮的 `ret=4/5/6` 不同，尚未解释（`ret` 是
   pselect 的返回值，即就绪描述符数）。
