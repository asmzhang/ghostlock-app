# Marble 5.10.149 打偏根治 — 2026-10-22 收尾报告

设备：Redmi Note 12 Turbo（marble），`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`，adb `3e6f1443`。
构建：`main-510-port` @ `9443450`（marble 最后提交）+ 本轮 TEMP 探针。

## 1. 结论摘要

1. **打偏 = 整机在 ≤500 ms 内冻结**，不是单线程挂起。心跳在最后一个 tick 之后不再落盘，
   而设备要到 30–90 s 后才真正掉线/重启。⇒ 用户 m06134 选定的
   **「超时判定 + 安全回收」方向不可行**：冻结发生在一个 tick 之内，用户态没有任何机会
   跑判定线程，更无法执行 disarm/回收。
2. **打偏发生在当轮 route 自己的 walk 内**：最后一行日志恒为
   `consumer call 1 entering sched_setattr tid=… nice=1`，`route_done` 永不返回。
3. **上一阶段不毒化下一阶段**：W1 成功后 canary A（对自身做 `sched_setattr`，完整走一次
   `rt_mutex_adjust_pi`）返回 0 ⇒ 批次 H 这条线结案。
4. **未解决**：为何 craft 形状完全相同的两次 route，一次干净返回、一次锁死整机。
5. **现存最强假设**：泄漏页在 walk 前被内核复用/改写 ⇒ `waiter->lock->wait_lock` 非 0
   ⇒ `raw_spin_trylock()` 无限重试（`rt_mutex_adjust_prio_chain` 步骤 [5] 的 `goto retry`）
   ⇒ 该 CPU 硬挂 ⇒ PMIC 复位。今日全部打偏轮**零内核证词**（无 oops / panic / RCU stall /
   dropbox 条目），与该假设一致（纯自旋，不触发任何内核报告路径）。

## 2. 今日带探针的轮次（8 轮）

| 轮 | 结果 | 关键证据 |
| --- | --- | --- |
| 15:03 | **HIT-ROOT** | 5 条 route 全 `route-returned code=0`；W1/W2/W3-0/W3-TIF/W3-mode 全过；handoff → kernelpatch 126976 Live，`su` uid=0，Permissive |
| 15:13 | W1 打偏 | `step7 spray-done` → `wd t=0s` → `wd t=1s` → 无 `route-returned`；native log 374 B 全 0（page cache 全丢） |
| 15:16 | **HIT-ROOT** | 5 条 route 全 `route-returned code=0`；`su -c 'id -u'`=0；证据 `build/510profile/hit-151650/` |
| 15:21 | W2 打偏 | route1 干净 → route2 `wd t=0ms` / `wd t=500ms` → 无后续；设备 ~15:22:36 重启 |
| 15:34 | W3-TIF 打偏 | `psel page=ffffff8819ee0000` → 停在 `consumer call 1 entering sched_setattr tid=28753`；native log 25 KB 幸存 |
| 15:56 | W1 打偏 | `psel page=ffffff884f1f0000`；reclaim `ok=4/4 errno=0` |
| 15:59 | 未取到 | 起跑 ~14 s 设备掉线 |
| 16:00 | W1 打偏 | `psel page=ffffff88d8370000`；reclaim `ok=4/4 errno=0`；停在 `consumer call 1 … tid=11988` |

干净命中率 **2/8 = 25%**（不含 15:59 未知轮）。

## 3. 三个被证伪的假设

| # | 假设 | 证伪证据 |
| --- | --- | --- |
| H1 | `FUTEX_WAIT_REQUEUE_PI` 可被 SIGALRM 中断，因此打偏可返回 | 34 次 wait（v1/v2/v3 三种探针），**0 次 EINTR**，全部 `errno=110` |
| H2 | 上一阶段遗留的 ghost waiter 毒化下一阶段的 walk | canary A：W1 成功后对自身 `sched_setattr` 返回 `ret=0 errno=0` |
| H3 | reclaim send 失败 ⇒ craft 写在没人用的页上 | 两轮打偏轮 `reclaim sends ok=4/4 errno=0`，仍锁死 |

另：`canary B`（对真实 `target_futex` 做短超时 `FUTEX_LOCK_PI`）返回 ETIMEDOUT 属预期
（fake owner 持有），**无判别力**，建议删除。

## 4. 唯一的内核侧证词（历史，非今日）

kmsgd 累积日志（`build/510profile/w3diag-i/round-1.glk.kmsg-tail.bin`，325 MB / 201 个 boot）
里有 **18 条**带完整调用栈的死亡，全部集中在 2026-10-14 / 10-16 / 10-20，今日 0 条：

```
note: libghostlock.so[PID] exited with preempt_count 3
rb_insert_color+0x48/0x164
  ← rt_mutex_adjust_pi+0x174/0x30c
  ← __sched_setscheduler+0xeb4/0x14f4
  ← __do_sys_sched_setattr+0x25c/0x3f8
寄存器 x8=0；faulting 指令 f940050a = ldr x10,[x8,#8]
```

即 `rb_insert_color` 读到**零父节点**后在 +0x8 取指 fault。disarm（commit `1f98b97`，10-16）
之后这一类 oops 再未出现 ⇒ disarm 确实消灭了「陈旧节点被重新插入」这条路径，
但**没有**消灭今日的纯自旋死法（两者机制不同）。

## 5. 打偏样本的页地址分布

| 结果 | page | 64K 对齐 |
| --- | --- | --- |
| 打偏 | `ffffff8819ee0000` | 是 |
| 打偏 | `ffffff884f1f0000` | 是 |
| 打偏 | `ffffff88d8370000` | 是 |
| 干净 | `ffffff890ddb8000` | 否（32K） |
| 干净 | `ffffff882aa00000` | 是 |
| 干净 | `ffffff8801a08000` | 否（32K） |
| 干净 | `ffffff87f33c0000` | 是 |
| 干净 | `ffffff8847838000` | 否（32K） |

3/3 打偏页是 64K 对齐，2/5 干净页也是 ⇒ **样本量不足以判定对齐是判别因子**，
但「打偏页全部 64K 对齐」值得下轮优先验证（若 `SKB_SEND_SIZE = 64 KiB` 而
`ORDER3_SIZE = 32 KiB`，泄漏页可能只是 64 KiB skb 块的一半，payload 落在另一半）。

## 6. 下一步（下个会话，按价值排序）

1. **造「读回」原语验证 craft 页**（最高价值）。现有 `rb_erase` 只能写 8 字节；
   无法确认 `fake_lock` 页里到底是什么。可选路径：把 `fake_lock->wait_lock` 指到一个
   可观测地址（如目标 cred 的 uid 字段），用写 0 的效果反推页内容是否为我们所写。
2. **验证 64K/32K 对齐假设**：把 `SKB_SEND_SIZE` 与 `ORDER3_SIZE` 的关系、以及
   `prepare_skb_payload` 的写入偏移核对一遍；若 payload 只覆盖 64 KiB 块的一半，
   则泄漏页落在上半区时全部指针都会指到填充区。
3. **缩短 spray→walk 窗口**：把 `prepare_kernel_page` 与 route 之间的日志/线程创建前移，
   route 内只留 `pselect`。
4. **页占用保持**：spray 后不把 ctx 页放回 buddy，减少复用机会。
5. **产品化兜底**：接受 ~25%/boot，做冷机重试循环（每轮 ~90 s）。

## 7. 本轮交付物

- 代码（全部 `TEMP(...)` 标记，可一键回退）：
  - `src/core/race/threads.cpp`：route 窗口心跳（`wd t=%dms alive` / `wd route-returned code=%d`）+ canary A/B
  - `src/core/route/select_stack_route.cpp`：`psel page=/lock=/w0=/task=/shift=` 镜像
  - `src/core/support/util.cpp`：reclaim send 计数（`step6 done ok=%d errno=%d`）
  - `src/core/session/backend/cve_2026_43499_backend.cpp`：`hold_after_route_if_requested()`（300 s 驻留，marker 文件控制）
- 证据：`build/510profile/{wd-150324,hit-151650,wdone-155629,wdone-160028}/`
- 门禁：`cmp_disasm`（8 个攻击函数计数不变，仅 `waiter_thread` / `run_main_route_threads` /
  `prepare_good_kernel_page` 因探针变化）+ NDK 零告警 + clang-tidy 0。
- 计划文档：`docs/analysis/marble-pselect-miss-rootfix-plan.md`（已回填 15:03 / 15:13–15:22 / 15:34–16:00 三节）。

## 8. 建议保留 / 删除

- **保留**：心跳 + `psel` 镜像（成本每 route 一行，是唯一能区分「route 未返回」与「整机冻结」的判据）。
- **删除**：canary B（无判别力）、`hold_after_route_if_requested`（仅 15:03 一轮用过，已完成使命）。
