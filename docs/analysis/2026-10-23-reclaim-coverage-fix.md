# marble 打偏根治：reclaim 覆盖不足（`SKB_RECLAIM_SENDS` 4 → 8）

日期：2026-10-23
设备：marble（Redmi Note 12 Turbo，`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）
构建：`GhostLock 1.2+592`，native `2792688 B`（2026-10-23 10:13:13）

## 1 结论

`SKB_RECLAIM_SENDS` 由 4 提到 8 后，第一批连续 3 轮全部走完 5 条 route 并到达 handoff，
W3 seccomp clear 由失败转为成功（probe `0x16`），其中一轮当场验到
`su -c id` = `uid=0(root) context=u:r:kernel:s0`、`kernelpatch 126976 Live`。

但第二批 5 轮全部死亡，**合计 8 轮 3 次 handoff（37.5%）**，说明提高覆盖只是把
「打偏」从 ~26%/route 压到 ~10%/route，并没有改变「一次打偏就整机冻结」这个性质。

| 构建 | 轮次 | 到达 handoff | W3 seccomp probe | 确认 root |
| --- | --- | --- | --- | --- |
| 4 sends（2026-10-22 16:40） | 5 | 1（20%） | `0xfffffffd`（失败） | 0 |
| 8 sends（2026-10-23 10:14，第一批） | 3 | 3 | `0x16`（成功） | 1（当场已验） |
| 8 sends（2026-10-23 10:28，第二批） | 5 | 0 | — | 0 |
| **8 sends 合计** | **8** | **3（37.5%）** | — | **1** |

## 2 机制

`prepare_kernel_page()` 的 reclaim 阶段把「按泄漏页地址烘焙好的 craft」塞进刚释放的整页里：

- 发送前 `prepare_ctx` 先归还整页，空闲整页池由 ~8 页升到 **~16 页**（`util.cpp` v4 注释）。
- 每次 `sendmsg` 64 KiB = **2 个 32 KiB 整页**。
- 4 sends ⇒ 只覆盖 **8 / 16 页**；泄漏页若不在被覆盖的那一半，craft 就没落到 walk 会读的那一页，
  walk 读到未映射/陈旧内容 → `rt_mutex_adjust_prio_chain` 解引用 `waiter->lock` → translation fault。
- 8 sends ⇒ 512 KiB < `SO_SNDBUF`(1 MiB)，覆盖 **16 / 16 页**，泄漏页必然被填。

这同时解释了两个此前的「独立」失败：

1. **打偏即死**：walk 读到未填充页 → 持锁自旋 → 整机冻结（无 oops、无 panic、~2–90 s 后被看门狗复位）。
2. **W3 写验证失败**（`finit_module probe = 0xfffffffd`）：seccomp 那次写用的是同一套 reclaim，
   覆盖不足时写没落到目标页，验证自然失败。

## 3 证据

第一批 run `20261023-101709` / `20261023-102203` / `20261023-102537`：

```
[spray] reclaim sends ok=8/8 errno=0 +857ms   (每条 route 一次)
[+] child is root!
seccomp finit_module probe = 0x16
handoff: root script path=.../.ghostlock_root.sh
handoff: root shell worker pid=25688
native exited code=0
```

`ok=8/8 errno=0` 全部满长度入队（短包会被计为 `errno=-1` 并 break，未出现）。

第一批之后当场验证：

```
$ su -c id
uid=0(root) gid=918198784(u9181_i8784) context=u:r:kernel:s0
$ su -c 'grep kernelpatch /proc/modules'
kernelpatch 126976 0 - Live 0x0000000000000000 (O)
```

第二批死亡点分布（面包屑）：

| 轮 | run | 死亡点 | 形态 |
| --- | --- | --- | --- |
| 1 | 20261023-103250 | 第 3 条 route（`mode=1`） | CMP errno=35 → 等 route_done 不回 |
| 2 | 20261023-103522 | W1 route（`ffffff802aa2fb98`） | 同上 |
| 3 | 20261023-103915 | `step2 prepare_ctxs`（W3 spray 中） | 无 route，死在碰撞筛选 |
| 4 | 20261023-104153 | `step2b children-killed`（`early collision screen 4/3 at 37%`） | 同上 |
| 5 | 20261023-104418 | 最后一条 route | CMP errno=35 → 等 route_done 不回 |

⇒ **死亡点从「只在 route」扩散到「route + spray」**，两类各占约一半。这意味着即使把
route 打偏率降到 0，仍有 ~40% 的轮次会在 spray 阶段死掉。

## 4 门禁

`py tools\cmp_disasm.py build\ghostlock-gh2-preprobe.bin build\native\ghostlock`：

| 函数 | 结果 | 说明 |
| --- | --- | --- |
| `owner_thread` | IDENTICAL (69, strict) | — |
| `waiter_thread` | IDENTICAL (918, strict) | — |
| `consumer_thread` | LAYOUT-SHIFT (409) | 仅地址操作数注释差异 |
| `do_kernel5_fake_lock_route` | LAYOUT-SHIFT (173) | 同上 |
| `do_one_write` | LAYOUT-SHIFT (134) | 同上 |
| `run_main_route_threads` | DIFF 414→461 | 2026-10-22 的 route 计时插桩（已复核） |
| `prepare_good_kernel_page` | DIFF 2104→2194 | 4 sends→8 sends 展开（+50）＋上一轮 reclaim 计数插桩（+40） |
| `multicast_*` | SKIP | 两侧均无 |

NDK 重建零告警；`util.cpp` 无新增告警；APK `22,246,566 B`（10:14:15）安装成功。

## 5 结论与去向

- 8 sends 是**真实改善**（W3 clear 由必失败变必成功；route 打偏率下降），但**不足以根治**：
  37.5%/轮 仍然意味着用户平均要试 2–3 次。
- 打偏一旦发生，内核持锁自旋、用户态无法回收（≤500 ms 整机冻结，SIGALRM 不可中断，34 次 0 EINTR），
  这是 PI-futex 原语的性质，**修不掉**。
- 因此方向应转为「**打偏之后自动重来**」：App 侧 `BOOT_COMPLETED` 自启 + 待重试标记 +
  失败判定（native 退出码 / `getenforce` / `su` 探测），把 37.5%/轮 变成 3 次重试 ~76%、5 次 ~91%。
- 次优先：减少 route 数量（5→4/3），乘法收益大于继续抠 per-route 概率。

## 6 待办

- [x] 8 sends 真机样本（8 轮）
- [ ] `SKB_RECLAIM_SENDS` 改为 profile 字段（当前是编译期常量）
- [ ] App 侧自动重试（`BOOT_COMPLETED` + 待重试标记 + 失败判定）
- [ ] 评估合并 W3 的两条 route
- [ ] 更新 `docs/analysis/marble-pselect-miss-rootfix-plan.md` 的批次 C/E 结论
