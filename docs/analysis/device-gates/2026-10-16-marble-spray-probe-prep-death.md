# 2026-10-16 — 页准备死亡定位（spray_probe 面包屑批次）

## 结论

1. **PREP-DEATH 实锤并定位到 KernelSnitch early-collision-screen**。rounds-sprayprobe 批次 20 轮：
   18 HIT / 2 PANIC / 0 FREEZE。其中 **7 轮日志止于 `[spray] early collision screen N/3 at 37%`**
   （r2/3/9/12/13/14/17），此行打印于 step2b（children killed）之后、step4（mm-leak-scan）之前
   ——即 KernelSnitch 的碰撞筛选阶段。设备上 `.ghostlock_spray_probe` 的完整健康序列为
   `step1 → step2 → step2b → step4 → step6×4 → step7`，死亡轮缺其后各步 ⇒ 死点在 early-collision-screen。
2. **这 7 轮全部发生在 uid=0 已拿到之后**（W2 已成功写入 init_cred，summary 行都判 HIT-ROOT）
   ⇒ PREP-DEATH 不损失 uid=0，但损失 KernelSU handoff 与设备可用性（内核被楔死，需硬重启）。
3. **命中轮的 pselect 形状不变**：命中轮每 stage 1 开火 1 返回；打偏轮（r8/16）在
   `consumer call 1 entering sched_setattr` 后断流（与历史一致，waiter 词进 pselect 未返回）。
4. **0 FREEZE**：`-RebootEveryRound -RebootAfterHit` 协议下看门狗全程武装，不再出现
   「命中后 oops → 卡死」链（对照 calls1b 期 freeze 事件）。

## 判据表

| 项 | 值 |
|---|---|
| native | `build/native/ghostlock` 2786296 B，md5 `70454074DE35C7CE1F0376A309CAFA07` |
| APK | `GhostLock-v1.2(579)-arm64-v8a-debug.apk`，23184303 B |
| 设备 | marble `3e6f1443`，5.10.149-android12-9-00001-gda3d81545d1d-ab9545656 |
| 批次 | `build/510profile/rounds-sprayprobe/`（20 轮 full log + kernel.log） |
| 面包屑 | `files/.ghostlock_spray_probe`，`src/core/support/util.cpp` 的 `spray_breadcrumb()` |
| kmsg | 12 MB tail 全扫仅 1 条 oops：`rb_insert_color+0x48` ← `rt_mutex_adjust_pi` ← `sched_setattr`，fault addr **0xa**（此前为 0x8），boot 后 297 s，`kernelsu(O)` 已加载 ⇒ 命中后 boot |

## 机制注记

- PREP-DEATH 轮的统一死点在 **W3-0（leaf dir 探针）的页准备**里，不是 pselect：
  W3 写本身 100% 返回（历史批次 W3 三写 9/9、8/8、8/8），但首次生效仅 ~54% ⇒ 触发重试
  ⇒ 重试的页准备 = 又一次完整喷页 = 撞上 KernelSnitch 筛选阶段的死点。
- 与 pselect 打偏的差别：打偏死在 `sched_setattr`（waiter 词已进内核，PI 链损坏）；
  PREP-DEATH 死在 **clone/memfd/futex 风暴中的碰撞筛选**，此时 W1/W2 的残留 PI 损伤仍在。
- 上一个模型留下的 calls=1 A/B（W2 71% vs 38%，p=0.083）与"面包屑 fsync 时序效应"
  （本批 18/20 = 90% 命中，历史最高）**未分离**：面包屑的 open/fsync/close 加在
  prepare_kernel_page 的每一步，可能等效于又一次 wait_for_waiter_syscall 式门闩。
  下一批需做**空转面包屑**（写 /dev/null）的对照来分离。

## 下一步

1. 分离实验：面包屑写 `/dev/null`（保留时序、去掉 I/O），跑 20 轮对照。
   - 若命中率回落 ⇒ 面包屑 fsync 是新增益，值得产品化为可调时序垫片；
   - 若命中率不变 ⇒ 增益来自别的因素（如当日设备状态），A/B 才有效。
2. PREP-DEATH 修复候选（按死点）：
   - early-collision-screen 阶段降速/分批（`kernelsnitch_collisions` 8 → 4 已知 my2 验证值）；
   - 或在 W3 重试前**复用已持有页**（`HeapContext::held[24]`），跳过整段喷页。
3. harness：把「末行是 `[spray] …`」正式记为 `PREP-DEATH` 判定（已人工核过 7 轮）。

## 未决

- PREP-DEATH 7 轮的设备侧 oops 均未捕获（kmsg 环形被冲掉）⇒ 修复后需再跑一批并保留 kmsg。
- 面包屑时序效应 vs calls=1 效应未分离（上）。
