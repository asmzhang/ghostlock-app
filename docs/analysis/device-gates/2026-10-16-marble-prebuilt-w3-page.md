# 2026-10-16 — W3-0 页前移（prebuilt）消除 PREP-DEATH

## 结论

1. **PREP-DEATH 7/20 → 0/20**（对照 `rounds-sprayprobe` 基线）。Fisher 单侧 p≈0.003，
   修复目标达成：W2 开火后的第一场 KernelSnitch futex 扫描（实测唯一死亡点）整段消失。
2. 本批 20 轮：**uid=0 12/20 = 60%**，完整 KernelSU（fork-hold parked）4/20 = 20%，
   PANIC 8/20，FREEZE 0。8 个 PANIC **全部**死在 pselect 打偏（W1×5、W2×3，
   末行一律 `consumer call 1 entering sched_setattr`），零死在页准备。
3. uid=0 60% vs 基线 90% 的差距落在 W1 固有打偏的噪音带内：W1 落地 15/20 = 75%
   （历史区间 60–90%，sprayprobe 恰是高点），p≈0.75、n=20 下 1.5σ，不显著；
   W2 落地 15/15 = 100% 未被新增的前置喷页干扰。
4. 机制证据链：20 轮中 15 轮打出 `W3-0 page prebuilt ok`（恰等于 W1 落地轮数），
   10 轮打出 `heap spray skipped (prebuilt W3-0 page activated)`——W3-0 的页准备
   从「W2 开火后的危险窗口」整体搬进了「W2 开火前的安全窗口」。

## 判据表

| 项 | 值 |
|---|---|
| native | `build/native/ghostlock` 2788472 B，md5 `1BB38C56D2C0054C0DFD96D51895DC0A`，零告警 |
| APK | `GhostLock-v1.2(580)-arm64-v8a-debug.apk`，22006074 B，md5 `CC9FB09DC6913894812E06618B0E7746` |
| 设备 | marble `3e6f1443`，5.10.149-android12-9-00001-gda3d81545d1d-ab9545656 |
| 提交 | 90% 基线钉住 `fb50d54`；本修复 `a82dc55` |
| 批次 | `build/510profile/rounds-prebuilt/`（20 轮 full log + summary + forensics） |
| 协议 | `-RebootEveryRound -RebootAfterHit`（up_before 全在 61–64 s ⇒ 隔离成立） |
| host 门禁 | WSL 27/27 + `host_attack_dataflow_test` ok |

## 机制注记

- 死点修订（推翻早前「重试 prepare 死」的判断）：7/7 PREP-DEATH 全部在
  **W3-0 attempt 1 的第一次 prepare**，即 W2 Credential 开火之后、任何 W3 开火之前
  的第一场 KernelSnitch 扫描。对照：W2 前同样的扫描 18/18 零死亡；W3 leaf 开火后的
  22+ 次重喷（TIF/mode 阶段）零死亡。危险窗口由「W2 已开火」界定，与重试无关。
- 修复（`prepare_prebuilt_leaf_page` / `consume_prebuilt_leaf_page`，`a82dc55`）：
  child task 确认后、W2 开火前喷好 W3-0 的 leaf 页并 stash 进 prebuilt；
  W3-0 attempt 1 的 attack_write 顶端匹配 Zero+leaf 且 target==fake_parent+8 时
  park W2 页 → 激活 prebuilt → 直接路由。attempts 保持 4（重试阶梯全在安全类）。
- 面包屑混淆未分离：PREP-DEATH 只在带面包屑的 sprayprobe 批次出现（此前 50 轮 0 次），
  面包屑 fsync 时序可能是把该窗口暴露出来的变量。prebuilt 方案不依赖该假设成立。
- 主机侧 `logcat -b kernel` 捕获在本设备为 0 字节 ⇒ 该取证通道无效；本批 0 PREP-DEATH
  故无需 oops 栈。

## 未决

- uid=0 60% 的样本噪音与真实回归未分离（一次只动一个变量的原则下，本批唯一变量是
  prebuilt，但 W1 打偏本身波动 ±2σ）。下一批若 W1 落地回到 ~90% 而 uid=0 不升，
  才需要怀疑 prebuilt 喷页改变了 W1 之后的堆状态。
- r13/14/19/20 的 HIT 轮 log 截断在 W3 段（v4.11 已知现象），4/12 命中带不来 KernelSU
  的原因未逐轮审计（基线同样 ~15% 命中无 KernelSU）。
