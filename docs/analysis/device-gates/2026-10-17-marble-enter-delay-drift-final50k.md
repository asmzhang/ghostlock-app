# marble — enter_delay 配置漂移发现与 rounds-final50k 验证

日期：2026-10-17（审计驱动）
分支：`main-510-port`

## 结论

1. **发现配置漂移**：设备 App 的 SharedPreferences 用户覆盖（`debug_profile_overrides`）存有
   `execution.routes.select_stack.enter_delay_us = 150000`（10-15 enter150 实验遗留），
   压过 APK 内嵌 profile 的 50000，且 `adb install -r` 不清除 shared_prefs。
   最近三批（rounds-sprayprobe 90%、rounds-prebuilt A/B）**全部实际跑在 150000**。
   三批内部一致 ⇒ 已有的批次间对比结论（PREP-DEATH 0/40、p=0.0002）不受影响。
2. **清除覆盖后**实测 resolved = 50000（probe 轮 debug.execution 行确认）。
3. **rounds-final50k（20 轮，RebootEveryRound + RebootAfterHit）**：
   - HIT-ROOT（uid=0）= **14/20 = 70%**
   - 完整（hold=ok，v4.12 含 ksu-log 判据）= **14/20 = 70%**
   - PANIC 6/20：W1 miss ×3（r4/6/15）、W2 miss ×2（r3/16）、W2 页喷 prepare 死 ×1（r1）
   - PREP-DEATH（命中后的 W3-0 prepare 死）= **0/20**；三批合计 **0/60 vs 基线 7/20（p=0.0002）**
4. **50000 vs 150000 对比**：uid=0 = 14/20 vs 24/40，Fisher 单侧 p=0.32；W1 = 17/20 vs 30/40，p=0.30。
   **无统计显著差** —— 50000 与 150000 等价，60–70% 命中带是当前机制的水位。
   合并三配置 38/60 = 63%。

## 逐轮表

| round | verdict | W1 | W2 | W3 | hold | up_before | up_after |
|---|---|---|---|---|---|---|---|
| 1 | W1-OK | ok | entered | – | – | 59.41 | 154.44（死于 W2 页 prepare 的 early collision screen，pre-hit） |
| 2 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 61.33 | 90.12 |
| 3 | PANIC | ok | entered | – | – | 61.33 | 25.95 |
| 4 | PANIC | – | – | – | – | 61.37 | 24.40 |
| 5 | HIT-ROOT | ok | entered | ok | ok(pid) | 61.46 | 135.32 |
| 6 | PANIC | – | – | – | – | 61.33 | 24.83 |
| 7 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 61.66 | 93.28 |
| 8 | HIT-ROOT | ok | entered | ok | ok(pid) | 63.47 | 137.08 |
| 9 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 61.45 | 92.27 |
| 10 | HIT-ROOT | ok | entered | ok | ok(pid) | 63.42 | 137.32 |
| 11 | HIT-ROOT | ok | entered | ok | ok(pid) | 61.49 | 135.96 |
| 12 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 63.46 | 88.49 |
| 13 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 63.47 | 89.88 |
| 14 | HIT-ROOT | ok | entered | ok | ok(pid) | 63.62 | 137.65 |
| 15 | PANIC | – | – | – | – | 61.68 | 25.91 |
| 16 | PANIC | ok | entered | – | – | 63.60 | 25.42 |
| 17 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 62.85 | 96.33 |
| 18 | HIT-ROOT | ok | entered | entered | ok(ksu-log) | 61.34 | 90.97 |
| 19 | HIT-ROOT | ok | entered | entered | ok(pid) | 63.51 | 167.06 |
| 20 | HIT-ROOT | ok | entered | ok | ok(pid) | 63.51 | 138.25 |

up_after≈25 均为真 PANIC（内核按 panic_on_oops 重启）；命中轮 up_after 88–167 无一重启。

## 机制注释

- 覆盖存储位置：`/data/user/0/com.ghostlock.app/shared_prefs/ghostlock_prefs.xml` 的
  `debug_profile_overrides` 键（AndroidProfileConfigController.PrefDebugProfileOverrides）。
- 修复动作：删除该 XML（App 下次启动重建空文件）。**换设备/重装后需重新检查**该键。
- r1 的 prepare 死属于 pre-hit 的 KernelSnitch 扫描家族（W1 已落地、W2 页准备时死），
  与 prebuilt 修复针对的 post-hit W3-0 prepare 死是两类；后者三批 0/60。

## 环节水位定案（合并 60 轮）

| 环节 | 条件成功率 | 备注 |
|---|---|---|
| W1 落地 | ~75% | 最大单一杠杆；pselect 竞态未接住 ⇒ 设备重启 |
| W2 落地 | ~80% | 打偏同 W1 机制 |
| W3 完成 | ~59%→修后 ~95%+ | prebuilt 页修复（0/60） |
| 完整跑通 | **70%**（本批） | harness v4.12 判据 |
