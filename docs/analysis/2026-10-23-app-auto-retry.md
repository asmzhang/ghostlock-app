# App 内自动重试层（2026-10-23）

## 动机

marble 每轮攻击只有约 25–37% 能走到 handoff，打偏后设备会静默重启，人必须重新点一次
「执行」。目标：点一次之后，后续每次重启由 app 自己接着跑，直到拿到 root 或次数用尽。

## 实现（`app/src/main/kotlin/com/ghostlock/app/retry/`）

| 文件 | 职责 |
| --- | --- |
| `RetryStore.kt` | 计数器持久化到 `files/.ghostlock_retry.conf`（attempt/max/primary/consumer/shizuku/armed_at），写入用 `commit()` |
| `RetryRunner.kt` | `beginCycle()` 取号并落盘；`runOnce()` 加锁跑一轮；`onBoot()` 处理开机续跑 |
| `RetryJobService.kt` | `JobService`，`JobInfo.setPersisted(true)` + `setMinimumLatency(90s)` |
| `RetryAlarmReceiver.kt` | `AlarmManager` 精确/免打扰闹钟兜底（`setExactAndAllowWhileIdle`） |
| `RetryService.kt` | 前台服务（`specialUse` 类型 + 低优先级通知），承载 `runOnce()` |
| `BootReceiver.kt` | `BOOT_COMPLETED` → `RetryRunner.onBoot()` |

计数与停止条件：`max = 6`，`primary = 4`、`consumer = 5`（select_stack 的 CPU 对），
到 `max` 后清状态不再自启。手动点「执行」视为第 1 次。

## 已证实的部分

- 11:02:44 点「执行」，arm 成功（`attempt=1 max=6 armed_at=...`）。
- 11:03:14 设备重启后，**`attempt 2/6` 由持久化 job 自动拉起并跑完一整轮**，
  说明重试层本身工作正常（`files/.ghostlock_retry.log` 有记录）。

## 阻塞：MIUI 每次开机把 app 打成「受限」

证据（2026-10-23 11:12–11:18，两轮独立复现）：

```
dumpsys jobscheduler → Restricted packages:  u0a271 com.ghostlock.app
cmd appops get com.ghostlock.app RUN_ANY_IN_BACKGROUND
    → ignore; time=+2m16s ago          # +2m16s 正好等于开机时刻
am get-standby-bucket com.ghostlock.app → 5   # RESTRICTED
```

手动 `cmd appops set ... allow` 后，受限列表立刻清空、job 也能正常注册；
但下一次重启后 MIUI 又把它写回 `ignore`，同时：

- `JOB #u0a271/4713` 从 jobscheduler 里消失（持久化 job 被取消）；
- `BOOT_COMPLETED` 不投递（`BootReceiver` 没跑）；
- `AlarmManager` 的闹钟不跨重启保留。

结论：**在 MIUI 的受限策略下，app 无法靠自身在被杀/重启后复活**。这不是代码问题，
是设备电源策略。`am set-standby-bucket ... active` 与 `dumpsys deviceidle whitelist`
都改不动它（无权限 / 被 powerkeeper 覆盖）。

## 解除方式（一次性，用户操作）

设置 → 应用设置 → 应用管理 → GhostLock：

1. **省电策略 → 无限制**
2. **自启动 → 允许**
3. 最近任务里给 GhostLock 上锁（可选，防止清理）

做完后重新点一次「执行」，重试层即可跨重启接力。

## 备选

PC 侧 harness（`build/wd-round.ps1`、`tools/trials_ps4.ps1`）本来就是 adb 驱动重启 +
点击，不受 MIUI 限制；只是需要连电脑。
