# Marble 收尾：20/20 实测、W3 假成功实证与已 root 守卫

日期：2026-10-26。设备：Redmi Note 12 Turbo（marble），
`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`，APK `1.2(603)`。

## 1 结论

手机端一键链路已经跑通并且可复现：点一次「执行」→ 关 SELinux 强制 → 换 root 身份 →
关 seccomp → 用 `libapd.so` 把 `kernelpatch.ko` 插进内核 → `su` 可用（`uid=0`、
`u:r:magisk:s0`）。全程不需要 PC，失败会自行重启再来一次。

最近 20 轮冷机连续实测 **20/20 完全成功**。其中 3 轮的第一遍 W3 写入是假成功，
被重试阶梯救回，见 §3。

尚未解决的只有「打偏」（pselect 打偏导致内核 wedge），见 §6。

## 2 实测数据

同一构建（APK 600/602/603，32-send reclaim，4 条 route）：

| 批次 | W3 重试 | 轮数 | 完全成功 | 死在 W3 | 打偏 |
| --- | --- | --- | --- | --- | --- |
| recheck-d | 1 | 10 | 9 | 1 | 0 |
| recheck-e | 1 | 10 | 8 | 2 | 0 |
| w3retry-a | 3 | 5 | 3 | 0 | 1 |
| w3retry-b | 3 | 10 | 9 | 0 | 1 |
| w3retry-c | 3 | 20 | **20** | 0 | 0 |
| 合计（重试=3 的子集） | 3 | 35 | 32（91.4%） | 0 | 2 |

重试=1 的 20 轮里出现 3 次 W3 假成功（15%）；重试=3 的 35 轮里 0 次未恢复。
20/20 的 Wilson 95% 下界约 84%。

## 3 W3 假成功：实证与修法

### 现象

两条 W3 写（`TIF_SECCOMP`、`seccomp.mode`）都报 `route_done status=0`，
但探针 `seccomp finit_module probe = 0xfffffffd` 说明进程仍被 SIGSYS 杀掉，
即两次写都没落地。两条一起失败，不是其中一条。

### 判据

`0xfffffffd` 在 `src/core/session/victim_process.cpp` 里被定义为「探针被信号杀死」。
单边失败会给出不同现象：只清 `TIF_SECCOMP` 不清 `mode` → 过滤器不跑、探针正常；
只清 `mode` 不清 `TIF_SECCOMP` → 下一个系统调用在 `__secure_computing` 里
`brk #0x800`（BUG）触发 panic。两者都没观察到，所以是同时失败。

已排除「抢页失败」：3 次失败轮的每一轮都 `reclaim sends ok=32/32 errno=0`。

### 修法

`stages.w3_attempts` 1 → 3（只改 profile）。`w3()` 的尝试循环每轮都会重新 craft
页并复验 `victim::verify_seccomp_probe_stage`，所以 1→3 等于给静默失败加两次
独立重抽。`w3_chain_rounds` 保持 1（那层要 `park_retry_child` 重开子进程，代价更大）。

### 实证（run 20261026-151042，20/20 批次的 r2）

```
W3: TIF_SECCOMP+mode attempt 1/3
  === W3: TIF_SECCOMP ===  ...
  === W3: seccomp mode ===  ...
  seccomp finit_module probe = 0xfffffffd      <- 假成功
W3: TIF_SECCOMP+mode attempt 2/3
  === W3: TIF_SECCOMP ===  ...
  === W3: seccomp mode ===  ...
  seccomp finit_module probe = 0x16            <- 成功
[+] child seccomp fully bypassed
[+] KernelSU ready
```

同一轮里 W1 也先失败一次（`attempt 1/15` → `attempt 2/15`）再成功，整轮仍然命中。
20 轮里有 3 轮走了这条路径（r2、r7、r20），全部救回。

## 4 已 root 守卫

历史记录里「命中后同一 boot 再跑会永久卡死」，所以重复执行必须被拦住。
两层守卫：

1. **native**（`src/core/session/backend/cve_2026_43499_backend.cpp` 的 `run_setup`）：
   `if (!force_attack && (ksu_root_owned() || kernelsu_module_visible()))` 直接
   `StageResult::Done`。原来只查 `su -c 'id -u'`，现补上「模块已加载」这一条，
   覆盖 handoff 刚完成、`su` 还没应答的那几秒窗口。`/proc/modules` 是
   `-r--r--r--`，非特权上下文也能读。
2. **app**（`GhostlockViewModel.runExploit`）：启动 native 之前读 `/proc/modules`，
   发现 `kernelpatch`/`kernelsu` 就写一行日志并弹 NOTICE，不启动 native。

真机验证（root 生效时点「执行」）：没有产生新的 run 目录，弹窗文案为
「已经是 root 状态 / 本次开机已经加载了 root 管理器模块……」。

## 5 失败形态与自愈

| 形态 | 占比（重试=3，35 轮） | 代价 |
| --- | --- | --- |
| 完全成功 | 32（91.4%） | 约 2 分钟 |
| 打偏 → 内核 wedge | 2（5.7%） | 厂商看门狗约 90 秒自重启 |
| W3 假成功未恢复 | 0 | — |

打偏轮没有 `SYSTEM_LAST_KMSG`（`panic_on_oops=0`，非 oops 路径），设备自行重启后
可以继续跑；不需要人工干预。

## 6 已知缺口

1. **打偏未根治**。已定性为「抢页失手」：`glk_lk` 探针读到 `lock` 地址等于我们
   算出的页基址，但 `*(lock+8)` 不是我们写的 `page+0x300`，说明该页内容不是我们的
   payload。加宽 reclaim（8 → 32 sends）后单轮命中率从 39% 提到约 90%，但仍有约 6%。
   进一步方向：验证 `SKB_DATA_DELTA`/`SKB_FRAG_BIAS` 这组偏移，或改成「不释放、
   直接用自己持有的页」。
2. **管理器界面刷新**。模块插进内核后，APatch/KernelSU 管理器通常要一次
   `apd soft-reboot` 才显示「已激活」；app 不做这一步，也不跳转管理器。
3. **app 内自动重试**被 MIUI 后台限制掐断，目前靠 PC 侧 harness 循环。

## 7 门禁记录

| 项 | 结果 |
| --- | --- |
| NDK 构建 | 2,793,352 B，零告警 |
| `tools/cmp_disasm.py` | PASS；7 个攻击函数指令数不变（仅 LAYOUT-SHIFT），multicast 两个 SKIP |
| clang-tidy（`build/lint_all.bat`） | `TIDY_STATUS=0`；改动文件 136 warnings 全在 non-user code，1 NOLINT |
| `:app:assembleDebug` | BUILD SUCCESSFUL，APK 22,072,444 B |
| 真机 | 20/20 完全成功；已 root 守卫真机验证通过 |

## 8 复现步骤

```sh
# 构建
powershell -File build\rebuild-native.ps1
Copy-Item build\native\ghostlock app\src\main\jniLibs\arm64-v8a\libghostlock.so -Force
.\gradlew.bat :app:assembleDebug -x buildGhostlockNative
adb install -r -d build\app\outputs\apk\debug\GhostLock-v1.2(603)-arm64-v8a-debug.apk

# 冷机单轮 / 多轮批测
powershell -File build\ab-rounds.ps1 -Rounds 20 -Tag w3retry-c

# 完全成功的判定
adb shell 'su -c "grep kernelpatch /proc/modules"'   # kernelpatch ... Live
adb shell "su -c id -u"                              # 0
adb shell "su -c id -Z"                              # u:r:magisk:s0
adb shell getenforce                                 # Permissive
```

## 附录 A 口径说明：本报告所有数字都是「无 app 内自动重试」

发布版 APK 不含 app 内自动重试层。2026-10-23 曾实现过一版
（`RetryStore` / `RetryRunner` / `RetryJob` / `RetryAlarmReceiver`），
实测被 MIUI 反复回收后台进程，最终没有合入发布构建（记录见
`docs/analysis/2026-10-23-app-auto-retry.md`），代码也已从工作树移除。

因此 §2 的每一轮都是「点一次，不成就得再点一次」：

| 口径 | 样本 | 结果 |
| --- | --- | --- |
| 单次点击（`w3_attempts=3`） | 35 轮 | **32 命中 = 91.4%**；2 打偏（5.7%）；1 没点着（2.9%） |
| 其中最新一批 | 20 轮 | 20/20 |
| 单轮耗时 | — | 约 2 分 04 秒 |

按独立伯努利估算的累积成功率：2 次点击约 99.3%，3 次约 99.9%。
打偏轮由厂商看门狗自动重启（约 90 秒），设备回来后重新点击即可；
**同一 boot 内不得重复点击**，这条已由 §4 的双层守卫强制。

「没点着」那一次是 PC 脚本的定位问题（锁屏遮罩或对话框挡住按钮），
人工目视点击不会出现，所以人工单次成功率应略高于 91.4%。
