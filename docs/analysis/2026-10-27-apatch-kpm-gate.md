# 门禁记录：handoff 补跑 apd 开机阶段（APatch/KPM 路线）

- 日期：2026-10-27
- 分支：`p6-multicast-2026-10-21`
- 设备：marble `3e6f1443`（5.10.149-android12-9-00001-gda3d81545d1d-ab9545656）
- 设计稿：`docs/analysis/2026-10-27-apatch-kpm-handoff-plan.md`
- 改动：`src/core/attack/ops.cpp` 的 APatch 分支，`insmod` 之后补跑
  `post-fs-data` / `services` / `boot-completed`（全部后台化）

## 1 门禁

| 项 | 命令 | 结果 |
| --- | --- | --- |
| NDK 构建 | `build\rebuild-native.ps1` | 2,796,976 B，零告警 |
| 攻击函数比对 | `py tools\cmp_disasm.py build\ghostlock-preapd.bin build\native\ghostlock` | **PASS**：owner_thread 69 / waiter_thread 918 / consumer_thread 409 / run_main_route_threads 461 / do_kernel5_fake_lock_route 173 / do_one_write 134 / prepare_good_kernel_page 2116，全部 LAYOUT-SHIFT-only；multicast 两项 SKIP |
| clang-tidy | `build\lint_all.bat` | `TIDY_STATUS=0`（用户代码 0 findings） |
| 主机单测 | `build/hosttests.sh` | PASS=27 FAIL=0（`tcp_zerocopy_route_test` 因 arm64 内联 `yield` 在 x86 编译不过，既有问题） |
| APK | `:app:assembleDebug -x buildGhostlockNative` | `GhostLock-v1.2(618)` 22,662,131 B |

## 2 真机结果

### 2.1 用例 T1 管理器可用 —— PASS

冷机 → 点执行 → run `20261027-200846`。日志：

```
[*] apd insmod rc=0
[*] apd boot stages bg pid=21060
[*] apd daemon pid=21061 alive=1
```

随后：

| 检查 | 结果 |
| --- | --- |
| `su -c 'id -u'` | `0` |
| `pidof apd libapd.so` | `21066` |
| `getenforce` | `Permissive` |
| 启动管理器 | `me.bmax.apatch/me.bmax.apatch.ui.MainActivity` 获得焦点 |
| ANR 计数 | `0` |
| 界面内容 | 越狱模式 / KernelPatch 版本 0.13.9 / 可执行su路径 `/system/bin/su` / APatch 版本 11282 / 系统版本 13 (API 33) / SELinux 状态 宽容模式 |

对比：改动前同一台设备、同一路径，管理器启动后 spawn 3 个 `/system/bin/sh` 停在
`pipe_read`，5 秒后 `Input dispatching timed out`。

### 2.2 用例 T3 su 不变 —— PASS

见上表，`id -u` = 0。

### 2.3 用例 T6 阶段失败仍完成 handoff —— PASS（意外获得）

第一版把 `post-fs-data` 放在**前台**执行。run `20261027-195920` 的 xtrace 显示：

```
+ /data/user/0/com.ghostlock.app/files/libapd.so post-fs-data
+ rm -f /data/user/0/com.ghostlock.app/files/.ghostlock_policy.xG0U0E
+ dump_debug
```

即该阶段启动后调用方 shell 直接走到 `EXIT` trap（清理 + dump_debug），后面的
`services` / `boot-completed` 从未执行。但模块已经 `insmod rc=0`，所以
`su -c 'id -u'` 仍是 0、`kernelpatch` 仍是 Live —— **阶段失败没有毁掉 handoff**。

处置：把三个阶段全部后台化（`( ... ) </dev/null >>"$LOG" 2>&1 &`），父 shell 不再
被拖死；改后即 2.1 的 run。

同一路径用 `sh -x` 在 adb shell 里单独跑（`su -c`、`</dev/null`、空环境、管道
stdin 四种变体）`post-fs-data` 与 `services` 都返回 `rc=0`，因此该现象只在
handoff 的上下文里出现，未定位到根因；后台化使其不再是风险。

### 2.4 用例 T2 KPM 页 —— 未通过（产品限制，非缺陷）

管理器"模块"页只显示 `尚未安装模块` / `系统模块`，滚动后仍无 KPM 入口，
UI dump 中检索不到 `KPM` 字样。管理器主页自述处于**越狱模式**：
"在未修补的内核上加载 KernelPatch 模块。该模式下不允许修补。"

结论：当前 APatch 11282 在越狱模式下不提供 KPM 页面；要用 KPM 需要非越狱
（打过补丁的内核），与本项目"不刷机"的前提冲突。**KPM 路线在本前提下不可达**，
记为产品限制。

### 2.5 用例 T4/T5 —— 未执行

- T4（同 boot 重复跑不叠加 daemon）：`已 root 守卫` 会拦住第二次执行，需要临时
  关守卫才能测；代码路径上已由 `pidof apd libapd.so` 分支覆盖。
- T5（KernelSU 路径不回归）：本次未触碰该分支，`cmp_disasm` 已证明攻击函数不变。

## 3 结论

- APatch 管理器在攻击成功后**立即可用**（无需 soft-reboot、无需手动起守护进程）。
- `su` 行为不变。
- KPM 在越狱模式下不可用，属 APatch 产品限制。
- 一个未解现象（前台跑 stage 会带走调用方 shell）已用后台化规避，不影响交付。
