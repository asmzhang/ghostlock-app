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

### 2.4 用例 T2 KPM 页 —— 页面可达（初次判定有误，已更正）

初次判定写成"不可达"，是因为找错了入口：底部导航第一项（图标，`content-desc="内核模块"`，
bounds `[287,2213][353,2262]`）就是 KPM 页，而不是我先前点开的"模块"页（那是 magisk 模块）。

点进去后页面标题 `内核模块`、正文 `尚未加载模块`，无 ANR。管理器 APK 里也能找到
`KPModuleScreenDestination`、`KPMInfo(type=`、`kpm list:`、`.kpm`、`Invalid KPM` 等符号，
说明这是该版本自带的功能。

未验证：越狱模式下能否真正**加载** `.kpm`（需要先有一个 `.kpm` 文件，本轮没有）。
主页那句"该模式下不允许修补"限制的是修补（patch），不等于 KPM 页不可用。

### 2.5 用例 T4/T5 —— 未执行

- T4（同 boot 重复跑不叠加 daemon）：`已 root 守卫` 会拦住第二次执行，需要临时
  关守卫才能测；代码路径上已由 `pidof apd libapd.so` 分支覆盖。
- T5（KernelSU 路径不回归）：本次未触碰该分支，`cmp_disasm` 已证明攻击函数不变。

## 3 结论

- APatch 管理器在攻击成功后**立即可用**（无需 soft-reboot、无需手动起守护进程）。
- `su` 行为不变。
- KPM 页（"内核模块"）在越狱模式下可打开，显示空列表；能否加载 `.kpm` 未验证。
- 一个未解现象（前台跑 stage 会带走调用方 shell）已用后台化规避，不影响交付。
