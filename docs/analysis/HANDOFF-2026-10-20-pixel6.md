# GhostLock 5.10 移植项目 — 交接文档（2026-10-19/20 深夜）

> 本文档是完整交接底稿。目标读者 = 接手的新会话/新工程师。
> 配套文档：`docs/analysis/5.10-marble-handoff.md`（marble 终章，第 15 节是最新状态）、
> `docs/analysis/device-gates/`（每次关键修复的门禁证据）、`build/510profile/`（全部批次日志）。

---

## 1. 项目一句话

把 GhostLock（CVE-2026-43499 exploit + Android App）从上游只支持 5.15 移植到 5.10 内核。
**marble（Redmi Note 12 Turbo, 5.10.149-android12）已完全成功并封版**；
**Pixel 6（oriole, 5.10.157-android13）适配进行中，卡在最后验证**。

- 仓库：`D:\work\1\ghostlock-main`，分支 `main-510-port`，已推送 GitHub（asmzhang/ghostlock-app）。
- 上游 = `origin/main`（YuKongA/ghostlock-app，C++23 重写）；本地 fork = asmzhang。
- `my2` 分支 = 旧 C 架构全量素材（只读参考），关键参考文件在 `build/510profile/my2_*_utf8.*`。

---

## 2. marble 成绩单（已封版，勿再动）

| 指标 | 数值 | 出处 |
|---|---|---|
| 冷启动 uid=0 | 60–70%（38/60 合并三配置） | final50k + prebuilt A/B |
| 完整 KernelSU | 70%（14/20） | rounds-final50k |
| APatch 全链 | 2/2 独立验证成功 | rounds-apatch5 r2 / apatch8 r1 |
| PREP-DEATH | 0/60（p=0.0002） | prebuilt 修复后 |
| FREEZE | 0 | 同上 |
| 打偏⇒重启 | 21/60=35%（W1 miss 13 + W2 miss 8） | 结构性，marble 无 ramoops 取证无解，已定性放弃，并入 P6 |

关键修复链（提交号）：
- `fb50d54` best-known-good 90% 配置（spray 面包屑 + fire 预算分离）
- `a82dc55` **prebuilt W3-0 页**（W2 安全窗制备，PREP-DEATH 根治）
- `4a13a29` prebuilt base=0 修复（prepare 后漏写 `heap.current.base`）
- `d577ef0` root script 按能力选 loader（APatch 臂永远走不到的 bug）
- `22f82e0` handoff 文档第 15 节终章
- 全部已推送（走本地代理 127.0.0.1:7890，github 直连不通）。

marble 设备 `3e6f1443` 当前离线。

---

## 3. Pixel 6 现状（接手人从这里开始）

### 3.1 设备与刷机状态

- 设备 `22251FDF60004E`，oriole，BL 已解锁，slot a。
- 官方 factory：`D:\BaiduSyncdisk\AndroidFlash\pixel6\android13\oriole-tq3a.230805.001-factory-18133fe9\oriole-tq3a.230805.001`，已完整刷过（2026-10-18）。
- **当前 boot_a = APatch 0.13.9 修补镜像**（`apatch_patched_11282_0.13.9_kosa.img`，用户手机上拿到的），**有 root**（su = uid=0 u:r:magisk:s0）。
- 原厂 boot.img 已提取：`build\oriole\boot.img`（67108864 B）——未刷回，留作还原。
- **内核 build 变了**：factory 00001 = `5.10.157-android13-4-00001-g5c7ff5dc7aac-ab10381520`（APatch 镜像就是基于这个）；此前 OTA 上的 00003 = `...-00003-g776d0a76f6aa-ab10208116` 已不在机器上。
- profile 已改名对准 00001（App 现在显示"受支持·配置已就绪"）。

**★ 用户明确的方法学裁定（必须遵守）**：APatch boot 上的 W1→W2→W3 全链验证**不作数**（KP 内嵌修补内核 + root 已存在 + handoff 会走错臂三重污染）。W1 地址数学验证可以在此环境做（写机制与 root 无关），**全链验收必须刷回原厂 boot 后做**。

### 3.2 根因链（最重要——接手人先读这段）

P6 首跑打偏（`heap spray done` 后无输出、设备重启）的排查史：

1. ~~VA_BITS 39/40 之争~~ → 伪问题（marble 也是 VA39，PAGE_OFFSET=0xffffff8000000000 通用）。
2. ~~KASLR 镜像 VA 反推 phys_offset~~ → 错误方法（kallsyms VA 是 KASLR 镜像映射，不是线性映射）。
3. ~~phys_load 盲扫 28 候选~~ → 方法论失效（phys_offset 恒错导致别名全错，扫描必然 miss）。
4. **✅ 真凶（root 取证实锤）**：extractor 推导的 `selinux_enforcing` 偏移 0x3195958 **不是 enforcing 标志**。5.10.157 里该符号不存在（只有 `selinux_enforcing_boot`，是 boot 参数持有者）。真 enforcing = `selinux_state@0x3195970` 的 **+1 字节** ⇒ 正确偏移 = **51992945**。
   - 佐证：首跑 W1 target 别名有效可写（28 轮零 oops = 写对了页），但写错标志 ⇒ clean miss/重启。
5. **phys_load 定论**：`/proc/iomem` 实测 Kernel code PA **0x80000000**-0x82c8ffff ⇒ `kernel_phys_load=0x80000000`（Tensor 与 QCOM 一样从 DRAM 基址加载）。`kernel_phys_offset=null`（runtime 按 Google soc 推 0x80000000）。
6. alias 数学：`alias = (phys_load + off − phys_offset) | 0xffffff8000000000`；init_cred image=0xffffffc082fffb58 alias=0xffffff8002fffb58 ✓（与 marble 成功日志同构）。

### 3.3 已落盘但尚未真机验证

profile（`app/src/main/assets/kernel_profiles/5.10.157-android13-4-00001-g5c7ff5dc7aac-ab10381520.conf`）：
- `kernel_phys_load = 2147483648`（0x80000000）、`kernel_phys_offset = null`
- `selinux_enforcing = 51992945`（selinux_state+1，新值）
- `init_cred = 50330496`（0x2FFFB80，extractor 原值低 0x28 已修——注意查一下这个修正是否已在 profile 里）
- route = multicast_waiter（select_stack 几何不可行：oriole 的 do_futex 帧 0x130 vs marble 0x70，waiter 落在 fd_set 窗口外 24 qwords）
- multicast 参数：waiter_off=136 / buffer_size=264 / task_offset=48 / lock_offset=56（编码门禁 200≤264 ✓）
- **⚠️ 最大遗留嫌疑（见 3.5）**

构建产物：APK v1.2(592+) 已含新 profile，装机完成。

### 3.4 真机操作手册（P6）

- 执行按钮 tap 坐标 **(540, 2176)**（UI dump 实测 [95,2110][985,2242]）；该坐标同时是"上次攻击未完成"对话框的关闭按钮。
- tap 后**必须验证 `.ghostlock_native.log` mtime 变化**才算 run 开跑（陈旧日志误读多次）。
- native 日志走 stdout 管道有 ~4KB 截断 ⇒ 关键路径用 `spray_breadcrumb()`（O_APPEND+fsync 到 `files/.ghostlock_spray_probe`），multicast route 已埋 `mcast pre-copy`/`mcast post-copy`/`mcast fire` 三个点。
- run-as 直读：`adb shell run-as com.ghostlock.app cat files/.ghostlock_native.log`。
- 设备时钟慢（显示 2023-06-23），mtime 对照用设备 `date +%s`。
- root 可用：`adb shell su -c '...'`（引号嵌套：PowerShell 里 `su -c "'echo 0 > /proc/sys/kernel/kptr_restrict'"` 双单引号）。
- kptr_restrict=0 后 `/proc/kallsyms` 可读（全量留档 `D:\work\1\_ghostlock_refs\oriole_kallsyms_root.txt` 27MB）。
- APatch su 授权弹窗按钮 resource-id 混淆，UI dump 看不到文字按钮，需人工点（已发生多次）。

### 3.5 下一步（按序）

1. **W1 地址验证（APatch boot，1–2 发）**：跑 exploit，判据 = 设备存活 + `getenforce` 变 Permissive ⇒ 地址数学正确。打偏 = 重启（无害，重来）。
   - 注意先确认 App 实际下发的 profile 值（p0 日志行 `kernel_phys_load=...`）= 0x80000000 而非旧的 0xa8000000（上一轮 run 是 reinstall 前的旧值；新 APK 已是 2147483648）。
2. **multicast 6.1 布局嫌疑排查（最强静态嫌疑，未排除）**：multicast 路由只在 5.15 硬件验证过（上游 CPP00-CPP17 门禁全是 A301SO 一台设备）；`encode_multicast_waiter` 只写 task/lock 两字、pi_tree_entry 全零，在 5.10 的 rt_mutex 语义下 RB_EMPTY_NODE 判定与 6.1 不同。marble 的 multicast 被编码门禁拒绝是"幸运失败"。**若 W1 过但 W2/multicast 段死，先查这里**。
3. **刷回原厂 boot**：`fastboot flash boot build\oriole\boot.img`（或 `fastboot flash boot_b` 先验 b 槽）。干净态下全链验收 = 项目交付形态。
4. **打偏取证（P6 独有优势）**：P6 有 ramoops（device-tree `ramoops_mem@fd3ff000`）——root 后可读，跨 reboot 保留。marble 上无解的"打偏⇒重启"取证在 P6 可行。取证器（`victim_process.cpp` 的 kmsg tailer）目前生于 uid=0 后；打偏 boot 依 ramoops 拿现场。
5. extractor 调试代码（derive.rs 的 eprintln）**未提交**，收尾时决定去留。

### 3.6 P6 与 marble 的差异速查

| 项 | marble | P6 (oriole) |
|---|---|---|
| 内核 | 5.10.149-android12 | 5.10.157-android13-4-00001 |
| BTF | 无 | **有**（CONFIG_DEBUG_INFO_BTF=y） |
| ramoops | 无 | **有**（fd3ff000） |
| soc 检测 | qcom/other → phys_load=0xA8000000（profile 硬编码） | Google → runtime 推 0x80000000 |
| 可行路由 | select_stack（multicast 被门禁拒） | multicast（select_stack 几何不可行） |
| 打偏后果 | 毒树 oops ⇒ 重启 | 首跑即重启（同 marble？未复验）|
| cred copy_size | 176 | 168 |
| task_struct 15 项 | ✓ | 与 marble 逐项相同 |
| kallsyms | root 后可读 | root 后可读（27MB 留档） |

---

## 4. 架构与关键代码地图（两设备通用）

### 4.1 代码骨架

- `src/core/main.cpp` → `run_orchestrated_pipeline`（CLI: `--ghostlock-app-call` / `--load-prebuilt-profile`）
- `src/core/session/backend/cve_2026_43499_backend.cpp` = 主后端：
  - `attack_write`（:487-518）= timer_mark + prepare_good_kernel_page + run_middleware_route
  - `w1()` = W1 SELinux（oracle 分支 GHOSTLOCK_PHYS_PROBE 门控）
  - `w2()` = W2 cred（先 `w2p`：prepare_prebuilt_leaf_page）
  - `w3()` = W3 seccomp 三写（leaf/TIF/mode），w3_attempts=0 早退分支仍在
  - `retry_write_stage`（:41-91）= attempts 循环 + slab_drain
- `src/core/support/util.cpp`：
  - `prepare_kernel_page`（:605-842）= park→cleanup→ctxs→KernelSnitch scan→base→skb payload→喷页
  - `prepare_good_kernel_page`（:844-889）= max_attempts 循环 + 双验收
  - `prepare_prebuilt_leaf_page`/`consume_prebuilt_leaf_page`（:891-918+）
  - `park_reclaim_page`（:569-583）= 退役页进 held[]（防 0x8 oops 的保活机制）
  - `spray_breadcrumb`（:589-603）= fsync 面包屑
  - `hold_reclaim_sockets_until_exit`（:298-348）= fork-hold 保活（P0-1）
- `src/core/route/multicast_waiter_route.cpp` = P6 主路由（`do_kernel5_fake_lock_route`）
- `src/core/route/select_stack_route.cpp` = marble 主路由（waiter_words 5.10 三态表）
- `src/core/memory/payload_builder.cpp` = `payload_write_layout`/`encode_multicast_waiter`/`encode_compact_waiter`/accepts_page 门禁
- `src/core/profile/binary.cpp` = GLK1 v2 字段表（与 Kotlin 键名逐字一致，AGENTS.md 强制）
- `src/core/session/victim_process.cpp` = child 进程管理 + handoff + kmsg tailer + boot_id oracle
- `src/core/attack/ops.cpp` = perf 泄漏（kPerfDataPages=256, 候选池 8192）+ write_root_script（490 行内嵌 shell，APatch/KernelSU 双臂）
- `tools/extract_rs/` = Rust 偏移提取器（kallsyms 恢复 + 帧深推导；`derive.rs` 有未提交的调试 eprintln）
- `tools/trials/trials_ps4.ps1` = marble 批量 harness v4.13；`p6_phys_scan.ps1` = P6 扫描器；`apatch_finish.ps1` = APatch 收尾
- `tools/trials/analyze_batch.ps1` = 批次统计

### 4.2 构建命令（可复现，全部验证过）

```powershell
# native（必须剔 mise、补 git）
$env:PATH = "D:\platform\Git\cmd;D:\platform\Git\usr\bin;C:\Users\Administrator\.cargo\bin;" + (($env:PATH -split ';') | Where-Object { $_ -notmatch 'mise' }) -join ';'
$make = "C:\Users\Administrator\AppData\Local\mise\installs\make\4.4.1\.mise-bins\make.exe"
& $make -C src ghostlock NDK_ROOT="D:/platform/Android/Sdk/ndk/28.2.13676358"
Copy-Item build\native\ghostlock app\src\main\jniLibs\arm64-v8a\libghostlock.so

# APK（跳过 gradle 的 native 任务——它会崩）
.\gradlew.bat :app:assembleDebug -x buildGhostlockNative --no-configuration-cache

# host 测试（必须 WSL，Windows llvm-mingw 缺头文件）
wsl -d Ubuntu-24.04 -- bash -c "make -C src native-host-tests"   # 或 bash build/run_host_tests_510.sh

# 装机
adb -s 22251FDF60004E install -r "build\app\outputs\apk\debug\GhostLock-v1.2(592)-arm64-v8a-debug.apk"  # 路径含括号要引号
```

### 4.3 profile→native 值流（改 profile 前必读）

HOCON asset → `BuiltinProfileCatalog.flatten()` → Kotlin 校验门禁（`AndroidProfileConfigController.validateProfileFields`：10 项 requireNonZero、kernel_major∈{5,6}、multicast 门禁 136+56+8≤264）→ `NativeProfileDocument.routeSection()` 写 GLK1 → native `kRouteMulticast` 读入。
**大数坑**：>Long.MAX 的 u64 用负数位等价编码（`NativeProfile.kt:327` raw=toULong 位保持）。
**SharedPreferences 坑**：`debug_profile_overrides` 会压过 APK 内嵌 profile 且 `adb install -r` 不清（marble enter150 事故根因）。设备侧清法：`su -c 'rm /data/user/0/com.ghostlock.app/shared_prefs/*.xml'`。

---

## 5. 历史教训清单（防再踩）

1. **单次 panic 不得归因代码**（上游 KERNEL-PANIC-01）——同构建 PASS/panic/PASS。
2. **静态分析只产出否定**——时序/概率/运行时内存必须真机 A/B；一次只动一个变量 + 足够样本。
3. **判据文件必须每轮清**（v4.11/v4.13 两次"陈旧产物假判据"事故）。
4. **kmsg tailer 生于 uid=0 后** ⇒ 打偏 boot 零内核日志（marble）；P6 靠 ramoops 破局。
5. **fd 位图=fd_set 词值**——W2 的 0x0930 点亮 fd 4/5 ⇒ reserve_low_fds 全位图 park + raise_pipe_fd。
6. **perf ring 必须 256 页**（32 页时 99.9% 采样丢失 ⇒ child_task 是垃圾 ⇒ W2 写随机地址）。
7. **W3 leaf 写第一枪就消费页内黑节点** ⇒ 同请求 fired 后绝不能复用页（freeze 机制本身）。
8. **prebuilt 页必须写回 heap.current.base**（4a13a29）。
9. **kallsyms VA ≠ 线性映射 VA**（P6 phys_offset 弯路根源）。
10. **APatch boot 上的全链验证不作数**（用户裁定，本文档 3.1）。
11. fastboot 相对路径必须先 cd 到镜像目录；`adb shell` 内嵌引号在 PowerShell 5.1 极易翻车（grep 多模式必拆）。
12. 设备时钟漂移（P6=2023-06-23），mtime 判断用设备 date。

---

## 6. 未决问题（按优先级）

| # | 问题 | 状态 |
|---|---|---|
| 1 | P6 W1 地址验证（selinux_enforcing=51992945 已入 profile，未实测） | **立即做** |
| 2 | multicast 的 6.1 compact 布局在 5.10 的语义嫌疑 | W1 过后立即查（3.5-2） |
| 3 | 原厂 boot 还原 + 干净态全链验收 | 交付前必做 |
| 4 | P6 打偏取证（ramoops） | root 已就绪，待做 |
| 5 | extractor 调试代码去留 | 收尾提交前 |
| 6 | `docs/analysis/device-gates/2026-10-19-pixel6-root-forensics.md` 含旧 phys_offset 结论 | 需按新认知修订 |
| 7 | marble 打偏⇒重启（35%） | 已定性放弃，并入 P6 #4 |
| 8 | 上游 PR 是否开 | 用户决定（建议暂不开） |

---

## 7. 环境速查

- adb：`D:\platform\Android\Sdk\platform-tools\adb.exe`
- 设备：P6 `22251FDF60004E`（在线）；marble `3e6f1443`（离线）；HNKOZ `AEUN9X1723G05852`
- NDK 28.2.13676358；rustc 1.98.1；python 3.12.13；WSL Ubuntu-24.04（host 测试）
- GitHub 推送走代理 `127.0.0.1:7890`（`git -c http.proxy=http://127.0.0.1:7890 push`）
- P6 取证留档：`D:\work\1\_ghostlock_refs\{oriole_kernel_image.bin, oriole_kallsyms_root.txt, oriole_iomem_root.txt, oriole_config_root.txt}`
- marble 取证留档：`build/510profile/marble_iomem.txt`、`marble_dmesg.txt`
- 关键批次日志：`build/510profile/rounds-*`（marble 20+ 批）、`build/oriole/scan-results.txt`（P6 盲扫）
