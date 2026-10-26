# 设计：root 管理器选择（module_loader）

状态：设计稿，待批准后实现。级别：**L**（profile/wire 新字段 + 跨 Native↔Kotlin 契约）。
分支：`marble-closeout-2026-10-25`。

## 1 问题

两件事是同一个根：

1. **用户无法选择用哪个 root 管理器**。当前 loader 是硬编码优先级，用户没有任何入口。
2. **APatch 管理器打开即「没有响应」**（2026-10-26 实测，见 §2）。

原因在于：选择的对象被实现成了「用哪个 loader 二进制插模块」，而真正决定用户体验的是
「**插进去的是哪个管理器的内核模块**」——管理器的界面能不能用，取决于模块的
name / 协议 / 版本，而不是取决于谁把模块插进去。

## 2 实测证据：APatch 无响应

设备 marble `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`，设备已由 GhostLock 取得 root。

| 事实 | 值 |
| --- | --- |
| APatch app | `me.bmax.apatch`，`versionName=9a63e0f`，`versionCode=11224`，`lastUpdateTime=2023-12-19`，uid 10270 |
| 已加载模块版本 | `/sys/module/kernelpatch/version` = **0.13.8** |
| 随包模块 | `app/src/main/assets/kernelpatch/android12-5.10_kernelpatch.ko`，183,312 B，模内 `version=0.13.8`，`vermagic=5.10.252-dirty` |
| **APatch 自带的同名资产** | APK 内 `assets/android12-5.10_kernelpatch.ko` = 138,864 B，模内 `version=`**0.13.3**，`vermagic=5.10.252-dirty` |

两者确实是同一个上游模块的两个不同构建（`kernelpatch-lkm` 日志前缀 81 vs 116 处，KPM 12 vs 14 处），
**版本 0.13.3 与 0.13.8 不一致**。APatch app 的 `libapd.so` 也是它自己的（3,969,440 B），与随包模块的
协议版本不匹配。

### ANR 形态

打开 app 后弹「**APatch没有响应**」（等待 / 确定）。logcat：

```
ANR in me.bmax.apatch (me.bmax.apatch/.ui.MainActivity)
Reason: Input dispatching timed out (... Waited 5000ms for FocusEvent(hasFocus=true))
```

`/data/anr/anr_2026-10-26-16-16-09-435` 里主线程栈（`TimedWaiting`）自下而上：

```
ActivityThread.main -> Looper.loop -> Handler.handleCallback -> ne.run -> oe.K
  -> be0.run -> jo.g -> f10.t -> os2.e -> u1.<clinit>          <- 类静态初始化
  -> ky.f -> ut.a -> ut.c -> ut.b -> xl2.<init>
  -> FutureTask.get -> FutureTask.awaitDone -> LockSupport.parkNanos -> Unsafe.park
```

即某个类的 `<clinit>` 里 `FutureTask.get()` 无限等待 —— 不是在等输入，是初始化期就卡死。

排除项：

- 不是 su 授权问题：`/data/adb/ap/package_config` 里已有
  `me.bmax.apatch,0,1,10270,0,u:r:magisk:s0`。
- 不是内核通道坏死：`apd module list` 正常返回 JSON（能看到 `ghostlock-panic` 模块）；
  `apd -V` 正常返回 `apd 11107`。
- 但 `apd boot-completed` 打印 `[start_uid_listener] Registering...` 后**永久挂起**（>300 s 未返回，
  残留进程被 reparent 到 init，已清理）。这条正是 app 启动路径会走的一类调用。

结论：**模块与 app 版本错配**，app 在初始化期等一个永远不会来的应答。用我们随包的
0.13.8 模块，旧版 APatch app 的界面就不可能可用。

## 3 目标

1. 用户能明确选择用哪个 root 管理器加载模块，选择随 profile 持久化、可导出。
2. 选中的管理器**之后能正常打开**，不出现 ANR。
3. 不引入新的 profile 格式版本号（仍为 v2，见 AGENTS.md）。
4. 失败可解释：日志与 UI 都要说明「用了哪个模块、来自哪里、是否与原厂匹配」。

## 4 设计

### 4.1 选择对象改为「模块来源」

`execution.handoff.module_loader`，枚举 `auto | apatch | kernelsu`，默认 `auto`。

| 取值 | 行为 |
| --- | --- |
| `apatch` | 用 `apd` 的 `insmod` 插入 **APatch app 自带**的 `assets/android12-5.10_kernelpatch.ko`；读不到才回落随包资产，并在日志与 UI 标注「随包模块，管理器可能不识别」 |
| `kernelsu` | 走 `ksud late-load --kmi <kmi>`，由 KernelSU 自行匹配模块 |
| `auto` | 按 4.2 的可用性顺序自动挑 |

模块来源的解析放在 Kotlin（`AndroidGhostlockRepository.prepareKpatch`），因为只有它有
`PackageManager`；native 只按已有约定读 `$HOME_DIR/kernelpatch.ko` 与 `$HOME_DIR/ksud`，
脚本里的 loader 选择改为读 profile 字段，不再「APatch 永远赢」。

### 4.2 auto 的判定顺序

1. APatch 已装 **且** 能读到它自己的 ko → `apatch`；
2. KernelSU 系（`me.weishu.kernelsu.pr` / `me.weishu.kernelsu` / `com.resukisu.resukisu` /
   `com.kowx712.supermanager`）已装 → `kernelsu`；
3. APatch 已装但读不到自带 ko → `apatch`（降级用随包模块，明确告警）；
4. 都没有 → 不加载模块，只完成 W1/W2 拿到 uid 0（与今天行为一致）。

第 1 条优先于第 2 条，是因为「模块与 app 匹配」比「哪个管理器更新」更决定可用性；
第 3 条排最后，是因为它必然让管理器界面降级。

### 4.3 触点清单（实现时只碰这些）

| 层 | 文件 | 改动 |
| --- | --- | --- |
| Profile 模型 | `src/core/profile/model.h` | `HandoffConfig` 增 `ModuleLoader` 枚举 + 字段 |
| Profile 二进制 | `src/core/profile/binary.cpp` | 字段表加一项（与 Kotlin 键名逐字一致） |
| Native 脚本 | `src/core/attack/ops.cpp` | loader 选择改读 profile 字段；`auto` 时保留现有 fallback 但去掉「APatch 无条件优先」 |
| Kotlin 契约 | 对应 route config 的 `entries()/apply()/from()` | 同键名同步 |
| Kotlin 备料 | `AndroidGhostlockRepository.prepareKpatch` | 按选择取模块来源；新增「读 APatch 自带 ko」 |
| App UI | 执行页 + profile 编辑器 | 一行只读摘要 + 选择入口 |
| 文档 | `docs/kernel_profiles/PROFILE_SCHEMA*.md`、`defaults*.md`、`README` | 新字段与语义 |

双侧一致性由既有测试抓（`route_catalog_test.cpp` / `RouteCatalogAgreementTest.kt` 的同类断言）。

### 4.4 UI

执行页「执行」按钮上方一行：

```
模块：APatch（app 自带）      >  选择
```

点进去是三选一（自动 / APatch / KernelSU），每个选项下标明当前可用性与后果，例如：

- `APatch  可用（app 自带模块，界面正常）`
- `APatch  降级（将使用随包模块，管理器界面可能无响应）`
- `KernelSU v3.3.0  可用`
- `自动  当前会选 APatch（app 自带模块）`

选择写入当前 profile 并随 profile 一起导出，不另建配置通道（AGENTS.md：配置权威是
GLK1 profile + HOCON，执行层不读配置类环境变量）。

### 4.5 明确不做

- 不自动跳转管理器，不替用户执行 `apd soft-reboot`（README 已说明管理器需一次框架重启）。
- 不引入 profile v3/v4。
- 不尝试「修复旧版 APatch app」，那是上游兼容问题；我们只负责选对模块。

## 5 验证计划

| 项 | 判据 |
| --- | --- |
| `module_loader=apatch`（app 自带 ko） | root 成功；打开 APatch **无 ANR**，模块列表可见 |
| `module_loader=kernelsu` | root 成功；打开 KernelSU 显示已激活 |
| `module_loader=auto` | 按 4.2 选出预期项，日志打印来源 |
| 双侧一致性 | profile 二进制字段表与 Kotlin 键名逐字一致，测试通过 |
| 回归 | `make -C src native-host-tests`、NDK 零告警、`TIDY_STATUS=0` |
| 攻击路径 | `cmp_disasm` 对 8 个攻击函数 PASS（本改动不碰攻击函数，预期仅 LAYOUT-SHIFT） |
| 真机 | 每形态各 3 轮冷机，记录开关管理器后的表现 |

## 6 风险

1. **Kotlin 读别的 app 的 assets**：`getResourcesForApplication` 在 Android 13 上不需要额外权限，
   但 APatch 若把资产放在 split APK 里会读不到 —— 需要回落路径（已有 4.2 第 3 条）。
2. **`ksud late-load` 需要网络**：它可能要下载匹配的 `kernelsu.ko`；离线时应报错而不是挂起。
3. **模块 already-loaded 分支**：脚本里原有的「已加载则跳过」逻辑必须保留，否则会重复打补丁
   （这正是 10-26 新增已 root 守卫要防的场景）。
