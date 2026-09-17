# Harness 配置与可移植性审计（2026-09-17）

> 审计对象：`tools/harness/*`、`Makefile`、`build.sh`、`tools/build_apk.sh`、`tools/kernel_verify.py`、
> `tools/probe_tcp_route.*`、`build.gradle.kts`、`docs/*` 中的构建/运行入口。
> 目标：回答"配置放哪、怎么传、换电脑会不会坏"，并给出解耦/模块化/可移植的落地方案。
> 路径写法遵循仓库约定：`<REPO>`=本仓根、`<WORK_DIR>`=运行层（harness 的 `WORK_DIR`）。

## 0. 结论摘要

1. **`gl_tuned.env` 不进仓库是对的**（它是设备相关运行期产物），**但它的闭环是断的**：
   全仓只有 `tools/harness/run.sh:120` 写它，**没有任何脚本读它**；`run.sh:3` 注释与
   `docs/MARBLE_RESTORE_2026-09-15.md:88` 所说的 "USE 模式" 在当前 harness 中**不存在**。
   ⇒ 所谓"命中后锁参"目前只是留档，不产生行为。
2. **换电脑会坏的点是硬编码工具链路径**（5 处，P0），以及 **`timeout`/`md5sum` 在 macOS 不可用**
   （`timeout` 出现 34 次、`md5sum` 12 次）。
3. **核心模块化已经不错**：`env.sh` 已把设备探测与目录推导集中（曾经的 5–9 处重复已消除），
   8 个脚本统一 `source env.sh`；问题集中在"离群脚本 + 常量内联 + 平台工具"三处。

## 1. 为什么 `gl_tuned.env` 不放在 `<REPO>` 内

**设计理由（成立）**

- 它是**运行期产物**：TUNE 命中时才写入，内容随设备/时序变化（`SHIFT/CORE/CCORE/DATE`）。
- 它是**设备相关状态**：同一份源码在不同设备上锁出的参数不同，不该跟源码走。
- 边界一致性：仓库要能公开（已做"零本机信息"净化），而该文件天然携带本机路径与时间戳。
  历史命中证据里那份 `artifacts/2026-09-15/gl_tuned.env` 是**证据归档**，不是活动配置。

**问题（必须修）**

| 现状 | 影响 |
|---|---|
| 只写不读 | "锁参复跑"能力实际上不存在，命中后的参数只能靠人肉复制 |
| 无 schema/校验 | 手改一个非法值不会被发现 |
| 与 `<WORK_DIR>` 强绑定 | 换机后若把素材放别处，需要同时改 `GHOSTLOCK_WORK` 与约定 |

## 2. 参数传递链（现状）

```
L3 内置默认        env.sh 自动探测：DEV(按型号 marble) / PROJECT_DIR(脚本位置反推) /
                   WORK_DIR(=PROJECT_DIR 的上一级) / BIN·KO·KSUD·KSUN(由上述推导)
L2 脚本内置默认     run.sh:16,59,20 SHIFT=-2  ROUNDS=10  REBOOT_EVERY=0  CORE/CCORE=设备频率探测→4/5
L1 环境变量覆盖     SHIFT/CORE/CCORE/ROUNDS/REBOOT_EVERY/OWNER/GHOSTLOCK_DEV/GHOSTLOCK_WORK/
                   GHOSTLOCK_BIN/GHOSTLOCK_KO/GHOSTLOCK_KSUD/GHOSTLOCK_KSUN/GHOSTLOCK_LOGDIR
L0 运行期下发       run.sh:115 把 exploit 语义常量**内联写死**后随 adb shell 下发：
                   GHOSTLOCK_SKIP_POLICY_FIXUP=1 LAYOUT=A SELF_W2=1 INSMOD_ONLY=1 HOLD=1
写回（无人读）      run.sh:120 命中 → 写 <WORK_DIR>/gl_tuned.env（TUNED）
```

要点：**L0 里的 exploit 语义与 harness 逻辑耦合**——想改布局/自 W2/只加载模块等行为，必须改脚本源码；
**L1 缺一个"本机配置文件"层**，所有覆盖只能靠临时 `export`，换机后没有可复现的落点。

## 3. 审计发现（按严重度）

### P0 —— 换机/换平台即坏，或功能缺失

| # | 位置 | 事实 | 换机影响 |
|---|---|---|---|
| P0-1 | `run.sh:120` ↔ 全仓 grep | `gl_tuned.env` 只写不读，USE 模式不存在 | 命中后无法一键复跑 |
| P0-2 | `tools/harness/preflight.sh:2` | `BIN=<NDK>/.../<prebuilt>/bin` 写死 | 任意换机/换 NDK 版本/换平台都坏 |
| P0-3 | `Makefile:5,7,12` | 兜底 `D:/AndroidSDK/ndk/*`；`PREBUILT` 只有 windows/linux，**无 darwin** | macOS 无法构建；本机路径兜底会误导 |
| P0-4 | `tools/kernel_verify.py:72`、`tools/probe_tcp_route.sh:26,29,30` | 默认 `<SDK>`，写死 `<prebuilt>`、clang35/34 | 偏移提取/路由分析在新机器不可用 |
| P0-5 | `tools/harness/*` 统计 | `timeout`×34、`md5sum`×12 | macOS 默认无 `timeout`（需 `gtimeout`）、无 `md5sum`（需 `md5 -q`） |
| P0-6 | `build.gradle.kts:51` | `prebuilt` 仅 windows/linux | 同 P0-3 |

### P1 —— 一致性 / 边界破损

| # | 位置 | 事实 |
|---|---|---|
| P1-1 | `tools/harness/stats.sh` | 在**自身目录** glob `gl_*.out`，而日志实际在 `<WORK_DIR>` 且名为 `gl_tune_r<N>.log` ⇒ **该脚本已失效**（WORK_DIR 重构后未同步） |
| P1-2 | `harvest.sh:39-44`、`retry.sh:27-31` | 直接硬编码 `/data/local/tmp`，未用 `env.sh` 已定义的 `$D_TMP`（边界破口，改设备侧目录要改多处） |
| P1-3 | `run.sh:115` | exploit 语义常量内联（见 §2 L0） |
| P1-4 | `run.sh.bak`、`run.sh.bak2` | 与 `run.sh` 近乎重复（差异是 `GHOSTLOCK_OWNER=fake`）；跟踪入库 ⇒ 漂移与误用风险 |
| P1-5 | 各脚本 | 无参数校验、无 `--help`/`--dry-run`/`--print-config`；`ROUNDS=abc` 之类会静默走偏 |
| P1-6 | `tools/harness/check.sh:27` | `stat -c%s`（GNU）在 macOS 不可用（需 `stat -f%z`） |

### P2 —— 打磨项

| # | 位置 | 事实 |
|---|---|---|
| P2-1 | 全仓 `adb`×114 | 假设 `adb` 在 PATH，无校验/无 `ADB` 覆盖；离线脚本（`stats.sh`/`preflight.sh`）也依赖 |
| P2-2 | `env.sh:64-66` | 设备侧根路径 `D_TMP/D_SDCARD/D_AP` 集中但**不可覆盖**（建议支持 `GHOSTLOCK_D_TMP` 等） |
| P2-3 | `docs/*`、`README*.md` | 大量写死工具链绝对路径与 NDK 版本；`python` 与 `python3` 混用（34 vs 14） |
| P2-4 | `tools/copy_len.py:18` | 注释引用本机 `<LLVM_MINGW>/...`（无害但属本机信息） |
| P2-5 | `run.sh` / `shift_scan.sh` / `retry.sh` | 日志命名不统一（`gl_tune_r*.log` / `gl_scan_*.log` / `gl_retry_r*.log`） |

## 4. 目标架构（解耦 · 模块化 · 边界 · 跨平台）

### 4.1 配置优先级（四层，单一来源）

```
L0  CLI / 环境变量       一次性覆盖（最高优先）
L1  <WORK_DIR>/gl_local.env    本机配置（不进库）：设备序列号、NDK、素材路径、常用开关
L2  <REPO>/config/harness.example.env   入库示例：全部键 + 默认值 + 说明（零本机信息）
L3  env.sh 内置默认 + 自动探测（设备型号/频率/目录推导）
                    ↓
          唯一配置对象（env.sh 导出）→ 各脚本只消费，不再自带默认值
```

### 4.2 模块边界

| 模块 | 职责 | 不做 |
|---|---|---|
| `config.sh`（新） | 读 L1/L2、校验、`--print-config`、`--dry-run` | 不探测设备、不跑 adb |
| `env.sh` | 设备探测、目录推导、导出配置对象 | 不含平台命令分支 |
| `platform.sh`（新） | `md5_of()`、`timeout_cmd()`、`stat_size()`、`ndk_prebuilt_dir()`、`host_os()` | 不关心业务语义 |
| `run.sh`/`watcher.sh`/... | 只做流程 | 不再出现字面量路径/常量 |
| exploit 开关 | 全部列在 L2 示例文件里，由 `run.sh` 组装下发 | 不写死在脚本中 |

### 4.3 跨平台要求

- `PREBUILT` 用**目录探测**（windows / darwin / linux 三种宿主各取实际存在的那个），不写死；
- `timeout` → `timeout_cmd()`（`timeout` 或 `gtimeout`）；`md5sum` → `md5_of()`（`md5sum` 或 `md5 -q`）；
- `stat -c%s` → `stat_size()`；`python` → `PYTHON=${PYTHON:-python3}` 统一；
- 脚本一律 LF（仓库 `* text=auto` 已保证），Windows 侧编辑后需确认未被转成 CRLF；
- NDK 定位顺序：`ANDROID_NDK_HOME` → `ANDROID_NDK_ROOT` → `ANDROID_HOME/ndk/*` → `LOCALAPPDATA/Android/Sdk/ndk/*`
  （**移除** `D:/AndroidSDK` 这类本机兜底）。

## 5. 换机清单（照着做即可迁移）

1. 装 `adb`（在 PATH）、NDK（设 `ANDROID_NDK_HOME`）、`python3`；Linux/macOS 另需 `coreutils`
   （macOS 建议 `brew install coreutils` 提供 `gtimeout`/`md5sum`，或依赖 `platform.sh` 降级）。
2. 克隆仓库到任意位置；把 `android12-5.10_kernelpatch.ko`、`libksud.so` 放到**仓库的上一级**
   （或设 `GHOSTLOCK_WORK=<素材目录>`）。
3. 复制 `config/harness.example.env` 为 `<WORK_DIR>/gl_local.env`，填入设备序列号/路径。
4. `bash tools/harness/run.sh`（TUNE）＋另起 `bash tools/harness/watcher.sh`；命中后
   `bash tools/harness/finish.sh` 收尾。

## 6. 落地计划（分批、可回滚、每步可验证）

| 批次 | 内容 | 验证方式 |
|---|---|---|
| P0-A | 新增 `platform.sh`（md5/timeout/stat/ndk 探测），替换 34 处 `timeout` 与 12 处 `md5sum` | `bash -n` 全部脚本；在 Windows 上跑一轮 harness 不回归 |
| P0-B | 新增 `config/harness.example.env` + `env.sh` 读取 `<WORK_DIR>/gl_local.env`；`run.sh:115` 的开关移入配置 | `--print-config` 输出与旧行为逐项对照 |
| P0-C | 实现 USE 模式（`MODE=use` 读 `gl_tuned.env` 复跑，含参数校验） | 用现有 `gl_tuned.env` 复跑一轮，参数与日志逐字对照 |
| P0-D | 修 `Makefile`/`build.gradle.kts` 的 darwin 分支、删本机兜底；`preflight.sh`/`kernel_verify.py`/`probe_tcp_route.sh` 改走探测 | 在本机与新 NDK 版本路径下各构建一次 |
| P1 | 修 `stats.sh`（目录+命名）、`harvest/retry` 改用 `$D_TMP`、清理 `.bak`、加参数校验与 `--help` | 单脚本 dry-run |
| P2 | 文档外部化（本机路径→占位符 + 指回 PLAYBOOK 配置章节）；统一 `python3` 与日志命名 | `git grep` 复查本机路径命中=0 |

> 原则：P0-A/B 先做（零行为变化、可逐项对照），P0-C/D 涉及行为，改完必须跑一轮真机复验
> （参考 2026-09-17 的复验：第 13 轮命中、终验 `u:r:magisk:s0`）。

---

## 7. 实施记录（2026-09-17，同日落地）

**目标**：换机/换平台时**只带 `ghostlock-main` 一个目录**即可运行。

### 7.1 新增

| 文件 | 作用 |
|---|---|
| `tools/harness/platform.sh` | 平台适配层：`host_os / md5_of / tmo / stat_size / find_ndk / ndk_prebuilt_bin / ndk_clang / require_cmd`（macOS 无 `timeout`/`md5sum` 也能跑：内建兜底 + `md5 -q`） |
| `tools/harness/config.sh` | 配置层：读 L1、CLI 解析（`--print-config / --dry-run / --mode / --device / --rounds / --shift / --help`）、参数校验、`config_exploit_env`、NDK 版本偏离告警 |
| `config/harness.example.env` | L2 入库示例：全键位 + 默认值 + 说明，零本机信息 |
| `config/deps.manifest` | 依赖清单（文件名/字节/md5）+ **已验证构建锚点**（`build-pin: ndk=28.2.13676358 ghostlock=4bb625f8…`） |
| `tools/harness/deps.sh` | 换机第一步：依赖/产物/NDK/adb 自足性检查（退出码=失败项数） |
| `harness.local.env` | L1 本机配置（**不入库**，`.gitignore` 已忽略） |

### 7.2 改造

- `env.sh`：接入 `platform.sh`；先 source L1 再推导；**WORK_DIR 三档解析**（显式 → 仓库上一级若有依赖 → `<REPO>/run`）；`DEPS` 可独立指定；`D_TMP/D_SDCARD/D_AP/D_KSU` 可覆盖；新增 `adb()` 包装（`ADB_CMD`，调用点零改动即可换 adb 二进制）。
- `run.sh`：explit 开关改为从配置组装（`config_exploit_env`），新增 `MODE=use`（读 `gl_tuned.env` 复跑）与 `--dry-run`；日志/设备路径统一变量。
- `watcher.sh / retry.sh / harvest.sh / finish.sh / shift_scan.sh / check_stride.sh / probe_tcp_route.sh`：`timeout`→`tmo`、本地 `md5sum`→`md5_of`、`stat -c%s`→`stat_size`、`/data/local/tmp`→`$D_TMP`（单引号 payload 改为双引号以便展开）。
- `stats.sh`：**修复失效**——改从 `LOGDIR` 读 `gl_run*.out` / `harness_run_*.out`（轮次头在这里，不在逐轮日志里）。
- NDK 硬编码全部移除：`preflight.sh`、`kernel_verify.py`、`probe_tcp_route.sh`、`build.sh`、`build_apk.sh`、`Makefile`（含 darwin 分支与"取最高版本"修正）、`build.gradle.kts`（prebuilt 目录探测）。
- 清理：删除冗余的 `run.sh.bak` / `run.sh.bak2`（历史仍在 git 中）。

### 7.3 验证（零行为变化）

| 项 | 结果 |
|---|---|
| 全部 shell 脚本 `bash -n` | 通过 |
| `python -m py_compile tools/kernel_verify.py` | 通过 |
| `run.sh --dry-run` 下发的设备命令 | 与改造前 `run.sh:115` **逐项一致**（8 个 `GHOSTLOCK_*` 变量同值） |
| `make` 构建（NDK 28.2.13676358） | 产物 md5 `4bb625f8…` 与改造前**逐字节一致** |
| `make` 无 NDK 变量 | 明确英文报错退出（不再静默/乱码） |
| `make` 仅给 `ANDROID_HOME` | 自动选中最高版本 NDK 并构建成功 |
| 四层优先级 | L0 环境变量压过 L1 ✓；`--rounds 30` 压过默认 ✓；NDK 偏离已验证版本时给出告警 ✓ |
| `MODE=use` | 正确读取 `gl_tuned.env`；缺失时明确报错并给出补救命令 ✓ |
| `deps.sh` | 本机全绿（依赖 md5 匹配、NDK/clang/adb 均找到）✓ |
| `stats.sh` | 正确汇总今日 13 轮 / 1 命中 / 12 panic ✓ |

### 7.4 仍建议跟进（未做）

1. ~~文档层写死路径~~ **已解决（见 §7.5）**：全部换成 `<SDK>`/`<NDK>`/`<prebuilt>` 等占位符，README 改为自动取 NDK 版本与 prebuilt 名。
2. ~~`python`/`python3` 混用~~ **已解决（见 §7.5）**：`platform.sh` 解析 `PYTHON_BIN`（PYTHON > python3 > python）并导出。
3. ~~`finish.sh` 表结构硬编码~~ **已解决（见 §7.5）**：表头/行模板/默认包名改为配置项（GL_AP_*），表头不符默认拒绝写入。

### 7.5 遗留项收口（同日）

| 原遗留项 | 处理方式 | 验证 |
|---|---|---|
| ① 文档/README 写死工具链路径 | 批量替换为占位符：`<SDK>` / `<NDK>` / `<prebuilt>` / `<LLVM_MINGW>`（脚本 `externalize_docs.py`，14 行 / 9 文件）；README 中英文的交叉编译示例改为**自动取 NDK 版本与 prebuilt 目录名**；`PLAYBOOK §0` 增加占位符对照表，并注明"带日期的文档是历史现场记录" | `git grep` 复查 = 0（仅剩 `copy_len.py` 注释里作为工具名的 `llvm-mingw`，非路径） |
| ② `python` / `python3` 混用 | `platform.sh` 新增 `find_python` 与导出 `PYTHON_BIN`（`PYTHON` > `python3` > `python`）；`check.sh` 改用它，缺失时明确报错 | 本机解析为 `python3`；`bash -n` 通过 |
| ③ `finish.sh` 的 `package_config` 表结构硬编码 | 表头 / 行模板 / 默认包名改为配置项：`GL_AP_HEADER`、`GL_AP_ROW_FMT`（printf 格式：包名、uid）、`GL_AP_PKGS`、`GL_AP_FORCE`；表头与预期不符时**默认拒绝写入**（`exit 3`）并打印实际/预期，避免换 ROM 写坏授权表 | 真机 `finish.sh --dry-run`（只读）确认现有表头与预期一致、各步骤计划正确、设备未被改动 |

附带改进：`finish.sh` 新增 `--dry-run`，可在不重启框架、不写授权表的前提下预览收尾计划（收尾窗口只有约 1 分钟，预览能力对换机后首次运行很有价值）。

### 7.6 一键入口与"证据是否入库"的判断（同日）

**新增 `tools/harness/root.sh`**（编排，不改动既有脚本行为）：
自检 `deps.sh` → 后台起 `watcher.sh` → `run.sh`（TUNE/USE）→ 命中即停 → `finish.sh` 收尾 → `su -c id` 终验。
退出码：`0` 已 root / `2` 轮数用尽未命中 / `3` 前置失败 / `4` 命中但收尾或终验失败；支持
`--rounds N`、`--no-finish`、`--skip-preflight`、`--dry-run`。

**关于"能不能一键 root"**：能一键化的是**流程**，不能一键化的是**结果**——本漏洞是两线程时序竞态，
单轮命中率约 5–8%，命中是概率事件：30 轮 ≈83%、50 轮 ≈95%、100 轮 ≈99.7%（按 5.8%/轮估算）。
因此 `root.sh` 的设计目标是"一条命令跑到终验"，而不是"必成"；失败时以退出码区分"没中"与"中了但收尾失败"。

**关于命中证据是否入库**：判断结论是**原始日志不入库**，理由三条：
1. 含设备序列号、机型与本地路径等本机信息（与仓库"零本机信息"的既定约定冲突）；
2. 体积与信噪比不合算（klog 数百行，多为第三方内核噪声）；
3. **可复现性不靠原始日志**——它由"已验证产物 md5 + 完整流程脚本"保证：
   `config/deps.manifest` 的 `build-pin`（NDK 版本 + `ghostlock` md5）+ 本文件 §7.3 的验证矩阵
   + `harvest_hit/`（本地留存）。

若确需在仓库留痕，建议只留一份**结论锚点**（日期 / 机型 / `uname -r` / 轮数 / 终验输出 / 产物 md5，约 10 行），
而不是原始日志；原始证据保留在本机 `harvest_hit/`。

### 7.7 harness 主流程 Python 化（同日，按"shell 不通用"的要求）

**动机**：bash 版依赖 coreutils（`timeout` / `md5sum` / `stat`）与 MSYS 路径行为，
Windows(Git Bash) / Linux / macOS 三者不一致；Python 只有一个运行时依赖，路径/哈希/超时/进程管理都是标准库行为。

**结构**（模块边界清晰，各自单一职责）：

| 文件 | 职责 |
|---|---|
| `tools/harness/harness.py` | 入口（解析命令行、分派子命令） |
| `tools/harness/ghostlock/plat.py` | 平台层：md5(`hashlib`)、超时(`subprocess`)、文件大小、NDK 与 adb 探测、路径正斜杠化 |
| `tools/harness/ghostlock/config.py` | 四层配置（L0 CLI/env ＞ L1 `harness.local.env` ＞ L3 默认+探测）、目录解析（WORK_DIR 三档）、校验 |
| `tools/harness/ghostlock/device.py` | 设备层：adb 封装、设备/核心对探测、推送校验、`Watcher`（独立线程盯 `/proc/modules`）、收尾流程 |
| `tools/harness/ghostlock/flow.py` | 编排：`deps` / `run`(tune\|use) / `root` 一键 / `stats` |
| `tools/harness/ghostlock/cli.py` | 命令行定义与 `config` 打印 |

**子命令**：`deps`（换机第一步）、`run`、`root`（一键：自检→监视→循环→命中即停→收尾→终验）、
`finish`（幂等，含 `--dry-run` 只读预览）、`stats`、`config`；
全局选项：`--dry-run` / `--print-config` / `--mode` / `--device` / `--rounds` / `--shift` / `--no-finish` / `--skip-preflight`。

**与 bash 版的行为一致性验证**

| 项 | 结果 |
|---|---|
| `run --dry-run` 下发的设备命令 | 与 bash 版**逐字符一致**（8 个 `GHOSTLOCK_*` 同值） |
| `deps` | 全绿（依赖 md5 匹配、NDK/clang/adb 均已定位） |
| `stats` | 13 轮 / 1 命中 / 12 PANIC，与 bash 版一致 |
| `finish --dry-run` | 真机只读通过：表头匹配、计划正确、设备未被改动 |
| `root --dry-run` | 6 阶段计划正确 |
| 构建产物 | md5 `4bb625f8…` 未变 |
| 全部模块 `py_compile` | 通过 |

**删除**：`run/watcher/finish/deps/stats/root/config` 共 7 个 `.sh`（历史仍在 git 中）。
**保留**：`env.sh` + `platform.sh` 作为薄适配层，供 4 个**离线/探索脚本**（`retry.sh`、`harvest.sh`、
`shift_scan.sh`、`check_stride.sh`）与自检脚本 `check.sh` 使用——它们不在主流程内，是否一并移植待定。

**实现要点**：L1 本地配置里的 `ANDROID_*` 会注入进程环境供 NDK 探测（不覆盖已有环境变量）；
所有传给 adb 的路径统一转正斜杠（adb.exe 只认盘符路径，反斜杠与 POSIX 形式会静默失败）。

### 7.8 Python 版端到端真机验证（2026-09-17）

**命令**：`python3 tools/harness/harness.py root --rounds 30`
**起点**：`adb reboot` 后的干净基线（uptime 25 s、`kernelpatch` 模块=0、无 `su`）

**结果：一次跑通，退出码 0**

| 项 | 实测 |
|---|---|
| 命中 | **第 16 轮**（11:17:23 起跑 → 11:33:45 SUCCESS → 11:40:12 结束） |
| 分类统计 | `hit=1 panic=15 safe=0`（命中率 6.3%，落在历史 5–8% 区间） |
| 命中监视 | `Watcher` 11:34:44 检出模块（基线判定生效：起跑时模块=0，出现即命中） |
| 自动收尾 | soft-reboot → 修正 `sys.boot_completed` → 授权表幂等合并（`me.bmax.apatch` 已有则保留，`bin.mt.plus` 未被覆盖）→ 重启管理器 |
| 终验 | `uid=0(root) gid=0(root) … context=u:r:magisk:s0` |
| 退出码 | `0` —— 与设计语义（已 root 且终验通过）一致 |
| 参数锁定 | `gl_tuned.env` 由 Python 版正常写入：`SHIFT=-2 CORE=4 CCORE=5 DATE=2026-09-17 11:40:03` |

**测试过程中发现并修复的 3 个缺陷**（提交 `b3b4279`）：① `stage()` 比对设备 `md5sum` 时漏取首字段
（等价 `| cut -d' ' -f1`），导致每轮都判 `stage failed`；② 输出块缓冲导致重定向日志长时间为空；
③ `Watcher` 把设备上**遗留**模块当命中（改为"基线 + 消失后重现"）。

**结论**：Python 版与 bash 版行为一致，且**能真正拿到 root**；`--rounds 1` 是最便宜的试金石
（dry-run 只验证命令拼装，验不出推送校验/分类/退出码这类问题）。
