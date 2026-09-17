# 拿到一台新设备后的操作顺序

> 核心原则：**能离线判定的绝不上机，能一次问清的绝不试错。**
> 一次命中要等 1~20 分钟，所以任何"上机才发现"的错误都是昂贵错误。

```
1 侦察 ──→ 2 符号预检 ──→ 3 偏移+构建 ──→ 4 等命中 ──→ 5 收尾验证
  └────────── 全程离线，不碰设备 ──────────┘   └── 需设备在线 ──┘
```

---

## 第 0 步 · 配置与换机（只带仓库也能跑）

**四层配置，优先级从高到低**（查看最终生效值：`python3 tools/harness/harness.py config`）：

| 层 | 位置 | 是否入库 | 放什么 |
|---|---|---|---|
| L0 | 命令行 / 环境变量 | — | 一次性覆盖，如 `--rounds 30`、`ANDROID_NDK_HOME=…` |
| L1 | `<REPO>/harness.local.env` | **否**（已 gitignore） | 本机值：SDK/NDK 路径、设备序列号、运行参数 |
| L2 | `config/harness.example.env` | 是 | 全键位示例与默认值（零本机信息），复制成 L1 |
| L3 | `env.sh` + `platform.sh` | 是 | 自动探测：设备型号、核心对、目录推导、平台命令 |

**换一台机器 / 换一个平台**：

```bash
git clone <repo> && cd <repo>
cp config/harness.example.env harness.local.env    # 只改这一个文件
# 填 ANDROID_NDK_HOME（或 ANDROID_HOME）
python3 tools/harness/harness.py deps              # 依赖自足性检查（.ko / libksud.so / NDK / adb）
python3 tools/harness/harness.py config            # 看一眼最终生效配置
```

> harness 主流程是 **Python**（`tools/harness/harness.py` + `tools/harness/ghostlock/` 包），只需要 python3：
> 路径、哈希、超时、进程管理全部走标准库，**不依赖 coreutils**（timeout / md5sum / stat），
> 因此 Windows(Git Bash) / Linux / macOS 行为一致。
> 子命令：`deps` / `run` / `root` / `finish` / `stats` / `config`。

**运行层与依赖放哪**（自动判定，无需配置）：

1. `GHOSTLOCK_WORK` / `harness.local.env` 显式指定；
2. 否则**仓库的上一级**若已有 `*.ko` / `libksud.so` → 用它（旧布局，本机走这条）；
3. 否则 `<REPO>/run/`（自动创建）——**新机器只拷仓库也能跑**。

依赖文件本身不入库：见 `config/deps.manifest`（含文件名/字节数/md5 + 已验证构建的 NDK 版本）。
放 `<WORK_DIR>`、`<REPO>/deps/`（已忽略）或用 `GHOSTLOCK_DEPS` 指定均可。

**平台差异已收敛**：主流程用 Python（`ghostlock/plat.py`：md5=`hashlib`、超时=`subprocess timeout`、NDK=`find_ndk`），
业务脚本不再出现 `md5sum`、`timeout`、写死的 prebuilt 目录名这类平台限定写法（macOS 缺 `timeout`/`md5sum`
也能跑：内建兜底 + `md5 -q`）。

> ⚠️ **NDK 版本会改变产物**：已验证构建用的是 `28.2.13676358`（`ghostlock` md5 见 `config/deps.manifest`）。
> 用别的版本构建出的二进制哈希不同，必须重跑一轮真机复验后才能当基线。

**路径占位符**（文档中统一用这些；真实值只在 L1 本地配置里）：

| 占位符 | 含义 |
|---|---|
| `<SDK>` / `<NDK>` | Android SDK 根 / NDK 根（如 `<SDK>/ndk/<版本>`） |
| `<prebuilt>` | NDK 的 `toolchains/llvm/prebuilt/<宿主>` 目录名，按实际存在取 |
| `<REPO>` / `<WORK_DIR>` | 本仓库根 / 运行层（默认仓库上一级，可 `GHOSTLOCK_WORK` 指定） |
| `<ARCHIVE>` / `<ARCHIVE_DIR>` / `<REFS_DIR>` / `<HOME>` | 冻结档案仓 / 其父目录 / 素材目录 / 用户主目录 |

> 文件名带日期的文档（`docs/*_2026-09-*.md`、`docs/evidence/**`）是**当时的现场记录**，其中的路径与设备串属历史事实，不代表当前环境；当前有效配置一律以 `config/harness.example.env` + L1 本地配置为准。

---

## 第 1 步 · 侦察：把设备底细摸清

**目的**：在写任何代码之前，先确定"这条路能不能走"。此步不写一行代码。

```bash
export GHOSTLOCK_DEV=<序列号>          # 或依赖自动探测
adb -s $GHOSTLOCK_DEV shell 'uname -r'                 # 内核版本
adb -s $GHOSTLOCK_DEV shell 'getprop ro.product.model' # 机型
adb -s $GHOSTLOCK_DEV shell 'getenforce'               # SELinux 状态
adb -s $GHOSTLOCK_DEV shell 'grep -c . /proc/kallsyms' # 符号表规模
adb -s $GHOSTLOCK_DEV shell 'cat /proc/cmdline'        # 内核开关
adb -s $GHOSTLOCK_DEV shell 'pm list packages | grep -iE "apatch|kernelsu|sukisu"'
```

要拿到结论的四件事：

| 问 | 为什么 |
|---|---|
| 内核版本 / KMI | 决定漏洞是否适用、用哪套偏移 |
| **kallsyms 快照** | 第 2 步的判据，必须**先落盘**（`/proc/kallsyms` 的完整副本） |
| 有无 BTF / boot 镜像 | 决定偏移从哪来（BTF 更省事） |
| 已装哪个管理器 | 决定收尾时授权表的包名与路径 |

同时记下三个**内核开关**（它们会决定调试代价）：

```bash
adb -s $GHOSTLOCK_DEV shell 'cat /proc/cmdline' | tr ' ' '\n' | grep -iE "panic|oops"
```

- `panic_on_oops=1` → 每次 oops 都会重启（**调试会非常慢**）
- `kernel.panic_on_rcu_stall=1` → RCU 卡顿也会重启，**且不受 `panic_on_oops` 影响**

> 这两个开关只有在拿到 root 之后才能关，所以"命中之前每轮必然会重启"是正常的，
> 不要误判成故障。

---

## 第 2 步 · 闸门：符号预检（不过就别往下走）

**目的**：用零成本判定"目标 `.ko` 能不能被加载"，避免白跑一轮命中。

```bash
python3 tools/harness/harness.py preflight.sh
```

判据：输出里每一项的 `NOT in device kallsyms` **必须是 0**。

```
undefined in module : 62
NOT in device kallsyms: 0     ← 必须是 0
```

为什么这条是闸门：本方案加载模块靠的是**用户态重定位** ——
读 `.ko` 的符号表，把每个未定义符号改用 `/proc/kallsyms` 的地址写成绝对符号，
再 `init_module`，从而绕开"内核不导出这些符号"的问题。
**但前提是这些符号必须出现在 kallsyms 里。** 缺一个，加载必然失败。

| 结果 | 动作 |
|---|---|
| 全部为 0 | 通过，继续 |
| 有缺失 | **换模块版本**（比如换 APatch 内置的那份 / KernelSU 的那份再测），或换提权目标 |

> 顺带澄清一个曾经误导我们的现象：加载失败返回的是 **`ENOENT(2)`**，
> toybox 把它显示成 `No such file or directory`，看起来像路径问题，
> 实际含义是"符号找不到"。**vermagic 在本内核不参与判定**
> （`CONFIG_MODVERSIONS` 下只比较第一个空格之后的文本），不要往那个方向查。

---

## 第 3 步 · 偏移提取 + 构建

```bash
# 偏移：优先从 BTF 提取；没有 BTF 就从 boot 镜像推导，或从 kallsyms 反查
cd tools/extract_rs && cargo run -- <boot 镜像或 kallsyms>

# 构建（本机没有 make，用等价脚本；它会先把脚本模板转成内嵌头）
export ANDROID_HOME=<你的 Sdk>
cd ../.. && bash build.sh
```

构建必须**零警告** —— 警告在这个项目里通常意味着真实的类型/截断问题。

构建完先跑一次离线自检，不要急着上机：

```bash
python3 tools/harness/harness.py check.sh      # 18 项：编译/语法/模板无损/符号预检/产物未入库
```

> 本机构建有两个坑已写进 `build.sh`：
> ① 不能挑版本号最大的 NDK（高版本可能缺所需 API 的编译器入口），要选**真正含所需编译器**的；
> ② Git Bash 下 `.cmd` 包装脚本没有执行位，`[ -x ...cmd ]` 会全部落空，应优先用无扩展名的 wrapper。

---

## 第 4 步 · 跑循环，等命中

**要同时开两条线，不能只开一条。**

```bash
cd <运行目录>                                      # 放 .ko 与日志的地方
python3 <项目>/tools/harness/harness.py run --rounds 30 > gl_run.out 2>&1
python3 <项目>/tools/harness/harness.py root         # 或直接用一键入口：内置后台监视 + 收尾 + 终验
```

**为什么必须两条线**（`root` 子命令内部已经这么做了）：
`adb shell ./ghostlock` 会**一直阻塞到进程退出**，
而提权成功后进程会原地保活数百秒 —— 等它返回时设备早已重启。
所以命中检测必须由**另一条独立的轮询**（`ghostlock/device.py` 的 `Watcher`，直接盯 `/proc/modules`）来做。
早期所有"命中后设备失联"的判断，绝大多数是**检查方式错了，不是设备崩了**。

单独跑 `run` 时的注意点：
- **命令里不要加 `&` 再跟其它命令** —— 进程链会被一起清理，表现为"设备不重启但也没有进展"，极易误判成设备稳定。

预期：单轮 60~70 秒（大头是 PANIC 后等重启），**单轮命中率 5~8%**，
所以一次命中通常 1~20 分钟。

**想少盯屏：一条命令跑完整个流程**

```bash
python3 tools/harness/harness.py root --rounds 30   # 自检 → 后台监视 → TUNE → 命中即停 → 收尾 → 终验
python3 tools/harness/harness.py root --dry-run     # 先看计划，不碰设备
python3 tools/harness/harness.py run  --rounds 30   # 只要循环（自己另开监视与收尾）
```

它把上面两条线 + 第 5 步收尾编排成一条命令，退出码语义：
`0`=已 root 且终验通过 / `2`=轮数用尽未命中（可加大轮数重跑）/ `3`=前置检查失败 / `4`=命中但收尾或终验失败。

> **"一键"能一键化流程，不能一键化结果**：命中是竞态概率事件（30 轮 ≈83%、50 轮 ≈95%、100 轮 ≈99.7%）。
> 想更稳就加轮数，不能靠"再点一次"。

---

## 第 5 步 · 收尾 + 验证（窗口只有约 1 分钟，务必脚本化）

```bash
python3 <项目>/tools/harness/harness.py finish
```

它按顺序做四件事，**幂等、无命中时安全退出**：

1. **软重启** —— 只重启 Android 框架，内核不动，模块保留
   （用 APatch 原生 `apd soft-reboot`，它内部已处理"重启时自己会被杀掉"）
2. **修 `sys.boot_completed`** —— 软重启把它置 0，但 `system_server` 往往没真正重启，
   于是没人置回 1，管理器会永远停在"等待软重启"
   （注意 `resetprop` 是 `apd` 的**子命令**，不能走符号链接调用）
3. **填授权表** —— `/data/adb/ap/package_config` 默认为空，
   **空表 → 管理器自己拿不到 root → 判定不出越狱模式 → 死循环**。
   写入时**必须读取-合并-去重**，否则会抹掉用户已授权过的应用。
   改完用 `rename` 落地，`apd` 的 inotify 监听器才会触发同步
4. **重启管理器并验证**

**验收标准**（三条都要满足）：

```
su -c id        → gid=0(root) groups=... context=u:r:magisk:s0
/proc/modules   → kernelpatch ... Live
管理器进程       → 有 UID=0 的子进程
```

只要 `su` 仍是 `gid=<垃圾值>` + `u:r:kernel:s0`，说明它还走的是内核钩子那条临时路径，
**而不是管理器正式发放的 root** —— 收尾没做完。

---

## 三条贯穿全程的红线

1. **绝不 exec 任何东西。**
   漏洞的副作用写会落在 `init_cred+8`，**那就是 gid 字段**。
   `execve` 会用被污染的 cred 重建副本，新镜像在**第一条指令之前**就死 ——
   表现为"脚本完整落盘、语法正确，却一行没执行"。
   所以模块加载必须在**当前进程内**完成，之后只保活，验证从设备外做。
2. **诊断信息必须 `write()+fsync()` 且双写 `/sdcard`。**
   `stdout` 在 adb 重定向后是**全缓冲**，崩溃时最后几行必丢；
   本机 f2fs 是 `fsync_mode=nobarrier`，不 fsync 的文件会随崩溃蒸发；
   而 `/data/local/tmp` 里由 kernel 域创建的文件 adb shell **读不了**。
3. **收尾要赶在设备重启前完成。**
   命中后设备状态不稳定（cred 被指向全局 `init_cred`），
   所以第 5 步必须一条命令跑完，不能手敲。
