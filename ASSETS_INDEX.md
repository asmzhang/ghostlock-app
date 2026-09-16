# <WORK_DIR> 资产索引（先读这个）

> 最后更新：2026-09-16 13:45（工作区清理后）
> 目的：任何 AI / 人接手时，**不要在错误的目录里找东西**。此前已发生过两次找错。

## 0.5 占位符约定（本仓库不记录任何本机绝对路径）

文档中的绝对路径已统一改为占位符，含义如下（本机真实值仅保存在仓库外的本地笔记，不入库）：

| 占位符 | 含义 |
|---|---|
| `<WORK_DIR>` | 工作区根目录；即 harness 的 `WORK_DIR`（`gl_tuned.env`、`*.ko`、`libksud.so` 所在层） |
| `<REPO>` | 本仓库根（exploit 代码 / 工具 / 文档 / 命中证据） |
| `<ARCHIVE>` | 冻结档案仓（旧工作树；**勿改勿跑勿删**，历史文档仍引用它） |
| `<ARCHIVE_DIR>` | 冻结档案仓的上级目录 |
| `<REFS_DIR>` | 内核镜像 / 符号 / 固件素材目录 |
| `<HOME>` | 用户主目录 |

脚本不再硬编码本机路径：`tools/*.py` 改读环境变量（如 `VIVO_IMAGE`、`VIVO_SYMS`）。

## 0. 一句话定位

| 你要找什么 | 去哪 |
|---|---|
| **exploit 代码 / 工具 / 文档 / 命中证据（主仓）** | `<REPO>\`（唯一分支 `my2`） |
| harness 运行素材 | `<WORK_DIR>\` 顶层：`gl_tuned.env`、`android12-5.10_kernelpatch.ko`、`libksud.so`（harness 的 WORK_DIR = 此层，缺了会 stage retry 死循环） |
| **内核镜像 / 符号 / 固件 / 各机型素材** | `_ghostlock_refs\`（marble-kernel / samsung_a35 / vivo / gki510-arm64 / APatch 等） |
| 历史档案 | `root\ghostlock-app\`（**冻结档案：勿改勿跑勿删**，历史文档仍引用它） |
| 历史实验脚本 | `root\exp\`（90 个，仅档案） |
| 当前任务笔记（AI 的） | `root\.workbuddy\memory\` + 主仓 `docs\` |

## 1. 顶层结构（2026-09-16 清理后，root 从 1.9G → 1.5G）

```
<WORK_DIR>\
├─ ASSETS_INDEX.md            ← 本文件
├─ ghostlock-main\            3.8 MB ★ 主仓（唯一分支 my2；工作树干净）
├─ _ghostlock_refs\           ~8-12 GB ★ 素材库（各机型内核/固件/APatch 源码+归档 APK/.ko/libapd）
├─ android12-5.10_kernelpatch.ko + libksud.so + gl_tuned.env   harness 前置件
├─ gl_tune_r13.log            09-16 命中轮日志（已入主仓 evidence，原件留存）
├─ my2\                       已退休 worktree 残留（句柄锁定暂未删，内有 _RETIRED 标记）
└─ root\                      1.5 GB 档案层
    ├─ ghostlock-app\         1.2 GB 冻结档案（39 未推送提交 + 32 未提交改动 + docs 26 份 + tools 36 项）
    ├─ exp\                   90 个历史实验脚本（档案）
    ├─ _lastkmsg\             A35 panic 原始 dump（证据）
    ├─ _ksrc\                 A35 内核源码引用子集（rtmutex/sched/rbtree）
    ├─ gl_cal\                marble kprobe 标定工具
    ├─ samloader\ / tools_usb\  三星固件下载 / USB 直通工具
    ├─ SM-A356E_16_Opensource.zip  272M（A35 源码包；解压目录已清理，可随时再解）
    └─ gl_run.out / gl_tune_r14.log  09-15 命中证据（已入主仓 evidence）
```

## 2. ★ 素材（唯一可信来源）

- **A35**（SM-A356U，5.15.180，**已封版走不通**）：`_ghostlock_refs\samsung_a35\`
  （kernel.verified.elf 44.4MB / syms.txt / 官方固件 zip 8.17GB；封版结论见主仓 `docs/CARRIER_EXHAUSTION_2026-09-15.md`）
- **marble**（Redmi Note 12 Turbo，5.10.149，**主力机，root 流程已验证**）：`_ghostlock_refs\marble-kernel\`
- **APatch**：源码仓 `_ghostlock_refs\APatch\`（HEAD=6ec140e，kp 0.13.8）；管理器 11224 签名 APK 归档
  `_ghostlock_refs\APatch_11224_9a63e0f_HEAD-release-signed.apk`；版本要求见主仓 `docs/APATCH_VERSIONS.md`

## 3. 工具

- exploit 全部工具在**主仓** `ghostlock-main\tools\`（20 项，含 harness 全套）。
- 16 项机型专用/侧信道工具在冻结仓 `root\ghostlock-app\tools\`（取舍清单见主仓 `docs/AUDIT_HANDOVER_2026-09-15.md` §4）。
- 反汇编坑：objdump 用 **`/d/platform/llvm-mingw/bin/llvm-objdump`**（NDK 的不支持 `--start-address`）；
  clang/adb/objdump 等 Windows 程序只认**盘符路径**（`D:/...`）。

## 4. 已清理项（2026-09-16，全部走回收站，可恢复）

SM-A356E 解压目录(279M)、`root\_attic\`(157M：mtkclient/_gki_tmp 等 vivo/A35 时代临时件)、
`_ghostlock_trash_20260911\`(7.1M)、两轮 PANIC 日志 ×42、root 顶层散脚本 ×8（已在冻结仓
`tools/session_2026-09-15/` 归档）、root 副本 ko/libksud/gl_tuned.env（与主层 md5 一致）、`_mem_sam*.md`×4。
合计回收 ≈ **443M**。

## 5. 三条"再也不找错"的规矩

1. **代码 / 工具 / 文档 / 证据 → `ghostlock-main\`**；内核素材 → `_ghostlock_refs\`。
2. **`root\ghostlock-app\` 是冻结档案**——只读考古，勿改勿跑勿删（历史文档引用它的 docs/）。
3. 命中证据在主仓 `docs\evidence\<日期>\`；清理工作区层运行日志前，先确认证据已入库（`git log -- docs/evidence/`）。
