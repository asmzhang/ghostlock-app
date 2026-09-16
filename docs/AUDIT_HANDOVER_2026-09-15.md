# 现状说明与审计清单 — 2026-09-15

> **本文用途**：交给**另一个 AI/人独立审计**：本次会话的**经验、代码、工具、文档**是否**全部蒸馏并保存**。
> 审计方式见 §6：**每条断言都给了可执行命令与期望输出**，请直接复算，不要采信叙述。
> **审计已完成（2026-09-15 晚）**：判定通过，结论见 `docs/AUDIT_VERDICT_2026-09-15.md`；本文所列勘误已于 2026-09-16 回填修复。

---

## 1. 一句话现状

目标漏洞 **CVE-2026-43499（GhostLock / popsicle）**，本项目做**跨内核移植**。
本次会话完成两件事：① **A35（Exynos 1380 / 5.15.180）判定"走不通"并封版**；
② 把**marble（Redmi Note 12 Turbo / 5.10.149）的 root 恢复**（我用两次冒烟测试把它重启、临时 root 丢失），
并把该机型**可复现的配置固化**。随后把**可行基线 + 全部精华**整理进 `<WORK_DIR>/my2`（拟作为新主项目）。

**设备当前状态**：marble `uid=0(root) gid=0(root) … context=u:r:magisk:s0`，`kernelpatch` 已加载（1 条）✓

---

## 2. 三层目录（角色必须分清）

| 路径 | 角色 | 状态 |
|---|---|---|
| `<WORK_DIR>/` | **工作区根**；harness 的 `WORK_DIR`（`tools/harness/env.sh` 里 `WORK_DIR=PROJECT_DIR/..`）| 放着 `gl_tuned.env`、`libksud.so`、`android12-5.10_kernelpatch.ko`（**harness 期望在这里**）、`root/`（旧树）、`my2/`（新主候选）、`_ghostlock_refs/`（固件素材，8GB 量级）、`_attic/`、`root/exp/`（历史实验脚本 90 个）|
| `<ARCHIVE>/` | **旧工作树**（历史现场，含**未提交**的实验性改动）| HEAD=`8a82e2f`（**已知在 marble 上会秒崩 C1**，勿上真机）；docs 26 / tools 36 |
| `<WORK_DIR>/my2/` | **新主候选**（**git worktree**，分支 `my2`，HEAD=`9f2affc`=上游）| 内容 = 上游 + **`347dfec` 的代码** + 蒸馏后的文档/工具；**32 项未提交** |

**关键基线**：`347dfec8fa6cd5c204a693565f7e9fd1482ee6ca`（2026-09-11 11:44:52，"root achieved"）——
本项目**唯一被实测证明能出 root** 的代码状态。

---

## 3. 本次会话做了什么（可核验的时间线）

| 时间 | 事件 | 产物 |
|---|---|---|
| 09-15 全天 | A35 载体调查（12 轮上机）→ 判定"所有可达载体都覆盖不到悬垂 waiter 的 `lock`(+0x38)" | `docs/CARRIER_EXHAUSTION_2026-09-15.md` |
| 17:16 | **marble root 恢复**：`347dfec` 二进制第 **14** 轮命中 → soft-reboot → 终验 `gid=0`+magisk 域 | `docs/MARBLE_RESTORE_2026-09-15.md` |
| 17:22 | 参数锁定到 `gl_tuned.env`（`SHIFT=-2 CORE=4 CCORE=5`）| `artifacts/2026-09-15/gl_tuned.env` |
| 18:20+ | 建 `my2`（上基于游 `9f2affc`）→ 压平应用 `347dfec`（**不提交**）→ 搬到 `my2/docs` | §4 |
| 18:30–18:56 | 多轮**蒸馏 + 精简**：写 `ESSENCE.md`（11 节）、剔除历史档案、补回方法/素材原文与通用工具 | §4 表 |

---

## 4. ★ 四类资产：来源 → 蒸馏 → 保存（审计重点）

| 类别 | 来源 | 蒸馏去处 | my2 中的保存 | 完整性判定 |
|---|---|---|---|---|
| **经验** | ① 旧树 25 份文档 ② git 提交信息 ③ 当日实测（12 轮 A35 + 保险根 marble）| **`docs/ESSENCE.md`**（11 节 26KB：铁律/速查/方法论7条/硬数字/10条坑/流程/§7硬约束/§8工具优先/§9补遗/§10旧树再蒸馏）| ✅ `docs/ESSENCE.md` | ✅ **覆盖**；**逐条可回溯**（§0–§10 与 §5 索引）|
| **代码** | `347dfec` 的完整树 | **不蒸馏**（必须原样）| ✅ `src/`（134 文件）+ `tools/extract_rs/` | ✅ **逐字节一致**（§6 命令 2）+ 构建 md5 一致（命令 3）|
| **工具** | 旧树 36 项 | 名与用途并入 ESSENCE §10.2 / §8.2 | ✅ **20 项**（`harness/` 全套 + `extract_rs` 源码 + 分析工具 `stack_depth/find_bytecopy/scan_handlers/copy_len/kernel_verify/btf_dump/gen_root_template/patch_main_rootscript/verify_template/bookmark_lookup/sym_lookup/elf_xref/disasm_vivo/find_transport/extract_collisions/check_readme_devices/probe_tcp_route.c`）| ⚠️ **16 项有意未搬**：编译产物 3（agree_mm/brute_mm/solve_pairs 的 `*.exe`）、机型专用 3（`samsung_extract*`、`vendor_boot_modules`）、侧信道实验源码及产物 7（agree_mm/brute_mm/solve_pairs/ks_probe/pile_test 的 `.c` + `ks_probe`/`pile_test` 可执行）、杂项 3（`emu_hash_check.py`＝vivo futex 哈希仿真校验、`extract_block.py`＝一次性重构工具、`session_2026-09-15/`＝当日实验脚本快照；均在旧树）|
| **文档** | 旧树 26 份 | ESSENCE = 精华 | ✅ **12 份 + archive 1**：`ESSENCE` / `README`(索引) / `VULN_SCOPE` / `PORTING_PLAYBOOK` / `ADAPT_NEW_KERNEL` / `PLAYBOOK` / `FIRMWARE_ACQUISITION` / `DEVICE_MARBLE` / `GHOSTLOCK_SUCCESS_2026-09-11` / `MARBLE_RESTORE_2026-09-15` / `CARRIER_EXHAUSTION_2026-09-15` / `archive/GHOSTLOCK_PORTING_METHODOLOGY` | ⚠️ **13 份历史档案有意留在旧树**（vivo×3、A35 过程×4〔HANDOVER_A35/SRC_AUDIT/KICKOFF/FINDINGS〕、审计稿×2、GHOSTLOCK_LOGIC〔同源内容已由已搬入的 GHOSTLOCK_SUCCESS 覆盖〕、SESSION_INDEX、MTK_BROM、PORTING_NEW_DEVICE；另 evidence 的 raw dump 与旧 `docs/archive/` 3 份 debug/交接/报告档案）—— ESSENCE §5 注已指明位置 |
| **素材/证据** | `_ghostlock_refs/`、旧树 `docs/evidence/` | — | ✅ `artifacts/2026-09-15/`（能出 root 的二进制 + md5 + 参数）；`docs/evidence/2026-09-15/`（A35 panic 全文 `kp103_lst.txt`、`reset_reason.txt`）| ✅ 被引用的证据都在；❌ **未搬**：A35 固件/内核素材（`_ghostlock_refs/samsung_a35/`，GB 级，非仓库内容）|

---

## 5. 已知缺口与风险（**审计请重点质疑这里**）

| # | 风险 | 影响 | 现状 |
|---|---|---|---|
| R1 | **`my2` 是 git worktree**（`.git` → `gitdir: …/root/ghostlock-app/.git/worktrees/my2`）| 旧仓库一旦删除/移动，my2 失效 | ❌ **未解决**（需提交 + clone 独立化）|
| R2 | **my2 有 32 项未提交** | 尚未固化；`git clean` 会丢 | ❌ 未提交 |
| R3 | `docs/ESSENCE.md` §5 标题仍写"只留 5 份"，实际已补回 12 份 | 文档自相矛盾 | ✅ 已修复（2026-09-15 晚核实：标题已改为"13 份"，与实际一致） |
| R4 | harness 依赖的素材在**工作区层**（`<WORK_DIR>/`）而非 my2 内 | 换机器要重新放置 | ⚠️ 已在 ESSENCE §1 说明出处 |
| R5 | 旧树 `root/ghostlock-app` 的**未提交改动**（1000+ 行，含使 marble 秒崩的回归）| 误用即坏事 | ⚠️ 已在 §2/§10 标注"勿上真机" |
| R6 | `exp/`（90 个历史实验脚本）在**工作区层**，未进任何仓库 | 仅作档案 | ⚠️ ESSENCE §10.2 已记录 |

---

## 6. 审计核验清单（可直接复算，勿采信叙述）

```bash
cd <WORK_DIR>/my2

# 1) 分支与基线
git rev-parse --abbrev-ref HEAD          # 期望: my2
git log -1 --format='%h %s'              # 期望: 9f2affc Add a safe mode toggle that disables all KSU modules (#85)
git rev-parse --verify 347dfec           # 期望: 347dfec8fa6cd5c204a693565f7e9fd1482ee6ca

# 2) 代码完整性：与 347dfec 的差异必须为空
git diff 347dfec --stat -- src/ tools/extract_rs/   # 期望: 无输出
git ls-tree -r --name-only 347dfec | wc -l          # 期望: 113
git ls-files | wc -l                                 # 期望: 113（仅代码追踪；新增文档/工具为未跟踪）

# 3) 可构建性 + 指纹（需 NDK）
make NDK_ROOT=D:/platform/Android/Sdk/ndk/28.2.13676358 ghostlock
md5sum ghostlock       # 期望: 36430a2fbb2c42c243acf9a8698d169e（100880 字节）
md5sum artifacts/2026-09-15/ghostlock-347dfec-100880   # 期望: 同上

# 4) 文档/工具是否齐
ls docs/ docs/archive/ ; ls tools/
grep -c '^## ' docs/ESSENCE.md           # 期望: 11
grep -n '^## ' docs/ESSENCE.md           # 期望: §0..§10

# 5) 悬空引用（文档提到的文件是否都在）
grep -oE 'docs/[A-Za-z0-9_./-]+\.md' docs/*.md docs/archive/*.md | sed 's/.*://' | sort -u | while read r; do [ -e "$r" ] || echo "悬空: $r"; done
# 期望: 空，或仅剩带"已归档"标注的引用（当前唯一命中：PORTING_PLAYBOOK 引 docs/MTK_BROM_DUMP.md，正文已标注归档于旧工作树）

# 6) harness 素材
ls -la <WORK_DIR>/{gl_tuned.env,libksud.so,android12-5.10_kernelpatch.ko}   # 期望: 三个都在

# 7) 旧树对照（确认"有意未搬"的都在，没丢）
ls <ARCHIVE>/docs | wc -l     # 期望: 26
ls <ARCHIVE>/tools | wc -l    # 期望: 36
ls <ARCHIVE_DIR>/exp | wc -l                    # 期望: 90

# 8) 设备侧（可选）
adb -s 3e6f1443 shell 'su -c id'                 # 期望: gid=0(root) + context=u:r:magisk:s0
adb -s 3e6f1443 shell 'grep -c kernelpatch /proc/modules'   # 期望: 1
```

### 请重点回答的三个审计问题

1. **经验是否"全部"蒸馏？** 举反例即可推翻：旧树 25 份文档 + 提交信息 + 当日实测中，**是否有 ESSENCE 未覆盖的可操作结论**？（提示：§5 索引与 §10 声称覆盖了方法论、硬数字、坑、流程四类）
2. **代码是否"原样"保存？** 用命令 2/3 复算：差异为空 + md5 一致，是否成立？
3. **工具与文档的取舍是否合理？** 未搬的 16 项工具 / 12 份文档是否确实"非必需"？（§4 已列明每一类，可逐项质疑）

---

## 7. 未决事项（需用户决定）

1. ✅ **已完成（2026-09-16 11:01）**：`my2` 61 个文件压成 1 个提交 `aa37ddf`（走 `git_commit_repair.sh` SOP，`REF_OK` + 另起命令验证通过；与 347dfec 的 diff 仍为空）；
2. ✅ **已完成（2026-09-16 11:12）**：独立主仓 **`<REPO>`**（本地 clone，唯一分支 `my2`=`aa37ddf`，本地 `main` 已删除；独立构建 md5 与 my2/归档成功件三方一致）⇒ R1 解除；旧仓库转为**冻结档案**（39 个未推送提交 + 32 项未提交改动原地封存，勿用勿删）；
3. 仍未决：是否把 `exp/`（90 个历史脚本）也纳入档案。
