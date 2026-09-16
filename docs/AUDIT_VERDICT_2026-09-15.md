# 独立审计结论 — 2026-09-15

> 审计对象：`docs/AUDIT_HANDOVER_2026-09-15.md`（本文件按其 §6 要求**逐条复算**，未采信叙述）。
> 复算环境：`<WORK_DIR>/my2`，2026-09-15 19:00–19:10。

## 总判定：✅ 通过（附 4 项低危勘误 + 2 项建议）

核心断言全部成立：代码逐字节一致、可干净重建且 md5 指纹一致、经验蒸馏有据可查、设备状态与文档一致。

---

## 一、§6 命令逐条复算

| # | 断言 | 实测 | 判定 |
|---|---|---|---|
| 1 | 分支 `my2` / HEAD `84087d0` / 基线 `347dfec8fa6…` / 未提交 32 项 | 全部一致 | ✅ |
| 2 | `git diff 347dfec -- src/ tools/extract_rs/` 为空；tree 113 = tracked 113 | 为空；113 = 113 | ✅ |
| 3 | 可构建 + md5 `36430a2fbb2c42c243acf9a8698d169e`（100880 B）与归档一致 | **干净重建**（删 `ghostlock` 与全部 `.o/.d` 后重编）→ md5 与归档二进制逐字节一致 | ✅（注：首次 `make` 报 "up to date"，为严格起见已强制重建复验） |
| 4 | docs 12 份 + archive 1；tools 20 项；ESSENCE 11 节（§0–§10） | 12 md + `archive/` + `evidence/`；20 项；`grep -c '^## '` = 11，§0..§10 | ✅ |
| 5 | 悬空引用只应出现"已归档"说明性引用 | **1 条真悬空**：`docs/MTK_BROM_DUMP.md`（被 `PORTING_PLAYBOOK.md:183` 引用，my2 内无归档标注） | ⚠️ 与期望不符（低危，见 §三-4） |
| 6 | `gl_tuned.env` / `libksud.so` / `android12-5.10_kernelpatch.ko` 在工作区层 | 三个都在 | ✅ |
| 7 | 旧树 docs 26 / tools 36 / exp 90 | 26 ✓ / 36 ✓ / 90 ✓ —— 但命令路径 `<WORK_DIR>/exp` **错误**，实际 `<ARCHIVE_DIR>/exp` | ⚠️ 路径勘误（资产本身完好） |
| 8 | marble：`gid=0` + `u:r:magisk:s0`；kernelpatch = 1 | 逐字一致；设备 3e6f1443 在线 | ✅ |

## 二、三个审计问题的回答

### Q1 经验是否全部蒸馏？—— **成立（有一处建议补强）**
- 抽查了未搬文档中内容最重的三份（`GHOSTLOCK_LOGIC_2026-09-11` / `GHOSTLOCK_AUDIT_2026-09-14` / `SESSION_2026-09-15_INDEX`）的目录结构并与其对照：
  - 机制级关键结论——**禁止 exec（cred 被污染、exec 重建必死）**、**用户态 ELF 符号重定位**、**`package_config` CSV + rename 触发监听器**、resetprop 子命令坑——全部在**已搬入的 `GHOSTLOCK_SUCCESS_2026-09-11.md`**（第 48/53/80/84/205–239 行）中有完整叙述；`GHOSTLOCK_LOGIC` 是同源逻辑梳理稿，未搬不丢信息。
  - A35 过程档已被封版记录 `CARRIER_EXHAUSTION_2026-09-15.md`（已搬）覆盖；vivo 教训已蒸馏为 ESSENCE §7。
- **建议补强**：ESSENCE 自身全文没有出现 exec 禁忌（仅 §10.4 提到 package_config）。它目前只靠"§5 指路 SUCCESS 文档"间接覆盖。建议在 §0 铁律或 §10.4 补一行："全程禁止 exec/setuid/setgid——exec 会以被污染的 cred 重建，新镜像必死（详见 GHOSTLOCK_SUCCESS §③）"。

### Q2 代码是否原样保存？—— **成立**
diff 为空 + 113 = 113 + 干净重建 md5 一致（三重复验）。另确认：`src/core/root_template.h` 在 `347dfec` 中是仓库内文件（当时尚未改为生成物），故 my2 直接 `make` 即通过，无需先跑生成器。

### Q3 工具与文档取舍是否合理？—— **合理，但账目不完全（应修正）**
- tools：36 − 20 = **16 项未搬，计数正确**；但 §4 点名清单只覆盖 **13 项**，漏 3 项：`emu_hash_check.py`（vivo 5.15.178 futex 哈希仿真校验件）、`extract_block.py`（一次性重构工具，已完成使命）、`session_2026-09-15/`（当日 8 个 `gl_*.sh` 快照，已被 harness 取代）。逐项核实后**均确实非必需**，判定不变，仅应补进清单。
- docs：未搬 md 实为 **13 份**（handover 写"12 份"、点名 11）：漏点名 `GHOSTLOCK_LOGIC_2026-09-11` 与 `HANDOVER_2026-09-14_A35`；另旧树 `docs/archive/` 共 4 份，my2 只搬 1 份（其余 3 份 debug/交接/report 档案未点名，蒸馏价值低，可接受）。`evidence/` 只搬 2026-09-15（vivo_logs 等留旧树，与"raw dump 留旧树"一致）。

## 三、handover 文档自身勘误（4 项，低危）
1. §2 表与 §6 命令 7：`exp/` 实际在 **`<ARCHIVE_DIR>/exp`**，不在 `<WORK_DIR>/exp`。
2. §4 未搬清单：tools 漏 3 项、docs 漏 2 份（计数 12 → 13）。
3. R3 已过时：ESSENCE §5 标题现已是"13 份"，该风险实际已修复。
4. §6 命令 5 期望与实际不符：存在 1 条真悬空引用（`PORTING_PLAYBOOK.md:183` → `MTK_BROM_DUMP.md`）。

## 四、R1–R6 复核
R1 未解决（worktree 依赖旧仓库，`gitdir` 指向 root/ghostlock-app）· R2 未解决（32 项未提交）· R3 **已修复** · R4 属设计意图（SESSION_INDEX §2.2 明言"按设计期望在别处"）· R5/R6 标注在案。

## 五、建议动作（按优先级）
1. **提交 my2 的 32 项**（走 `git_commit_repair.sh` SOP，提交后另起命令验 `git log -1`）。
2. `PORTING_PLAYBOOK.md:183` 给 `MTK_BROM_DUMP.md` 加"（已归档旧工作树 docs/）"标注，消除唯一悬空引用。
3. handover §4 未搬清单补齐（tools 3 项 + docs 2 份），exp 路径更正。
4. ESSENCE 补一行 exec 禁忌（见 Q1）。
5. 独立化 my2（解除 R1）：clone → checkout my2。

## 六、修复记录（2026-09-16）
- handover：§2 表与 §6 命令 7 的 `exp/` 路径更正为 `root/exp`；§4 未搬清单补齐（tools 杂项 3 项、docs 计数 12→13 并补点名 2 份）；R3 更正为"已修复"；§6 命令 5 期望与实际对齐；文首补审计结论指引。
- `PORTING_PLAYBOOK.md:183`：`docs/MTK_BROM_DUMP.md` 已加"已归档于旧工作树"标注（唯一悬空引用闭环）。
- `ESSENCE.md` §0：标题"三条铁律"→"五条铁律"，新增第 5 条：命中后禁 exec/setuid/setgid（exec 会以被污染 cred 重建，新镜像必死）。
- 复验：悬空引用检查现仅命中已标注的 MTK_BROM 归档引用（机制性命中，属预期）；其余断言不变。
