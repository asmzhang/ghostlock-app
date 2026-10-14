# Device gate: marble 5.10.149 — 同 boot 短路 W1（每轮 pselect 次数减半）

## 结论

在 Redmi Note 12 Turbo（marble，`3e6f1443`，内核 `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）上，
同一 boot 内一旦命中过一次（SELinux 已变 permissive），后续每一轮的 W1 段会被
`src/core/session/backend/cve_2026_43499_backend.cpp:404` 的 `attack::check_selinux_off()` 整段短路，
于是**每轮只需要 1 次 pselect（只剩 W2），而不是 2 次（W1+W2）**。

批次 `rounds-p01p02-v4c`（原计划 30 轮，第 14 轮后由用户中止）实测：

| 分组 | 轮次 | 命中 | 单轮 pselect 次数 |
| --- | --- | --- | --- |
| 同 boot 续跑（W1 被短路） | r2 r3 r4 r9 r10 r11 r13 r14 | **8/8 = 100%** | 1 |
| 新 boot 首跑（W1 必须重做） | r1 r5 r6 r7 r8 r12 | **3/6 = 50%** | 2 |
| 合计 | 14 | **11/14 = 78.6%** | — |

对照同日 `rounds-p01p02-v4b`（`-RebootAfterHit`，每命中即重启 ⇒ 每轮都付 2 次 pselect）的
21/30 = 70.0%。⇒ 把「每轮都付 2 次」改成「每个 boot 只有第 1 轮付 2 次」，是同向的改进；
但**新 boot 首跑仍是唯一风险点**（3/6 = 50%），而且它那两次 pselect 无法避免（SELinux 在重启后必然回到 enforcing）。

复算命令（本文件的统计都由它产出）：

```sh
python tools/trials/tally.py build/510profile/rounds-p01p02-v4c/summary.txt
```

## 判据

| 项 | v4c 批次 |
| --- | --- |
| 调用 | `powershell -NoProfile -ExecutionPolicy Bypass -File tools/trials/trials_ps4.ps1 -Rounds 30 -Dev 3e6f1443 -PollSeconds 70 -SettleSeconds 20 -Tag rounds-p01p02-v4c -RebootEveryHits 4`（脚本 md5 `18E255ED46394126B9B784BBE8602E2C`） |
| 时间 | 2026-10-14 13:58:39 – 14:24:56（第 14 轮后中止，未跑完 30 轮） |
| 已跑轮数 | 14 |
| W1 落地（`W1=ok`） | 4（r1 r6 r8 r12） |
| 进入 W2（`W2=entered`） | 12 |
| verdict `HIT-ROOT` | 11（78.6%） |
| verdict `PANIC` | 3（r5 r6 r7，全部发生在重启后的首轮） |
| verdict `FREEZE` | 0 |
| 每轮 up_before | 43–52 s（重启后首轮）/ 168–403 s（同 boot 续跑） |
| native 二进制 | `build/native/ghostlock` md5 `DFB94C4322CBEDC423049444C0CC260C`（2782744 B，与设备 APK 内 `.so` 同源） |
| 设备 APK | `base.apk` md5 `69567f0a335010e63b1b4df3c1c46f06` |
| 日志 | `build/510profile/rounds-p01p02-v4c/round-N.full.log` + `summary.txt` |
| 归档时间 | 2026-10-14 |

## 逐字证据：round 14（`W1=no`，同 boot 续跑）确实跳过了 W1

`build/510profile/rounds-p01p02-v4c/round-14.full.log:42-63`：

```
[+] startup context pid=31053 uid=10271 euid=10271 gid=10271 egid=10271 boot_ms=314366 attr=u:r:untrusted_app:s0:c15,c257,c512,c768 enforce=0
[+] startup limits pid=31053 NoNewPrivs=0 Seccomp=2 Seccomp_filters=1
[*] main thread running on cpu=4
[*] [T+0ms] exploit start
[+] SELinux already permissive
GLK_STATUS w1a completed
GLK_STATUS w1b completed
[*] [T+508ms] pre-W2 drain
[*] perf task: 0xffffff889bc63780 (7779/8192 votes)
[*] [T+843ms] perf_find_task done
[*] child_pid=31227 child_task=0xffffff889bc63780
GLK_STATUS w2b in_progress
[*] vr.ko not loaded; skipping tag clear
GLK_STATUS w2b completed
GLK_STATUS w2a in_progress
[*] W2: cred attempt 1/15
[*] === W2: cred === target=0xffffff889bc63f00 mode=2 leaf=0
```

判读：整段没有 `[*] W1: SELinux attempt`、没有 `[*] === W1: SELinux ===`、也没有 W1 的那次
`pselect route setup`；`w1a`/`w1b` 两个状态步在 508 ms 内直接完成，然后进入 `pre-W2 drain`。
⇒ W1 没有做任何一次 pselect。对比 round 12（新 boot 首跑，`W1=ok`）有完整的
`W1: SELinux attempt 1/15` → `pselect route setup` → `pselect route done calls=1 success=1` → `[+] SELinux permissive`。

## 机理

- 判定点在 `src/core/session/backend/cve_2026_43499_backend.cpp:401-431`：`w1()` 先调用
  `attack::check_selinux_off()`，只有 `if (!selinux_ok)` 才进入 SELinux 写入阶段。
- SELinux 的 permissive 状态在同一 boot 内不会被重置，所以第一次命中之后的每一轮都命中该短路。
- 重启会把 SELinux 恢复为 enforcing ⇒ 每个 boot 的第 1 轮必然要付 W1 的那次 pselect。

## 与 v4（`2026-10-14-marble-v4-reclaim-order.md`）的关系

v4 把单次 W1 pselect 的落地率从 26.7% 提到 80%；本实验进一步把「每轮要赌几次」从 2 次降到 1 次。
两者叠加的效果是：每个 boot 只有第 1 轮是「两次连续赌博」，其余轮都是「一次赌博」。

## harness 变化

`tools/trials/trials_ps4.ps1` 新增 `-RebootEveryHits N`：每命中 N 次主动重启一次
（`=== rebooting to re-arm the watchdog (RebootEveryHits=4 at hit #4) ===`），用来把「同 boot 续跑」与
「新 boot 首跑」分开计量。该选项与 `-RebootAfterHit` 互斥优先（`-RebootAfterHit` 优先）。批次运行期间
脚本本体被追加过「重启后 uptime 打印」修复（`Invoke-AdbTimed … cat /proc/uptime` + `<no answer>` 兜底），
不影响判轮逻辑。

## 未决

1. 批次被中止在第 14 轮（原计划 30 轮）⇒ 未产出 Fisher p 值；同 boot 8/8 的方向性结论已成立，
   但要把 p 值做实需要补跑剩余 16 轮。
2. 新 boot 首跑（2 次 pselect）仍是唯一风险点，3/6 = 50%；它无法通过「少赌一次」规避。
3. 同 boot 内打偏的形态应当是 `FREEZE`（命中时已写 `panic_on_oops=0` 并 unbind 了 `gh-watchdog`），
   本批次 0 次 FREEZE ⇒ 该路径未被覆盖。
4. 单次 pselect 生还率 ~85% 仍是硬上限：W3 重开需要最多 13 次 pselect，在该概率下不可行
   （这是 `w3_attempts=0` 的直接原因）。
5. 设备在本批次结束时留有 3 个存活 root 进程（pid 3639 / 18089 / 24886，即 r12/r13/r14 的 handoff
   worker），SELinux 保持 Permissive，直到下一次重启。
