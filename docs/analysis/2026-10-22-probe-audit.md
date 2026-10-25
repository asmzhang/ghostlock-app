# 探针代码审计 — 2026-10-22

审计对象：`main-510-port` @ `9443450` 工作树中 **6 个未提交文件**（+162 / −2），全部为 `TEMP(...)` 探针。
审计依据：`AGENTS.md`「核心攻击代码审查」四条（所有权与生命周期 / UAF / 终结点与清理顺序 / 反汇编核对）。

## 1. 所有权与生命周期

| 对象 | 创建 | 所有者 | 访问者 | 终结点 | 释放者 |
| --- | --- | --- | --- | --- | --- |
| `g_wd_stop`（static int32_t，threads.cpp:343） | 静态初始化 | 进程 | heartbeat 线程（:346/:355）、主线程（:397/:401） | 进程退出 | — |
| `wd_tid`（pthread_t，:398） | `pthread_create` @ :399 | `run_main_route_threads` 栈 | 同函数 | `pthread_join` @ :403 | 同函数 |
| 面包屑 fd | `spray_breadcrumb` 内 `open` | 调用线程栈 | 同线程 | `close()` 同函数 | 同函数 |
| hold marker | 外部 `touch` | 用户 | `hold_after_route_if_requested` | `access()` 即返回 | — |
| 17 处 `w3diag-*` | 每次调用即时写 | 调用者栈 | 同线程 | 函数返回 | — |

**UAF**：无。所有 fd 都是「开—写—fsync—关」的局部生命周期，不跨线程共享；`wd_tid` 在 join 前始终有效；
`pthread_create` 失败时 `wd_err != 0`，join 被跳过，`wd_tid` 是 `{}` 初始化的 0，不会误 join。

**fork 安全性**：`spray_breadcrumb` → `config::runtime_config_snapshot()` 只是返回 `g_exploit_session.runtime`
的引用（`exploit_session.cpp:28`），**不加锁、不分配**；`std::array` 在栈上，`snprintf` 不分配。
因此在 victim 子进程（多线程父进程 fork 出来的）里调用是安全的，不存在「fork 后拿已被持有的锁」的死锁。

**终结点顺序**：heartbeat 在 `race.run()` 返回后立即 `stop=1` + join（:401-403），
之后才可能走 `fail_stop_dirty_race()` 的 `exit_group(70)` ⇒ 顺序正确。

## 2. 发现

### P1（真实风险）心跳线程创建在 spray 与 walk 之间

`threads.cpp:399` 的 `pthread_create` 发生在 `start_threads()` 之后、`race.run()` 之前 ——
也就是**紧挨着 pselect 之前**。一次 `clone` 要分配 `task_struct`、内核栈、`mm` 引用计数，
这些分配正好可能回收我们刚 spray 出去、还没被 walk 用掉的那 32 KiB 页。

这与「27% 的 craft 不落位」的假设直接冲突：**探针本身可能就是原因之一**。

建议：把心跳线程提前到 `start_threads()` 之前创建（spray 之前），route 窗口内只用
`__atomic_store` 唤醒；或改成 route 返回后一次性回填起止时间戳（无窗口内线程）。

### P2（测量污染）route 窗口内的 fsync

心跳每 500 ms 一次 `open/write/fsync/close`。fsync 会进文件系统日志路径，
在 pselect 的 200 ms 超时窗口内制造 I/O 与内核锁。样本上最多 1 次，但方向不可控。

### P3（规范违反）新增可变全局 `g_wd_stop`

`AGENTS.md` 写明：「全局状态只允许 `g_exploit_session`（进程唯一 singleton）与启动期只读的
`g_direct_map_end`；新代码不得再引入可变全局」。`g_wd_stop` 虽是 `TEMP` 且在匿名命名空间，
提交前必须处理（改成 `PiRace` 成员或 `run_main_route_threads` 的 static 局部）。

### P4（时序改变）W3 的 F 交换路径多 4 次 fsync

`victim_process.cpp` 在 child 的 `'F'` handler 里新增 `w3diag-F-recv/forked/exited/replied`
四个面包屑（父侧另有 3 个）。父进程在 `verify_seccomp_probe_stage` 里**阻塞 `read` 4 字节**，
子进程每个面包屑都是一次 `open+fsync+close` ⇒ F 交换的往返时间被拉长。
W3 的 50 ms settle / 时序假设是否仍成立，需要重新确认。

### P5（判据偏松）reclaim send 的部分写被计为成功

`util.cpp` 里 `sent <= 0` 才算失败，`sent > 0` 即 `reclaim_ok++`。
`sendmsg` 在 `MSG_DONTWAIT` 下可能只排入部分数据。判据应为 `sent == 期望长度`。

## 3. 对攻击路径的行为差异

| 文件 | 差异 | 是否改变控制流 |
| --- | --- | --- |
| `threads.cpp` | 心跳线程 + `wd req` + `wd route-returned` 三条面包屑 | 否（只新增线程与日志） |
| `select_stack_route.cpp` | `psel page/lock/w0/task/shift` 一行 | 否（读 `heap.current`，在 `open_selected_fds` 之前） |
| `cve_2026_43499_backend.cpp` | `hold_after_route_if_requested()`（无 marker 立即返回） | 否 |
| `victim_process.cpp` | 17 处 `w3diag-*` 面包屑 + 一个 `else` 分支（只写日志） | 否 |
| `util.cpp` | reclaim 计数 + `step6 done` 面包屑 + 一行 pr_info | 否 |

反汇编核对：`cmp_disasm` 对 8 个攻击函数，仅 `waiter_thread` / `run_main_route_threads` /
`prepare_good_kernel_page` 因探针本体出现计数变化，其余全部 LAYOUT-SHIFT-only。

## 4. 数据可信度评估

- **单条命中率 72.4%（110/152）无法用于判断探针影响**：152 个标定样本**全部**来自
  没有心跳的构建（`wd t=` 行 0 命中）。带心跳的轮次样本量不足（1–2 个），不能做前后对比。
- 因此「72.4%」是**无心跳构建**的干净数字；今天下午带心跳的轮次命中率是否更低，
  现有数据无法回答 —— 必须在 P1 修复后重测才能确认。

## 5. 处理建议

**收尾前必做**
1. P1：心跳线程前移（或改为 route 返回后回填）—— 这是唯一可能**改变命中率**的项。
2. P3：`g_wd_stop` 去全局化。
3. 删除 `hold_after_route_if_requested`（三处：decls.hpp / util.cpp / backend 调用点）——
   仅 15:03 一轮用过，已完成使命。

**可选保留**
4. `psel page=...` 与 `wd req` / `wd route-returned` 面包屑（只读、无窗口内线程）。
5. `w3diag-*`（若还要继续查 W3 wedge；否则一并删除）。
6. P5：把 reclaim 判据收紧为 `sent == 期望长度`。

**重新基线**
修复 P1 后跑 8 轮，重新测「单条命中率」与「全链成功率」，再决定是否加 abort 门。

## 6. 处理记录（2026-10-22 16:38）

用户批准 ①②③ 后按下列方式落地：

| 项 | 处理 | 结果 |
| --- | --- | --- |
| P1 | **删掉窗口内线程**。`g_wd_stop` + `wd_heartbeat` + `pthread_create/join` 全部移除；改为 `clock_gettime(CLOCK_MONOTONIC)` 取 `race.run()` 前后时间，route 返回后写一行 `wd route-returned code=%d elapsed=%dms` | 窗口内零 `clone`。挂死的 route 只是不写这行 —— 与「没返回」同义，正是要的信号 |
| P3 | `g_wd_stop` 随之消失，无新增全局 | 符合 `AGENTS.md` 全局状态约束 |
| ③ | 删除 `hold_after_route_if_requested`（`decls.hpp` 声明 / `util.cpp` 实现 / `backend` 调用点） | 三处清零 |
| P5 | reclaim 判据改为 `sent == SKB_SEND_SIZE`；短写记 `reclaim_errno = -1` 以便区分 | `step6 done` 的 `ok=` 现在是严格计数 |
| P2 | 随 P1 一并消失（窗口内不再有 fsync 循环） | — |
| P4 | 保留 `w3diag-*`（仍在查 W3 wedge）；F 交换的 fsync 开销未动 | 待 W3 收尾时一并删 |
| 保留 | `wd req` / `psel page=...` / `w3diag-*` 三类只读面包屑 | 无窗口内线程、无全局 |

**门禁**（对照 `build/ghostlock-gh2-preprobe.bin`）：
`IDENTICAL owner_thread (69)`、`IDENTICAL waiter_thread (918)`（canary 删除后恢复逐条一致）；
`DIFF run_main_route_threads 414→461`（计时 + 面包屑）、`DIFF prepare_good_kernel_page 2104→2144`（reclaim 判据）；
其余 `LAYOUT-SHIFT` only。构建 2,792,496 B，零告警；`clang-tidy` 三个改动源文件 exit=0 / 0 diagnostics。

**注意**：`waiter_thread` 回到 918 说明 canary A/B 确已不在树里；`run_main_route_threads` 的 +47 全部是计时与面包屑。

