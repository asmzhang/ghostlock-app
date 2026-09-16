# marble root 恢复与配置固化 — 2026-09-15

> 设备：Xiaomi marble / Redmi Note 12 Turbo（`23049RAD8C`，SM7475），adb `3e6f1443`
> 内核：`5.10.149-android12-9-00001-gda3d81545d1d-ab9545656`
> 结果：**root 已恢复并通过终验**（`gid=0` + `u:r:magisk:s0`），可用参数已锁定。

## 1. 固化下来的可用配置（照此可复现）

| 项 | 值 |
|---|---|
| **代码版本** | **`347dfec8fa6cd5c204a693565f7e9fd1482ee6ca`** — "ghostlock: load kpatch in-process via userspace ELF relocation (root achieved)"（2026-09-11 11:44:52）|
| **二进制** | `_head_347/ghostlock_doc`，**100880 字节**，md5 `36430a2fbb2c42c243acf9a8698d169e` |
| **构建命令** | 见 §2 第 ① 步（文档原样的 4 文件 clang；`make` 产出**同尺寸**，互为交叉验证）|
| **参数** | `SHIFT=-2`、`CORE=4`、`CCORE=5`（锁在 **`<ARCHIVE_DIR>/gl_tuned.env`**）|
| 关键 env | `GHOSTLOCK_SHIFT=-2 / CORE / CONSUMER_CORE / SKIP_POLICY_FIXUP=1 / LAYOUT=A / SELF_W2=1 / INSMOD_ONLY=1 / HOLD=1`（**无 `OWNER=fake`**，即 OWNER 空 = INIT_TASK）|
| 轮数 | `ROUNDS=30`、`REBOOT_EVERY=0`（本轮命中在第 **14** 轮；历史命中在第 28/7/1/1/22/1/14/43 轮）|
| APatch 版本 | 管理器 **11224**（9a63e0f，签名 APK 归档 `_ghostlock_refs/`）+ .ko **0.13.8**；最低要求与匹配规则见 `APATCH_VERSIONS.md` |

> ⚠️ `run.sh:115` 原本硬编码 `GHOSTLOCK_OWNER=fake`，**成功文档的六项 env 里没有它** ⇒
> 已改为 `GHOSTLOCK_OWNER=${OWNER:-}`（默认空 = INIT_TASK，与当年一致）。备份：`run.sh.bak` / `run.sh.bak2`。

## 2. 完整步骤（本轮实际执行并验证过的）

```bash
export ANDROID_HOME=D:/platform/Android/Sdk ; DEV=3e6f1443

# ① 取正确提交并构建（worktree 用相对路径；root_template.h 是生成物，需从当前树拷入）
cd <ARCHIVE>
git worktree add _head_347 347dfec
cp src/core/root_template.h _head_347/src/core/root_template.h
cd _head_347
"/d/platform/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android35-clang" \
  -O2 -flto -Wall -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"target.h\" \
  -fPIE -pie -pthread src/core/main.c src/core/offsets_json.c src/core/util.c src/core/fops.c \
  -o ghostlock_doc                                  # ⇒ 100880 字节

# ② 部署（adb.exe 只认盘符路径！）
adb -s $DEV push <ARCHIVE>/_head_347/ghostlock_doc /data/local/tmp/ghostlock
adb -s $DEV push <ARCHIVE_DIR>/android12-5.10_kernelpatch.ko /data/local/tmp/kernelpatch.ko
adb -s $DEV shell 'chmod 755 /data/local/tmp/ghostlock'

# ③④ 跑循环 + 独立 watcher（两条都要起；用工具的"托管后台"，不要 nohup &）
cd <ARCHIVE>
GHOSTLOCK_BIN="<ARCHIVE>/_head_347/ghostlock_doc" ROUNDS=30 REBOOT_EVERY=0 \
  bash tools/harness/run.sh            # 期望：多轮 PANIC (fired, died) …… 直到 SUCCESS (hit N)
bash tools/harness/watcher.sh          # 盯 /proc/modules，模块一出现立刻验证

# ⑤ 命中后【立刻停 harness】（否则下一轮 panic 会打掉 root）
# ⑥ 稳住窗口
adb -s $DEV shell "su -c 'echo 0 > /proc/sys/kernel/panic_on_oops; echo 0 > /proc/sys/kernel/panic_on_rcu_stall'"

# ⑦ 让它变成"正规 root"（APatch 通道）
adb -s $DEV shell 'am force-stop me.bmax.apatch; am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity'
adb -s $DEV push <REFS_DIR>/libapd.so /data/local/tmp/libapd.so     # 若设备上没有
adb -s $DEV shell "su -c 'chmod 755 /data/local/tmp/libapd.so; /data/local/tmp/libapd.so soft-reboot'"
sleep 50
adb -s $DEV shell 'cat /proc/uptime; grep -c kernelpatch /proc/modules'   # 内核未重启 + 模块仍在
adb -s $DEV shell "su -c '/data/adb/ap/bin/apd resetprop sys.boot_completed 1'"
adb -s $DEV shell 'am force-stop me.bmax.apatch; am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity'

# ⑧ 终验
adb -s $DEV shell 'su -c id'
```

## 3. 终验输出（本次实测，与 `GHOSTLOCK_SUCCESS_2026-09-11.md` 逐字符一致）

```
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs) context=u:r:magisk:s0
```
`kernelpatch 126976 0 - Live 0x0000000000000000 (O)` 在 `/proc/modules` ✓

## 4. 本次踩过的坑（务必遵守）

| # | 坑 | 正确做法 |
|---|---|---|
| 1 | **命中前的中间态**：`su -c id` 显示 **gid 为垃圾值**（如 `4116308992`）⇒ 这是 hook 态，**还没 soft-reboot** | 按 §2 ⑦ 做完才是 `gid=0` |
| 2 | **长跑后台用 `nohup &` 会被"中断命令"连带杀死**（harness 曾静默死在 round 3，日志都没生成）| 用工具的**托管后台**启动 |
| 3 | `adb.exe` 不认 POSIX 路径（`/d/...`）⇒ push 静默失败 | 一律用**盘符路径** `D:/...` |
| 4 | `android12-5.10_kernelpatch.ko` / `libksud.so` 实际在 **`<REFS_DIR>/`（上一层）** | 复制到 `<ARCHIVE_DIR>/`（harness 期望位置）|
| 5 | harness 中途的累计 `hit=` 不可信（要轮次结束才打印）| 以 **watcher 的 `/proc/modules`** 为准（它会早几十秒看到）|
| 6 | **命中后不停 harness** ⇒ 下一轮 panic 打掉 root | **立即 `pkill -f tools/harness/run.sh`** |
| 7 | worktree 用 POSIX 绝对路径会被拼成 `D:/d/...` | 用**相对路径**（`git worktree add _head_347 347dfec`）|
| 8 | `347dfec`（及 HEAD）**不自足**：缺生成物 `src/core/root_template.h` ⇒ `expected expression` | 从当前工作树**拷该头**进 worktree |

## 5. 下次要再拿 root（设备已重启后）

参数已固化在 `<ARCHIVE_DIR>/gl_tuned.env`（`SHIFT=-2 CORE=4 CCORE=5`）⇒ 用同一套 §2 步骤即可；
若逐轮跟跑代价高，可用 harness 的 USE 模式（读 `gl_tuned.env`）。

## 6. 仍未解决（与本文件无关）

**当前工作树的未提交改动会让 marble 秒崩在 C1**，而本文件所用的 `347dfec` 正常
⇒ 那批改动里存在回归（嫌疑区：`3f441be`(12:09) 之后的提交 + 未提交改动）。
定位它见任务 #3。
