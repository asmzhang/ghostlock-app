#!/bin/bash
# GhostLock 命中后的收尾流程 —— 把原先手敲的 5 步固化成一条命令。
#
# 为什么需要它：
#   命中一次要等 1~20 分钟，而收尾步骤（软重启 → 修启动标志 → 填授权表 →
#   重启管理器 → 验证）本次是逐条手敲的，任何一步敲错都要再等一次命中。
#
# 设计约束（都来自实测踩坑）：
#   * **幂等**：可重复执行；无命中时安全退出，不会把设备带进坏状态。
#   * **不覆盖已有授权**：package_config 里可能已有用户授权过的应用（实测出现过
#     bin.mt.plus），必须读取-合并-去重，而不是整体覆盖。
#   * `apd` 的 resetprop 是**子命令**，不能走符号链接调用（会报 unrecognized subcommand）。
#   * soft-reboot 会把 sys.boot_completed 置 0，而 system_server 往往没真正重启，
#     于是没人置回 1 → 管理器永远停在"等待软重启"。必须手动修。
#
# 用法： bash tools/harness/finish.sh [包名...]
#        默认包名取 me.bmax.apatch
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
require_dev || exit 1
config_init "$@" || exit 1

PKGS=("$@")
# 默认包名来自配置（GL_AP_PKGS，空格分隔），不再写死在脚本里
if [ ${#PKGS[@]} -eq 0 ]; then
    read -r -a PKGS <<< "${GL_AP_PKGS:-me.bmax.apatch}"
fi

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
dev_sh() { tmo 25 adb -s "$DEV" shell "$@"; }
dev_su() { tmo 25 adb -s "$DEV" shell "su -c \"$1\""; }

# ---------------------------------------------------------------- 0. 前提检查
say "0. 前提：内核里有没有 kpatch"
MODS=$(dev_sh 'grep -c kernelpatch /proc/modules 2>/dev/null' | tr -d '\r')
if [ "${MODS:-0}" != "1" ]; then
    echo "  /proc/modules 里没有 kernelpatch。"
    echo "  收尾只能在命中并成功加载模块之后进行；本次不做任何改动，直接退出。"
    exit 2
fi
echo "  kpatch 已在内核中。"

# 授权表现状（只读）+ 表头校验，提前做——dry-run 也要能看到结论
CUR=$(dev_su "cat ${D_AP}/package_config" 2>/dev/null | tr -d '\r')
CUR_HEADER="$(printf '%s\n' "$CUR" | head -1)"
if [ -n "$CUR_HEADER" ] && [ "$CUR_HEADER" != "${GL_AP_HEADER:-pkg,exclude,allow,uid,to_uid,sctx}" ]; then
    if [ "${GL_AP_FORCE:-0}" != 1 ]; then
        echo "  [!] 现有 package_config 表头与预期不一致，已中止写入：" >&2
        echo "      实际: $CUR_HEADER" >&2
        echo "      预期: ${GL_AP_HEADER:-pkg,exclude,allow,uid,to_uid,sctx}" >&2
        echo "      确认表结构后可用 GL_AP_HEADER=<实际表头> 覆盖，或 GL_AP_FORCE=1 强制写入。" >&2
        exit 3
    fi
    echo "  [!] 表头不一致但 GL_AP_FORCE=1，继续写入"
fi

if [ "${DRY_RUN:-0}" = 1 ]; then
    echo
    echo "--- DRY-RUN：以下步骤不会执行（当前只读检查已完成）---"
    echo "1) soft-reboot（${D_TMP}/libapd.so soft-reboot）→ 等 zygote running → 核对 uptime 连续增长（内核未重启）"
    echo "2) 若 sys.boot_completed != 1 → ${D_AP}/bin/apd resetprop sys.boot_completed 1"
    echo "3) 授权表（表头 ${GL_AP_HEADER:-pkg,exclude,allow,uid,to_uid,sctx}；现有 $([ -n "$CUR_HEADER" ] && echo 1 || echo 0) 行表头）："
    echo "   包名=${GL_AP_PKGS:-me.bmax.apatch}  新行模板=${GL_AP_ROW_FMT:-%s,0,1,%s,0,u:r:magisk:s0}"
    echo "4) 重启管理器：am force-stop/start <包名>"
    echo "5) 终验：su -c id / grep kernelpatch /proc/modules / 管理器 UID=0 子进程"
    exit 0
fi

# ---------------------------------------------------------------- 1. 软重启
say "1. 软重启（只重启框架，内核与模块保留）"
BEFORE=$(dev_sh 'cut -d" " -f1 /proc/uptime' | tr -d '\r')
echo "  重启前 uptime=$BEFORE"
dev_su "chmod 755 ${D_TMP}/libapd.so 2>/dev/null; ${D_TMP}/libapd.so soft-reboot" >/dev/null 2>&1
echo "  已下发 soft-reboot，等待框架恢复…"
for _ in $(seq 1 40); do
    sleep 5
    st=$(dev_sh 'getprop init.svc.zygote' 2>/dev/null | tr -d '\r')
    [ "$st" = "running" ] && break
done
sleep 10
AFTER=$(dev_sh 'cut -d" " -f1 /proc/uptime' 2>/dev/null | tr -d '\r')
echo "  重启后 uptime=$AFTER  (只涨几十秒即证明内核没重启)"
if [ "${MODS}" = "1" ]; then
    echo "  模块: $(dev_sh 'grep -c kernelpatch /proc/modules' 2>/dev/null | tr -d '\r')"
fi

# ---------------------------------------------------------------- 2. 修启动标志
say "2. 修正 sys.boot_completed（soft-reboot 置 0 后无人置回）"
BC=$(dev_sh 'getprop sys.boot_completed' | tr -d '\r')
echo "  当前 = ${BC:-空}"
if [ "$BC" != "1" ]; then
    # 注意：resetprop 是 apd 的子命令
    dev_su "${D_AP}/bin/apd resetprop sys.boot_completed 1" >/dev/null 2>&1
    sleep 2
    echo "  修正后 = $(dev_sh 'getprop sys.boot_completed' | tr -d '\r')"
else
    echo "  已是 1，跳过。"
fi

# ---------------------------------------------------------------- 3. 授权表（幂等合并）
say "3. 确保管理器自身在授权表内"
LISTENER_UP=$(dev_sh 'ps -A -o NAME 2>/dev/null | grep -c "^apd$"' | tr -d '\r')
if [ "${LISTENER_UP:-0}" = "0" ]; then
    dev_su "nohup ${D_AP}/bin/apd uid-listener </dev/null >>${D_AP}/log/uid_listener.log 2>&1 &" >/dev/null 2>&1
    sleep 3
    echo "  已启动 uid-listener（inotify 监听 ${D_AP}/）"
else
    echo "  uid-listener 已在运行"
fi

# 读取现有条目 -> 合并缺失 -> 用 rename 落地（rename 才会触发 inotify）
# （CUR 读取与表头校验已在步骤 0 之后完成）
NEW="${GL_AP_HEADER:-pkg,exclude,allow,uid,to_uid,sctx}"
ADDED=0
for pkg in "${PKGS[@]}"; do
    uid=$(dev_sh "dumpsys package $pkg 2>/dev/null | grep -m1 userId" | tr -d '\r' | grep -oE '[0-9]+')
    if [ -z "$uid" ]; then
        echo "  [跳过] $pkg 未安装"
        continue
    fi
    if printf '%s\n' "$CUR" | grep -q "^${pkg},"; then
        echo "  [已有] $pkg (uid=$uid)"
        NEW="${NEW}"$'\n'"$(printf '%s\n' "$CUR" | grep "^${pkg},")"
    else
        NEW="${NEW}"$'\n'"$(printf "${GL_AP_ROW_FMT:-%s,0,1,%s,0,u:r:magisk:s0}" "$pkg" "$uid")"
        ADDED=$((ADDED + 1))
        echo "  [新增] $pkg (uid=$uid)"
    fi
done
# 保留表中其它既有条目
while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in pkg,*) continue ;; esac
    keep=1
    for pkg in "${PKGS[@]}"; do
        case "$line" in "${pkg},"*) keep=0 ;; esac
    done
    [ "$keep" = "1" ] && NEW="${NEW}"$'\n'"$line"
done <<<"$CUR"

if [ "$ADDED" -gt 0 ]; then
    printf '%s\n' "$NEW" > /tmp/_pkgcfg
    adb -s "$DEV" push /tmp/_pkgcfg "${D_TMP}/_pkgcfg" >/dev/null 2>&1
    dev_su "cp ${D_TMP}/_pkgcfg ${D_AP}/package_config.tmp && chmod 644 ${D_AP}/package_config.tmp && mv ${D_AP}/package_config.tmp ${D_AP}/package_config"
    sleep 4
    echo "  授权表已更新（新增 $ADDED 条）"
else
    echo "  授权表无需变更"
fi
echo "  当前内容:"; dev_su "cat ${D_AP}/package_config" 2>/dev/null | sed 's/^/    /'

# ---------------------------------------------------------------- 4. 重启管理器
say "4. 重启管理器以重新读取内核状态"
for pkg in "${PKGS[@]}"; do
    dev_sh "am force-stop $pkg" >/dev/null 2>&1
    sleep 2
    dev_sh "am start -n $pkg/$pkg.ui.MainActivity" >/dev/null 2>&1
    echo "  已重启 $pkg"
done
sleep 8

# ---------------------------------------------------------------- 5. 验证
say "5. 验证"
echo "  --- su -c id ---"
dev_sh 'su -c id' 2>&1 | sed 's/^/    /'
echo "  --- /proc/modules ---"
dev_sh 'grep kernelpatch /proc/modules' 2>&1 | sed 's/^/    /'
echo "  --- 管理器的 root 子进程（UID 应为 0）---"
for pkg in "${PKGS[@]}"; do
    pid=$(dev_sh "pidof $pkg" | tr -d '\r' | awk '{print $1}')
    [ -z "$pid" ] && continue
    dev_su "ps -A -o PID,PPID,UID,NAME 2>/dev/null | awk '\$2==$pid'" 2>&1 | sed 's/^/    /'
done

say "完成"
echo "  判定标准：su 的 gid 应为 0，SELinux 域为 u:r:magisk:s0，"
echo "            且管理器进程下出现 UID=0 的子进程。"
