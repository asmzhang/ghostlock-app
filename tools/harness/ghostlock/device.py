"""设备操作层：adb 封装、设备探测、核心对探测、推送校验、收尾流程、/proc/modules 监视。

这一层只跟"设备"打交道，不做流程编排（编排在 flow.py）。
"""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

from . import plat
from .config import Config

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}OK{RESET}   {msg}")


def to_display(items: list[str], keep: int = 8) -> str:
    return " ".join((x[:keep] + "…") if len(x) > keep else x for x in items)


def bad(msg: str) -> None:
    print(f"  {RED}FAIL{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}WARN{RESET} {msg}")


class Device:
    def __init__(self, serial: str, adb: str | None = None):
        self.serial = serial
        self.adb_bin = adb or plat.adb_binary()

    # ------------------------------------------------------------ 基础
    def adb(self, *args: str, timeout: float | None = 60) -> subprocess.CompletedProcess:
        try:
            return plat.run([self.adb_bin, "-s", self.serial, *args], timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return subprocess.CompletedProcess([], 124, stdout=e.stdout or "", stderr="timeout")

    def shell(self, cmd: str, timeout: float | None = 30) -> str:
        return self.adb("shell", cmd, timeout=timeout).stdout.replace("\r", "").strip()

    def shell_su(self, cmd: str, timeout: float | None = 30) -> str:
        return self.shell(f'su -c "{cmd}"', timeout=timeout)

    def push(self, src: Path | str, dst: str, timeout: float | None = 180) -> bool:
        return self.adb("push", plat.as_arg(src), dst, timeout=timeout).returncode == 0

    def uptime(self) -> str:
        return self.shell("cat /proc/uptime").split(" ")[0] if self.shell("cat /proc/uptime") else ""

    def modules_count(self, name: str = "kernelpatch") -> int:
        out = self.shell(f"grep -c {name} /proc/modules 2>/dev/null")
        try:
            return int(out or 0)
        except ValueError:
            return 0

    def has_root(self) -> bool:
        out = self.shell("su -c id", timeout=25)
        return "uid=0" in out and "u:r:magisk:s0" in out

    def id_line(self) -> str:
        return self.shell("su -c id", timeout=25)


def detect_device(adb: str | None = None) -> str | None:
    """GHOSTLOCK_DEV → 型号匹配 → 唯一设备。"""
    env_dev = __import__("os").environ.get("GHOSTLOCK_DEV")
    if env_dev:
        return env_dev
    binary = adb or plat.adb_binary()
    try:
        out = plat.run([binary, "devices", "-l"], timeout=30).stdout
    except Exception:
        return None
    rows = [ln for ln in out.splitlines() if " device " in ln]
    if not rows:
        return None
    target = __import__("os").environ.get("GHOSTLOCK_TARGET_MODEL", "marble")
    for ln in rows:
        if f"model:{target}" in ln or f"device:{target}" in ln:
            return ln.split()[0]
    if len(rows) == 1:
        return rows[0].split()[0]
    return None


def detect_core_pair(dev: Device) -> tuple[str, str]:
    """取"成员 ≥2 的最高频同簇"的前两个核；探测不到退回 4/5。
    为什么不用最高频单核：两线程跨簇会引入调度迁移抖动，而本漏洞依赖两线程时序对齐。"""
    raw = dev.shell(
        "for d in /sys/devices/system/cpu/cpu[0-9]*; do "
        "[ -r \"$d/cpufreq/cpuinfo_max_freq\" ] || continue; "
        'echo "$(cat $d/cpufreq/cpuinfo_max_freq 2>/dev/null) $(basename $d | sed s/cpu//)"; done',
        timeout=25,
    )
    rows = []
    for ln in raw.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1]))
    if not rows:
        return "4", "5"
    groups: dict[int, list[str]] = {}
    for freq, core in rows:
        groups.setdefault(freq, []).append(core)
    best: list[str] = []
    for freq in sorted(groups, reverse=True):
        if len(groups[freq]) >= 2:
            best = groups[freq][:2]
            break
    if len(best) < 2:
        return "4", "5"
    return best[0], best[1]


def stage(dev: Device, cfg: Config, log=print) -> bool:
    """推送二进制与 .ko，并按 md5 校验（/data/local/tmp 在早期启动会回滚，故重试）。"""
    for _ in range(60):
        if dev.shell("echo ok", timeout=10) == "ok":
            break
        time.sleep(3)
    for _ in range(40):
        if dev.shell("getprop sys.boot_completed", timeout=10) == "1":
            break
        time.sleep(3)
    time.sleep(2)

    expect_bin = plat.md5_of(cfg.bin_path)
    expect_ko = plat.md5_of(cfg.ko_path)
    d_tmp, d_sdcard = cfg.d_tmp, cfg.d_sdcard
    for i in range(1, 9):
        dev.push(cfg.bin_path, f"{d_tmp}/ghostlock")
        dev.push(cfg.ko_path, f"{d_tmp}/kernelpatch.ko")
        # KernelSU 路线本轮刻意不铺：root 脚本会优先走 ksud+kernelsu.ko，而 kernelsu.ko
        # 在这台设备上从未加载成功过，会把唯一一次命中引到未验证的分支。
        dev.shell(f"rm -f {d_tmp}/kernelsu.ko {d_tmp}/ksud")
        # /sdcard 上的耐用副本：/data/local/tmp 每次重启都会回滚，而 root 脚本可能在重启后才跑
        dev.shell(f"mkdir -p {d_sdcard}/ghostlock_ko")
        dev.push(cfg.ko_path, f"{d_sdcard}/ghostlock_ko/kernelpatch.ko")
        dev.push(cfg.ksun_path, f"{d_sdcard}/ghostlock_ko/kernelsu.ko")
        dev.push(cfg.ksud_path, f"{d_sdcard}/ghostlock_ko/ksud")
        dev.shell(f"chmod 755 {d_tmp}/ghostlock; chmod 644 {d_tmp}/kernelpatch.ko")
        time.sleep(5)
        # 设备侧 md5sum 输出是 "<哈希>  <路径>"，只取每行的第一个字段（哈希）——
        # 直接 split() 会把路径也当成哈希来比，导致永远不相等（实测踩过）。
        raw = dev.shell(f"md5sum {d_tmp}/ghostlock {d_tmp}/kernelpatch.ko")
        got = [ln.split()[0] for ln in raw.splitlines() if ln.strip()]
        if len(got) >= 2 and got[0] == expect_bin and got[1] == expect_ko:
            log("stage ok (round verified after rollback window)")
            return True
        log(f"stage retry {i}: got [{to_display(got)}] (expect {expect_bin[:8]}… {expect_ko[:8]}…)")
        time.sleep(4)
    return False


# ---------------------------------------------------------------- 命中监视
class Watcher(threading.Thread):
    """独立盯 /proc/modules：`adb shell ./ghostlock` 会阻塞到 exploit 退出（保活数百秒），
    等它返回时设备往往已重启 —— 所以命中检测必须由独立轮询来做。

    判定规则（实测修正）：不是"见到模块就算命中"，而是**基线 + 消失后重现**：
      * 起始基线=0（干净）→ 模块出现即命中；
      * 起始基线=1（设备上已有遗留模块，如上一轮 root 还没丢）→ 先等它消失（一次 panic
        就会清空），消失后再出现才算命中。否则会在开跑瞬间误报。
    """

    def __init__(self, dev: Device, cfg: Config, interval: float = 3.0, max_polls: int = 1600):
        super().__init__(daemon=True)
        self.dev, self.cfg = dev, cfg
        self.interval, self.max_polls = interval, max_polls
        self.log_path = cfg.log_dir / "_watcher.log"
        self.harvest_dir = cfg.log_dir / "harvest_hit"
        self.detected = False
        self.detected_at: str | None = None
        self.baseline = -1
        self._stop = threading.Event()

    def _log(self, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}" if not msg.startswith("[") else msg
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        self.log_path.write_text(
            f"watcher start {time.strftime('%H:%M:%S')} — polling /proc/modules directly\n",
            encoding="utf-8",
        )
        self.harvest_dir.mkdir(parents=True, exist_ok=True)
        self.baseline = self.dev.modules_count()
        seen_absent = self.baseline == 0
        if not seen_absent:
            self._log(f"NOTE: 起始时模块已存在（遗留 root？baseline={self.baseline}）——"
                      f"将等它消失后再出现才算命中（一次 panic 即会清空）")
        for _ in range(self.max_polls):
            if self._stop.is_set():
                self._log("watcher stopped by caller")
                return
            count = self.dev.modules_count()
            if count == 0:
                seen_absent = True
            elif count == 1 and seen_absent:
                self.detected = True
                self.detected_at = time.strftime("%H:%M:%S")
                self._log("*** MODULE DETECTED in /proc/modules ***")
                self._record()
                self._track_residency()
                return
            time.sleep(self.interval)
        self._log(f"watcher timeout {time.strftime('%H:%M:%S')}")

    def _record(self) -> None:
        d = self.dev
        self._log("--- su -c id (kpatch sucompat) ---")
        self._log(d.id_line())
        self._log("--- /proc/modules entry ---")
        self._log(d.shell("grep kernelpatch /proc/modules"))
        self._log("--- ghostlock klog ---")
        klog = d.shell(f"cat {self.cfg.d_sdcard}/ghostlock_klog 2>/dev/null || cat {self.cfg.d_tmp}/.ghostlock_klog 2>/dev/null")
        self._log("\n".join(klog.splitlines()[-20:]) or "(no klog)")
        # 顺带留存证据到本地（bash 版的 adb pull 会失败，这里直接读内容落盘）
        try:
            (self.harvest_dir / "klog_live.txt").write_text(klog, encoding="utf-8")
            (self.harvest_dir / "final_id.txt").write_text(d.id_line() + "\n", encoding="utf-8")
        except OSError:
            pass
        self._log("verification recorded; tracking module residency")

    def _track_residency(self, rounds: int = 20, gap: float = 5.0) -> None:
        for _ in range(rounds):
            if self._stop.is_set():
                return
            time.sleep(gap)
            loaded = self.dev.modules_count()
            su = self.dev.id_line().splitlines()[0] if self.dev.id_line() else ""
            self._log(f"loaded={loaded} su=[{su}]")


# ---------------------------------------------------------------- 收尾
def finish(dev: Device, cfg: Config, dry_run: bool = False, pkgs: list[str] | None = None) -> int:
    """命中后的收尾：soft-reboot → 修启动标志 → 授权表（幂等合并）→ 重启管理器 → 验证。
    返回：0 成功 / 2 前置不满足（内核无 kpatch）/ 3 授权表结构不符 / 4 中途失败。"""
    pkgs = pkgs or [p for p in cfg.get("GL_AP_PKGS").split() if p]
    d_tmp, d_ap = cfg.d_tmp, cfg.d_ap

    print("\n== 0. 前提：内核里有没有 kpatch")
    mods = dev.modules_count()
    if mods != 1:
        print("  /proc/modules 里没有 kernelpatch —— 收尾只能在命中并成功加载模块之后做，本次不改动设备。")
        return 2
    print("  kpatch 已在内核中。")

    cur = dev.shell_su(f"cat {d_ap}/package_config 2>/dev/null")
    header = cur.splitlines()[0] if cur.strip() else ""
    expect = cfg.get("GL_AP_HEADER")
    if header and header != expect:
        if cfg.get("GL_AP_FORCE") != "1":
            print(f"  {RED}[!]{RESET} 现有 package_config 表头与预期不一致，已中止写入：")
            print(f"      实际: {header}")
            print(f"      预期: {expect}")
            print("      确认表结构后可用 GL_AP_HEADER=<实际表头> 覆盖，或 GL_AP_FORCE=1 强制写入。")
            return 3
        warn("表头不一致但 GL_AP_FORCE=1，继续写入")

    if dry_run:
        print("\n--- DRY-RUN：以下步骤不会执行（只读检查已完成）---")
        print(f"1) soft-reboot（{d_tmp}/libapd.so soft-reboot）→ 等 zygote running → 核对 uptime 连续")
        print(f"2) 若 sys.boot_completed != 1 → {d_ap}/bin/apd resetprop sys.boot_completed 1")
        print(f"3) 授权表（表头 {expect}；现有表头 {'有' if header else '无'}）包名={pkgs}")
        print(f"   新行模板={cfg.get('GL_AP_ROW_FMT')}")
        print("4) 重启管理器：am force-stop/start <包名>")
        print("5) 终验：su -c id / grep kernelpatch /proc/modules / 管理器 UID=0 子进程")
        return 0

    # 1. 软重启（只重启框架，内核与模块保留）
    print("\n== 1. 软重启（只重启框架）")
    before = dev.shell("cut -d' ' -f1 /proc/uptime")
    print(f"  重启前 uptime={before}")
    dev.shell_su(f"chmod 755 {d_tmp}/libapd.so 2>/dev/null; {d_tmp}/libapd.so soft-reboot", timeout=40)
    for _ in range(40):
        time.sleep(5)
        if dev.shell("getprop init.svc.zygote") == "running":
            break
    time.sleep(10)
    after = dev.shell("cut -d' ' -f1 /proc/uptime")
    print(f"  重启后 uptime={after}  (只涨几十秒即证明内核没重启)")
    print(f"  模块计数: {dev.modules_count()}")

    # 2. 修启动标志（soft-reboot 置 0 后没人置回）
    print("\n== 2. 修正 sys.boot_completed")
    bc = dev.shell("getprop sys.boot_completed")
    print(f"  当前 = {bc or '空'}")
    if bc != "1":
        dev.shell_su(f"{d_ap}/bin/apd resetprop sys.boot_completed 1", timeout=30)
        time.sleep(2)
        print(f"  修正后 = {dev.shell('getprop sys.boot_completed')}")
    else:
        print("  已是 1，跳过。")

    # 3. 授权表（幂等：读取-合并-去重；用 rename 落地才会触发 inotify）
    print("\n== 3. 确保管理器自身在授权表内")
    if dev.shell("ps -A -o NAME 2>/dev/null | grep -c '^apd$'") == "0":
        dev.shell_su(f"nohup {d_ap}/bin/apd uid-listener </dev/null >>{d_ap}/log/uid_listener.log 2>&1 &", timeout=20)
        time.sleep(3)
        print("  已启动 uid-listener")
    else:
        print("  uid-listener 已在运行")

    cur_lines = cur.splitlines()
    new_lines = [expect]
    added = 0
    for pkg in pkgs:
        uid_out = dev.shell(f"dumpsys package {pkg} 2>/dev/null | grep -m1 userId")
        uid = "".join(ch for ch in uid_out if ch.isdigit())
        if not uid:
            print(f"  [跳过] {pkg} 未安装")
            continue
        existing = [ln for ln in cur_lines if ln.startswith(pkg + ",")]
        if existing:
            print(f"  [已有] {pkg} (uid={uid})")
            new_lines.extend(existing)
        else:
            new_lines.append(cfg.get("GL_AP_ROW_FMT") % (pkg, uid))
            added += 1
            print(f"  [新增] {pkg} (uid={uid})")
    for ln in cur_lines:
        if not ln or ln.startswith("pkg,"):
            continue
        if any(ln.startswith(p + ",") for p in pkgs):
            continue
        new_lines.append(ln)

    if added:
        payload = "\n".join(new_lines) + "\n"
        local_tmp = Path(cfg.log_dir) / "_pkgcfg.out"
        local_tmp.write_text(payload, encoding="utf-8", newline="\n")
        dev.push(local_tmp, f"{d_tmp}/_pkgcfg")
        dev.shell_su(
            f"cp {d_tmp}/_pkgcfg {d_ap}/package_config.tmp && chmod 644 {d_ap}/package_config.tmp "
            f"&& mv {d_ap}/package_config.tmp {d_ap}/package_config"
        )
        time.sleep(4)
        print(f"  授权表已更新（新增 {added} 条）")
    else:
        print("  授权表无需变更")
    print("  当前内容:")
    for ln in dev.shell_su(f"cat {d_ap}/package_config").splitlines():
        print(f"    {ln}")

    # 4. 重启管理器
    print("\n== 4. 重启管理器")
    for pkg in pkgs:
        dev.shell(f"am force-stop {pkg}")
        time.sleep(2)
        dev.shell(f"am start -n {pkg}/{pkg}.ui.MainActivity")
        print(f"  已重启 {pkg}")
    time.sleep(8)

    # 5. 验证
    print("\n== 5. 验证")
    print("  --- su -c id ---")
    idl = dev.id_line()
    print(f"    {idl}")
    print("  --- /proc/modules ---")
    print(f"    {dev.shell('grep kernelpatch /proc/modules')}")
    print("  判定标准：su 的 gid 应为 0，SELinux 域为 u:r:magisk:s0。")
    return 0 if dev.has_root() else 4
