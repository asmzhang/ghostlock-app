"""四层配置与路径解析。

优先级（高 → 低）：
  L0 命令行 / 环境变量
  L1 <REPO>/harness.local.env（不进库，换机只改这个文件）
  L3 内置默认 + 自动探测（设备型号、目录、核心对）

配置文件是 shell 风格（KEY=VALUE / KEY="${KEY:-默认值}"），这里自己解析，
不依赖 bash —— 这样 Windows / macOS / Linux 行为一致。
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import plat

REPO = Path(__file__).resolve().parents[3]          # tools/harness/ghostlock/config.py → <REPO>

_VAR_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*):?-?(.*)\}$")


def parse_env_file(path: Path) -> dict[str, str]:
    """解析 shell 风格配置文件；`${VAR:-默认}` 表示"环境里已有就用环境里的"。"""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        m = _VAR_REF.match(val)
        if m:
            ref, default = m.group(1), m.group(2)
            val = os.environ.get(ref) or out.get(ref) or default
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            out[key] = val
    return out


DEFAULTS = {
    # 运行
    "MODE": "tune",
    "SHIFT": "-2",
    "ROUNDS": "10",
    "REBOOT_EVERY": "0",
    "CORE": "",
    "CCORE": "",
    # exploit 开关（随 adb shell 下发）
    "GL_SKIP_FIXUP": "1",
    "GL_LAYOUT": "A",
    "GL_SELF_W2": "1",
    "GL_INSMOD_ONLY": "1",
    "GL_HOLD": "1",
    "GL_OWNER": "",
    "GL_W1_ATTEMPTS": "",
    "GL_KS_VERBOSE": "",
    # APatch 收尾（表结构按 ROM 可覆盖）
    "GL_AP_PKGS": "me.bmax.apatch",
    "GL_AP_HEADER": "pkg,exclude,allow,uid,to_uid,sctx",
    "GL_AP_ROW_FMT": "%s,0,1,%s,0,u:r:magisk:s0",
    "GL_AP_FORCE": "0",
    # 设备
    "GHOSTLOCK_TARGET_MODEL": "marble",
    "API": "35",
}


@dataclass
class Config:
    values: dict[str, str] = field(default_factory=dict)
    local_env_file: Path | None = None
    tuned_env_file: Path | None = None
    cli_overrides: dict[str, str] = field(default_factory=dict)
    dry_run: bool = False
    print_config: bool = False

    # ------------------------------------------------------------ 取值
    def get(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)

    def get_int(self, key: str) -> int | None:
        v = self.get(key).strip()
        if not v:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    # ------------------------------------------------------------ 路径
    @property
    def repo(self) -> Path:
        return REPO

    @property
    def work_dir(self) -> Path:
        return Path(self.values["_WORK_DIR"])

    @property
    def deps_dir(self) -> Path:
        return Path(self.values["_DEPS_DIR"])

    @property
    def log_dir(self) -> Path:
        return Path(self.values["_LOGDIR"])

    @property
    def bin_path(self) -> Path:
        return Path(self.values["_BIN"])

    @property
    def ko_path(self) -> Path:
        return Path(self.values["_KO"])

    @property
    def ksud_path(self) -> Path:
        return Path(self.values["_KSUD"])

    @property
    def ksun_path(self) -> Path:
        return Path(self.values["_KSUN"])

    @property
    def tuned_path(self) -> Path:
        return Path(self.values["_TUNED"])

    @property
    def manifest_path(self) -> Path:
        return Path(self.values["_MANIFEST"])

    # 设备侧路径
    @property
    def d_tmp(self) -> str:
        return self.get("GHOSTLOCK_D_TMP", "/data/local/tmp")

    @property
    def d_sdcard(self) -> str:
        return self.get("GHOSTLOCK_D_SDCARD", "/sdcard")

    @property
    def d_ap(self) -> str:
        return self.get("GHOSTLOCK_D_AP", "/data/adb/ap")

    # ------------------------------------------------------------ 组装
    def exploit_env(self, core: int | str, ccore: int | str) -> str:
        """随 adb shell 下发的 GHOSTLOCK_* 串（唯一来源，别处不要再拼字面量）。"""
        parts = [
            f"GHOSTLOCK_SHIFT={self.get('SHIFT')}",
            f"GHOSTLOCK_CORE={core}",
            f"GHOSTLOCK_CONSUMER_CORE={ccore}",
            f"GHOSTLOCK_SKIP_POLICY_FIXUP={self.get('GL_SKIP_FIXUP')}",
            f"GHOSTLOCK_LAYOUT={self.get('GL_LAYOUT')}",
            f"GHOSTLOCK_SELF_W2={self.get('GL_SELF_W2')}",
            f"GHOSTLOCK_INSMOD_ONLY={self.get('GL_INSMOD_ONLY')}",
            f"GHOSTLOCK_HOLD={self.get('GL_HOLD')}",
            f"GHOSTLOCK_OWNER={self.get('GL_OWNER')}",
        ]
        if self.get("GL_W1_ATTEMPTS"):
            parts.append(f"GHOSTLOCK_W1_ATTEMPTS={self.get('GL_W1_ATTEMPTS')}")
        if self.get("GL_KS_VERBOSE"):
            parts.append(f"GHOSTLOCK_KS_VERBOSE={self.get('GL_KS_VERBOSE')}")
        return " ".join(parts)

    def ndk_root(self) -> Path | None:
        pin = self.get("_NDK_ROOT")
        return Path(pin) if pin else None

    def validate(self) -> list[str]:
        errs: list[str] = []
        mode = self.get("MODE")
        if mode not in ("tune", "use"):
            errs.append(f"MODE 只能是 tune|use，当前={mode}")
        rounds = self.get_int("ROUNDS")
        if rounds is None or rounds < 1:
            errs.append(f"ROUNDS 必须是正整数，当前={self.get('ROUNDS')!r}")
        if self.get_int("SHIFT") is None:
            errs.append(f"SHIFT 必须是整数，当前={self.get('SHIFT')!r}")
        re_ = self.get_int("REBOOT_EVERY")
        if re_ is None or re_ < 0:
            errs.append(f"REBOOT_EVERY 必须是非负整数，当前={self.get('REBOOT_EVERY')!r}")
        for k in ("CORE", "CCORE"):
            v = self.get(k).strip()
            if v and self.get_int(k) is None:
                errs.append(f"{k} 必须是整数，当前={v!r}")
        if self.get("CORE").strip() and self.get("CORE") == self.get("CCORE"):
            errs.append("CORE 与 CCORE 不能相同（竞态需要两个核）")
        return errs


def build(cli: dict[str, str], dry_run: bool = False, print_config: bool = False) -> Config:
    cfg = Config(dry_run=dry_run, print_config=print_config, cli_overrides=dict(cli))

    local = Path(os.environ.get("GHOSTLOCK_LOCAL_ENV") or (REPO / "harness.local.env"))
    if local.is_file():
        cfg.local_env_file = local
    values: dict[str, str] = dict(DEFAULTS)
    if cfg.local_env_file:
        values.update(parse_env_file(cfg.local_env_file))
    # 环境变量（L0 的一部分，仅次于 CLI）
    for key in list(values) + ["GHOSTLOCK_DEV", "GHOSTLOCK_WORK", "GHOSTLOCK_DEPS", "GHOSTLOCK_BIN",
                               "GHOSTLOCK_KO", "GHOSTLOCK_KSUD", "GHOSTLOCK_KSUN", "GHOSTLOCK_LOGDIR",
                               "GHOSTLOCK_TUNED", "GHOSTLOCK_D_TMP", "GHOSTLOCK_D_SDCARD", "GHOSTLOCK_D_AP"]:
        if os.environ.get(key):
            values[key] = os.environ[key]
    values.update({k: v for k, v in cli.items() if v is not None})

    # 把本地配置里的工具链/设备键注入进程环境：探测（find_ndk）与子进程都靠它，
    # 只在环境里原本没有时才写入，避免压过 L0。
    for key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_HOME", "ANDROID_SDK_ROOT",
                "GHOSTLOCK_DEV", "GHOSTLOCK_TARGET_MODEL", "GHOSTLOCK_ADB"):
        if values.get(key) and not os.environ.get(key):
            os.environ[key] = values[key]

    # ---- 目录解析（"只带仓库换机"的关键：不依赖仓库外布局）
    work = values.get("GHOSTLOCK_WORK") or values.get("_WORK_DIR_OVERRIDE") or ""
    if work:
        work_dir = Path(work).resolve()
    else:
        parent = REPO.parent
        if (parent / "android12-5.10_kernelpatch.ko").is_file() or (parent / "libksud.so").is_file():
            work_dir = parent
        else:
            work_dir = REPO / "run"
            work_dir.mkdir(parents=True, exist_ok=True)
    deps_dir = Path(values["GHOSTLOCK_DEPS"]).resolve() if values.get("GHOSTLOCK_DEPS") else work_dir

    values["_WORK_DIR"] = str(work_dir)
    values["_DEPS_DIR"] = str(deps_dir)
    values["_LOGDIR"] = values.get("GHOSTLOCK_LOGDIR") or str(work_dir)
    values["_BIN"] = values.get("GHOSTLOCK_BIN") or str(REPO / "ghostlock")
    values["_KO"] = values.get("GHOSTLOCK_KO") or str(deps_dir / "android12-5.10_kernelpatch.ko")
    values["_KSUD"] = values.get("GHOSTLOCK_KSUD") or str(deps_dir / "libksud.so")
    values["_KSUN"] = values.get("GHOSTLOCK_KSUN") or str(deps_dir / "android12-5.10_kernelsu.ko")
    values["_TUNED"] = values.get("GHOSTLOCK_TUNED") or str(Path(values["_LOGDIR"]) / "gl_tuned.env")
    values["_MANIFEST"] = str(REPO / "config" / "deps.manifest")
    ndk = plat.find_ndk()
    values["_NDK_ROOT"] = str(ndk) if ndk else ""
    clang = plat.ndk_clang(ndk, int(values.get("API") or 35))
    values["_NDK_CLANG"] = str(clang) if clang else ""
    values["_PYTHON"] = shutil.which("python3") or shutil.which("python") or "python"
    values["_ADB"] = plat.adb_binary()
    values["_HOST_OS"] = plat.host_os()

    cfg.values = values
    return cfg


def load_tuned(cfg: Config) -> dict[str, str]:
    """MODE=use：读取 TUNE 命中时锁定的参数（SHIFT/CORE/CCORE）。"""
    path = cfg.tuned_path
    if not path.is_file():
        raise FileNotFoundError(path)
    return parse_env_file(path)
