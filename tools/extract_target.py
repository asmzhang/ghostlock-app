#!/usr/bin/env python3
"""Extract only the symbols and BTF fields consumed by ghostlock."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


ANDROID_MAGIC = b"ANDROID!"
BTF_MAGIC = 0xEB9F
PAGE_SIZE = 4096
FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9
ARM64_MEMSTART_ALIGN = 1 << 30

KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19


class ExtractError(RuntimeError):
    pass


def align(value: int, size: int) -> int:
    return (value + size - 1) & ~(size - 1)


def recover_kernel_phys_load(path: Path) -> int:
    """Recover the XBL Kernel physical base from embedded FDT memory maps."""
    data = path.read_bytes()
    candidates: set[tuple[int, int, int, int]] = set()
    cursor = 0
    while True:
        pos = data.find(struct.pack(">I", FDT_MAGIC), cursor)
        if pos < 0:
            break
        cursor = pos + 4
        if pos + 40 > len(data):
            continue
        (magic, total, struct_off, strings_off, _rsv, version, last_version,
         _cpu, strings_size, struct_size) = struct.unpack_from(">10I", data, pos)
        if magic != FDT_MAGIC or version < 16 or last_version > 17:
            continue
        if total < 40 or pos + total > len(data):
            continue
        if struct_off > total or struct_size > total - struct_off:
            continue
        if strings_off > total or strings_size > total - strings_off:
            continue
        struct_start, struct_end = pos + struct_off, pos + struct_off + struct_size
        strings_start, strings_end = pos + strings_off, pos + strings_off + strings_size
        stack: list[dict[str, object]] = []
        regions: list[tuple[str, str, int, int]] = []
        p = struct_start
        try:
            while p < struct_end:
                token = struct.unpack_from(">I", data, p)[0]
                if token == FDT_BEGIN_NODE:
                    end = data.index(b"\0", p + 4, struct_end)
                    name = data[p + 4:end].decode("ascii")
                    parent_ac = int(stack[-1]["child_ac"]) if stack else 2
                    parent_sc = int(stack[-1]["child_sc"]) if stack else 1
                    path_name = (str(stack[-1]["path"]).rstrip("/") + "/" + name) if stack else ("/" + name if name else "/")
                    stack.append({
                        "path": path_name,
                        "parent_ac": parent_ac,
                        "parent_sc": parent_sc,
                        "child_ac": 2,
                        "child_sc": 1,
                        "props": {},
                    })
                    p = align(end + 1, 4)
                elif token == FDT_END_NODE:
                    node = stack.pop()
                    props = node["props"]
                    assert isinstance(props, dict)
                    label = props.get("mem-label", b"").split(b"\0", 1)[0].decode("ascii")
                    reg = props.get("reg")
                    if "/memorymap/" in str(node["path"]) and label in {"NOMAP", "Kernel"} and reg is not None:
                        ac, sc = int(node["parent_ac"]), int(node["parent_sc"])
                        if ac not in (1, 2) or sc not in (1, 2) or len(reg) != (ac + sc) * 4:
                            raise ValueError("unsupported memory-map reg")
                        split = ac * 4
                        regions.append((label, str(node["path"]), int.from_bytes(reg[:split], "big"), int.from_bytes(reg[split:], "big")))
                    p += 4
                elif token == FDT_PROP:
                    size, name_off = struct.unpack_from(">II", data, p + 4)
                    if name_off >= strings_size or p + 12 + size > struct_end or not stack:
                        raise ValueError("invalid property")
                    ns = strings_start + name_off
                    ne = data.index(b"\0", ns, strings_end)
                    prop_name = data[ns:ne].decode("ascii")
                    props = stack[-1]["props"]
                    assert isinstance(props, dict)
                    props[prop_name] = data[p + 12:p + 12 + size]
                    if prop_name == "#address-cells" and size == 4:
                        stack[-1]["child_ac"] = int.from_bytes(props[prop_name], "big")
                    elif prop_name == "#size-cells" and size == 4:
                        stack[-1]["child_sc"] = int.from_bytes(props[prop_name], "big")
                    p = align(p + 12 + size, 4)
                elif token == FDT_NOP:
                    p += 4
                elif token == FDT_END:
                    break
                else:
                    raise ValueError("unknown FDT token")
            nomap = {(base, size) for label, _, base, size in regions if label == "NOMAP"}
            kernel = {(base, size) for label, _, base, size in regions if label == "Kernel"}
            if len(nomap) == 1 and len(kernel) == 1:
                nb, ns = next(iter(nomap)); kb, ks = next(iter(kernel))
                if nb & (PAGE_SIZE - 1) or kb & (PAGE_SIZE - 1) or not ns or not ks:
                    raise ValueError("unaligned or empty memory map")
                if not (nb & -ARM64_MEMSTART_ALIGN) <= nb < (nb & -ARM64_MEMSTART_ALIGN) + ARM64_MEMSTART_ALIGN:
                    raise ValueError("invalid NOMAP phys offset")
                candidates.add((nb, ns, kb, ks))
        except (IndexError, UnicodeError, ValueError, struct.error):
            continue
    if not candidates:
        raise ExtractError("xbl_config contains no unique NOMAP/Kernel memory map")
    if len(candidates) != 1:
        raise ExtractError(f"xbl_config contains conflicting memory maps: {sorted(candidates)}")
    return next(iter(candidates))[2]


@dataclass
class BootImage:
    path: Path
    kernel: bytes

    @classmethod
    def load(cls, path: Path) -> "BootImage":
        raw = path.read_bytes()
        if raw[:8] == ANDROID_MAGIC:
            if len(raw) < 44:
                raise ExtractError("truncated Android boot header")
            kernel_size, header_size, version = (
                struct.unpack_from("<I", raw, 8)[0],
                struct.unpack_from("<I", raw, 20)[0],
                struct.unpack_from("<I", raw, 40)[0],
            )
            if version not in (3, 4):
                raise ExtractError(f"unsupported boot header version {version}")
            start = align(header_size, PAGE_SIZE)
            end = start + kernel_size
            if end > len(raw):
                raise ExtractError("kernel payload exceeds boot image")
            return cls(path, raw[start:end])
        if raw[:3] == b"\x1f\x8b\x08":
            try:
                raw = gzip.decompress(raw)
            except OSError as exc:
                raise ExtractError(f"invalid gzip image: {exc}") from exc
        if len(raw) < 64 or raw[56:60] != b"ARM\x64":
            raise ExtractError("input is not an Android boot image or arm64 Image")
        return cls(path, raw)

    def release(self) -> str | None:
        match = re.search(rb"Linux version ([^\x00\r\n ]+)", self.kernel)
        return match.group(1).decode("ascii", "replace") if match else None

    def embedded_btf(self) -> bytes | None:
        signature = struct.pack("<HBBI", BTF_MAGIC, 1, 0, 24)
        cursor = 0
        candidates: list[bytes] = []
        while True:
            pos = self.kernel.find(signature, cursor)
            if pos < 0:
                break
            cursor = pos + 1
            if pos + 24 > len(self.kernel):
                continue
            magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = (
                struct.unpack_from("<HBBIIIII", self.kernel, pos)
            )
            if magic != BTF_MAGIC or version != 1 or hdr_len < 24:
                continue
            total = hdr_len + max(type_off + type_len, str_off + str_len)
            if total <= hdr_len or pos + total > len(self.kernel):
                continue
            strings = pos + hdr_len + str_off
            if str_len and self.kernel[strings] == 0:
                candidates.append(self.kernel[pos : pos + total])
        return max(candidates, key=len) if candidates else None


@dataclass
class BtfMember:
    name: str
    type_id: int
    bit_offset: int


@dataclass
class BtfType:
    type_id: int
    name: str
    kind: int
    size: int
    members: list[BtfMember] = field(default_factory=list)


class Btf:
    def __init__(self, raw: bytes):
        if len(raw) < 24:
            raise ExtractError("truncated BTF header")
        magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = (
            struct.unpack_from("<HBBIIIII", raw, 0)
        )
        if magic != BTF_MAGIC or version != 1 or hdr_len < 24:
            raise ExtractError("invalid BTF header")
        self.types_raw = raw[hdr_len + type_off : hdr_len + type_off + type_len]
        self.strings = raw[hdr_len + str_off : hdr_len + str_off + str_len]
        self.types: dict[int, BtfType] = {}
        self.by_name: dict[str, list[BtfType]] = {}
        self._parse()

    def string(self, offset: int) -> str:
        if offset == 0:
            return ""
        if offset < 0 or offset >= len(self.strings):
            raise ExtractError(f"invalid BTF string offset {offset}")
        end = self.strings.find(b"\x00", offset)
        if end < 0:
            raise ExtractError("unterminated BTF string")
        return self.strings[offset:end].decode("utf-8", "replace")

    def _parse(self) -> None:
        fixed = {
            KIND_INT: 4, KIND_PTR: 0, KIND_ARRAY: 12, KIND_ENUM: 8,
            KIND_FWD: 0, KIND_TYPEDEF: 0, KIND_VOLATILE: 0, KIND_CONST: 0,
            KIND_RESTRICT: 0, KIND_FUNC: 0, KIND_FUNC_PROTO: 8,
            KIND_VAR: 4, KIND_DATASEC: 12, KIND_FLOAT: 0,
            KIND_DECL_TAG: 8, KIND_TYPE_TAG: 0, KIND_ENUM64: 12,
        }
        cursor = 0
        type_id = 1
        while cursor < len(self.types_raw):
            if cursor + 12 > len(self.types_raw):
                raise ExtractError("truncated BTF type record")
            name_off, info, size_or_type = struct.unpack_from(
                "<III", self.types_raw, cursor
            )
            cursor += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            item = BtfType(type_id, self.string(name_off), kind, size_or_type)
            if kind in (KIND_STRUCT, KIND_UNION):
                extra = vlen * 12
                if cursor + extra > len(self.types_raw):
                    raise ExtractError("truncated BTF members")
                for index in range(vlen):
                    name, member_type, bit_offset = struct.unpack_from(
                        "<III", self.types_raw, cursor + index * 12
                    )
                    item.members.append(
                        BtfMember(self.string(name), member_type, bit_offset & 0xFFFFFF)
                    )
                cursor += extra
            else:
                unit = fixed.get(kind)
                if unit is None:
                    raise ExtractError(f"unsupported BTF kind {kind}")
                cursor += unit * vlen if kind in (
                    KIND_ENUM, KIND_FUNC_PROTO, KIND_DATASEC, KIND_ENUM64
                ) else unit
            self.types[type_id] = item
            if item.name:
                self.by_name.setdefault(item.name, []).append(item)
            type_id += 1

    def struct(self, name: str) -> BtfType | None:
        candidates = [
            item for item in self.by_name.get(name, [])
            if item.kind in (KIND_STRUCT, KIND_UNION)
        ]
        return max(candidates, key=lambda item: len(item.members)) if candidates else None

    def resolve(self, type_id: int) -> BtfType | None:
        seen: set[int] = set()
        while type_id and type_id not in seen:
            seen.add(type_id)
            item = self.types.get(type_id)
            if item is None:
                return None
            if item.kind not in (KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG):
                return item
            type_id = item.size
        return None

    def _find_member(self, item: BtfType, name: str, base: int, seen: set[int]) -> int | None:
        if item.type_id in seen:
            return None
        seen.add(item.type_id)
        for member in item.members:
            offset = base + member.bit_offset
            if member.name == name:
                return offset // 8
            if member.name == "":
                child = self.resolve(member.type_id)
                if child is not None and child.kind in (KIND_STRUCT, KIND_UNION):
                    found = self._find_member(child, name, offset, seen.copy())
                    if found is not None:
                        return found
        return None

    def field(self, struct_name: str, field_name: str) -> int | None:
        item = self.struct(struct_name)
        return self._find_member(item, field_name, 0, set()) if item else None

    def size(self, struct_name: str) -> int | None:
        item = self.struct(struct_name)
        return item.size if item else None


def parse_kallsyms(path: Path) -> tuple[dict[str, set[int]], dict[str, set[str]]]:
    symbols: dict[str, set[int]] = {}
    types: dict[str, set[str]] = {}
    pattern = re.compile(r"^([0-9a-fA-F]{8,16})\s+(\S)\s+(.+?)\s*$")
    for line in path.read_text("utf-8", "replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address, symbol_type, name = match.groups()
        value = int(address, 16)
        if value == 0:
            continue
        symbols.setdefault(name, set()).add(value)
        types.setdefault(name, set()).add(symbol_type)
    if "_text" not in symbols and "_head" not in symbols:
        raise ExtractError("kallsyms has no _text or _head symbol")
    return symbols, types


def unique(symbols: dict[str, set[int]], name: str) -> int | None:
    values = symbols.get(name, set())
    return next(iter(values)) if len(values) == 1 else None


def find_data_symbol(
    symbols: dict[str, set[int]], types: dict[str, set[str]], exact: str,
    fragments: tuple[str, ...] = (),
) -> int | None:
    address = unique(symbols, exact)
    if address is not None:
        return address
    matches: set[int] = set()
    for name, values in symbols.items():
        if not fragments or not all(fragment.lower() in name.lower() for fragment in fragments):
            continue
        if not (types.get(name, set()) & set("dDbB")):
            continue
        matches.update(values)
    return next(iter(matches)) if len(matches) == 1 else None


def find_function(symbols: dict[str, set[int]], exact: str, fragments: tuple[str, ...] = ()) -> int | None:
    address = unique(symbols, exact)
    if address is not None:
        return address
    matches: set[int] = set()
    for name, values in symbols.items():
        if all(fragment.lower() in name.lower() for fragment in fragments):
            matches.update(values)
    return next(iter(matches)) if len(matches) == 1 else None


SYMBOLS = {
    "off_init_task": ("init_task",),
    "off_init_cred": ("init_cred",),
    "off_root_task_group": ("root_task_group",),
    "off_selinux_enforcing": ("selinux_state",),
    "off_selinux_blob_sizes": ("selinux_blob_sizes",),
    "off_security_hook_heads": ("security_hook_heads",),
    "off_kmalloc_caches": ("kmalloc_caches",),
    "off_anon_pipe_buf_ops": ("anon_pipe_buf_ops",),
    "off_slide_nfulnl_logger": ("nfulnl_logger",),
    "off_slide_boot_id": ("sysctl_bootid",),
}

FUNCTIONS = {
    "off_configfs_read_iter": ("configfs_read_iter",),
    "off_configfs_bin_write_iter": ("configfs_bin_write_iter",),
    "off_copy_splice_read": ("copy_splice_read",),
    "off_noop_llseek": ("noop_llseek",),
}

ASHMEM_FUNCTIONS = {
    "off_ashmem_ioctl": ("ashmem_ioctl", "fops_ioctl"),
    "off_ashmem_compat_ioctl": ("compat_ashmem_ioctl", "fops_compat_ioctl"),
    "off_ashmem_mmap": ("ashmem_mmap", "fops_mmap"),
    "off_ashmem_open": ("ashmem_open", "fops_open"),
    "off_ashmem_release": ("ashmem_release", "fops_release"),
    "off_ashmem_show_fdinfo": ("ashmem_show_fdinfo", "fops_show_fdinfo"),
}

# Slot offsets of ashmem function pointers within struct file_operations.
# The classic C layout (OPPO 6.6) and the 6.12+ Rust ashmem vtable differ by
# one 8-byte field before unlocked_ioctl; both observed on real devices.
ASHMEM_FOPS_LAYOUTS = (
    {
        "off_ashmem_ioctl": 0x50,
        "off_ashmem_compat_ioctl": 0x58,
        "off_ashmem_mmap": 0x60,
        "off_ashmem_open": 0x68,
        "off_ashmem_release": 0x78,
        "off_ashmem_show_fdinfo": 0xd8,
    },
    {
        "off_ashmem_ioctl": 0x48,
        "off_ashmem_compat_ioctl": 0x50,
        "off_ashmem_mmap": 0x58,
        "off_ashmem_open": 0x68,
        "off_ashmem_release": 0x78,
        "off_ashmem_show_fdinfo": 0xd8,
    },
)


# Fields that may legitimately be absent from a kernel's kallsyms (e.g. GKI
# drops some data symbols). Missing optional fields are emitted as 0, which
# makes the runtime fall back to the target.h default.
OPTIONAL_SYMBOLS = {
    "off_security_hook_heads",
    "off_ashmem_fops",
    "off_ashmem_misc_fops",
}

STRUCT_FIELDS = {
    "task_struct": {
        "task_prio": "prio", "task_normal_prio": "normal_prio",
        "task_sched_task_group": "sched_task_group", "task_pi_lock": "pi_lock",
        "task_pi_waiters": "pi_waiters", "task_pi_top_task": "pi_top_task",
        "task_pi_blocked_on": "pi_blocked_on", "task_pid": "pid", "task_tgid": "tgid",
        "task_atomic_flags": "atomic_flags",
        "task_real_cred": "real_cred", "task_cred": "cred", "task_comm": "comm",
        "task_tasks": "tasks", "task_seccomp": "seccomp",
    },
    "rt_mutex_waiter": {
        "waiter_tree": "tree", "waiter_pi_tree": "pi_tree", "waiter_task": "task",
        "waiter_lock": "lock", "waiter_wake_state": "wake_state", "waiter_ww_ctx": "ww_ctx",
    },
    "cred": {
        "cred_uid": "uid", "cred_securebits": "securebits",
        "cred_caps": "cap_inheritable", "cred_security": "security",
    },
    "seccomp": {
        "seccomp_mode": "mode", "seccomp_filter_count": "filter_count", "seccomp_filter": "filter",
    },
    "file_operations": {
        "fops_owner": "owner", "fops_llseek": "llseek", "fops_read": "read",
        "fops_write": "write", "fops_read_iter": "read_iter", "fops_write_iter": "write_iter",
        "fops_ioctl": "unlocked_ioctl", "fops_compat_ioctl": "compat_ioctl", "fops_mmap": "mmap",
        "fops_open": "open", "fops_release": "release", "fops_splice_read": "splice_read",
        "fops_show_fdinfo": "show_fdinfo",
    },
    "configfs_buffer": {
        "cfg_page": "page", "cfg_needs_read_fill": "needs_read_fill",
        "cfg_bin_buffer": "bin_buffer", "cfg_bin_buffer_size": "bin_buffer_size",
        "cfg_cb_max_size": "cb_max_size",
    },
}


def resolve_symbols(
    symbols: dict[str, set[int]], types: dict[str, set[str]], btf: Btf, base: int
) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for name, (symbol,) in SYMBOLS.items():
        result[name] = unique(symbols, symbol)
    for name, (symbol,) in FUNCTIONS.items():
        result[name] = unique(symbols, symbol)
    result["off_slide_loggers_0_1"] = (
        unique(symbols, "loggers") + 0x10 if unique(symbols, "loggers") is not None else None
    )
    misc = find_data_symbol(symbols, types, "ashmem_misc", ("ashmem", "misc"))
    misc_fops = btf.field("miscdevice", "fops")
    result["off_ashmem_misc_fops"] = (
        misc + misc_fops if misc is not None and misc_fops is not None else None
    )
    result["off_ashmem_fops"] = find_data_symbol(
        symbols, types, "ashmem_fops", ("ashmem", "fops")
    )
    for field_name, fragments in ASHMEM_FUNCTIONS.items():
        exact, rust_fragment = fragments
        value = unique(symbols, exact)
        if value is None:
            value = find_function(symbols, exact, (rust_fragment, "ashmem_rust6Ashmem"))
        result[field_name] = value
    return {
        name: None if value is None else value - base
        for name, value in result.items()
    }


def scan_ashmem_fops(
    kernel: bytes, base: int, resolved: dict[str, int | None]
) -> int | None:
    """Locate the ashmem struct file_operations by scanning the kernel image
    for a struct whose slots point to the resolved ashmem functions.

    Rust (6.12+) ashmem exposes no kallsyms data symbol for its fops, so this
    pattern scan is the only reliable way to resolve off_ashmem_fops there.
    Returns the offset from _text, or None when not uniquely found.
    """
    candidates: set[int] = set()
    for layout in ASHMEM_FOPS_LAYOUTS:
        slots = [
            (key, off) for key, off in layout.items() if resolved.get(key) is not None
        ]
        if len(slots) < 4:
            continue
        anchor_key, anchor_off = slots[0]
        anchor = struct.pack("<Q", base + resolved[anchor_key])
        max_slot = max(off for _, off in slots)
        pos = 0
        while True:
            pos = kernel.find(anchor, pos)
            if pos < 0:
                break
            start = pos - anchor_off
            if start >= 0 and start % 8 == 0 and start + max_slot + 8 <= len(kernel):
                if all(
                    struct.unpack_from("<Q", kernel, start + off)[0]
                    == base + resolved[key]
                    for key, off in slots[1:]
                ):
                    candidates.add(start)
            pos += 1
    return next(iter(candidates)) if len(candidates) == 1 else None


def resolve_structs(btf: Btf) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for struct_name, fields in STRUCT_FIELDS.items():
        if btf.struct(struct_name) is None:
            for macro in fields:
                result[macro] = None
            continue
        for macro, field_name in fields.items():
            result[macro] = btf.field(struct_name, field_name)
    for macro, struct_name in (
        ("struct_page_size", "page"),
    ):
        result[macro] = btf.size(struct_name)
    for macro, field_name in (
        ("struct_page_compound_head", "compound_head"),
        ("struct_page_type", "page_type"),
    ):
        result[macro] = btf.field("page", field_name)
    result["struct_slab_cache"] = btf.field("slab", "slab_cache")
    result["struct_mm_struct"] = btf.size("mm_struct")
    return result


def find_kallsyms(image: Path, provided: Path | None, explicit: str | None) -> tuple[Path, bool]:
    if provided is not None:
        if not provided.is_file():
            raise ExtractError(f"kallsyms file not found: {provided}")
        return provided, False
    tool = explicit or shutil.which("kallsyms-finder")
    if not tool:
        raise ExtractError("provide --kallsyms or install/pass --kallsyms-finder")
    fd, name = tempfile.mkstemp(prefix="ghostlock-kallsyms-", suffix=".txt")
    os.close(fd)
    Path(name).unlink(missing_ok=True)
    output = Path(name)
    appended = Path(f"{output}.kallsyms")
    try:
        proc = subprocess.run(
            [tool, str(image), "--output", str(output)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not output.exists() and appended.exists():
            appended.replace(output)
        elif appended.exists():
            appended.unlink()
        if proc.returncode or not output.exists():
            raise ExtractError(
                f"kallsyms-finder failed ({proc.returncode}): {proc.stdout[-4000:]}"
            )
        return output, True
    except Exception:
        output.unlink(missing_ok=True)
        appended.unlink(missing_ok=True)
        raise


def require_fields(values: dict[str, int | None], optional: set[str]) -> None:
    missing = [name for name, value in values.items() if value is None and name not in optional]
    if missing:
        raise ExtractError("missing required values: " + ", ".join(sorted(missing)))


DEVICE_ROOT = Path(__file__).resolve().parent.parent / "src" / "devices"


def device_header_path(name: str) -> Path:
    return DEVICE_ROOT / name / "offsets.h"


def kernel_struct_macro(release: str | None) -> str:
    """STRUCT_OFFSETS_6_12 for 6.12+ kernels, STRUCT_OFFSETS_6_6 otherwise."""
    if release:
        match = re.match(r"^(\d+)\.(\d+)", release)
        if match and tuple(map(int, match.groups())) >= (6, 12):
            return "STRUCT_OFFSETS_6_12"
    return "STRUCT_OFFSETS_6_6"


def pselect_waiter_shift_for(release: str | None) -> int:
    """6.12 GKI moved the pselect fd_set waiter word (shift 0); 6.6 OPPO -2."""
    return 0 if kernel_struct_macro(release) == "STRUCT_OFFSETS_6_12" else -2


def render_device(
    release: str | None,
    symbols: dict[str, int | None],
    structs: dict[str, int | None],
    phys: int | None,
) -> str:
    lines = [f"/* {release} */", ""]
    lines.append("OFFSETS_ENTRY(")
    lines.append(f'    "{release}",')
    lines.append(f"    {kernel_struct_macro(release)},")
    if phys is not None:
        lines.append(f"    .kernel_phys_load = 0x{phys:x},")
    lines.append(f"    .pselect_waiter_shift = {pselect_waiter_shift_for(release)},")
    for key, value in symbols.items():
        if value is None:
            continue
        lines.append(f"    .{key} = 0x{value:08x},")
    lines.append("),")
    reference = {
        key: value for key, value in structs.items()
        if value is not None and (
            key.startswith("struct_page")
            or key in ("struct_slab_cache", "struct_mm_struct")
        )
    }
    if reference:
        lines.append("")
        lines.append("/* BTF reference (runtime uses target.h defaults): */")
        for key, value in reference.items():
            lines.append(f"/* #define {key.upper()} 0x{value:X} */")
    return "\n".join(lines) + "\n"


def existing_entries() -> dict[str, dict[str, int]]:
    """Map each registered release to its {field: value} from device headers."""
    entries: dict[str, dict[str, int]] = {}
    for header in sorted(DEVICE_ROOT.glob("*/offsets.h")):
        text = header.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r'OFFSETS_ENTRY\(\s*"([^"]+)"', text):
            release = match.group(1)
            fields: dict[str, int] = {}
            for fm in re.finditer(
                r"\.([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)",
                text[match.end():],
            ):
                fields[fm.group(1)] = int(fm.group(2), 0)
            entries.setdefault(release, fields)
    return entries


def warn_existing_mismatches(
    release: str | None, symbols: dict[str, int | None]
) -> None:
    if not release:
        return
    existing = existing_entries().get(release)
    if not existing:
        return
    for key, value in symbols.items():
        if value is None:
            continue
        if key in existing and existing[key] != value:
            print(
                f"warning: {release} is already registered with .{key}="
                f"0x{existing[key]:08X}; this image extracts 0x{value:08X}",
                file=sys.stderr,
            )


def register_device(name: str) -> Path:
    """Add #include "<name>/offsets.h" to src/devices/offsets.h if missing."""
    header = DEVICE_ROOT / "offsets.h"
    text = header.read_text(encoding="utf-8")
    include = f'#include "{name}/offsets.h"'
    if include in text:
        return header
    marker = re.search(r"^\s*\{\s*\.uname_r\s*=\s*NULL", text, re.MULTILINE)
    if marker is None:
        raise ExtractError(f"cannot locate NULL terminator in {header}")
    text = text[: marker.start()] + include + "\n" + text[marker.start():]
    header.write_text(text, encoding="utf-8")
    return header


def render_c(release: str | None, symbols: dict[str, int | None], structs: dict[str, int | None], phys: int | None, name: str) -> str:
    lines = [f"/* Generated offsets for {release or name}. */", ""]
    lines.append("#define STRUCT_OFFSETS_EXTRACTED \\")
    task_keys = (
        "task_prio", "task_normal_prio", "task_sched_task_group", "task_pi_lock",
        "task_pi_waiters", "task_pi_top_task", "task_pi_blocked_on", "task_pid", "task_tgid",
        "task_atomic_flags", "task_real_cred", "task_cred", "task_comm",
        "task_tasks", "task_seccomp",
    )
    present = [(key, structs.get(key)) for key in task_keys if structs.get(key) is not None]
    for index, (key, value) in enumerate(present):
        suffix = " \\" if index + 1 < len(present) else ""
        if value is not None:
            lines.append(f"  .{key} = 0x{value:X},{suffix}")
    lines.append("")
    lines.append("OFFSETS_ENTRY(\"%s\"," % (release or name))
    if phys is not None:
        lines.append(f"  .kernel_phys_load=0x{phys:X},")
    for key, value in symbols.items():
        if value is not None:
            lines.append(f"  .{key}=0x{value:08X},")
    lines.append("),")
    lines.append("")
    lines.append("/* BTF fields not stored in kernel_offsets: */")
    for key, value in structs.items():
        if not key.startswith("task_") and value is not None:
            lines.append(f"#define {key.upper()} 0x{value:X}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="boot.img, raw arm64 Image, or gzip Image")
    parser.add_argument("--kallsyms", type=Path)
    parser.add_argument("--kallsyms-finder")
    parser.add_argument(
        "--xbl-config",
        type=Path,
        help="optional XBL xbl_config.img; derive kernel physical load address from its FDT",
    )
    parser.add_argument("--name", default="target")
    parser.add_argument("--format", choices=("text", "json", "c"), default="text")
    parser.add_argument(
        "--device",
        type=str,
        help="render and register src/devices/<name>/offsets.h (repo format)",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="treat every unresolved symbol as optional (emit 0)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing device header that differs",
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    try:
        boot = BootImage.load(args.image)
        args.kernel_phys_load = (
            recover_kernel_phys_load(args.xbl_config)
            if args.xbl_config is not None
            else None
        )
        btf_raw = boot.embedded_btf()
        if btf_raw is None:
            raise ExtractError("embedded BTF not found")
        btf = Btf(btf_raw)
        kallsyms_path, owned_kallsyms = find_kallsyms(
            args.image, args.kallsyms, args.kallsyms_finder
        )
        try:
            symbols, types = parse_kallsyms(kallsyms_path)
        finally:
            if owned_kallsyms:
                kallsyms_path.unlink(missing_ok=True)
        base = unique(symbols, "_text") or unique(symbols, "_head")
        if base is None:
            raise ExtractError("_text/_head is not unique in kallsyms")
        symbol_offsets = resolve_symbols(symbols, types, btf, base)
        if symbol_offsets.get("off_ashmem_fops") is None:
            scanned = scan_ashmem_fops(boot.kernel, base, symbol_offsets)
            if scanned is not None:
                symbol_offsets["off_ashmem_fops"] = scanned
                print(
                    f"info: off_ashmem_fops = 0x{scanned:08x} "
                    "(file_operations pattern scan)",
                    file=sys.stderr,
                )
        struct_offsets = resolve_structs(btf)
        missing = {key for key, value in symbol_offsets.items() if value is None}
        existing = existing_entries().get(boot.release() or "", {})
        tolerated = set(OPTIONAL_SYMBOLS)
        if args.allow_missing:
            tolerated.update(missing)
        for key in sorted(missing & tolerated):
            carried = existing.get(key) or 0
            symbol_offsets[key] = carried
            if carried:
                print(
                    f"warning: {key} not found in kallsyms; carried over "
                    f"0x{carried:08x} from the registered {boot.release()} entry",
                    file=sys.stderr,
                )
            else:
                print(
                    f"warning: {key} not found in kallsyms; emitted 0x00000000 "
                    "(runtime falls back to target.h default)",
                    file=sys.stderr,
                )
        require_fields(symbol_offsets, set())
        require_fields(struct_offsets, set())
        mm_size = struct_offsets.get("struct_mm_struct")
        if mm_size is not None:
            print(
                f"info: sizeof(mm_struct)=0x{mm_size:X} "
                "(MM_STRUCT_SZ=0x500 in src/core/common.h)",
                file=sys.stderr,
            )
            if mm_size > 0x500:
                print(
                    "warning: sizeof(mm_struct) exceeds the hardcoded "
                    "MM_STRUCT_SZ slab stride",
                    file=sys.stderr,
                )
        report = {
            "release": boot.release(),
            "kimage_text_base": base,
            "kernel_phys_load": args.kernel_phys_load,
            "symbols": symbol_offsets,
            "struct_fields": struct_offsets,
            "btf_size": len(btf_raw),
        }
        if args.device:
            output = render_device(
                boot.release(), symbol_offsets, struct_offsets,
                args.kernel_phys_load,
            )
            target = args.out or device_header_path(args.device)
            if (
                args.out is None
                and target.exists()
                and target.read_text(encoding="utf-8") != output
                and not args.force
            ):
                raise ExtractError(
                    f"{target} already exists and differs; pass --force to "
                    "overwrite or --out to write elsewhere"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output, encoding="utf-8")
            print(f"wrote {target}", file=sys.stderr)
            if args.out is None:
                register_device(args.device)
            warn_existing_mismatches(boot.release(), symbol_offsets)
            return 0
        if args.format == "c":
            output = render_c(boot.release(), symbol_offsets, struct_offsets, args.kernel_phys_load, args.name)
        else:
            output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        missing = [key for key, value in {**symbol_offsets, **struct_offsets}.items() if value is None]
        if missing:
            print("missing:", ", ".join(sorted(missing)), file=sys.stderr)
        return 0
    except (OSError, ExtractError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
