//! 从内核镜像里直接导出结构体字段偏移（BTF 驱动）。
//!
//! 用法：`offsets <boot.img>`
//! 输出的偏移是"通用事实"，与任何漏洞是否被修复无关。

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;

const WANTED: &[(&str, &[&str])] = &[
    ("task_struct", &["cred", "real_cred", "comm", "pid", "mm", "flags"]),
    ("selinux_state", &["enforcing", "initialized"]),
    ("cred", &["uid", "gid", "euid", "egid", "cap_effective"]),
];

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: offsets <boot.img>"))?;
    let boot = BootImage::load(Path::new(&path))?;
    let raw = boot
        .embedded_btf()
        .ok_or_else(|| anyhow::anyhow!("no BTF in this image"))?;
    let btf = Btf::new(&raw)?;

    for (name, fields) in WANTED {
        let Some(size) = btf.size(name) else {
            println!("{name}: <not found>");
            continue;
        };
        println!("{name} size=0x{size:x}");
        for field in *fields {
            match btf.field(name, field) {
                // field() 已经返回字节偏移（校准依据：task_struct.cred=0x900、
                // real_cred=0x8f8 二者相差 8 且都 8 字节对齐，符合指针布局）。
                Some(offset) => println!("  {field:16} 0x{offset:x}"),
                None => println!("  {field:16} <none>"),
            }
        }
    }
    Ok(())
}
