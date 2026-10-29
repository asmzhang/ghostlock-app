//! Dump recovered kallsyms symbols from a boot image.
//!
//! 用法：`ghostlock-extract` 的兄弟命令 `syms <boot.img> [子串过滤]`
//! 输出 `<16 位十六进制地址> <符号名>`，用于离线反汇编前的地址定位。

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::kallsyms_finder;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: syms <boot.img> [substr]"))?;
    let filter = args.next();

    let boot = BootImage::load(Path::new(&path))?;
    let ks = kallsyms_finder::recover(&boot.kernel, None)?;

    let mut dumped = 0usize;
    for (name, addrs) in &ks.symbols {
        if let Some(needle) = filter.as_deref()
            && !name.contains(needle)
        {
            continue;
        }
        for addr in addrs {
            println!("{:016x} {}", addr, name);
            dumped += 1;
        }
    }
    eprintln!("dumped {dumped} symbols (total names {})", ks.symbols.len());
    Ok(())
}
