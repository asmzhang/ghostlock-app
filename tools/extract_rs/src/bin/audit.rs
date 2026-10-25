//! Disassembly helper for kernel-profile audits.
//!
//! Resolves symbols in a `boot.img` through its embedded kallsyms and prints the
//! instructions at each target, so a profile's struct offsets and route geometry
//! can be checked against the image instead of being trusted.
//!
//! Usage: `audit <boot.img> [window_hex] [symbol|0xADDR ...]`
//!
//! A `0x`-prefixed target is treated as an absolute address, which lets a single
//! instruction inside a neighbouring symbol be inspected without renaming it.
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::disasm::disassemble_range;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[1];
    let window: usize = args
        .get(2)
        .and_then(|v| usize::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x500);
    let boot = BootImage::load(Path::new(path)).expect("load boot image");
    eprintln!("image bytes = {}", boot.kernel.len());
    let ks = kallsyms_finder::recover(&boot.kernel, None).expect("kallsyms recover");
    let base = kallsyms::unique(&ks.symbols, "_text").expect("_text");
    eprintln!("_text = 0x{base:x}  symbols = {}", ks.symbols.len());

    let targets: Vec<&str> = if args.len() > 3 {
        args[3..].iter().map(|s| s.as_str()).collect()
    } else {
        vec![
            "cap_capable",
            "get_task_cred",
            "__task_cred",
            "prepare_creds",
            "rt_mutex_adjust_prio_chain",
        ]
    };

    for name in targets {
        let resolved = if let Some(hex) = name.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            kallsyms::unique(&ks.symbols, name)
        };
        let Some(addr) = resolved else {
            println!("== {name}: absent or not unique");
            continue;
        };
        let start = addr.wrapping_sub(base) as usize;
        if start >= boot.kernel.len() {
            println!("== {name} @0x{addr:x}: outside image");
            continue;
        }
        let stop = (start + window).min(boot.kernel.len());
        match disassemble_range(&boot.kernel, start, stop) {
            Ok(lines) => {
                println!("== {name} @0x{addr:x}  off=0x{start:x}  insns={}", lines.len());
                for line in &lines {
                    println!("{line}");
                }
            }
            Err(err) => println!("== {name} @0x{addr:x}: disasm error: {err}"),
        }
    }
}
