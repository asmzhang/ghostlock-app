//! One-off probe: measure the IPv6 setsockopt chain frames and the greqs copy
//! window on a stock arm64 Image, to decide whether FUTEX_LOCK_PI parking can
//! reach the multicast stamp on Pixel 6 (oriole 5.10.157).
//!
//! Usage: `p6-ipv6-probe <image>`

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{disassemble_symbol, relative_symbols, RelSymbols};
use ghostlock_extract::kallsyms_finder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).expect("usage: p6-ipv6-probe <image>");
    let boot = BootImage::load(std::path::Path::new(&path))?;

    let ks = kallsyms_finder::recover(&boot.kernel, None)?;
    let base = *ks
        .symbols
        .get("_text")
        .and_then(|s| s.iter().next())
        .ok_or("_text not found")?;
    let (rel, sorted): (RelSymbols, Vec<u64>) = relative_symbols(&ks.symbols, base);

    const CAP: usize = 0x1000;

    // 1) Frames of every function on the two candidate chains.
    let chains: &[&[&str]] = &[
        // IPv4 reference chain (known): 0x370 with greqs at 0x18
        &[
            "__arm64_sys_setsockopt",
            "__sys_setsockopt",
            "sock_common_setsockopt",
            "udp_setsockopt",
            "ip_setsockopt",
        ],
        // IPv6 candidate chain
        &[
            "__arm64_sys_setsockopt",
            "__sys_setsockopt",
            "sock_common_setsockopt",
            "udpv6_setsockopt",
            "ipv6_setsockopt",
            "do_ipv6_setsockopt",
        ],
    ];
    for (ci, chain) in chains.iter().enumerate() {
        println!("== chain {ci} ==");
        let mut total = 0u64;
        for name in chain.iter() {
            match disassemble_symbol(&boot.kernel, &rel, &sorted, name, CAP) {
                Ok(dis) => {
                    // first_sp_frame equivalent: look for paciasp + `sub sp, sp, #imm`
                    // or pre-indexed `stp x29, x30, [sp, #-imm]!`
                    let mut frame: Option<u64> = None;
                    let mut started = false;
                    for l in &dis {
                        let t = l.trim();
                        if !started {
                            if t.contains("paciasp") {
                                started = true;
                            }
                            continue;
                        }
                        let sub: Regex = Regex::new(r"sub\s+sp,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
                        if let Some(c) = sub.captures(t) {
                            frame = u64::from_str_radix(&c[1], 16).ok();
                            break;
                        }
                        let pre: Regex =
                            Regex::new(r"stp\s+x29,\s*x30,\s*\[sp,\s*#-0x([0-9a-f]+)\]!").unwrap();
                        if let Some(c) = pre.captures(t) {
                            frame = u64::from_str_radix(&c[1], 16).ok();
                            break;
                        }
                        // leaf-ish: leave frame None
                    }
                    let off = rel
                        .get(*name)
                        .and_then(|s| s.iter().next())
                        .copied()
                        .unwrap_or(0);
                    println!("  {name} off=0x{off:x} frame={}", fmt(frame));
                    if let Some(f) = frame {
                        total = total.saturating_add(f);
                    }
                }
                Err(e) => println!("  {name}: DIS FAIL {e}"),
            }
        }
        println!("  Σ frames = 0x{total:x}");
    }

    // 2) The IPv6 greqs copy: `mov w2, #0x108` fed by `add xN, sp, #imm`
    //    inside do_ipv6_setsockopt.
    if let Ok(dis) = disassemble_symbol(&boot.kernel, &rel, &sorted, "do_ipv6_setsockopt", 0x2000) {
        println!("== do_ipv6_setsockopt copy sites ==");
        for (i, l) in dis.iter().enumerate() {
            let t = l.trim();
            if t.contains("mov\tw2, #0x108") || t.contains("mov w2, #0x108") {
                let lo = i.saturating_sub(8);
                println!("  mov site #{i} addr={}", l.split(':').next().unwrap_or("?"));
                for prev in dis[lo..i].iter().rev() {
                    let p = prev.trim();
                    if p.contains("add\tx") && p.contains(", sp, #") {
                        println!("    fed by {}", p);
                        break;
                    }
                }
            }
        }
        // Also dump how many 0x108 constants appear at all (x29-relative too).
        let n = dis.iter().filter(|l| l.contains("#0x108")).count();
        println!("  total '#0x108' occurrences: {n}");
    } else {
        println!("do_ipv6_setsockopt: symbol missing");
    }

    // 3) udpv6_setsockopt / ipv6_setsockopt dispatch shapes (indirect vs direct).
    for name in ["udpv6_setsockopt", "ipv6_setsockopt", "rawv6_setsockopt", "tcp_setsockopt"] {
        match disassemble_symbol(&boot.kernel, &rel, &sorted, name, 0x800) {
            Ok(dis) => {
                println!("== {name} head ==");
                for l in dis.iter().take(24) {
                    println!("  {}", l.trim());
                }
            }
            Err(e) => println!("== {name}: DIS FAIL {e} =="),
        }
    }

    Ok(())
}

fn fmt(f: Option<u64>) -> String {
    match f {
        Some(v) => format!("0x{v:x}"),
        None => "leaf/none".to_string(),
    }
}

use regex::Regex;
