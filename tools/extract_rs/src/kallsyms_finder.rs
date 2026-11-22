//! In-image kallsyms recovery: rebuild the kernel's embedded symbol table from
//! the uncompressed arm64 Image alone (no root, no /proc/kallsyms).
//!
//! Format (kernel/kallsyms.c, scripts/kallsyms.c): a 256-entry token table
//! with a u16 index, length-prefixed compressed names (u8 or uleb128 since
//! v4.20), u32 markers every 256 names, and 32-bit addresses relative to a
//! base (since v4.6; pre-6.4 they sit before the names, 6.4+ after the token
//! index). The scan/validation follows these invariants, matching the layout
//! used by KernelSU ksud for ARM64 GKI images.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{ExtractError, Result};
use crate::kallsyms::Kallsyms;

const ALIGN: usize = 8;
const TOKEN_COUNT: usize = 256;
const TOKEN_INDEX_SIZE: usize = TOKEN_COUNT * 2;
/// token 表尾到索引表的最大搜索距离（4.14 实测 65 字节填充，按 256 对齐）。
const TOKEN_INDEX_SEARCH: usize = 1024;
const MAX_TOKEN_LEN: usize = 256;
const MARKER_SEARCH_WINDOW: usize = 4 * 1024 * 1024;
const NAME_TAIL_SEARCH: usize = 0x40000;
/// `kallsyms_markers` may sit up to this far past the end of the names block
/// (linkers round the block up to 256 bytes on 4.14+).
const NAME_END_PADDING: usize = 256;
const MIN_MARKERS: usize = 8;
const MAX_MARKERS: usize = 4096;

const SYMBOL_TYPES: &[u8] = b"aAbBcCdDeEfFgGiInNpPrRsStTuUvVwW?-";
/// Anchor symbols every real kallsyms table carries. Vendor 4.14 kernels drop
/// `_text`/`_end` in favour of `_stext`/`_etext`, so only `load_module` is
/// mandatory here; the address decoders pick whichever text base exists.
const REQUIRED_SYMBOLS: [&str; 1] = ["load_module"];

const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn find_subslice(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start > data.len() {
        return None;
    }
    data[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + start)
}

/// Image size from the arm64 Image header (offset 0x10), when present.  The
/// declared size may exceed the stored bytes: vendor boot.img packers often
/// trim trailing zeros (.bss/padding) from the Image.
fn arm64_image_size(image: &[u8]) -> Option<usize> {
    if image.len() < 64 || image.get(0x38..0x3c) != Some(b"ARM\x64") {
        return None;
    }
    let size = read_u64(image, 0x10)?;
    usize::try_from(size).ok().filter(|size| *size != 0)
}

struct TokenTable {
    tokens: Vec<Vec<u8>>,
    table_offset: usize,
    index_offset: usize,
}

/// Validate the 256-token table starting at `start`, whose '0' entry must sit
/// exactly at `digit_offset` (the position the digit run was found at).
fn parse_token_table_at(image: &[u8], start: usize, digit_offset: usize) -> Option<TokenTable> {
    if start % ALIGN != 0 {
        return None;
    }
    let mut tokens = Vec::with_capacity(TOKEN_COUNT);
    let mut token_offsets = Vec::with_capacity(TOKEN_COUNT);
    let mut token_starts = Vec::with_capacity(TOKEN_COUNT);
    let mut position = start;
    for _ in 0..TOKEN_COUNT {
        token_starts.push(position);
        let search_end = position.checked_add(MAX_TOKEN_LEN + 1)?.min(image.len());
        let length = image
            .get(position..search_end)?
            .iter()
            .position(|byte| *byte == 0)?;
        if length == 0 {
            return None;
        }
        let end = position.checked_add(length)?;
        let token = image.get(position..end)?;
        if token.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return None;
        }
        token_offsets.push(position.checked_sub(start)?);
        tokens.push(token.to_vec());
        position = end.checked_add(1)?;
    }

    if *token_starts.get(b'0' as usize)? != digit_offset {
        return None;
    }
    for &value in b"0123456789_abcdefghijklmnopqrstuvwxyzT" {
        if tokens.get(value as usize)?.as_slice() != [value] {
            return None;
        }
    }

    // 4.14 及更早的内核把 token 表放进单独的节，`kallsyms_token_index` 与表尾之间
    // 会留一段零填充（实测 65 字节，按 256 字节对齐），不像 5.10+ 那样紧贴 8 字节对齐。
    // 因此在表尾之后一小段范围内逐个试候选索引起点，取第一个 256 项全部吻合的位置。
    if *token_offsets.last()? > u16::MAX as usize {
        return None;
    }
    let search_limit = position.saturating_add(TOKEN_INDEX_SEARCH);
    let mut index_offset = align_up(position, 2);
    while index_offset < search_limit && index_offset + TOKEN_INDEX_SIZE <= image.len() {
        let matches = token_offsets
            .iter()
            .enumerate()
            .all(|(index, &expected)| {
                read_u16(image, index_offset + index * 2) == Some(expected as u16)
            });
        if matches {
            return Some(TokenTable {
                tokens,
                table_offset: start,
                index_offset,
            });
        }
        index_offset += 2;
    }
    None
}

/// Scan the image for token tables: find the "0\0..9\0" digit run, then try
/// every 8-aligned table start that could place the '0' entry at that run.
fn find_token_tables(image: &[u8]) -> Vec<TokenTable> {
    let mut digit_needle = Vec::with_capacity(20);
    for value in b'0'..=b'9' {
        digit_needle.extend_from_slice(&[value, 0]);
    }
    let mut tables = Vec::new();
    let mut search_from = 0;
    while let Some(digit_offset) = find_subslice(image, &digit_needle, search_from) {
        let earliest = digit_offset.saturating_sub(b'0' as usize * (MAX_TOKEN_LEN + 1));
        let mut start = align_up(earliest, ALIGN);
        while start <= digit_offset {
            if let Some(table) = parse_token_table_at(image, start, digit_offset) {
                tables.push(table);
            }
            start += ALIGN;
        }
        search_from = digit_offset.saturating_add(1);
        if search_from >= image.len() {
            break;
        }
    }
    tables
}

/// Read `kallsyms_markers` starting at `start`: first entry 0, every following
/// delta within one name-block (0x200..=0x40000); bounded by `limit`.
/// 读一个条目：`stride` 为 4 表示 u32（5.x 起的 `kallsyms_markers`），
/// 为 8 表示「PTR」宽度的 u64（4.14 及更早在 arm64 上就是 8 字节）。
fn read_marker_word(image: &[u8], offset: usize, stride: usize) -> Option<u32> {
    let value = if stride == 8 {
        let bytes = image.get(offset..offset.checked_add(8)?)?;
        u64::from_le_bytes(bytes.try_into().ok()?)
    } else {
        read_u32(image, offset)? as u64
    };
    u32::try_from(value).ok()
}

fn read_markers_with_stride(image: &[u8], start: usize, limit: usize, stride: usize) -> Vec<u32> {
    if start % ALIGN != 0 || start.saturating_add(stride * 2) > limit {
        return Vec::new();
    }
    let Some(first) = read_marker_word(image, start, stride) else {
        return Vec::new();
    };
    let Some(second) = read_marker_word(image, start + stride, stride) else {
        return Vec::new();
    };
    if first != 0 || !(0x200..=0x40000).contains(&second) {
        return Vec::new();
    }

    let mut markers = vec![first, second];
    let mut position = start + stride * 2;
    while markers.len() < MAX_MARKERS && position.saturating_add(stride) <= limit {
        let Some(value) = read_marker_word(image, position, stride) else {
            break;
        };
        let Some(delta) = value.checked_sub(*markers.last().expect("non-empty markers")) else {
            break;
        };
        if !(0x200..=0x40000).contains(&delta) {
            break;
        }
        markers.push(value);
        position += stride;
    }
    if markers.len() < MIN_MARKERS {
        Vec::new()
    } else {
        markers
    }
}

fn read_markers(image: &[u8], start: usize, limit: usize) -> Vec<(usize, Vec<u32>)> {
    let mut found = Vec::new();
    for stride in [4usize, 8] {
        let markers = read_markers_with_stride(image, start, limit, stride);
        if !markers.is_empty() {
            found.push((stride, markers));
        }
    }
    found
}

/// Walk `count` length-prefixed name entries; every 256th entry must match the
/// corresponding marker, and the block must end exactly at `markers_offset`.
fn parse_name_spans(
    image: &[u8],
    names_offset: usize,
    count: usize,
    markers_offset: usize,
    markers: &[u32],
    uleb128_lengths: bool,
) -> Option<Vec<(usize, usize)>> {
    if count == 0 || markers.len() != count.div_ceil(256) {
        return None;
    }

    let mut spans = Vec::with_capacity(count);
    let mut position = names_offset;
    for index in 0..count {
        if index.is_multiple_of(256)
            && position.checked_sub(names_offset)? != markers[index / 256] as usize
        {
            return None;
        }
        if position >= markers_offset {
            return None;
        }
        let mut length = *image.get(position)? as usize;
        position += 1;
        if uleb128_lengths && length & 0x80 != 0 {
            if position >= markers_offset {
                return None;
            }
            let high = *image.get(position)? as usize;
            if high & 0x80 != 0 {
                return None;
            }
            length = (length & 0x7f) | (high << 7);
            position += 1;
        }
        if length == 0 || length > 0x3fff || position.checked_add(length)? > markers_offset {
            return None;
        }
        spans.push((position, length));
        position += length;
    }

    if markers_offset < position
        || markers_offset - position > NAME_END_PADDING
        || image
            .get(position..markers_offset)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }
    Some(spans)
}

/// Expand token runs into `(type, name)` pairs and require the anchor symbols
/// that every real kallsyms table carries.
fn decode_names(
    image: &[u8],
    spans: &[(usize, usize)],
    tokens: &[Vec<u8>],
) -> Option<Vec<(u8, String)>> {
    let mut decoded = Vec::with_capacity(spans.len());
    for &(position, length) in spans {
        let encoded = image.get(position..position.checked_add(length)?)?;
        let expanded_length = encoded.iter().try_fold(0usize, |total, &index| {
            total.checked_add(tokens.get(index as usize)?.len())
        })?;
        if expanded_length > 4096 {
            return None;
        }
        let mut expanded = Vec::with_capacity(expanded_length);
        for &index in encoded {
            expanded.extend_from_slice(tokens.get(index as usize)?);
        }
        let (&kind, name_bytes) = expanded.split_first()?;
        if name_bytes.is_empty()
            || !SYMBOL_TYPES.contains(&kind)
            || name_bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        {
            return None;
        }
        decoded.push((kind, String::from_utf8(name_bytes.to_vec()).ok()?));
    }

    let names: BTreeSet<&str> = decoded.iter().map(|(_, name)| name.as_str()).collect();
    if REQUIRED_SYMBOLS
        .iter()
        .any(|required| !names.contains(required))
    {
        return None;
    }
    Some(decoded)
}

/// (num_syms offset, names offset, markers offset, decoded symbols)
type NameTable = (usize, usize, usize, Vec<(u8, String)>);

/// Recover the names block: search for markers before the token table, then
/// hunt for the `num_syms` word whose count and padding line up with the
/// markers, decoding both u8 and uleb128 length encodings.
fn find_name_tables(image: &[u8], tokens: &[Vec<u8>], token_table_offset: usize) -> Vec<NameTable> {
    let lower = token_table_offset.saturating_sub(MARKER_SEARCH_WINDOW);
    let mut marker_candidates = Vec::new();
    let mut position = align_up(lower, ALIGN);
    while position.saturating_add(8) <= token_table_offset {
        for (stride, markers) in read_markers(image, position, token_table_offset) {
            marker_candidates.push((position, stride, markers));
        }
        position += ALIGN;
    }

    eprintln!("[dbg] marker candidates = {}", marker_candidates.len());
    let mut recovered = Vec::new();
    for (markers_offset, marker_stride, markers) in marker_candidates {
        let _ = marker_stride;
        let minimum_count = (markers.len() - 1) * 256 + 1;
        let maximum_count = markers.len() * 256;
        let Some(approximate_names) =
            markers_offset.checked_sub(*markers.last().expect("non-empty markers") as usize)
        else {
            continue;
        };
        eprintln!(
            "[dbg] markers @0x{:x} n={} last=0x{:x} approx_names=0x{:x}",
            markers_offset,
            markers.len(),
            *markers.last().unwrap(),
            approximate_names
        );
        let search_start = approximate_names.saturating_sub(NAME_TAIL_SEARCH);
        let mut num_syms_offset = approximate_names - approximate_names % ALIGN;
        loop {
            if num_syms_offset.saturating_add(8) <= image.len() {
                let count = read_u64(image, num_syms_offset).unwrap_or(0) as usize;
                if (minimum_count..=maximum_count).contains(&count) {
                    eprintln!(
                        "[dbg] count candidate @0x{:x} = {} (window {}..={})",
                        num_syms_offset, count, minimum_count, maximum_count
                    );
                    // 4.14 (and later) pad the names block to a 256-byte
                    // boundary, so `kallsyms_names` can start well after the
                    // `num_syms` word. Try every power-of-two pad the linker
                    // uses and keep the ones whose gap is entirely zero.
                    for pad in [ALIGN, 0x40, 0x80, 0x100] {
                        let names_offset = num_syms_offset.saturating_add(pad);
                        let gap_is_zero = image
                            .get(num_syms_offset + ALIGN..names_offset)
                            .is_some_and(|gap| gap.iter().all(|byte| *byte == 0));
                        if !gap_is_zero {
                            continue;
                        }
                        let mut seen_spans: Vec<Vec<(usize, usize)>> = Vec::new();
                        for uleb128_lengths in [true, false] {
                            let Some(spans) = parse_name_spans(
                                image,
                                names_offset,
                                count,
                                markers_offset,
                                &markers,
                                uleb128_lengths,
                            ) else {
                                continue;
                            };
                            if seen_spans.contains(&spans) {
                                continue;
                            }
                            seen_spans.push(spans.clone());
                            if let Some(decoded) = decode_names(image, &spans, tokens) {
                                recovered.push((
                                    num_syms_offset,
                                    names_offset,
                                    markers_offset,
                                    decoded,
                                ));
                            }
                        }
                    }
                }
            }
            if num_syms_offset < search_start.saturating_add(ALIGN) {
                break;
            }
            num_syms_offset -= ALIGN;
        }
    }
    recovered
}

const fn is_arm64_kernel_address(address: u64) -> bool {
    address >> 48 == 0xffff && address.is_multiple_of(4096)
}

/// Decode `kallsyms_offsets` + `kallsyms_relative_base` into absolute
/// addresses, requiring a sorted table that spans exactly the image.
fn decode_addresses(
    image: &[u8],
    image_size: usize,
    names: &[(u8, String)],
    offsets_offset: usize,
    relative_base_offset: usize,
) -> Option<Vec<(u64, u8, String)>> {
    let count = names.len();
    let offsets_end = offsets_offset.checked_add(count.checked_mul(4)?)?;
    if offsets_end > image.len()
        || relative_base_offset < offsets_end
        || relative_base_offset.checked_add(8)? > image.len()
        || image
            .get(offsets_end..relative_base_offset)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }
    let relative_base = read_u64(image, relative_base_offset)?;
    if !is_arm64_kernel_address(relative_base) {
        return None;
    }

    let signed_offsets = (0..count)
        .map(|index| read_i32(image, offsets_offset + index * 4))
        .collect::<Option<Vec<_>>>()?;
    let negative_count = signed_offsets.iter().filter(|offset| **offset < 0).count();
    let addresses = if negative_count * 2 >= count {
        signed_offsets
            .iter()
            .map(|&offset| {
                let address = if offset < 0 {
                    i128::from(relative_base) - 1 - i128::from(offset)
                } else {
                    i128::from(offset)
                };
                u64::try_from(address).ok()
            })
            .collect::<Option<Vec<_>>>()?
    } else {
        (0..count)
            .map(|index| {
                relative_base.checked_add(u64::from(read_u32(image, offsets_offset + index * 4)?))
            })
            .collect::<Option<Vec<_>>>()?
    };

    if addresses.windows(2).any(|pair| pair[0] > pair[1]) {
        return None;
    }
    let text_addresses = addresses
        .iter()
        .zip(names)
        .filter_map(|(&address, (_, name))| (name == "_text").then_some(address))
        .collect::<Vec<_>>();
    let end_addresses = addresses
        .iter()
        .zip(names)
        .filter_map(|(&address, (_, name))| (name == "_end").then_some(address))
        .collect::<Vec<_>>();
    if text_addresses.len() != 1
        || end_addresses.len() != 1
        || text_addresses[0] != relative_base
        || end_addresses[0].checked_sub(text_addresses[0])? != image_size as u64
    {
        return None;
    }

    let ordinary_addresses = addresses
        .iter()
        .zip(names)
        .filter_map(|(&address, (kind, _))| {
            (!b"Aa".contains(kind) && address != 0).then_some(address)
        })
        .collect::<Vec<_>>();
    let in_image = ordinary_addresses
        .iter()
        .filter(|&&address| text_addresses[0] <= address && address <= end_addresses[0])
        .count();
    if ordinary_addresses.is_empty() || in_image * 100 < ordinary_addresses.len() * 90 {
        eprintln!("[dbg] abs: in_image {}/{}", in_image, ordinary_addresses.len());
        return None;
    }

    Some(
        addresses
            .into_iter()
            .zip(names)
            .map(|(address, (kind, name))| (address, *kind, name.clone()))
            .collect(),
    )
}

/// Decode `kallsyms_addresses`: one absolute 8-byte address per symbol, used by
/// kernels built without `CONFIG_KALLSYMS_BASE_RELATIVE` (the common 4.14
/// configuration on Android vendor kernels).
fn decode_absolute_addresses(
    image: &[u8],
    image_size: usize,
    names: &[(u8, String)],
    addresses_offset: usize,
) -> Option<Vec<(u64, u8, String)>> {
    let count = names.len();
    let addresses_end = addresses_offset.checked_add(count.checked_mul(8)?)?;
    if addresses_end > image.len() {
        return None;
    }

    let addresses = (0..count)
        .map(|index| read_u64(image, addresses_offset + index * 8))
        .collect::<Option<Vec<_>>>()?;
    decode_with_addresses(image_size, names, addresses)
}

/// Validate an address table against the decoded names.
fn decode_with_addresses(
    image_size: usize,
    names: &[(u8, String)],
    addresses: Vec<u64>,
) -> Option<Vec<(u64, u8, String)>> {
    if addresses.len() != names.len() {
        return None;
    }
    if addresses.windows(2).any(|pair| pair[0] > pair[1]) {
        return None;
    }

    let text_addresses = addresses
        .iter()
        .zip(names)
        .filter_map(|(&address, (_, name))| (name == "_text" || name == "_stext").then_some(address))
        .collect::<Vec<_>>();
    if text_addresses.len() != 1 {
        eprintln!("[dbg] abs: text anchors = {}", text_addresses.len());
        return None;
    }
    let image_end = text_addresses[0].checked_add(image_size as u64)?;

    let ordinary_addresses = addresses
        .iter()
        .zip(names)
        .filter_map(|(&address, (kind, _))| {
            (!b"Aa".contains(kind) && address != 0).then_some(address)
        })
        .collect::<Vec<_>>();
    let in_image = ordinary_addresses
        .iter()
        .filter(|&&address| text_addresses[0] <= address && address <= image_end)
        .count();
    if ordinary_addresses.is_empty() || in_image * 100 < ordinary_addresses.len() * 90 {
        eprintln!("[dbg] abs: in_image {}/{}", in_image, ordinary_addresses.len());
        return None;
    }

    Some(
        addresses
            .into_iter()
            .zip(names)
            .map(|(address, (kind, name))| (address, *kind, name.clone()))
            .collect(),
    )
}

const R_AARCH64_RELATIVE: u32 = 0x403;
const RELA_ENTRY_SIZE: usize = 24;

/// Relocatable kernels keep `kallsyms_addresses` as zero-filled space that the
/// boot-time `.rela.dyn` pass fills in. The addends of those
/// `R_AARCH64_RELATIVE` entries already hold the linked addresses, so read them
/// straight out of the relocation table instead of the (zeroed) array.
fn recover_relocated_addresses(image: &[u8], count: usize) -> Option<Vec<u64>> {
    if count == 0 {
        return None;
    }
    let limit = image.len().checked_sub(RELA_ENTRY_SIZE)?;
    let is_relative = |offset: usize| {
        read_u64(image, offset + 8)
            .is_some_and(|info| (info & 0xffff_ffff) as u32 == R_AARCH64_RELATIVE)
    };

    // Entries are 24 bytes apart; walk the longest stretch of relative
    // relocations, which is the `.rela.dyn` blob.
    let mut table = (0usize, 0usize);
    let mut offset = 0usize;
    while offset <= limit {
        let starts_run = is_relative(offset)
            && (offset < RELA_ENTRY_SIZE || !is_relative(offset - RELA_ENTRY_SIZE));
        if !starts_run {
            offset += 8;
            continue;
        }
        let mut length = 0usize;
        while offset + length * RELA_ENTRY_SIZE <= limit && is_relative(offset + length * RELA_ENTRY_SIZE) {
            length += 1;
        }
        if length > table.1 {
            table = (offset, length);
        }
        offset += length.max(1) * RELA_ENTRY_SIZE;
    }
    if table.1 < count {
        return None;
    }

    let entries = (0..table.1)
        .filter_map(|index| {
            let offset = table.0 + index * RELA_ENTRY_SIZE;
            let r_offset = read_u64(image, offset)?;
            let info = read_u64(image, offset + 8)?;
            let addend = read_u64(image, offset + 16)?;
            ((info & 0xffff_ffff) as u32 == R_AARCH64_RELATIVE).then_some((r_offset, addend))
        })
        .collect::<Vec<_>>();

    // The address array is relocated one entry per symbol, so it shows up as a
    // `count`-long run whose targets step by eight bytes.
    let mut index = 0usize;
    while index < entries.len() {
        let start = index;
        while index + 1 < entries.len() && entries[index + 1].0 == entries[index].0 + 8 {
            index += 1;
        }
        if index - start + 1 == count {
            let addresses = entries[start..=index]
                .iter()
                .map(|&(_, addend)| addend)
                .collect::<Vec<_>>();
            if addresses.iter().all(|address| *address >= 0xffff_0000_0000_0000) {
                eprintln!("[dbg] rela table @0x{:x} entries={}", table.0, table.1);
                return Some(addresses);
            }
        }
        index += 1;
    }
    None
}

struct Candidate {
    entries: Vec<(u64, u8, String)>,
    layout: &'static str,
}

impl Candidate {
    fn resolve(&self, name: &str) -> Option<u64> {
        let mut found = None;
        for &(address, _, ref candidate) in &self.entries {
            if candidate == name {
                if found.replace(address).is_some() {
                    return None;
                }
            }
        }
        found
    }
}

/// Recover the full kallsyms table from an uncompressed arm64 Image.
///
/// `btf` optionally carries the embedded BTF blob's (file offset, size); when
/// several candidates survive, the one whose `__start_BTF`/`__stop_BTF`
/// delimit that blob wins.
pub fn recover(image: &[u8], btf: Option<(usize, usize)>) -> Result<Kallsyms> {
    let image_size = arm64_image_size(image).unwrap_or(image.len());
    let token_tables = find_token_tables(image);
    let mut candidates = Vec::new();
    let mut name_blocks = 0usize;

    for table in &token_tables {
        eprintln!(
            "[dbg] token table @0x{:x} index @0x{:x} tokens={}",
            table.table_offset,
            table.index_offset,
            table.tokens.len()
        );
        let name_tables = find_name_tables(image, &table.tokens, table.table_offset);
        eprintln!("[dbg] name tables = {}", name_tables.len());
        for (num_syms_offset, _, _, names) in name_tables {
            name_blocks += 1;
            let count = names.len();
            let old_relative_base = num_syms_offset.saturating_sub(ALIGN);
            let old_offsets = old_relative_base.saturating_sub(align_up(count * 4, ALIGN));
            let new_offsets = align_up(table.index_offset + TOKEN_INDEX_SIZE, ALIGN);
            let new_relative_base = align_up(new_offsets + count * 4, ALIGN);
            for (layout, offsets_offset, relative_base_offset) in [
                ("pre-6.4", old_offsets, old_relative_base),
                ("6.4+", new_offsets, new_relative_base),
            ] {
                if let Some(entries) = decode_addresses(
                    image,
                    image_size,
                    &names,
                    offsets_offset,
                    relative_base_offset,
                ) {
                    candidates.push(Candidate { entries, layout });
                }
            }
            let absolute_offsets =
                num_syms_offset.saturating_sub(count.saturating_mul(8)) & !(ALIGN - 1);
            if let Some(entries) =
                decode_absolute_addresses(image, image_size, &names, absolute_offsets)
            {
                candidates.push(Candidate {
                    entries,
                    layout: "absolute-8",
                });
            } else if let Some(addresses) = recover_relocated_addresses(image, count) {
                if let Some(entries) = decode_with_addresses(image_size, &names, addresses) {
                    candidates.push(Candidate {
                        entries,
                        layout: "rela-8",
                    });
                }
            }
        }
    }

    if candidates.is_empty() {
        // No name block at all points at a stripped/moved kallsyms table;
        // name blocks without a matching address table point at an unusual
        // offsets/relative_base or image-size layout.
        return Err(ExtractError::new(format!(
            "no kallsyms table found in the kernel image ({} token tables, {} name blocks, image_size=0x{image_size:x})",
            token_tables.len(),
            name_blocks,
        )));
    }

    let mut boundary_matches = Vec::new();
    if let Some((btf_offset, btf_size)) = btf {
        for (index, candidate) in candidates.iter().enumerate() {
            let Some(base) = candidate.resolve("_text") else {
                continue;
            };
            let Some(btf_start) = candidate.resolve("__start_BTF") else {
                continue;
            };
            let Some(btf_stop) = candidate.resolve("__stop_BTF") else {
                continue;
            };
            let Some(recovered_offset) = btf_start.checked_sub(base) else {
                continue;
            };
            let Some(recovered_size) = btf_stop.checked_sub(btf_start) else {
                continue;
            };
            if recovered_offset == btf_offset as u64 && recovered_size == btf_size as u64 {
                boundary_matches.push(index);
            }
        }
    }

    let selected = if boundary_matches.len() == 1 {
        candidates.swap_remove(boundary_matches[0])
    } else if boundary_matches.is_empty() && candidates.len() == 1 {
        candidates.pop().expect("one candidate")
    } else {
        return Err(ExtractError::new(format!(
            "ambiguous kallsyms recovery in the kernel image ({} token tables, {} complete candidates, {} BTF boundary matches)",
            token_tables.len(),
            candidates.len(),
            boundary_matches.len(),
        )));
    };
    eprintln!(
        "info: kallsyms layout {} recovered ({} symbols)",
        selected.layout,
        selected.entries.len()
    );

    let mut symbols: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut types: BTreeMap<String, BTreeSet<char>> = BTreeMap::new();
    for (address, kind, name) in selected.entries {
        symbols.entry(name.clone()).or_default().insert(address);
        types.entry(name).or_default().insert(kind as char);
    }
    Ok(Kallsyms { symbols, types })
}
