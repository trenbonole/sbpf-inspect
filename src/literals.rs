//! Exact string literals and source locations a program carries.
//!
//! Rust packs string literals back to back with no terminator, so a plain scan glues them
//! together. Exact strings come from where the program says how long they are:
//!
//! * code slices: `lddw rN, addr` with `mov rN+1, len` next to it (a `&str` passed as two
//!   registers);
//! * data slices: a pointer slot followed by a length, as in `&str` tables;
//! * panic locations: Rust's `core::panic::Location { file: &str, line: u32, col: u32 }`, which
//!   give the source file, line and column of each panic site the compiler kept.
//!
//! An embedded security.txt (solana-security-txt) is read as well.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::isa::{AluOp, Op, Operand};
use crate::program::Program;

const MAX_SLICE: u64 = 4096;
const MAX_LOCATIONS: usize = 200_000;
const MAX_STRINGS: usize = 500_000;
const SECURITY_BEGIN: &[u8] = b"=======BEGIN SECURITY.TXT V1=======\0";
const SECURITY_END: &[u8] = b"=======END SECURITY.TXT V1=======\0";

#[derive(Debug, Clone, Serialize)]
pub struct StringRef {
    pub addr: u64,
    pub text: String,
    /// `code` (a pointer and length in registers) or `data` (a pointer and length in memory).
    pub via: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PanicLocation {
    /// Address of the `Location` value.
    pub addr: u64,
    pub file: String,
    pub line: u32,
    pub col: u32,
    /// Instructions that load this location's address.
    pub referenced_by: Vec<u32>,
}

#[derive(Debug, Default)]
pub struct Literals {
    /// Exact strings by address.
    pub strings: BTreeMap<u64, StringRef>,
    /// Instruction -> string address it loads with its length.
    pub code_slices: HashMap<u32, u64>,
    /// Address of a `&str` value in memory -> the string's address.
    pub str_slots: HashMap<u64, u64>,
    pub locations: BTreeMap<u64, PanicLocation>,
    pub security_txt: Option<Vec<(String, String)>>,
    pub truncated: bool,
}

fn plausible_text(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    if s.is_empty() {
        return None;
    }
    let good = s.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r')).count();
    (good * 10 >= s.chars().count() * 9).then(|| s.to_string())
}

/// The length register an `lddw` into `dst` is paired with: `mov dst+1, len` within a few
/// straight-line instructions before or after it.
fn paired_len(p: &Program, i: usize, dst: u8) -> Option<u64> {
    let len_reg = dst + 1;
    if len_reg > 5 {
        return None;
    }
    let is_len_mov = |op: &Op| match *op {
        Op::Alu { op: AluOp::Mov, dst: d, src: Operand::Imm(n), .. } if d == len_reg && n > 0 && (n as u64) <= MAX_SLICE => Some(n as u64),
        _ => None,
    };
    let writes = |op: &Op, r: u8| match *op {
        Op::Lddw { dst, .. } | Op::Load { dst, .. } | Op::Alu { dst, .. } => dst == r,
        _ => false,
    };
    let ends = |op: &Op| matches!(op, Op::Ja { .. } | Op::Jcond { .. } | Op::Call { .. } | Op::Callx { .. } | Op::Exit);
    for k in i + 1..(i + 5).min(p.insns.len()) {
        let op = &p.insns[k].op;
        if let Some(n) = is_len_mov(op) {
            return Some(n);
        }
        if ends(op) || writes(op, len_reg) || writes(op, dst) {
            break;
        }
    }
    for k in (i.saturating_sub(4)..i).rev() {
        let op = &p.insns[k].op;
        if let Some(n) = is_len_mov(op) {
            return Some(n);
        }
        if ends(op) || writes(op, len_reg) {
            break;
        }
    }
    None
}

pub fn recover(p: &Program) -> Literals {
    let mut out = Literals::default();

    // Code slices.
    for (i, x) in p.insns.iter().enumerate() {
        let Op::Lddw { dst, .. } = x.op else { continue };
        let Some(addr) = p.lddw_value(i as u32) else { continue };
        if p.region_of(addr).is_none() {
            continue;
        }
        let Some(len) = paired_len(p, i, dst) else { continue };
        let Some(text) = p.read(addr, len as usize).and_then(plausible_text) else { continue };
        out.code_slices.insert(i as u32, addr);
        if out.strings.len() < MAX_STRINGS {
            out.strings.entry(addr).or_insert(StringRef { addr, text, via: "code" });
        } else {
            out.truncated = true;
        }
    }

    // Data slices and panic locations: 8-aligned pointer slots followed by a length.
    for r in &p.data {
        let n = r.bytes.len();
        let mut o = 0usize;
        while o + 16 <= n {
            let slot = r.vaddr + o as u64;
            o += 8;
            let Some(ptr) = p.pointer_at(slot) else { continue };
            if p.region_of(ptr).is_none() {
                continue;
            }
            let len = u64::from_le_bytes(r.bytes[o..o + 8].try_into().unwrap_or([0; 8]));
            if len == 0 || len > MAX_SLICE {
                continue;
            }
            let Some(text) = p.read(ptr, len as usize).and_then(plausible_text) else { continue };
            // Newer Rust toolchains store location file names NUL-terminated, the NUL counted in the length.
            let text = text.strip_suffix('\0').map(str::to_string).unwrap_or(text);
            if text.ends_with(".rs") && o + 16 <= n && out.locations.len() < MAX_LOCATIONS {
                let line = u32::from_le_bytes(r.bytes[o + 8..o + 12].try_into().unwrap_or([0; 4]));
                let col = u32::from_le_bytes(r.bytes[o + 12..o + 16].try_into().unwrap_or([0; 4]));
                if (1..=1_000_000).contains(&line) && col <= 10_000 {
                    out.locations.insert(slot, PanicLocation { addr: slot, file: text.clone(), line, col, referenced_by: Vec::new() });
                }
            }
            out.str_slots.insert(slot, ptr);
            if out.strings.len() < MAX_STRINGS {
                out.strings.entry(ptr).or_insert(StringRef { addr: ptr, text, via: "data" });
            } else {
                out.truncated = true;
            }
        }
    }

    // Which instructions load each location.
    if !out.locations.is_empty() {
        for (i, x) in p.insns.iter().enumerate() {
            if let Op::Lddw { .. } = x.op {
                if let Some(v) = p.lddw_value(i as u32) {
                    if let Some(loc) = out.locations.get_mut(&v) {
                        loc.referenced_by.push(i as u32);
                    }
                }
            }
        }
    }

    out.security_txt = security_txt(p.elf.bytes);
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Key/value pairs of an embedded security.txt.
pub fn security_txt(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let start = find(bytes, SECURITY_BEGIN)? + SECURITY_BEGIN.len();
    let rest = bytes.get(start..start + (64 << 10).min(bytes.len() - start))?;
    let end = find(rest, SECURITY_END)?;
    let fields: Vec<String> = rest[..end].split(|&b| b == 0).map(|f| String::from_utf8_lossy(f).into_owned()).collect();
    let pairs = fields.chunks(2).filter(|c| c.len() == 2 && !c[0].is_empty()).map(|c| (c[0].clone(), c[1].clone())).collect();
    Some(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_txt_pairs() {
        let mut b = b"junk".to_vec();
        b.extend_from_slice(SECURITY_BEGIN);
        b.extend_from_slice(b"name\0Demo\0contacts\0email:a@b.c\0");
        b.extend_from_slice(SECURITY_END);
        let pairs = security_txt(&b).unwrap();
        assert_eq!(pairs, vec![("name".into(), "Demo".into()), ("contacts".into(), "email:a@b.c".into())]);
        assert!(security_txt(b"nothing here").is_none());
    }
}
