//! Per-instruction account lists of Anchor programs.
//!
//! Anchor generates a `try_accounts` function for each instruction's Accounts
//! struct. It consumes the accounts slice in field order, through a loader call
//! for typed fields or by taking the next account inline, and when a load fails
//! it attaches the field's name to the error. Constraint checks then raise
//! numbered Anchor errors (2000 ConstraintMut, 2002 ConstraintSigner, 3010
//! AccountNotSigner, ...) that carry the field's name too. So the binary holds,
//! for each account, where it is loaded and which checks name it:
//!
//! 1. The instruction's `try_accounts` is the first function called after its
//!    `Instruction: <Name>` log, in control-flow order, that can raise
//!    AccountNotEnoughKeys (3005) within two call levels.
//! 2. A must-analysis over that function's control flow tracks which registers
//!    and stack slots hold the accounts slice. A load is a call handed the
//!    slice, or an inline take that stores the shortened length back.
//! 3. Account names are read where the code builds them: rodata string slices,
//!    and names assembled inline from immediates (common on sBPF v3).
//! 4. Each load gets the first name its failure path reaches. Each Anchor error
//!    code is attributed to the first name its path reaches.
//! 5. Writable comes from ConstraintMut; signer from ConstraintSigner or
//!    AccountNotSigner, raised by the checks or by the account's loader.
//!
//! Everything here is inferred from code shape. Names come only from the
//! binary, so an account whose name the program never embeds is not listed.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    rc::Rc,
};

use crate::report::{AccountPosition, RecoveredAccount};

const OP_LDDW: u8 = 0x18;
const OP_ADD64_IMM: u8 = 0x07;
const OP_JA: u8 = 0x05;
const OP_JEQ_IMM: u8 = 0x15;
const OP_JNE_IMM: u8 = 0x55;
const OP_CALL: u8 = 0x85;
const OP_EXIT: u8 = 0x95;
const OP_MOV32_IMM: u8 = 0xb4;
const OP_MOV64_IMM: u8 = 0xb7;
const OP_MOV64_REG: u8 = 0xbf;
const OP_LDXDW: u8 = 0x79;
const OP_STXDW: u8 = 0x7b;

const CONSTRAINT_MUT: i32 = 2000;
const CONSTRAINT_SIGNER: i32 = 2002;
const CONSTRAINT_MUT_VARIANT: i32 = 2040;
const ACCOUNT_NOT_ENOUGH_KEYS: i32 = 3005;
const ACCOUNT_NOT_SIGNER: i32 = 3010;
/// Codes only a typed-account loader raises: its error codes are its own.
const TYPED_LOADER_CODES: [i32; 4] = [3001, 3002, 3007, 3012];
/// Syscalls and symbols that never return.
const NO_RETURN: [&str; 3] = ["abort", "sol_panic_", "custom_panic"];
const LOG_PREFIX: &str = "Instruction: ";

/// One decoded instruction. `pc` counts 8-byte slots from the start of `.text`.
#[derive(Debug, Clone, Copy)]
struct Insn {
    pc: i64,
    op: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
    imm64: u64,
    file_offset: u64,
}

struct Section {
    name: String,
    kind: u32,
    addr: u64,
    offset: u64,
    size: u64,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn section_headers(b: &[u8]) -> Option<Vec<Section>> {
    let shoff = usize::try_from(u64_at(b, 0x28)?).ok()?;
    let entsize = usize::from(u16_at(b, 0x3a)?);
    let count = usize::from(u16_at(b, 0x3c)?);
    let strndx = usize::from(u16_at(b, 0x3e)?);
    let mut out = Vec::with_capacity(count);
    let mut name_offsets = Vec::with_capacity(count);
    for i in 0..count {
        let o = shoff.checked_add(i.checked_mul(entsize)?)?;
        name_offsets.push(u32_at(b, o)?);
        out.push(Section {
            name: String::new(),
            kind: u32_at(b, o + 4)?,
            addr: u64_at(b, o + 16)?,
            offset: u64_at(b, o + 24)?,
            size: u64_at(b, o + 32)?,
        });
    }
    let strtab = usize::try_from(out.get(strndx)?.offset).ok()?;
    for (s, name_off) in out.iter_mut().zip(name_offsets) {
        s.name = c_string(b, strtab.checked_add(name_off as usize)?);
    }
    Some(out)
}

fn c_string(b: &[u8], at: usize) -> String {
    b.get(at..).unwrap_or(&[]).iter().take_while(|&&c| c != 0).map(|&c| c as char).collect()
}

fn section_bytes<'a>(b: &'a [u8], s: &Section) -> &'a [u8] {
    let start = usize::try_from(s.offset).unwrap_or(usize::MAX).min(b.len());
    let end = start.saturating_add(usize::try_from(s.size).unwrap_or(usize::MAX)).min(b.len());
    &b[start..end]
}

/// murmur3 32-bit with seed 0: sBPF v3 encodes a syscall as `call` with src 0 and this hash of its name.
pub fn murmur3(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h: u32 = 0;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut k: u32 = 0;
        for (i, &byte) in rest.iter().enumerate() {
            k ^= u32::from(byte) << (8 * i);
        }
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

fn is_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Width of a store-immediate instruction (`stb`, `sth`, `stw`, `stdw`; the immediate is 32 bits).
fn store_imm_width(op: u8) -> Option<u32> {
    match op {
        0x72 => Some(1),
        0x6a => Some(2),
        0x62 | 0x7a => Some(4),
        _ => None,
    }
}

fn is_jump(x: &Insn) -> bool {
    let class = x.op & 7;
    (class == 5 || class == 6) && !matches!(x.op, 0x85 | 0x95 | 0x8d | 0x9d)
}
fn is_term(x: &Insn) -> bool {
    x.op == OP_JA || x.op == OP_EXIT
}
fn is_code(x: &Insn) -> bool {
    (x.op == OP_MOV64_IMM || x.op == OP_MOV32_IMM) && (2000..7000).contains(&x.imm)
}
fn jump_target(x: &Insn) -> i64 {
    x.pc + i64::from(x.off) + 1
}
fn call_target(x: &Insn) -> i64 {
    x.pc + i64::from(x.imm) + 1
}

/// Registers and 8-byte stack slots known to hold the accounts slice.
#[derive(Debug, Clone, Default)]
struct Holds {
    regs: u16,
    slots: BTreeSet<i16>,
}

impl Holds {
    fn reg(&self, r: u8) -> bool {
        self.regs & (1 << r) != 0
    }
    fn set_reg(&mut self, r: u8, on: bool) {
        if on {
            self.regs |= 1 << r;
        } else {
            self.regs &= !(1 << r);
        }
    }
    /// Keep only what `other` also holds; true when something was dropped.
    fn intersect(&mut self, other: &Holds) -> bool {
        let before = (self.regs, self.slots.len());
        self.regs &= other.regs;
        self.slots.retain(|s| other.slots.contains(s));
        before != (self.regs, self.slots.len())
    }
}

#[derive(Debug, Clone)]
struct NameRef {
    i: usize,
    pc: i64,
    name: Rc<str>,
}

#[derive(Debug, Clone)]
struct Event {
    pc: i64,
    callee: Option<i64>,
    names: Vec<Rc<str>>,
    /// Placed for a name with no load of its own; `pc` is a check, not a load.
    synthetic: bool,
}

#[derive(Debug, Clone)]
struct NameInfo {
    codes: BTreeSet<i32>,
    load_key: Option<i64>,
    first_pc: i64,
    check_key: i64,
}

enum Field {
    Nested(RecoveredAccount),
    Named { name: Rc<str>, callee: Option<i64>, position: AccountPosition, load_pc: Option<i64> },
}

/// One instruction's located accounts check and its accounts.
#[derive(Debug, Clone)]
pub struct AccountsCheck {
    /// File offset of the instruction's `try_accounts` function.
    pub check_offset: u64,
    pub accounts: Vec<RecoveredAccount>,
}

struct Analyzer<'a> {
    ins: Vec<Insn>,
    /// Instruction index of each slot; `usize::MAX` for the second slot of `lddw`.
    slot_index: Vec<usize>,
    version: u32,
    rodata: Option<(u64, &'a [u8])>,
    starts: Vec<i64>,
    end_of: HashMap<i64, i64>,
    jumps_to: HashMap<i64, Vec<i64>>,
    syscall_names: HashMap<i64, String>,
    error_ctors: HashSet<i64>,
    name_cache: RefCell<Vec<Option<Option<Rc<str>>>>>,
    names_cache: RefCell<HashMap<i64, Rc<Vec<NameRef>>>>,
    refs_cache: RefCell<HashMap<i64, Rc<Vec<NameRef>>>>,
    helper_cache: RefCell<HashMap<i64, Option<Rc<str>>>>,
    codes_cache: RefCell<HashMap<i64, Rc<BTreeSet<i32>>>>,
    no_return_cache: RefCell<HashMap<i64, bool>>,
    raises_cache: RefCell<HashMap<(i64, i32, u32), bool>>,
    reads_cache: RefCell<HashMap<(i64, u8, u32), bool>>,
    recovered: RefCell<HashMap<i64, Rc<Vec<RecoveredAccount>>>>,
}

impl<'a> Analyzer<'a> {
    fn new(b: &'a [u8]) -> Option<Self> {
        let sections = section_headers(b)?;
        let text = sections.iter().find(|s| s.name == ".text")?;
        let rodata = sections.iter().find(|s| s.name == ".rodata").map(|s| (s.addr, section_bytes(b, s)));
        let version = u32_at(b, 48)?;
        let text_start = usize::try_from(text.offset).ok()?;
        let text_end = text_start.checked_add(usize::try_from(text.size).ok()?)?;

        let mut ins = Vec::new();
        let mut slot_index = Vec::new();
        let (mut p, mut pc) = (text_start, 0i64);
        while p + 8 <= text_end && p + 8 <= b.len() {
            let op = b[p];
            let regs = b[p + 1];
            let off = i16::from_le_bytes([b[p + 2], b[p + 3]]);
            let imm = i32::from_le_bytes([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]);
            let mut x = Insn { pc, op, dst: regs & 15, src: regs >> 4, off, imm, imm64: 0, file_offset: p as u64 };
            slot_index.push(ins.len());
            if op == OP_LDDW {
                let hi = u32_at(b, p + 12).unwrap_or(0);
                x.imm64 = (u64::from(hi) << 32) | u64::from(imm as u32);
                ins.push(x);
                slot_index.push(usize::MAX);
                p += 16;
                pc += 2;
            } else {
                ins.push(x);
                p += 8;
                pc += 1;
            }
        }
        if ins.is_empty() {
            return None;
        }

        // Syscall names: relocations against .dynsym on v0/v1, hashed names on v3.
        let mut syscall_names = HashMap::new();
        let rel = sections.iter().find(|s| s.kind == 9 && s.name == ".rel.dyn");
        let dynsym = sections.iter().find(|s| s.kind == 11);
        let dynstr = sections.iter().find(|s| s.name == ".dynstr");
        if let (Some(rel), Some(dynsym), Some(dynstr)) = (rel, dynsym, dynstr) {
            let rel_bytes = section_bytes(b, rel);
            for entry in rel_bytes.chunks_exact(16) {
                let at = u64::from_le_bytes(entry[0..8].try_into().ok()?);
                let sym = (u64::from_le_bytes(entry[8..16].try_into().ok()?) >> 32) as usize;
                if sym == 0 || at < text.addr || at >= text.addr.saturating_add(text.size) || (at - text.addr) % 8 != 0 {
                    continue;
                }
                let name_off = dynsym.offset as usize + sym * 24;
                let Some(name_idx) = u32_at(b, name_off) else { continue };
                let name = c_string(b, dynstr.offset as usize + name_idx as usize);
                if !name.is_empty() {
                    syscall_names.insert(((at - text.addr) / 8) as i64, name);
                }
            }
        }
        let hashed: HashMap<u32, &str> = ["abort", "sol_panic_"].iter().map(|n| (murmur3(n.as_bytes()), *n)).collect();
        for x in &ins {
            if x.op == OP_CALL && x.src == 0 {
                if let Some(n) = hashed.get(&(x.imm as u32)) {
                    syscall_names.insert(x.pc, n.to_string());
                }
            }
        }

        let mut a = Analyzer {
            ins,
            slot_index,
            version,
            rodata,
            starts: Vec::new(),
            end_of: HashMap::new(),
            jumps_to: HashMap::new(),
            syscall_names,
            error_ctors: HashSet::new(),
            name_cache: RefCell::new(Vec::new()),
            names_cache: RefCell::default(),
            refs_cache: RefCell::default(),
            helper_cache: RefCell::default(),
            codes_cache: RefCell::default(),
            no_return_cache: RefCell::default(),
            raises_cache: RefCell::default(),
            reads_cache: RefCell::default(),
            recovered: RefCell::default(),
        };
        *a.name_cache.borrow_mut() = vec![None; a.ins.len()];

        // Function starts: the entrypoint and every internal call target.
        let mut starts = BTreeSet::new();
        let entry = u64_at(b, 0x18)?;
        if entry >= text.addr && (entry - text.addr) % 8 == 0 {
            starts.insert(((entry - text.addr) / 8) as i64);
        }
        for x in &a.ins {
            if a.is_call(x) {
                starts.insert(call_target(x));
            }
        }
        a.starts = starts.into_iter().collect();
        let last = a.ins.last().map_or(0, |x| x.pc + 1);
        for (k, s) in a.starts.iter().enumerate() {
            a.end_of.insert(*s, a.starts.get(k + 1).copied().unwrap_or(last));
        }
        for x in &a.ins {
            if is_jump(x) {
                a.jumps_to.entry(jump_target(x)).or_default().push(x.pc);
            }
        }
        // Functions handed an Anchor error code right before a call build errors, not accounts.
        for (i, z) in a.ins.iter().enumerate() {
            if !a.is_call(z) {
                continue;
            }
            for k in (i.saturating_sub(3)..i).rev() {
                let m = &a.ins[k];
                if (m.op == OP_MOV64_IMM || m.op == OP_MOV32_IMM) && (1..=5).contains(&m.dst) && (2000..7000).contains(&m.imm) {
                    a.error_ctors.insert(call_target(z));
                    break;
                }
            }
        }
        Some(a)
    }

    fn idx(&self, pc: i64) -> Option<usize> {
        let i = *self.slot_index.get(usize::try_from(pc).ok()?)?;
        (i != usize::MAX).then_some(i)
    }

    /// Instruction indexes of function `f`, which must be a function start.
    fn body(&self, f: i64) -> std::ops::Range<usize> {
        match (self.idx(f), self.end_of.get(&f)) {
            (Some(i0), Some(&end)) => i0..self.ins.partition_point(|x| x.pc < end).max(i0),
            _ => 0..0,
        }
    }

    fn fn_of(&self, pc: i64) -> Option<i64> {
        let k = self.starts.partition_point(|&s| s <= pc);
        if k == 0 { self.starts.first().copied() } else { Some(self.starts[k - 1]) }
    }

    fn is_syscall(&self, x: &Insn) -> bool {
        x.op == OP_CALL && (x.imm == -1 || (self.version >= 3 && x.src == 0))
    }
    fn is_call(&self, x: &Insn) -> bool {
        x.op == OP_CALL && !self.is_syscall(x)
    }
    fn ends_path(&self, x: &Insn) -> bool {
        self.is_syscall(x) && self.syscall_names.get(&x.pc).is_some_and(|n| NO_RETURN.contains(&n.as_str()))
    }
    /// A call that cannot return: to a no-return syscall, or to a function with no exit.
    fn stops(&self, x: &Insn) -> bool {
        x.op == OP_EXIT || self.ends_path(x) || (self.is_call(x) && self.no_return(call_target(x)))
    }

    fn in_rodata(&self, addr: u64) -> bool {
        self.rodata.is_some_and(|(base, data)| addr >= base && addr < base + data.len() as u64)
    }

    // --- account names ---------------------------------------------------------------------

    /// Length of the slice whose address `lddw` at `i` loads: the next slot's immediate, or the
    /// immediate a shared block puts in the next register (`lddw r3, name; ja L` ... `L: mov r4, len`).
    fn slice_len(&self, i: usize) -> Option<usize> {
        let x = &self.ins[i];
        let y = self.ins.get(i + 1)?;
        let ok = |imm: i32| (imm > 0 && imm < 200).then_some(imm as usize);
        if y.op == OP_MOV64_IMM {
            return ok(y.imm);
        }
        if y.op != OP_JA {
            return None;
        }
        let t = &self.ins[self.idx(jump_target(y))?];
        if t.op == OP_MOV64_IMM && t.dst == x.dst + 1 { ok(t.imm) } else { None }
    }

    fn rodata_slice(&self, i: usize) -> Option<String> {
        let x = &self.ins[i];
        if x.op != OP_LDDW || !self.in_rodata(x.imm64) {
            return None;
        }
        let n = self.slice_len(i)?;
        let (base, data) = self.rodata?;
        let start = (x.imm64 - base) as usize;
        let end = start.saturating_add(n).min(data.len());
        Some(data[start..end].iter().map(|&c| c as char).collect())
    }

    /// The 64-bit immediate (not a rodata address) that `stxdw` at `k` stores, when its source
    /// register was just loaded with one.
    fn lddw_source(&self, k: usize) -> Option<u64> {
        let z = &self.ins[k];
        for j in (k.saturating_sub(6)..k).rev() {
            let l = &self.ins[j];
            if l.op == OP_LDDW && l.dst == z.src {
                return if self.in_rodata(l.imm64) { None } else { Some(l.imm64) };
            }
            if l.dst == z.src {
                return None;
            }
        }
        None
    }

    /// A name the code assembles in memory from immediates, anchored at the group's first store.
    fn inline_name(&self, i: usize) -> Option<String> {
        let x = &self.ins[i];
        if store_imm_width(x.op).is_none() && x.op != OP_STXDW {
            return None;
        }
        for k in (i.saturating_sub(6)..i).rev() {
            let z = &self.ins[k];
            if z.dst == x.dst && (store_imm_width(z.op).is_some() || (z.op == OP_STXDW && self.lddw_source(k).is_some())) {
                return None;
            }
        }
        let mut bytes: BTreeMap<i64, u8> = BTreeMap::new();
        for k in i..(i + 8).min(self.ins.len()) {
            let z = &self.ins[k];
            if z.dst != x.dst {
                continue;
            }
            if let Some(width) = store_imm_width(z.op) {
                let v = z.imm as u32;
                for b in 0..width {
                    bytes.insert(i64::from(z.off) + i64::from(b), (v >> (8 * b)) as u8);
                }
            } else if z.op == OP_STXDW {
                if let Some(v) = self.lddw_source(k) {
                    for b in 0..8 {
                        bytes.insert(i64::from(z.off) + b, (v >> (8 * b)) as u8);
                    }
                }
            }
        }
        let (&lo, _) = bytes.iter().next()?;
        let mut text = String::new();
        let mut o = lo;
        while let Some(&c) = bytes.get(&o) {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
                return None;
            }
            text.push(c as char);
            o += 1;
        }
        (text.len() >= 3 && is_ident(&text)).then_some(text)
    }

    /// Whether the name built at `i` goes into a call that never returns: a panic message, such as
    /// bytemuck's `from_bytes`, not an account name.
    fn into_panic(&self, i: usize) -> bool {
        for k in i + 1..(i + 12).min(self.ins.len()) {
            let z = &self.ins[k];
            if z.op == OP_CALL {
                return self.ends_path(z) || (self.is_call(z) && self.no_return(call_target(z)));
            }
            if is_jump(z) || z.op == OP_EXIT {
                return false;
            }
        }
        false
    }

    fn name_at(&self, i: usize) -> Option<Rc<str>> {
        if let Some(cached) = &self.name_cache.borrow()[i] {
            return cached.clone();
        }
        let name = match self.rodata_slice(i) {
            Some(s) => is_ident(&s).then_some(s),
            None => self.inline_name(i),
        }
        .filter(|_| !self.into_panic(i))
        .map(Rc::from);
        self.name_cache.borrow_mut()[i] = Some(name.clone());
        name
    }

    fn names_in(&self, f: i64) -> Rc<Vec<NameRef>> {
        if let Some(c) = self.names_cache.borrow().get(&f) {
            return c.clone();
        }
        let out: Vec<NameRef> = self
            .body(f)
            .filter_map(|i| self.name_at(i).map(|name| NameRef { i, pc: self.ins[i].pc, name }))
            .collect();
        let out = Rc::new(out);
        self.names_cache.borrow_mut().insert(f, out.clone());
        out
    }

    /// The one name a small outlined function builds to attach to an error.
    fn helper_name(&self, f: i64) -> Option<Rc<str>> {
        if let Some(c) = self.helper_cache.borrow().get(&f) {
            return c.clone();
        }
        let mut r = None;
        if self.end_of.get(&f).is_some_and(|&e| e - f <= 80) {
            let n = self.names_in(f);
            if n.len() == 1 {
                r = Some(n[0].name.clone());
            }
        }
        self.helper_cache.borrow_mut().insert(f, r.clone());
        r
    }

    /// Names referenced in `f`, counting a call to a one-name helper as a reference at the call.
    fn refs_in(&self, f: i64) -> Rc<Vec<NameRef>> {
        if let Some(c) = self.refs_cache.borrow().get(&f) {
            return c.clone();
        }
        let mut out: Vec<NameRef> = self.names_in(f).as_ref().clone();
        for i in self.body(f) {
            let z = self.ins[i];
            if self.is_call(&z) {
                if let Some(name) = self.helper_name(call_target(&z)) {
                    out.push(NameRef { i, pc: z.pc, name });
                }
            }
        }
        out.sort_by_key(|r| r.i);
        let out = Rc::new(out);
        self.refs_cache.borrow_mut().insert(f, out.clone());
        out
    }

    // --- functions and error codes ------------------------------------------------------------

    fn own_codes(&self, f: i64) -> Rc<BTreeSet<i32>> {
        if let Some(c) = self.codes_cache.borrow().get(&f) {
            return c.clone();
        }
        let s: BTreeSet<i32> = self.body(f).map(|i| self.ins[i]).filter(is_code).map(|z| z.imm).collect();
        let s = Rc::new(s);
        self.codes_cache.borrow_mut().insert(f, s.clone());
        s
    }

    fn tail_codes(&self, f: i64) -> BTreeSet<i32> {
        let mut out = self.own_codes(f).as_ref().clone();
        for i in self.body(f) {
            let z = &self.ins[i];
            if i + 1 < self.ins.len() && self.is_call(z) && self.ins[i + 1].op == OP_EXIT {
                out.extend(self.own_codes(call_target(z)).iter());
            }
        }
        out
    }

    /// A loader's error codes: its own, its tail calls', and one call deeper unless it is a typed loader.
    fn loader_codes(&self, f: i64) -> BTreeSet<i32> {
        let own = self.tail_codes(f);
        if TYPED_LOADER_CODES.iter().any(|c| own.contains(c)) {
            return own;
        }
        let mut out = own;
        for i in self.body(f) {
            let z = &self.ins[i];
            if self.is_call(z) {
                out.extend(self.own_codes(call_target(z)).iter());
            }
        }
        out
    }

    fn no_return(&self, f: i64) -> bool {
        if let Some(&c) = self.no_return_cache.borrow().get(&f) {
            return c;
        }
        let r = self.idx(f).is_some() && !self.body(f).any(|i| self.ins[i].op == OP_EXIT);
        self.no_return_cache.borrow_mut().insert(f, r);
        r
    }

    /// Whether `f`, or a function it calls within `depth` levels, materializes error `code`.
    fn raises(&self, f: i64, code: i32, depth: u32) -> bool {
        let key = (f, code, depth);
        if let Some(&c) = self.raises_cache.borrow().get(&key) {
            return c;
        }
        self.raises_cache.borrow_mut().insert(key, false);
        let mut r = self.own_codes(f).contains(&code);
        if depth > 0 {
            for i in self.body(f) {
                if r {
                    break;
                }
                let z = self.ins[i];
                if self.is_call(&z) {
                    r = self.raises(call_target(&z), code, depth - 1);
                }
            }
        }
        self.raises_cache.borrow_mut().insert(key, r);
        r
    }

    /// Whether `f` reads register `r` before writing it, along its straight-line start. A call
    /// passes `r` on when the callee reads it; past two levels it is assumed to.
    fn reads_reg(&self, f: i64, r: u8, depth: u32) -> bool {
        let key = (f, r, depth);
        if let Some(&c) = self.reads_cache.borrow().get(&key) {
            return c;
        }
        let result = (|| {
            let Some(start) = self.idx(f) else { return false };
            for z in self.ins[start..].iter().take(40) {
                let class = z.op & 7;
                let reads_src = z.op & 8 != 0;
                if z.op == OP_CALL {
                    return if self.is_call(z) && depth < 2 { self.reads_reg(call_target(z), r, depth + 1) } else { depth >= 2 };
                }
                if z.op == OP_EXIT {
                    return false;
                }
                match class {
                    1 => {
                        if z.src == r {
                            return true;
                        }
                        if z.dst == r {
                            return false;
                        }
                    }
                    2 => {
                        if z.dst == r {
                            return true;
                        }
                    }
                    3 => {
                        if z.dst == r || z.src == r {
                            return true;
                        }
                    }
                    0 => {
                        if z.dst == r {
                            return false;
                        }
                    }
                    4 | 7 => {
                        if reads_src && z.src == r {
                            return true;
                        }
                        if z.dst == r {
                            return z.op & 0xf0 != 0xb0;
                        }
                    }
                    _ => {
                        if z.op == OP_JA {
                            return false;
                        }
                        if z.dst == r || (reads_src && z.src == r) {
                            return true;
                        }
                    }
                }
            }
            false
        })();
        self.reads_cache.borrow_mut().insert(key, result);
        result
    }

    /// The pc of the jump that first leads into the block holding `p`, walking back through
    /// fall-through predecessors: where the check that ends at `p` happens.
    fn entry_key(&self, p: i64, f: i64, fe: i64) -> i64 {
        let Some(mut i) = self.idx(p) else { return p };
        for _ in 0..64 {
            while i > 0
                && self.ins[i - 1].pc >= f
                && !is_term(&self.ins[i - 1])
                && !is_jump(&self.ins[i - 1])
                && !self.jumps_to.contains_key(&self.ins[i].pc)
            {
                i -= 1;
            }
            let q = self.ins[i].pc;
            let srcs: Vec<i64> =
                self.jumps_to.get(&q).map(|v| v.iter().copied().filter(|&x| x >= f && x < fe).collect()).unwrap_or_default();
            let prev = if i > 0 { Some(self.ins[i - 1]) } else { None };
            let falls = prev.is_some_and(|p| p.pc >= f && !is_term(&p));
            if !srcs.is_empty() {
                let m = srcs.iter().copied().min().unwrap_or(q);
                return match prev {
                    Some(p) if falls => m.min(p.pc),
                    _ => m,
                };
            }
            if !falls {
                return q;
            }
            i -= 1;
            if is_jump(&self.ins[i]) {
                return self.ins[i].pc;
            }
        }
        p
    }

    /// Targets of the calls reachable from instruction `i` within `[f, fe)`, breadth-first.
    fn calls_from(&self, i: usize, f: i64, fe: i64) -> Vec<i64> {
        let mut out = Vec::new();
        let mut seen = HashSet::from([i]);
        let mut frontier = vec![i];
        while !frontier.is_empty() && seen.len() < 5000 {
            let mut next = Vec::new();
            for &k in &frontier {
                let z = self.ins[k];
                if self.is_call(&z) {
                    out.push(call_target(&z));
                }
                if self.stops(&z) {
                    continue;
                }
                let succ = if z.op == OP_JA {
                    [self.idx(jump_target(&z)), None]
                } else if is_jump(&z) {
                    [Some(k + 1), self.idx(jump_target(&z))]
                } else {
                    [Some(k + 1), None]
                };
                for t in succ.into_iter().flatten() {
                    if t < self.ins.len() && self.ins[t].pc >= f && self.ins[t].pc < fe && seen.insert(t) {
                        next.push(t);
                    }
                }
            }
            frontier = next;
        }
        out
    }

    // --- one accounts check -------------------------------------------------------------------

    /// Which registers and stack slots hold the slice passed in `param`, before each instruction of
    /// `[i0, ie)`, on every path.
    fn slice_flow(&self, i0: usize, ie: usize, param: u8) -> Vec<Option<Holds>> {
        let mut inn: Vec<Option<Holds>> = vec![None; ie - i0];
        if ie <= i0 {
            return inn;
        }
        let mut start = Holds::default();
        start.set_reg(param, true);
        inn[0] = Some(start);
        let mut work = vec![i0];
        while let Some(i) = work.pop() {
            let z = self.ins[i];
            let Some(mut s) = inn[i - i0].clone() else { continue };
            let class = z.op & 7;
            if z.op == OP_MOV64_REG {
                let on = s.reg(z.src);
                s.set_reg(z.dst, on);
            } else if z.op == OP_LDXDW {
                let on = z.src == 10 && s.slots.contains(&z.off);
                s.set_reg(z.dst, on);
            } else if z.op == OP_STXDW && z.dst == 10 {
                if s.reg(z.src) {
                    s.slots.insert(z.off);
                } else {
                    s.slots.remove(&z.off);
                }
            } else if (class == 2 || class == 3) && z.dst == 10 {
                s.slots.remove(&z.off);
            } else if self.is_syscall(&z) {
                // Syscalls write only r0, and an abort ends the path anyway.
                s.set_reg(0, false);
            } else if z.op == OP_CALL {
                for r in 0..=5 {
                    s.set_reg(r, false);
                }
            } else if matches!(class, 0 | 1 | 4 | 7) {
                s.set_reg(z.dst, false);
            }
            let succ = if self.stops(&z) {
                [None, None]
            } else if z.op == OP_JA {
                [self.idx(jump_target(&z)), None]
            } else if is_jump(&z) {
                [self.idx(jump_target(&z)), Some(i + 1)]
            } else {
                [Some(i + 1), None]
            };
            for t in succ.into_iter().flatten() {
                if t < i0 || t >= ie {
                    continue;
                }
                match &mut inn[t - i0] {
                    None => {
                        inn[t - i0] = Some(s.clone());
                        work.push(t);
                    }
                    Some(cur) => {
                        if cur.intersect(&s) {
                            work.push(t);
                        }
                    }
                }
            }
        }
        inn
    }

    fn composite(&self, callee: Option<i64>, depth: u32) -> bool {
        callee.is_some_and(|c| depth < 3 && !self.refs_in(c).is_empty() && self.raises(c, ACCOUNT_NOT_ENOUGH_KEYS, 2))
    }

    /// The ordered accounts of the `try_accounts` function `t`.
    fn recover(&self, t: i64, depth: u32) -> Rc<Vec<RecoveredAccount>> {
        if let Some(c) = self.recovered.borrow().get(&t) {
            return c.clone();
        }
        let out = Rc::new(self.recover_uncached(t, depth));
        self.recovered.borrow_mut().insert(t, out.clone());
        out
    }

    fn recover_uncached(&self, t: i64, depth: u32) -> Vec<RecoveredAccount> {
        let (Some(i0), Some(&e)) = (self.idx(t), self.end_of.get(&t)) else { return Vec::new() };
        let ins = &self.ins;
        let refs = self.refs_in(t);
        let ie = ins.partition_point(|x| x.pc < e).max(i0);

        // Which argument register holds the slice: score loads and takes under each choice.
        let moved_in = |i: usize, r: u8, flow: &[Option<Holds>]| -> bool {
            for k in (i0.max(i.saturating_sub(6))..i).rev() {
                let m = &ins[k];
                if m.dst == r && !is_jump(m) && !matches!(m.op & 7, 2 | 3) {
                    return m.op == OP_MOV64_REG && flow[k - i0].as_ref().is_some_and(|h| h.reg(m.src));
                }
                if is_jump(m) || m.op == OP_CALL || self.jumps_to.contains_key(&m.pc) {
                    return false;
                }
            }
            false
        };
        let holds = |i: usize, r: u8, flow: &[Option<Holds>]| flow[i - i0].as_ref().is_some_and(|h| h.reg(r));
        // A loader gets the slice in r2 (specialized) or r3 (after program_id), and reads it. A function
        // handed an error code builds an error. When the other register was just given the slice, this
        // one only still holds it.
        let loader_call = |i: usize, larg: u8, flow: &[Option<Holds>]| -> bool {
            let z = &ins[i];
            if !self.is_call(z) || !holds(i, larg, flow) {
                return false;
            }
            let f = call_target(z);
            if self.error_ctors.contains(&f) || !self.reads_reg(f, larg, 0) {
                return false;
            }
            moved_in(i, larg, flow) || !moved_in(i, if larg == 2 { 3 } else { 2 }, flow)
        };
        let loader_arg = |i: usize, flow: &[Option<Holds>]| -> Option<u8> {
            if loader_call(i, 2, flow) {
                Some(2)
            } else if loader_call(i, 3, flow) {
                Some(3)
            } else {
                None
            }
        };
        let is_grab = |i: usize, flow: &[Option<Holds>]| -> bool {
            let z = &ins[i];
            z.op == OP_STXDW
                && z.off == 8
                && holds(i, z.dst, flow)
                && ins[i.saturating_sub(5)..i].iter().any(|p| p.op == OP_ADD64_IMM && p.imm < 0 && p.imm >= -16 && p.dst == z.src)
        };
        let mut flow: Vec<Option<Holds>> = Vec::new();
        let mut best = -1i64;
        for param in [2u8, 3] {
            let candidate = self.slice_flow(i0, ie, param);
            let mut score = 0i64;
            for i in i0..ie {
                if let Some(a) = loader_arg(i, &candidate) {
                    score += if moved_in(i, a, &candidate) { 2 } else { 1 };
                }
                if is_grab(i, &candidate) {
                    score += 3;
                }
            }
            if score > best {
                best = score;
                flow = candidate;
            }
        }

        let mut events: Vec<Event> = Vec::new();
        for i in i0..ie {
            let z = &ins[i];
            if loader_arg(i, &flow).is_some() {
                events.push(Event { pc: z.pc, callee: Some(call_target(z)), names: Vec::new(), synthetic: false });
            } else if is_grab(i, &flow) {
                events.push(Event { pc: z.pc, callee: None, names: Vec::new(), synthetic: false });
            }
        }

        // Each error code belongs to the first name its path reaches.
        let ref_idx: HashSet<usize> = refs.iter().map(|r| r.i).collect();
        let mut pending: HashMap<usize, Vec<i32>> = HashMap::new();
        for i in i0..ie {
            let z = &ins[i];
            if !is_code(z) {
                continue;
            }
            let mut seen = HashSet::from([i]);
            let mut frontier = vec![i + 1];
            let mut hit = None;
            for _ in 0..120 {
                if frontier.is_empty() || hit.is_some() {
                    break;
                }
                let mut next = Vec::new();
                for &k in &frontier {
                    if k >= ins.len() || ins[k].pc >= e || ins[k].pc < t || !seen.insert(k) {
                        continue;
                    }
                    if ref_idx.contains(&k) {
                        hit = Some(k);
                        break;
                    }
                    let y = &ins[k];
                    if is_code(y) || y.op == OP_EXIT {
                        continue;
                    }
                    if is_jump(y) {
                        if let Some(tg) = self.idx(jump_target(y)) {
                            next.push(tg);
                        }
                        if y.op != OP_JA {
                            next.push(k + 1);
                        }
                    } else {
                        next.push(k + 1);
                    }
                }
                frontier = next;
            }
            if let Some(h) = hit {
                pending.entry(h).or_default().push(z.imm);
            }
        }

        // Per name: its codes, where its load-time check sits, and where its first check sits.
        let mut order: Vec<Rc<str>> = Vec::new();
        let mut info: HashMap<Rc<str>, NameInfo> = HashMap::new();
        for r in refs.iter() {
            let codes = pending.get(&r.i).cloned().unwrap_or_default();
            let key = self.entry_key(r.pc, t, e);
            let v = info.entry(r.name.clone()).or_insert_with(|| {
                order.push(r.name.clone());
                NameInfo { codes: BTreeSet::new(), load_key: None, first_pc: r.pc, check_key: i64::MAX }
            });
            v.check_key = v.check_key.min(key);
            v.codes.extend(codes.iter().copied());
            if codes.is_empty() || codes.iter().any(|&c| c >= 3000) {
                v.load_key = Some(v.load_key.map_or(key, |k| k.min(key)));
            }
        }
        let mut load_names: Vec<Rc<str>> = order.iter().filter(|n| info[*n].load_key.is_some()).cloned().collect();
        load_names.sort_by_key(|n| info[n].load_key);
        let load_key = |n: &Rc<str>| info[n].load_key.unwrap_or(0);
        let last_load = load_names.last().map_or(-1, |n| load_key(n));
        events.retain(|ev| ev.pc <= last_load || self.composite(ev.callee, depth));

        // A load owns the first unclaimed name its failure path reaches.
        let ref_at: HashMap<usize, Rc<str>> = refs.iter().map(|r| (r.i, r.name.clone())).collect();
        let event_pcs: HashSet<i64> = events.iter().map(|ev| ev.pc).collect();
        let load_set: HashSet<Rc<str>> = load_names.iter().cloned().collect();
        let mut taken: HashSet<Rc<str>> = HashSet::new();
        // An inline take's failure path starts at its empty-slice check: the nearest `jeq rA, 0, L`
        // before it, or a `jne rN, 0` after the previous take that falls through into the failure.
        let grab_failure = |i: usize| -> Option<usize> {
            let mut k = i;
            for _ in 0..12 {
                if k == 0 || k - 1 < i0 {
                    break;
                }
                k -= 1;
                let j = &ins[k];
                if j.op == OP_JEQ_IMM && j.imm == 0 {
                    return self.idx(jump_target(j));
                }
                if j.op == OP_STXDW && j.off == 8 && holds(k, j.dst, &flow) {
                    return None;
                }
                if let Some(srcs) = self.jumps_to.get(&j.pc) {
                    if srcs.len() == 1 {
                        if let Some(s) = self.idx(srcs[0]) {
                            if ins[s].op == OP_JNE_IMM && ins[s].imm == 0 {
                                return Some(s + 1);
                            }
                        }
                    }
                }
            }
            None
        };
        for ev in events.iter_mut() {
            let Some(at) = self.idx(ev.pc) else { continue };
            let start = if ev.callee.is_none() { grab_failure(at) } else { Some(at + 1) };
            let Some(start) = start else { continue };
            let mut seen = HashSet::new();
            let mut frontier = vec![start];
            let mut hit: Option<Rc<str>> = None;
            for _ in 0..200 {
                if frontier.is_empty() || hit.is_some() {
                    break;
                }
                let mut next = Vec::new();
                for &k in &frontier {
                    if k >= ins.len() || ins[k].pc >= e || !seen.insert(k) {
                        continue;
                    }
                    if let Some(nm) = ref_at.get(&k) {
                        if load_set.contains(nm) && !taken.contains(nm) {
                            hit = Some(nm.clone());
                            break;
                        }
                        continue;
                    }
                    let y = &ins[k];
                    let take_failure = ev.callee.is_none() && k >= start && k <= start + 3 && y.imm == ACCOUNT_NOT_ENOUGH_KEYS;
                    if (is_code(y) && !take_failure) || y.op == OP_EXIT || (event_pcs.contains(&y.pc) && k != start) {
                        continue;
                    }
                    if is_jump(y) {
                        if let Some(tg) = self.idx(jump_target(y)) {
                            next.push(tg);
                        }
                        if y.op != OP_JA {
                            next.push(k + 1);
                        }
                    } else {
                        next.push(k + 1);
                    }
                }
                frontier = next;
            }
            if let Some(h) = hit {
                taken.insert(h.clone());
                ev.names.push(h);
            }
        }
        // A name no load claimed and first seen past the last load is checked in the constraint
        // phase: it fills an empty load below, like a name never seen while loading.
        let last_ev = events.iter().map(|ev| ev.pc).max().unwrap_or(-1);
        let any_empty = events.iter().any(|ev| ev.names.is_empty());
        let deferred: HashSet<Rc<str>> = load_names
            .iter()
            .filter(|n| {
                !taken.contains(*n) && load_key(n) > last_ev && !info[*n].codes.iter().any(|&c| c >= 3000) && any_empty
            })
            .cloned()
            .collect();
        for n in &load_names {
            if taken.contains(n) || deferred.contains(n) {
                continue;
            }
            let k = load_key(n);
            match events.iter_mut().filter(|ev| ev.pc <= k).last() {
                Some(ev) => ev.names.push(n.clone()),
                None => events.insert(0, Event { pc: k, callee: None, names: vec![n.clone()], synthetic: true }),
            }
        }
        for ev in events.iter_mut() {
            ev.names.sort_by_key(|n| load_key(n));
        }

        // Names seen only in later checks fill empty loads in check order: Anchor checks fields in order.
        let mut leftovers: Vec<Rc<str>> =
            order.iter().filter(|n| info[*n].load_key.is_none() || deferred.contains(*n)).cloned().collect();
        leftovers.sort_by(|a, b| info[a].check_key.cmp(&info[b].check_key).then(info[a].first_pc.cmp(&info[b].first_pc)));
        let mut leftovers = leftovers.into_iter();
        let mut fields: Vec<Field> = Vec::new();
        for ev in &events {
            if self.composite(ev.callee, depth) {
                // A nested Accounts struct: its fields replace it, and the group's own name is not an account.
                let nested = self.recover(ev.callee.unwrap_or_default(), depth + 1);
                if !nested.is_empty() {
                    fields.extend(nested.iter().cloned().map(Field::Nested));
                    for n in ev.names.iter().skip(1) {
                        fields.push(Field::Named { name: n.clone(), callee: None, position: AccountPosition::Loaded, load_pc: None });
                    }
                    continue;
                }
            }
            let load_pc = (!ev.synthetic).then_some(ev.pc);
            if !ev.names.is_empty() {
                for (k, n) in ev.names.iter().enumerate() {
                    fields.push(Field::Named {
                        name: n.clone(),
                        callee: if k == 0 { ev.callee } else { None },
                        position: AccountPosition::Loaded,
                        load_pc: if k == 0 { load_pc } else { None },
                    });
                }
            } else if let Some(n) = leftovers.next() {
                fields.push(Field::Named { name: n, callee: ev.callee, position: AccountPosition::Matched, load_pc });
            }
        }
        for n in leftovers {
            fields.push(Field::Named { name: n, callee: None, position: AccountPosition::Appended, load_pc: None });
        }

        fields
            .into_iter()
            .map(|f| match f {
                Field::Nested(a) => a,
                Field::Named { name, callee, position, load_pc } => {
                    let codes = info.get(&name).map(|v| v.codes.clone()).unwrap_or_default();
                    let loader = callee.map(|c| self.loader_codes(c)).unwrap_or_default();
                    RecoveredAccount {
                        name: name.to_string(),
                        writable: codes.contains(&CONSTRAINT_MUT) || codes.contains(&CONSTRAINT_MUT_VARIANT),
                        signer: codes.contains(&ACCOUNT_NOT_SIGNER)
                            || codes.contains(&CONSTRAINT_SIGNER)
                            || loader.contains(&ACCOUNT_NOT_SIGNER),
                        position,
                        load_offset: load_pc.and_then(|pc| self.idx(pc)).map(|i| ins[i].file_offset),
                        error_codes: codes.iter().map(|&c| c as u32).collect(),
                        loader_error_codes: loader.iter().map(|&c| c as u32).collect(),
                    }
                }
            })
            .collect()
    }

    /// The `try_accounts` of the instruction whose log string `lddw` at `li` loads.
    fn accounts_check(&self, li: usize) -> Option<i64> {
        let wrap = self.fn_of(self.ins[li].pc)?;
        let wrap_end = *self.end_of.get(&wrap)?;
        // Calls in control-flow order from the log, since handlers that share code jump away from it.
        let after = self.calls_from(li, wrap, wrap_end);
        let mut t = after.iter().copied().find(|&c| self.raises(c, ACCOUNT_NOT_ENOUGH_KEYS, 2));
        // An outlined instruction wrapper (program-id check, decoding, try_accounts, handler, exit)
        // names no accounts and makes one call into a function that does: descend into it. Several
        // such calls make it an Accounts struct built only from nested ones.
        for _ in 0..3 {
            let Some(cur) = t else { break };
            if !self.refs_in(cur).is_empty() {
                break;
            }
            let kids: Vec<i64> = self
                .body(cur)
                .map(|i| self.ins[i])
                .filter(|z| self.is_call(z))
                .map(|z| call_target(&z))
                .filter(|&c| !self.refs_in(c).is_empty() && self.raises(c, ACCOUNT_NOT_ENOUGH_KEYS, 2))
                .collect();
            if kids.len() != 1 {
                break;
            }
            t = Some(kids[0]);
        }
        if t.is_none() {
            // Failing that, the call with the most name references.
            let mut best = 0;
            for &c in &after {
                let n = self.names_in(c).len();
                if n > best {
                    best = n;
                    t = Some(c);
                }
            }
        }
        t
    }
}

/// Account lists keyed by the name in each `Instruction: <Name>` log string the code loads.
/// `None` when that instruction's accounts check could not be located.
pub fn recover(bytes: &[u8]) -> BTreeMap<String, Option<AccountsCheck>> {
    let mut out: BTreeMap<String, Option<AccountsCheck>> = BTreeMap::new();
    let Some(a) = Analyzer::new(bytes) else { return out };
    for li in 0..a.ins.len() {
        let Some(log) = a.rodata_slice(li) else { continue };
        let Some(name) = log.strip_prefix(LOG_PREFIX) else { continue };
        let located = a.accounts_check(li).map(|t| AccountsCheck {
            check_offset: a.idx(t).map_or(0, |i| a.ins[i].file_offset),
            accounts: a.recover(t, 0).as_ref().clone(),
        });
        // A log string loaded from several places yields one entry, a located one when any is.
        match out.get(name) {
            Some(Some(_)) => {}
            Some(None) if located.is_none() => {}
            _ => {
                out.insert(name.to_string(), located);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur3_matches_solana_syscall_hashes() {
        // The hashes sBPF v3 programs carry for these syscalls.
        assert_eq!(murmur3(b"abort"), 0xb6fc_1a11);
        assert_eq!(murmur3(b"sol_log_"), 0x2075_59bd);
    }

    fn insn(pc: i64, op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn { pc, op, dst, src, off, imm, imm64: 0, file_offset: pc as u64 * 8 }
    }

    fn analyzer(ins: Vec<Insn>) -> Analyzer<'static> {
        let n = ins.len();
        Analyzer {
            slot_index: (0..n).collect(),
            ins,
            version: 3,
            rodata: None,
            starts: vec![0],
            end_of: HashMap::from([(0, n as i64)]),
            jumps_to: HashMap::new(),
            syscall_names: HashMap::new(),
            error_ctors: HashSet::new(),
            name_cache: RefCell::new(vec![None; n]),
            names_cache: RefCell::default(),
            refs_cache: RefCell::default(),
            helper_cache: RefCell::default(),
            codes_cache: RefCell::default(),
            no_return_cache: RefCell::default(),
            raises_cache: RefCell::default(),
            reads_cache: RefCell::default(),
            recovered: RefCell::default(),
        }
    }

    #[test]
    fn inline_names_overlap_their_stores() {
        // stw [r1+3], "nker" ; stw [r1+0], "cran" -> "cranker", as sBPF v3 code builds it.
        let a = analyzer(vec![
            insn(0, 0x62, 1, 0, 3, i32::from_le_bytes(*b"nker")),
            insn(1, 0x62, 1, 0, 0, i32::from_le_bytes(*b"cran")),
            insn(2, OP_EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(a.name_at(0).as_deref(), Some("cranker"));
        assert_eq!(a.name_at(1), None, "only the group's first store anchors it");
    }

    #[test]
    fn inline_names_reject_non_identifiers() {
        let a = analyzer(vec![insn(0, 0x62, 1, 0, 0, i32::from_le_bytes(*b"Ab.c")), insn(1, OP_EXIT, 0, 0, 0, 0)]);
        assert_eq!(a.name_at(0), None);
    }

    #[test]
    fn slice_flow_follows_moves_spills_and_calls() {
        // mov r6, r3 ; stxdw [r10-8], r6 ; call 5 ; ldxdw r7, [r10-8] ; exit ; (callee) exit
        let mut a = analyzer(vec![
            insn(0, OP_MOV64_REG, 6, 3, 0, 0),
            insn(1, OP_STXDW, 10, 6, -8, 0),
            insn(2, OP_CALL, 0, 1, 0, 2),
            insn(3, OP_LDXDW, 7, 10, -8, 0),
            insn(4, OP_EXIT, 0, 0, 0, 0),
            insn(5, OP_EXIT, 0, 0, 0, 0),
        ]);
        a.starts = vec![0, 5];
        a.end_of = HashMap::from([(0, 5), (5, 6)]);
        let flow = a.slice_flow(0, 5, 3);
        let at = |i: usize| flow[i].clone().unwrap_or_default();
        assert!(at(2).reg(3) && at(2).reg(6) && at(2).slots.contains(&-8));
        assert!(!at(3).reg(3), "a call clobbers r1..r5");
        assert!(at(3).reg(6), "callee-saved registers survive a call");
        assert!(at(4).reg(7), "a reload from the spill slot holds the slice again");
    }
}
