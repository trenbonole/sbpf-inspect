//! A program as the loader would see it: decoded text, read-only data, and what the loader's
//! relocations make of calls and pointers.
//!
//! The ELF on chain is not relocated yet (v0–v2). The loader rewrites call immediates and
//! pointers when it loads the program, and those rewrites can change what runs, so they are
//! replayed here instead of trusting the raw bytes:
//!
//! * `R_BPF_64_32` on a `call`: a defined function symbol makes it an internal call; any other
//!   symbol makes it a syscall, named by the symbol.
//! * `R_BPF_64_64` on an `lddw`: the value becomes the symbol's address plus the immediate.
//! * `R_BPF_64_RELATIVE` outside the text: the pointer slot gets a program address. On v0 the
//!   loader reads the address from the slot's upper four bytes (an old toolchain quirk Agave
//!   keeps); later versions read all eight.
//!
//! v3 has no relocations: calls with `src = 0` are syscalls by murmur3 hash, `src = 1` relative.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::elf::{self, Elf, ElfError, PF_X, PT_LOAD};
use crate::isa::{self, Insn, Op};
use crate::syscalls;

/// Where the loader maps the program (v0–v2 addresses are relative to it).
pub const MM_PROGRAM_START: u64 = 0x1_0000_0000;
const R_BPF_64_64: u32 = 1;
const R_BPF_64_RELATIVE: u32 = 8;
const R_BPF_64_32: u32 = 10;
/// Most instructions decoded; Solana's largest programs are far below this.
pub const MAX_INSNS: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    /// A function in this program, by instruction index.
    Internal(u32),
    Syscall(&'static str),
    /// A named import that is not a registered syscall.
    Import(String),
    /// A v3 syscall hash that matches no known name.
    UnknownHash(u32),
    Unresolved,
}

pub struct Region<'a> {
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub bytes: &'a [u8],
}

pub struct Program<'a> {
    pub elf: Elf<'a>,
    pub version: u32,
    pub text: &'a [u8],
    pub text_vaddr: u64,
    pub text_file_offset: u64,
    pub data: Vec<Region<'a>>,
    pub insns: Vec<Insn>,
    /// Instruction index per text slot; `u32::MAX` inside an `lddw`.
    pub slot_index: Vec<u32>,
    pub entry: Option<u32>,
    /// Call instruction index -> target.
    pub calls: HashMap<u32, CallTarget>,
    /// Call instruction index -> the symbol name its relocation gives it (v0–v2), including calls
    /// the loader resolves to a function defined in the program, such as `custom_panic`.
    pub call_names: HashMap<u32, String>,
    /// Instruction index -> function symbol name.
    pub symbols: BTreeMap<u32, String>,
    /// `lddw` instruction index -> value after `R_BPF_64_64`.
    pub lddw_values: HashMap<u32, u64>,
    /// Pointer slot address -> address it holds after `R_BPF_64_RELATIVE`.
    pub data_pointers: HashMap<u64, u64>,
    /// `lddw` instructions the loader relocates (their value is an address).
    pub relocated_lddw: HashSet<u32>,
    /// Functions whose address is taken (called through a pointer, e.g. a vtable or callback).
    pub address_taken: BTreeSet<u32>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug)]
pub enum LoadError {
    Elf(ElfError),
    NoText,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Elf(e) => write!(f, "{e}"),
            LoadError::NoText => write!(f, "no .text section or executable segment"),
        }
    }
}

impl<'a> Program<'a> {
    pub fn load(bytes: &'a [u8]) -> Result<Self, LoadError> {
        let elf = Elf::parse(bytes).map_err(LoadError::Elf)?;
        let version = elf.e_flags;
        let mut diagnostics = elf.diagnostics.clone();
        if version > 3 {
            diagnostics.push(format!("e_flags {version}: not a deployable sBPF version; decoded as v3"));
        }

        // Text: the .text section, or (v3 without section headers) the executable segment.
        let (text, text_vaddr, text_file_offset) = if let Some(s) = elf.section(".text") {
            (elf.data(s), s.addr, s.offset)
        } else if let Some(p) = elf.segments.iter().find(|p| p.kind == PT_LOAD && p.flags & PF_X != 0) {
            (elf.segment_data(p), p.vaddr, p.offset)
        } else {
            return Err(LoadError::NoText);
        };
        if text.is_empty() {
            return Err(LoadError::NoText);
        }

        // Read-only data: named data sections, or the non-executable loadable segments.
        let mut data = Vec::new();
        let named: Vec<_> = elf
            .sections
            .iter()
            .filter(|s| (s.name.starts_with(".rodata") || s.name.starts_with(".data")) && s.kind != elf::SHT_NOBITS)
            .collect();
        if !named.is_empty() {
            for s in named {
                data.push(Region { name: s.name.clone(), vaddr: s.addr, file_offset: s.offset, bytes: elf.data(s) });
            }
        } else {
            for p in elf.segments.iter().filter(|p| p.kind == PT_LOAD && p.flags & PF_X == 0) {
                data.push(Region { name: "rodata segment".into(), vaddr: p.vaddr, file_offset: p.offset, bytes: elf.segment_data(p) });
            }
        }

        let decode_version = version.min(3);
        let (insns, slot_index) = isa::decode_all(decode_version, text, MAX_INSNS);
        if insns.len() >= MAX_INSNS {
            diagnostics.push(format!("stopped decoding after {MAX_INSNS} instructions"));
        }
        if text.len() % isa::SLOT != 0 {
            diagnostics.push(format!("text size {} is not a multiple of 8; the last {} bytes are ignored", text.len(), text.len() % 8));
        }

        let mut p = Program {
            elf,
            version,
            text,
            text_vaddr,
            text_file_offset,
            data,
            insns,
            slot_index,
            entry: None,
            calls: HashMap::new(),
            call_names: HashMap::new(),
            symbols: BTreeMap::new(),
            lddw_values: HashMap::new(),
            data_pointers: HashMap::new(),
            relocated_lddw: HashSet::new(),
            address_taken: BTreeSet::new(),
            diagnostics,
        };
        p.entry = p.index_of_vaddr(p.elf.e_entry);
        if p.entry.is_none() {
            p.diagnostics.push(format!("entrypoint {:#x} is not an instruction in the text", p.elf.e_entry));
        }
        p.add_symbols();
        if version < 3 {
            p.apply_relocations();
        } else if !p.elf.relocations().is_empty() {
            p.diagnostics.push("sBPF v3 program carries relocations; the loader rejects these, they are ignored".into());
        }
        p.resolve_remaining_calls();
        p.find_address_taken();
        Ok(p)
    }

    /// Instruction index at a text virtual address.
    pub fn index_of_vaddr(&self, vaddr: u64) -> Option<u32> {
        let rel = vaddr.checked_sub(self.text_vaddr)?;
        if rel % 8 != 0 {
            return None;
        }
        self.index_of_slot(usize::try_from(rel / 8).ok()?)
    }

    pub fn index_of_slot(&self, slot: usize) -> Option<u32> {
        let i = *self.slot_index.get(slot)?;
        (i != u32::MAX).then_some(i)
    }

    /// Byte offset of instruction `i` from the start of the text.
    pub fn text_offset(&self, i: u32) -> u64 {
        self.insns.get(i as usize).map_or(0, |x| x.pc as u64 * 8)
    }

    pub fn file_offset(&self, i: u32) -> u64 {
        self.text_file_offset + self.text_offset(i)
    }

    /// Program addresses of v0–v2 are relative to [`MM_PROGRAM_START`] once loaded.
    pub fn normalize(&self, addr: u64) -> u64 {
        if self.version < 3 && (MM_PROGRAM_START..MM_PROGRAM_START * 2).contains(&addr) { addr - MM_PROGRAM_START } else { addr }
    }

    /// `len` bytes of read-only data at `addr`.
    pub fn read(&self, addr: u64, len: usize) -> Option<&'a [u8]> {
        let addr = self.normalize(addr);
        for r in &self.data {
            if addr >= r.vaddr {
                let start = usize::try_from(addr - r.vaddr).ok()?;
                if start < r.bytes.len() {
                    return r.bytes.get(start..start.checked_add(len)?);
                }
            }
        }
        None
    }

    pub fn region_of(&self, addr: u64) -> Option<&Region<'a>> {
        let addr = self.normalize(addr);
        self.data.iter().find(|r| addr >= r.vaddr && addr - r.vaddr < r.bytes.len() as u64)
    }

    /// The 64-bit pointer stored at `addr`, as the loader leaves it.
    pub fn pointer_at(&self, addr: u64) -> Option<u64> {
        let addr = self.normalize(addr);
        if let Some(&v) = self.data_pointers.get(&addr) {
            return Some(v);
        }
        let b = self.read(addr, 8)?;
        Some(self.normalize(u64::from_le_bytes(b.try_into().ok()?)))
    }

    /// The value an `lddw` loads, after relocation.
    pub fn lddw_value(&self, i: u32) -> Option<u64> {
        if let Some(&v) = self.lddw_values.get(&i) {
            return Some(v);
        }
        match self.insns.get(i as usize)?.op {
            Op::Lddw { imm, .. } => Some(self.normalize(imm)),
            _ => None,
        }
    }

    fn add_symbols(&mut self) {
        let mut syms = self.elf.dynamic_symbols();
        syms.extend(self.elf.static_symbols());
        for s in syms {
            if s.is_function() && s.is_defined() && !s.name.is_empty() {
                if let Some(i) = self.index_of_vaddr(s.value) {
                    self.symbols.entry(i).or_insert(s.name);
                }
            }
        }
    }

    fn apply_relocations(&mut self) {
        let dynsym = self.elf.dynamic_symbols();
        let text_end = self.text_vaddr.saturating_add(self.text.len() as u64);
        let mut unknown: BTreeMap<u32, usize> = BTreeMap::new();
        for r in self.elf.relocations() {
            let in_text = r.offset >= self.text_vaddr && r.offset < text_end;
            let insn = if in_text && (r.offset - self.text_vaddr) % 8 == 0 {
                self.index_of_slot(((r.offset - self.text_vaddr) / 8) as usize)
            } else {
                None
            };
            let sym = dynsym.get(r.sym as usize);
            match r.kind {
                R_BPF_64_32 => {
                    let (Some(i), Some(sym)) = (insn, sym) else { continue };
                    if !matches!(self.insns[i as usize].op, Op::Call { .. }) {
                        continue;
                    }
                    let target = if sym.is_function() && sym.value != 0 {
                        match self.index_of_vaddr(sym.value) {
                            Some(t) => {
                                self.symbols.entry(t).or_insert_with(|| sym.name.clone());
                                CallTarget::Internal(t)
                            }
                            None => CallTarget::Unresolved,
                        }
                    } else {
                        match syscalls::SYSCALLS.iter().find(|(n, _, _)| *n == sym.name) {
                            Some((n, _, _)) => CallTarget::Syscall(n),
                            None => CallTarget::Import(sym.name.clone()),
                        }
                    };
                    if !sym.name.is_empty() {
                        self.call_names.insert(i, sym.name.clone());
                    }
                    self.calls.insert(i, target);
                }
                R_BPF_64_64 => {
                    let (Some(i), Some(sym)) = (insn, sym) else { continue };
                    if let Op::Lddw { imm, .. } = self.insns[i as usize].op {
                        let low = imm & 0xffff_ffff;
                        self.lddw_values.insert(i, self.normalize(sym.value.wrapping_add(low)));
                    }
                }
                R_BPF_64_RELATIVE => {
                    if in_text {
                        // lddw: the immediate already holds the address
                        if let Some(i) = insn {
                            self.relocated_lddw.insert(i);
                        }
                        continue;
                    }
                    let Some(at) = self.elf.file_offset_of(r.offset).and_then(|o| usize::try_from(o).ok()) else { continue };
                    let target = if self.version == 0 {
                        at.checked_add(4).and_then(|a| elf::u32_at(self.elf.bytes, a)).map(u64::from)
                    } else {
                        elf::u64_at(self.elf.bytes, at)
                    };
                    if let Some(t) = target {
                        self.data_pointers.insert(r.offset, self.normalize(t));
                    }
                }
                other => *unknown.entry(other).or_default() += 1,
            }
        }
        for (kind, n) in unknown {
            self.diagnostics.push(format!("{n} relocations of unknown type {kind} ignored"));
        }
    }

    fn resolve_remaining_calls(&mut self) {
        for (i, x) in self.insns.iter().enumerate() {
            let i = i as u32;
            let Op::Call { src, imm } = x.op else { continue };
            if self.calls.contains_key(&i) {
                continue;
            }
            let target = if self.version >= 3 && src == 0 {
                match syscalls::by_hash(imm as u32) {
                    Some(n) => CallTarget::Syscall(n),
                    None => CallTarget::UnknownHash(imm as u32),
                }
            } else if imm == -1 {
                CallTarget::Unresolved
            } else {
                let t = x.pc as i64 + imm as i64 + 1;
                match usize::try_from(t).ok().and_then(|s| self.index_of_slot(s)) {
                    Some(t) => CallTarget::Internal(t),
                    None => CallTarget::Unresolved,
                }
            };
            self.calls.insert(i, target);
        }
    }

    /// Code addresses the program holds as data: function pointers. On v0–v2 only values the
    /// loader relocates count (they are certainly addresses); v3 has no relocations, so aligned
    /// values inside the text's address range count.
    fn find_address_taken(&mut self) {
        let mut found = BTreeSet::new();
        let text_hit = |p: &Program, v: u64| p.index_of_vaddr(v);
        if self.version < 3 {
            for &i in &self.relocated_lddw {
                if let Some(t) = self.lddw_value(i).and_then(|v| text_hit(self, v)) {
                    found.insert(t);
                }
            }
            for &v in self.lddw_values.values() {
                if let Some(t) = text_hit(self, v) {
                    found.insert(t);
                }
            }
            for &v in self.data_pointers.values() {
                if let Some(t) = text_hit(self, v) {
                    found.insert(t);
                }
            }
        } else {
            for x in &self.insns {
                if let Op::Lddw { imm, .. } = x.op {
                    if imm >= self.text_vaddr {
                        if let Some(t) = text_hit(self, imm) {
                            found.insert(t);
                        }
                    }
                }
            }
            for r in &self.data {
                for w in r.bytes.chunks_exact(8) {
                    let v = u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]);
                    if v >= self.text_vaddr && v != 0 {
                        if let Some(t) = text_hit(self, v) {
                            found.insert(t);
                        }
                    }
                }
            }
        }
        self.address_taken = found;
    }

    pub fn call_target(&self, i: u32) -> &CallTarget {
        self.calls.get(&i).unwrap_or(&CallTarget::Unresolved)
    }
}
