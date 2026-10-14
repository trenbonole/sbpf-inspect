//! Tests on small ELFs assembled here, plus a mutation fuzzer.

use std::collections::BTreeMap;

use crate::cfg::Cfg;
use crate::constants::ByteCompares;
use crate::program::{CallTarget, Program};
use crate::syscalls::murmur3;
use crate::inspect;

const R_BPF_64_RELATIVE: u32 = 8;
const R_BPF_64_32: u32 = 10;

pub fn ins(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let o = off.to_le_bytes();
    let i = imm.to_le_bytes();
    [op, dst | (src << 4), o[0], o[1], i[0], i[1], i[2], i[3]]
}

pub fn lddw(dst: u8, v: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&ins(0x18, dst, 0, 0, v as u32 as i32));
    b[12..16].copy_from_slice(&((v >> 32) as u32).to_le_bytes());
    b
}

#[derive(Default)]
pub struct Builder {
    pub version: u32,
    pub text: Vec<u8>,
    pub rodata: Vec<u8>,
    pub relro: Vec<u8>,
    /// (name, st_info, defined-in-text, value as text offset)
    pub syms: Vec<(String, u8, bool, u64)>,
    /// (offset within section, section: 't' text / 'r' relro, kind, symbol index)
    pub rels: Vec<(u64, char, u32, u32)>,
    pub entry: u64,
}

fn align8(v: &mut Vec<u8>) {
    while v.len() % 8 != 0 {
        v.push(0);
    }
}

impl Builder {
    pub fn text(mut self, insns: &[&[u8]]) -> Self {
        for i in insns {
            self.text.extend_from_slice(i);
        }
        self
    }

    /// Section addresses equal file offsets, as in v0 programs.
    pub fn build(&self) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let text_off = out.len() as u64;
        out.extend_from_slice(&self.text);
        align8(&mut out);
        let ro_off = out.len() as u64;
        out.extend_from_slice(&self.rodata);
        align8(&mut out);
        let relro_off = out.len() as u64;
        out.extend_from_slice(&self.relro);
        align8(&mut out);
        // .dynstr / .dynsym
        let mut dynstr = vec![0u8];
        let mut dynsym = vec![0u8; 24];
        for (name, info, defined, value) in &self.syms {
            let name_off = dynstr.len() as u32;
            dynstr.extend_from_slice(name.as_bytes());
            dynstr.push(0);
            let mut e = [0u8; 24];
            e[0..4].copy_from_slice(&name_off.to_le_bytes());
            e[4] = *info;
            e[6..8].copy_from_slice(&(if *defined { 1u16 } else { 0 }).to_le_bytes());
            let v = if *defined { text_off + value } else { 0 };
            e[8..16].copy_from_slice(&v.to_le_bytes());
            dynsym.extend_from_slice(&e);
        }
        let dynsym_off = out.len() as u64;
        out.extend_from_slice(&dynsym);
        let dynstr_off = out.len() as u64;
        out.extend_from_slice(&dynstr);
        align8(&mut out);
        let rel_off = out.len() as u64;
        for (o, sec, kind, sym) in &self.rels {
            let base = if *sec == 't' { text_off } else { relro_off };
            out.extend_from_slice(&(base + o).to_le_bytes());
            out.extend_from_slice(&((u64::from(*sym) << 32) | u64::from(*kind)).to_le_bytes());
        }
        let rel_len = out.len() as u64 - rel_off;
        let names = b"\0.text\0.rodata\0.data.rel.ro\0.dynsym\0.dynstr\0.rel.dyn\0.shstrtab\0";
        let shstr_off = out.len() as u64;
        out.extend_from_slice(names);
        align8(&mut out);
        let shoff = out.len() as u64;
        let name_at = |n: &str| -> u32 {
            let needle = format!("{n}\0");
            names.windows(needle.len()).position(|w| w == needle.as_bytes()).unwrap() as u32
        };
        let mut sh = |name: u32, kind: u32, addr_off: u64, size: u64, link: u32, entsize: u64| {
            let mut e = [0u8; 64];
            e[0..4].copy_from_slice(&name.to_le_bytes());
            e[4..8].copy_from_slice(&kind.to_le_bytes());
            e[16..24].copy_from_slice(&addr_off.to_le_bytes());
            e[24..32].copy_from_slice(&addr_off.to_le_bytes());
            e[32..40].copy_from_slice(&size.to_le_bytes());
            e[40..44].copy_from_slice(&link.to_le_bytes());
            e[56..64].copy_from_slice(&entsize.to_le_bytes());
            out.extend_from_slice(&e);
        };
        sh(0, 0, 0, 0, 0, 0);
        sh(name_at(".text"), 1, text_off, self.text.len() as u64, 0, 0);
        sh(name_at(".rodata"), 1, ro_off, self.rodata.len() as u64, 0, 0);
        sh(name_at(".data.rel.ro"), 1, relro_off, self.relro.len() as u64, 0, 0);
        sh(name_at(".dynsym"), 11, dynsym_off, dynsym.len() as u64, 5, 24);
        sh(name_at(".dynstr"), 3, dynstr_off, dynstr.len() as u64, 0, 0);
        sh(name_at(".rel.dyn"), 9, rel_off, rel_len, 4, 16);
        sh(name_at(".shstrtab"), 3, shstr_off, names.len() as u64, 0, 0);
        // ELF header
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        out[16..18].copy_from_slice(&3u16.to_le_bytes());
        out[18..20].copy_from_slice(&247u16.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..32].copy_from_slice(&(text_off + self.entry).to_le_bytes());
        out[40..48].copy_from_slice(&shoff.to_le_bytes());
        out[48..52].copy_from_slice(&self.version.to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes());
        out[58..60].copy_from_slice(&64u16.to_le_bytes());
        out[60..62].copy_from_slice(&8u16.to_le_bytes());
        out[62..64].copy_from_slice(&7u16.to_le_bytes());
        out
    }

    pub fn rodata_addr(&self) -> u64 {
        let t = 64 + self.text.len() as u64;
        t.div_ceil(8) * 8
    }

    pub fn relro_addr(&self) -> u64 {
        let r = self.rodata_addr() + self.rodata.len() as u64;
        r.div_ceil(8) * 8
    }
}

const FUNC: u8 = 0x12; // STB_GLOBAL | STT_FUNC
const NOTYPE: u8 = 0x10;

/// A v0 program: entrypoint calls `sol_log_` (relocated syscall) and `helper` (relocated defined
/// function), loads a string and a panic location, and a pointer slot uses the v0 quirk.
fn sample_v0() -> Builder {
    let mut b = Builder { version: 0, rodata: b"hellosrc/lib.rs\0".to_vec(), entry: 0, ..Default::default() };
    let ro = b.rodata_addr_for_text_len(10 * 8);
    let relro = (ro + 16).div_ceil(8) * 8;
    b = b.text(&[
        &lddw(1, ro),                    // 0: lddw r1, "hello"
        &ins(0xb7, 2, 0, 0, 5),          // 2: mov r2, 5
        &ins(0x85, 0, 0, 0, -1),         // 3: call sol_log_ (relocated)
        &ins(0x85, 0, 0, 0, -1),         // 4: call helper (relocated)
        &lddw(1, relro),                 // 5: lddw r1, &Location
        &ins(0xb7, 0, 0, 0, 0),          // 7: mov r0, 0
        &ins(0x95, 0, 0, 0, 0),          // 8: exit
        &ins(0x95, 0, 0, 0, 0),          // 9: helper: exit
    ]);
    // Location { file: &str (pointer slot, v0 quirk: address in the upper 4 bytes), len, line, col }
    let mut slot = [0u8; 8];
    slot[4..8].copy_from_slice(&((ro + 5) as u32).to_le_bytes());
    b.relro.extend_from_slice(&slot);
    b.relro.extend_from_slice(&10u64.to_le_bytes());
    b.relro.extend_from_slice(&42u32.to_le_bytes());
    b.relro.extend_from_slice(&7u32.to_le_bytes());
    // A second location, as newer toolchains emit it: the file name's length counts a trailing NUL.
    let mut slot2 = [0u8; 8];
    slot2[4..8].copy_from_slice(&((ro + 5) as u32).to_le_bytes());
    b.relro.extend_from_slice(&slot2);
    b.relro.extend_from_slice(&11u64.to_le_bytes());
    b.relro.extend_from_slice(&9u32.to_le_bytes());
    b.relro.extend_from_slice(&3u32.to_le_bytes());
    b.syms = vec![("sol_log_".into(), NOTYPE, false, 0), ("helper".into(), FUNC, true, 9 * 8), ("entrypoint".into(), FUNC, true, 0)];
    b.rels = vec![(3 * 8, 't', R_BPF_64_32, 1), (4 * 8, 't', R_BPF_64_32, 2), (0, 'r', R_BPF_64_RELATIVE, 0), (24, 'r', R_BPF_64_RELATIVE, 0)];
    b
}

impl Builder {
    fn rodata_addr_for_text_len(&self, text_len: usize) -> u64 {
        (64 + text_len as u64).div_ceil(8) * 8
    }
}


#[test]
fn relocations_resolve_calls_symbols_and_pointers() {
    let b = sample_v0();
    let elf = b.build();
    let p = Program::load(&elf).expect("loads");
    assert_eq!(p.version, 0);
    // Instruction indexes: the lddw at slot 0 takes two slots, so the calls at slots 3 and 4 are 2 and 3.
    assert_eq!(p.call_target(2), &CallTarget::Syscall("sol_log_"));
    let helper = p.index_of_slot(9).unwrap();
    assert_eq!(p.call_target(3), &CallTarget::Internal(helper));
    assert_eq!(p.symbols.get(&helper).map(String::as_str), Some("helper"));
    assert_eq!(p.call_names.get(&3).map(String::as_str), Some("helper"));
    // v0 quirk: the pointer comes from the slot's upper four bytes.
    assert_eq!(p.pointer_at(b.relro_addr()), Some(b.rodata_addr() + 5));
}

#[test]
fn strings_and_panic_locations_are_recovered() {
    let b = sample_v0();
    let elf = b.build();
    let p = Program::load(&elf).unwrap();
    let s = crate::literals::recover(&p);
    assert_eq!(s.strings.get(&b.rodata_addr()).map(|x| x.text.as_str()), Some("hello"));
    let loc = s.locations.get(&b.relro_addr()).expect("location found");
    assert_eq!((loc.file.as_str(), loc.line, loc.col), ("src/lib.rs", 42, 7));
    assert_eq!(loc.referenced_by, vec![4]);
    let nul = s.locations.get(&(b.relro_addr() + 24)).expect("NUL-terminated location found");
    assert_eq!((nul.file.as_str(), nul.line, nul.col), ("src/lib.rs", 9, 3));
    let r = inspect(&elf).expect("inspects");
    assert!(r.panic_locations.iter().any(|l| l.file == "src/lib.rs" && l.line == 42 && l.col == 7));
    let calls: Vec<&str> = r.syscalls.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(calls, ["helper", "sol_log_"], "relocation names are reported, a defined function as not registered");
}

#[test]
fn v3_static_syscalls_and_no_return_propagation() {
    // f0: jeq r1, 0, +2 ; call f1 (src=1, relative) ; exit ; mov r0, 1 ; exit
    // f1: call abort (src=0, murmur3 hash) -> f1 never returns, so the block after `call f1` ends.
    let b = Builder { version: 3, ..Default::default() }.text(&[
        &ins(0x15, 1, 0, 2, 0),
        &ins(0x85, 0, 1, 0, 3),
        &ins(0x95, 0, 0, 0, 0),
        &ins(0xb7, 0, 0, 0, 1),
        &ins(0x95, 0, 0, 0, 0),
        &ins(0x85, 0, 0, 0, murmur3(b"abort") as i32),
    ]);
    let elf = b.build();
    let p = Program::load(&elf).unwrap();
    assert_eq!(p.call_target(5), &CallTarget::Syscall("abort"));
    assert_eq!(p.call_target(1), &CallTarget::Internal(5));
    let cfg = Cfg::build(&p);
    assert_eq!(cfg.functions.len(), 2);
    assert!(!cfg.functions[&5].returns, "f1 only aborts");
    assert!(cfg.functions[&0].returns);
}

/// A dispatcher with one instruction whose `u64` argument is added to: `data` arrives in r1.
fn dispatcher(disc: u64) -> Vec<u8> {
    Builder { version: 0, ..Default::default() }
        .text(&[
            &ins(0x79, 2, 1, 0, 0),  // 0: ldxdw r2, [r1+0]   the discriminator
            &lddw(3, disc),          // 1: lddw r3, DISC
            &ins(0x5d, 2, 3, 3, 0),  // 3: jne r2, r3, +3 -> 7
            &ins(0x79, 4, 1, 8, 0),  // 4: ldxdw r4, [r1+8]   the argument
            &ins(0x07, 4, 0, 0, 1),  // 5: add r4, 1          used
            &ins(0x95, 0, 0, 0, 0),  // 6: exit
            &ins(0xb7, 0, 0, 0, 1),  // 7: mov r0, 1
            &ins(0x95, 0, 0, 0, 0),  // 8: exit
        ])
        .build()
}

#[test]
fn argument_layout_follows_the_matching_dispatch() {
    let disc = 0x1122_3344_5566_7788u64;
    let elf = dispatcher(disc);
    let p = Program::load(&elf).unwrap();
    let cfg = Cfg::build(&p);
    let chains = ByteCompares::scan(p.text, p.text_file_offset);
    let names = BTreeMap::from([("deposit".to_string(), (disc, Vec::new())), ("other".to_string(), (disc ^ 1, Vec::new()))]);
    let (layouts, exhausted) = crate::args::recover(&p, &cfg, &chains, &names);
    assert!(!exhausted);
    let deposit = layouts.get("deposit").expect("its dispatch is walked");
    assert_eq!(deposit.fields.iter().map(|f| (f.offset, f.size, f.copied)).collect::<Vec<_>>(), [(0, 8, false)]);
    assert_eq!(deposit.fixed_size, 8);
    assert!(deposit.complete && !deposit.irregular && !deposit.truncated);
    assert!(!layouts.contains_key("other"), "a discriminator the code never tests has no dispatch to walk");
}

/// xorshift64*: deterministic, so a failure reproduces.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn mutated_programs_never_panic() {
    let base = sample_v0().build();
    let v3 = Builder { version: 3, ..Default::default() }.text(&[&ins(0x85, 0, 1, 0, 1), &ins(0x95, 0, 0, 0, 0), &ins(0x95, 0, 0, 0, 0)]).build();
    let anchorish = dispatcher(0x1122_3344_5566_7788);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..3000 {
        let mut b = match round % 3 {
            0 => base.clone(),
            1 => v3.clone(),
            _ => anchorish.clone(),
        };
        let edits = 1 + (rng.next() % 24) as usize;
        for _ in 0..edits {
            let at = (rng.next() as usize) % b.len();
            b[at] = match rng.next() % 4 {
                0 => 0xff,
                1 => 0,
                _ => rng.next() as u8,
            };
        }
        if rng.next() % 5 == 0 {
            let cut = (rng.next() as usize) % b.len();
            b.truncate(cut);
        }
        // Must return Ok or Err, never panic (overflow checks are on in tests).
        let _ = inspect(&b);
    }
    for len in [0usize, 1, 63, 64, 65, 200, 4096] {
        let junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = inspect(&junk);
    }
}
