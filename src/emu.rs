//! Concrete execution of a program's entrypoint, up to where it holds the instruction data.
//!
//! The loader hands a program one buffer: the accounts, then the instruction data (a u64 length
//! and the bytes), then the program id. Entrypoints decode it with code that differs by framework
//! and version: solana-program's `deserialize` filling a struct on the caller's stack, Pinocchio's
//! inline loop, Anchor's macro around the former. Rather than recognise that code, it is run on a
//! buffer with no accounts and known instruction data. The first time the entry function holds a
//! pointer into the instruction data, in a register or in a stack slot a callee filled, is where
//! an abstract walk can start with the data pointer known (see `args::unnamed`); so is the first
//! call it hands the data to.

use crate::cfg::Cfg;
use crate::isa::{AluOp, Op, Operand};
use crate::program::{CallTarget, Program};

const STACK_START: u64 = 0x2_0000_0000;
const HEAP_START: u64 = 0x3_0000_0000;
const INPUT_START: u64 = 0x4_0000_0000;
const FRAME: u64 = 4096;
/// Call depth the run allows, as the runtime does.
const MAX_FRAMES: usize = 64;
/// Fixed frames are 4 KiB apart with a 4 KiB gap between them.
const STACK_SIZE: u64 = FRAME * 2 * MAX_FRAMES as u64;
const HEAP_SIZE: u64 = 32 * 1024;
/// Length of the instruction data in the run: long enough for any fixed prefix.
const DATA_LEN: u64 = 1024;
/// With no accounts, the data follows the account count and its own length.
const DATA_START: u64 = INPUT_START + 16;
/// Instructions run before giving up: decoding an input without accounts takes a few hundred.
const MAX_STEPS: usize = 200_000;
/// Stack bytes either side of the entry function's `r10` searched for a data pointer.
const SLOT_WINDOW: u64 = 2 * FRAME;

/// Where the entry function holds the instruction data pointer: about to run instruction `at` of
/// function `func`, with `regs` and the stack `slots` (offsets from its `r10`) holding the
/// instruction data's address plus the given amount, and `frame_regs` and `frame_slots` holding
/// addresses on its own stack, as offsets from its `r10` (an out-parameter, or the stack
/// arguments `r5` points to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    pub func: u32,
    pub at: u32,
    pub regs: Vec<(u8, i64)>,
    pub slots: Vec<(i64, i64)>,
    pub frame_regs: Vec<(u8, i64)>,
    pub frame_slots: Vec<(i64, i64)>,
}

struct Machine<'a> {
    p: &'a Program<'a>,
    stack: Vec<u8>,
    heap: Vec<u8>,
    input: Vec<u8>,
    /// Next free heap byte for the `sol_alloc_free_` syscall.
    heap_next: u64,
}

impl Machine<'_> {
    fn region(&mut self, addr: u64, n: u64) -> Option<&mut [u8]> {
        let (buf, base) = match addr {
            a if a >= INPUT_START => (&mut self.input, INPUT_START),
            a if a >= HEAP_START => (&mut self.heap, HEAP_START),
            a if a >= STACK_START => (&mut self.stack, STACK_START),
            _ => return None,
        };
        let start = usize::try_from(addr - base).ok()?;
        buf.get_mut(start..start.checked_add(usize::try_from(n).ok()?)?)
    }

    fn read(&mut self, addr: u64, n: u64) -> Option<u64> {
        if addr < STACK_START {
            // Program memory: pointers as the loader relocated them, other bytes as in the file.
            if n == 8 {
                return self.p.pointer_at(addr);
            }
            let b = self.p.read(addr, n as usize)?;
            let mut v = [0u8; 8];
            v[..b.len()].copy_from_slice(b);
            return Some(u64::from_le_bytes(v));
        }
        let b = self.region(addr, n)?;
        let mut v = [0u8; 8];
        v[..b.len()].copy_from_slice(b);
        Some(u64::from_le_bytes(v))
    }

    fn write(&mut self, addr: u64, n: u64, v: u64) -> Option<()> {
        self.region(addr, n)?.copy_from_slice(&v.to_le_bytes()[..n as usize]);
        Some(())
    }

    fn bytes(&mut self, addr: u64, n: u64) -> Option<Vec<u8>> {
        if addr < STACK_START {
            return self.p.read(addr, usize::try_from(n).ok()?).map(<[u8]>::to_vec);
        }
        self.region(addr, n).map(|b| b.to_vec())
    }

    /// The syscalls an entrypoint may make before the instruction data is reached. `None` stops
    /// the run.
    fn syscall(&mut self, name: &str, r: &mut [u64; 11]) -> Option<()> {
        match name {
            "sol_memcpy_" | "sol_memmove_" => {
                let src = self.bytes(r[2], r[3])?;
                self.region(r[1], r[3])?.copy_from_slice(&src);
            }
            "sol_memset_" => self.region(r[1], r[3])?.fill(r[2] as u8),
            "sol_memcmp_" => {
                let (a, b) = (self.bytes(r[1], r[3])?, self.bytes(r[2], r[3])?);
                let diff = a.iter().zip(&b).find(|(x, y)| x != y).map_or(0, |(x, y)| i32::from(*x) - i32::from(*y));
                self.write(r[4], 4, u64::from(diff as u32))?;
            }
            "sol_alloc_free_" => {
                r[0] = 0;
                if r[2] == 0 {
                    let at = self.heap_next.next_multiple_of(8);
                    if let Some(end) = at.checked_add(r[1]).filter(|&e| e <= HEAP_SIZE) {
                        self.heap_next = end;
                        r[0] = HEAP_START + at;
                    }
                }
                return Some(());
            }
            n if n.starts_with("sol_log") => {}
            _ => return None,
        }
        r[0] = 0;
        Some(())
    }
}

fn alu(version: u32, wide: bool, op: AluOp, d: u64, s: u64) -> Option<u64> {
    match op {
        AluOp::Neg if wide => Some(d.wrapping_neg()),
        AluOp::Neg => Some(u64::from((d as u32).wrapping_neg())),
        // `le`/`be` carry the width in bits as their operand.
        AluOp::Le => match s {
            16 => Some(d & 0xffff),
            32 => Some(d & 0xffff_ffff),
            64 => Some(d),
            _ => None,
        },
        AluOp::Be => match s {
            16 => Some(u64::from((d as u16).swap_bytes())),
            32 => Some(u64::from((d as u32).swap_bytes())),
            64 => Some(d.swap_bytes()),
            _ => None,
        },
        _ => crate::args::compute(version, wide, op, d, s),
    }
}

/// Registers a syscall takes, from r1: those it reads.
fn syscall_arity(name: &str) -> u8 {
    match name {
        "abort" | "sol_log_compute_units_" | "sol_get_stack_height" | "sol_remaining_compute_units" => 0,
        "sol_log_pubkey" => 1,
        n if n.starts_with("sol_get_") && n.ends_with("_sysvar") => 1,
        "sol_log_" | "sol_log_data" | "sol_set_return_data" | "sol_alloc_free_" => 2,
        "sol_memcpy_" | "sol_memmove_" | "sol_memset_" | "sol_get_return_data" | "sol_sha256" | "sol_keccak256" | "sol_blake3" => 3,
        "sol_memcmp_" | "sol_panic_" | "sol_create_program_address" => 4,
        _ => 5,
    }
}

/// Whether function `f` reads register `reg` before writing it on some path from its entry, so
/// takes it as an argument. Calls it makes read only what their callee reads (followed three
/// levels down) or what a syscall takes. Unknown functions and long searches count as reading it.
fn argument(p: &Program, cfg: &Cfg, f: u32, reg: u8) -> bool {
    argument_at(p, cfg, f, reg, 0)
}

fn argument_at(p: &Program, cfg: &Cfg, f: u32, reg: u8, depth: u8) -> bool {
    let Some(func) = cfg.functions.get(&f) else { return true };
    let reads = |at: u32, op: Op| match op {
        Op::Load { src, .. } => src == reg,
        Op::StoreImm { dst, .. } => dst == reg,
        Op::StoreReg { dst, src, .. } => dst == reg || src == reg,
        Op::Alu { op, dst, src, .. } => (op != AluOp::Mov && dst == reg) || src == Operand::Reg(reg),
        Op::Jcond { dst, src, .. } => dst == reg || src == Operand::Reg(reg),
        // A function given its arguments reads them early, not three calls down (an error path
        // formatting a panic, say), so a deeper call counts as not reading.
        Op::Call { .. } if (1..=5).contains(&reg) => match p.call_target(at) {
            CallTarget::Internal(t) => depth < 3 && argument_at(p, cfg, *t, reg, depth + 1),
            CallTarget::Syscall(name) => reg <= syscall_arity(name),
            _ => true,
        },
        Op::Callx { reg: t } => t == reg || (1..=5).contains(&reg),
        Op::Exit => reg == 0,
        _ => false,
    };
    let writes = |op: Op| match op {
        Op::Lddw { dst, .. } | Op::Load { dst, .. } | Op::Alu { dst, .. } => dst == reg,
        Op::Call { .. } | Op::Callx { .. } => reg <= 5,
        _ => false,
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut work = vec![func.entry];
    while let Some(b) = work.pop() {
        if !seen.insert(b) {
            continue;
        }
        if seen.len() > 256 {
            return true;
        }
        let Some(blk) = cfg.blocks.get(b as usize) else { return true };
        let mut written = false;
        for i in blk.start..blk.end {
            let op = p.insns[i as usize].op;
            if reads(i, op) {
                return true;
            }
            if writes(op) {
                written = true;
                break;
            }
        }
        if !written {
            work.extend(blk.succs());
        }
    }
    false
}

/// Run the entrypoint and return where its function holds the instruction data: at the first call
/// it makes that is handed the data, nearest the dispatch, and at the first place it holds a
/// pointer into the data at all, when that is earlier. Both are kept because an entrypoint can
/// peek at the data before it decodes the input (a fast path for one instruction, say), and a walk
/// starting there would have to follow the decoding, which it cannot. Empty when the run reaches
/// neither.
pub fn handovers(p: &Program, cfg: &Cfg) -> Vec<Handover> {
    let mut first = None;
    let call = run(p, cfg, &mut first);
    let mut out: Vec<Handover> = call.into_iter().collect();
    if let Some(h) = first {
        if out.first().is_none_or(|c| c.at != h.at) {
            out.push(h);
        }
    }
    out
}

/// The run behind [`handovers`]: returns the handover at the first call handed the data, after
/// recording the first place the data is held in `first`.
fn run(p: &Program, cfg: &Cfg, first: &mut Option<Handover>) -> Option<Handover> {
    let entry = p.entry?;
    let func = *cfg.functions.range(..=entry).next_back().filter(|(_, f)| f.start == entry)?.0;
    let blocks = &cfg.functions.get(&func)?.blocks;
    // Programs that size their own frames (`add64 r10, imm`) keep `r10` across calls; the others
    // get a fresh fixed frame per call.
    let dynamic = p.insns.iter().any(|x| matches!(x.op, Op::Alu { wide: true, op: AluOp::Add, dst: 10, src: Operand::Imm(_) }));
    let mut input = vec![0u8; (16 + DATA_LEN + 32) as usize];
    input[8..16].copy_from_slice(&DATA_LEN.to_le_bytes());
    let mut m = Machine { p, stack: vec![0; STACK_SIZE as usize], heap: vec![0; HEAP_SIZE as usize], input, heap_next: 0 };
    let mut r = [0u64; 11];
    r[1] = INPUT_START;
    r[10] = if dynamic { STACK_START + STACK_SIZE } else { STACK_START + FRAME };
    let mut frames: Vec<(u32, [u64; 4], u64)> = Vec::new();
    let mut pc = entry;
    let in_data = |v: u64| (DATA_START..DATA_START + DATA_LEN).contains(&v);
    for _ in 0..MAX_STEPS {
        let x = *p.insns.get(pc as usize)?;
        let mut next = pc + 1;
        let jump = |x: &crate::isa::Insn| x.jump_target().and_then(|t| usize::try_from(t).ok()).and_then(|s| p.index_of_slot(s));
        match x.op {
            Op::Lddw { dst, .. } => r[dst as usize] = p.lddw_value(pc)?,
            Op::Load { w, dst, src, off } => r[dst as usize] = m.read(r[src as usize].wrapping_add(off as i64 as u64), u64::from(w.bytes()))?,
            Op::StoreImm { w, dst, off, imm } => m.write(r[dst as usize].wrapping_add(off as i64 as u64), u64::from(w.bytes()), imm as i64 as u64)?,
            Op::StoreReg { w, dst, src, off } => m.write(r[dst as usize].wrapping_add(off as i64 as u64), u64::from(w.bytes()), r[src as usize])?,
            Op::Alu { wide, op, dst, src } => {
                let s = match src {
                    Operand::Imm(i) => i as i64 as u64,
                    Operand::Reg(k) => r[k as usize],
                };
                // v2: `sub` with an immediate computes `imm - dst`.
                let (a, b) = if op == AluOp::Sub && p.version == 2 && matches!(src, Operand::Imm(_)) { (s, r[dst as usize]) } else { (r[dst as usize], s) };
                r[dst as usize] = alu(p.version, wide, op, a, b)?;
            }
            Op::Ja { .. } => next = jump(&x)?,
            Op::Jcond { cond, wide, dst, src, .. } => {
                let s = match src {
                    Operand::Imm(i) => i as i64 as u64,
                    Operand::Reg(k) => r[k as usize],
                };
                if crate::args::holds(cond, wide, r[dst as usize], s) {
                    next = jump(&x)?;
                }
            }
            Op::Call { .. } | Op::Callx { .. } => {
                let target = match (x.op, p.call_target(pc)) {
                    (Op::Callx { reg }, _) => p.index_of_vaddr(p.normalize(r[reg as usize]))?,
                    (_, CallTarget::Internal(t)) => *t,
                    (_, CallTarget::Syscall(name)) => {
                        m.syscall(name, &mut r)?;
                        pc = next;
                        continue;
                    }
                    _ => return None,
                };
                if frames.len() >= MAX_FRAMES - 1 {
                    return None;
                }
                frames.push((next, [r[6], r[7], r[8], r[9]], r[10]));
                if !dynamic {
                    r[10] += 2 * FRAME;
                }
                next = target;
            }
            Op::Exit => {
                let (ret, saved, r10) = frames.pop()?;
                r[6..10].copy_from_slice(&saved);
                r[10] = r10;
                next = ret;
            }
            Op::Invalid { .. } => return None,
        }
        pc = next;
        if !frames.is_empty() {
            continue;
        }
        let regs: Vec<(u8, i64)> = (0..10u8).filter(|&k| in_data(r[k as usize])).map(|k| (k, (r[k as usize] - DATA_START) as i64)).collect();
        let mut slots = Vec::new();
        let mut frame_slots = Vec::new();
        let r10 = r[10];
        let lo = r10.saturating_sub(SLOT_WINDOW).max(STACK_START);
        let hi = (r10 + SLOT_WINDOW).min(STACK_START + STACK_SIZE);
        let in_frame = |v: u64| (lo..hi).contains(&v);
        if r10 % 8 == 0 {
            for a in (lo..hi).step_by(8) {
                let v = m.read(a, 8)?;
                if in_data(v) {
                    slots.push((a as i64 - r10 as i64, (v - DATA_START) as i64));
                } else if in_frame(v) {
                    frame_slots.push((a as i64 - r10 as i64, v as i64 - r10 as i64));
                }
            }
        }
        if regs.is_empty() && slots.is_empty() {
            continue;
        }
        let frame_regs: Vec<(u8, i64)> = (0..10u8).filter(|&k| in_frame(r[k as usize])).map(|k| (k, r[k as usize] as i64 - r10 as i64)).collect();
        let b = *cfg.block_of.get(pc as usize)?;
        if blocks.binary_search(&b).is_err() {
            return None;
        }
        let h = Handover { func, at: pc, regs, slots, frame_regs, frame_slots };
        if first.is_none() {
            *first = Some(h.clone());
        }
        // About to call a function of the program with the data: in r1–r5, in the stack arguments
        // r5 points to, or in a stack struct an argument points to.
        let calls_internal = match p.insns.get(pc as usize).map(|x| x.op) {
            Some(Op::Call { .. }) => matches!(p.call_target(pc), CallTarget::Internal(_)),
            Some(Op::Callx { .. }) => true,
            _ => false,
        };
        let callee = match p.insns.get(pc as usize).map(|x| x.op) {
            Some(Op::Callx { reg }) => p.index_of_vaddr(p.normalize(r[reg as usize])),
            Some(Op::Call { .. }) if calls_internal => match p.call_target(pc) {
                CallTarget::Internal(t) => Some(*t),
                _ => None,
            },
            _ => None,
        };
        if let Some(callee) = callee {
            let mut holds_data = |at: u64| (0..8u64).any(|k| m.read(at.wrapping_add(8 * k), 8).is_some_and(in_data));
            let stack = |v: u64| (STACK_START..STACK_START + STACK_SIZE).contains(&v);
            // Only registers the callee reads before writing are arguments: a register left holding
            // the data by earlier code is not handed on.
            let handed = (1..=5u8).any(|k| {
                let v = r[k as usize];
                argument(p, cfg, callee, k)
                    && (in_data(v) || (k == 5 && v == r10 && holds_data(r10.wrapping_sub(FRAME))) || (stack(v) && v % 8 == 0 && holds_data(v)))
            });
            if handed {
                return Some(h);
            }
        }
    }
    None
}
