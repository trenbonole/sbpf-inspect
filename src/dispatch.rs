//! Native instruction dispatch: `match instruction_data[0] { 0 => …, 1 => …, … }`.
//!
//! Native and Pinocchio programs select an instruction by a tag in the instruction data (a byte,
//! or a little-endian integer for bincode). The compiler turns the `match` into a tree of compares
//! (sBPF has no jump tables), often after arithmetic on the tag (packing it into a `Result`, say).
//! So each candidate tag load is executed concretely for every value 0–255: registers derived
//! from the tag hold exact values, everything else is unknown, and a path stops at the first call,
//! exit, or branch on an unknown value. The block where it stops is that tag's handler. A load
//! whose values reach at least three different handlers is a dispatch. Handlers are named by the
//! first `Instruction: <Name>` log they reach (following calls two levels down, never into another
//! handler or the switch itself), when the program logs one.

use std::collections::{BTreeMap, HashSet, VecDeque};

use serde::Serialize;

use crate::cfg::{BlockId, Cfg};
use crate::isa::{AluOp, Cond, Op, Operand, Width};
use crate::program::{CallTarget, Program};
use crate::literals::Literals;

const MAX_PATH: usize = 400;
const MIN_TAGS: usize = 3;
const NAME_SEARCH_BLOCKS: usize = 400;
const MAX_CANDIDATES: usize = 50_000;

#[derive(Debug, Serialize, Clone)]
pub struct Handler {
    /// The tag values that reach this code.
    pub tags: Vec<u8>,
    /// Text offset where the handler's code starts.
    pub offset: u64,
    /// From the first `Instruction: <Name>` log the handler reaches, when there is one.
    pub log_name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Dispatch {
    /// Text offset of the load of the tag the dispatch switches on.
    pub tag_load_offset: u64,
    /// Width of the tag load in bytes (1 for a byte tag, 4 for bincode's u32).
    pub tag_width: u32,
    /// Handlers reached by exactly one tag value.
    pub single_tag_handlers: usize,
    pub handlers: Vec<Handler>,
    /// Tag values that reach code shared by many values (usually "invalid instruction").
    pub other_tags: usize,
}

fn holds(cond: Cond, wide: bool, a: u64, b: u64) -> bool {
    let (a, b) = if wide { (a, b) } else { (a & 0xffff_ffff, b & 0xffff_ffff) };
    let (sa, sb) = if wide { (a as i64, b as i64) } else { (a as u32 as i32 as i64, b as u32 as i32 as i64) };
    match cond {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Gt => a > b,
        Cond::Ge => a >= b,
        Cond::Lt => a < b,
        Cond::Le => a <= b,
        Cond::Sgt => sa > sb,
        Cond::Sge => sa >= sb,
        Cond::Slt => sa < sb,
        Cond::Sle => sa <= sb,
        Cond::Set => a & b != 0,
    }
}

/// One ALU step on known values, with the loader's semantics for `version` (see `lift.rs`).
fn alu(version: u32, wide: bool, op: AluOp, d: u64, s: u64) -> Option<u64> {
    let v2 = version == 2;
    if wide {
        return Some(match op {
            AluOp::Mov => s,
            AluOp::Add => d.wrapping_add(s),
            AluOp::Sub => d.wrapping_sub(s),
            AluOp::Mul | AluOp::Lmul => d.wrapping_mul(s),
            AluOp::Div | AluOp::Udiv => d.checked_div(s)?,
            AluOp::Mod | AluOp::Urem => d.checked_rem(s)?,
            AluOp::Or => d | s,
            AluOp::And => d & s,
            AluOp::Xor => d ^ s,
            AluOp::Lsh => d.wrapping_shl(s as u32),
            AluOp::Rsh => d.wrapping_shr(s as u32),
            AluOp::Arsh => (d as i64).wrapping_shr(s as u32) as u64,
            AluOp::Neg => d.wrapping_neg(),
            AluOp::Hor => d | (s << 32),
            _ => return None,
        });
    }
    let (d32, s32) = (d as u32, s as u32);
    let sext = |v: u32| if v2 { v as u64 } else { v as i32 as i64 as u64 };
    Some(match op {
        AluOp::Mov => s32 as u64,
        AluOp::Add => sext(d32.wrapping_add(s32)),
        AluOp::Sub => sext(d32.wrapping_sub(s32)),
        AluOp::Mul | AluOp::Lmul => sext(d32.wrapping_mul(s32)),
        AluOp::Div | AluOp::Udiv => d32.checked_div(s32)? as u64,
        AluOp::Mod | AluOp::Urem => d32.checked_rem(s32)? as u64,
        AluOp::Or => (d32 | s32) as u64,
        AluOp::And => (d32 & s32) as u64,
        AluOp::Xor => (d32 ^ s32) as u64,
        AluOp::Lsh => d32.wrapping_shl(s32) as u64,
        AluOp::Rsh => d32.wrapping_shr(s32) as u64,
        AluOp::Arsh => (d32 as i32).wrapping_shr(s32) as u32 as u64,
        AluOp::Neg => (d32 as i32).wrapping_neg() as u32 as u64,
        _ => return None,
    })
}

fn target(p: &Program, x: &crate::isa::Insn) -> Option<u32> {
    x.jump_target().and_then(|t| usize::try_from(t).ok()).and_then(|s| p.index_of_slot(s))
}

/// Execute from the instruction after the tag load at `i`, with the tag register `reg` = `v`.
/// Returns the block where the path stops; `trail` gets the blocks it passed through.
fn run(p: &Program, cfg: &Cfg, i: u32, reg: u8, v: u64, trail: &mut Vec<BlockId>) -> Option<BlockId> {
    let mut regs: [Option<u64>; 11] = [None; 11];
    regs[reg as usize] = Some(v);
    let mut pc = i + 1;
    let mut stop_block = cfg.block_of[i as usize];
    for _ in 0..MAX_PATH {
        let x = p.insns.get(pc as usize)?;
        let b = cfg.block_of[pc as usize];
        if cfg.blocks[b as usize].start == pc {
            trail.push(b);
            stop_block = b;
        }
        let operand = |o: Operand, regs: &[Option<u64>; 11]| match o {
            Operand::Imm(n) => Some(n as i64 as u64),
            Operand::Reg(r) => regs[r as usize],
        };
        match x.op {
            Op::Alu { wide, op, dst, src } => {
                let s = operand(src, &regs);
                regs[dst as usize] = match (op, regs[dst as usize], s) {
                    (AluOp::Mov, _, Some(s)) => alu(p.version, wide, op, 0, s),
                    // v2: `sub` with an immediate is `imm - dst`.
                    (AluOp::Sub, Some(d), Some(s)) if p.version == 2 && matches!(src, Operand::Imm(_)) => alu(p.version, wide, op, s, d),
                    (_, Some(d), Some(s)) => alu(p.version, wide, op, d, s),
                    _ => None,
                };
            }
            Op::Lddw { dst, .. } => regs[dst as usize] = p.lddw_value(pc),
            Op::Load { dst, .. } => regs[dst as usize] = None,
            Op::StoreImm { .. } | Op::StoreReg { .. } => {}
            Op::Ja { .. } => {
                pc = target(p, x)?;
                continue;
            }
            Op::Jcond { cond, wide, dst, src, .. } => {
                let (Some(a), Some(c)) = (regs[dst as usize], operand(src, &regs)) else { return Some(stop_block) };
                pc = if holds(cond, wide, a, c) { target(p, x)? } else { pc + 1 };
                continue;
            }
            Op::Call { .. } | Op::Callx { .. } | Op::Exit | Op::Invalid { .. } => return Some(stop_block),
        }
        pc += 1;
    }
    Some(stop_block)
}

/// The first `Instruction: <Name>` string reachable from block `b`, following calls two levels
/// down, without entering `avoid` (the switch and the other handlers).
fn log_name(p: &Program, cfg: &Cfg, literals: &Literals, b: BlockId, avoid: &HashSet<BlockId>) -> Option<String> {
    let mut seen: HashSet<BlockId> = HashSet::from([b]);
    let mut queue: VecDeque<(BlockId, u8)> = VecDeque::from([(b, 0)]);
    while let Some((x, depth)) = queue.pop_front() {
        if seen.len() > NAME_SEARCH_BLOCKS {
            break;
        }
        let blk = &cfg.blocks[x as usize];
        for i in blk.start..blk.end {
            if let Some(s) = literals.code_slices.get(&i).and_then(|a| literals.strings.get(a)) {
                if let Some(name) = s.text.strip_prefix("Instruction: ") {
                    let name: String = name.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            if depth < 2 {
                if let (Op::Call { .. }, CallTarget::Internal(t)) = (p.insns[i as usize].op, p.call_target(i)) {
                    let entry = cfg.block_of[*t as usize];
                    if seen.insert(entry) {
                        queue.push_back((entry, depth + 1));
                    }
                }
            }
        }
        for s in blk.succs() {
            if !avoid.contains(&s) && seen.insert(s) {
                queue.push_back((s, depth));
            }
        }
    }
    None
}

/// The program's instruction dispatch, if it has a native one: the switch whose handlers log the
/// most distinct instruction names, then the one with the most single-tag handlers.
pub fn recover(p: &Program, cfg: &Cfg, literals: &Literals) -> Option<Dispatch> {
    let mut best: Option<((usize, usize), Dispatch)> = None;
    let mut tried = 0usize;
    let mut trail = Vec::new();
    for (i, x) in p.insns.iter().enumerate() {
        let Op::Load { w: w @ (Width::B | Width::H | Width::W), dst, .. } = x.op else { continue };
        if tried >= MAX_CANDIDATES {
            break;
        }
        tried += 1;
        let i = i as u32;
        // Cheap check: three tag values that all stop in the same place mean no switch here.
        let probe: Vec<Option<BlockId>> = [0u64, 1, 2].iter().map(|&v| run(p, cfg, i, dst, v, &mut Vec::new())).collect();
        if probe[0] == probe[1] && probe[1] == probe[2] {
            continue;
        }
        let mut leaves: BTreeMap<BlockId, Vec<u8>> = BTreeMap::new();
        let mut tree: HashSet<BlockId> = HashSet::new();
        for v in 0..=255u64 {
            trail.clear();
            if let Some(b) = run(p, cfg, i, dst, v, &mut trail) {
                leaves.entry(b).or_default().push(v as u8);
                tree.extend(trail.iter().copied().filter(|t| *t != b));
            }
        }
        let singles = leaves.values().filter(|t| t.len() == 1).count();
        if singles < MIN_TAGS {
            continue;
        }
        let leaf_blocks: HashSet<BlockId> = leaves.keys().copied().collect();
        let mut handlers = Vec::new();
        let mut other = 0;
        for (b, tags) in &leaves {
            if tags.len() > 8 {
                other += tags.len();
                continue;
            }
            let mut avoid: HashSet<BlockId> = leaf_blocks.iter().copied().filter(|x| x != b).collect();
            avoid.extend(tree.iter().copied());
            handlers.push(Handler {
                tags: tags.clone(),
                offset: p.text_offset(cfg.blocks[*b as usize].start),
                log_name: log_name(p, cfg, literals, *b, &avoid),
            });
        }
        handlers.sort_by_key(|h| h.tags.first().copied());
        let named: HashSet<&str> = handlers.iter().filter_map(|h| h.log_name.as_deref()).collect();
        let score = (named.len(), singles);
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((
                score,
                Dispatch { tag_load_offset: p.text_offset(i), tag_width: w.bytes(), single_tag_handlers: singles, handlers, other_tags: other },
            ));
        }
    }
    best.map(|(_, d)| d)
}
