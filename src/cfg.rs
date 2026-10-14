//! Basic blocks, functions and their control flow.
//!
//! Blocks split at every leader (function starts, jump targets, and after every branch, call and
//! exit), so a call always ends its block. Functions start at the entrypoint, at every internal
//! call target and at every function symbol; a function's blocks are those reachable from its
//! start without following calls. A function that cannot reach an `exit` never returns, and a
//! call to it ends the path; that is iterated to a fixed point, starting from `abort` and
//! `sol_panic_`.

use std::collections::{BTreeMap, BTreeSet};

use crate::isa::Op;
use crate::program::{CallTarget, Program};
use crate::syscalls;

pub type BlockId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    NoReturnCall,
    Invalid,
    BadTarget,
    OffEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Term {
    Goto(BlockId),
    /// The block's last instruction is a conditional jump.
    Branch { taken: BlockId, fall: BlockId },
    Return,
    Stop(Stop),
}

#[derive(Debug, Clone)]
pub struct Block {
    /// Instruction indexes `[start, end)`.
    pub start: u32,
    pub end: u32,
    pub term: Term,
    pub preds: Vec<BlockId>,
}

impl Block {
    pub fn succs(&self) -> Vec<BlockId> {
        match self.term {
            Term::Goto(b) => vec![b],
            Term::Branch { taken, fall } => {
                if taken == fall { vec![taken] } else { vec![taken, fall] }
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub start: u32,
    pub entry: BlockId,
    /// Sorted by start instruction.
    pub blocks: Vec<BlockId>,
    pub returns: bool,
    pub callers: Vec<u32>,
    /// Its address is taken: it is (also) called through a pointer.
    pub address_taken: bool,
}

pub struct Cfg {
    pub blocks: Vec<Block>,
    /// Instruction index -> block id.
    pub block_of: Vec<BlockId>,
    pub functions: BTreeMap<u32, Function>,
    /// Blocks no function reaches.
    pub unreached: Vec<BlockId>,
    pub truncated: bool,
}

const MAX_FUNCTIONS: usize = 200_000;
const NORETURN_ROUNDS: usize = 32;

fn is_term_op(op: &Op) -> bool {
    matches!(op, Op::Ja { .. } | Op::Jcond { .. } | Op::Exit | Op::Call { .. } | Op::Callx { .. } | Op::Invalid { .. })
}

impl Cfg {
    pub fn build(p: &Program) -> Cfg {
        let n = p.insns.len();
        let mut leaders: BTreeSet<u32> = BTreeSet::new();
        if n > 0 {
            leaders.insert(0);
        }
        let mut starts: BTreeSet<u32> = BTreeSet::new();
        if let Some(e) = p.entry {
            starts.insert(e);
        }
        starts.extend(p.symbols.keys().copied());
        starts.extend(p.address_taken.iter().copied());
        for t in p.calls.values() {
            if let CallTarget::Internal(t) = t {
                starts.insert(*t);
            }
        }
        let mut truncated = false;
        if starts.len() > MAX_FUNCTIONS {
            truncated = true;
            starts = starts.into_iter().take(MAX_FUNCTIONS).collect();
        }
        leaders.extend(starts.iter().copied());
        let target_index = |i: usize| -> Option<u32> {
            let t = p.insns[i].jump_target()?;
            p.index_of_slot(usize::try_from(t).ok()?)
        };
        for (i, x) in p.insns.iter().enumerate() {
            if x.is_branch() {
                if let Some(t) = target_index(i) {
                    leaders.insert(t);
                }
            }
            if is_term_op(&x.op) && i + 1 < n {
                leaders.insert(i as u32 + 1);
            }
        }

        let leaders: Vec<u32> = leaders.into_iter().collect();
        let mut block_of = vec![0u32; n];
        let mut blocks = Vec::with_capacity(leaders.len());
        for (k, &s) in leaders.iter().enumerate() {
            let e = leaders.get(k + 1).copied().unwrap_or(n as u32);
            for i in s..e {
                block_of[i as usize] = k as u32;
            }
            blocks.push(Block { start: s, end: e, term: Term::Stop(Stop::OffEnd), preds: Vec::new() });
        }

        let mut cfg = Cfg { blocks, block_of, functions: BTreeMap::new(), unreached: Vec::new(), truncated };
        // No-return to a fixed point: seed with the no-return syscalls.
        let mut no_return: BTreeSet<u32> = BTreeSet::new();
        for _ in 0..NORETURN_ROUNDS {
            cfg.set_terms(p, &target_index, &no_return);
            let mut next = BTreeSet::new();
            for &s in &starts {
                if !cfg.reaches_return(cfg.block_of[s as usize]) {
                    next.insert(s);
                }
            }
            if next == no_return {
                break;
            }
            no_return = next;
        }
        cfg.set_terms(p, &target_index, &no_return);
        for b in 0..cfg.blocks.len() {
            for s in cfg.blocks[b].succs() {
                cfg.blocks[s as usize].preds.push(b as u32);
            }
        }

        let mut owned = vec![false; cfg.blocks.len()];
        for &s in &starts {
            let entry = cfg.block_of[s as usize];
            let blocks = cfg.reachable(entry);
            for &b in &blocks {
                owned[b as usize] = true;
            }
            cfg.functions.insert(
                s,
                Function {
                    start: s,
                    entry,
                    blocks,
                    returns: !no_return.contains(&s),
                    callers: Vec::new(),
                    address_taken: p.address_taken.contains(&s),
                },
            );
        }
        cfg.unreached = (0..cfg.blocks.len() as u32).filter(|&b| !owned[b as usize]).collect();
        for (i, t) in &p.calls {
            if let CallTarget::Internal(t) = t {
                if let Some(f) = cfg.functions.get_mut(t) {
                    f.callers.push(*i);
                }
            }
        }
        for f in cfg.functions.values_mut() {
            f.callers.sort_unstable();
        }
        cfg
    }

    fn set_terms(&mut self, p: &Program, target_index: &dyn Fn(usize) -> Option<u32>, no_return: &BTreeSet<u32>) {
        let n = p.insns.len() as u32;
        for b in 0..self.blocks.len() {
            let (start, end) = (self.blocks[b].start, self.blocks[b].end);
            if end <= start {
                continue;
            }
            let last = end - 1;
            let next = (end < n).then(|| self.block_of[end as usize]);
            let fall = next.map_or(Term::Stop(Stop::OffEnd), Term::Goto);
            let term = match p.insns[last as usize].op {
                Op::Ja { .. } => target_index(last as usize).map_or(Term::Stop(Stop::BadTarget), |t| Term::Goto(self.block_of[t as usize])),
                Op::Jcond { .. } => match (target_index(last as usize), next) {
                    (Some(t), Some(f)) => Term::Branch { taken: self.block_of[t as usize], fall: f },
                    (Some(t), None) => Term::Goto(self.block_of[t as usize]),
                    (None, _) => Term::Stop(Stop::BadTarget),
                },
                Op::Exit => Term::Return,
                Op::Invalid { .. } => Term::Stop(Stop::Invalid),
                Op::Call { .. } => {
                    let stops = match p.call_target(last) {
                        CallTarget::Syscall(name) => syscalls::NO_RETURN.contains(name),
                        CallTarget::Internal(t) => no_return.contains(t),
                        _ => false,
                    };
                    if stops { Term::Stop(Stop::NoReturnCall) } else { fall }
                }
                _ => fall,
            };
            self.blocks[b].term = term;
        }
    }

    fn reachable(&self, entry: BlockId) -> Vec<BlockId> {
        let mut seen = BTreeSet::from([entry]);
        let mut stack = vec![entry];
        while let Some(b) = stack.pop() {
            for s in self.blocks[b as usize].succs() {
                if seen.insert(s) {
                    stack.push(s);
                }
            }
        }
        seen.into_iter().collect()
    }

    fn reaches_return(&self, entry: BlockId) -> bool {
        let mut seen = BTreeSet::from([entry]);
        let mut stack = vec![entry];
        while let Some(b) = stack.pop() {
            if self.blocks[b as usize].term == Term::Return {
                return true;
            }
            for s in self.blocks[b as usize].succs() {
                if seen.insert(s) {
                    stack.push(s);
                }
            }
        }
        false
    }

}
