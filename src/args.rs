//! Instruction argument layouts of Anchor programs, inferred from how the code reads its
//! instruction data.
//!
//! Anchor dispatches on the first 8 bytes of the instruction data and decodes the rest with Borsh,
//! field by field. So the layout of an instruction's arguments is visible as the reads its code
//! path makes from "instruction data + k" (k >= 8) once its discriminator has matched.
//!
//! The walk is an abstract interpretation that knows the discriminator being dispatched. The first
//! 8 data bytes read as that discriminator's bytes, so every comparison in the dispatch is decided
//! and the walk follows only the path that instruction takes, whatever the dispatch's shape: one
//! 64-bit compare, a binary search, older Anchor's byte-by-byte decision tree, or `sol_memcmp_`
//! against a copy in read-only data. The data pointer is followed through registers, 8-byte stack
//! slots, `memcpy` and calls (four levels down, including arguments passed on the caller's stack).
//!
//! The walk starts where the data pointer comes from, found by searching back along the control
//! flow, not at the comparison: the dispatch often computes `data + 8` and loads the discriminator
//! bytes before its first comparison, and starting later would lose them. Each place the code tests
//! this discriminator (a 64-bit constant, a byte chain, a read-only copy) gives one start; a start
//! counts only when its walk decided all 8 discriminator bytes, and the one whose walk found the
//! most fields is kept. That also skips places that test a discriminator for another purpose, such
//! as an instruction gate.
//!
//! Values loaded from the data keep, byte by byte, which data bytes they hold, through shifts, ORs
//! and masks (how unaligned values are assembled) and through stack copies at any alignment. A
//! value the code computes with, compares, or hands to a function is a field with the bounds of
//! that value. Data only moved to the stack and never used on the walk is reported from its copies
//! and marked `copied`, since a copy's pieces are how the compiler split the move, not fields.
//!
//! Calls return what they leave in memory, so a deserializer filling an out-parameter or advancing
//! a `&mut &[u8]` cursor is seen by its caller. Where paths meet, a data pointer that advanced
//! further wins, since a decoder advances only on success; numbers written on one path only never
//! decide a later branch.
//!
//! The result is offsets and sizes, not names or types: a 1-byte field may be a `u8` or a `bool`,
//! and two 8-byte reads may be one `u128`. Variable-length values (vectors, strings, options) end
//! the layout, since their contents are read at offsets the walk cannot know. `complete` says
//! whether the data went anywhere the walk does not follow.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::cfg::{BlockId, Cfg, Term};
use crate::constants::ByteCompares;
use crate::isa::{AluOp, Cond, Op, Operand, Width};
use crate::program::{CallTarget, Program};
use crate::report::{ArgumentField, ArgumentLayout};

/// Call levels followed below the dispatching function.
const MAX_DEPTH: u8 = 4;
/// Instructions interpreted for one start.
const WALK_BUDGET: usize = 4_000_000;
/// Instructions interpreted for one program, over all instructions and starts.
const PROGRAM_BUDGET: usize = 1_500_000_000;
/// Instructions interpreted for one guessed start (see [`Guess`]).
const GUESS_BUDGET: usize = 600_000;
/// Starts tried for one instruction.
const MAX_STARTS: usize = 8;
/// Instructions searched back for the definition of the data pointer.
const TRACE_WINDOW: usize = 600;
/// Largest `memcpy` whose bytes are modelled one by one.
const MAX_COPY: u64 = 64;
/// Constants tried as unnamed discriminators.
const MAX_ID_CANDIDATES: usize = 1024;
/// Instructions interpreted for all of them together.
const UNNAMED_BUDGET: usize = 400_000_000;
/// Walks spent discovering discriminators byte by byte from one start, the instructions one of
/// them may interpret, and the instructions all of them may (the rest of [`UNNAMED_BUDGET`] is
/// for confirming what they found).
const MAX_DISCOVERY_WALKS: usize = 1024;
const DISCOVERY_WALK_BUDGET: usize = 500_000;
const DISCOVERY_BUDGET: usize = 30_000_000;

/// An abstract value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum V {
    Unknown,
    Const(u64),
    /// A pointer: instruction data + k.
    Data(i64),
    /// A stack address: frame id + offset from that frame's `r10`.
    Frame(u32, i64),
    /// A value computed from discriminator bytes (bit k of the mask: byte k took part).
    Disc(u64, u8),
    /// A value made of instruction data bytes, byte by byte (least significant first): loaded from
    /// the data, or assembled from several loads with shifts and ORs.
    Mix([Px; 8]),
}

/// One byte of a [`V::Mix`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Px {
    Unknown,
    Zero,
    /// Instruction data byte k.
    Data(i64),
    /// Discriminator byte k (the second number), holding the first number: how the walks that find
    /// unnamed discriminators see them, so a value split off by shifts and masks names exactly the
    /// bytes it holds.
    Disc(u8, u8),
}

/// The value a load of data bytes `[k, k + w)` gives (zero-extended).
fn loaded(k: i64, w: u32) -> V {
    V::Mix(std::array::from_fn(|i| if (i as u32) < w { Px::Data(k + i as i64) } else { Px::Zero }))
}

/// The bytes of `v` as a [`V::Mix`] sees them: only the instruction data's bytes and zeros count.
fn pixels(v: V) -> [Px; 8] {
    match v {
        V::Mix(b) => b,
        V::Const(c) => std::array::from_fn(|i| if (c >> (8 * i)) & 0xff == 0 { Px::Zero } else { Px::Unknown }),
        _ => [Px::Unknown; 8],
    }
}

/// A [`V::Mix`] needs a data byte, or known discriminator bytes and zeros only (a number whose
/// bytes keep where they came from); anything else is unknown.
fn mix(b: [Px; 8]) -> V {
    if b.iter().any(|p| matches!(p, Px::Data(_))) || known_bytes(&b).is_some() { V::Mix(b) } else { V::Unknown }
}

/// The number a [`V::Mix`] of known discriminator bytes and zeros holds, and those bytes as a
/// mask, counting only its first `lane` bytes.
fn known_bytes_in(b: &[Px], lane: usize) -> Option<(u64, u8)> {
    let (mut v, mut m) = (0u64, 0u8);
    for (i, p) in b.iter().enumerate() {
        match *p {
            Px::Disc(x, k) => {
                v |= u64::from(x) << (8 * i);
                if i < lane {
                    m |= 1 << k;
                }
            }
            Px::Zero => {}
            _ => return None,
        }
    }
    (m != 0 || b.iter().any(|p| matches!(p, Px::Disc(..)))).then_some((v, m))
}

fn known_bytes(b: &[Px]) -> Option<(u64, u8)> {
    known_bytes_in(b, 8)
}

/// Whether a value holds instruction data bytes.
fn has_data(v: V) -> bool {
    matches!(v, V::Mix(b) if b.iter().any(|p| matches!(p, Px::Data(_))))
}

/// Runs of consecutive data bytes in `b`, as (position in `b`, first data byte, length).
fn data_runs(b: &[Px]) -> Vec<(usize, i64, u32)> {
    let mut out = Vec::new();
    let mut run: Option<(usize, i64, u32)> = None;
    for (i, p) in b.iter().copied().chain(std::iter::once(Px::Unknown)).enumerate() {
        match (run, p) {
            (Some((pos, k, n)), Px::Data(x)) if x == k + i64::from(n) => run = Some((pos, k, n + 1)),
            _ => {
                if let Some(r) = run.take() {
                    out.push(r);
                }
                if let Px::Data(x) = p {
                    run = Some((i, x, 1));
                }
            }
        }
    }
    out
}

/// Byte moves on a value of data bytes: shifts by whole bytes, ORs of disjoint bytes, byte masks
/// and truncation, which is how unaligned values are assembled from smaller loads. `None` when the
/// operation computes something else.
fn shuffle(wide: bool, op: AluOp, d: V, s: V) -> Option<V> {
    let lane = if wide { 8 } else { 4 };
    let trunc = |mut b: [Px; 8]| {
        for p in b.iter_mut().skip(lane) {
            *p = Px::Zero;
        }
        b
    };
    let amount = |v: V| match v {
        V::Const(c) if c % 8 == 0 && c < 64 => Some((c / 8) as usize),
        _ => None,
    };
    let b = match op {
        AluOp::Mov => trunc(pixels(s)),
        AluOp::Lsh => {
            let n = amount(s)?;
            let src = trunc(pixels(d));
            trunc(std::array::from_fn(|i| if i < n { Px::Zero } else { src[i - n] }))
        }
        AluOp::Rsh => {
            let n = amount(s)?;
            let src = trunc(pixels(d));
            trunc(std::array::from_fn(|i| if i + n < lane { src[i + n] } else { Px::Zero }))
        }
        AluOp::Or => {
            let (x, y) = (pixels(d), pixels(s));
            trunc(std::array::from_fn(|i| match (x[i], y[i]) {
                (Px::Zero, p) | (p, Px::Zero) => p,
                _ => Px::Unknown,
            }))
        }
        AluOp::And => {
            let V::Const(m) = s else { return None };
            let x = pixels(d);
            trunc(std::array::from_fn(|i| match (m >> (8 * i)) & 0xff {
                0xff => x[i],
                0 => Px::Zero,
                _ => Px::Unknown,
            }))
        }
        _ => return None,
    };
    Some(mix(b))
}

fn known(v: V) -> Option<(u64, u8)> {
    match v {
        V::Const(c) => Some((c, 0)),
        V::Disc(c, m) => Some((c, m)),
        V::Mix(b) => known_bytes(&b),
        _ => None,
    }
}

/// The discriminator bytes a comparison of `lane` bytes reads from `v`.
fn compared_bytes(v: V, lane: usize) -> u8 {
    match v {
        V::Mix(b) => known_bytes_in(&b, lane).map_or(0, |(_, m)| m),
        V::Disc(_, m) => m,
        _ => 0,
    }
}

fn add(v: V, d: i64) -> V {
    match v {
        V::Data(k) => V::Data(k.wrapping_add(d)),
        V::Frame(f, o) => V::Frame(f, o.wrapping_add(d)),
        V::Const(c) => V::Const(c.wrapping_add(d as u64)),
        V::Disc(c, m) => V::Disc(c.wrapping_add(d as u64), m),
        V::Unknown | V::Mix(_) => V::Unknown,
    }
}


/// Exact arithmetic on known values, with the loader's 32-bit semantics for `version`.
pub(crate) fn compute(version: u32, wide: bool, op: AluOp, a: u64, b: u64) -> Option<u64> {
    if wide {
        return Some(match op {
            AluOp::Mov => b,
            AluOp::Add => a.wrapping_add(b),
            AluOp::Sub => a.wrapping_sub(b),
            AluOp::Mul | AluOp::Lmul => a.wrapping_mul(b),
            AluOp::Div | AluOp::Udiv => a.checked_div(b)?,
            AluOp::Mod | AluOp::Urem => a.checked_rem(b)?,
            AluOp::And => a & b,
            AluOp::Or => a | b,
            AluOp::Xor => a ^ b,
            AluOp::Lsh => a.wrapping_shl(b as u32),
            AluOp::Rsh => a.wrapping_shr(b as u32),
            AluOp::Arsh => (a as i64).wrapping_shr(b as u32) as u64,
            AluOp::Hor => a | (b << 32),
            _ => return None,
        });
    }
    let (a32, b32) = (a as u32, b as u32);
    // 32-bit add, sub and mul sign-extend, except in v2.
    let sext = |v: u32| if version == 2 { u64::from(v) } else { v as i32 as i64 as u64 };
    Some(match op {
        AluOp::Mov => u64::from(b32),
        AluOp::Add => sext(a32.wrapping_add(b32)),
        AluOp::Sub => sext(a32.wrapping_sub(b32)),
        AluOp::Mul | AluOp::Lmul => sext(a32.wrapping_mul(b32)),
        AluOp::Div | AluOp::Udiv => u64::from(a32.checked_div(b32)?),
        AluOp::Mod | AluOp::Urem => u64::from(a32.checked_rem(b32)?),
        AluOp::And => u64::from(a32 & b32),
        AluOp::Or => u64::from(a32 | b32),
        AluOp::Xor => u64::from(a32 ^ b32),
        AluOp::Lsh => u64::from(a32.wrapping_shl(b32)),
        AluOp::Rsh => u64::from(a32.wrapping_shr(b32)),
        AluOp::Arsh => u64::from((a32 as i32).wrapping_shr(b32) as u32),
        _ => return None,
    })
}

pub(crate) fn holds(cond: Cond, wide: bool, a: u64, b: u64) -> bool {
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

/// What one stack byte holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum B {
    /// A known byte, with the discriminator bytes it came from.
    Known(u8, u8),
    /// A copy of instruction data byte k.
    Data(i64),
}

/// One 8-byte stack slot: a whole value, or bytes tracked one by one.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Slot {
    Whole(V),
    Bytes([Option<B>; 8]),
}

impl Slot {
    fn byte(&self, i: usize) -> Option<B> {
        match self {
            Slot::Whole(V::Mix(b)) => px_byte(b[i]),
            Slot::Whole(v) => {
                let (c, m) = known(*v)?;
                Some(B::Known((c >> (8 * i)) as u8, byte_mask(m, i)))
            }
            Slot::Bytes(b) => b[i],
        }
    }

    fn bytes(&self) -> [Option<B>; 8] {
        std::array::from_fn(|i| self.byte(i))
    }

    /// What survives of a slot that only one path wrote: pointers and data copies, not numbers.
    fn one_sided(&self) -> Slot {
        match self {
            Slot::Whole(V::Const(_) | V::Disc(..)) => Slot::Whole(V::Unknown),
            Slot::Whole(v) => Slot::Whole(*v),
            Slot::Bytes(b) => Slot::Bytes(b.map(|x| x.filter(|x| matches!(x, B::Data(_))))),
        }
    }
}

fn px_byte(p: Px) -> Option<B> {
    match p {
        Px::Data(k) => Some(B::Data(k)),
        Px::Disc(v, k) => Some(B::Known(v, 1 << k)),
        Px::Zero => Some(B::Known(0, 0)),
        Px::Unknown => None,
    }
}

/// Byte `i` of value `v`, as it would sit in memory.
fn byte_of(v: V, i: usize) -> Option<B> {
    match v {
        V::Mix(b) => px_byte(b[i]),
        _ => known(v).map(|(c, m)| B::Known((c >> (8 * i)) as u8, byte_mask(m, i))),
    }
}

/// The value of `bytes` read together (zero-extended): known bytes make a number, and bytes that
/// include copies of data bytes make a [`V::Mix`].
fn value_of(bytes: &[Option<B>]) -> V {
    if bytes.iter().all(|b| matches!(b, Some(B::Known(..)))) {
        let (mut v, mut m) = (0u64, 0u8);
        for (i, b) in bytes.iter().enumerate() {
            if let Some(B::Known(x, xm)) = b {
                v |= u64::from(*x) << (8 * i);
                m |= xm;
            }
        }
        return if m == 0 { V::Const(v) } else { V::Disc(v, m) };
    }
    mix(std::array::from_fn(|i| match bytes.get(i) {
        None => Px::Zero,
        Some(Some(B::Data(k))) => Px::Data(*k),
        Some(Some(B::Known(0, _))) => Px::Zero,
        Some(_) => Px::Unknown,
    }))
}

/// The provenance of byte `i` of a value whose discriminator mask is `m`: when the mask is a
/// contiguous run (a direct load of data bytes `k..k+n`), byte `i` is discriminator byte `k + i`;
/// otherwise every byte keeps the whole mask.
fn byte_mask(m: u8, i: usize) -> u8 {
    if m == 0 {
        return 0;
    }
    let k = m.trailing_zeros() as usize;
    let rest = u16::from(m) >> k;
    let run = rest.trailing_ones() as usize;
    if rest >> run == 0 {
        if i < run { 1 << (k + i) } else { 0 }
    } else {
        m
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct State {
    regs: [V; 11],
    mem: BTreeMap<(u32, i64), Slot>,
    /// Discriminator bytes an equality test on this path found equal (walks with exact bytes only).
    matched: u8,
}

impl State {
    /// Where paths meet. A register keeps its value only when every path agrees. Memory is merged
    /// optimistically for where data goes: a slot written on one path keeps its pointers and copies
    /// of data bytes, since the other path usually left it alone (an error path that returns before
    /// filling an out-parameter, say). Numbers written on one path only become unknown, so a branch
    /// is never decided by a value only some paths hold. A slot the paths disagree on becomes
    /// unknown for good, so the merge always settles.
    ///
    /// When `lenient`, two data pointers that disagree keep the one further into the data: a
    /// deserializer advances its cursor only on success, so the path that read further is the one
    /// that goes on decoding, and a value holding data bytes survives a path that holds a number
    /// instead. Only the first merges into a block are lenient, so loops settle.
    fn join(&mut self, o: &State, lenient: bool) -> bool {
        let further = |a: V, b: V| match (a, b) {
            (V::Data(x), V::Data(y)) if lenient && (x - y).abs() <= 4096 => Some(V::Data(x.max(y))),
            // Data bytes on one path, a number or nothing known on the other (an error path that
            // builds a different result in the same register): the data bytes go on.
            (m, V::Unknown | V::Const(_) | V::Disc(..)) | (V::Unknown | V::Const(_) | V::Disc(..), m) if lenient && has_data(m) => Some(m),
            _ => None,
        };
        let mut changed = false;
        if self.matched & o.matched != self.matched {
            self.matched &= o.matched;
            changed = true;
        }
        for r in 0..11 {
            if self.regs[r] != o.regs[r] && (self.regs[r] != V::Unknown || (lenient && has_data(o.regs[r]))) {
                let v = further(self.regs[r], o.regs[r]).unwrap_or(V::Unknown);
                if v != self.regs[r] {
                    self.regs[r] = v;
                    changed = true;
                }
            }
        }
        for (k, v) in &o.mem {
            match self.mem.get(k) {
                None => {
                    self.mem.insert(*k, v.one_sided());
                    changed = true;
                }
                Some(cur) if cur != v && *cur != Slot::Whole(V::Unknown) => {
                    let merged = match (cur, v) {
                        (Slot::Whole(a), Slot::Whole(b)) => further(*a, *b).map_or(Slot::Whole(V::Unknown), Slot::Whole),
                        _ => Slot::Whole(V::Unknown),
                    };
                    if merged != *cur {
                        self.mem.insert(*k, merged);
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        changed
    }

    fn load(&self, f: u32, o: i64, width: u32) -> V {
        let slot = o.div_euclid(8) * 8;
        let at = (o - slot) as usize;
        if at + width as usize > 8 {
            // Straddles two slots: byte by byte.
            let bytes: Vec<Option<B>> = (0..i64::from(width)).map(|i| self.byte(f, o + i)).collect();
            return value_of(&bytes);
        }
        let Some(s) = self.mem.get(&(f, slot)) else { return V::Unknown };
        if width == 8 && at == 0 {
            if let Slot::Whole(v) = s {
                return *v;
            }
        }
        if at + width as usize > 8 {
            // Straddles two slots: byte by byte.
            let bytes: Vec<Option<B>> = (0..i64::from(width)).map(|i| self.byte(f, o + i)).collect();
            return value_of(&bytes);
        }
        let bytes: Vec<Option<B>> = (0..width as usize).map(|i| s.byte(at + i)).collect();
        value_of(&bytes)
    }

    fn store(&mut self, f: u32, o: i64, width: u32, v: V) {
        let slot = o.div_euclid(8) * 8;
        let at = (o - slot) as usize;
        if width == 8 && at == 0 {
            self.mem.insert((f, slot), Slot::Whole(v));
            return;
        }
        if at + width as usize > 8 {
            // Straddles two slots: byte by byte.
            for i in 0..width as i64 {
                let b = byte_of(v, i as usize);
                self.store_byte(f, o + i, b);
            }
            return;
        }
        let mut bytes = self.mem.get(&(f, slot)).map_or([None; 8], Slot::bytes);
        for i in 0..width as usize {
            bytes[at + i] = byte_of(v, i);
        }
        self.mem.insert((f, slot), Slot::Bytes(bytes));
    }

    fn store_byte(&mut self, f: u32, o: i64, b: Option<B>) {
        let slot = o.div_euclid(8) * 8;
        let mut bytes = self.mem.get(&(f, slot)).map_or([None; 8], Slot::bytes);
        bytes[(o - slot) as usize] = b;
        self.mem.insert((f, slot), Slot::Bytes(bytes));
    }

    fn byte(&self, f: u32, o: i64) -> Option<B> {
        let slot = o.div_euclid(8) * 8;
        self.mem.get(&(f, slot))?.byte((o - slot) as usize)
    }
}

struct Walk<'a> {
    p: &'a Program<'a>,
    cfg: &'a Cfg,
    disc: [u8; 8],
    /// The discriminator bytes known (bit k: byte k); the others read as unknown data bytes.
    known_bytes: u8,
    /// When discovering discriminators: equality tests of unknown discriminator bytes against a
    /// constant, as (first byte, length, the bytes as a little-endian value).
    tests: Option<BTreeSet<(i64, u32, u64)>>,
    /// Data byte ranges whose values the code uses: the argument fields.
    reads: BTreeSet<(i64, u32)>,
    /// Data loaded and stored to the stack as it is: (first data byte, length, frame, offset).
    copies: Vec<(i64, u32, u32, i64)>,
    /// Discriminator bytes that took part in a decided branch.
    checked: u8,
    /// Discriminator bytes a decided comparison found equal to what the code tests them against,
    /// and the branch where the last of the 8 matched.
    matched: u8,
    matched_at: Option<u32>,
    /// Stop as soon as all 8 bytes matched: only whether they do is wanted.
    stop_on_match: bool,
    /// A call the walk does not follow may have written anything at or above a stack address it
    /// was handed (an out-parameter it filled). The layout walks keep such slots, which suits
    /// recovering fields; the walks that confirm discriminators drop them, so a stale data pointer
    /// left in a reused slot never stands in for what the call put there.
    sound_calls: bool,
    /// Discriminator bytes are loaded as known bytes that keep their positions (`Px::Disc`), and
    /// matching is tracked per path: a candidate counts only when one path finds all 8 equal.
    exact_bytes: bool,
    /// Branches the walk could not decide, so took both ways.
    undecided: u64,
    steps: usize,
    budget: usize,
    next_frame: u32,
    /// The instruction data's pointer went somewhere the walk does not follow (a call it does not
    /// enter, memory outside the stack, a copy of unknown length), so reads may be missing.
    escaped: bool,
    /// Instructions that load this instruction's `Instruction: <Name>` log string: its handler.
    log_sites: &'a [u32],
    /// The walk reached one of `log_sites` with argument bytes still reachable.
    reached_handler: bool,
}

impl Walk<'_> {
    fn exhausted(&self) -> bool {
        self.steps >= self.budget
    }

    fn all_known(&self, k: i64, n: u32) -> bool {
        let m = ((1u16 << n) - 1) << k;
        u16::from(self.known_bytes) & m == m
    }

    /// When discovering: an equality test of `v` against the number `c` under a comparison of
    /// `lane` bytes, where `v` is one run of unknown discriminator bytes, the rest zeros or known
    /// discriminator bytes. Records what the run must hold for the two to be equal. A
    /// discriminator tree tests a byte only where the bytes before it matched, so below the first
    /// level a test counts only on a path (`path`: the bytes equality tests matched on it) where
    /// every known byte matched; elsewhere the code is past the dispatch (a handler reached through
    /// range checks on a one-byte tag, reading its arguments).
    fn record_test(&mut self, v: V, c: u64, lane: usize, path: u8) -> Test {
        let (Some(tests), V::Mix(b)) = (self.tests.as_mut(), v) else { return Test::None };
        let runs = data_runs(&b[..lane]);
        let [(pos, k, n)] = runs.as_slice() else { return Test::None };
        let (pos, k, n) = (*pos, *k, *n);
        if k < 0 || k + i64::from(n) > 8 {
            return Test::None;
        }
        let mut agree = true;
        // Known bytes this test compares too: when they agree with the constant, the test itself
        // checks them.
        let mut covers = 0u8;
        for (i, p) in b[..lane].iter().enumerate() {
            if (pos..pos + n as usize).contains(&i) {
                continue;
            }
            let byte = (c >> (8 * i)) as u8;
            match *p {
                Px::Zero => agree &= byte == 0,
                Px::Disc(x, k) => {
                    agree &= byte == x;
                    covers |= 1 << k;
                }
                _ => return Test::None,
            }
        }
        if !agree {
            return Test::Unequal;
        }
        if (path | covers) & self.known_bytes != self.known_bytes {
            return Test::OffPath;
        }
        let run = if n == 8 { u64::MAX } else { (1u64 << (8 * n)) - 1 };
        tests.insert((k, n, (c >> (8 * pos)) & run));
        Test::Recorded
    }

    fn operand(s: &State, o: Operand) -> V {
        match o {
            Operand::Imm(i) => V::Const(i as i64 as u64),
            Operand::Reg(r) => s.regs[r as usize],
        }
    }

    /// Whether `v` gives access to argument bytes: the data pointer past the discriminator, a value
    /// holding data bytes, or a stack frame some slot of which holds either (a cursor or a decoded
    /// argument struct handed on by reference).
    fn reaches_data(s: &State, v: V) -> bool {
        let slot_has = |slot: &Slot| match slot {
            Slot::Whole(V::Data(k)) => *k >= 8,
            Slot::Whole(V::Mix(_)) => true,
            Slot::Bytes(b) => b.iter().any(|x| matches!(x, Some(B::Data(_)))),
            _ => false,
        };
        match v {
            V::Data(k) => k >= 8,
            V::Mix(_) => true,
            V::Frame(f, _) => s.mem.range((f, i64::MIN)..=(f, i64::MAX)).any(|(_, slot)| slot_has(slot)),
            _ => false,
        }
    }

    /// A data value the code uses (in arithmetic, a comparison, a call, a return, or a store
    /// outside the stack) is an argument field.
    fn consume(&mut self, v: V) {
        if let V::Mix(b) = v {
            for (_, k, n) in data_runs(&b) {
                self.reads.insert((k, n));
            }
        }
    }

    fn load(&mut self, s: &State, base: V, off: i16, width: u32) -> V {
        self.consume(base);
        match add(base, i64::from(off)) {
            V::Data(k) if k >= 8 => loaded(k, width),
            V::Data(k) if k >= 0 && k as u32 + width <= 8 && (self.exact_bytes || !self.all_known(k, width)) => V::Mix(std::array::from_fn(|i| {
                let j = k + i as i64;
                if i as u32 >= width {
                    Px::Zero
                } else if self.all_known(j, 1) {
                    Px::Disc(self.disc[j as usize], j as u8)
                } else {
                    Px::Data(j)
                }
            })),
            V::Data(k) if k >= 0 && k as u32 + width <= 8 => {
                let mut b = [0u8; 8];
                b[..width as usize].copy_from_slice(&self.disc[k as usize..k as usize + width as usize]);
                let mask = ((((1u16 << width) - 1) << k) & 0xff) as u8;
                V::Disc(u64::from_le_bytes(b), mask)
            }
            V::Frame(f, o) => s.load(f, o, width),
            V::Const(addr) => match self.p.read(addr, width as usize) {
                // Read-only data the program loads from (a discriminator table, say).
                Some(b) if self.p.region_of(addr).is_some() => {
                    let mut v = [0u8; 8];
                    v[..b.len()].copy_from_slice(b);
                    V::Const(u64::from_le_bytes(v))
                }
                _ => V::Unknown,
            },
            _ => V::Unknown,
        }
    }

    fn store(&mut self, s: &mut State, base: V, off: i16, width: u32, v: V) {
        self.consume(base);
        if !matches!(add(base, i64::from(off)), V::Frame(..)) && matches!(v, V::Data(k) if k >= 8) {
            self.escaped = true;
        }
        match add(base, i64::from(off)) {
            V::Frame(f, o) => {
                if let V::Mix(b) = v {
                    for (pos, k, n) in data_runs(&b[..width as usize]) {
                        self.copies.push((k, n, f, o + pos as i64));
                    }
                }
                s.store(f, o, width, v);
            }
            _ => self.consume(v),
        }
    }

    /// One byte at `addr`, for a copy or a comparison.
    fn byte_at(&self, s: &State, addr: V) -> Option<B> {
        match addr {
            V::Data(k) if (0..8).contains(&k) && self.all_known(k, 1) => Some(B::Known(self.disc[k as usize], 1 << k)),
            V::Data(k) if (0..8).contains(&k) => Some(B::Data(k)),
            V::Data(k) if k >= 8 => Some(B::Data(k)),
            V::Frame(f, o) => s.byte(f, o),
            V::Const(a) => self.p.read(a, 1).map(|b| B::Known(b[0], 0)),
            _ => None,
        }
    }

    /// Record the data bytes among `bytes` (runs of consecutive data bytes) as used.
    fn consume_bytes(&mut self, bytes: &[Option<B>]) {
        let mut run: Option<(i64, u32)> = None;
        for b in bytes.iter().copied().chain(std::iter::once(None)) {
            match (run, b) {
                (Some((k, n)), Some(B::Data(x))) if x == k + i64::from(n) => run = Some((k, n + 1)),
                _ => {
                    if let Some((k, n)) = run.take() {
                        self.reads.insert((k, n));
                    }
                    if let Some(B::Data(x)) = b {
                        run = Some((x, 1));
                    }
                }
            }
        }
    }

    /// `memcpy(dst, src, n)`: data copied to the stack is tracked byte by byte; data copied
    /// anywhere else is used.
    fn memcpy(&mut self, s: &mut State, dst: V, src: V, n: V) {
        let V::Const(n) = n else {
            if matches!(src, V::Data(k) if k >= 8) {
                self.escaped = true;
            }
            // Unknown length (a vector's or string's contents): the destination's bytes are unknown.
            if let V::Frame(f, o) = dst {
                s.mem.retain(|(ff, oo), _| *ff != f || *oo + 8 <= o);
            }
            return;
        };
        if n == 0 || n > 4096 {
            return;
        }
        if n > MAX_COPY {
            if let V::Data(k) = src {
                if k >= 8 {
                    self.reads.insert((k, n as u32));
                }
            }
            if let V::Frame(f, o) = dst {
                let end = o + n as i64;
                s.mem.retain(|(ff, oo), _| *ff != f || *oo + 8 <= o || *oo >= end);
            }
            return;
        }
        // Whole aligned slots between stack frames keep pointer values.
        if let (V::Frame(f, o), V::Frame(sf, so)) = (dst, src) {
            if n % 8 == 0 && o % 8 == 0 && so % 8 == 0 {
                for i in (0..n as i64).step_by(8) {
                    match s.mem.get(&(sf, so + i)).cloned() {
                        Some(slot) => s.mem.insert((f, o + i), slot),
                        None => s.mem.remove(&(f, o + i)),
                    };
                }
                return;
            }
        }
        let bytes: Vec<Option<B>> = (0..n as i64).map(|i| self.byte_at(s, add(src, i))).collect();
        match dst {
            V::Frame(f, o) => {
                if let V::Data(k) = src {
                    if k >= 8 {
                        self.copies.push((k, n as u32, f, o));
                    }
                }
                for (i, b) in bytes.into_iter().enumerate() {
                    s.store_byte(f, o + i as i64, b);
                }
            }
            _ => self.consume_bytes(&bytes),
        }
    }

    /// `sol_memcmp_(a, b, n, &result)`: when both sides are known bytes, the result is known too.
    /// Data bytes compared are used.
    fn memcmp(&mut self, s: &mut State, at: u32) {
        let (a, b, n, out) = (s.regs[1], s.regs[2], s.regs[3], s.regs[4]);
        let mut result = V::Unknown;
        if let V::Const(n) = n {
            if n > 0 && n <= 64 {
                let xs: Vec<Option<B>> = (0..n as i64).map(|i| self.byte_at(s, add(a, i))).collect();
                let ys: Vec<Option<B>> = (0..n as i64).map(|i| self.byte_at(s, add(b, i))).collect();
                self.consume_bytes(&xs);
                self.consume_bytes(&ys);
                let on_path = s.matched & self.known_bytes == self.known_bytes;
                if let (Some(tests), true) = (self.tests.as_mut(), on_path) {
                    for (d, c) in [(&xs, &ys), (&ys, &xs)] {
                        let k0 = match d.first() {
                            Some(Some(B::Data(k))) => *k,
                            _ => continue,
                        };
                        let run = d.iter().enumerate().all(|(i, x)| *x == Some(B::Data(k0 + i as i64)));
                        let bytes: Option<Vec<u8>> = c.iter().map(|y| match y { Some(B::Known(b, _)) => Some(*b), _ => None }).collect();
                        if let (true, Some(bytes)) = (run && k0 >= 0 && k0 + n as i64 <= 8, bytes) {
                            let mut v = [0u8; 8];
                            v[..bytes.len()].copy_from_slice(&bytes);
                            tests.insert((k0, n as u32, u64::from_le_bytes(v)));
                            // As for a comparison: only the bytes-differ outcome is followed.
                            result = V::Const(1);
                        }
                    }
                }
                let (mut differ, mut mask, mut all) = (false, 0u8, true);
                for (x, y) in xs.iter().zip(&ys) {
                    match (x, y) {
                        (Some(B::Known(x, mx)), Some(B::Known(y, my))) => {
                            differ |= x != y;
                            mask |= mx | my;
                        }
                        _ => all = false,
                    }
                }
                if all && mask != 0 && self.tests.is_none() {
                    result = V::Disc(u64::from(differ), mask);
                    if !differ {
                        if self.exact_bytes {
                            s.matched |= mask;
                            if s.matched == 0xff && self.matched_at.is_none() {
                                self.matched = 0xff;
                                self.matched_at = Some(at);
                            }
                        } else {
                            self.matched |= mask;
                        }
                    }
                }
            }
        }
        if let V::Frame(f, o) = out {
            s.store(f, o, 4, result);
        }
    }

    /// Run instructions `[from, end)` of one block and return the state at its end.
    fn block(&mut self, mut s: State, from: u32, end: u32, depth: u8) -> State {
        for i in from..end {
            if self.exhausted() {
                break;
            }
            self.steps += 1;
            let x = self.p.insns[i as usize];
            match x.op {
                Op::Lddw { dst, .. } => {
                    if !self.reached_handler && self.log_sites.contains(&i) {
                        self.reached_handler = (1..=9).any(|r| Self::reaches_data(&s, s.regs[r]))
                            || s.mem.values().any(|slot| matches!(slot, Slot::Whole(V::Data(k)) if *k >= 8));
                    }
                    s.regs[dst as usize] = self.p.lddw_value(i).map_or(V::Unknown, V::Const)
                }
                Op::Load { w, dst, src, off } => s.regs[dst as usize] = self.load(&s, s.regs[src as usize], off, w.bytes()),
                Op::StoreImm { w, dst, off, imm } => {
                    let base = s.regs[dst as usize];
                    self.store(&mut s, base, off, w.bytes(), V::Const(imm as i64 as u64))
                }
                Op::StoreReg { w, dst, src, off } => {
                    let (base, v) = (s.regs[dst as usize], s.regs[src as usize]);
                    self.store(&mut s, base, off, w.bytes(), v)
                }
                Op::Alu { wide, op, dst, src } => {
                    let d = s.regs[dst as usize];
                    let v = Self::operand(&s, src);
                    let v2 = self.p.version == 2;
                    s.regs[dst as usize] = match (op, wide, d, v) {
                        (AluOp::Mov, true, _, v) => v,
                        // Byte moves on data values (assembling an unaligned value, say) keep where each byte came from.
                        (_, _, d, v) if (matches!(d, V::Mix(_)) && op != AluOp::Mov) || matches!(v, V::Mix(_)) => match shuffle(wide, op, d, v) {
                            Some(r) => r,
                            // Arithmetic on known discriminator bytes: a number from all of them.
                            None if !has_data(d) && !has_data(v) && op != AluOp::Mov && known(d).is_some() && known(v).is_some() => {
                                let ((a, ma), (b, mb)) = (known(d).unwrap(), known(v).unwrap());
                                compute(self.p.version, wide, op, a, b).map_or(V::Unknown, |r| V::Disc(r, ma | mb))
                            }
                            None => {
                                if op != AluOp::Mov {
                                    self.consume(d);
                                }
                                self.consume(v);
                                V::Unknown
                            }
                        },
                        (AluOp::Add, true, d @ (V::Data(_) | V::Frame(..)), V::Const(c)) => add(d, c as i64),
                        (AluOp::Add, true, V::Const(c), v @ (V::Data(_) | V::Frame(..))) => add(v, c as i64),
                        (AluOp::Sub, true, d @ (V::Data(_) | V::Frame(..)), V::Const(c)) if !v2 => add(d, (c as i64).wrapping_neg()),
                        (_, _, d, v) => {
                            if op != AluOp::Mov {
                                self.consume(d);
                            }
                            self.consume(v);
                            // v2: `sub` with an immediate computes `imm - dst`.
                            let swap = op == AluOp::Sub && v2 && matches!(src, Operand::Imm(_));
                            let (a, b) = if op == AluOp::Mov { (Some((0, 0)), known(v)) } else { (known(d), known(v)) };
                            match (a, b) {
                                (Some((a, ma)), Some((b, mb))) => {
                                    let (a, b) = if swap { (b, a) } else { (a, b) };
                                    match compute(self.p.version, wide, op, a, b) {
                                        Some(r) if ma | mb != 0 => V::Disc(r, ma | mb),
                                        Some(r) => V::Const(r),
                                        None => V::Unknown,
                                    }
                                }
                                _ => V::Unknown,
                            }
                        }
                    };
                }
                Op::Call { .. } => {
                    match self.p.call_target(i) {
                        CallTarget::Syscall(name) if name.starts_with("sol_memcpy") || name.starts_with("sol_memmove") => {
                            let (d, src, n) = (s.regs[1], s.regs[2], s.regs[3]);
                            self.memcpy(&mut s, d, src, n);
                        }
                        CallTarget::Syscall("sol_memcmp_") => self.memcmp(&mut s, i),
                        target => {
                            // A data value handed to a function or syscall is used.
                            for r in 1..=5 {
                                self.consume(s.regs[r]);
                            }
                            let enters = matches!(target, CallTarget::Internal(t) if depth < MAX_DEPTH && self.cfg.functions.contains_key(t));
                            if !enters && !matches!(target, CallTarget::Syscall(_)) && s.regs[1..=5].iter().any(|v| Self::reaches_data(&s, *v)) {
                                self.escaped = true;
                            }
                            if let CallTarget::Internal(t) = target {
                                // A callee handed neither the data nor a stack address cannot reach either.
                                // Discovering, a call handed the data past its first byte (and not its
                                // start) is a decoder or handler reading arguments, not dispatch.
                                let past_dispatch = self.tests.is_some()
                                    && s.regs[1..=5].iter().any(|v| matches!(v, V::Data(k) if *k >= 1))
                                    && !s.regs[1..=5].iter().any(|v| matches!(v, V::Data(0)));
                                if depth < MAX_DEPTH && !past_dispatch && s.regs[1..=5].iter().any(|v| matches!(v, V::Data(_) | V::Frame(..))) {
                                    let t = *t;
                                    let mut callee = State { regs: [V::Unknown; 11], mem: s.mem.clone(), matched: s.matched };
                                    callee.regs[1..=5].copy_from_slice(&s.regs[1..=5]);
                                    let frame = self.next_frame;
                                    self.next_frame += 1;
                                    callee.regs[10] = V::Frame(frame, 0);
                                    let cfg = self.cfg;
                                    if let Some(f) = cfg.functions.get(&t) {
                                        // What the callee leaves in memory (an out-parameter it filled, say) is what
                                        // the caller sees next, and its return value is in r0. Only its pointers and
                                        // data copies are kept: the walk may not have seen all its paths, so a number
                                        // it produced (a result tag, say) must not decide a branch in the caller.
                                        let undecided = self.undecided;
                                        let ret = self.region(f.entry, cfg.blocks[f.entry as usize].start, callee, &f.blocks, depth + 1);
                                        // A callee that decided every branch ran as the program would (a
                                        // comparison helper on the discriminator, say): what it leaves is exact.
                                        let exact = self.undecided == undecided;
                                        // A callee the walk could not see return may have read argument bytes on
                                        // a path it did not finish.
                                        if ret.is_none() && s.regs[1..=5].iter().any(|v| Self::reaches_data(&s, *v)) {
                                            self.escaped = true;
                                        }
                                        if let Some(ret) = ret {
                                            s.matched = ret.matched;
                                            let before = std::mem::take(&mut s.mem);
                                            for (k, v) in ret.mem {
                                                if k.0 == frame {
                                                    continue;
                                                }
                                                let keep = exact || before.get(&k) == Some(&v);
                                                s.mem.insert(k, if keep { v } else { v.one_sided() });
                                            }
                                            for r in 1..=5 {
                                                s.regs[r] = V::Unknown;
                                            }
                                            s.regs[0] = match ret.regs[0] {
                                                v @ (V::Mix(_) | V::Data(_) | V::Frame(..)) => v,
                                                v if exact => v,
                                                _ => V::Unknown,
                                            };
                                            continue;
                                        }
                                    }
                                }
                            }
                            if self.sound_calls && !matches!(target, CallTarget::Syscall(n) if READ_ONLY_SYSCALLS.contains(n)) {
                                let args = s.regs;
                                clobber(&mut s, &args[1..=5]);
                            }
                        }
                    }
                    for r in 0..=5 {
                        s.regs[r] = V::Unknown;
                    }
                }
                Op::Callx { .. } => {
                    if s.regs[1..=5].iter().any(|v| Self::reaches_data(&s, *v)) {
                        self.escaped = true;
                    }
                    if self.sound_calls {
                        let args = s.regs;
                        clobber(&mut s, &args[1..=5]);
                    }
                    for r in 1..=5 {
                        self.consume(s.regs[r]);
                    }
                    for r in 0..=5 {
                        s.regs[r] = V::Unknown;
                    }
                }
                // A function returns its value to its caller; only the dispatch's own return uses it.
                Op::Exit if depth == 0 => self.consume(s.regs[0]),
                _ => {}
            }
        }
        s
    }

    /// Worklist over the blocks of `allowed` reachable from `entry`, starting mid-block at `from`.
    /// Returns the state at its returns, joined, when it reaches one.
    fn region(&mut self, entry: BlockId, from: u32, st: State, allowed: &[BlockId], depth: u8) -> Option<State> {
        let mut at_entry: HashMap<BlockId, State> = HashMap::from([(entry, st)]);
        let mut work = vec![entry];
        let mut first = Some(from);
        let mut returned: Option<State> = None;
        let mut visits: HashMap<BlockId, u8> = HashMap::new();
        while let Some(b) = work.pop() {
            if self.exhausted() || (self.stop_on_match && self.matched == 0xff) {
                return None;
            }
            let blk = &self.cfg.blocks[b as usize];
            let start = first.take().unwrap_or(blk.start);
            let mut out = self.block(at_entry[&b].clone(), start, blk.end, depth);
            if blk.term == Term::Return {
                match returned.as_mut() {
                    None => returned = Some(out.clone()),
                    Some(r) => {
                        r.join(&out, true);
                    }
                }
            }
            // A branch whose operands are known goes one way only.
            let mut succs = blk.succs();
            if let (Term::Branch { taken, fall }, Op::Jcond { cond, wide, dst, src, .. }) =
                (blk.term, self.p.insns[blk.end.saturating_sub(1) as usize].op)
            {
                let (lhs, rhs) = (out.regs[dst as usize], Self::operand(&out, src));
                self.consume(lhs);
                self.consume(rhs);
                // Discovering: a test of unknown discriminator bytes is recorded and only its not-equal
                // side is followed. The equal side is the next walk's, with those bytes fixed, so a
                // walk covers one level of the dispatch and never enters the handlers.
                let mut test = Test::None;
                if matches!(cond, Cond::Eq | Cond::Ne) {
                    let (width, lane) = if wide { (u64::MAX, 8) } else { (u64::from(u32::MAX), 4) };
                    if let (m @ V::Mix(_), V::Const(c)) | (V::Const(c), m @ V::Mix(_)) = (lhs, rhs) {
                        test = self.record_test(m, c & width, lane, out.matched);
                    }
                }
                if test == Test::OffPath {
                    succs = Vec::new();
                } else if test != Test::None {
                    // A known byte that differs from the constant also leaves only the not-equal side.
                    succs = vec![if cond == Cond::Eq { fall } else { taken }];
                } else if let (Some((a, ma)), Some((c, mc))) = (known(lhs), known(rhs)) {
                    self.checked |= ma | mc;
                    // An equality test that holds, under the comparison's width (a 32-bit one compares
                    // at most 4 bytes). Ordered comparisons do not count: a binary search's pivots are
                    // often a discriminator plus or minus one.
                    let lane = if wide { 8 } else { 4 };
                    let m = if self.exact_bytes { compared_bytes(lhs, lane) | compared_bytes(rhs, lane) } else { ma | mc };
                    if m != 0 && matches!(cond, Cond::Eq | Cond::Ne) && holds(Cond::Eq, wide, a, c) && (wide || m.count_ones() <= 4) {
                        if self.exact_bytes {
                            out.matched |= m;
                        } else {
                            self.matched |= m;
                        }
                        if (out.matched == 0xff || self.matched == 0xff) && self.matched_at.is_none() {
                            self.matched = 0xff;
                            self.matched_at = Some(blk.end - 1);
                        }
                    }
                    succs = vec![if holds(cond, wide, a, c) { taken } else { fall }];
                } else {
                    self.undecided += 1;
                }
            }
            for succ in succs {
                if allowed.binary_search(&succ).is_err() {
                    continue;
                }
                let seen = visits.entry(succ).or_insert(0u8);
                *seen = seen.saturating_add(1);
                let lenient = *seen <= 3;
                match at_entry.get_mut(&succ) {
                    None => {
                        at_entry.insert(succ, out.clone());
                        work.push(succ);
                    }
                    Some(cur) => {
                        if cur.join(&out, lenient) {
                            work.push(succ);
                        }
                    }
                }
            }
        }
        returned
    }

    /// The fields, each with whether the code only copied it. Used data (in arithmetic, a comparison, a
    /// call, a return, or a store outside the stack) gives fields whose bounds the code shows. Data
    /// only copied to the stack and never used on the walk (handed on by address, say) is added from
    /// the copies, gathered by where they land into runs of data bytes copied side by side: a run
    /// whose pieces tile it evenly (each piece a natural size at a multiple of that size) keeps them,
    /// and one moved in uneven pieces (4, 2, 8, 1, ..., how the compiler splits a move of a public
    /// key) is one copied span, since the pieces say nothing about the fields inside. Longer runs
    /// go first; a run cutting across a field already placed is left out.
    fn fields(&self) -> Vec<(i64, u32, bool)> {
        let mut out: BTreeSet<(i64, u32, bool)> = self.reads.iter().map(|&(k, n)| (k, n, false)).collect();
        let covered = |k: i64, n: u32| self.reads.iter().any(|&(a, w)| a < k + i64::from(n) && k < a + i64::from(w));
        let mut left: Vec<(i64, u32, u32, i64)> = self.copies.iter().copied().filter(|&(k, n, _, _)| !covered(k, n)).collect();
        left.sort_unstable();
        left.dedup();
        let mut i = 0;
        while i < left.len() {
            let (k0, _, f0, o0) = left[i];
            let mut j = i + 1;
            let mut end = k0 + i64::from(left[i].1);
            let mut uneven = false;
            while j < left.len() {
                let (k, n, f, o) = left[j];
                if k != end || f != f0 || o - k != o0 - k0 {
                    break;
                }
                uneven |= n > 1 && (k - k0) % i64::from(n) != 0;
                end = k + i64::from(n);
                j += 1;
            }
            if uneven {
                out.insert((k0, (end - k0) as u32, true));
            } else {
                for &(k, n, _, _) in &left[i..j] {
                    out.insert((k, n, true));
                }
            }
            i = j;
        }
        let all: Vec<(i64, u32, bool)> = out.iter().copied().collect();
        out.retain(|&(k, n, _)| !all.iter().any(|&(a, w, _)| (a, w) != (k, n) && a <= k && k + i64::from(n) <= a + i64::from(w)));
        out.into_iter().collect()
    }
}


/// Fields from the data reads: sorted, merged where a read lies inside an earlier one.
fn layout(reads: &[(i64, u32, bool)]) -> (Vec<ArgumentField>, bool) {
    let mut fields: Vec<ArgumentField> = Vec::new();
    let mut irregular = false;
    for &(k, w, copied) in reads {
        let off = (k - 8) as u32;
        if let Some(last) = fields.last_mut() {
            let end = last.offset + last.size;
            if off < end {
                if off + w > end {
                    irregular = true;
                    last.size = off + w - last.offset;
                    last.copied &= copied;
                }
                continue;
            }
            if off > end {
                irregular = true;
            }
        } else if off != 0 {
            irregular = true;
        }
        fields.push(ArgumentField { offset: off, size: w, copied });
    }
    (fields, irregular)
}

/// Where a fallback start puts the data pointer: an argument register, or a slot of the caller's
/// stack arguments (reached through `r5`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Guess {
    Reg(u8),
    Stack(i64),
}

/// What a backward search found.
enum Found {
    Def(u32),
    Top(u32),
}

/// Where a walk starts: instruction `at` of function `func`, with register `reg` holding the data
/// pointer plus `delta`. `site` is the instruction that tests the discriminator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Start {
    func: u32,
    at: u32,
    reg: u8,
    delta: i64,
    site: u32,
}

struct Finder<'a> {
    p: &'a Program<'a>,
    cfg: &'a Cfg,
    /// Function starts, sorted.
    starts: Vec<u32>,
}

impl<'a> Finder<'a> {
    fn new(p: &'a Program<'a>, cfg: &'a Cfg) -> Self {
        Finder { p, cfg, starts: cfg.functions.keys().copied().collect() }
    }

    /// The function holding instruction `i`: the closest start at or before it whose blocks hold it.
    fn function_of(&self, i: u32) -> Option<u32> {
        let b = *self.cfg.block_of.get(i as usize)?;
        let k = self.starts.partition_point(|&s| s <= i);
        self.starts[..k].iter().rev().take(64).copied().find(|s| self.cfg.functions[s].blocks.binary_search(&b).is_ok())
    }

    fn writes(op: &Op, r: u8) -> bool {
        match *op {
            Op::Lddw { dst, .. } | Op::Load { dst, .. } | Op::Alu { dst, .. } => dst == r,
            Op::Call { .. } | Op::Callx { .. } => r <= 5,
            _ => false,
        }
    }

    /// The instruction before `at` that `hit` matches on every path into `at`, searched back along
    /// the control flow: through a block's single predecessor, or through several when all of them
    /// lead to the same instruction. `Top(k)` when the search stops first, at instruction `k` (the
    /// function's entry, or a join whose predecessors disagree).
    fn back(&self, func: u32, at: u32, hit: &dyn Fn(&Op) -> bool) -> Found {
        let Some(&b) = self.cfg.block_of.get(at as usize) else { return Found::Top(at) };
        let mut budget = TRACE_WINDOW;
        self.back_from(func, b, at, hit, 0, &mut BTreeSet::new(), &mut budget)
    }

    /// Search instructions `[start of block b, upto)` backwards, then the block's predecessors.
    fn back_from(&self, func: u32, mut b: BlockId, mut upto: u32, hit: &dyn Fn(&Op) -> bool, depth: u8, seen: &mut BTreeSet<BlockId>, budget: &mut usize) -> Found {
        let Some(f) = self.cfg.functions.get(&func) else { return Found::Top(upto) };
        loop {
            let start = self.cfg.blocks[b as usize].start;
            for k in (start..upto).rev() {
                if *budget == 0 {
                    return Found::Top(k + 1);
                }
                *budget -= 1;
                if hit(&self.p.insns[k as usize].op) {
                    return Found::Def(k);
                }
            }
            if b == f.entry || !seen.insert(b) {
                return Found::Top(start);
            }
            let preds: Vec<BlockId> =
                self.cfg.blocks[b as usize].preds.iter().copied().filter(|p| f.blocks.binary_search(p).is_ok()).collect();
            match preds.as_slice() {
                [] => return Found::Top(start),
                [p] => {
                    b = *p;
                    upto = self.cfg.blocks[*p as usize].end;
                }
                many if depth < 4 => {
                    // Several ways in: the answer holds only if every one of them gives it.
                    let mut agreed: Option<u32> = None;
                    for &p in many {
                        let mut branch = seen.clone();
                        match self.back_from(func, p, self.cfg.blocks[p as usize].end, hit, depth + 1, &mut branch, budget) {
                            Found::Def(k) if agreed.is_none_or(|x| x == k) => agreed = Some(k),
                            _ => return Found::Top(start),
                        }
                    }
                    return agreed.map_or(Found::Top(start), Found::Def);
                }
                _ => return Found::Top(start),
            }
        }
    }

    /// The instruction before `i` that writes `r`, on every path into `i`.
    fn def(&self, func: u32, i: u32, r: u8) -> Option<u32> {
        match self.back(func, i, &|op| Self::writes(op, r)) {
            Found::Def(k) => Some(k),
            Found::Top(_) => None,
        }
    }

    /// Where the data pointer in `r` at instruction `i` comes from: through register moves, pointer
    /// arithmetic and stack spills, back to the instruction that produced it (a load from memory,
    /// say) or to the function's entry.
    fn origin(&self, func: u32, i: u32, r: u8) -> Start {
        let (mut at, mut reg, mut delta) = (i, r, 0i64);
        for _ in 0..32 {
            let k = match self.back(func, at, &|op| Self::writes(op, reg)) {
                Found::Def(k) => k,
                Found::Top(top) => return Start { func, at: top, reg, delta, site: i },
            };
            match self.p.insns[k as usize].op {
                Op::Alu { wide: true, op: AluOp::Mov, src: Operand::Reg(s), .. } if s != 10 => {
                    at = k;
                    reg = s;
                }
                Op::Alu { wide: true, op: AluOp::Add, src: Operand::Imm(c), .. } => {
                    at = k;
                    delta += i64::from(c);
                }
                Op::Load { w: Width::DW, src: 10, off, .. } => {
                    // A spill reloaded: continue from the register stored there.
                    let spill = self.back(func, k, &|op| matches!(*op, Op::StoreReg { w: Width::DW, dst: 10, off: o, .. } if o == off));
                    match spill {
                        Found::Def(j) => {
                            let Op::StoreReg { src, .. } = self.p.insns[j as usize].op else { unreachable!() };
                            at = j;
                            reg = src;
                        }
                        Found::Top(_) => return Start { func, at: k + 1, reg, delta, site: i },
                    }
                }
                _ => return Start { func, at: k + 1, reg, delta, site: i },
            }
        }
        Start { func, at, reg, delta, site: i }
    }

    /// The register whose bytes `site` compares, for a byte compare `jxx rX, imm`.
    fn byte_start(&self, site: u32) -> Option<Start> {
        let func = self.function_of(site)?;
        let Op::Jcond { dst, src: Operand::Imm(_), .. } = self.p.insns[site as usize].op else { return None };
        // The compared byte may have been moved, masked or shifted out of a wider load, or spilled to
        // the stack and reloaded: follow it back to the load from the data.
        let (mut at, mut reg) = (site, dst);
        for _ in 0..32 {
            let k = self.def(func, at, reg)?;
            match self.p.insns[k as usize].op {
                Op::Alu { op: AluOp::Mov, src: Operand::Reg(s), .. } if s != 10 => {
                    at = k;
                    reg = s;
                }
                Op::Alu { op: AluOp::And | AluOp::Rsh | AluOp::Lsh | AluOp::Arsh, src: Operand::Imm(_), .. } => at = k,
                Op::Load { w, src: 10, off, .. } => {
                    let (lo, hi) = (i64::from(off), i64::from(off) + i64::from(w.bytes()));
                    let covers = |op: &Op| match *op {
                        Op::StoreReg { w, dst: 10, off: o, .. } => i64::from(o) <= lo && hi <= i64::from(o) + i64::from(w.bytes()),
                        _ => false,
                    };
                    let Found::Def(j) = self.back(func, k, &covers) else { return None };
                    let Op::StoreReg { src: v, .. } = self.p.insns[j as usize].op else { return None };
                    at = j;
                    reg = v;
                }
                Op::Load { src, off, .. } if src != 10 && (0..8).contains(&off) => return Some(self.origin(func, k, src)),
                _ => return None,
            }
        }
        None
    }

    /// Functions that test this discriminator: where its constant is loaded, where its byte chain
    /// is, or where a table holding a copy of it is addressed.
    fn testing_functions(&self, value: u64, chain: Option<u32>, rodata_copies: &[u64]) -> Vec<u32> {
        let near = |a: u64| rodata_copies.iter().any(|&c| a <= c && c - a <= 8192);
        let mut out: Vec<u32> = Vec::new();
        for (i, x) in self.p.insns.iter().enumerate() {
            let i = i as u32;
            if let Op::Lddw { .. } = x.op {
                let v = self.p.lddw_value(i);
                if v == Some(value) || v.is_some_and(|a| near(self.p.normalize(a))) {
                    if let Some(f) = self.function_of(i) {
                        if !out.contains(&f) {
                            out.push(f);
                        }
                    }
                }
            }
            if out.len() >= 4 {
                break;
            }
        }
        if let Some(f) = chain.and_then(|c| self.chain_head(c)).and_then(|i| self.function_of(i)) {
            if !out.contains(&f) {
                out.push(f);
            }
        }
        out
    }

    /// Starts for one discriminator: 64-bit constants compared with the first 8 data bytes, its
    /// byte chain, and copies in read-only data handed to `sol_memcmp_`.
    fn starts(&self, value: u64, chain: Option<u32>, rodata_copies: &[u64]) -> Vec<Start> {
        let mut out = Vec::new();
        for (i, x) in self.p.insns.iter().enumerate() {
            let i = i as u32;
            match x.op {
                Op::Lddw { dst, .. } if self.p.lddw_value(i) == Some(value) => self.compare_start(i, dst, &mut out),
                Op::Lddw { dst, .. } if self.p.lddw_value(i).is_some_and(|a| rodata_copies.contains(&self.p.normalize(a))) => {
                    self.memcmp_start(i, dst, &mut out)
                }
                // sBPF v2: mov32 low half, then hor64 high half.
                Op::Alu { op: AluOp::Hor, dst, src: Operand::Imm(hi), .. } if (value >> 32) as u32 == hi as u32 => {
                    let lo = (i.saturating_sub(4)..i).rev().find_map(|j| match self.p.insns[j as usize].op {
                        Op::Alu { op: AluOp::Mov, wide: false, dst: d, src: Operand::Imm(lo) } if d == dst => Some(lo as u32),
                        _ => None,
                    });
                    if lo == Some(value as u32) {
                        self.compare_start(i, dst, &mut out);
                    }
                }
                _ => {}
            }
            if out.len() >= MAX_STARTS {
                break;
            }
        }
        if let Some(site) = chain.and_then(|c| self.chain_head(c)) {
            if let Some(s) = self.byte_start(site) {
                out.push(s);
            }
        }
        out.dedup();
        out
    }

    /// The compare that uses the constant loaded into `reg` at `i`, and the 8-byte data load it
    /// is compared with.
    fn compare_start(&self, i: u32, reg: u8, out: &mut Vec<Start>) {
        let Some(func) = self.function_of(i) else { return };
        let end = (i as usize + 12).min(self.p.insns.len());
        for k in i as usize + 1..end {
            let op = self.p.insns[k].op;
            if let Op::Jcond { cond: Cond::Eq | Cond::Ne, dst, src: Operand::Reg(src), .. } = op {
                let other = if dst == reg { src } else if src == reg { dst } else { continue };
                let Some(d) = self.def(func, k as u32, other) else { return };
                if let Op::Load { w: Width::DW, src: base, off: 0, .. } = self.p.insns[d as usize].op {
                    if base != 10 {
                        out.push(self.origin(func, d, base));
                    }
                }
                return;
            }
            if Self::writes(&op, reg) {
                return;
            }
        }
    }

    /// A `sol_memcmp_` call near `i` comparing the read-only copy in `reg` with the data.
    fn memcmp_start(&self, i: u32, reg: u8, out: &mut Vec<Start>) {
        let Some(func) = self.function_of(i) else { return };
        // `sol_memcmp_`, or a comparison the program implements itself (`starts_with` on a slice).
        let end = (i as usize + 16).min(self.p.insns.len());
        let Some(call) = (i as usize + 1..end).find(|&k| matches!(self.p.insns[k].op, Op::Call { .. })).map(|k| k as u32) else { return };
        // The data is one of the other pointer arguments; the walk tells which.
        for r in 1..=3u8 {
            let Some(d) = self.def(func, call, r) else { continue };
            let is_copy = d == i || matches!(self.p.insns[d as usize].op, Op::Alu { op: AluOp::Mov, src: Operand::Reg(s), .. } if s == reg);
            if !is_copy && !matches!(self.p.insns[d as usize].op, Op::Alu { op: AluOp::Mov, src: Operand::Imm(_), .. }) {
                out.push(self.origin(func, call, r));
            }
        }
    }

    /// 64-bit constants the code compares with the first 8 bytes of a buffer (a 64-bit load at
    /// offset 0 from a pointer other than the stack), or with 8 bytes through `sol_memcmp_`, each
    /// with the first place it is loaded. Instruction discriminators are among them, and so are
    /// account type tags and anything else compared that way; [`unnamed`] tells them apart.
    fn id_candidates(&self) -> BTreeMap<u64, u32> {
        let mut out = BTreeMap::new();
        let compared = |i: u32, reg: u8| {
            let func = self.function_of(i)?;
            let end = (i as usize + 12).min(self.p.insns.len());
            for k in i as usize + 1..end {
                let op = self.p.insns[k].op;
                if let Op::Jcond { dst, src: Operand::Reg(src), .. } = op {
                    let other = if dst == reg { src } else if src == reg { dst } else { continue };
                    let d = self.def(func, k as u32, other)?;
                    return matches!(self.p.insns[d as usize].op, Op::Load { w: Width::DW, src: base, off: 0, .. } if base != 10).then_some(());
                }
                if Self::writes(&op, reg) {
                    return None;
                }
            }
            None
        };
        for (i, x) in self.p.insns.iter().enumerate() {
            let i = i as u32;
            match x.op {
                Op::Lddw { dst, .. } => {
                    let Some(v) = self.p.lddw_value(i) else { continue };
                    if compared(i, dst).is_some() {
                        out.entry(v).or_insert(i);
                    } else if let Some(c) = self.memcmp_operand(i, dst, v) {
                        out.entry(c).or_insert(i);
                    }
                }
                // sBPF v2: mov32 low half, then hor64 high half.
                Op::Alu { op: AluOp::Hor, dst, src: Operand::Imm(hi), .. } => {
                    let lo = (i.saturating_sub(4)..i).rev().find_map(|j| match self.p.insns[j as usize].op {
                        Op::Alu { op: AluOp::Mov, wide: false, dst: d, src: Operand::Imm(lo) } if d == dst => Some(lo as u32),
                        _ => None,
                    });
                    if let Some(lo) = lo {
                        if compared(i, dst).is_some() {
                            out.entry(u64::from(lo) | (u64::from(hi as u32) << 32)).or_insert(i);
                        }
                    }
                }
                _ => {}
            }
            if out.len() >= MAX_ID_CANDIDATES {
                break;
            }
        }
        out
    }

    /// The 8 bytes at read-only address `addr`, loaded into `reg` at `i`, when a `sol_memcmp_` of
    /// 8 bytes follows that takes them.
    fn memcmp_operand(&self, i: u32, reg: u8, addr: u64) -> Option<u64> {
        let bytes = self.p.read(addr, 8)?;
        let end = (i as usize + 16).min(self.p.insns.len());
        let call = (i as usize + 1..end).find(|&k| matches!(self.p.insns[k].op, Op::Call { .. }))? as u32;
        if *self.p.call_target(call) != CallTarget::Syscall("sol_memcmp_") {
            return None;
        }
        let func = self.function_of(i)?;
        let len = self.def(func, call, 3)?;
        if !matches!(self.p.insns[len as usize].op, Op::Alu { op: AluOp::Mov, src: Operand::Imm(8), .. }) {
            return None;
        }
        let takes = (1..=2u8).any(|r| {
            self.def(func, call, r).is_some_and(|d| {
                d == i || matches!(self.p.insns[d as usize].op, Op::Alu { op: AluOp::Mov, src: Operand::Reg(s), .. } if s == reg)
            })
        });
        takes.then(|| u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// The jump at file offset `chain` (the byte-chain evidence) as an instruction index, walked back
    /// to the first byte compare of its run.
    fn chain_head(&self, chain_file_offset: u32) -> Option<u32> {
        let rel = u64::from(chain_file_offset).checked_sub(self.p.text_file_offset)?;
        self.p.index_of_slot((rel / 8) as usize)
    }
}

/// Argument layouts for the instructions in `discriminators` (name -> the 8 bytes as a little-endian
/// u64, and the instructions that load its `Instruction: <Name>` log string). `chains` finds
/// byte-wise dispatch. When no start near the dispatch works, `entries` (where the entrypoint
/// holds the data, for instructions [`unnamed`] proved) are tried before guessing. Returns the
/// layouts, and whether the program-wide budget ran out.
///
/// A layout is `complete` only when the walk reached the instruction's log string with the
/// argument bytes still reachable, and nothing it does not follow received them.
pub fn recover(
    p: &Program,
    cfg: &Cfg,
    chains: &ByteCompares,
    discriminators: &BTreeMap<String, (u64, Vec<u32>)>,
    entries: &[crate::emu::Handover],
) -> (BTreeMap<String, ArgumentLayout>, bool) {
    let finder = Finder::new(p, cfg);
    let mut out = BTreeMap::new();
    let mut spent = 0usize;
    let mut exhausted = false;
    let mut known_guess: HashMap<u32, Guess> = HashMap::new();
    for (name, (value, log_sites)) in discriminators {
        let (value, log_sites) = (*value, log_sites.as_slice());
        let d = value.to_le_bytes();
        let chain = chains.find_chain(d).and_then(|o| u32::try_from(o).ok());
        let copies: Vec<u64> = p
            .data
            .iter()
            .flat_map(|r| r.bytes.windows(8).enumerate().filter(|(_, w)| *w == d).map(move |(k, _)| r.vaddr + k as u64))
            .take(4)
            .collect();
        let mut best: Option<(usize, usize, Walk, Start)> = None;
        for start in finder.starts(value, chain, &copies).into_iter().take(MAX_STARTS) {
            if spent >= PROGRAM_BUDGET {
                exhausted = true;
                break;
            }
            let Some(f) = cfg.functions.get(&start.func) else { continue };
            let mut walk = Walk {
                p,
                cfg,
                disc: d,
                known_bytes: 0xff,
                tests: None,
                reads: BTreeSet::new(),
                copies: Vec::new(),
                checked: 0,
                matched: 0,
                matched_at: None,
                stop_on_match: false,
                sound_calls: false,
                exact_bytes: false,
                undecided: 0,
                steps: 0,
                budget: WALK_BUDGET.min(PROGRAM_BUDGET - spent),
                next_frame: 1,
                escaped: false,
                log_sites,
                reached_handler: false,
            };
            let mut st = State { regs: [V::Unknown; 11], mem: BTreeMap::new(), matched: 0 };
            st.regs[start.reg as usize] = V::Data(-start.delta);
            st.regs[10] = V::Frame(0, 0);
            let Some(&b) = cfg.block_of.get(start.at as usize) else { continue };
            let _ = walk.region(b, start.at, st, &f.blocks, 0);
            spent += walk.steps;
            // Only a walk that decided all 8 discriminator bytes went through this instruction's dispatch.
            if walk.checked != 0xff {
                continue;
            }
            let fields = walk.fields();
            let score = (fields.len(), walk.steps);
            if best.as_ref().is_none_or(|(r, s, _, _)| score > (*r, *s)) {
                best = Some((score.0, score.1, walk, start));
            }
        }
        for h in entries {
            if best.is_some() {
                break;
            }
            let (Some(f), Some(&b)) = (cfg.functions.get(&h.func), cfg.block_of.get(h.at as usize)) else { continue };
            if spent >= PROGRAM_BUDGET {
                exhausted = true;
                break;
            }
            let mut walk = Walk {
                p,
                cfg,
                disc: d,
                known_bytes: 0xff,
                tests: None,
                reads: BTreeSet::new(),
                copies: Vec::new(),
                checked: 0,
                matched: 0,
                matched_at: None,
                stop_on_match: false,
                sound_calls: false,
                exact_bytes: false,
                undecided: 0,
                steps: 0,
                budget: WALK_BUDGET.min(PROGRAM_BUDGET - spent),
                next_frame: 1,
                escaped: false,
                log_sites,
                reached_handler: false,
            };
            let _ = walk.region(b, h.at, handover_state(h), &f.blocks, 0);
            spent += walk.steps;
            if walk.checked == 0xff {
                let site = walk.matched_at.unwrap_or(h.at);
                let fields = walk.fields();
                best = Some((fields.len(), walk.steps, walk, Start { func: h.func, at: h.at, reg: 0, delta: 0, site }));
            }
        }
        // When no traced start works, start at the entry of each function that tests the discriminator
        // with the data pointer in each argument register in turn, or in one of the caller's stack
        // argument slots. Deciding all 8 bytes is what shows a guess was right; a guess that worked
        // for another instruction of the same function is tried first.
        if best.is_none() {
            for func in finder.testing_functions(value, chain, &copies) {
                let Some(f) = cfg.functions.get(&func) else { continue };
                let mut guesses: Vec<Guess> = (1..=5).map(Guess::Reg).chain([Guess::Stack(-4096), Guess::Stack(-4088)]).collect();
                if let Some(&g) = known_guess.get(&func) {
                    guesses.retain(|x| *x != g);
                    guesses.insert(0, g);
                }
                for guess in guesses {
                    if spent >= PROGRAM_BUDGET {
                        exhausted = true;
                        break;
                    }
                    let mut walk = Walk {
                        p,
                        cfg,
                        disc: d,
                        known_bytes: 0xff,
                        tests: None,
                        reads: BTreeSet::new(),
                        copies: Vec::new(),
                        checked: 0,
                        matched: 0,
                        matched_at: None,
                        stop_on_match: false,
                        sound_calls: false,
                        exact_bytes: false,
                        undecided: 0,
                        steps: 0,
                        budget: GUESS_BUDGET.min(PROGRAM_BUDGET - spent),
                        next_frame: 2,
                        escaped: false,
                        log_sites,
                        reached_handler: false,
                    };
                    let mut st = State { regs: [V::Unknown; 11], mem: BTreeMap::new(), matched: 0 };
                    st.regs[10] = V::Frame(0, 0);
                    match guess {
                        Guess::Reg(r) => st.regs[r as usize] = V::Data(0),
                        Guess::Stack(o) => {
                            st.regs[5] = V::Frame(1, 0);
                            st.mem.insert((1, o), Slot::Whole(V::Data(0)));
                        }
                    }
                    let _ = walk.region(f.entry, cfg.blocks[f.entry as usize].start, st, &f.blocks, 0);
                    spent += walk.steps;
                    if walk.checked == 0xff {
                        known_guess.insert(func, guess);
                        let fields = walk.fields();
                        let start = Start { func, at: func, reg: 0, delta: 0, site: func };
                        if best.as_ref().is_none_or(|(r, s, _, _)| (fields.len(), walk.steps) > (*r, *s)) {
                            best = Some((fields.len(), walk.steps, walk, start));
                        }
                        break;
                    }
                }
                if best.is_some() {
                    break;
                }
            }
        }
        if let Some((_, _, walk, start)) = best {
            let (fields, irregular) = layout(&walk.fields());
            let fixed_size = fields.last().map_or(0, |f| f.offset + f.size);
            out.insert(
                name.clone(),
                ArgumentLayout {
                    fields,
                    fixed_size,
                    irregular,
                    complete: !walk.escaped && !walk.exhausted() && (walk.reached_handler || log_sites.is_empty()),
                    dispatch_offset: p.file_offset(start.site),
                    truncated: walk.exhausted(),
                },
            );
        }
    }
    (out, exhausted)
}

/// What an equality test of discriminator bytes told discovery.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Test {
    /// Not a test of unknown discriminator bytes against a number.
    None,
    /// Recorded: the bytes it covers may equal the number.
    Recorded,
    /// A known byte already differs from the number.
    Unequal,
    /// On a path where the known bytes did not all match: not followed.
    OffPath,
}

/// Syscalls that write nothing on the caller's stack.
const READ_ONLY_SYSCALLS: &[&str] = &[
    "abort",
    "sol_panic_",
    "sol_log_",
    "sol_log_64_",
    "sol_log_pubkey",
    "sol_log_compute_units_",
    "sol_log_data",
    "sol_set_return_data",
    "sol_invoke_signed_c",
    "sol_invoke_signed_rust",
];

/// Forget the stack slots a call may have written: at or above each stack address among `args`,
/// in that address's frame.
fn clobber(s: &mut State, args: &[V]) {
    for v in args {
        if let V::Frame(f, o) = *v {
            s.mem.retain(|(ff, oo), _| *ff != f || *oo + 8 <= o);
        }
    }
}

/// Whether 8 bytes can be an identifier rather than a number: at most two of them are 0x00 or
/// 0xff, which hashes and ASCII tags satisfy and amounts, limits and masks do not.
fn looks_like_id(v: u64) -> bool {
    v.to_le_bytes().iter().filter(|&&b| b == 0 || b == 0xff).count() <= 2
}

/// The walk state at a handover: the data pointer where the entrypoint holds it, nothing else known.
fn handover_state(h: &crate::emu::Handover) -> State {
    let mut st = State { regs: [V::Unknown; 11], mem: BTreeMap::new(), matched: 0 };
    st.regs[10] = V::Frame(0, 0);
    for &(r, k) in &h.regs {
        st.regs[r as usize] = V::Data(k);
    }
    for &(o, k) in &h.slots {
        if o % 8 == 0 {
            st.mem.insert((0, o), Slot::Whole(V::Data(k)));
        }
    }
    for &(r, o) in &h.frame_regs {
        st.regs[r as usize] = V::Frame(0, o);
    }
    for &(o, f) in &h.frame_slots {
        if o % 8 == 0 {
            st.mem.insert((0, o), Slot::Whole(V::Frame(0, f)));
        }
    }
    st
}

/// Instruction discriminators found without a name: values the program tests the first 8 bytes of
/// its instruction data against, as its own entrypoint delivers the data (`hs`, nearest the
/// dispatch first).
///
/// Discovery walks from each handover with those bytes unknown and records every equality test of
/// them against a constant, following only the not-equal side; fixing the bytes a test covers and
/// walking again goes one level down a byte-wise decision tree. Every value found that way, and
/// every 64-bit constant compared with the first 8 bytes of any buffer, is then tried as the data's
/// first 8 bytes. It counts only when, on one path, equality tests find all 8 bytes equal to what
/// they test them against: bytes keep their positions through shifts and masks, so a test of one
/// byte proves one byte, and a call the walk does not follow is assumed to overwrite the stack it
/// is handed. A constant compared with an account's data never meets that. Returns the
/// discriminators (as little-endian u64s) with the comparison where the last byte matched, and
/// whether a budget ran out.
pub fn unnamed(p: &Program, cfg: &Cfg, hs: &[crate::emu::Handover], known: &BTreeSet<u64>) -> (Vec<(u64, u32)>, bool) {
    let finder = Finder::new(p, cfg);
    let starts: Vec<(&[BlockId], BlockId, u32, State)> = hs
        .iter()
        .filter_map(|h| Some((cfg.functions.get(&h.func)?.blocks.as_slice(), *cfg.block_of.get(h.at as usize)?, h.at, handover_state(h))))
        .collect();
    if starts.is_empty() {
        return (Vec::new(), false);
    }
    let walk_from = |s: usize, disc: [u8; 8], known_bytes: u8, tests: bool, budget: usize| {
        let (blocks, b, at, st) = &starts[s];
        let mut walk = Walk {
            p,
            cfg,
            disc,
            known_bytes,
            tests: tests.then(BTreeSet::new),
            reads: BTreeSet::new(),
            copies: Vec::new(),
            checked: 0,
            matched: 0,
            matched_at: None,
            stop_on_match: !tests,
            sound_calls: true,
            exact_bytes: true,
            undecided: 0,
            steps: 0,
            budget,
            next_frame: 1,
            escaped: false,
            log_sites: &[],
            reached_handler: false,
        };
        let _ = walk.region(*b, *at, st.clone(), blocks, 0);
        walk
    };
    let mut spent = 0usize;
    let mut exhausted = false;
    // Each candidate with the starts to try it from: the constants from the start nearest the
    // dispatch, what discovery finds from the start it was found from.
    let mut candidates: BTreeMap<u64, (u32, Vec<usize>)> = finder.id_candidates().into_iter().map(|(v, site)| (v, (site, vec![0]))).collect();
    for s in 0..starts.len() {
        let mut queue: Vec<([u8; 8], u8)> = vec![([0; 8], 0)];
        let mut seen: BTreeSet<([u8; 8], u8)> = BTreeSet::new();
        let mut walks = 0usize;
        while let Some((bytes, mask)) = queue.pop() {
            if spent >= DISCOVERY_BUDGET || walks >= MAX_DISCOVERY_WALKS {
                exhausted = true;
                break;
            }
            walks += 1;
            let walk = walk_from(s, bytes, mask, true, DISCOVERY_WALK_BUDGET.min(DISCOVERY_BUDGET - spent));
            spent += walk.steps;
            // A walk below the first level that runs out has gone past the dispatch into code that
            // reads arguments (a handler, in a program whose tag is shorter than 8 bytes), so its
            // tests are not followed further down.
            let descend = mask == 0 || !walk.exhausted();
            for (k, n, v) in walk.tests.unwrap_or_default() {
                let mut next = bytes;
                let mut next_mask = mask;
                let mut consistent = true;
                for i in 0..n as usize {
                    let (at, byte) = (k as usize + i, (v >> (8 * i)) as u8);
                    if mask & (1 << at) != 0 {
                        consistent &= bytes[at] == byte;
                    }
                    next[at] = byte;
                    next_mask |= 1 << at;
                }
                if !consistent || next_mask == mask {
                    continue;
                }
                if next_mask == 0xff {
                    let (_, from) = candidates.entry(u64::from_le_bytes(next)).or_insert((starts[s].2, Vec::new()));
                    if !from.contains(&s) {
                        from.push(s);
                    }
                } else if descend && seen.insert((next, next_mask)) {
                    queue.push((next, next_mask));
                }
            }
        }
    }
    let mut out = Vec::new();
    'candidates: for (value, (site, from)) in candidates {
        if known.contains(&value) || !looks_like_id(value) {
            continue;
        }
        for s in from {
            if spent >= UNNAMED_BUDGET {
                return (out, true);
            }
            let walk = walk_from(s, value.to_le_bytes(), 0xff, false, WALK_BUDGET.min(UNNAMED_BUDGET - spent));
            spent += walk.steps;
            if walk.matched == 0xff {
                out.push((value, walk.matched_at.unwrap_or(site)));
                continue 'candidates;
            }
        }
    }
    (out, exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_bytes_keep_their_discriminator_provenance() {
        let mut s = State { regs: [V::Unknown; 11], mem: BTreeMap::new(), matched: 0 };
        // The 8 discriminator bytes stored whole, then read back one byte at a time.
        s.store(0, -8, 8, V::Disc(0x0807_0605_0403_0201, 0xff));
        assert_eq!(s.load(0, -6, 1), V::Disc(0x03, 1 << 2));
        // Two bytes overwritten with a constant keep the rest.
        s.store(0, -8, 2, V::Const(0xaaaa));
        assert_eq!(s.load(0, -8, 4), V::Disc(0x0403_aaaa, 0b1100));
        // A pointer is only read back whole.
        s.store(0, -16, 8, V::Data(8));
        assert_eq!(s.load(0, -16, 8), V::Data(8));
        assert_eq!(s.load(0, -16, 4), V::Unknown);
    }

    #[test]
    fn byte_mask_follows_contiguous_runs() {
        assert_eq!(byte_mask(0xff, 3), 1 << 3);
        assert_eq!(byte_mask(0b1100, 1), 1 << 3);
        assert_eq!(byte_mask(0b1010, 0), 0b1010, "a derived value keeps its whole mask");
    }

    #[test]
    fn layout_merges_and_flags_gaps() {
        let reads = [(8, 8, false), (16, 1, false), (17, 32, true)];
        let (fields, irregular) = layout(&reads);
        assert_eq!(
            fields,
            vec![
                ArgumentField { offset: 0, size: 8, copied: false },
                ArgumentField { offset: 8, size: 1, copied: false },
                ArgumentField { offset: 9, size: 32, copied: true }
            ]
        );
        assert!(!irregular);
        // A read that runs past the one before it, or a gap, makes the layout uncertain.
        assert!(layout(&[(8, 8, false), (12, 8, false)]).1);
        assert!(layout(&[(8, 8, false), (20, 4, false)]).1);
    }
}
