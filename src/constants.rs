//! 64-bit immediates loaded by the program's code.
//!
//! Discriminators and other 8-byte tags are usually compared against a register
//! that was loaded with a 64-bit immediate. Most programs load those with the
//! two-slot `lddw`, including sBPF v3 programs on mainnet. sBPF v2 removed
//! `lddw` (SIMD-0173), and compilers targeting it build the value with `mov32`
//! for the low half and `hor64` for the high half, so v2 and later are scanned
//! for both shapes.

use crate::report::{EvidenceKind, ImmediateUse};

const OP_LDDW: u8 = 0x18;
const OP_MOV32_IMM: u8 = 0xb4;
const OP_HOR64_IMM: u8 = 0xf7;
/// How many instruction slots back a `hor64` may look for its `mov32`.
const MOV32_WINDOW: usize = 4;
/// How many instruction slots after a load are searched for the value's first use.
const USE_WINDOW: usize = 8;

/// One 64-bit immediate and where its loading instruction sits in the file.
#[derive(Debug, Clone, Copy)]
pub struct Constant {
    pub value: u64,
    pub file_offset: u64,
    pub kind: EvidenceKind,
    /// What the code does first with the loaded register.
    pub use_after_load: ImmediateUse,
}

/// First use of register `reg` in the instructions starting at `from`.
///
/// A conditional jump that reads it is a comparison, as in instruction
/// dispatch; a register store of it writes the value to memory, as when
/// building instruction data for a call to another program. Any other write
/// to the register ends the search.
fn first_use(text: &[u8], from: usize, reg: u8) -> ImmediateUse {
    for insn in text.get(from..).unwrap_or(&[]).chunks_exact(8).take(USE_WINDOW) {
        let opcode = insn[0];
        let dst = insn[1] & 0x0f;
        let src = insn[1] >> 4;
        let class = opcode & 0x07;
        let reads_src = opcode & 0x08 != 0;
        match class {
            // jmp and jmp32, excluding ja, call, callx and exit/return.
            0x05 | 0x06 if !matches!(opcode, 0x05 | 0x85 | 0x8d | 0x95 | 0x9d) => {
                if dst == reg || (reads_src && src == reg) {
                    return ImmediateUse::Compare;
                }
            }
            // stx: store register `src` to memory.
            0x03 if src == reg => return ImmediateUse::Store,
            // alu, alu64, ld, ldx: anything that writes `reg` replaces the value.
            0x00 | 0x01 | 0x04 | 0x07 if dst == reg => return ImmediateUse::Other,
            _ => {}
        }
    }
    ImmediateUse::Other
}

const OP_JEQ_IMM: u8 = 0x15;
const OP_JNE_IMM: u8 = 0x55;
/// How many instructions after one byte comparison the next one may sit.
const CHAIN_GAP: usize = 16;

/// Conditional jumps that compare a register with one byte (`jeq`/`jne` with an
/// immediate from 0 to 255), indexed for discriminator lookups.
///
/// Older Anchor versions compile instruction dispatch to a byte-wise decision
/// tree: a switch on the first discriminator bytes, then a chain of
/// comparisons against the remaining bytes, one at a time. The tree can share
/// the first two bytes between instructions, so a chain is matched on bytes 2
/// to 7: six comparisons in order, each within [`CHAIN_GAP`] instructions of
/// the previous one.
#[derive(Debug, Default)]
pub struct ByteCompares {
    /// The compared byte at each instruction position, if that instruction is a byte comparison.
    byte_at: Vec<Option<u8>>,
    file_offset: Vec<u64>,
    by_byte: Vec<Vec<usize>>,
}

impl ByteCompares {
    pub fn scan(text: &[u8], text_file_offset: u64) -> Self {
        let mut out = ByteCompares { by_byte: vec![Vec::new(); 256], ..Default::default() };
        let mut pos = 0usize;
        while pos + 8 <= text.len() {
            let opcode = text[pos];
            let imm = i32::from_le_bytes([text[pos + 4], text[pos + 5], text[pos + 6], text[pos + 7]]);
            let byte = (matches!(opcode, OP_JEQ_IMM | OP_JNE_IMM) && (0..=255).contains(&imm)).then_some(imm as u8);
            if let Some(b) = byte {
                out.by_byte[usize::from(b)].push(out.byte_at.len());
            }
            out.byte_at.push(byte);
            out.file_offset.push(text_file_offset + pos as u64);
            pos += if opcode == OP_LDDW { 16 } else { 8 };
        }
        out
    }

    pub fn len(&self) -> usize {
        self.by_byte.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// File offset of the first comparison of a chain over bytes 2 to 7 of `value`, if there is one.
    pub fn find_chain(&self, value: [u8; 8]) -> Option<u64> {
        for &start in self.by_byte.get(usize::from(value[2]))? {
            let mut at = start;
            let complete = value[3..].iter().all(|&b| {
                let next = (at + 1..=at + CHAIN_GAP).take_while(|&k| k < self.byte_at.len()).find(|&k| self.byte_at[k] == Some(b));
                next.inspect(|&k| at = k).is_some()
            });
            if complete {
                return Some(self.file_offset[start]);
            }
        }
        None
    }
}

/// Scan `.text` for 64-bit immediates. `text_file_offset` is the section's file offset.
pub fn scan(text: &[u8], text_file_offset: u64, sbpf_version: u32) -> Vec<Constant> {
    let mut out = scan_lddw(text, text_file_offset);
    if sbpf_version >= 2 {
        out.extend(scan_mov32_hor64(text, text_file_offset));
    }
    out
}

fn scan_lddw(text: &[u8], base: u64) -> Vec<Constant> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= text.len() {
        if text[pos] == OP_LDDW && pos + 16 <= text.len() {
            let lo = u32::from_le_bytes([text[pos + 4], text[pos + 5], text[pos + 6], text[pos + 7]]);
            let hi = u32::from_le_bytes([text[pos + 12], text[pos + 13], text[pos + 14], text[pos + 15]]);
            out.push(Constant {
                value: (u64::from(hi) << 32) | u64::from(lo),
                file_offset: base + pos as u64,
                kind: EvidenceKind::LddwImmediate,
                use_after_load: first_use(text, pos + 16, text[pos + 1] & 0x0f),
            });
            pos += 16;
        } else {
            pos += 8;
        }
    }
    out
}

fn scan_mov32_hor64(text: &[u8], base: u64) -> Vec<Constant> {
    let mut out = Vec::new();
    // (slot index, destination register, low 32 bits) of recent mov32 immediates.
    let mut recent: Vec<(usize, u8, u32)> = Vec::new();
    for (slot, insn) in text.chunks_exact(8).enumerate() {
        let opcode = insn[0];
        let dst = insn[1] & 0x0f;
        let imm = u32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
        recent.retain(|(s, _, _)| slot - s <= MOV32_WINDOW);
        if opcode == OP_HOR64_IMM {
            if let Some(&(mov_slot, _, lo)) = recent.iter().rev().find(|(_, d, _)| *d == dst) {
                out.push(Constant {
                    value: (u64::from(imm) << 32) | u64::from(lo),
                    file_offset: base + (mov_slot * 8) as u64,
                    kind: EvidenceKind::Mov32Hor64Immediate,
                    use_after_load: first_use(text, (slot + 1) * 8, dst),
                });
            }
        }
        if opcode == OP_MOV32_IMM {
            recent.push((slot, dst, imm));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lddw_combines_both_slots() {
        // lddw r1, 0x1122334455667788 ; exit
        let text = [
            0x18, 0x01, 0, 0, 0x88, 0x77, 0x66, 0x55, //
            0x00, 0x00, 0, 0, 0x44, 0x33, 0x22, 0x11, //
            0x95, 0x00, 0, 0, 0, 0, 0, 0,
        ];
        let found = scan(&text, 0x100, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, 0x1122_3344_5566_7788);
        assert_eq!(found[0].file_offset, 0x100);
    }

    #[test]
    fn lddw_is_scanned_on_v3_too() {
        // sBPF v3 mainnet programs still use lddw; a v3 program must not lose it.
        let text = [
            0x18, 0x06, 0, 0, 0x52, 0xfb, 0xe9, 0x9c, //
            0x00, 0x00, 0, 0, 0x0c, 0x34, 0xb8, 0xca,
        ];
        let found = scan(&text, 0, 3);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value.to_le_bytes(), [0x52, 0xfb, 0xe9, 0x9c, 0x0c, 0x34, 0xb8, 0xca]);
    }

    #[test]
    fn first_use_tells_dispatch_from_outgoing_calls() {
        // lddw r6, X ; jeq r0, r6, +3   -> compared, as in dispatch
        let compare = [
            0x18, 0x06, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            0x1d, 0x60, 3, 0, 0, 0, 0, 0,
        ];
        assert_eq!(scan(&compare, 0, 0)[0].use_after_load, ImmediateUse::Compare);
        // lddw r1, X ; stxdw [r10-16], r1   -> stored, as when building a call
        let store = [
            0x18, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            0x7b, 0x1a, 0xf0, 0xff, 0, 0, 0, 0,
        ];
        assert_eq!(scan(&store, 0, 0)[0].use_after_load, ImmediateUse::Store);
        // lddw r1, X ; mov64 r1, 0   -> overwritten before use
        let overwritten = [
            0x18, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            0xb7, 0x01, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(scan(&overwritten, 0, 0)[0].use_after_load, ImmediateUse::Other);
    }

    fn jump(opcode: u8, imm: u8) -> [u8; 8] {
        [opcode, 0x03, 0x10, 0x00, imm, 0, 0, 0]
    }

    #[test]
    fn byte_chain_follows_byte_wise_dispatch() {
        // Bytes 2..7 compared in order with a load between each, as older Anchor dispatch does.
        let value = [0xd3, 0x16, 0xdd, 0xfb, 0x4a, 0x79, 0xc1, 0x2f];
        let mut text = Vec::new();
        for (k, &b) in value[2..].iter().enumerate() {
            text.extend_from_slice(&[0x79, 0x34, 0, 0, 0, 0, 0, 0]); // ldxdw r4, [r3]
            text.extend_from_slice(&jump(if k == 5 { OP_JEQ_IMM } else { OP_JNE_IMM }, b));
        }
        let chains = ByteCompares::scan(&text, 0x200);
        assert_eq!(chains.find_chain(value), Some(0x208));
        let mut other = value;
        other[5] ^= 1;
        assert_eq!(chains.find_chain(other), None, "every byte from 2 to 7 must be compared");
        let mut out_of_order = value;
        out_of_order.swap(3, 4);
        assert_eq!(chains.find_chain(out_of_order), None, "the bytes must be compared in order");
    }

    #[test]
    fn mov32_hor64_pairs_by_register() {
        // mov32 r2, 0x55667788 ; mov32 r3, 1 ; hor64 r2, 0x11223344
        let text = [
            0xb4, 0x02, 0, 0, 0x88, 0x77, 0x66, 0x55, //
            0xb4, 0x03, 0, 0, 0x01, 0x00, 0x00, 0x00, //
            0xf7, 0x02, 0, 0, 0x44, 0x33, 0x22, 0x11,
        ];
        let found = scan(&text, 0, 2);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, 0x1122_3344_5566_7788);
        assert_eq!(found[0].file_offset, 0);
    }
}
