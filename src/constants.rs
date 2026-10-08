//! 64-bit immediates loaded by the program's code.
//!
//! Discriminators and other 8-byte tags are usually compared against a register
//! that was loaded with a 64-bit immediate. sBPF v0 and v1 load those with the
//! two-slot `lddw`; v2 removed `lddw` (SIMD-0173), so compilers build the value
//! with `mov32` for the low half and `hor64` for the high half.

use crate::report::EvidenceKind;

const OP_LDDW: u8 = 0x18;
const OP_MOV32_IMM: u8 = 0xb4;
const OP_HOR64_IMM: u8 = 0xf7;
/// How many instruction slots back a `hor64` may look for its `mov32`.
const MOV32_WINDOW: usize = 4;

/// One 64-bit immediate and where its loading instruction sits in the file.
#[derive(Debug, Clone, Copy)]
pub struct Constant {
    pub value: u64,
    pub file_offset: u64,
    pub kind: EvidenceKind,
}

/// Scan `.text` for 64-bit immediates. `text_file_offset` is the section's file offset.
pub fn scan(text: &[u8], text_file_offset: u64, sbpf_version: u32) -> Vec<Constant> {
    if sbpf_version >= 2 {
        scan_mov32_hor64(text, text_file_offset)
    } else {
        scan_lddw(text, text_file_offset)
    }
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
