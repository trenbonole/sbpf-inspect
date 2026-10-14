//! sBPF instruction decoding for every deployable version.
//!
//! The same opcode byte means different things in different versions, so the version (the ELF
//! `e_flags`) picks the table before anything is decoded:
//!
//! * v0 and v1: the classic encoding. v1 only adds dynamic stack frames (`add64 r10, imm`).
//! * v2 (SIMD-0173/0174): `lddw` and `le` are gone, memory operations moved into the ALU opcode
//!   space, `hor64` builds the upper half of 64-bit constants, multiply/divide/remainder moved to
//!   the PQR class, and `callx` takes its register from `src`.
//! * v3 (SIMD-0377/0178/0189): back to the classic encoding, plus the JMP32 class; calls with
//!   `src = 0` are syscalls named by a murmur3 hash and `src = 1` are relative calls.
//!
//! `exit` is 0x95; 0x9d (`return`) is accepted as the same thing in every version.

pub const SLOT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    B,
    H,
    W,
    DW,
}

impl Width {
    pub fn bytes(self) -> u32 {
        match self {
            Width::B => 1,
            Width::H => 2,
            Width::W => 4,
            Width::DW => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Imm(i32),
    Reg(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Neg,
    Mod,
    Xor,
    Mov,
    Arsh,
    Le,
    Be,
    Hor,
    Uhmul,
    Udiv,
    Urem,
    Lmul,
    Shmul,
    Sdiv,
    Srem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    Eq,
    Gt,
    Ge,
    Set,
    Ne,
    Sgt,
    Sge,
    Lt,
    Le,
    Slt,
    Sle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lddw { dst: u8, imm: u64 },
    Load { w: Width, dst: u8, src: u8, off: i16 },
    StoreImm { w: Width, dst: u8, off: i16, imm: i32 },
    StoreReg { w: Width, dst: u8, src: u8, off: i16 },
    Alu { wide: bool, op: AluOp, dst: u8, src: Operand },
    Ja { off: i16 },
    Jcond { cond: Cond, wide: bool, dst: u8, src: Operand, off: i16 },
    Call { src: u8, imm: i32 },
    Callx { reg: u8 },
    Exit,
    Invalid { opcode: u8, why: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct Insn {
    /// Slot index from the start of the text: one slot is 8 bytes.
    pub pc: u32,
    /// 1, or 2 for `lddw`.
    pub slots: u8,
    pub opcode: u8,
    pub op: Op,
}

impl Insn {
    pub fn next_pc(&self) -> u32 {
        self.pc.saturating_add(self.slots as u32)
    }
    /// Target of a jump, as a slot index (may be out of range for a malformed program).
    pub fn jump_target(&self) -> Option<i64> {
        match self.op {
            Op::Ja { off } | Op::Jcond { off, .. } => Some(self.pc as i64 + off as i64 + 1),
            _ => None,
        }
    }
    pub fn is_branch(&self) -> bool {
        matches!(self.op, Op::Ja { .. } | Op::Jcond { .. })
    }
}

fn reg_ok(r: u8) -> bool {
    r <= 10
}

fn width_classic(op: u8) -> Width {
    match op & 0x18 {
        0x00 => Width::W,
        0x08 => Width::H,
        0x10 => Width::B,
        _ => Width::DW,
    }
}

fn alu_classic(code: u8) -> Option<AluOp> {
    Some(match code {
        0x00 => AluOp::Add,
        0x10 => AluOp::Sub,
        0x20 => AluOp::Mul,
        0x30 => AluOp::Div,
        0x40 => AluOp::Or,
        0x50 => AluOp::And,
        0x60 => AluOp::Lsh,
        0x70 => AluOp::Rsh,
        0x80 => AluOp::Neg,
        0x90 => AluOp::Mod,
        0xa0 => AluOp::Xor,
        0xb0 => AluOp::Mov,
        0xc0 => AluOp::Arsh,
        _ => return None,
    })
}

fn cond_of(code: u8) -> Option<Cond> {
    Some(match code {
        0x10 => Cond::Eq,
        0x20 => Cond::Gt,
        0x30 => Cond::Ge,
        0x40 => Cond::Set,
        0x50 => Cond::Ne,
        0x60 => Cond::Sgt,
        0x70 => Cond::Sge,
        0xa0 => Cond::Lt,
        0xb0 => Cond::Le,
        0xc0 => Cond::Slt,
        0xd0 => Cond::Sle,
        _ => return None,
    })
}

fn pqr(code: u8) -> Option<(AluOp, bool)> {
    Some(match code {
        0x30 => (AluOp::Uhmul, true),
        0x40 => (AluOp::Udiv, false),
        0x50 => (AluOp::Udiv, true),
        0x60 => (AluOp::Urem, false),
        0x70 => (AluOp::Urem, true),
        0x80 => (AluOp::Lmul, false),
        0x90 => (AluOp::Lmul, true),
        0xb0 => (AluOp::Shmul, true),
        0xc0 => (AluOp::Sdiv, false),
        0xd0 => (AluOp::Sdiv, true),
        0xe0 => (AluOp::Srem, false),
        0xf0 => (AluOp::Srem, true),
        _ => return None,
    })
}

fn invalid(opcode: u8, why: &'static str) -> Op {
    Op::Invalid { opcode, why }
}

/// Decode one instruction at slot `pc`. `next` is the following slot, for `lddw`.
pub fn decode(version: u32, pc: u32, slot: &[u8; 8], next: Option<&[u8; 8]>) -> Insn {
    let opcode = slot[0];
    let dst = slot[1] & 0x0f;
    let src = slot[1] >> 4;
    let off = i16::from_le_bytes([slot[2], slot[3]]);
    let imm = i32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]);
    let v2 = version == 2;
    let jmp32 = version >= 3;
    let operand = if opcode & 0x08 != 0 { Operand::Reg(src) } else { Operand::Imm(imm) };
    let mut slots = 1u8;

    let op = 'op: {
        if !reg_ok(dst) || (opcode & 0x08 != 0 && !reg_ok(src)) {
            break 'op invalid(opcode, "register out of range");
        }
        // lddw (not in v2)
        if opcode == 0x18 {
            if v2 {
                break 'op invalid(opcode, "lddw does not exist in sBPF v2");
            }
            let Some(n) = next else { break 'op invalid(opcode, "lddw at the end of the text") };
            slots = 2;
            let hi = u32::from_le_bytes([n[4], n[5], n[6], n[7]]);
            break 'op Op::Lddw { dst, imm: (u64::from(hi) << 32) | u64::from(imm as u32) };
        }
        let class = opcode & 0x07;
        if v2 {
            // Memory operations live in the ALU opcode space in v2.
            let mem = match opcode {
                0x2c => Some((Width::B, 'l')),
                0x3c => Some((Width::H, 'l')),
                0x8c => Some((Width::W, 'l')),
                0x9c => Some((Width::DW, 'l')),
                0x27 => Some((Width::B, 'i')),
                0x37 => Some((Width::H, 'i')),
                0x87 => Some((Width::W, 'i')),
                0x97 => Some((Width::DW, 'i')),
                0x2f => Some((Width::B, 'r')),
                0x3f => Some((Width::H, 'r')),
                0x8f => Some((Width::W, 'r')),
                0x9f => Some((Width::DW, 'r')),
                _ => None,
            };
            if let Some((w, kind)) = mem {
                break 'op match kind {
                    'l' => Op::Load { w, dst, src, off },
                    'i' => Op::StoreImm { w, dst, off, imm },
                    _ => Op::StoreReg { w, dst, src, off },
                };
            }
            if class == 0x06 {
                match pqr(opcode & 0xf0) {
                    Some((op, wide)) => break 'op Op::Alu { wide, op, dst, src: operand },
                    None => break 'op invalid(opcode, "unknown PQR opcode"),
                }
            }
            if opcode == 0xf7 {
                break 'op Op::Alu { wide: true, op: AluOp::Hor, dst, src: Operand::Imm(imm) };
            }
        }
        match class {
            0x01 | 0x02 | 0x03 if !v2 => {
                if opcode & 0xe0 != 0x60 {
                    break 'op invalid(opcode, "unsupported memory addressing mode");
                }
                let w = width_classic(opcode);
                match class {
                    0x01 => Op::Load { w, dst, src, off },
                    0x02 => Op::StoreImm { w, dst, off, imm },
                    _ => Op::StoreReg { w, dst, src, off },
                }
            }
            0x04 | 0x07 => {
                let wide = class == 0x07;
                let code = opcode & 0xf0;
                if code == 0xd0 {
                    // le / be, 32-bit class only; le is gone in v2
                    if wide {
                        break 'op invalid(opcode, "byte swap is in the 32-bit ALU class");
                    }
                    let op = if opcode & 0x08 != 0 { AluOp::Be } else { AluOp::Le };
                    if op == AluOp::Le && v2 {
                        break 'op invalid(opcode, "le does not exist in sBPF v2");
                    }
                    if !matches!(imm, 16 | 32 | 64) {
                        break 'op invalid(opcode, "byte swap width must be 16, 32 or 64");
                    }
                    break 'op Op::Alu { wide: true, op, dst, src: Operand::Imm(imm) };
                }
                let Some(op) = alu_classic(code) else { break 'op invalid(opcode, "unknown ALU operation") };
                if v2 && matches!(op, AluOp::Mul | AluOp::Div | AluOp::Mod | AluOp::Neg) {
                    break 'op invalid(opcode, "mul/div/mod/neg moved to the PQR class in sBPF v2");
                }
                Op::Alu { wide, op, dst, src: operand }
            }
            0x05 => match opcode {
                0x05 => Op::Ja { off },
                0x85 => Op::Call { src, imm },
                0x8d => {
                    // callx register: imm (v0/v1), src (v2), dst (v3)
                    let reg = match version {
                        0 | 1 => imm as u8,
                        2 => src,
                        _ => {
                            if dst != 0 { dst } else { src }
                        }
                    };
                    if !reg_ok(reg) {
                        break 'op invalid(opcode, "callx register out of range");
                    }
                    Op::Callx { reg }
                }
                0x95 | 0x9d => Op::Exit,
                _ => match cond_of(opcode & 0xf0) {
                    Some(cond) => Op::Jcond { cond, wide: true, dst, src: operand, off },
                    None => invalid(opcode, "unknown jump"),
                },
            },
            0x06 if jmp32 => match cond_of(opcode & 0xf0) {
                Some(cond) => Op::Jcond { cond, wide: false, dst, src: operand, off },
                None => invalid(opcode, "unknown 32-bit jump"),
            },
            _ => invalid(opcode, "unknown opcode for this sBPF version"),
        }
    };
    Insn { pc, slots, opcode, op }
}

/// Decode a whole text section. Returns the instructions and, per slot, the index of the
/// instruction starting there (`u32::MAX` for the second slot of `lddw`).
pub fn decode_all(version: u32, text: &[u8], max_insns: usize) -> (Vec<Insn>, Vec<u32>) {
    let n_slots = text.len() / SLOT;
    let mut insns = Vec::with_capacity(n_slots.min(max_insns));
    let mut slot_index = vec![u32::MAX; n_slots];
    let mut pc = 0usize;
    let slot_at = |i: usize| -> Option<&[u8; 8]> { text.get(i * SLOT..i * SLOT + SLOT).and_then(|s| s.try_into().ok()) };
    while pc < n_slots && insns.len() < max_insns {
        let Some(slot) = slot_at(pc) else { break };
        let insn = decode(version, pc as u32, slot, slot_at(pc + 1));
        slot_index[pc] = insns.len() as u32;
        pc += insn.slots as usize;
        insns.push(insn);
    }
    (insns, slot_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(version: u32, bytes: [u8; 8]) -> Op {
        decode(version, 0, &bytes, None).op
    }

    #[test]
    fn same_byte_differs_by_version() {
        // 0x2c: mul32 reg in v0/v3, ldxb in v2.
        let b = [0x2c, 0x21, 0x08, 0x00, 0, 0, 0, 0];
        assert_eq!(d(0, b), Op::Alu { wide: false, op: AluOp::Mul, dst: 1, src: Operand::Reg(2) });
        assert_eq!(d(2, b), Op::Load { w: Width::B, dst: 1, src: 2, off: 8 });
        assert_eq!(d(3, b), Op::Alu { wide: false, op: AluOp::Mul, dst: 1, src: Operand::Reg(2) });
        // 0x36: uhmul64 imm in v2, jge32 imm in v3, invalid in v0.
        let b = [0x36, 0x01, 0x02, 0x00, 7, 0, 0, 0];
        assert_eq!(d(2, b), Op::Alu { wide: true, op: AluOp::Uhmul, dst: 1, src: Operand::Imm(7) });
        assert_eq!(d(3, b), Op::Jcond { cond: Cond::Ge, wide: false, dst: 1, src: Operand::Imm(7), off: 2 });
        assert!(matches!(d(0, b), Op::Invalid { .. }));
    }

    #[test]
    fn lddw_takes_two_slots_and_not_in_v2() {
        let a = [0x18, 0x01, 0, 0, 0x88, 0x77, 0x66, 0x55];
        let b = [0, 0, 0, 0, 0x44, 0x33, 0x22, 0x11];
        let i = decode(0, 0, &a, Some(&b));
        assert_eq!(i.slots, 2);
        assert_eq!(i.op, Op::Lddw { dst: 1, imm: 0x1122_3344_5566_7788 });
        assert!(matches!(decode(2, 0, &a, Some(&b)).op, Op::Invalid { .. }));
    }

    #[test]
    fn callx_register_field_moves() {
        assert_eq!(d(0, [0x8d, 0x00, 0, 0, 5, 0, 0, 0]), Op::Callx { reg: 5 });
        assert_eq!(d(2, [0x8d, 0x50, 0, 0, 0, 0, 0, 0]), Op::Callx { reg: 5 });
        assert_eq!(d(3, [0x8d, 0x05, 0, 0, 0, 0, 0, 0]), Op::Callx { reg: 5 });
    }

    #[test]
    fn bad_registers_are_invalid_not_panics() {
        assert!(matches!(d(0, [0xbf, 0xff, 0, 0, 0, 0, 0, 0]), Op::Invalid { .. }));
        let (insns, idx) = decode_all(0, &[0x18, 0x01, 0, 0, 0, 0, 0, 0], 10);
        assert_eq!(insns.len(), 1);
        assert!(matches!(insns[0].op, Op::Invalid { .. }));
        assert_eq!(idx, vec![0]);
    }
}
