//! The serialized result of one inspection.
//!
//! Every offset is a byte offset into the input file. Facts read directly from
//! the file are reported as observations; names, discriminator meanings and
//! framework identification are inferences and say what corroborates them.

use serde::Serialize;

/// Complete result of inspecting one sBPF ELF file.
#[derive(Debug, Serialize)]
pub struct Report {
    pub engine: Engine,
    pub artifact: Artifact,
    pub elf: ElfFacts,
    pub syscalls: Vec<SyscallUse>,
    pub constants: ConstantCoverage,
    pub strings: Vec<StringFact>,
    pub anchor: AnchorFacts,
    pub unknowns: Vec<String>,
    /// Non-fatal problems met while parsing; analysis continued past them.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Engine {
    pub name: &'static str,
    pub version: &'static str,
    pub upstream: Vec<Upstream>,
}

#[derive(Debug, Serialize)]
pub struct Upstream {
    pub name: &'static str,
    pub version: &'static str,
    pub license: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub size: usize,
    /// SHA-256 of the exact input bytes. Not a Solana program hash.
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ElfFacts {
    pub e_machine: u16,
    pub e_flags: u32,
    /// sBPF version read from `e_flags`, as the Solana loader maps it.
    pub sbpf_version: String,
    /// File offset of the entrypoint instruction, when it lies inside `.text`.
    pub entrypoint_offset: Option<u64>,
    pub sections: Vec<SectionFact>,
}

#[derive(Debug, Serialize)]
pub struct SectionFact {
    pub name: String,
    pub file_offset: u64,
    pub size: u64,
}

/// A call target named through a relocation or a static syscall hash.
#[derive(Debug, Serialize)]
pub struct SyscallUse {
    pub name: String,
    /// True when the name is in the registered Solana syscall list. False means
    /// a named symbol that is not a syscall, such as a program's `custom_panic`.
    pub registered: bool,
    /// File offsets of the call instructions.
    pub call_sites: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct ConstantCoverage {
    /// 64-bit immediates found as `lddw` (sBPF v0 and v1).
    pub lddw: usize,
    /// 64-bit immediates found as `mov32` followed by `hor64` (sBPF v2 and later).
    pub mov32_hor64: usize,
    /// Conditional jumps comparing a register with one byte, searched for
    /// byte-wise instruction dispatch.
    pub byte_compares: usize,
}

#[derive(Debug, Serialize)]
pub struct StringFact {
    pub file_offset: u64,
    pub section: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct AnchorFacts {
    /// True when a corroborated instruction, the IDL instruction tag or Anchor's
    /// error strings were found. Instruction log strings alone do not count.
    pub detected: bool,
    pub markers: Vec<Marker>,
    pub instructions: Vec<RecoveredInstruction>,
    /// Instruction log strings whose name could not be corroborated.
    pub uncorroborated_instruction_logs: Vec<UncorroboratedLog>,
    pub accounts: Vec<RecoveredType>,
    pub events: Vec<RecoveredType>,
}

#[derive(Debug, Serialize)]
pub struct Marker {
    pub name: &'static str,
    pub description: &'static str,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub file_offset: u64,
    /// For code immediates: what the code does first with the loaded value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_after_load: Option<ImmediateUse>,
}

/// The first use of a 64-bit immediate after it is loaded into a register.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImmediateUse {
    /// Read by a conditional jump, as when dispatching on an instruction discriminator.
    Compare,
    /// Stored to memory, as when building instruction data for a call to another program.
    Store,
    /// Used some other way, overwritten, or not used within the search window.
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A 64-bit immediate loaded by `lddw`.
    LddwImmediate,
    /// A 64-bit immediate built by `mov32` + `hor64`.
    Mov32Hor64Immediate,
    /// Bytes 2 to 7 compared one at a time, in order, by nearby conditional
    /// jumps: the byte-wise dispatch older Anchor versions compile to. The
    /// offset is the first of those comparisons.
    ByteCompareChain,
    /// The bytes appear in a data section.
    DataBytes,
    /// A log or error string in a data section.
    String,
}

#[derive(Debug, Serialize)]
pub struct RecoveredInstruction {
    /// Inferred Rust handler name, as Anchor hashes it.
    pub name: String,
    /// The name as it appears in the program's log string.
    pub log_name: String,
    /// `sha256("global:" + name)[..8]`, hex. Absent for framework instructions,
    /// which Anchor dispatches through its IDL instruction tag instead.
    pub discriminator: Option<String>,
    /// Whether this program handles the instruction, only references it, or is
    /// Anchor's own IDL-management instruction.
    pub status: InstructionStatus,
    /// Log strings whose text contains this name.
    pub log_string_offsets: Vec<u64>,
    /// Where the discriminator bytes were found. Empty for framework instructions.
    pub discriminator_evidence: Vec<Evidence>,
    /// File offset of the function that loads and checks this instruction's
    /// accounts (Anchor's `try_accounts`), when it could be located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts_check_offset: Option<u64>,
    /// The instruction's accounts in order, recovered from its accounts check.
    /// Absent when the check could not be located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<RecoveredAccount>>,
}

/// One account of an instruction, as its accounts check loads and checks it.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveredAccount {
    /// The field name the program attaches to this account's errors.
    pub name: String,
    /// The account is checked to be writable (ConstraintMut, 2000).
    pub writable: bool,
    /// The account is checked to be a signer (ConstraintSigner, 2002, or
    /// AccountNotSigner, 3010, raised by its checks or its loader).
    pub signer: bool,
    /// How the account's position in the list was established.
    pub position: AccountPosition,
    /// File offset of the call or inline take that loads the account, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_offset: Option<u64>,
    /// Anchor error codes whose failure path names this account.
    pub error_codes: Vec<u32>,
    /// Anchor error codes the function that loads this account can raise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub loader_error_codes: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountPosition {
    /// Placed by its own load: the load's failure path names it, or its name is
    /// checked where the loads happen.
    Loaded,
    /// Named only by later constraint checks (an `init` account, say) and matched,
    /// in check order, to a load that names nothing.
    Matched,
    /// Named only by later checks with no unnamed load left: listed last, its
    /// position is unknown.
    Appended,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstructionStatus {
    /// A handler of this program: the discriminator is compared right after it
    /// is loaded, or, when the code shape is not visible, the name is the
    /// longest corroborated name in its own log string.
    Implemented,
    /// The discriminator is in the binary but is only written to memory, or the
    /// name is just a shorter prefix of another handler's log string. Typically
    /// an instruction this program calls on another program.
    Referenced,
    /// Anchor's own IDL-management instruction.
    Framework,
}

#[derive(Debug, Serialize)]
pub struct UncorroboratedLog {
    pub log_token: String,
    pub file_offset: u64,
}

#[derive(Debug, Serialize)]
pub struct RecoveredType {
    pub name: String,
    /// `sha256("account:" + name)[..8]` or `sha256("event:" + name)[..8]`, hex.
    pub discriminator: String,
    pub discriminator_evidence: Vec<Evidence>,
}
