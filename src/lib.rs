//! Offline interface recovery for Solana sBPF programs.
//!
//! [`inspect`] reads one program ELF and reports what can be observed in it
//! (sBPF version, entrypoint, sections, syscalls, strings, panic locations)
//! and what can be inferred and corroborated from it (Anchor instruction,
//! account and event names, each instruction's accounts and argument layout,
//! and the dispatch of native programs). It never executes the program and
//! never touches the network.

pub mod accounts;
pub mod anchor;
pub mod args;
pub mod cfg;
pub mod constants;
pub mod dispatch;
pub mod elf;
pub mod emu;
pub mod isa;
pub mod literals;
pub mod program;
pub mod report;
pub mod strings;
pub mod syscalls;
#[cfg(test)]
mod tests;
#[cfg(all(target_arch = "wasm32", feature = "bindgen"))]
mod wasm;
#[cfg(all(target_arch = "wasm32", not(feature = "bindgen")))]
mod raw;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use sha2::{Digest, Sha256};

use crate::cfg::Cfg;
use crate::program::{CallTarget, LoadError, Program};
use crate::report::{
    Artifact, ConstantCoverage, ElfFacts, Engine, EvidenceKind, InstructionStatus, NativeDispatch, NativeHandler,
    PanicLocationFact, Report, SectionFact, SecurityTxtField, SyscallUse, UnnamedInstruction,
};

pub const ENGINE_NAME: &str = "sbpf-inspect";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Largest input accepted, well above the 10 MiB Solana allows a program.
pub const MAX_INPUT: usize = 64 << 20;

/// Why a file could not be inspected at all.
#[derive(Debug)]
pub enum InspectError {
    /// The bytes are not an sBPF ELF file.
    InvalidElf(String),
    /// The ELF has no `.text` section or executable segment.
    MissingText,
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectError::InvalidElf(detail) => write!(f, "not a parsable sBPF ELF: {detail}"),
            InspectError::MissingText => write!(f, "the ELF has no .text section or executable segment"),
        }
    }
}

impl std::error::Error for InspectError {}

fn sbpf_version_name(e_flags: u32) -> &'static str {
    match e_flags {
        0 => "v0",
        1 => "v1",
        2 => "v2",
        3 => "v3",
        4 => "v4",
        _ => "reserved",
    }
}

/// Sections whose bytes are data the program reads, as opposed to code or ELF tables.
fn is_data_section(name: &str) -> bool {
    name.starts_with(".rodata") || name.starts_with(".data")
}

const UNKNOWNS: &[&str] = &[
    "Instruction names come from Anchor's `Instruction: <Name>` log strings. An instruction whose name is not in the binary is listed under unnamed_instructions when the code proves its 8-byte discriminator, and its name stays unknown. Native programs' one-byte tags are listed under native_dispatch, named when their handlers log names.",
    "Unnamed instructions are found only when the program's entrypoint can be run to the instruction data on an input without accounts, and the dispatch tests all 8 bytes for equality within four call levels of it. Dispatch that compares in a loop, or reads the tag only after checking accounts, is missed.",
    "A discriminator counts as found only when its 8 bytes are a 64-bit immediate (`lddw`, or `mov32` + `hor64` on sBPF v2 and later) or appear in a data section, or, for instructions, when bytes 2 to 7 are compared one at a time in order (byte-wise dispatch). Other code shapes, such as two 32-bit comparisons, are not detected.",
    "Event names are recovered only when the name appears in the program's strings. Calls a program makes to itself starting with Anchor's event tag (see the event_cpi_tag marker) carry events, not instructions.",
    "Account names are recovered only when the name itself appears in the program's strings. A recovered account type can belong to another program this one validates, such as pump AMM's Pool inside pump.fun's bonding-curve program.",
    "Account lists are recovered only for Anchor instructions whose accounts check (try_accounts) can be located, and list only accounts whose names the binary embeds. An account positioned `matched` or `appended` was named only by later checks, so its position is weaker evidence. Of the constraints, only mut and signer are reported.",
    "Argument layouts are byte offsets and sizes read on the instruction's code path: names and types are not in the binary, a 1-byte field may be a u8 or a bool, and a variable-length value (vector, string, option) ends the layout.",
    "Error codes defined by the program are not recovered.",
    "Deployment identity, upgrade authority, verified-build status and runtime behaviour are unknown: the analysis is offline, and the only code it runs is the entrypoint's decoding of a made-up input with no accounts, to find where the instruction data goes.",
];

/// Inspect one sBPF program ELF.
pub fn inspect(bytes: &[u8]) -> Result<Report, InspectError> {
    if bytes.len() > MAX_INPUT {
        return Err(InspectError::InvalidElf(format!("input is {} bytes; the limit is {MAX_INPUT}", bytes.len())));
    }
    let p = Program::load(bytes).map_err(|e| match e {
        LoadError::Elf(e) => InspectError::InvalidElf(e.to_string()),
        LoadError::NoText => InspectError::MissingText,
    })?;
    let cfg = Cfg::build(&p);
    let mut diagnostics = p.diagnostics.clone();
    if cfg.truncated {
        diagnostics.push("too many functions; control flow was recovered for the first ones only".into());
    }

    // Named call targets: the relocation's symbol (v0-v2), or the syscall a v3 hash names.
    let mut calls: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (&i, target) in &p.calls {
        let name = match (p.call_names.get(&i), target) {
            (Some(n), _) => n.clone(),
            (None, CallTarget::Syscall(n)) => n.to_string(),
            (None, CallTarget::Import(n)) => n.clone(),
            _ => continue,
        };
        calls.entry(name).or_default().push(p.file_offset(i));
    }
    for sites in calls.values_mut() {
        sites.sort_unstable();
    }

    let constants = constants::scan(p.text, p.text_file_offset, p.version);
    let chains = constants::ByteCompares::scan(p.text, p.text_file_offset);
    let data_sections: Vec<anchor::DataSection> =
        p.data.iter().map(|r| anchor::DataSection { file_offset: r.file_offset, data: r.bytes }).collect();
    let mut anchor = anchor::analyze(&constants, &chains, &data_sections);

    // Account lists, matched to instructions by the name in their log string. Account recovery reads
    // raw opcodes, and sBPF v2 moved the memory ones.
    if p.version == 2 {
        anchor.limits_hit.push("account lists are not recovered for sBPF v2, whose memory opcodes differ".into());
    } else {
        let (checks, exhausted) = accounts::recover(&p);
        if exhausted {
            anchor.limits_hit.push("account-list search hit its step budget; some lists may be missing".into());
        }
        for ix in &mut anchor.instructions {
            if let Some(Some(check)) = checks.get(&ix.log_name) {
                ix.accounts_check_offset = Some(check.check_offset);
                ix.accounts = Some(check.accounts.clone());
            }
        }
    }

    let literals = literals::recover(&p);
    if literals.truncated {
        diagnostics.push("too many string literals; the rest were not read".into());
    }
    // Argument layouts of the instructions this program implements, each with the instructions that
    // load its `Instruction: <Name>` log string.
    let mut log_sites: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for (&i, addr) in &literals.code_slices {
        if let Some(name) = literals.strings.get(addr).and_then(|s| s.text.strip_prefix("Instruction: ")) {
            log_sites.entry(name).or_default().push(i);
        }
    }
    // Instructions known by their discriminator: values the program's own code tests the start of
    // its instruction data against, as its entrypoint delivers the data. Those whose names are not
    // in the binary are reported as unnamed (Anchor instructions that are not logged, native
    // programs' own 8-byte tags); a `referenced` instruction found this way is implemented after all.
    let handovers = emu::handovers(&p, &cfg);
    let mut found = Vec::new();
    if !handovers.is_empty() {
        let mut known: BTreeSet<u64> = anchor
            .instructions
            .iter()
            .filter(|ix| ix.status != InstructionStatus::Referenced)
            .filter_map(|ix| Some(u64::from_str_radix(ix.discriminator.as_deref()?, 16).ok()?.swap_bytes()))
            .collect();
        known.extend([anchor::IDL_IX_TAG, anchor::EVENT_IX_TAG]);
        let exhausted;
        (found, exhausted) = args::unnamed(&p, &cfg, &handovers, &known);
        if exhausted {
            diagnostics.push("the search for unnamed instructions hit its step budget; some may be missing".into());
        }
        found.retain(|&(v, _)| {
            let hex = anchor::hex(&v.to_le_bytes());
            match anchor.instructions.iter_mut().find(|ix| ix.status == InstructionStatus::Referenced && ix.discriminator.as_deref() == Some(hex.as_str())) {
                Some(ix) => {
                    ix.status = InstructionStatus::Implemented;
                    false
                }
                None => true,
            }
        });
    }

    let discriminators: BTreeMap<String, (u64, Vec<u32>)> = anchor
        .instructions
        .iter()
        .filter(|ix| ix.status == InstructionStatus::Implemented)
        .filter_map(|ix| {
            let value = u64::from_str_radix(ix.discriminator.as_deref()?, 16).ok()?.swap_bytes();
            Some((ix.name.clone(), (value, log_sites.get(ix.log_name.as_str()).cloned().unwrap_or_default())))
        })
        .collect();
    let (layouts, exhausted) = args::recover(&p, &cfg, &chains, &discriminators, &[]);
    if exhausted {
        anchor.limits_hit.push("argument-layout search hit its program-wide step budget; some layouts are missing".into());
    }
    let truncated = layouts.values().filter(|l| l.truncated).count();
    if truncated > 0 {
        anchor.limits_hit.push(format!("{truncated} argument layouts were cut short by their step budget (marked truncated)"));
    }
    for ix in &mut anchor.instructions {
        ix.arguments = layouts.get(&ix.name).cloned();
    }
    let mut unnamed_instructions = Vec::new();
    if !found.is_empty() {
        let named: BTreeMap<String, (u64, Vec<u32>)> =
            found.iter().map(|&(v, _)| (anchor::hex(&v.to_le_bytes()), (v, Vec::new()))).collect();
        let (layouts, _) = args::recover(&p, &cfg, &chains, &named, &handovers);
        for (v, at) in found {
            let bytes = v.to_le_bytes();
            let discriminator = anchor::hex(&bytes);
            unnamed_instructions.push(UnnamedInstruction {
                text: bytes.iter().all(|b| b.is_ascii_graphic()).then(|| bytes.iter().map(|&b| b as char).collect()),
                match_offset: p.file_offset(at),
                arguments: layouts.get(&discriminator).cloned(),
                discriminator,
            });
        }
    }

    // Native programs switch on an instruction-data tag instead of Anchor discriminators.
    let native_dispatch = if anchor.detected {
        None
    } else {
        dispatch::recover(&p, &cfg, &literals).map(|d| {
            let named: BTreeSet<&str> = d.handlers.iter().filter_map(|h| h.log_name.as_deref()).collect();
            NativeDispatch {
                tag_load_offset: p.text_file_offset + d.tag_load_offset,
                tag_width: d.tag_width,
                confirmed: named.len() >= 3,
                handlers: d
                    .handlers
                    .iter()
                    .map(|h| NativeHandler { tags: h.tags.clone(), file_offset: p.text_file_offset + h.offset, log_name: h.log_name.clone() })
                    .collect(),
                other_tags: d.other_tags,
            }
        })
    };
    let panic_locations = literals
        .locations
        .values()
        .map(|l| PanicLocationFact {
            file: l.file.clone(),
            line: l.line,
            col: l.col,
            file_offset: p.elf.file_offset_of(l.addr).unwrap_or(0),
            referenced_by: l.referenced_by.iter().map(|&i| p.file_offset(i)).collect(),
        })
        .collect();
    let security_txt = literals
        .security_txt
        .as_ref()
        .map(|pairs| pairs.iter().map(|(field, value)| SecurityTxtField { field: field.clone(), value: value.clone() }).collect());

    let strings = p
        .elf
        .sections
        .iter()
        .filter(|s| is_data_section(&s.name) || s.name == ".dynstr")
        .flat_map(|s| strings::extract(&s.name, p.elf.data(s), s.offset))
        .collect();

    Ok(Report {
        engine: Engine { name: ENGINE_NAME, version: ENGINE_VERSION, upstream: Vec::new() },
        artifact: Artifact { size: bytes.len(), sha256: anchor::hex(&Sha256::digest(bytes)) },
        elf: ElfFacts {
            e_machine: p.elf.e_machine,
            e_flags: p.elf.e_flags,
            sbpf_version: sbpf_version_name(p.elf.e_flags).to_string(),
            entrypoint_offset: p.entry.map(|i| p.file_offset(i)),
            sections: p
                .elf
                .sections
                .iter()
                .map(|s| SectionFact { name: s.name.clone(), file_offset: s.offset, size: p.elf.data(s).len() as u64 })
                .collect(),
        },
        syscalls: calls
            .into_iter()
            .map(|(name, call_sites)| SyscallUse { registered: syscalls::is_registered(&name), name, call_sites })
            .collect(),
        constants: ConstantCoverage {
            lddw: constants.iter().filter(|c| c.kind == EvidenceKind::LddwImmediate).count(),
            mov32_hor64: constants.iter().filter(|c| c.kind == EvidenceKind::Mov32Hor64Immediate).count(),
            byte_compares: chains.len(),
        },
        strings,
        panic_locations,
        security_txt,
        anchor,
        native_dispatch,
        unnamed_instructions,
        unknowns: UNKNOWNS.iter().map(|s| s.to_string()).collect(),
        diagnostics,
    })
}
