//! Offline interface recovery for Solana sBPF programs.
//!
//! [`inspect`] reads one program ELF and reports what can be observed in it
//! (sBPF version, entrypoint, sections, syscalls, strings) and what can be
//! inferred and corroborated from it (Anchor instruction, account and event
//! names). It never executes the program and never touches the network.

pub mod anchor;
pub mod constants;
pub mod report;
pub mod strings;
#[cfg(target_arch = "wasm32")]
mod wasm;

use std::{collections::BTreeMap, fmt};

use either::Either;
use sbpf_common::{opcode::Opcode, syscalls::REGISTERED_SYSCALLS};
use sbpf_disassembler::program::Program;
use sha2::{Digest, Sha256};

use crate::report::{
    Artifact, ConstantCoverage, ElfFacts, Engine, Report, SectionFact, SyscallUse, Upstream,
};
use crate::report::EvidenceKind;

pub const ENGINE_NAME: &str = "sbpf-inspect";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why a file could not be inspected at all.
#[derive(Debug)]
pub enum InspectError {
    /// The bytes are not an ELF file the sBPF parser accepts.
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
    "Instruction names come from Anchor's `Instruction: <Name>` log strings. Programs built without those logs, native programs and other frameworks yield none.",
    "A discriminator counts as found only when its 8 bytes are a 64-bit immediate (`lddw`, or `mov32` + `hor64` on sBPF v2 and later) or appear in a data section. Other code shapes, such as two 32-bit comparisons, are not detected.",
    "Event names are recovered only when the name appears in the program's strings. Calls a program makes to itself starting with Anchor's event tag (see the event_cpi_tag marker) carry events, not instructions.",
    "Account names are recovered only when the name itself appears in the program's strings. A recovered account type can belong to another program this one validates, such as pump AMM's Pool inside pump.fun's bonding-curve program.",
    "Instruction arguments, account lists, constraints and error codes are not recovered.",
    "Deployment identity, upgrade authority, verified-build status and runtime behaviour are unknown: the analysis is offline and does not execute the program.",
];

/// Inspect one sBPF program ELF.
pub fn inspect(bytes: &[u8]) -> Result<Report, InspectError> {
    let program = Program::from_bytes(bytes).map_err(|errors| {
        InspectError::InvalidElf(errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
    })?;
    let e_machine = program.elf_header.e_machine;
    let e_flags = program.elf_header.e_flags;

    let sections: Vec<(String, u64, Vec<u8>)> = program
        .section_header_entries
        .iter()
        .map(|e| (e.label.trim_end_matches('\0').to_string(), e.offset as u64, e.data.clone()))
        .collect();
    let (text_offset, text) = sections
        .iter()
        .find(|(name, _, _)| name == ".text")
        .map(|(_, off, data)| (*off, data.clone()))
        .ok_or(InspectError::MissingText)?;
    let entrypoint_offset = program.get_entrypoint_offset().map(|rel| text_offset + rel);

    let mut diagnostics = Vec::new();

    // Syscall call sites, from the disassembler's relocation-resolved call names.
    let mut syscalls: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    match program.to_ixs_raw() {
        Ok(parsed) => {
            diagnostics.extend(parsed.errors.iter().map(|e| e.to_string()));
            let mut pos = 0u64;
            for item in &parsed.value.instructions {
                match item {
                    Either::Left(ix) => {
                        if ix.opcode == Opcode::Call
                            && let Some(Either::Left(name)) = &ix.imm
                        {
                            syscalls.entry(name.clone()).or_default().push(text_offset + pos);
                        }
                        pos += ix.get_size();
                    }
                    Either::Right(_) => pos += 8,
                }
            }
        }
        Err(errors) => diagnostics.extend(errors.iter().map(|e| e.to_string())),
    }

    let constants = constants::scan(&text, text_offset, e_flags);
    let data_sections: Vec<anchor::DataSection> = sections
        .iter()
        .filter(|(name, _, _)| is_data_section(name))
        .map(|(_, off, data)| anchor::DataSection { file_offset: *off, data })
        .collect();
    let anchor = anchor::analyze(&constants, &data_sections);

    let strings = sections
        .iter()
        .filter(|(name, _, _)| is_data_section(name) || name == ".dynstr")
        .flat_map(|(name, off, data)| strings::extract(name, data, *off))
        .collect();

    Ok(Report {
        engine: Engine {
            name: ENGINE_NAME,
            version: ENGINE_VERSION,
            upstream: vec![
                Upstream { name: "sbpf-disassembler", version: "0.3.2", license: "MIT" },
                Upstream { name: "sbpf-common", version: "0.3.2", license: "MIT" },
            ],
        },
        artifact: Artifact { size: bytes.len(), sha256: anchor::hex(&Sha256::digest(bytes)) },
        elf: ElfFacts {
            e_machine,
            e_flags,
            sbpf_version: sbpf_version_name(e_flags).to_string(),
            entrypoint_offset,
            sections: sections
                .iter()
                .map(|(name, off, data)| SectionFact { name: name.clone(), file_offset: *off, size: data.len() as u64 })
                .collect(),
        },
        syscalls: syscalls
            .into_iter()
            .map(|(name, call_sites)| SyscallUse {
                registered: REGISTERED_SYSCALLS.contains(&name.as_str()),
                name,
                call_sites,
            })
            .collect(),
        constants: ConstantCoverage {
            lddw: constants.iter().filter(|c| c.kind == EvidenceKind::LddwImmediate).count(),
            mov32_hor64: constants.iter().filter(|c| c.kind == EvidenceKind::Mov32Hor64Immediate).count(),
        },
        strings,
        anchor,
        unknowns: UNKNOWNS.iter().map(|s| s.to_string()).collect(),
        diagnostics,
    })
}
