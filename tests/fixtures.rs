//! End-to-end checks against the source-owned programs in `fixtures/`.
//! Rebuild the binaries with `scripts/build-fixtures.sh`.

use sbpf_inspect::{
    anchor::{discriminator, hex},
    inspect,
    report::{InstructionStatus, Report},
};

fn load(name: &str) -> Report {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}; run scripts/build-fixtures.sh"));
    inspect(&bytes).expect("fixture parses")
}

#[test]
fn anchor_instructions_are_recovered_and_corroborated() {
    let r = load("inspect_fixture_anchor.so");
    let user: Vec<_> = r
        .anchor
        .instructions
        .iter()
        .filter(|i| i.status == InstructionStatus::Corroborated)
        .collect();
    let names: Vec<_> = user.iter().map(|i| i.name.as_str()).collect();
    // `deposit_v2` checks letter-digit words, `step_2` the digit spelling heck does not produce.
    assert_eq!(names, ["deposit_v2", "initialize", "set_authority", "step_2"]);
    for i in &user {
        assert_eq!(i.discriminator.as_deref(), Some(hex(&discriminator("global", &i.name)).as_str()));
        assert!(!i.discriminator_evidence.is_empty(), "{} has no evidence", i.name);
        assert!(!i.log_string_offsets.is_empty(), "{} has no log string", i.name);
    }
    assert!(r.anchor.detected);
    assert!(r.anchor.uncorroborated_instruction_logs.is_empty());
}

#[test]
fn anchor_idl_management_instructions_are_framework() {
    let r = load("inspect_fixture_anchor.so");
    let framework: Vec<_> = r
        .anchor
        .instructions
        .iter()
        .filter(|i| i.status == InstructionStatus::Framework)
        .map(|i| i.name.as_str())
        .collect();
    assert_eq!(framework.len(), 7, "anchor-lang 0.31 ships seven IDL instructions: {framework:?}");
    assert!(framework.iter().all(|n| n.starts_with("idl_")));
    let tag = r.anchor.markers.iter().find(|m| m.name == "idl_instruction_tag").expect("marker present");
    assert!(!tag.evidence.is_empty());
}

#[test]
fn anchor_accounts_and_events_need_their_names_in_the_binary() {
    let r = load("inspect_fixture_anchor.so");
    let accounts: Vec<_> = r.anchor.accounts.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(accounts, ["Settings", "Vault"]);
    for a in &r.anchor.accounts {
        assert_eq!(a.discriminator, hex(&discriminator("account", &a.name)));
    }
    // `VaultDeposited` is named in a log string; `SettingsChanged` is not.
    let events: Vec<_> = r.anchor.events.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(events, ["VaultDeposited"]);
}

#[test]
fn anchor_facts_are_observed() {
    let r = load("inspect_fixture_anchor.so");
    assert!(r.elf.entrypoint_offset.is_some());
    assert!(r.elf.sections.iter().any(|s| s.name == ".text"));
    let calls: Vec<_> = r.syscalls.iter().map(|s| s.name.as_str()).collect();
    assert!(calls.contains(&"sol_log_"), "{calls:?}");
    assert!(calls.contains(&"sol_log_data"), "emit! uses sol_log_data: {calls:?}");
    assert!(r.syscalls.iter().all(|s| !s.call_sites.is_empty()));
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
}

#[test]
fn native_program_is_not_mistaken_for_anchor() {
    let r = load("inspect_fixture_native.so");
    assert!(!r.anchor.detected, "an `Instruction: Ping` log string alone is not Anchor");
    assert!(r.anchor.instructions.is_empty());
    assert_eq!(r.anchor.uncorroborated_instruction_logs.len(), 1);
    assert!(r.anchor.uncorroborated_instruction_logs[0].log_token.starts_with("Ping"));
}

#[test]
fn rejects_non_elf_input() {
    assert!(inspect(b"").is_err());
    assert!(inspect(b"definitely not an ELF file").is_err());
    let anchor = std::fs::read(format!("{}/tests/fixtures/inspect_fixture_anchor.so", env!("CARGO_MANIFEST_DIR")))
        .expect("fixture present");
    assert!(inspect(&anchor[..200]).is_err(), "a truncated header must be rejected");
}
