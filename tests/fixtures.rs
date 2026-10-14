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
        .filter(|i| i.status == InstructionStatus::Implemented)
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
fn anchor_account_lists_follow_the_accounts_structs() {
    let r = load("inspect_fixture_anchor.so");
    let list = |name: &str| -> Vec<(String, bool, bool)> {
        let ix = r.anchor.instructions.iter().find(|i| i.name == name).expect("instruction recovered");
        assert!(ix.accounts_check_offset.is_some(), "{name}: accounts check located");
        let accounts = ix.accounts.as_ref().expect("account list recovered");
        accounts.iter().map(|a| (a.name.clone(), a.writable, a.signer)).collect()
    };
    let expect = |v: &[(&str, bool, bool)]| -> Vec<(String, bool, bool)> {
        v.iter().map(|(n, w, s)| (n.to_string(), *w, *s)).collect()
    };
    // `init` accounts without seeds are created by the payer and must sign; `mut` is writable.
    assert_eq!(
        list("initialize"),
        expect(&[("settings", true, true), ("vault", true, true), ("authority", true, true), ("system_program", false, false)])
    );
    assert_eq!(list("deposit_v2"), expect(&[("vault", true, false), ("depositor", false, true)]));
    assert_eq!(list("step_2"), expect(&[("settings", false, false)]));
    assert_eq!(list("set_authority"), expect(&[("settings", true, false), ("authority", false, true)]));

    let text = r.elf.sections.iter().find(|s| s.name == ".text").expect(".text");
    for ix in &r.anchor.instructions {
        for a in ix.accounts.iter().flatten() {
            if let Some(at) = a.load_offset {
                assert!((text.file_offset..text.file_offset + text.size).contains(&at), "{}: load inside .text", a.name);
            }
            if a.writable {
                assert!(a.error_codes.contains(&2000), "{}: writable needs its ConstraintMut path", a.name);
            }
        }
    }
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
fn anchor_argument_layouts_follow_the_source() {
    let r = load("inspect_fixture_anchor.so");
    let layout = |name: &str| {
        let ix = r.anchor.instructions.iter().find(|i| i.name == name).unwrap_or_else(|| panic!("{name} missing"));
        ix.arguments.clone().unwrap_or_else(|| panic!("{name} has no layout"))
    };
    let fields = |name: &str| layout(name).fields.iter().map(|f| (f.offset, f.size)).collect::<Vec<_>>();
    // initialize(fee_bps: u16), deposit_v2(amount: u64), step_2(), set_authority(new_authority: Pubkey)
    assert_eq!(fields("initialize"), [(0, 2)]);
    assert_eq!(fields("deposit_v2"), [(0, 8)]);
    assert_eq!(fields("step_2"), []);
    assert!(layout("step_2").complete, "an empty, complete layout means no arguments");
    // The public key is moved in uneven pieces: the layout covers its 32 bytes and says it is uncertain.
    let key = layout("set_authority");
    assert_eq!(key.fixed_size, 32);
    assert!(key.irregular || key.fields.iter().all(|f| f.copied));
}

#[test]
fn panic_locations_name_source_files() {
    let r = load("inspect_fixture_anchor.so");
    assert!(!r.panic_locations.is_empty());
    assert!(r.panic_locations.iter().all(|l| l.file.ends_with(".rs") && l.line > 0));
}

#[test]
fn native_program_is_not_mistaken_for_anchor() {
    let r = load("inspect_fixture_native.so");
    assert!(!r.anchor.detected, "an `Instruction: Ping` log string alone is not Anchor");
    assert!(r.anchor.instructions.is_empty());
    assert_eq!(r.anchor.uncorroborated_instruction_logs.len(), 1);
    assert!(r.anchor.uncorroborated_instruction_logs[0].log_token.starts_with("Ping"));
    assert!(r.native_dispatch.is_none(), "one logged instruction is not a dispatch of three or more");
}

#[test]
fn rejects_non_elf_input() {
    assert!(inspect(b"").is_err());
    assert!(inspect(b"definitely not an ELF file").is_err());
    let anchor = std::fs::read(format!("{}/tests/fixtures/inspect_fixture_anchor.so", env!("CARGO_MANIFEST_DIR")))
        .expect("fixture present");
    assert!(inspect(&anchor[..200]).is_err(), "a truncated header must be rejected");
}
