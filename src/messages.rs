//! The human-readable messages a program carries: its Anchor error messages, and its `msg!` logs
//! and warnings. Their text is in the binary even though the variant and field names are not, and
//! it often says what an instruction's arguments mean (`"Name is empty or longer than 32
//! characters"`).
//!
//! The compiler materialises each `&'static str` as `lddw ptr; mov len` — the shape
//! [`crate::literals`] already recovers with exact bounds, so packed strings come back whole.
//! anchor-lang's own `ErrorCode`, `solana_program`'s `ProgramError` and the Rust/borsh runtime
//! carry messages too; those are set apart by the framework set below. What remains, loaded by a
//! function that uses several such messages (so a lone incidental string is not mistaken for one),
//! is the program's own.
//!
//! This does not tell an error from a log, and it misses enums whose `Display` reads its messages
//! from a read-only table instead of loading each inline (then nothing here is reported for them).

use std::collections::BTreeMap;

use crate::cfg::Cfg;
use crate::literals::Literals;
use crate::program::Program;
use crate::report::ProgramMessageFact;

/// anchor-lang `ErrorCode` messages that do not end in "constraint was violated" (that suffix,
/// matched separately, covers the ~45 constraint variants). Plus the Solana and Rust runtime
/// sentences that are shaped like error messages, so they are not reported as the program's.
const FRAMEWORK: &[&str] = &[
    // anchor_lang::error::ErrorCode (instruction / IDL / event)
    "Instruction discriminator not provided",
    "Fallback functions are not supported",
    "The program could not deserialize the given instruction",
    "The program could not serialize the given instruction",
    "The program was compiled without idl instructions",
    "Invalid program given to the IDL instruction",
    "IDL account must be empty in order to resize, try closing first",
    "The program was compiled without `event-cpi` feature",
    // constraints that do not use the common suffix
    "A required account for the constraint is None",
    "Expected zero account discriminant",
    "Deprecated Error, feel free to replace with something else",
    // accounts
    "Account is already migrated",
    "Account must be migrated before exiting",
    "The account discriminator was already set on this account",
    "No discriminator was found on the account",
    "Account discriminator did not match what was expected",
    "Failed to deserialize the account",
    "Failed to serialize the account",
    "Not enough account keys given to the instruction",
    "The given account is not mutable",
    "The given account is owned by a different program than expected",
    "Program ID was not as expected",
    "Program account is not executable",
    "The given account did not sign",
    "The given account is not owned by the system program",
    "The program expected this account to be already initialized",
    "The given account is not a program data account",
    "The given account is not the associated token account",
    "The given public key does not match the required sysvar",
    "The account reallocation exceeds the MAX_PERMITTED_DATA_INCREASE limit",
    "The account was duplicated for more than one reallocation",
    // misc
    "The declared program id does not match the actual program id",
    "You cannot/modify this program",
    "Error during numeric conversion",
    "The API being used is deprecated and should no longer be used",
    // require! family
    "A require expression was violated",
    "A require_eq expression was violated",
    "A require_keys_eq expression was violated",
    "A require_neq expression was violated",
    "A require_keys_neq expression was violated",
    "A require_gt expression was violated",
    "A require_gte expression was violated",
    // solana_program::program_error::ProgramError Display
    "Unable to find a viable program address bump seed",
    "The arguments provided to a program instruction were invalid",
    "An instruction's data contents was invalid",
    "An account's data contents was invalid",
    "An account's data was too small",
    "An account's balance was too small to complete the instruction",
    "The account did not have the expected program id",
    "A signature was required but not found",
    "An initialize instruction was sent to an account that has already been initialized",
    "An attempt to operate on an account that hasn't been initialized",
    "The instruction expected additional account keys",
    "Failed to borrow a reference to account data, already borrowed",
    "Length of the seed is too long for address generation",
    "Provided seeds do not result in a valid address",
    "An account does not have enough lamports to be rent-exempt",
    "Provided owner is not allowed",
    "Accounts data allocations exceeded the maximum allowed per transaction",
    "Account data reallocation was invalid",
    "Instruction trace length exceeded the maximum allowed per transaction",
    "Builtin programs must consume compute units",
    "Invalid account owner",
    "Program arithmetic overflowed",
    "Account is immutable",
    "Incorrect authority provided",
    "Unsupported sysvar",
    "This account may not be used to pay transaction fees",
    "This program may not be used for executing instructions",
    // borsh / std
    "IO Error",
    "Not all bytes read",
    "Unexpected length of input",
    "Error during numeric conversion",
];

/// Whether `t` reads like a human error message: a capitalised sentence, printable ASCII, a few
/// words, and not a format fragment or a log prefix.
fn error_shaped(t: &str) -> bool {
    let t = t.trim();
    if !(6..=160).contains(&t.len()) || !t.is_ascii() {
        return false;
    }
    if !t.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return false;
    }
    if t.starts_with("Instruction: ") || t.contains('{') || t.contains('}') || t.ends_with(": ") || t.ends_with('`') {
        return false;
    }
    // At least two words, and mostly letters and spaces.
    let letters = t.chars().filter(|c| c.is_ascii_alphabetic()).count();
    t.split_whitespace().count() >= 2 && letters * 10 >= t.len() * 7
}

fn is_framework(t: &str) -> bool {
    let t = t.trim();
    t.ends_with("constraint was violated") || FRAMEWORK.contains(&t)
}

/// Whether the `&str` loaded at instruction `i` is handed to `sol_log_` shortly after, so the
/// program logs it rather than raising it as an error. `msg!` compiles to `...; call sol_log_`.
fn feeds_log(p: &Program, i: u32) -> bool {
    let end = (i + 8).min(p.insns.len() as u32);
    for k in i + 1..end {
        if let crate::isa::Op::Call { .. } = p.insns[k as usize].op {
            return matches!(p.call_target(k), crate::program::CallTarget::Syscall(n) if n.starts_with("sol_log"));
        }
    }
    false
}

/// The program's own messages, in address order. Empty when the program carries none. Each is
/// tagged `error` or `log`: a message handed to `sol_log_` at every site that loads it is a log,
/// anything else (an Anchor error enum's `Display`, a panic) an error.
pub fn recover(p: &Program, cfg: &Cfg, literals: &Literals) -> Vec<ProgramMessageFact> {
    // Which function each instruction belongs to.
    let mut func_of = vec![u32::MAX; cfg.block_of.len()];
    for (&start, f) in &cfg.functions {
        for &b in &f.blocks {
            for i in cfg.blocks[b as usize].start..cfg.blocks[b as usize].end {
                func_of[i as usize] = start;
            }
        }
    }

    // Candidate messages the code materialises as `&str`, by the function that loads them. For each,
    // track whether every load site logs it (then it is a log, not an error).
    struct Cand {
        text: String,
        logged_everywhere: bool,
    }
    let mut by_func: BTreeMap<u32, BTreeMap<u64, Cand>> = BTreeMap::new();
    for (&i, &addr) in &literals.code_slices {
        let Some(s) = literals.strings.get(&addr) else { continue };
        if !error_shaped(&s.text) || is_framework(&s.text) {
            continue;
        }
        let Some(&func) = func_of.get(i as usize).filter(|&&f| f != u32::MAX) else { continue };
        let logged = feeds_log(p, i);
        by_func
            .entry(func)
            .or_default()
            .entry(addr)
            .and_modify(|c| c.logged_everywhere &= logged)
            .or_insert(Cand { text: s.text.clone(), logged_everywhere: logged });
    }

    // An error enum's Display loads several of its messages in one function; a lone capitalised
    // string elsewhere is more likely an incidental log than an error variant.
    let mut out: BTreeMap<u64, Cand> = BTreeMap::new();
    for msgs in by_func.into_values() {
        if msgs.len() >= 2 {
            out.extend(msgs);
        }
    }
    out.into_iter()
        .map(|(addr, c)| ProgramMessageFact {
            message: c.text,
            kind: if c.logged_everywhere { "log" } else { "error" },
            file_offset: p.elf.file_offset_of(addr).unwrap_or(0),
        })
        .collect()
}
