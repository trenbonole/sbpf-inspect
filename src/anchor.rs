//! Anchor framework recovery.
//!
//! Anchor programs log `Instruction: <UpperCamelName>` on entry to each handler
//! and dispatch on `sha256("global:" + snake_name)[..8]`. Accounts and events
//! carry `sha256("account:" + Name)[..8]` and `sha256("event:" + Name)[..8]`.
//! A name is reported only when the 8 bytes it hashes to occur in the binary,
//! either as a 64-bit immediate in code or as bytes in a data section, so a
//! string that merely looks like a name is never promoted to one.
//!
//! The search runs in reverse: every 8-byte value the binary holds is indexed
//! first, then candidate names are hashed and kept only on a hit. That lets the
//! engine try every substring of every identifier-like run, which is what
//! names packed against other literals or against binary bytes need.

use std::collections::{BTreeMap, HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::{
    constants::Constant,
    report::{
        AnchorFacts, Evidence, EvidenceKind, InstructionStatus, Marker, RecoveredInstruction,
        RecoveredType, UncorroboratedLog,
    },
};

const INSTRUCTION_LOG_PREFIX: &[u8] = b"Instruction: ";
const ANCHOR_ERROR: &[u8] = b"AnchorError";
/// `anchor_lang::idl::IDL_IX_TAG`, the tag Anchor's IDL-management instructions start with.
pub const IDL_IX_TAG: u64 = 0x0a69_e9a7_78bc_f440;
/// Anchor's own IDL-management instructions, logged like user instructions.
const IDL_INSTRUCTIONS: &[&str] = &[
    "IdlCreateAccount",
    "IdlResizeAccount",
    "IdlCloseAccount",
    "IdlCreateBuffer",
    "IdlWrite",
    "IdlSetBuffer",
    "IdlSetAuthority",
];
/// Longest identifier run considered.
const MAX_TOKEN: usize = 96;
/// Longest word sequence tried as an account or event name.
const MAX_TYPE_WORDS: usize = 4;
/// Substrings of one word tried as an account or event name: lengths in this range.
const MIN_SUBSTRING: usize = 3;
const MAX_SUBSTRING: usize = 40;

/// A section whose bytes are data, not code.
pub struct DataSection<'a> {
    pub file_offset: u64,
    pub data: &'a [u8],
}

/// `sha256(namespace + ":" + name)[..8]`.
pub fn discriminator(namespace: &str, name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Split an identifier into words the way `heck` does: on `_`, on a
/// lower-or-digit to upper transition, and before the last capital of an
/// acronym that is followed by a lowercase letter (`HTTPServer` -> `HTTP`, `Server`).
pub fn split_words(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for i in 0..b.len() {
        let c = b[i];
        if c == b'_' {
            if let Some(st) = start.take() {
                words.push(&s[st..i]);
            }
            continue;
        }
        match start {
            None => start = Some(i),
            Some(st) => {
                let prev = b[i - 1];
                let next = b.get(i + 1).copied();
                let boundary = c.is_ascii_uppercase()
                    && (prev.is_ascii_lowercase()
                        || prev.is_ascii_digit()
                        || (prev.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase())));
                if boundary {
                    words.push(&s[st..i]);
                    start = Some(i);
                }
            }
        }
    }
    if let Some(st) = start {
        words.push(&s[st..]);
    }
    words
}

/// snake_case spellings an Anchor handler named after `camel` could have.
/// `heck` keeps digits inside a word (`Step2` -> `step2`), but the handler may
/// have been written `step_2`, so both spellings are tried.
fn snake_variants(camel: &str) -> Vec<String> {
    let words = split_words(camel);
    let plain = words.iter().map(|w| w.to_ascii_lowercase()).collect::<Vec<_>>().join("_");
    let mut split_digits = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            split_digits.push('_');
        }
        let lower = w.to_ascii_lowercase();
        let mut prev_alpha = false;
        for ch in lower.chars() {
            if ch.is_ascii_digit() && prev_alpha {
                split_digits.push('_');
            }
            prev_alpha = ch.is_ascii_alphabetic();
            split_digits.push(ch);
        }
    }
    if split_digits == plain { vec![plain] } else { vec![plain, split_digits] }
}

/// `settings` -> `Settings`; leaves the rest of the word as written.
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => {
            let mut s = String::with_capacity(word.len());
            s.push(first.to_ascii_uppercase());
            s.push_str(chars.as_str());
            s
        }
        None => String::new(),
    }
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect()
}

/// Every place an 8-byte value appears: code immediates first, then data bytes.
fn locate(value_le: [u8; 8], constants: &[Constant], sections: &[DataSection]) -> Vec<Evidence> {
    let mut out = Vec::new();
    for c in constants {
        if c.value.to_le_bytes() == value_le {
            out.push(Evidence { kind: c.kind, file_offset: c.file_offset });
        }
    }
    for s in sections {
        for i in find_all(s.data, &value_le) {
            out.push(Evidence { kind: EvidenceKind::DataBytes, file_offset: s.file_offset + i as u64 });
        }
    }
    out
}

/// The set of every 8-byte value the program holds, and evidence lookup for hits.
struct Haystack<'a> {
    values: HashSet<[u8; 8]>,
    constants: &'a [Constant],
    sections: &'a [DataSection<'a>],
    evidence: HashMap<[u8; 8], Vec<Evidence>>,
}

impl<'a> Haystack<'a> {
    fn new(constants: &'a [Constant], sections: &'a [DataSection<'a>]) -> Self {
        let mut values = HashSet::new();
        for c in constants {
            values.insert(c.value.to_le_bytes());
        }
        for s in sections {
            for w in s.data.windows(8) {
                let mut key = [0u8; 8];
                key.copy_from_slice(w);
                values.insert(key);
            }
        }
        Haystack { values, constants, sections, evidence: HashMap::new() }
    }

    /// Evidence for `key`, or `None` when the program does not hold it.
    fn find(&mut self, key: [u8; 8]) -> Option<&Vec<Evidence>> {
        if !self.values.contains(&key) {
            return None;
        }
        let (constants, sections) = (self.constants, self.sections);
        Some(self.evidence.entry(key).or_insert_with(|| locate(key, constants, sections)))
    }
}

/// One `Instruction: <token>` log string.
struct LogOccurrence {
    token: String,
    file_offset: u64,
}

/// Identifier-like runs of data bytes, each distinct run once.
fn identifier_runs<'s>(sections: &'s [DataSection]) -> Vec<&'s str> {
    let mut seen = HashSet::new();
    let mut runs = Vec::new();
    for s in sections {
        let mut i = 0;
        while i < s.data.len() {
            if !is_ident(s.data[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < s.data.len() && is_ident(s.data[i]) {
                i += 1;
            }
            let run = &s.data[start..i];
            if run.len() >= 2 && run.len() <= MAX_TOKEN && seen.insert(run) {
                // Identifier bytes are ASCII, so this cannot fail.
                if let Ok(text) = std::str::from_utf8(run) {
                    runs.push(text);
                }
            }
        }
    }
    runs
}

/// Account and event name candidates in one run: windows of up to
/// [`MAX_TYPE_WORDS`] words, and every substring of every word, since a name
/// can sit inside a longer run (`uwsettings`, `authorityvaultsol`).
fn type_candidates(run: &str, out: &mut HashSet<String>) {
    let words = split_words(run);
    for a in 0..words.len() {
        for b in a + 1..=(a + MAX_TYPE_WORDS).min(words.len()) {
            let name: String = words[a..b].iter().map(|w| capitalize(w)).collect();
            out.insert(name);
        }
    }
    for w in &words {
        let len = w.len();
        if len > MAX_SUBSTRING * 2 {
            continue;
        }
        for start in 0..len {
            for end in (start + MIN_SUBSTRING)..=(start + MAX_SUBSTRING).min(len) {
                out.insert(capitalize(&w[start..end]));
            }
        }
    }
}

/// Recover Anchor instruction, account and event names from one program.
pub fn analyze(constants: &[Constant], sections: &[DataSection]) -> AnchorFacts {
    let mut haystack = Haystack::new(constants, sections);

    // 1. Instruction log strings.
    let mut logs = Vec::new();
    for s in sections {
        for at in find_all(s.data, INSTRUCTION_LOG_PREFIX) {
            let start = at + INSTRUCTION_LOG_PREFIX.len();
            let end = s.data[start..]
                .iter()
                .take(MAX_TOKEN)
                .position(|&b| !is_ident(b))
                .map_or((start + MAX_TOKEN).min(s.data.len()), |n| start + n);
            if end > start {
                logs.push(LogOccurrence {
                    token: String::from_utf8_lossy(&s.data[start..end]).into_owned(),
                    file_offset: s.file_offset + at as u64,
                });
            }
        }
    }

    // 2. Instructions. A log token may run into the next packed literal
    //    (`BuyProgram log...`), so every prefix is a candidate and the
    //    discriminator decides which ones are real.
    let mut instructions: BTreeMap<String, RecoveredInstruction> = BTreeMap::new();
    let mut uncorroborated = Vec::new();
    for log in &logs {
        let mut corroborated: Vec<(String, String, [u8; 8], Vec<Evidence>)> = Vec::new();
        for end in 1..=log.token.len() {
            let prefix = &log.token[..end];
            if !prefix.as_bytes()[0].is_ascii_alphabetic() {
                break;
            }
            for snake in snake_variants(prefix) {
                let key = discriminator("global", &snake);
                if let Some(evidence) = haystack.find(key) {
                    corroborated.push((snake, prefix.to_string(), key, evidence.clone()));
                }
            }
        }
        // A token that starts with an IDL-management name is Anchor's own
        // instruction, unless a longer user name is corroborated
        // (a handler called `idl_writer` logs `IdlWriter`).
        let longest_user = corroborated.iter().map(|(_, prefix, _, _)| prefix.len()).max().unwrap_or(0);
        if let Some(fw) = IDL_INSTRUCTIONS.iter().find(|n| log.token.starts_with(**n) && longest_user <= n.len()) {
            let snake = snake_variants(fw).remove(0);
            instructions
                .entry(snake.clone())
                .or_insert_with(|| RecoveredInstruction {
                    name: snake,
                    log_name: (*fw).to_string(),
                    discriminator: None,
                    status: InstructionStatus::Framework,
                    log_string_offsets: Vec::new(),
                    discriminator_evidence: Vec::new(),
                })
                .log_string_offsets
                .push(log.file_offset);
            continue;
        }
        if corroborated.is_empty() {
            uncorroborated.push(UncorroboratedLog { log_token: log.token.clone(), file_offset: log.file_offset });
        }
        for (snake, prefix, key, evidence) in corroborated {
            let entry = instructions.entry(snake.clone()).or_insert_with(|| RecoveredInstruction {
                name: snake,
                log_name: prefix,
                discriminator: Some(hex(&key)),
                status: InstructionStatus::Corroborated,
                log_string_offsets: Vec::new(),
                discriminator_evidence: evidence,
            });
            if !entry.log_string_offsets.contains(&log.file_offset) {
                entry.log_string_offsets.push(log.file_offset);
            }
        }
    }

    // 3. Accounts and events.
    let mut candidates = HashSet::new();
    for run in identifier_runs(sections) {
        type_candidates(run, &mut candidates);
    }
    let mut accounts = BTreeMap::new();
    let mut events = BTreeMap::new();
    for name in candidates {
        if !name.as_bytes().first().is_some_and(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        for (namespace, found) in [("account", &mut accounts), ("event", &mut events)] {
            let key = discriminator(namespace, &name);
            if let Some(evidence) = haystack.find(key) {
                found.insert(
                    name.clone(),
                    RecoveredType { name: name.clone(), discriminator: hex(&key), discriminator_evidence: evidence.clone() },
                );
            }
        }
    }

    // 4. Framework markers.
    let mut error_strings = Vec::new();
    for s in sections {
        for at in find_all(s.data, ANCHOR_ERROR) {
            error_strings.push(Evidence { kind: EvidenceKind::String, file_offset: s.file_offset + at as u64 });
        }
    }
    let markers = vec![
        Marker {
            name: "instruction_log_strings",
            description: "`Instruction: <Name>` strings Anchor logs on handler entry",
            evidence: logs
                .iter()
                .map(|l| Evidence { kind: EvidenceKind::String, file_offset: l.file_offset })
                .collect(),
        },
        Marker {
            name: "idl_instruction_tag",
            description: "Anchor's IDL-management instruction tag 0x0a69e9a778bcf440",
            evidence: locate(IDL_IX_TAG.to_le_bytes(), constants, sections),
        },
        Marker {
            name: "anchor_error_strings",
            description: "`AnchorError` strings from Anchor's error logging",
            evidence: error_strings,
        },
    ];

    // Log strings alone are a weak signal: any program can log `Instruction: X`.
    // Detection needs a corroborated instruction, the IDL tag or Anchor's error strings.
    let detected = instructions.values().any(|i| i.status == InstructionStatus::Corroborated)
        || markers.iter().filter(|m| m.name != "instruction_log_strings").any(|m| !m.evidence.is_empty());

    AnchorFacts {
        detected,
        markers,
        instructions: instructions.into_values().collect(),
        uncorroborated_instruction_logs: uncorroborated,
        accounts: accounts.into_values().collect(),
        events: events.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_follow_heck() {
        assert_eq!(split_words("InitConfig"), ["Init", "Config"]);
        assert_eq!(split_words("BuyV2"), ["Buy", "V2"]);
        assert_eq!(split_words("HTTPServer"), ["HTTP", "Server"]);
        assert_eq!(split_words("collect_creator_fees"), ["collect", "creator", "fees"]);
    }

    #[test]
    fn snake_variants_cover_digit_spellings() {
        assert_eq!(snake_variants("InitConfig"), ["init_config"]);
        assert_eq!(snake_variants("Step2"), ["step2", "step_2"]);
    }

    #[test]
    fn global_discriminator_matches_anchor() {
        // sha256("global:initialize")[..8], the value in every Anchor tutorial.
        assert_eq!(hex(&discriminator("global", "initialize")), "afaf6d1f0d989bed");
    }

    #[test]
    fn name_needs_its_discriminator() {
        let disc = discriminator("global", "buy");
        let mut data = b"Instruction: BuyProgram log: Instruction: Sell\0".to_vec();
        data.extend_from_slice(&disc);
        let sections = [DataSection { file_offset: 0x1000, data: &data }];
        let facts = analyze(&[], &sections);
        let names: Vec<_> = facts.instructions.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["buy"], "sell has no discriminator in the binary");
        assert_eq!(facts.uncorroborated_instruction_logs.len(), 1);
        assert_eq!(facts.uncorroborated_instruction_logs[0].log_token, "Sell");
    }

    #[test]
    fn idl_instruction_survives_a_packed_literal() {
        let data = b"Instruction: IdlResizeAccountdata_len";
        let facts = analyze(&[], &[DataSection { file_offset: 0, data }]);
        assert_eq!(facts.instructions.len(), 1);
        assert_eq!(facts.instructions[0].name, "idl_resize_account");
        assert_eq!(facts.instructions[0].status, InstructionStatus::Framework);
        assert!(facts.uncorroborated_instruction_logs.is_empty());
    }

    #[test]
    fn longer_user_name_beats_idl_prefix() {
        let disc = discriminator("global", "idl_writer");
        let mut data = b"Instruction: IdlWriter\0".to_vec();
        data.extend_from_slice(&disc);
        let facts = analyze(&[], &[DataSection { file_offset: 0, data: &data }]);
        assert_eq!(facts.instructions.len(), 1);
        assert_eq!(facts.instructions[0].name, "idl_writer");
        assert_eq!(facts.instructions[0].status, InstructionStatus::Corroborated);
    }

    #[test]
    fn account_name_inside_noise_is_found() {
        // `uw` are the last two bytes of a neighbouring discriminator.
        let disc = discriminator("account", "Settings");
        let mut data = b"\xd3\x08uwsettings\0".to_vec();
        data.extend_from_slice(&disc);
        let facts = analyze(&[], &[DataSection { file_offset: 0, data: &data }]);
        let names: Vec<_> = facts.accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["Settings"]);
    }
}
