//! Printable strings in data sections.
//!
//! Rust packs string literals back to back without terminators, so one run can
//! hold several literals. Runs are reported as found; splitting them is left to
//! the analyses that know what they are looking for.

use crate::report::StringFact;

/// Shortest run reported.
pub const MIN_LEN: usize = 4;

fn printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// All printable ASCII runs of at least [`MIN_LEN`] bytes in one section.
pub fn extract(section: &str, data: &[u8], file_offset: u64) -> Vec<StringFact> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0u8)).enumerate() {
        match (printable(b) && i < data.len(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_LEN {
                    out.push(StringFact {
                        file_offset: file_offset + s as u64,
                        section: section.to_string(),
                        text: String::from_utf8_lossy(&data[s..i]).into_owned(),
                    });
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_non_printable_bytes() {
        let data = b"\x00\x01Instruction: Buy\x00ab\x00Program log\x7f";
        let found = extract(".rodata", data, 0x40);
        let texts: Vec<_> = found.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, ["Instruction: Buy", "Program log"]);
        assert_eq!(found[0].file_offset, 0x42);
    }
}
