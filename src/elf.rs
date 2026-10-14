//! A bounds-checked reader for sBPF program ELFs.
//!
//! Every field comes from untrusted bytes, so every read is checked and every count is capped. A
//! malformed file yields an [`ElfError`], never a panic. sBPF v3 programs may carry no section
//! headers at all (SIMD-0189), so program headers are read too.

use std::fmt;

pub const EM_BPF: u16 = 247;
pub const EM_SBPF: u16 = 263;

const MAX_SECTIONS: usize = 4096;
const MAX_SEGMENTS: usize = 256;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_NAME: usize = 1024;

pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_SYMTAB: u32 = 2;
pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    NotElf64LittleEndian,
    NotSbpf(u16),
    BadHeader(&'static str),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::TooSmall => write!(f, "too small to be an ELF file"),
            ElfError::BadMagic => write!(f, "no ELF magic"),
            ElfError::NotElf64LittleEndian => write!(f, "not a 64-bit little-endian ELF"),
            ElfError::NotSbpf(m) => write!(f, "e_machine {m} is not BPF (247) or SBPF (263)"),
            ElfError::BadHeader(what) => write!(f, "malformed ELF: {what}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub kind: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub entsize: u64,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub info: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl Symbol {
    pub fn is_function(&self) -> bool {
        self.info & 0x0f == 2
    }
    pub fn is_defined(&self) -> bool {
        self.shndx != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rel {
    pub offset: u64,
    pub kind: u32,
    pub sym: u32,
}

pub struct Elf<'a> {
    pub bytes: &'a [u8],
    pub e_machine: u16,
    pub e_flags: u32,
    pub e_entry: u64,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub diagnostics: Vec<String>,
}

pub fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}
pub fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
pub fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// A NUL-terminated name inside `table`, capped at [`MAX_NAME`] bytes.
fn name_in(table: &[u8], at: usize) -> String {
    let rest = table.get(at..).unwrap_or(&[]);
    let end = rest.iter().take(MAX_NAME).position(|&c| c == 0).unwrap_or(rest.len().min(MAX_NAME));
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

impl<'a> Elf<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < 64 {
            return Err(ElfError::TooSmall);
        }
        if &bytes[0..4] != b"\x7fELF" {
            return Err(ElfError::BadMagic);
        }
        if bytes[4] != 2 || bytes[5] != 1 {
            return Err(ElfError::NotElf64LittleEndian);
        }
        let e_machine = u16_at(bytes, 18).ok_or(ElfError::TooSmall)?;
        if e_machine != EM_BPF && e_machine != EM_SBPF {
            return Err(ElfError::NotSbpf(e_machine));
        }
        let e_entry = u64_at(bytes, 24).ok_or(ElfError::TooSmall)?;
        let e_phoff = u64_at(bytes, 32).ok_or(ElfError::TooSmall)?;
        let e_shoff = u64_at(bytes, 40).ok_or(ElfError::TooSmall)?;
        let e_flags = u32_at(bytes, 48).ok_or(ElfError::TooSmall)?;
        let e_phentsize = u16_at(bytes, 54).ok_or(ElfError::TooSmall)? as usize;
        let e_phnum = u16_at(bytes, 56).ok_or(ElfError::TooSmall)? as usize;
        let e_shentsize = u16_at(bytes, 58).ok_or(ElfError::TooSmall)? as usize;
        let e_shnum = u16_at(bytes, 60).ok_or(ElfError::TooSmall)? as usize;
        let e_shstrndx = u16_at(bytes, 62).ok_or(ElfError::TooSmall)? as usize;

        let mut diagnostics = Vec::new();
        let mut segments = Vec::new();
        if e_phnum > 0 {
            if e_phentsize != 56 {
                return Err(ElfError::BadHeader("program header entry size is not 56"));
            }
            if e_phnum > MAX_SEGMENTS {
                return Err(ElfError::BadHeader("too many program headers"));
            }
            let base = usize::try_from(e_phoff).map_err(|_| ElfError::BadHeader("program header offset"))?;
            for i in 0..e_phnum {
                let o = base.checked_add(i * 56).ok_or(ElfError::BadHeader("program header offset"))?;
                if o.checked_add(56).is_none_or(|end| end > bytes.len()) {
                    return Err(ElfError::BadHeader("program header table runs past the end of the file"));
                }
                let (Some(kind), Some(flags), Some(offset), Some(vaddr), Some(filesz), Some(memsz)) = (
                    u32_at(bytes, o),
                    u32_at(bytes, o + 4),
                    u64_at(bytes, o + 8),
                    u64_at(bytes, o + 16),
                    u64_at(bytes, o + 32),
                    u64_at(bytes, o + 40),
                ) else {
                    return Err(ElfError::BadHeader("program header table runs past the end of the file"));
                };
                segments.push(Segment { kind, flags, offset, vaddr, filesz, memsz });
            }
        }

        let mut sections = Vec::new();
        if e_shnum > 0 && e_shoff != 0 {
            if e_shentsize != 64 {
                return Err(ElfError::BadHeader("section header entry size is not 64"));
            }
            if e_shnum > MAX_SECTIONS {
                return Err(ElfError::BadHeader("too many section headers"));
            }
            let base = usize::try_from(e_shoff).map_err(|_| ElfError::BadHeader("section header offset"))?;
            let mut name_offsets = Vec::with_capacity(e_shnum);
            for i in 0..e_shnum {
                let o = base.checked_add(i * 64).ok_or(ElfError::BadHeader("section header offset"))?;
                if o.checked_add(64).is_none_or(|end| end > bytes.len()) {
                    return Err(ElfError::BadHeader("section header table runs past the end of the file"));
                }
                let (Some(name), Some(kind), Some(flags), Some(addr), Some(offset), Some(size), Some(link), Some(entsize)) = (
                    u32_at(bytes, o),
                    u32_at(bytes, o + 4),
                    u64_at(bytes, o + 8),
                    u64_at(bytes, o + 16),
                    u64_at(bytes, o + 24),
                    u64_at(bytes, o + 32),
                    u32_at(bytes, o + 40),
                    u64_at(bytes, o + 56),
                ) else {
                    return Err(ElfError::BadHeader("section header table runs past the end of the file"));
                };
                name_offsets.push(name as usize);
                sections.push(Section { name: String::new(), kind, flags, addr, offset, size, link, entsize });
            }
            match sections.get(e_shstrndx).cloned() {
                Some(strtab) => {
                    let table = section_slice(bytes, &strtab);
                    for (s, at) in sections.iter_mut().zip(name_offsets) {
                        s.name = name_in(table, at);
                    }
                }
                None => diagnostics.push("section name table index is out of range; sections are unnamed".into()),
            }
        }
        if sections.is_empty() && segments.is_empty() {
            return Err(ElfError::BadHeader("no section headers and no program headers"));
        }
        Ok(Elf { bytes, e_machine, e_flags, e_entry, sections, segments, diagnostics })
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn data(&self, s: &Section) -> &'a [u8] {
        section_slice(self.bytes, s)
    }

    pub fn segment_data(&self, s: &Segment) -> &'a [u8] {
        clamp(self.bytes, s.offset, s.filesz)
    }

    /// Symbols of a symbol table section, using its linked string table.
    pub fn symbols(&self, table: &Section) -> Vec<Symbol> {
        let data = self.data(table);
        let strings = self.sections.get(table.link as usize).map(|s| self.data(s)).unwrap_or(&[]);
        data.chunks_exact(24)
            .take(MAX_SYMBOLS)
            .map(|e| Symbol {
                name: name_in(strings, u32::from_le_bytes([e[0], e[1], e[2], e[3]]) as usize),
                info: e[4],
                shndx: u16::from_le_bytes([e[6], e[7]]),
                value: u64::from_le_bytes([e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]]),
                size: u64::from_le_bytes([e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23]]),
            })
            .collect()
    }

    pub fn dynamic_symbols(&self) -> Vec<Symbol> {
        self.sections.iter().find(|s| s.kind == SHT_DYNSYM).map(|s| self.symbols(s)).unwrap_or_default()
    }

    pub fn static_symbols(&self) -> Vec<Symbol> {
        self.sections.iter().find(|s| s.kind == SHT_SYMTAB).map(|s| self.symbols(s)).unwrap_or_default()
    }

    /// `Elf64_Rel` entries of every SHT_REL section.
    pub fn relocations(&self) -> Vec<Rel> {
        let mut out = Vec::new();
        for s in self.sections.iter().filter(|s| s.kind == SHT_REL) {
            for e in self.data(s).chunks_exact(16).take(MAX_SYMBOLS) {
                let info = u64::from_le_bytes([e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]]);
                out.push(Rel {
                    offset: u64::from_le_bytes([e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]]),
                    kind: (info & 0xffff_ffff) as u32,
                    sym: (info >> 32) as u32,
                });
            }
        }
        out
    }

    /// File offset of a virtual address, through the section (or, failing that, segment) holding it.
    pub fn file_offset_of(&self, vaddr: u64) -> Option<u64> {
        for s in &self.sections {
            if s.kind != SHT_NOBITS && s.addr != 0 && vaddr >= s.addr && vaddr - s.addr < s.size {
                return s.offset.checked_add(vaddr - s.addr);
            }
        }
        for p in &self.segments {
            if p.kind == PT_LOAD && vaddr >= p.vaddr && vaddr - p.vaddr < p.filesz {
                return p.offset.checked_add(vaddr - p.vaddr);
            }
        }
        None
    }
}

fn clamp(bytes: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(bytes.len());
    let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX)).min(bytes.len());
    &bytes[start..end]
}

fn section_slice<'b>(bytes: &'b [u8], s: &Section) -> &'b [u8] {
    if s.kind == SHT_NOBITS { &[] } else { clamp(bytes, s.offset, s.size) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_without_panicking() {
        assert_eq!(Elf::parse(b"").err(), Some(ElfError::TooSmall));
        assert_eq!(Elf::parse(&[0u8; 64]).err(), Some(ElfError::BadMagic));
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18] = 62; // x86-64
        assert_eq!(Elf::parse(&b).err(), Some(ElfError::NotSbpf(62)));
        b[18] = EM_BPF as u8;
        // No sections and no segments.
        assert!(matches!(Elf::parse(&b), Err(ElfError::BadHeader(_))));
        // A section table pointing far past the end.
        b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        b[58] = 64;
        b[60] = 3;
        assert!(Elf::parse(&b).is_err());
    }
}
