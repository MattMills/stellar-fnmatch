//! Minimal PE32+ (x64) reader: sections mapped into an RVA image, `.pdata`, imports (normal and
//! delay-load), exports, base relocations and MSVC RTTI vtables.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;

pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub vsize: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva + self.vsize.max(self.raw_size)
    }
    pub fn is_exec(&self) -> bool {
        self.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

/// One `.pdata` entry. `parent` is the index of the entry it chains to (UNW_FLAG_CHAININFO).
#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
    pub flags: u8,
    pub chained_to: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub dll: String,
    pub name: String,
    /// RVA of the IAT slot the code calls through
    pub iat_rva: u32,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub rva: u32,
}

#[derive(Debug, Clone)]
pub struct Vtable {
    pub rva: u32,
    /// mangled RTTI type name (".?AVFoo@@"), if the vtable has a complete object locator
    pub type_name: Option<String>,
    /// offset of this vtable inside the complete object (multiple inheritance)
    pub offset: u32,
    /// slot targets (RVAs of code)
    pub slots: Vec<u32>,
}

pub struct Pe {
    pub image_base: u64,
    pub entry: u32,
    pub timestamp: u32,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    /// the image laid out by RVA (zero-filled gaps)
    pub image: Vec<u8>,
    dirs: Vec<(u32, u32)>,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Pe {
    pub fn parse(file: &[u8]) -> Result<Pe> {
        if file.len() < 0x40 || &file[0..2] != b"MZ" {
            bail!("not an MZ file");
        }
        let pe = u32_at(file, 0x3c) as usize;
        if &file[pe..pe + 4] != b"PE\0\0" {
            bail!("no PE signature");
        }
        let coff = pe + 4;
        let machine = u16_at(file, coff);
        if machine != 0x8664 {
            bail!("machine 0x{:x} is not x64", machine);
        }
        let nsec = u16_at(file, coff + 2) as usize;
        let timestamp = u32_at(file, coff + 4);
        let opt_size = u16_at(file, coff + 16) as usize;
        let opt = coff + 20;
        if u16_at(file, opt) != 0x20b {
            bail!("not PE32+");
        }
        let entry = u32_at(file, opt + 16);
        let image_base = u64_at(file, opt + 24);
        let size_of_image = u32_at(file, opt + 56);
        let ndirs = u32_at(file, opt + 108) as usize;
        let mut dirs = Vec::new();
        for i in 0..ndirs.min(16) {
            let o = opt + 112 + i * 8;
            dirs.push((u32_at(file, o), u32_at(file, o + 4)));
        }
        let mut sections = Vec::new();
        let mut image = vec![0u8; size_of_image as usize];
        let sh = opt + opt_size;
        for i in 0..nsec {
            let o = sh + i * 40;
            let raw_name = &file[o..o + 8];
            let name = String::from_utf8_lossy(raw_name).trim_end_matches('\0').to_string();
            let vsize = u32_at(file, o + 8);
            let rva = u32_at(file, o + 12);
            let raw_size = u32_at(file, o + 16);
            let raw_ptr = u32_at(file, o + 20) as usize;
            let characteristics = u32_at(file, o + 36);
            let n = (raw_size.min(vsize.max(raw_size)) as usize)
                .min(file.len().saturating_sub(raw_ptr))
                .min(image.len().saturating_sub(rva as usize));
            image[rva as usize..rva as usize + n].copy_from_slice(&file[raw_ptr..raw_ptr + n]);
            sections.push(Section { name, rva, vsize, raw_size, characteristics });
        }
        Ok(Pe { image_base, entry, timestamp, size_of_image, sections, image, dirs })
    }

    pub fn dir(&self, i: usize) -> (u32, u32) {
        self.dirs.get(i).copied().unwrap_or((0, 0))
    }

    pub fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(rva))
    }

    pub fn is_code(&self, rva: u32) -> bool {
        self.section_of(rva).map_or(false, |s| s.is_exec())
    }

    pub fn in_image(&self, rva: u32, len: usize) -> bool {
        (rva as usize).checked_add(len).map_or(false, |e| e <= self.image.len())
    }

    pub fn u32(&self, rva: u32) -> Option<u32> {
        self.in_image(rva, 4).then(|| u32_at(&self.image, rva as usize))
    }
    pub fn u64(&self, rva: u32) -> Option<u64> {
        self.in_image(rva, 8).then(|| u64_at(&self.image, rva as usize))
    }
    pub fn bytes(&self, rva: u32, len: usize) -> Option<&[u8]> {
        self.in_image(rva, len).then(|| &self.image[rva as usize..rva as usize + len])
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.image_base).filter(|r| *r < self.size_of_image as u64).map(|r| r as u32)
    }

    pub fn cstr(&self, rva: u32, max: usize) -> Option<&[u8]> {
        let start = rva as usize;
        if start >= self.image.len() {
            return None;
        }
        let end = (start + max).min(self.image.len());
        let s = &self.image[start..end];
        let n = s.iter().position(|&b| b == 0)?;
        Some(&s[..n])
    }

    /// `.pdata` entries in table order, with chain parents resolved to entry indices.
    pub fn pdata(&self) -> Vec<RuntimeFunction> {
        let (rva, size) = self.dir(3);
        let n = size as usize / 12;
        let mut out = Vec::with_capacity(n);
        let mut by_begin: HashMap<u32, u32> = HashMap::with_capacity(n);
        for i in 0..n {
            let o = rva + (i as u32) * 12;
            let (Some(b), Some(e), Some(u)) = (self.u32(o), self.u32(o + 4), self.u32(o + 8)) else {
                break;
            };
            by_begin.insert(b, i as u32);
            out.push(RuntimeFunction { begin: b, end: e, unwind: u, flags: 0, chained_to: None });
        }
        for rf in out.iter_mut() {
            // UNWIND_INFO: u8 version:3 flags:5, u8 prolog size, u8 code count, u8 frame reg
            let Some(hdr) = self.bytes(rf.unwind & !1, 4) else { continue };
            let flags = hdr[0] >> 3;
            rf.flags = flags;
            if flags & 0x4 != 0 {
                let count = hdr[2] as u32;
                let chain = (rf.unwind & !1) + 4 + ((count + 1) & !1) * 2;
                if let Some(pb) = self.u32(chain) {
                    rf.chained_to = by_begin.get(&pb).copied();
                }
            }
        }
        out
    }

    fn read_imports(&self, desc_rva: u32, delay: bool, out: &mut Vec<Import>) {
        if desc_rva == 0 {
            return;
        }
        let stride = if delay { 32 } else { 20 };
        let mut d = desc_rva;
        loop {
            let (name_rva, iat, int) = if delay {
                (self.u32(d + 4), self.u32(d + 12), self.u32(d + 16))
            } else {
                (self.u32(d + 12), self.u32(d + 16), self.u32(d))
            };
            let (Some(name_rva), Some(iat), Some(int)) = (name_rva, iat, int) else { break };
            if name_rva == 0 && iat == 0 {
                break;
            }
            let dll = self
                .cstr(name_rva, 256)
                .map(|s| String::from_utf8_lossy(s).to_ascii_lowercase())
                .unwrap_or_default();
            let names = if int != 0 { int } else { iat };
            let mut i = 0u32;
            loop {
                let Some(e) = self.u64(names + i * 8) else { break };
                if e == 0 {
                    break;
                }
                let name = if e & (1 << 63) != 0 {
                    format!("#{}", e & 0xffff)
                } else {
                    self.cstr((e as u32) + 2, 512).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default()
                };
                out.push(Import { dll: dll.clone(), name, iat_rva: iat + i * 8 });
                i += 1;
            }
            d += stride;
        }
    }

    pub fn imports(&self) -> Vec<Import> {
        let mut out = Vec::new();
        self.read_imports(self.dir(1).0, false, &mut out);
        self.read_imports(self.dir(13).0, true, &mut out);
        out
    }

    pub fn exports(&self) -> Vec<Export> {
        let (rva, _) = self.dir(0);
        let mut out = Vec::new();
        if rva == 0 {
            return out;
        }
        let (Some(nfun), Some(nnames), Some(afun), Some(anames), Some(aord)) = (
            self.u32(rva + 20),
            self.u32(rva + 24),
            self.u32(rva + 28),
            self.u32(rva + 32),
            self.u32(rva + 36),
        ) else {
            return out;
        };
        for i in 0..nnames {
            let (Some(nr), Some(ord)) = (self.u32(anames + i * 4), self.in_image(aord + i * 2, 2).then(|| u16_at(&self.image, (aord + i * 2) as usize))) else {
                continue;
            };
            if ord as u32 >= nfun {
                continue;
            }
            let Some(f) = self.u32(afun + ord as u32 * 4) else { continue };
            let name = self.cstr(nr, 512).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
            out.push(Export { name, rva: f });
        }
        out
    }

    /// RVAs of all IMAGE_REL_BASED_DIR64 fixups.
    pub fn relocs(&self) -> Vec<u32> {
        let (rva, size) = self.dir(5);
        let mut out = Vec::new();
        let mut o = rva;
        let end = rva + size;
        while o + 8 <= end {
            let (Some(page), Some(bs)) = (self.u32(o), self.u32(o + 4)) else { break };
            if bs < 8 {
                break;
            }
            let n = (bs - 8) / 2;
            for i in 0..n {
                let e = u16_at(&self.image, (o + 8 + i * 2) as usize);
                if e >> 12 == 10 {
                    out.push(page + (e & 0xfff) as u32);
                }
            }
            o += bs;
        }
        out.sort_unstable();
        out
    }

    fn code_ptr_at(&self, reloc_set: &std::collections::HashSet<u32>, p: u32) -> Option<u32> {
        if !reloc_set.contains(&p) {
            return None;
        }
        self.u64(p).and_then(|v| self.va_to_rva(v)).filter(|&t| self.is_code(t))
    }

    /// Vtables: tables of relocated code pointers in data sections that start either right after a
    /// pointer to an MSVC RTTI complete object locator, or at an address the code takes with `lea`
    /// (`extra_starts`; Stellaris is mostly built without RTTI). A table ends at the first entry that
    /// is not a code pointer or at the next table start.
    pub fn vtables(&self, relocs: &[u32], extra_starts: &[u32]) -> Vec<Vtable> {
        let reloc_set: std::collections::HashSet<u32> = relocs.iter().copied().collect();
        let mut starts: std::collections::BTreeMap<u32, (Option<String>, u32)> = Default::default();
        for &loc in relocs {
            let Some(sec) = self.section_of(loc) else { continue };
            if sec.is_exec() {
                continue;
            }
            let Some(target) = self.u64(loc).and_then(|v| self.va_to_rva(v)) else { continue };
            // complete object locator, x64: signature 1, pSelf == own rva
            let (Some(sig), Some(off), Some(td), Some(selfr)) =
                (self.u32(target), self.u32(target + 4), self.u32(target + 12), self.u32(target + 20))
            else {
                continue;
            };
            if sig != 1 || selfr != target {
                continue;
            }
            let type_name = self
                .cstr(td + 16, 4096)
                .filter(|s| s.starts_with(b".?A"))
                .map(|s| String::from_utf8_lossy(s).into_owned());
            if self.code_ptr_at(&reloc_set, loc + 8).is_some() {
                starts.insert(loc + 8, (type_name, off));
            }
        }
        for &s in extra_starts {
            if self.section_of(s).map_or(false, |sec| !sec.is_exec()) && self.code_ptr_at(&reloc_set, s).is_some() {
                starts.entry(s).or_insert((None, 0));
            }
        }
        let keys: Vec<u32> = starts.keys().copied().collect();
        let mut out = Vec::with_capacity(keys.len());
        for (k, &vt) in keys.iter().enumerate() {
            let next = keys.get(k + 1).copied().unwrap_or(u32::MAX);
            let mut slots = Vec::new();
            let mut p = vt;
            while p < next {
                let Some(t) = self.code_ptr_at(&reloc_set, p) else { break };
                slots.push(t);
                p += 8;
            }
            let (type_name, offset) = starts.remove(&vt).unwrap();
            out.push(Vtable { rva: vt, type_name, offset, slots });
        }
        out
    }
}
