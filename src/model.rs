//! Per-build extract: the documented on-disk format (`<build id>.fnx`, postcard + zstd).
//! See SCHEMA.md for field semantics.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildMeta {
    /// unique id, e.g. `steam-6211642454078260483` or `gog-3.12.5`
    pub id: String,
    /// `steam` or `gog`
    pub platform: String,
    /// version number parsed from the build string (`3.12.5`), `?` when unknown
    pub version: String,
    /// raw build string from metadata.json (`Andromeda v3.12.5  00c910f0... (Jun 13 2024 15:58:38)`)
    pub build_string: String,
    /// 32-hex source commit hash from the build string
    pub commit: Option<String>,
    /// build date from the build string, ISO 8601
    pub build_date: Option<String>,
    /// Steam manifest id or GOG directory name
    pub source: String,
    pub exe_path: String,
    pub pdb_path: Option<String>,
    pub exe_md5: String,
    pub exe_size: u64,
}

/// Function flags
pub mod ff {
    /// has a primary `.pdata` entry
    pub const PDATA: u16 = 1;
    /// target of a direct call
    pub const CALLED: u16 = 2;
    /// a vtable slot
    pub const VTABLE: u16 = 4;
    /// exported
    pub const EXPORT: u16 = 8;
    /// pointed to by a relocated pointer in a data section
    pub const DATAPTR: u16 = 16;
    /// address taken by code (lea / mov imm)
    pub const ADDR_TAKEN: u16 = 32;
    /// target of a tail jump
    pub const JUMPED: u16 = 64;
    /// image entry point
    pub const ENTRY: u16 = 128;
    /// a PDB procedure starts here
    pub const PDB_PROC: u16 = 256;
    /// contains an indirect jump that could not be resolved to a jump table
    pub const UNRESOLVED_JMP: u16 = 512;
    /// decoding hit an invalid instruction
    pub const BAD_DECODE: u16 = 1024;
    /// added only because the PDB says a procedure starts here (never used for stripped builds)
    pub const PDB_ONLY: u16 = 2048;
}

/// Kinds of outgoing references from a function, in address order.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ref {
    /// direct call to function index
    Call(u32),
    /// tail jump to function index
    Jump(u32),
    /// call through an import slot
    CallImport(u32),
    /// jmp through an import slot (import thunk)
    JumpImport(u32),
    /// indirect call `call [reg+disp]` (virtual call); value = displacement
    CallVirt(u32),
    /// other indirect call (register, computed)
    CallIndirect,
    /// address of a function taken (lea / mov imm / data pointer in code)
    FnPtr(u32),
    /// call/jump into the middle of a function: target rva
    Interior(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Func {
    pub rva: u32,
    /// code chunks [start, end) (primary range first, then chained `.pdata` chunks)
    pub ranges: Vec<(u32, u32)>,
    pub flags: u16,
    /// bytes covered by decoded instructions
    pub size: u32,
    pub n_insn: u32,
    pub n_blocks: u32,
    pub n_edges: u32,
    /// hash of the raw instruction bytes in address order
    pub h_exact: u64,
    /// position-independent hash: normalized operands, rip-relative targets reduced to their kind,
    /// intra-function branches as instruction-index deltas
    pub h_pic: u64,
    /// hash of the mnemonic sequence
    pub h_mnem: u64,
    /// hash of the sorted mnemonic histogram
    pub h_mnem_bag: u64,
    /// hash of the CFG shape (blocks with their sizes and successor deltas)
    pub h_cfg: u64,
    /// sorted, deduplicated 32-bit hashes of basic blocks with at least 3 instructions
    pub blocks: Vec<u32>,
    /// outgoing references in address order
    pub refs: Vec<Ref>,
    /// referenced string literals (indices into Build.strings), address order
    pub strings: Vec<u32>,
    /// hashes of read-only non-string data loaded by the code (float constants, masks, ...),
    /// value = xxh3(size byte ++ bytes)
    pub consts: Vec<u64>,
    /// writable globals referenced (rva), address order
    pub globals: Vec<u32>,
    /// vtables whose address the code takes (constructors, destructors), indices into Build.vtables
    pub vtrefs: Vec<u32>,
    /// distinct notable immediates (|v| >= 0x100, not addresses), sorted
    pub imms: Vec<u64>,
    /// PDB procedure names starting here (indices into Build.names)
    pub names: Vec<u32>,
    /// PDB public (mangled) names at this address (indices into Build.names)
    pub publics: Vec<u32>,
    /// PDB procedure length, when a procedure starts here
    pub pdb_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRec {
    pub dll: String,
    pub name: String,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRec {
    pub name: String,
    pub rva: u32,
    /// function index when the export is code
    pub func: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableRec {
    pub rva: u32,
    pub type_name: Option<String>,
    pub offset: u32,
    /// function index per slot (u32::MAX when the slot target is not a known function start)
    pub slots: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdbProc {
    pub rva: u32,
    pub len: u32,
    pub name: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractStats {
    pub pdata_entries: u32,
    pub pdata_chained: u32,
    pub pdata_chain_unresolved: u32,
    pub funcs_pdata: u32,
    pub funcs_leaf: u32,
    pub jump_tables: u32,
    pub unresolved_indirect_jumps: u32,
    pub interior_refs: u32,
    pub bad_decodes: u32,
    pub pdb_procs: u32,
    pub pdb_publics: u32,
    pub pdb_procs_at_func_start: u32,
    pub pdb_procs_inside_func: u32,
    pub pdb_procs_outside: u32,
    pub seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Build {
    pub format_version: u32,
    pub meta: BuildMeta,
    pub image_base: u64,
    pub timestamp: u32,
    /// executable sections: (name, rva, size)
    pub code_sections: Vec<(String, u32, u32)>,
    pub funcs: Vec<Func>,
    pub strings: Vec<String>,
    pub imports: Vec<ImportRec>,
    pub exports: Vec<ExportRec>,
    pub vtables: Vec<VtableRec>,
    /// PDB names (procedure names undecorated, publics mangled)
    pub names: Vec<String>,
    /// PDB procedures that do not start at an extracted function (diagnostics)
    pub pdb_unmatched: Vec<PdbProc>,
    pub stats: ExtractStats,
}

impl Build {
    pub fn has_pdb(&self) -> bool {
        self.meta.pdb_path.is_some()
    }

    pub fn func_at(&self, rva: u32) -> Option<usize> {
        self.funcs.binary_search_by_key(&rva, |f| f.rva).ok()
    }

    /// Function whose ranges contain `rva`.
    pub fn func_containing(&self, rva: u32) -> Option<usize> {
        let i = self.funcs.partition_point(|f| f.rva <= rva);
        if i > 0 && self.funcs[i - 1].ranges.iter().any(|&(s, e)| rva >= s && rva < e) {
            return Some(i - 1);
        }
        // chained chunks can live far from their entry
        self.funcs.iter().position(|f| f.ranges.iter().any(|&(s, e)| rva >= s && rva < e))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("fnx.tmp");
        {
            let f = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            let mut z = zstd::Encoder::new(std::io::BufWriter::new(f), 9)?;
            let bytes = postcard::to_stdvec(self)?;
            z.write_all(&bytes)?;
            z.finish()?.flush()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Build> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut z = zstd::Decoder::new(std::io::BufReader::new(f))?;
        let mut bytes = Vec::new();
        z.read_to_end(&mut bytes)?;
        let b: Build = postcard::from_bytes(&bytes).with_context(|| format!("decode {}", path.display()))?;
        anyhow::ensure!(b.format_version == FORMAT_VERSION, "{}: format {} != {}", path.display(), b.format_version, FORMAT_VERSION);
        Ok(b)
    }
}
