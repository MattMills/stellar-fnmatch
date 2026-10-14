//! Everything the FFI generator reads from a PDB: the type records (TPI), the function ids (IPI),
//! every procedure with its type, and the public symbols (functions and data, e.g. the vftables
//! `??_7...`).

use crate::tpi::{self, FuncId, Tpi};
use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Proc {
    pub rva: u32,
    pub len: u32,
    /// undecorated qualified name (`CShip::CalcRegenAmount`)
    pub name: String,
    /// TPI index of the function type (`LF_PROCEDURE` / `LF_MFUNCTION`), 0 when unknown
    pub ty: u32,
    pub global: bool,
}

pub struct PdbInfo {
    pub tpi: Tpi,
    pub ipi: HashMap<u32, FuncId>,
    pub procs: Vec<Proc>,
    /// (rva, mangled name, is code)
    pub publics: Vec<(u32, String, bool)>,
    pub guid: String,
    pub age: u32,
}

pub fn load(path: &Path) -> Result<PdbInfo> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut pdb = pdb::PDB::open(std::io::BufReader::with_capacity(1 << 20, file)).with_context(|| format!("parse {}", path.display()))?;
    let info = pdb.pdb_information()?;
    let guid = info.guid.to_string();
    let age = pdb.debug_information()?.age().unwrap_or(info.age);
    let tpi_stream = pdb.raw_stream(pdb::StreamIndex(2))?.context("no TPI stream")?;
    let tpi = Tpi::parse(tpi_stream.as_slice())?;
    let ipi = match pdb.raw_stream(pdb::StreamIndex(4))? {
        Some(s) => tpi::parse_ipi(s.as_slice())?,
        None => HashMap::new(),
    };
    let address_map = pdb.address_map()?;

    let mut publics = Vec::new();
    let globals = pdb.global_symbols()?;
    let mut it = globals.iter();
    while let Some(sym) = it.next()? {
        if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
            if let Some(rva) = p.offset.to_rva(&address_map) {
                publics.push((rva.0, p.name.to_string().into_owned(), p.function || p.code));
            }
        }
    }

    let mut procs = Vec::new();
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(mi) = pdb.module_info(&module)? else { continue };
        let mut syms = mi.symbols()?;
        while let Some(sym) = syms.next()? {
            let kind = sym.raw_kind();
            if let Ok(pdb::SymbolData::Procedure(p)) = sym.parse() {
                let Some(rva) = p.offset.to_rva(&address_map) else { continue };
                // S_GPROC32_ID / S_LPROC32_ID refer to a function id of the IPI stream
                let ty = if kind == 0x1146 || kind == 0x1147 { ipi.get(&p.type_index.0).map_or(0, |f| f.ty) } else { p.type_index.0 };
                procs.push(Proc { rva: rva.0, len: p.len, name: p.name.to_string().into_owned(), ty, global: p.global });
            }
        }
    }
    procs.sort_by(|a, b| (a.rva, &a.name).cmp(&(b.rva, &b.name)));
    procs.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
    publics.sort();
    publics.dedup();
    Ok(PdbInfo { tpi, ipi, procs, publics, guid, age })
}
