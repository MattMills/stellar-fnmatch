//! Function names from a PDB: procedure symbols (undecorated, with lengths) from every module
//! stream, and public function symbols (mangled) from the global symbol stream.

use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PdbFunc {
    pub rva: u32,
    pub len: u32,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct PdbNames {
    pub procs: Vec<PdbFunc>,
    /// (rva, mangled name)
    pub publics: Vec<(u32, String)>,
}

pub fn read(path: &Path) -> Result<PdbNames> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut pdb = pdb::PDB::open(std::io::BufReader::with_capacity(1 << 20, file))
        .with_context(|| format!("parse {}", path.display()))?;
    let address_map = pdb.address_map()?;
    let mut out = PdbNames::default();

    let globals = pdb.global_symbols()?;
    let mut it = globals.iter();
    while let Some(sym) = it.next()? {
        if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
            if !p.function && !p.code {
                continue;
            }
            if let Some(rva) = p.offset.to_rva(&address_map) {
                out.publics.push((rva.0, p.name.to_string().into_owned()));
            }
        }
    }

    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(info) = pdb.module_info(&module)? else { continue };
        let mut syms = info.symbols()?;
        while let Some(sym) = syms.next()? {
            if let Ok(pdb::SymbolData::Procedure(p)) = sym.parse() {
                if let Some(rva) = p.offset.to_rva(&address_map) {
                    out.procs.push(PdbFunc { rva: rva.0, len: p.len, name: p.name.to_string().into_owned() });
                }
            }
        }
    }
    out.procs.sort_by(|a, b| (a.rva, &a.name).cmp(&(b.rva, &b.name)));
    out.procs.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
    out.publics.sort();
    out.publics.dedup();
    Ok(out)
}
