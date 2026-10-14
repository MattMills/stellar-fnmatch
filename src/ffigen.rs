//! `stellar-fnmatch cdef`: a Lua module of LuaJIT FFI declarations (types and functions) for a
//! set of classes and functions of a PDB build, with their dependency closure. docs/ffi.md
//! describes the module and the rules.

use crate::cdecl::{FuncDecl, Funcs};
use crate::cdef::{Db, Kind, Layout};
use crate::model::Build;
use crate::pdbtypes::{self, PdbInfo};
use crate::throws;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::Path;
use std::rc::Rc;

pub const FORMAT: u32 = 1;

#[derive(Default)]
pub struct Options {
    /// classes by C++ name (or C name)
    pub classes: Vec<String>,
    /// functions by PDB name
    pub functions: Vec<String>,
    pub all_classes: bool,
    pub all_functions: bool,
    /// leave the member lists out of the module (they are for validation and introspection)
    pub no_fields: bool,
}

#[derive(Default, Debug, serde::Serialize)]
pub struct Report {
    pub types_complete: usize,
    pub types_opaque: usize,
    pub structs: usize,
    pub unions: usize,
    pub enums: usize,
    pub packed: usize,
    pub with_bitfields: usize,
    pub with_overlaps: usize,
    pub virtual_bases: usize,
    pub notes: usize,
    pub ctypes: usize,
    pub functions: usize,
    pub functions_untyped: usize,
    pub virtual_methods: usize,
    pub virtual_unresolved: usize,
    pub this_adjusted: usize,
    pub hidden_returns: usize,
    pub hidden_returns_instance: usize,
    pub hidden_returns_cxx_udt: usize,
    pub hidden_returns_size: usize,
    pub by_value_copies: usize,
    pub by_value_registers: usize,
    pub variadic: usize,
    pub throws_yes: usize,
    pub throws_maybe: usize,
    pub throws_no: usize,
    pub throws_unknown: usize,
    pub missing_classes: Vec<String>,
    pub missing_functions: Vec<String>,
    pub odr_conflicts: usize,
}

pub fn lua_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\{}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn list(db: &Db, v: &BTreeSet<u32>) -> String {
    let names: Vec<String> = v.iter().map(|d| lua_str(&db.cname[d])).collect();
    format!("{{ {} }}", names.join(", "))
}

/// Is this a C++ EH funclet or another name no caller wants?
pub fn skip_proc(name: &str) -> bool {
    name.contains("dtor$") || name.contains("catch$") || name.contains("::`1'::") || name.starts_with("`") || name.contains("fin$") || name.contains("filt$")
}

pub struct Generated {
    pub text: String,
    pub report: Report,
}

pub fn generate(pdb_path: &Path, fnx: Option<&Build>, opts: &Options) -> Result<Generated> {
    let info = pdbtypes::load(pdb_path)?;
    generate_from(&info, pdb_path, fnx, opts)
}

pub fn generate_from(info: &PdbInfo, pdb_path: &Path, fnx: Option<&Build>, opts: &Options) -> Result<Generated> {
    let db = Db::new(&info.tpi);
    let funcs = Funcs::new(&db);
    let mut rep = Report { odr_conflicts: db.conflicts, ..Default::default() };

    // throws, by rva
    let throws_by_rva: HashMap<u32, throws::Throws> = match fnx {
        Some(b) => {
            let t = throws::analyse(b);
            b.funcs.iter().zip(t).map(|(f, t)| (f.rva, t)).collect()
        }
        None => HashMap::new(),
    };

    // roots
    let mut roots: Vec<u32> = Vec::new();
    if opts.all_classes {
        roots.extend(db.udts.iter().copied());
    }
    for c in &opts.classes {
        let mut found = false;
        if let Some(v) = db.by_cpp.get(c) {
            roots.extend(v.iter().copied());
            found = true;
        }
        if let Some(&d) = db.by_cname.get(c) {
            roots.push(d);
            found = true;
        }
        if !found {
            rep.missing_classes.push(c.clone());
        }
    }

    // functions
    let mut decls: Vec<FuncDecl> = Vec::new();
    let want: BTreeSet<&str> = opts.functions.iter().map(|s| s.as_str()).collect();
    let mut seen_names: BTreeSet<&str> = BTreeSet::new();
    for p in &info.procs {
        if !(opts.all_functions || want.contains(p.name.as_str())) || skip_proc(&p.name) {
            continue;
        }
        seen_names.insert(p.name.as_str());
        match funcs.declare(p) {
            Some(f) => decls.push(f),
            None => rep.functions_untyped += 1,
        }
    }
    for w in &want {
        if !seen_names.contains(w) {
            rep.missing_functions.push(w.to_string());
        }
    }
    for f in &decls {
        roots.extend(f.deps.full.iter().copied());
    }
    roots.sort();
    roots.dedup();
    let (order, mut opaque) = db.closure(&roots);
    for f in &decls {
        opaque.extend(f.deps.opaque.iter().copied());
    }
    let complete: BTreeSet<u32> = order.iter().copied().collect();
    opaque.retain(|x| !complete.contains(x));

    // the module
    let mut out = String::new();
    let pdb_name = pdb_path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    writeln!(out, "-- LuaJIT FFI declarations generated by stellar-fnmatch cdef from {} (guid {}, age {}). Do not edit.", pdb_name, info.guid, info.age)?;
    writeln!(out, "-- Load with fnmatch.ffi.load(); the format is described in stellar-fnmatch's docs/ffi.md.")?;
    writeln!(out, "local M = {{ format = {}, generator = {}, abi = \"msvc-x64\",", FORMAT, lua_str(&format!("stellar-fnmatch {}", env!("CARGO_PKG_VERSION"))))?;
    writeln!(out, "  pdb = {{ file = {}, guid = {}, age = {} }},", lua_str(&pdb_name), lua_str(&info.guid), info.age)?;
    if let Some(b) = fnx {
        writeln!(
            out,
            "  build = {{ id = {}, version = {}, build = {}, md5 = {}, image_base = 0x{:x} }},",
            lua_str(&b.meta.id),
            lua_str(&b.meta.version),
            lua_str(&b.meta.build_string),
            lua_str(&b.meta.exe_md5),
            b.image_base
        )?;
    }
    writeln!(out, "}}")?;
    writeln!(out, "local T, F, N, O = {{}}, {{}}, {{}}, {{}}")?;
    writeln!(out, "M.types, M.functions, M.names, M.opaque = T, F, N, O")?;

    // chunks of entries, each in its own function (a Lua function has at most 65536 constants)
    let mut chunk = 0usize;
    let mut in_chunk = 0usize;
    let mut open_chunk = |out: &mut String, in_chunk: &mut usize, chunk: &mut usize| {
        if *in_chunk == 0 {
            *chunk += 1;
            let _ = writeln!(out, "do (function() -- {}", chunk);
        }
        *in_chunk += 1;
    };
    let close_chunk = |out: &mut String, in_chunk: &mut usize, chunk: usize, force: bool| {
        if *in_chunk > 0 && (force || *in_chunk >= 400) {
            let _ = writeln!(out, "end)() end -- {}", chunk);
            *in_chunk = 0;
        }
    };

    let mut by_cpp: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for &d in &order {
        let Some(l) = db.layout(d) else { continue };
        open_chunk(&mut out, &mut in_chunk, &mut chunk);
        write_type(&mut out, &db, &l, !opts.no_fields)?;
        close_chunk(&mut out, &mut in_chunk, chunk, false);
        by_cpp.entry(l.cpp.clone()).or_default().push(l.cname.clone());
        rep.types_complete += 1;
        rep.ctypes += l.ctypes;
        match l.kind {
            Kind::Struct => rep.structs += 1,
            Kind::Union => rep.unions += 1,
            Kind::Enum => rep.enums += 1,
        }
        rep.packed += l.packed as usize;
        rep.with_bitfields += l.fields.iter().any(|f| f.bits.is_some()) as usize;
        rep.with_overlaps += (l.kind == Kind::Struct && l.cdef.contains("\n  union")) as usize;
        rep.virtual_bases += l.virtual_bases as usize;
        rep.notes += l.notes.len();
    }
    for &d in &opaque {
        open_chunk(&mut out, &mut in_chunk, &mut chunk);
        let kind = db.kind_of(d).map_or("struct", |k| k.word());
        writeln!(out, "O[{}] = {{ cpp = {}, kind = \"{}\" }}", lua_str(&db.cname[&d]), lua_str(db.cpp_name_of_def(d)), kind)?;
        close_chunk(&mut out, &mut in_chunk, chunk, false);
        by_cpp.entry(db.cpp_name_of_def(d).to_string()).or_default().push(db.cname[&d].clone());
        rep.types_opaque += 1;
    }

    // functions grouped by name, in rva order
    let mut by_name: BTreeMap<&str, Vec<&FuncDecl>> = BTreeMap::new();
    for f in &decls {
        by_name.entry(f.name.as_str()).or_default().push(f);
    }
    for (name, fs) in &by_name {
        open_chunk(&mut out, &mut in_chunk, &mut chunk);
        writeln!(out, "F[{}] = {{", lua_str(name))?;
        for f in fs {
            let t = throws_by_rva.get(&f.rva);
            write_func(&mut out, &db, f, t)?;
            rep.functions += 1;
            if let Some(v) = &f.virt {
                let _ = v;
                rep.virtual_methods += 1;
            }
            if f.virt.is_none() && funcs_is_virtual(&funcs, f) {
                rep.virtual_unresolved += 1;
            }
            rep.this_adjusted += (f.this_adjust != 0) as usize;
            if f.ret == "hidden" {
                rep.hidden_returns += 1;
                if f.kind == "method" || f.kind == "ctor" || f.kind == "dtor" {
                    rep.hidden_returns_instance += 1;
                } else if f.cxx_return_udt {
                    rep.hidden_returns_cxx_udt += 1;
                } else {
                    rep.hidden_returns_size += 1;
                }
            }
            for p in &f.params {
                if p.pass == "copy" {
                    rep.by_value_copies += 1;
                } else if p.cat == "v" {
                    rep.by_value_registers += 1;
                }
            }
            rep.variadic += f.va as usize;
            match t.map(|t| t.level()) {
                Some("yes") => rep.throws_yes += 1,
                Some("maybe") => rep.throws_maybe += 1,
                Some(_) => rep.throws_no += 1,
                None => rep.throws_unknown += 1,
            }
        }
        writeln!(out, "}}")?;
        close_chunk(&mut out, &mut in_chunk, chunk, false);
    }
    for (cpp, cs) in &by_cpp {
        open_chunk(&mut out, &mut in_chunk, &mut chunk);
        if cs.len() == 1 {
            writeln!(out, "N[{}] = {}", lua_str(cpp), lua_str(&cs[0]))?;
        } else {
            let v: Vec<String> = cs.iter().map(|c| lua_str(c)).collect();
            writeln!(out, "N[{}] = {{ {} }}", lua_str(cpp), v.join(", "))?;
        }
        close_chunk(&mut out, &mut in_chunk, chunk, false);
    }
    close_chunk(&mut out, &mut in_chunk, chunk, true);
    writeln!(out, "return M")?;
    if order.is_empty() && decls.is_empty() {
        bail!("nothing to generate (no class or function found)");
    }
    Ok(Generated { text: out, report: rep })
}

fn funcs_is_virtual(funcs: &Funcs, f: &FuncDecl) -> bool {
    let Some(c) = f.class else { return false };
    let Some((_, m)) = crate::cdecl::split_scope(&f.name) else { return false };
    funcs.methods.get(&(c, m.to_string())).map_or(false, |v| v.iter().any(|x| x.ty == f.ty && x.attr.is_virtual()))
}

fn write_type(out: &mut String, db: &Db, l: &Rc<Layout>, fields: bool) -> Result<()> {
    write!(
        out,
        "T[{}] = {{ cpp = {}, kind = \"{}\", size = {}, align = {}, cdef = {}, deps = {}, refs = {}",
        lua_str(&l.cname),
        lua_str(&l.cpp),
        l.kind.word(),
        l.size,
        l.align,
        lua_str(&l.cdef),
        list(db, &l.deps),
        list(db, &l.refs)
    )?;
    if l.packed {
        out.push_str(", packed = true");
    }
    if l.virtual_bases {
        out.push_str(", virtual_bases = true");
    }
    if !l.bases.is_empty() {
        let v: Vec<String> = l.bases.iter().map(|(b, o, p)| format!("{{ {}, {}, {} }}", lua_str(&db.cname[b]), o, lua_str(p))).collect();
        write!(out, ", bases = {{ {} }}", v.join(", "))?;
    }
    if !l.vfptrs.is_empty() {
        let v: Vec<String> = l.vfptrs.iter().map(|o| o.to_string()).collect();
        write!(out, ", vfptrs = {{ {} }}", v.join(", "))?;
    }
    if !l.enum_values.is_empty() {
        let v: Vec<String> = l.enum_values.iter().map(|(n, x)| format!("{{ {}, {} }}", lua_str(n), x)).collect();
        write!(out, ", values = {{ {} }}", v.join(", "))?;
    }
    if fields && !l.fields.is_empty() {
        let v: Vec<String> = l
            .fields
            .iter()
            .map(|f| {
                let mut s = format!("{{ {}, {}, {}", lua_str(&f.name), f.offset, lua_str(&f.cpp));
                match f.bits {
                    Some((p, n)) => {
                        let _ = write!(s, ", {}, {}", p, n);
                    }
                    None => s.push_str(", nil, nil"),
                }
                if !f.from.is_empty() {
                    let _ = write!(s, ", from = {}", lua_str(&f.from));
                }
                if f.name != f.cpp_name {
                    let _ = write!(s, ", cpp_name = {}", lua_str(&f.cpp_name));
                }
                if let Some(u) = &f.unit {
                    let _ = write!(s, ", unit = {}", lua_str(u));
                }
                s.push_str(" }");
                s
            })
            .collect();
        write!(out, ", fields = {{ {} }}", v.join(", "))?;
    }
    if !l.notes.is_empty() {
        let v: Vec<String> = l.notes.iter().map(|n| lua_str(n)).collect();
        write!(out, ", notes = {{ {} }}", v.join(", "))?;
    }
    writeln!(out, " }}")?;
    Ok(())
}

fn write_func(out: &mut String, db: &Db, f: &FuncDecl, t: Option<&throws::Throws>) -> Result<()> {
    let mut deps = f.deps.full.clone();
    let mut refs = f.deps.opaque.clone();
    // a complete type is also declared; keep refs to the rest
    refs.retain(|x| !deps.contains(x));
    deps.retain(|x| db.kind_of(*x).is_some());
    write!(
        out,
        "  {{ rva = 0x{:x}, decl = {}, cpp = {}, kind = \"{}\", ret = \"{}\"",
        f.rva,
        lua_str(&f.decl),
        lua_str(&f.cpp),
        f.kind,
        f.ret
    )?;
    if let Some(c) = &f.this_c {
        write!(out, ", this = {}", lua_str(c))?;
    }
    if f.this_adjust != 0 {
        write!(out, ", this_adjust = {}", f.this_adjust)?;
    }
    if let Some(c) = f.class {
        write!(out, ", class = {}", lua_str(&db.cname[&c]))?;
    }
    match t {
        Some(t) => {
            write!(out, ", throws = \"{}\"", t.level())?;
            let v = t.via_names();
            if !v.is_empty() {
                write!(out, ", via = \"{}\"", v.join(","))?;
            }
        }
        None => write!(out, ", throws = \"unknown\"")?,
    }
    if let Some(v) = &f.virt {
        write!(out, ", virtual = {{ vfptr = {}, slot = {}, intro = {}{} }}", v.vfptr, v.slot, lua_str(&db.cname[&v.intro]), if v.pure { ", pure = true" } else { "" })?;
    }
    write!(out, ", deps = {}, refs = {}", list(db, &deps), list(db, &refs))?;
    let ps: Vec<String> = f.params.iter().map(|p| lua_str(&format!("{}|{}|{}", p.cat, p.pass, p.cpp))).collect();
    write!(out, ", params = {{ {} }}", ps.join(", "))?;
    if f.va {
        out.push_str(", variadic = true");
    }
    if !f.rewrites.is_empty() {
        let v: Vec<String> = f.rewrites.iter().map(|r| lua_str(r)).collect();
        write!(out, ", rewrites = {{ {} }}", v.join(", "))?;
    }
    writeln!(out, " }},")?;
    Ok(())
}

/// Names from a list file: one per line, or the `name = "..."` entries of a Lua table such as
/// stellarstellaris's `functions.lua`.
pub fn read_names(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"name\s*=\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let v: Vec<String> = re.captures_iter(text).map(|c| c[1].replace("\\\"", "\"").replace("\\\\", "\\")).collect();
    if !v.is_empty() {
        return v;
    }
    text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("--")).map(|l| l.to_string()).collect()
}
