//! Static data for the exception translator web app (stellar-except-web 2.0): no database, no
//! executables. Everything the app needs to turn `stellaris.exe  EXPORT (+ offset)` frames into
//! function names, as flat files it can binary-search with fseek.
//!
//! Layout of the output directory (all integers little-endian):
//! - `builds.json`: builds (id, platform, version, build string, commit, date, exe md5, image base,
//!   name source, counts) and `versions`: version -> build ids, Steam first.
//! - `names.idx` + `names.dat`: global string table. idx = "SFN1", u32 count, then count+1 u32
//!   offsets into names.dat; string i = dat[off[i]..off[i+1]] (UTF-8).
//! - `builds/<id>.funcs`: "SFF1", u32 count, u64 image base, then count records of 24 bytes sorted
//!   by start: u32 start rva, u32 end rva (exclusive), u32 function entry rva, u32 name id,
//!   u32 evidence id (both 0xFFFFFFFF = none), u16 score*100, u8 source, u8 EH funclet kind.
//!   A function with chained `.pdata` chunks has one record per chunk.
//!   source: 1 PDB name, 2 matched by signatures, 3 EH funclet named after its owner,
//!   4 unnamed (name is a description from named neighbours), 0 nothing.
//! - `builds/<id>.rets`: "SFR1", u32 count, then sorted u32 RVAs that follow a call instruction
//!   (valid return addresses; used to tell which build a crash report came from).
//! - `builds/<id>.exports.json`: export name -> rva (mangled and plain names).
//! - `meta.json`: generation details.

use crate::corpus::Corpus;
use crate::model::{Build, Ref};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::Path;

pub const SRC_NONE: u8 = 0;
pub const SRC_PDB: u8 = 1;
pub const SRC_MATCHED: u8 = 2;
pub const SRC_FUNCLET: u8 = 3;
pub const SRC_CONTEXT: u8 = 4;
const NONE: u32 = u32::MAX;

#[derive(Serialize)]
struct BuildEntry {
    id: String,
    platform: String,
    version: String,
    build_string: String,
    commit: Option<String>,
    build_date: Option<String>,
    exe_md5: String,
    image_base: String,
    /// "pdb" when the names come from the build's own PDB, "matched" otherwise
    names: String,
    functions: usize,
    named: usize,
    named_by_source: BTreeMap<String, usize>,
}

/// One function's label as found in a labels CSV.
struct CsvLabel {
    label: String,
    score: f32,
    evidence: String,
}

fn read_labels_csv(path: &Path) -> HashMap<u32, CsvLabel> {
    let Ok(txt) = std::fs::read_to_string(path) else { return HashMap::new() };
    let mut out = HashMap::new();
    for line in txt.lines().skip(1) {
        let mut it = line.splitn(8, ',');
        let (Some(rva), Some(_end), Some(_size), Some(score), Some(_second), Some(_round), Some(ev), Some(label)) =
            (it.next(), it.next(), it.next(), it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let label = label.trim_matches('"').replace("\"\"", "\"");
        if label.is_empty() {
            continue;
        }
        if let Ok(rva) = u32::from_str_radix(rva.trim_start_matches("0x"), 16) {
            out.insert(rva, CsvLabel { label, score: score.parse().unwrap_or(0.0), evidence: ev.to_string() });
        }
    }
    out
}

/// Per-build output before name interning.
struct Prepared {
    entry: BuildEntry,
    /// (start, end, func rva, name, evidence, score, source, eh kind)
    recs: Vec<(u32, u32, u32, Option<String>, Option<String>, u16, u8, u8)>,
    rets: Vec<u32>,
    exports: BTreeMap<String, u32>,
    image_base: u64,
}

fn prepare(b: Build, labels: HashMap<u32, CsvLabel>) -> Prepared {
    let n = b.funcs.len();
    let has_pdb = b.has_pdb();
    // label, score, evidence, source per function
    let mut lab: Vec<Option<(String, u16, Option<String>, u8)>> = vec![None; n];
    for (i, f) in b.funcs.iter().enumerate() {
        if has_pdb {
            let mut v: Vec<&str> = f.names.iter().map(|&k| b.names[k as usize].as_str()).collect();
            if v.is_empty() {
                v = f.publics.iter().map(|&k| b.names[k as usize].as_str()).collect();
            }
            v.sort();
            v.dedup();
            if !v.is_empty() {
                lab[i] = Some((v.join(" | "), 0, None, SRC_PDB));
            }
        } else if let Some(l) = labels.get(&f.rva) {
            let src = if l.label.ends_with(" funclet]") { SRC_FUNCLET } else { SRC_MATCHED };
            let ev = if l.evidence.is_empty() { None } else { Some(l.evidence.clone()) };
            lab[i] = Some((l.label.clone(), (l.score * 100.0).round().clamp(0.0, 65535.0) as u16, ev, src));
        }
    }
    // PDB builds: EH funclets without a name of their own take their owner's name
    if has_pdb {
        for i in 0..n {
            if lab[i].is_some() {
                continue;
            }
            let mut p = b.funcs[i].eh_parent;
            for _ in 0..4 {
                if p == NONE {
                    break;
                }
                if let Some((l, _, _, SRC_PDB)) = &lab[p as usize] {
                    let what = if b.funcs[i].eh_kind == crate::eh::KIND_CATCH { "catch funclet" } else { "unwind funclet" };
                    lab[i] = Some((format!("{} [{}]", l, what), 0, None, SRC_FUNCLET));
                    break;
                }
                p = b.funcs[p as usize].eh_parent;
            }
        }
    }
    // unnamed functions: describe them by their named neighbours
    let first = |s: &str| s.split(" | ").next().unwrap_or("").to_string();
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, f) in b.funcs.iter().enumerate() {
        for r in &f.refs {
            if let Ref::Call(t) | Ref::Jump(t) = r {
                let t = *t as usize;
                if t < n && callers[t].last() != Some(&(i as u32)) {
                    callers[t].push(i as u32);
                }
            }
        }
    }
    let mut context: Vec<Option<String>> = vec![None; n];
    for i in 0..n {
        if lab[i].is_some() {
            continue;
        }
        let mut calls: Vec<String> = Vec::new();
        for r in &b.funcs[i].refs {
            if let Ref::Call(t) | Ref::Jump(t) = r {
                if let Some((l, _, _, s)) = &lab[*t as usize] {
                    if *s != SRC_CONTEXT {
                        let x = first(l);
                        if !calls.contains(&x) && calls.len() < 3 {
                            calls.push(x);
                        }
                    }
                }
            }
        }
        let mut by: Vec<String> = Vec::new();
        for &c in &callers[i] {
            if let Some((l, _, _, _)) = &lab[c as usize] {
                let x = first(l);
                if !by.contains(&x) && by.len() < 3 {
                    by.push(x);
                }
            }
        }
        if calls.is_empty() && by.is_empty() {
            continue;
        }
        let mut s = String::from("[no name]");
        if !calls.is_empty() {
            s += &format!(" calls {}", calls.join(", "));
        }
        if !by.is_empty() {
            s += &format!("{} called by {}", if calls.is_empty() { "" } else { ";" }, by.join(", "));
        }
        context[i] = Some(s);
    }
    let mut named_by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut recs = Vec::with_capacity(n + n / 4);
    let mut rets = Vec::new();
    for (i, f) in b.funcs.iter().enumerate() {
        let (name, score, ev, src) = match (&lab[i], &context[i]) {
            (Some((l, sc, ev, s)), _) => (Some(l.clone()), *sc, ev.clone(), *s),
            (None, Some(c)) => (Some(c.clone()), 0, None, SRC_CONTEXT),
            (None, None) => (None, 0, None, SRC_NONE),
        };
        let key = match src {
            SRC_PDB => "pdb",
            SRC_MATCHED => "matched",
            SRC_FUNCLET => "funclet",
            SRC_CONTEXT => "unnamed_context",
            _ => "none",
        };
        *named_by_source.entry(key.to_string()).or_insert(0) += 1;
        for &(s, e) in &f.ranges {
            recs.push((s, e, f.rva, name.clone(), ev.clone(), score, src, f.eh_kind));
        }
        rets.extend_from_slice(&f.call_rets);
    }
    recs.sort_by_key(|r| (r.0, r.1));
    rets.sort_unstable();
    rets.dedup();
    let mut exports = BTreeMap::new();
    for e in &b.exports {
        exports.insert(e.name.clone(), e.rva);
        if let Some(rest) = e.name.strip_prefix('?') {
            if let Some(plain) = rest.split('@').next() {
                exports.entry(plain.to_string()).or_insert(e.rva);
            }
        }
    }
    let named = named_by_source.iter().filter(|(k, _)| k.as_str() != "none" && k.as_str() != "unnamed_context").map(|(_, v)| v).sum();
    let entry = BuildEntry {
        id: b.meta.id.clone(),
        platform: b.meta.platform.clone(),
        version: b.meta.version.clone(),
        build_string: b.meta.build_string.clone(),
        commit: b.meta.commit.clone(),
        build_date: b.meta.build_date.clone(),
        exe_md5: b.meta.exe_md5.clone(),
        image_base: format!("0x{:x}", b.image_base),
        names: if has_pdb { "pdb".into() } else { "matched".into() },
        functions: n,
        named,
        named_by_source,
    };
    Prepared { entry, recs, rets, exports, image_base: b.image_base }
}

struct Names {
    ids: HashMap<String, u32>,
    list: Vec<String>,
}

impl Names {
    fn id(&mut self, s: &Option<String>) -> u32 {
        let Some(s) = s else { return NONE };
        if let Some(&i) = self.ids.get(s) {
            return i;
        }
        let i = self.list.len() as u32;
        self.list.push(s.clone());
        self.ids.insert(s.clone(), i);
        i
    }
}

pub fn generate(corpus: &Corpus, extract_dir: &Path, labels_dir: &Path, out_dir: &Path, threads: usize) -> Result<()> {
    std::fs::create_dir_all(out_dir.join("builds"))?;
    let metas: Vec<_> = corpus.builds.iter().filter(|m| extract_dir.join(format!("{}.fnx", m.id)).exists()).collect();
    let mut names = Names { ids: HashMap::new(), list: Vec::new() };
    let mut entries: Vec<BuildEntry> = Vec::new();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
    for chunk in metas.chunks(threads.max(1)) {
        let prepared: Vec<Result<Prepared>> = pool.install(|| {
            chunk
                .par_iter()
                .map(|m| {
                    let b = Build::load(&extract_dir.join(format!("{}.fnx", m.id)))?;
                    let labels = read_labels_csv(&labels_dir.join(format!("{}.csv", m.id)));
                    Ok(prepare(b, labels))
                })
                .collect()
        });
        for p in prepared {
            let p = p?;
            if p.entry.functions < 1000 {
                eprintln!("skipping {}: {} functions", p.entry.id, p.entry.functions);
                continue;
            }
            let id = p.entry.id.clone();
            let mut w = std::io::BufWriter::new(std::fs::File::create(out_dir.join("builds").join(format!("{}.funcs", id)))?);
            w.write_all(b"SFF1")?;
            w.write_all(&(p.recs.len() as u32).to_le_bytes())?;
            w.write_all(&p.image_base.to_le_bytes())?;
            for (s, e, f, name, ev, score, src, kind) in &p.recs {
                let nid = names.id(name);
                let eid = names.id(ev);
                for v in [*s, *e, *f, nid, eid] {
                    w.write_all(&v.to_le_bytes())?;
                }
                w.write_all(&score.to_le_bytes())?;
                w.write_all(&[*src, *kind])?;
            }
            w.flush()?;
            let mut w = std::io::BufWriter::new(std::fs::File::create(out_dir.join("builds").join(format!("{}.rets", id)))?);
            w.write_all(b"SFR1")?;
            w.write_all(&(p.rets.len() as u32).to_le_bytes())?;
            for r in &p.rets {
                w.write_all(&r.to_le_bytes())?;
            }
            w.flush()?;
            std::fs::write(out_dir.join("builds").join(format!("{}.exports.json", id)), serde_json::to_string(&p.exports)?)?;
            eprintln!("{} v{}: {} functions, {} named {:?}, {} return addresses", id, p.entry.version, p.entry.functions, p.entry.named, p.entry.named_by_source, p.rets.len());
            entries.push(p.entry);
        }
    }
    // string table
    {
        let mut idx = std::io::BufWriter::new(std::fs::File::create(out_dir.join("names.idx"))?);
        let mut dat = std::io::BufWriter::new(std::fs::File::create(out_dir.join("names.dat"))?);
        idx.write_all(b"SFN1")?;
        idx.write_all(&(names.list.len() as u32).to_le_bytes())?;
        let mut off: u32 = 0;
        for s in &names.list {
            idx.write_all(&off.to_le_bytes())?;
            dat.write_all(s.as_bytes())?;
            off = off.checked_add(s.len() as u32).context("names.dat over 4 GB")?;
        }
        idx.write_all(&off.to_le_bytes())?;
        idx.flush()?;
        dat.flush()?;
    }
    // versions: Steam builds first (the translator's main audience), then GOG, newest first
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let order: Vec<&BuildEntry> = {
        let mut v: Vec<&BuildEntry> = entries.iter().collect();
        v.sort_by(|a, c| (a.platform != "steam", std::cmp::Reverse(a.build_date.clone())).cmp(&(c.platform != "steam", std::cmp::Reverse(c.build_date.clone()))));
        v
    };
    for e in order {
        if e.version != "?" {
            versions.entry(e.version.clone()).or_default().push(e.id.clone());
        }
    }
    let builds_json = serde_json::json!({ "format": 1, "builds": entries, "versions": versions });
    std::fs::write(out_dir.join("builds.json"), serde_json::to_string_pretty(&builds_json)?)?;
    let meta = serde_json::json!({
        "generator": format!("stellar-fnmatch {}", env!("CARGO_PKG_VERSION")),
        "generated": chrono_like_now(),
        "labels_dir": labels_dir.to_string_lossy(),
        "builds": entries.len(),
        "names": names.list.len(),
    });
    std::fs::write(out_dir.join("meta.json"), serde_json::to_string_pretty(&meta)?)?;
    Ok(())
}

fn chrono_like_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{} (unix time)", secs)
}
