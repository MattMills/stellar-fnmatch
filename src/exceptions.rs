//! End-to-end check on crash reports: resolve the `stellaris.exe` frames of exception.txt files
//! (exported symbol + offset) to addresses in the matching Steam build, find the containing
//! function and its label.

use crate::model::Build;
use anyhow::{Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Frame {
    pub index: u32,
    pub module: String,
    pub symbol: String,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub version: String,
    pub frames: Vec<Frame>,
}

pub fn parse(text: &str) -> Option<Report> {
    let re_ver = Regex::new(r"(?m)^Version:\s*(\S+)").unwrap();
    let re_frame = Regex::new(r"(?m)^\s*(\d+)\s+(\S+)\s+(.*?)\s*\(\+\s*(\d+)\)\s*$").unwrap();
    let version = re_ver.captures(text)?[1].trim().to_string();
    let frames = re_frame
        .captures_iter(text)
        .filter_map(|c| {
            Some(Frame { index: c[1].parse().ok()?, module: c[2].to_string(), symbol: c[3].trim().to_string(), offset: c[4].parse().ok()? })
        })
        .collect();
    Some(Report { version, frames })
}

/// A label row from a solve's labels/<build>.csv
#[derive(Debug, Clone, Default)]
pub struct LabelRow {
    pub score: f32,
    pub evidence: String,
    pub label: String,
}

pub fn read_labels(path: &Path) -> Result<HashMap<u32, LabelRow>> {
    let txt = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = HashMap::new();
    for line in txt.lines().skip(1) {
        // rva,end,size,score,second,round,evidence,"label"
        let mut it = line.splitn(8, ',');
        let rva = it.next().and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok());
        let _end = it.next();
        let _size = it.next();
        let score = it.next().and_then(|x| x.parse::<f32>().ok()).unwrap_or(0.0);
        let _second = it.next();
        let _round = it.next();
        let evidence = it.next().unwrap_or("").to_string();
        let label = it.next().unwrap_or("").trim_matches('"').replace("\"\"", "\"");
        if let Some(rva) = rva {
            if !label.is_empty() {
                out.insert(rva, LabelRow { score, evidence, label });
            }
        }
    }
    Ok(out)
}

/// Is `rva` (a return address) directly preceded by a call instruction?
pub fn after_call(image: &[u8], rva: u32) -> bool {
    for k in [5u32, 6, 2, 3, 7, 4, 8, 9] {
        let Some(start) = rva.checked_sub(k) else { continue };
        let s = start as usize;
        if s + k as usize > image.len() {
            continue;
        }
        let mut d = Decoder::with_ip(64, &image[s..s + k as usize], start as u64, DecoderOptions::NONE);
        let i = d.decode();
        if !i.is_invalid() && i.len() as u32 == k && matches!(i.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FrameOut {
    pub file: usize,
    pub frame: u32,
    pub build: String,
    pub rva: String,
    pub func_rva: String,
    pub status: String,
    pub score: f32,
    pub evidence: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VersionSummary {
    pub files: usize,
    pub files_resolved_build: usize,
    pub frames: usize,
    pub frames_no_symbol: usize,
    pub frames_in_function: usize,
    pub frames_labelled: usize,
    pub frames_labelled_hi: usize,
    pub files_all_labelled: usize,
    pub distinct_functions: usize,
    pub distinct_labelled: usize,
    pub files_by_platform: BTreeMap<String, usize>,
}

struct BuildCtx {
    build: Build,
    image: Vec<u8>,
    exports: HashMap<String, u32>,
    labels: HashMap<u32, LabelRow>,
}

fn load_ctx(meta_id: &str, extract_dir: &Path, labels_dir: &Path) -> Result<BuildCtx> {
    let build = Build::load(&extract_dir.join(format!("{}.fnx", meta_id)))?;
    let exe = std::fs::read(&build.meta.exe_path)?;
    let pe = crate::pe::Pe::parse(&exe)?;
    // exports are MSVC-mangled ("?PHYSFS_swapSLE64@@YA_J_J@Z"); crash reports print the plain name
    let mut exports = HashMap::new();
    for e in pe.exports() {
        if let Some(rest) = e.name.strip_prefix('?') {
            if let Some(plain) = rest.split('@').next() {
                exports.entry(plain.to_string()).or_insert(e.rva);
            }
        }
        exports.insert(e.name, e.rva);
    }
    let labels = if build.has_pdb() {
        // a PDB build: its own names are the truth
        let norm = crate::corpusdb::NameNorm::new();
        build
            .funcs
            .iter()
            .filter_map(|f| {
                let mut v: Vec<String> = f.names.iter().filter_map(|&k| norm.norm(&build.names[k as usize])).collect();
                v.sort();
                v.dedup();
                (!v.is_empty()).then(|| (f.rva, LabelRow { score: 99.0, evidence: "pdb".into(), label: v.join(" | ") }))
            })
            .collect()
    } else {
        read_labels(&labels_dir.join(format!("{}.csv", meta_id))).unwrap_or_default()
    };
    Ok(BuildCtx { build, image: pe.image, exports, labels })
}

/// Describe an unnamed function by its named neighbours: "[no name] calls A, B; called by C".
fn context(c: &BuildCtx, k: usize) -> String {
    use crate::model::Ref;
    let name_of = |i: usize| c.labels.get(&c.build.funcs[i].rva).map(|l| l.label.split(" | ").next().unwrap_or("").to_string());
    let mut calls: Vec<String> = Vec::new();
    for r in &c.build.funcs[k].refs {
        if let Ref::Call(t) | Ref::Jump(t) = r {
            if let Some(n) = name_of(*t as usize) {
                if !calls.contains(&n) && calls.len() < 3 {
                    calls.push(n);
                }
            }
        }
    }
    let mut callers: Vec<String> = Vec::new();
    for (i, f) in c.build.funcs.iter().enumerate() {
        if f.refs.iter().any(|r| matches!(r, Ref::Call(t) | Ref::Jump(t) if *t as usize == k)) {
            if let Some(n) = name_of(i) {
                if !callers.contains(&n) && callers.len() < 3 {
                    callers.push(n);
                }
            }
        }
    }
    let mut s = String::from("[no name]");
    if !calls.is_empty() {
        s += &format!(" calls {}", calls.join(", "));
    }
    if !callers.is_empty() {
        s += &format!("{} called by {}", if calls.is_empty() { "" } else { ";" }, callers.join(", "));
    }
    s
}

pub fn run(corpus: &crate::corpus::Corpus, extract_dir: &Path, labels_dir: &Path, files: &[PathBuf], hi_score: f32) -> Result<(Vec<FrameOut>, BTreeMap<String, VersionSummary>)> {
    let mut reports: Vec<(usize, Report)> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let Ok(bytes) = std::fs::read(f) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if let Some(r) = parse(&text) {
            reports.push((i, r));
        }
    }
    let mut by_version: BTreeMap<String, Vec<(usize, Report)>> = BTreeMap::new();
    for (i, r) in reports {
        by_version.entry(r.version.clone()).or_default().push((i, r));
    }
    let mut frames_out = Vec::new();
    let mut summary: BTreeMap<String, VersionSummary> = BTreeMap::new();
    for (version, reps) in by_version {
        // Steam builds first (ties go to Steam), then GOG builds of the same version: a report
        // belongs to the build where its return addresses follow call instructions
        let mut cands: Vec<&crate::model::BuildMeta> = corpus.builds.iter().filter(|b| b.platform == "steam" && b.version == version).collect();
        cands.extend(corpus.builds.iter().filter(|b| b.platform == "gog" && b.version == version));
        if cands.is_empty() {
            continue;
        }
        let ctxs: Vec<BuildCtx> = cands.iter().filter_map(|m| load_ctx(&m.id, extract_dir, labels_dir).ok()).collect();
        if ctxs.is_empty() {
            continue;
        }
        let s = summary.entry(version.clone()).or_default();
        let mut funcs_seen: HashMap<(usize, u32), bool> = HashMap::new();
        for (fi, rep) in &reps {
            s.files += 1;
            let frames: Vec<&Frame> = rep.frames.iter().filter(|f| f.module.eq_ignore_ascii_case("stellaris.exe")).collect();
            // choose the build where the most return addresses follow a call
            let mut best: Option<(usize, usize)> = None;
            for (ci, c) in ctxs.iter().enumerate() {
                let mut ok = 0;
                for f in &frames {
                    if let Some(&e) = c.exports.get(&f.symbol) {
                        let rva = e as u64 + f.offset;
                        if rva < c.image.len() as u64 && (f.index == 1 || after_call(&c.image, rva as u32)) {
                            ok += 1;
                        }
                    }
                }
                if best.map_or(true, |b| ok > b.1) {
                    best = Some((ci, ok));
                }
            }
            let (ci, ok) = best.unwrap();
            if ok > 0 {
                s.files_resolved_build += 1;
            }
            let c = &ctxs[ci];
            *s.files_by_platform.entry(c.build.meta.platform.clone()).or_insert(0) += 1;
            let mut all = !frames.is_empty();
            for f in &frames {
                s.frames += 1;
                let mut out = FrameOut { file: *fi, frame: f.index, build: c.build.meta.id.clone(), ..Default::default() };
                let Some(&e) = c.exports.get(&f.symbol) else {
                    s.frames_no_symbol += 1;
                    out.status = if f.offset == 0 { "no_symbol_offset0".into() } else { "unknown_export".into() };
                    frames_out.push(out);
                    all = false;
                    continue;
                };
                let rva = (e as u64 + f.offset) as u32;
                out.rva = format!("0x{:x}", rva);
                // return addresses point after the call: look up the byte before
                let look = if f.index == 1 { rva } else { rva.saturating_sub(1) };
                let Some(k) = c.build.func_containing(look) else {
                    out.status = "no_function".into();
                    frames_out.push(out);
                    all = false;
                    continue;
                };
                s.frames_in_function += 1;
                let fr = c.build.funcs[k].rva;
                out.func_rva = format!("0x{:x}", fr);
                let first = !funcs_seen.contains_key(&(ci, fr));
                // an EH funclet takes the name of the function that owns it
                let mut via = c.labels.get(&fr).cloned();
                if via.is_none() {
                    let mut p = c.build.funcs[k].eh_parent;
                    let kind = c.build.funcs[k].eh_kind;
                    for _ in 0..4 {
                        if p == u32::MAX {
                            break;
                        }
                        let pf = &c.build.funcs[p as usize];
                        if let Some(l) = c.labels.get(&pf.rva) {
                            let what = if kind == crate::eh::KIND_CATCH { "catch funclet" } else { "unwind funclet" };
                            via = Some(LabelRow { score: l.score, evidence: format!("eh_parent+{}", l.evidence), label: format!("{} [{}]", l.label, what) });
                            break;
                        }
                        p = pf.eh_parent;
                    }
                }
                match via.as_ref() {
                    Some(l) => {
                        s.frames_labelled += 1;
                        if l.score >= hi_score {
                            s.frames_labelled_hi += 1;
                        }
                        out.status = "labelled".into();
                        out.score = l.score;
                        out.evidence = l.evidence.clone();
                        out.label = l.label.clone();
                        funcs_seen.insert((ci, fr), true);
                    }
                    None => {
                        out.status = "unlabelled".into();
                        out.label = context(c, k);
                        all = false;
                        if first {
                            funcs_seen.insert((ci, fr), false);
                        }
                    }
                }
                frames_out.push(out);
            }
            if all {
                s.files_all_labelled += 1;
            }
        }
        s.distinct_functions = funcs_seen.len();
        s.distinct_labelled = funcs_seen.values().filter(|v| **v).count();
    }
    Ok((frames_out, summary))
}
