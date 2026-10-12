//! Match a stripped executable against the signature files of the PDB builds.
//!
//! Every unique signature of the target is looked up in all reference (PDB) builds; it takes the
//! name of the function that carries it in the latest reference build where it occurs. Each
//! target function then gets the name supported by the most signatures (weighted by kind, with
//! repeated signatures of one kind adding less), if it clearly beats the runner-up. Names found
//! in one pass identify neighbours in the next pass (symbol-relation signatures), until nothing
//! changes.

use crate::corpusdb::{CBuild, Labels};
use crate::sigs::{self, kind, sig_kind, SigFile};
use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MatchParams {
    pub passes: usize,
    pub accept: f32,
    pub margin: f32,
    /// each further signature of one kind adds this fraction of the kind weight (up to `kind_cap`)
    pub repeat: f32,
    pub kind_cap: f32,
    /// weight of a signature whose reference builds disagree on the name (voting for the name in
    /// the reference build nearest to the target)
    pub inconsistent: f32,
}

impl Default for MatchParams {
    fn default() -> Self {
        MatchParams { passes: 6, accept: 1.0, margin: 2.0, repeat: 0.25, kind_cap: 2.0, inconsistent: 0.5 }
    }
}

pub fn kind_weight(k: u8) -> f32 {
    use kind::*;
    match k {
        EXACT | PIC => 1.0,
        MNEM => 0.6,
        BAGCFG => 0.5,
        UNWIND => 0.3,
        BLOCK => 0.5,
        STR => 0.9,
        STRSET => 1.0,
        ISTR => 0.8,
        CONST | IMM => 0.5,
        IMPORTS => 0.6,
        EXPORT => 1.5,
        CALLEE_SHAPES | WL1 => 0.6,
        CALLER_SHAPES => 0.5,
        LAYOUT3 => 0.4,
        _ => {
            let r = if k >= SYMBOL { k - SYMBOL } else if k >= ANCHOR { k - ANCHOR } else { return 0.0 };
            match r {
                R_CALLEE_ORD | R_FNPTR => 0.6,
                R_CALLER | R_CALLSET | R_THUNK | R_VTSLOT => 0.8,
                R_CALLEE_PAIR | R_LAYOUT_PREV | R_LAYOUT_NEXT | R_TABLE_PREV | R_TABLE_NEXT => 0.5,
                R_GLOBAL => 0.7,
                _ => 0.0,
            }
        }
    }
}

pub fn tiny_factor(n_insn: u32) -> f32 {
    match n_insn {
        0..=2 => 0.25,
        3 => 0.35,
        4..=5 => 0.55,
        6..=9 => 0.8,
        _ => 1.0,
    }
}

/// A reference (PDB) build in memory.
pub struct RefBuild {
    pub id: String,
    pub version: String,
    /// timeline position (larger = later)
    pub order: u16,
    pub sigs: Vec<u64>,
    pub funcs: Vec<u32>,
    /// label set per function (0 = no name)
    pub fset: Vec<u32>,
}

pub struct RefSet {
    pub builds: Vec<RefBuild>,
    pub labels: Labels,
    /// max number of functions carrying a name in one reference build
    pub name_mult: HashMap<u32, u8>,
}

impl RefSet {
    /// Load the .sig files of the given builds (in timeline order).
    /// `ids`: (build id, version, timeline position), in timeline order.
    pub fn load(sig_dir: &Path, ids: &[(String, String, u16)], threads: usize) -> Result<RefSet> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
        let files: Vec<Result<SigFile>> = pool.install(|| ids.par_iter().map(|(id, _, _)| SigFile::load(&sig_dir.join(format!("{}.sig", id)))).collect());
        let mut labels = Labels::new();
        let mut name_mult: HashMap<u32, u8> = HashMap::new();
        let mut builds = Vec::new();
        for (k, f) in files.into_iter().enumerate() {
            let order = ids[k].2;
            let f = f?;
            let mut cnt: HashMap<u32, u8> = HashMap::new();
            let fset: Vec<u32> = f
                .names
                .iter()
                .map(|ns| {
                    if ns.is_empty() {
                        return 0;
                    }
                    let ids: Vec<u32> = ns.iter().map(|s| labels.name(s)).collect();
                    for &i in &ids {
                        let e = cnt.entry(i).or_insert(0);
                        *e = e.saturating_add(1);
                    }
                    labels.set(ids)
                })
                .collect();
            for (n, c) in cnt {
                let e = name_mult.entry(n).or_insert(0);
                *e = (*e).max(c);
            }
            builds.push(RefBuild { id: f.meta.id.clone(), version: f.meta.version.clone(), order, sigs: f.sigs, funcs: f.funcs, fset });
        }
        Ok(RefSet { builds, labels, name_mult })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MatchResult {
    /// label set id in RefSet.labels (0 = none)
    pub set: u32,
    pub score: f32,
    pub second: f32,
    /// distinct matched signatures supporting the label
    pub nsigs: u32,
    /// latest reference build (timeline position) supporting the label
    pub latest: u16,
    /// bitmask of signature kinds supporting the label (bit = kind, kinds < 64)
    pub kinds: u64,
    pub pass: u8,
    /// set when the best candidate was not accepted: 1 low score, 2 margin, 3 exclusivity
    pub reject: u8,
}

/// What the reference builds say about one target signature.
#[derive(Clone, Copy, Default)]
pub struct Hit {
    /// label set to vote for (0 = signature not found on a named function)
    pub set: u32,
    /// latest reference build (timeline position) carrying the signature
    pub latest: u16,
    /// all reference builds agree on the label ("unique in every version")
    pub consistent: bool,
    /// internal: label of the reference build nearest to the target, and its distance
    near_set: u32,
    near_dist: u16,
}

/// For each target signature: the label of the function carrying it in the reference builds. When
/// they disagree, the label from the reference build nearest to the target on the timeline.
fn lookup(refs: &RefSet, tsigs: &[u64], tpos: u16) -> Vec<Hit> {
    const CHUNK: usize = 1 << 16;
    let labels = &refs.labels;
    let mut hit = vec![Hit { consistent: true, near_dist: u16::MAX, ..Default::default() }; tsigs.len()];
    hit.par_chunks_mut(CHUNK).enumerate().for_each(|(ci, hch)| {
        let ts = &tsigs[ci * CHUNK..ci * CHUNK + hch.len()];
        for r in &refs.builds {
            // merge-join of two sorted ranges
            let mut j = r.sigs.partition_point(|&x| x < ts[0]);
            let mut i = 0usize;
            let dist = (r.order as i32 - tpos as i32).unsigned_abs() as u16;
            while i < ts.len() && j < r.sigs.len() {
                let (a, b) = (ts[i], r.sigs[j]);
                if a < b {
                    i += 1;
                } else if a > b {
                    j += 1;
                } else {
                    let set = r.fset[r.funcs[j] as usize];
                    if set != 0 {
                        let h = &mut hch[i];
                        if h.set == 0 {
                            h.set = set;
                        } else if !labels.compatible(h.set, set) {
                            h.consistent = false;
                        }
                        if dist < h.near_dist {
                            h.near_dist = dist;
                            h.near_set = set;
                        }
                        h.latest = h.latest.max(r.order);
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
    });
    for h in hit.iter_mut() {
        if h.set != 0 && !h.consistent {
            h.set = h.near_set;
        }
    }
    hit
}

#[derive(Clone)]
struct Cand {
    set: u32,
    per_kind: HashMap<u8, f32>,
    nsigs: u32,
    latest: u16,
    kinds: u64,
}

/// Match one target build.
/// `tpos` is the target's position on the corpus timeline (same scale as `RefBuild.order`).
pub fn match_build(refs: &mut RefSet, target: &CBuild, tpos: u16, p: &MatchParams, log: &mut Vec<String>) -> Vec<MatchResult> {
    let n = target.n;
    // label-free signatures, computed fresh (a held-out PDB build's own symbol signatures are not used)
    let (fsigs, ffuncs) = sigs::unique(sigs::free_signatures(target));
    let fhit = lookup(refs, &fsigs, tpos);
    let mut res: Vec<MatchResult> = vec![MatchResult::default(); n];
    let mut sym_ids: Vec<u64> = vec![0; n];
    for pass in 0..p.passes {
        // symbol-relation signatures from the current names
        let (ssigs, sfuncs) = if pass == 0 {
            (Vec::new(), Vec::new())
        } else {
            let mut v = Vec::new();
            sigs::relations(target, &sym_ids, kind::SYMBOL, sigs::REACH, &mut v);
            sigs::unique(v)
        };
        let shit = lookup(refs, &ssigs, tpos);
        // evidence per function
        let mut ev: Vec<Vec<(u64, u32, u16, f32)>> = vec![Vec::new(); n]; // (sig, set, latest, factor)
        for (k, h) in fhit.iter().enumerate() {
            if h.set != 0 {
                ev[ffuncs[k] as usize].push((fsigs[k], h.set, h.latest, if h.consistent { 1.0 } else { p.inconsistent }));
            }
        }
        for (k, h) in shit.iter().enumerate() {
            if h.set != 0 {
                ev[sfuncs[k] as usize].push((ssigs[k], h.set, h.latest, if h.consistent { 1.0 } else { p.inconsistent }));
            }
        }
        let labels = &mut refs.labels;
        let mut out: Vec<MatchResult> = vec![MatchResult::default(); n];
        for f in 0..n {
            if ev[f].is_empty() {
                continue;
            }
            // group compatible label sets (identical code folded under several names)
            let mut cands: Vec<Cand> = Vec::new();
            for &(s, set, ord, fac) in &ev[f] {
                let kd = sig_kind(s);
                let c = match cands.iter_mut().position(|c| labels.compatible(c.set, set)) {
                    Some(i) => {
                        let inter = labels.intersect(cands[i].set, set);
                        if inter != 0 {
                            cands[i].set = inter;
                        }
                        &mut cands[i]
                    }
                    None => {
                        cands.push(Cand { set, per_kind: HashMap::new(), nsigs: 0, latest: 0, kinds: 0 });
                        cands.last_mut().unwrap()
                    }
                };
                *c.per_kind.entry(kd).or_insert(0.0) += fac;
                c.nsigs += 1;
                c.latest = c.latest.max(ord);
                c.kinds |= 1u64 << kd;
            }
            let score = |c: &Cand| -> f32 {
                c.per_kind
                    .iter()
                    .map(|(&kd, &cnt)| {
                        let mut w = kind_weight(kd);
                        if kind::code_shape(kd) {
                            w *= tiny_factor(target.n_insn[f]);
                        }
                        // the first signature of a kind counts fully, further ones add `repeat`
                        (w * (cnt.min(1.0) + p.repeat * (cnt - 1.0).max(0.0))).min(w * p.kind_cap)
                    })
                    .sum()
            };
            let mut scored: Vec<(f32, u16, &Cand)> = cands.iter().map(|c| (score(c), c.latest, c)).collect();
            // most signatures first, then the latest version
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(b.1.cmp(&a.1)));
            let (s1, latest, c) = scored[0];
            let s2 = scored.get(1).map_or(0.0, |x| x.0);
            let nsigs = c.nsigs;
            let mut r = MatchResult { set: c.set, score: s1, second: s2, nsigs, latest, kinds: c.kinds, pass: pass as u8, reject: 0 };
            if s1 < p.accept {
                r.reject = 1;
            } else if s1 < p.margin * s2 {
                r.reject = 2;
            }
            out[f] = r;
        }
        // exclusivity: a name is claimed at most as often as it occurs in one reference build
        let mut by_name: HashMap<u32, Vec<usize>> = HashMap::new();
        for f in 0..n {
            if out[f].set != 0 && out[f].reject == 0 {
                if let Some(pn) = labels.primary(out[f].set) {
                    by_name.entry(pn).or_default().push(f);
                }
            }
        }
        for (name, mut fs) in by_name {
            let m = refs.name_mult.get(&name).copied().unwrap_or(1).max(1) as usize;
            if fs.len() <= m {
                continue;
            }
            fs.sort_by(|&a, &b| out[b].score.partial_cmp(&out[a].score).unwrap());
            let keep = out[fs[m - 1]].score >= p.margin * out[fs[m]].score;
            for (i, &f) in fs.iter().enumerate() {
                if !keep || i >= m {
                    out[f].reject = 3;
                }
            }
        }
        let new_ids: Vec<u64> = out
            .iter()
            .map(|r| if r.set != 0 && r.reject == 0 { labels.primary(r.set).map_or(0, |pn| sigs::name_hash(&labels.names[pn as usize])) } else { 0 })
            .collect();
        let changed = new_ids.iter().zip(&sym_ids).filter(|(a, b)| a != b).count();
        let accepted = new_ids.iter().filter(|&&x| x != 0).count();
        log.push(format!("  {} pass {}: free sigs {} (hit {}), symbol sigs {} (hit {}), labelled {} of {}, changed {}", target.meta.id, pass, fsigs.len(), fhit.iter().filter(|h| h.set != 0).count(), ssigs.len(), shit.iter().filter(|h| h.set != 0).count(), accepted, n, changed));
        res = out;
        sym_ids = new_ids;
        if pass > 0 && changed * 1000 <= accepted.max(1) {
            break;
        }
    }
    res
}

pub fn kinds_names(mask: u64) -> String {
    (0..64u8).filter(|k| mask & (1u64 << k) != 0).map(kind::name).collect::<Vec<_>>().join("+")
}

/// Labels CSV (same columns as `solve`): `rva,end,size,score,second,round,evidence,label`.
/// EH funclets without a label of their own take their owner's label.
pub fn write_labels(refs: &RefSet, b: &CBuild, res: &[MatchResult], path: &Path) -> Result<()> {
    use std::io::Write;
    let mut w = std::io::BufWriter::new(std::fs::File::create(path)?);
    writeln!(w, "rva,end,size,score,second,round,evidence,label")?;
    let ok = |r: &MatchResult| r.set != 0 && r.reject == 0;
    for f in 0..b.n {
        let end = b.ranges.row(f).first().map_or(b.rva[f], |r| r.1);
        let mut r = res[f].clone();
        let mut label = String::new();
        if ok(&r) {
            label = refs.labels.display(r.set);
        } else {
            r = MatchResult::default();
            let mut p = b.eh_parent[f];
            for _ in 0..4 {
                if p == u32::MAX {
                    break;
                }
                if ok(&res[p as usize]) {
                    let what = if b.eh_kind[f] == crate::eh::KIND_CATCH { "catch funclet" } else { "unwind funclet" };
                    r = res[p as usize].clone();
                    r.kinds = 0;
                    label = format!("{} [{}]", refs.labels.display(r.set), what);
                    break;
                }
                p = b.eh_parent[p as usize];
            }
        }
        writeln!(w, "0x{:x},0x{:x},{},{:.3},{:.3},{},{},\"{}\"", b.rva[f], end, b.size[f], r.score, r.second, r.pass, kinds_names(r.kinds), label.replace('"', "\"\""))?;
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct MatchEval {
    pub build: String,
    pub version: String,
    pub named: usize,
    pub predicted: usize,
    pub correct: usize,
    pub predicted_unnamed: usize,
    pub precision: f64,
    pub recall: f64,
    /// recall over named functions that are not static initializers / atexit destructors
    pub recall_core: f64,
    /// (min score, predicted, correct)
    pub buckets: Vec<(f32, usize, usize)>,
    /// named functions left unlabelled: [no candidate, low score, margin, exclusivity]
    pub missed: [usize; 4],
    pub missed_right: [usize; 4],
    pub missed_by_cat: std::collections::BTreeMap<String, usize>,
    pub sample_errors: Vec<String>,
}

fn category(name: &str) -> &'static str {
    if name.contains("`dynamic initializer") {
        "dyn_init"
    } else if name.contains("`dynamic atexit destructor") {
        "dyn_atexit"
    } else if name.contains("<lambda") {
        "lambda"
    } else if name.contains('<') {
        "template"
    } else {
        "other"
    }
}

/// Score a held-out PDB build: a prediction is right when it shares a name with the truth.
pub fn evaluate(refs: &RefSet, b: &CBuild, truth: &[Vec<String>], res: &[MatchResult]) -> MatchEval {
    const BUCKETS: [f32; 6] = [1.0, 1.5, 2.0, 3.0, 5.0, 8.0];
    let mut e = MatchEval { build: b.meta.id.clone(), version: b.meta.version.clone(), ..Default::default() };
    e.buckets = BUCKETS.iter().map(|&x| (x, 0, 0)).collect();
    let (mut core_named, mut core_correct) = (0usize, 0usize);
    for f in 0..b.n {
        let t = &truth[f];
        let r = &res[f];
        let core = !t.is_empty() && !matches!(category(&t[0]), "dyn_init" | "dyn_atexit");
        if !t.is_empty() {
            e.named += 1;
            core_named += core as usize;
        }
        let pred: Vec<&str> = if r.set != 0 { refs.labels.sets[r.set as usize].iter().map(|&i| refs.labels.names[i as usize].as_str()).collect() } else { Vec::new() };
        let right = pred.iter().any(|p| t.iter().any(|x| x == p));
        if r.set == 0 || r.reject != 0 {
            if !t.is_empty() {
                let k = if r.set == 0 { 0 } else { r.reject as usize };
                e.missed[k] += 1;
                e.missed_right[k] += right as usize;
                *e.missed_by_cat.entry(category(&t[0]).to_string()).or_insert(0) += 1;
            }
            continue;
        }
        if t.is_empty() {
            e.predicted_unnamed += 1;
            continue;
        }
        e.predicted += 1;
        e.correct += right as usize;
        core_correct += (right && core) as usize;
        let k = BUCKETS.partition_point(|&x| x <= r.score).saturating_sub(1);
        e.buckets[k].1 += 1;
        e.buckets[k].2 += right as usize;
        if !right && e.sample_errors.len() < 30 {
            e.sample_errors.push(format!(
                "{:08x} n_insn={} score={:.2} 2nd={:.2} nsigs={} [{}] predicted '{}' truth '{}'",
                b.rva[f],
                b.n_insn[f],
                r.score,
                r.second,
                r.nsigs,
                kinds_names(r.kinds),
                refs.labels.display(r.set),
                t.join(" | ")
            ));
        }
    }
    e.precision = e.correct as f64 / e.predicted.max(1) as f64;
    e.recall = e.correct as f64 / e.named.max(1) as f64;
    e.recall_core = core_correct as f64 / core_named.max(1) as f64;
    e
}

pub fn print_eval(e: &MatchEval) {
    println!(
        "{} ({}): named {} predicted {} correct {} | precision {:.4} recall {:.4} recall(core) {:.4} | unnamed predicted {}",
        e.build, e.version, e.named, e.predicted, e.correct, e.precision, e.recall, e.recall_core, e.predicted_unnamed
    );
    let (mut cp, mut cc) = (0, 0);
    for (lo, p, c) in e.buckets.iter().rev() {
        cp += p;
        cc += c;
        println!("    score >= {:>4}: bucket {:>7} prec {:.4} | cumulative {:>7} prec {:.4} recall {:.4}", lo, p, *c as f64 / (*p).max(1) as f64, cp, cc as f64 / cp.max(1) as f64, cc as f64 / e.named.max(1) as f64);
    }
    println!("    missed: none {} low {} (right {}) margin {} (right {}) exclusive {} (right {})", e.missed[0], e.missed[1], e.missed_right[1], e.missed[2], e.missed_right[2], e.missed[3], e.missed_right[3]);
    println!("    missed by category: {:?}", e.missed_by_cat);
    for s in e.sample_errors.iter().take(10) {
        println!("    ERR {}", s);
    }
}

/// Append the labelled rows of a labels CSV to the combined, DB-ready export (VAs, not RVAs).
pub fn append_export(labels_csv: &Path, meta: &crate::model::BuildMeta, image_base: u64, w: &mut impl std::io::Write) -> Result<()> {
    let txt = std::fs::read_to_string(labels_csv)?;
    for line in txt.lines().skip(1) {
        let mut it = line.splitn(8, ',');
        let (Some(rva), Some(end), Some(_size), Some(score), Some(_second), Some(_round), Some(ev), Some(label)) =
            (it.next(), it.next(), it.next(), it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if label == "\"\"" {
            continue;
        }
        let rva = u64::from_str_radix(rva.trim_start_matches("0x"), 16).unwrap_or(0);
        let end = u64::from_str_radix(end.trim_start_matches("0x"), 16).unwrap_or(0);
        writeln!(w, "{},{},{},{},0x{:x},0x{:x},{},{},{}", meta.id, meta.version, meta.platform, meta.exe_md5, image_base + rva, image_base + end, score, ev, label)?;
    }
    Ok(())
}
