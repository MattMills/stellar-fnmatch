//! Leave-one-out evaluation: held-out PDB builds are solved as if stripped, then compared with
//! their real names per confidence bucket.

use crate::corpusdb::CorpusDb;
use crate::solve::{kt_names, Solver, ALL_KT};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

pub const BUCKETS: [f32; 7] = [1.0, 1.5, 2.0, 3.0, 5.0, 8.0, 1e9];

#[derive(Debug, Default, Clone, Serialize)]
pub struct Bucket {
    pub lo: f32,
    pub predicted: usize,
    pub correct: usize,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct BuildEval {
    pub build: String,
    pub version: String,
    /// functions with a (non-funclet) PDB name
    pub named: usize,
    /// named functions whose name occurs in some non-held-out PDB build
    pub predictable: usize,
    pub predicted: usize,
    pub correct: usize,
    /// predictions on functions without a PDB name (cannot be scored)
    pub predicted_unnamed: usize,
    pub precision: f64,
    pub recall: f64,
    pub recall_predictable: f64,
    pub buckets: Vec<Bucket>,
    /// precision per evidence key type (predictions where the type voted)
    pub by_type: Vec<(String, usize, usize)>,
    /// named functions without a label, by reason: [no candidate, low score, margin, exclusivity]
    pub missed: [usize; 4],
    /// of those, how many had the right name as best candidate
    pub missed_right: [usize; 4],
    /// named functions without a label by instruction count: [1-2, 3-5, 6-10, 11-30, 31+]
    pub missed_by_size: [usize; 5],
    pub named_by_size: [usize; 5],
    pub sample_errors: Vec<String>,
    pub sample_misses: Vec<String>,
    pub missed_by_cat: std::collections::BTreeMap<String, usize>,
}

pub fn evaluate(s: &Solver, holdout: &[String]) -> Vec<BuildEval> {
    let db: &CorpusDb = &*s.db;
    // names present in the training PDB builds
    let mut known: HashSet<u32> = HashSet::new();
    for (bi, b) in db.builds.iter().enumerate() {
        if b.has_pdb && !s.target[bi] {
            for f in 0..b.n {
                for &nm in &db.labels.sets[b.truth[f] as usize] {
                    known.insert(nm);
                }
            }
        }
    }
    let mut out = Vec::new();
    for id in holdout {
        let Some(bi) = db.build_index(id) else { continue };
        let b = &db.builds[bi];
        let mut e = BuildEval { build: id.clone(), version: b.meta.version.clone(), ..Default::default() };
        e.buckets = BUCKETS[..BUCKETS.len() - 1].iter().map(|&lo| Bucket { lo, ..Default::default() }).collect();
        let mut by_type: HashMap<usize, (usize, usize)> = HashMap::new();
        for f in 0..b.n {
            let g = db.gid(bi, f);
            let t = b.truth[f];
            let a = &s.assign[g as usize];
            if t != 0 {
                e.named += 1;
                if db.labels.sets[t as usize].iter().any(|n| known.contains(n)) {
                    e.predictable += 1;
                }
            }
            let sb = match b.n_insn[f] {
                0..=2 => 0,
                3..=5 => 1,
                6..=10 => 2,
                11..=30 => 3,
                _ => 4,
            };
            if t != 0 {
                e.named_by_size[sb] += 1;
            }
            if a.set == 0 || a.reject != crate::solve::reject::NONE {
                if t != 0 {
                    let r = if a.set == 0 { 0 } else { a.reject as usize };
                    e.missed[r] += 1;
                    e.missed_by_size[sb] += 1;
                    if a.set != 0 && db.labels.compatible(a.set, t) {
                        e.missed_right[r] += 1;
                    }
                    let disp = db.labels.display(t);
                    let cat = if disp.contains("`dynamic initializer") {
                        "dyn_init"
                    } else if disp.contains("`dynamic atexit destructor") {
                        "dyn_atexit"
                    } else if disp.contains("::~") {
                        "destructor"
                    } else if disp.contains("<lambda") {
                        "lambda"
                    } else if disp.contains('<') {
                        "template"
                    } else {
                        "other"
                    };
                    *e.missed_by_cat.entry(cat.to_string()).or_insert(0) += 1;
                    if e.sample_misses.len() < 60 && cat != "dyn_init" && (f * 2654435761) % 31 == 0 {
                        e.sample_misses.push(format!(
                            "{:08x} n_insn={} reason={} best={:.2} [{}] ncallers={} ncallees={} '{}'",
                            b.rva[f],
                            b.n_insn[f],
                            r,
                            a.score,
                            kt_names(a.types),
                            b.callers.row(f).len(),
                            b.callees.row(f).len(),
                            db.labels.display(t)
                        ));
                    }
                }
                continue;
            }
            if t == 0 {
                e.predicted_unnamed += 1;
                continue;
            }
            e.predicted += 1;
            let ok = db.labels.compatible(a.set, t);
            if ok {
                e.correct += 1;
            } else if e.sample_errors.len() < 40 && f % 7 == 0 {
                e.sample_errors.push(format!(
                    "{:08x} n_insn={} score={:.2} 2nd={:.2} [{}] predicted '{}' truth '{}'",
                    b.rva[f],
                    b.n_insn[f],
                    a.score,
                    a.second,
                    kt_names(a.types),
                    db.labels.display(a.set),
                    db.labels.display(t)
                ));
            }
            let k = BUCKETS.partition_point(|&lo| lo <= a.score).saturating_sub(1).min(e.buckets.len() - 1);
            e.buckets[k].predicted += 1;
            e.buckets[k].correct += ok as usize;
            for (ti, kt) in ALL_KT.iter().enumerate() {
                if a.types & kt.bit() != 0 {
                    let x = by_type.entry(ti).or_default();
                    x.0 += 1;
                    x.1 += ok as usize;
                }
            }
        }
        e.precision = e.correct as f64 / e.predicted.max(1) as f64;
        e.recall = e.correct as f64 / e.named.max(1) as f64;
        e.recall_predictable = e.correct as f64 / e.predictable.max(1) as f64;
        let mut bt: Vec<(String, usize, usize)> = by_type.into_iter().map(|(ti, (p, c))| (ALL_KT[ti].name().to_string(), p, c)).collect();
        bt.sort();
        e.by_type = bt;
        out.push(e);
    }
    out
}

pub fn print(evals: &[BuildEval]) {
    for e in evals {
        println!(
            "{} ({}): named {} predictable {} | predicted {} correct {} | precision {:.4} recall {:.4} (of predictable {:.4}) | unnamed predicted {}",
            e.build, e.version, e.named, e.predictable, e.predicted, e.correct, e.precision, e.recall, e.recall_predictable, e.predicted_unnamed
        );
        let mut cum_p = 0;
        let mut cum_c = 0;
        for bk in e.buckets.iter().rev() {
            cum_p += bk.predicted;
            cum_c += bk.correct;
            println!(
                "    score >= {:>4}: bucket {:>7} prec {:.4} | cumulative {:>7} prec {:.4} recall {:.4}",
                bk.lo,
                bk.predicted,
                bk.correct as f64 / bk.predicted.max(1) as f64,
                cum_p,
                cum_c as f64 / cum_p.max(1) as f64,
                cum_c as f64 / e.named.max(1) as f64
            );
        }
        println!(
            "    missed: none {} low {} (right {}) margin {} (right {}) exclusive {} (right {})",
            e.missed[0], e.missed[1], e.missed_right[1], e.missed[2], e.missed_right[2], e.missed[3], e.missed_right[3]
        );
        println!("    missed by size [1-2,3-5,6-10,11-30,31+]: {:?} of named {:?}", e.missed_by_size, e.named_by_size);
        println!("    missed by category: {:?}", e.missed_by_cat);
        for (t, p, c) in &e.by_type {
            println!("    type {:>14}: {:>7} prec {:.4}", t, p, *c as f64 / (*p).max(1) as f64);
        }
        for s in e.sample_misses.iter().take(40) {
            println!("    MISS {}", s);
        }
        for s in e.sample_errors.iter().take(15) {
            println!("    ERR {}", s);
        }
    }
}
