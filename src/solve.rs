//! The solver: fingerprints (keys) per function, global per-build uniqueness, name voting from the
//! nearest labelled builds on the timeline, per-build exclusivity, iterated with relational keys.
//!
//! A key value votes for a target function when it occurs exactly once in the target's build and
//! the nearest builds (before and after on the timeline) where it also occurs exactly once on a
//! labelled function agree on the label. Keys that are unique in every build where they occur,
//! and whose labelled occurrences all agree, get full weight. Relational keys are recomputed
//! every round from the current labels (PDB names, and accepted predictions), and residual
//! neighbour matching pairs the remaining unlabelled callers/callees of a labelled function with
//! the corresponding unclaimed ones in the nearest PDB builds.

use crate::corpusdb::{CBuild, CorpusDb};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use xxhash_rust::xxh3::xxh3_64_with_seed;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Kt {
    Exact,
    Pic,
    Mnem,
    BagCfg,
    Unwind,
    Block,
    Str,
    StrSet,
    IStr,
    Const,
    Imm,
    ImportSet,
    Export,
    RCalleeOrd,
    RCalleePic,
    RCallerPic,
    RCallSet,
    RCalleePair,
    RThunk,
    RVtSlot,
    RLayoutPrev,
    RLayoutNext,
    RTablePrev,
    RTableNext,
    RFnPtr,
    RGlobal,
    RResidual,
}

pub const ALL_KT: [Kt; 27] = [
    Kt::Exact,
    Kt::Pic,
    Kt::Mnem,
    Kt::BagCfg,
    Kt::Unwind,
    Kt::Block,
    Kt::Str,
    Kt::StrSet,
    Kt::IStr,
    Kt::Const,
    Kt::Imm,
    Kt::ImportSet,
    Kt::Export,
    Kt::RCalleeOrd,
    Kt::RCalleePic,
    Kt::RCallerPic,
    Kt::RCallSet,
    Kt::RCalleePair,
    Kt::RThunk,
    Kt::RVtSlot,
    Kt::RLayoutPrev,
    Kt::RLayoutNext,
    Kt::RTablePrev,
    Kt::RTableNext,
    Kt::RFnPtr,
    Kt::RGlobal,
    Kt::RResidual,
];

impl Kt {
    pub fn name(self) -> &'static str {
        match self {
            Kt::Exact => "exact",
            Kt::Pic => "pic",
            Kt::Mnem => "mnem",
            Kt::BagCfg => "bagcfg",
            Kt::Unwind => "unwind",
            Kt::Block => "block",
            Kt::Str => "str",
            Kt::StrSet => "strset",
            Kt::IStr => "istr",
            Kt::Const => "const",
            Kt::Imm => "imm",
            Kt::ImportSet => "imports",
            Kt::Export => "export",
            Kt::RCalleeOrd => "r_callee_ord",
            Kt::RCalleePic => "r_callee_pic",
            Kt::RCallerPic => "r_caller_pic",
            Kt::RCallSet => "r_callset",
            Kt::RCalleePair => "r_callee_pair",
            Kt::RThunk => "r_thunk",
            Kt::RVtSlot => "r_vtslot",
            Kt::RLayoutPrev => "r_layout_prev",
            Kt::RLayoutNext => "r_layout_next",
            Kt::RTablePrev => "r_table_prev",
            Kt::RTableNext => "r_table_next",
            Kt::RFnPtr => "r_fnptr",
            Kt::RGlobal => "r_global",
            Kt::RResidual => "r_residual",
        }
    }
    pub fn relational(self) -> bool {
        (self as u8) >= (Kt::RCalleeOrd as u8)
    }
    pub fn bit(self) -> u32 {
        1 << (self as u8)
    }
    /// key types whose value depends only on the function's own code (dampened for tiny functions)
    pub fn code_shape(self) -> bool {
        matches!(self, Kt::Exact | Kt::Pic | Kt::Mnem | Kt::BagCfg | Kt::Imm | Kt::Const)
    }
}

pub fn kt_names(mask: u32) -> String {
    ALL_KT.iter().filter(|k| mask & k.bit() != 0).map(|k| k.name()).collect::<Vec<_>>().join("+")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Params {
    pub rounds: usize,
    /// minimum score to accept a label
    pub accept: f32,
    /// best score must be at least `margin` times the second best
    pub margin: f32,
    /// weight factor for votes that come from predicted (not PDB) labels of other builds
    pub pred_weight: f32,
    /// predicted labels below this score are not used as evidence for other builds
    pub pred_min_score: f32,
    /// predicted labels below this score are not used as anchors for relational keys
    pub anchor_min_score: f32,
    /// layout keys reach this many functions away from a labelled one
    pub layout_reach: usize,
    pub weights: Vec<(Kt, f32)>,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            rounds: 12,
            accept: 1.0,
            margin: 2.0,
            pred_weight: 0.6,
            pred_min_score: 2.0,
            anchor_min_score: 1.0,
            layout_reach: 8,
            weights: vec![
                (Kt::Exact, 1.0),
                (Kt::Pic, 1.0),
                (Kt::Mnem, 0.6),
                (Kt::BagCfg, 0.5),
                (Kt::Unwind, 0.3),
                (Kt::Block, 0.5),
                (Kt::Str, 0.9),
                (Kt::StrSet, 1.0),
                (Kt::IStr, 0.8),
                (Kt::Const, 0.5),
                (Kt::Imm, 0.5),
                (Kt::ImportSet, 0.6),
                (Kt::Export, 1.5),
                (Kt::RCalleeOrd, 0.6),
                (Kt::RCalleePic, 0.9),
                (Kt::RCallerPic, 0.9),
                (Kt::RCallSet, 0.9),
                (Kt::RCalleePair, 0.6),
                (Kt::RThunk, 0.9),
                (Kt::RVtSlot, 0.9),
                (Kt::RLayoutPrev, 0.6),
                (Kt::RLayoutNext, 0.6),
                (Kt::RTablePrev, 0.6),
                (Kt::RTableNext, 0.6),
                (Kt::RFnPtr, 0.7),
                (Kt::RGlobal, 0.8),
                (Kt::RResidual, 1.0),
            ],
        }
    }
}

impl Params {
    pub fn weight(&self, k: Kt) -> f32 {
        self.weights.iter().find(|(x, _)| *x == k).map_or(0.0, |w| w.1)
    }
}

/// Size dampening for code-shape keys: a 2-instruction function that is "unique" usually differs
/// from its look-alikes only by an ID constant that shifts between versions.
pub fn tiny_factor(n_insn: u32) -> f32 {
    match n_insn {
        0..=2 => 0.25,
        3 => 0.35,
        4..=5 => 0.55,
        6..=9 => 0.8,
        _ => 1.0,
    }
}

pub mod reject {
    pub const NONE: u8 = 0;
    pub const LOW_SCORE: u8 = 1;
    pub const MARGIN: u8 = 2;
    pub const EXCLUSIVE: u8 = 3;
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Assign {
    /// label set id (0 = unlabelled)
    pub set: u32,
    /// score of the label, or of the best rejected candidate when set == 0
    pub score: f32,
    pub second: f32,
    /// key types that voted for the label
    pub types: u32,
    pub round: u8,
    pub reject: u8,
}

#[derive(Clone, Copy)]
struct Cand {
    set: u32,
    score: f32,
    types: u32,
}

#[inline]
fn h2(a: u64, b: u64, seed: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&a.to_le_bytes());
    buf[8..].copy_from_slice(&b.to_le_bytes());
    xxh3_64_with_seed(&buf, seed)
}

#[inline]
fn h3(a: u64, b: u64, c: u64, seed: u64) -> u64 {
    let mut buf = [0u8; 24];
    buf[..8].copy_from_slice(&a.to_le_bytes());
    buf[8..16].copy_from_slice(&b.to_le_bytes());
    buf[16..].copy_from_slice(&c.to_le_bytes());
    xxh3_64_with_seed(&buf, seed)
}

fn hseq(v: &[u64], seed: u64) -> u64 {
    let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    xxh3_64_with_seed(&bytes, seed)
}

const NONE: u32 = u32::MAX;

/// Emit (key value, local function index) for one key type and one build. `prim[f]` is the
/// representative name id of each function's current label (NONE when unlabelled).
pub fn emit(kt: Kt, b: &CBuild, prim: &[u32], reach: usize, out: &mut Vec<(u64, u32)>) {
    let n = b.n;
    let seed = kt as u64 + 1;
    match kt {
        Kt::Exact => (0..n).filter(|&f| b.n_insn[f] >= 2).for_each(|f| out.push((b.h_exact[f], f as u32))),
        Kt::Pic => (0..n).filter(|&f| b.n_insn[f] >= 2).for_each(|f| out.push((b.h_pic[f], f as u32))),
        Kt::Mnem => (0..n).filter(|&f| b.n_insn[f] >= 4).for_each(|f| out.push((b.h_mnem[f] ^ 0x9e37_79b9_7f4a_7c15, f as u32))),
        Kt::BagCfg => (0..n).filter(|&f| b.n_insn[f] >= 6).for_each(|f| out.push((h2(b.h_bag[f], b.h_cfg[f], seed), f as u32))),
        Kt::Unwind => (0..n).filter(|&f| b.h_unwind[f] != 0).for_each(|f| out.push((h2(b.h_unwind[f], (b.n_blocks[f] as u64).min(64), seed), f as u32))),
        Kt::Block => {
            for f in 0..n {
                for &x in b.blocks.row(f) {
                    out.push((x as u64 | (seed << 40), f as u32));
                }
            }
        }
        Kt::Str => {
            for f in 0..n {
                for &x in b.strs.row(f) {
                    out.push((x, f as u32));
                }
            }
        }
        Kt::StrSet => {
            for f in 0..n {
                let s = b.strs.row(f);
                if s.len() >= 2 {
                    let mut v = s.to_vec();
                    v.sort_unstable();
                    out.push((hseq(&v, seed), f as u32));
                }
            }
        }
        Kt::IStr => {
            for f in 0..n {
                for &x in b.istrs.row(f) {
                    out.push((x ^ (seed << 56), f as u32));
                }
            }
        }
        Kt::Const => {
            for f in 0..n {
                for &x in b.consts.row(f) {
                    out.push((x ^ seed, f as u32));
                }
            }
        }
        Kt::Imm => {
            for f in 0..n {
                for &x in b.imms.row(f) {
                    out.push((h2(x, 0, seed), f as u32));
                }
            }
        }
        Kt::ImportSet => {
            for f in 0..n {
                let s = b.imports.row(f);
                if !s.is_empty() {
                    let lg = 32 - (b.n_insn[f].max(1)).leading_zeros() as u64;
                    out.push((h2(hseq(s, seed), lg, seed), f as u32));
                }
            }
        }
        Kt::Export => (0..n).filter(|&f| b.export[f] != 0).for_each(|f| out.push((b.export[f], f as u32))),
        Kt::RCalleeOrd => {
            for f in 0..n {
                if prim[f] == NONE {
                    continue;
                }
                for (j, &c) in b.callees.row(f).iter().enumerate() {
                    out.push((h2(prim[f] as u64, j as u64, seed), c));
                }
            }
        }
        Kt::RCalleePic => {
            for f in 0..n {
                if prim[f] == NONE {
                    continue;
                }
                for &c in b.callees.row(f) {
                    out.push((h2(prim[f] as u64, b.h_pic[c as usize], seed), c));
                }
            }
        }
        Kt::RCallerPic => {
            for f in 0..n {
                for &c in b.callees.row(f) {
                    let p = prim[c as usize];
                    if p != NONE {
                        out.push((h2(p as u64, b.h_pic[f], seed), f as u32));
                    }
                }
            }
        }
        Kt::RCallSet => {
            for f in 0..n {
                let cs = b.callees.row(f);
                if cs.len() >= 2 && cs.iter().all(|&c| prim[c as usize] != NONE) {
                    let mut v: Vec<u64> = cs.iter().map(|&c| prim[c as usize] as u64).collect();
                    v.sort_unstable();
                    out.push((hseq(&v, seed), f as u32));
                }
            }
        }
        Kt::RCalleePair => {
            for f in 0..n {
                let cs = b.callees.row(f);
                for w in cs.windows(2) {
                    let (a, c) = (prim[w[0] as usize], prim[w[1] as usize]);
                    if a != NONE && c != NONE {
                        out.push((h2(a as u64, c as u64, seed), f as u32));
                    }
                }
            }
        }
        Kt::RThunk => {
            for f in 0..n {
                let t = b.thunk_to[f];
                if t != NONE && prim[t as usize] != NONE {
                    out.push((h2(prim[t as usize] as u64, 0, seed), f as u32));
                }
            }
        }
        Kt::RVtSlot => {
            // vtable identity from its slot 0 and from the functions that take its address
            let mut refs: Vec<Vec<u32>> = vec![Vec::new(); b.vtables.len()];
            for f in 0..n {
                for &v in b.vtrefs.row(f) {
                    if (v as usize) < refs.len() {
                        refs[v as usize].push(f as u32);
                    }
                }
            }
            for (vi, slots) in b.vtables.iter().enumerate() {
                let s0 = slots.first().copied().unwrap_or(NONE);
                let p0 = if s0 != NONE { prim[s0 as usize] } else { NONE };
                for (k, &s) in slots.iter().enumerate() {
                    if s == NONE {
                        continue;
                    }
                    if k > 0 && p0 != NONE {
                        out.push((h3(p0 as u64, k as u64, 0, seed), s));
                    }
                    for &r in &refs[vi] {
                        let pr = prim[r as usize];
                        if pr != NONE {
                            out.push((h3(pr as u64, k as u64, 1, seed), s));
                        }
                    }
                }
            }
        }
        Kt::RLayoutPrev => {
            for p in 0..n {
                if prim[p] == NONE {
                    continue;
                }
                for k in 1..=reach {
                    if p + k < n {
                        out.push((h3(prim[p] as u64, k as u64, b.h_bag[p + k], seed), (p + k) as u32));
                    }
                }
            }
        }
        Kt::RLayoutNext => {
            for q in 0..n {
                if prim[q] == NONE {
                    continue;
                }
                for k in 1..=reach.min(q) {
                    out.push((h3(prim[q] as u64, k as u64, b.h_bag[q - k], seed), (q - k) as u32));
                }
            }
        }
        Kt::RTablePrev | Kt::RTableNext => {
            // neighbours inside data tables of code pointers (initializer tables, registrations)
            let fwd = kt == Kt::RTablePrev;
            for t in &b.tables {
                for (i, &e) in t.iter().enumerate() {
                    if e == NONE || prim[e as usize] == NONE {
                        continue;
                    }
                    for k in 1..=reach {
                        let j = if fwd { i + k } else { match i.checked_sub(k) { Some(j) => j, None => break } };
                        if j >= t.len() {
                            break;
                        }
                        if t[j] != NONE {
                            out.push((h3(prim[e as usize] as u64, k as u64, b.h_bag[t[j] as usize], seed), t[j]));
                        }
                    }
                }
            }
        }
        Kt::RFnPtr => {
            for f in 0..n {
                if prim[f] == NONE {
                    continue;
                }
                for (j, &t) in b.fnptrs.row(f).iter().enumerate() {
                    out.push((h2(prim[f] as u64, j as u64, seed), t));
                }
            }
        }
        Kt::RGlobal => {
            // functions sharing a writable global with a labelled function: (label, ordinal of the
            // global in that function, own shape). Popular globals carry no identity.
            let mut users: HashMap<u32, Vec<u32>> = HashMap::new();
            for f in 0..n {
                for &g in b.globals.row(f) {
                    users.entry(g).or_default().push(f as u32);
                }
            }
            for f in 0..n {
                if prim[f] == NONE {
                    continue;
                }
                for (j, g) in b.globals.row(f).iter().enumerate() {
                    let us = &users[g];
                    if us.len() > 32 {
                        continue;
                    }
                    for &u in us {
                        if u as usize != f {
                            out.push((h3(prim[f] as u64, j as u64, b.h_bag[u as usize], seed), u));
                        }
                    }
                }
            }
        }
        Kt::RResidual => {}
    }
}

/// One labelled occurrence in a key group.
#[derive(Clone, Copy)]
struct LabOcc {
    build: u32,
    set: u32,
    truth: bool,
}

/// A vote for a target function.
#[derive(Clone, Copy)]
struct Vote {
    gid: u32,
    set_a: u32,
    set_b: u32,
    w: f32,
}

pub struct Solver<'a> {
    pub db: &'a mut CorpusDb,
    pub params: Params,
    /// per build: labels are predicted (no PDB, or held out)
    pub target: Vec<bool>,
    /// current label set per global node: truth for non-target builds, predictions for targets
    pub label: Vec<u32>,
    pub assign: Vec<Assign>,
    /// max number of functions carrying a name in one PDB build (overloads share names)
    name_mult: Vec<u8>,
    /// per truth build: primary name -> function (names carried by exactly one function)
    name_index: Vec<HashMap<u32, u32>>,
    pub log: Vec<String>,
}

impl<'a> Solver<'a> {
    pub fn new(db: &'a mut CorpusDb, params: Params, holdout: &[String]) -> Solver<'a> {
        let target: Vec<bool> = db.builds.iter().map(|b| !b.has_pdb || holdout.contains(&b.meta.id)).collect();
        let mut label = vec![0u32; db.total];
        let mut name_mult = vec![0u8; db.labels.names.len()];
        let mut name_index: Vec<HashMap<u32, u32>> = vec![HashMap::new(); db.builds.len()];
        for (bi, b) in db.builds.iter().enumerate() {
            if !b.has_pdb {
                continue;
            }
            let mut cnt: HashMap<u32, u8> = HashMap::new();
            for f in 0..b.n {
                for &nm in &db.labels.sets[b.truth[f] as usize] {
                    let e = cnt.entry(nm).or_insert(0);
                    *e = e.saturating_add(1);
                }
            }
            if !target[bi] {
                let mut idx: HashMap<u32, u32> = HashMap::with_capacity(b.n);
                for f in 0..b.n {
                    label[db.base[bi] as usize + f] = b.truth[f];
                    if let Some(p) = db.labels.primary(b.truth[f]) {
                        if cnt.get(&p) == Some(&1) {
                            idx.insert(p, f as u32);
                        }
                    }
                }
                name_index[bi] = idx;
            }
            for (nm, c) in cnt {
                name_mult[nm as usize] = name_mult[nm as usize].max(c);
            }
        }
        let total = db.total;
        Solver { db, params, target, label, assign: vec![Assign::default(); total], name_mult, name_index, log: Vec::new() }
    }

    fn logln(&mut self, s: String) {
        eprintln!("{}", s);
        self.log.push(s);
    }

    /// Representative name id per node for relational keys (anchors).
    fn prims(&self) -> Vec<Vec<u32>> {
        let labels = &self.db.labels;
        let prim_of_set: Vec<u32> = (0..labels.sets.len() as u32).map(|s| labels.primary(s).unwrap_or(NONE)).collect();
        self.db
            .builds
            .par_iter()
            .enumerate()
            .map(|(bi, b)| {
                let base = self.db.base[bi] as usize;
                (0..b.n)
                    .map(|f| {
                        let g = base + f;
                        let s = self.label[g];
                        if s == 0 {
                            return NONE;
                        }
                        if self.target[bi] && self.assign[g].score < self.params.anchor_min_score {
                            return NONE;
                        }
                        prim_of_set[s as usize]
                    })
                    .collect()
            })
            .collect()
    }

    /// Group scan for one key type: votes for target occurrences.
    fn votes_for(&self, kt: Kt, prims: &[Vec<u32>]) -> (Vec<Vote>, usize, usize) {
        let db = &*self.db;
        let reach = self.params.layout_reach;
        // estimate the occurrence count from one build and split the key space so that one
        // partition holds at most ~48M occurrences
        let est = {
            let mut tmp = Vec::new();
            let bi = db.builds.len() / 2;
            emit(kt, &db.builds[bi], &prims[bi], reach, &mut tmp);
            tmp.len() as f64 / db.builds[bi].n.max(1) as f64 * db.total as f64
        };
        let parts = ((est / 48e6).ceil() as u64).max(1);
        let mut votes: Vec<Vote> = Vec::new();
        let mut nocc = 0usize;
        let mut ngroups = 0usize;
        for part in 0..parts {
            let (v, o, g) = self.votes_part(kt, prims, part, parts);
            votes.extend(v);
            nocc += o;
            ngroups += g;
        }
        (votes, nocc, ngroups)
    }

    fn votes_part(&self, kt: Kt, prims: &[Vec<u32>], part: u64, parts: u64) -> (Vec<Vote>, usize, usize) {
        let db = &*self.db;
        let reach = self.params.layout_reach;
        let in_part = |v: u64| parts == 1 || (v.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) % parts == part;
        let mut occ: Vec<(u64, u32)> = db
            .builds
            .par_iter()
            .enumerate()
            .flat_map_iter(|(bi, b)| {
                let mut out = Vec::new();
                emit(kt, b, &prims[bi], reach, &mut out);
                out.retain(|x| in_part(x.0));
                let base = db.base[bi];
                out.into_iter().map(move |(v, f)| (v, base + f))
            })
            .collect();
        occ.par_sort_unstable();
        occ.dedup();
        let nocc = occ.len();
        let mut bounds: Vec<(u32, u32)> = Vec::new();
        let mut s = 0usize;
        for i in 1..=occ.len() {
            if i == occ.len() || occ[i].0 != occ[s].0 {
                if i - s >= 2 {
                    bounds.push((s as u32, i as u32));
                }
                s = i;
            }
        }
        let ngroups = bounds.len();
        let nb = db.builds.len();
        let w_type = self.params.weight(kt);
        let pred_w = self.params.pred_weight;
        let pred_min = self.params.pred_min_score;
        let labels = &db.labels;
        let votes: Vec<Vote> = bounds
            .par_iter()
            .flat_map_iter(|&(s, e)| {
                let g = &occ[s as usize..e as usize];
                let mut out: Vec<Vote> = Vec::new();
                if g.len() > 4 * nb {
                    return out.into_iter();
                }
                // per-build runs (gid order == build order == timeline order)
                let mut runs: Vec<(u32, u32, u32)> = Vec::with_capacity(g.len()); // (build, count, gid)
                for &(_, gid) in g {
                    let (bi, _) = db.split(gid);
                    match runs.last_mut() {
                        Some(r) if r.0 == bi as u32 => r.1 += 1,
                        _ => runs.push((bi as u32, 1, gid)),
                    }
                }
                let strict = runs.iter().all(|r| r.1 == 1);
                let mut labs: Vec<LabOcc> = Vec::new();
                let mut has_target = false;
                for r in &runs {
                    if r.1 != 1 {
                        continue;
                    }
                    let bi = r.0 as usize;
                    if self.target[bi] {
                        has_target = true;
                    }
                    let set = self.label[r.2 as usize];
                    if set == 0 {
                        continue;
                    }
                    let truth = !self.target[bi];
                    if !truth && self.assign[r.2 as usize].score < pred_min {
                        continue;
                    }
                    labs.push(LabOcc { build: r.0, set, truth });
                }
                if !has_target || labs.is_empty() {
                    return out.into_iter();
                }
                let consistent = labs.iter().all(|l| labels.compatible(l.set, labs[0].set));
                let base_w = w_type * if strict { 1.0 } else { 0.7 } * if consistent { 1.0 } else { 0.8 };
                for r in &runs {
                    if r.1 != 1 || !self.target[r.0 as usize] {
                        continue;
                    }
                    let gid = r.2;
                    let (tb, tf) = db.split(gid);
                    let mut w = base_w;
                    if kt.code_shape() {
                        w *= tiny_factor(db.builds[tb].n_insn[tf]);
                    }
                    let pos = labs.partition_point(|l| l.build < r.0);
                    let before = labs[..pos].iter().rev().find(|l| l.build != r.0);
                    let after = labs[pos..].iter().find(|l| l.build != r.0);
                    let vote = match (before, after) {
                        (Some(a), Some(b)) => {
                            if labels.compatible(a.set, b.set) {
                                let f = if a.truth && b.truth { 1.0 } else if a.truth || b.truth { (1.0 + pred_w) / 2.0 } else { pred_w };
                                Some(Vote { gid, set_a: a.set, set_b: b.set, w: w * f })
                            } else {
                                None
                            }
                        }
                        (Some(a), None) | (None, Some(a)) => {
                            let f = if a.truth { 0.85 } else { pred_w * 0.85 };
                            Some(Vote { gid, set_a: a.set, set_b: a.set, w: w * f })
                        }
                        (None, None) => None,
                    };
                    if let Some(v) = vote {
                        out.push(v);
                    }
                }
                out.into_iter()
            })
            .collect();
        (votes, nocc, ngroups)
    }

    /// Residual neighbour matching. For a labelled function in a target build and the function with
    /// the same name in a reference PDB build (the nearest before and after on the timeline), pair
    /// the target's unlabelled callees (callers) with the reference's callees (callers) whose names
    /// are not used anywhere in the target build: a 1:1 residual, or a pair that is unique within
    /// the residual by code hash.
    fn residual_votes(&self) -> Vec<Vote> {
        let db = &*self.db;
        let labels = &db.labels;
        let w = self.params.weight(Kt::RResidual);
        let truth_builds: Vec<usize> = (0..db.builds.len()).filter(|&b| !self.target[b]).collect();
        (0..db.builds.len())
            .into_par_iter()
            .filter(|&bi| self.target[bi])
            .flat_map_iter(|bi| {
                let b = &db.builds[bi];
                let base = db.base[bi] as usize;
                let lab = |f: usize| self.label[base + f];
                let used: HashSet<u32> = (0..b.n).filter_map(|f| labels.primary(lab(f))).collect();
                let pos = truth_builds.partition_point(|&t| t < bi);
                let refs: Vec<usize> = [pos.checked_sub(1).map(|i| truth_builds[i]), truth_builds.get(pos).copied()].into_iter().flatten().collect();
                // candidate (target func) -> per ref: set
                let mut found: HashMap<u32, Vec<(usize, u32, bool)>> = HashMap::new(); // f -> (ref, set, similar)
                for f in 0..b.n {
                    let Some(p) = labels.primary(lab(f)) else { continue };
                    if self.assign[base + f].score < self.params.anchor_min_score {
                        continue;
                    }
                    for &rb in &refs {
                        let r = &db.builds[rb];
                        let Some(&rf) = self.name_index[rb].get(&p) else { continue };
                        let rbase = db.base[rb] as usize;
                        for dir in 0..2 {
                            let (mine, theirs) = if dir == 0 { (b.callees.row(f), r.callees.row(rf as usize)) } else { (b.callers.row(f), r.callers.row(rf as usize)) };
                            let u: Vec<u32> = mine.iter().copied().filter(|&c| lab(c as usize) == 0).collect();
                            if u.is_empty() {
                                continue;
                            }
                            let rr: Vec<u32> = theirs
                                .iter()
                                .copied()
                                .filter(|&c| {
                                    let s = self.label[rbase + c as usize];
                                    s != 0 && labels.primary(s).map_or(false, |pn| !used.contains(&pn))
                                })
                                .collect();
                            if rr.is_empty() {
                                continue;
                            }
                            let similar = |a: u32, c: u32| {
                                let (x, y) = (b.n_insn[a as usize] as i64, r.n_insn[c as usize] as i64);
                                (x - y).abs() <= 3.max(x.max(y) / 4)
                            };
                            if u.len() == 1 && rr.len() == 1 {
                                let set = self.label[rbase + rr[0] as usize];
                                found.entry(u[0]).or_default().push((rb, set, similar(u[0], rr[0])));
                                continue;
                            }
                            // unique pairing inside the residual by code hash
                            for hk in 0..3 {
                                let hb = |x: u32| match hk {
                                    0 => b.h_pic[x as usize],
                                    1 => b.h_mnem[x as usize],
                                    _ => b.h_bag[x as usize],
                                };
                                let hr = |x: u32| match hk {
                                    0 => r.h_pic[x as usize],
                                    1 => r.h_mnem[x as usize],
                                    _ => r.h_bag[x as usize],
                                };
                                let mut any = false;
                                for &a in &u {
                                    let ma: Vec<u32> = rr.iter().copied().filter(|&c| hr(c) == hb(a)).collect();
                                    if ma.len() == 1 && u.iter().filter(|&&x| hb(x) == hb(a)).count() == 1 {
                                        let set = self.label[rbase + ma[0] as usize];
                                        found.entry(a).or_default().push((rb, set, true));
                                        any = true;
                                    }
                                }
                                if any {
                                    break;
                                }
                            }
                        }
                    }
                }
                let mut out = Vec::new();
                for (f, v) in found {
                    // all evidence must agree; both references agreeing counts more
                    let first = v[0].1;
                    if !v.iter().all(|x| labels.compatible(x.1, first)) {
                        continue;
                    }
                    let nrefs = v.iter().map(|x| x.0).collect::<HashSet<_>>().len();
                    let sim = v.iter().any(|x| x.2);
                    let ww = w * if nrefs >= 2 || refs.len() == 1 { 1.0 } else { 0.85 } * if sim { 1.0 } else { 0.5 };
                    out.push(Vote { gid: (base + f as usize) as u32, set_a: first, set_b: first, w: ww });
                }
                out.into_iter()
            })
            .collect()
    }

    fn merge_votes(&mut self, kt: Kt, mut votes: Vec<Vote>, cands: &mut HashMap<u32, Vec<Cand>>) -> usize {
        votes.par_sort_unstable_by(|a, b| (a.gid, a.set_a, a.set_b).cmp(&(b.gid, b.set_a, b.set_b)));
        let nv = votes.len();
        let wt = self.params.weight(kt);
        let mut i = 0;
        while i < votes.len() {
            let gid = votes[i].gid;
            let mut j = i;
            while j < votes.len() && votes[j].gid == gid {
                j += 1;
            }
            // merge compatible label sets within this node's votes of this type:
            // max weight plus a small bonus per extra agreeing value
            let mut local: Vec<(u32, f32, u32)> = Vec::new();
            for v in &votes[i..j] {
                let set = if v.set_a == v.set_b { v.set_a } else { self.db.labels.intersect(v.set_a, v.set_b) };
                if set == 0 {
                    continue;
                }
                if let Some(l) = local.iter_mut().find(|l| self.db.labels.compatible(l.0, set)) {
                    let inter = self.db.labels.intersect(l.0, set);
                    if inter != 0 {
                        l.0 = inter;
                    }
                    l.1 = l.1.max(v.w);
                    l.2 += 1;
                } else {
                    local.push((set, v.w, 1));
                }
            }
            for (set, w, c) in local {
                let w = w + (0.1 * (c as f32 - 1.0)).min(0.3) * wt;
                let list = cands.entry(gid).or_default();
                if let Some(c) = list.iter_mut().find(|c| self.db.labels.compatible(c.set, set)) {
                    let inter = self.db.labels.intersect(c.set, set);
                    if inter != 0 {
                        c.set = inter;
                    }
                    c.score += w;
                    c.types |= kt.bit();
                } else {
                    list.push(Cand { set, score: w, types: kt.bit() });
                }
            }
            i = j;
        }
        nv
    }

    /// Run all rounds until labels stop changing.
    pub fn run(&mut self) {
        let rounds = self.params.rounds;
        for round in 0..rounds {
            let t0 = std::time::Instant::now();
            let prims = self.prims();
            let ntarget: usize = self.db.builds.iter().enumerate().filter(|(i, _)| self.target[*i]).map(|(_, b)| b.n).sum();
            let mut cands: HashMap<u32, Vec<Cand>> = HashMap::with_capacity(ntarget);
            for kt in ALL_KT {
                let tk = std::time::Instant::now();
                let (votes, nocc, ngroups) = if kt == Kt::RResidual { (self.residual_votes(), 0, 0) } else { self.votes_for(kt, &prims) };
                let nv = self.merge_votes(kt, votes, &mut cands);
                self.logln(format!("  round {} {:>14}: occ {:>10} groups {:>9} votes {:>9} ({:.1}s)", round, kt.name(), nocc, ngroups, nv, tk.elapsed().as_secs_f64()));
            }
            drop(prims);
            // decide per node
            let mut decided: Vec<(u32, Assign)> = Vec::with_capacity(cands.len());
            for (gid, list) in cands.iter() {
                let mut best: Option<&Cand> = None;
                let mut second = 0f32;
                for c in list {
                    match best {
                        Some(b) if b.score >= c.score => second = second.max(c.score),
                        Some(b) => {
                            second = second.max(b.score);
                            best = Some(c);
                        }
                        None => best = Some(c),
                    }
                }
                let b = best.unwrap();
                let mut a = Assign { set: b.set, score: b.score, second, types: b.types, round: round as u8, reject: reject::NONE };
                if b.score < self.params.accept {
                    a.reject = reject::LOW_SCORE;
                } else if b.score < self.params.margin * second {
                    a.reject = reject::MARGIN;
                }
                decided.push((*gid, a));
            }
            drop(cands);
            // per-build exclusivity: a name is claimed by at most name_mult functions per build
            let mut by_build_name: HashMap<(usize, u32), Vec<(usize, f32)>> = HashMap::new();
            for (k, (gid, a)) in decided.iter().enumerate() {
                if a.reject != reject::NONE {
                    continue;
                }
                let (bi, _) = self.db.split(*gid);
                if let Some(p) = self.db.labels.primary(a.set) {
                    by_build_name.entry((bi, p)).or_default().push((k, a.score));
                }
            }
            for ((_, name), mut v) in by_build_name {
                let m = self.name_mult[name as usize].max(1) as usize;
                if v.len() <= m {
                    continue;
                }
                v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
                let keep = v[m - 1].1 >= self.params.margin * v[m].1;
                for (k, (idx, _)) in v.iter().enumerate() {
                    if !keep || k >= m {
                        decided[*idx].1.reject = reject::EXCLUSIVE;
                    }
                }
            }
            let prev: Vec<u32> = self.label.clone();
            for (bi, b) in self.db.builds.iter().enumerate() {
                if self.target[bi] {
                    let base = self.db.base[bi] as usize;
                    for f in 0..b.n {
                        self.label[base + f] = 0;
                        self.assign[base + f] = Assign::default();
                    }
                }
            }
            let mut labelled = 0usize;
            let mut rejected = [0usize; 4];
            for (gid, a) in &decided {
                self.assign[*gid as usize] = *a;
                if a.reject == reject::NONE {
                    self.label[*gid as usize] = a.set;
                    labelled += 1;
                } else {
                    rejected[a.reject as usize] += 1;
                }
            }
            let diff = self.label.par_iter().zip(prev.par_iter()).filter(|(a, b)| a != b).count();
            self.logln(format!(
                "round {}: targets {} labelled {} rejected low={} margin={} exclusive={}; changed {} ({:.1}s)",
                round,
                ntarget,
                labelled,
                rejected[1],
                rejected[2],
                rejected[3],
                diff,
                t0.elapsed().as_secs_f64()
            ));
            if round > 0 && diff * 1000 < labelled.max(1) {
                break;
            }
        }
    }
}
