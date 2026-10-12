//! Per-executable signatures: everything that identifies a function and is unique inside its own
//! executable, attached to the function address (and its PDB names when the build has them).
//!
//! Each executable is evaluated once into a `.sig` file. Matching a stripped build is then a
//! merge of its sorted signatures with those of the PDB builds (see `matcher`).
//!
//! A signature is a u64: the kind in the top 6 bits, a 58-bit hash below. Kinds:
//! - code and data: exact, pic, mnem, bagcfg, unwind, block, str, strset, istr, const, imm,
//!   imports, export
//! - structure, label free: callee shapes, caller shapes, WL neighbourhood, layout triple
//! - anchored relations, label free: the same relations as the symbol ones below, but the
//!   neighbour is identified by one of its own unique code/data signatures (its "anchor")
//! - symbol relations: callee ordinal under a named caller, caller of a named callee, call set,
//!   callee pairs, thunks, vtable slots, layout and data-table neighbours, shared globals,
//!   function pointers; the neighbour is identified by its (primary) PDB name

use crate::corpusdb::{CBuild, NameNorm};
use crate::model::{Build, BuildMeta};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed};

pub const SIG_FORMAT: u32 = 1;

pub mod kind {
    pub const EXACT: u8 = 0;
    pub const PIC: u8 = 1;
    pub const MNEM: u8 = 2;
    pub const BAGCFG: u8 = 3;
    pub const UNWIND: u8 = 4;
    pub const BLOCK: u8 = 5;
    pub const STR: u8 = 6;
    pub const STRSET: u8 = 7;
    pub const ISTR: u8 = 8;
    pub const CONST: u8 = 9;
    pub const IMM: u8 = 10;
    pub const IMPORTS: u8 = 11;
    pub const EXPORT: u8 = 12;
    pub const CALLEE_SHAPES: u8 = 13;
    pub const CALLER_SHAPES: u8 = 14;
    pub const WL1: u8 = 15;
    pub const LAYOUT3: u8 = 16;
    /// relation forms, added to ANCHOR or SYMBOL
    pub const R_CALLEE_ORD: u8 = 0;
    pub const R_CALLER: u8 = 1;
    pub const R_CALLSET: u8 = 2;
    pub const R_CALLEE_PAIR: u8 = 3;
    pub const R_THUNK: u8 = 4;
    pub const R_VTSLOT: u8 = 5;
    pub const R_LAYOUT_PREV: u8 = 6;
    pub const R_LAYOUT_NEXT: u8 = 7;
    pub const R_TABLE_PREV: u8 = 8;
    pub const R_TABLE_NEXT: u8 = 9;
    pub const R_GLOBAL: u8 = 10;
    pub const R_FNPTR: u8 = 11;
    pub const ANCHOR: u8 = 20;
    pub const SYMBOL: u8 = 40;
    pub const COUNT: usize = 52;

    pub fn name(k: u8) -> String {
        const BASE: [&str; 17] = [
            "exact", "pic", "mnem", "bagcfg", "unwind", "block", "str", "strset", "istr", "const", "imm", "imports", "export", "callee_shapes", "caller_shapes", "wl1", "layout3",
        ];
        const REL: [&str; 12] = ["callee_ord", "caller", "callset", "callee_pair", "thunk", "vtslot", "layout_prev", "layout_next", "table_prev", "table_next", "global", "fnptr"];
        if (k as usize) < BASE.len() {
            BASE[k as usize].to_string()
        } else if (ANCHOR..ANCHOR + 12).contains(&k) {
            format!("a_{}", REL[(k - ANCHOR) as usize])
        } else if (SYMBOL..SYMBOL + 12).contains(&k) {
            format!("s_{}", REL[(k - SYMBOL) as usize])
        } else {
            format!("k{}", k)
        }
    }
    /// code-shape kinds are dampened for tiny functions when matching
    pub fn code_shape(k: u8) -> bool {
        matches!(k, EXACT | PIC | MNEM | BAGCFG | CONST | IMM)
    }
}

const HMASK: u64 = (1u64 << 58) - 1;

#[inline]
pub fn sig_kind(s: u64) -> u8 {
    (s >> 58) as u8
}

#[inline]
fn mk(kind: u8, h: u64) -> u64 {
    (h & HMASK) | ((kind as u64) << 58)
}

#[inline]
fn h2(a: u64, b: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&a.to_le_bytes());
    buf[8..].copy_from_slice(&b.to_le_bytes());
    xxh3_64(&buf)
}

#[inline]
fn h3(a: u64, b: u64, c: u64) -> u64 {
    let mut buf = [0u8; 24];
    buf[..8].copy_from_slice(&a.to_le_bytes());
    buf[8..16].copy_from_slice(&b.to_le_bytes());
    buf[16..].copy_from_slice(&c.to_le_bytes());
    xxh3_64(&buf)
}

fn hseq(v: &[u64]) -> u64 {
    let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    xxh3_64(&bytes)
}

/// Hash of a symbol name as used inside symbol-relation signatures.
pub fn name_hash(s: &str) -> u64 {
    xxh3_64_with_seed(s.as_bytes(), 0x5157)
}

/// Code and data signatures of one function.
fn absolute(b: &CBuild, f: usize, out: &mut Vec<(u64, u32)>) {
    use kind::*;
    let fi = f as u32;
    let ni = b.n_insn[f];
    if ni >= 2 {
        out.push((mk(EXACT, b.h_exact[f]), fi));
        out.push((mk(PIC, b.h_pic[f]), fi));
    }
    if ni >= 4 {
        out.push((mk(MNEM, b.h_mnem[f]), fi));
    }
    if ni >= 6 {
        out.push((mk(BAGCFG, h2(b.h_bag[f], b.h_cfg[f])), fi));
    }
    if b.h_unwind[f] != 0 {
        out.push((mk(UNWIND, h2(b.h_unwind[f], (b.n_blocks[f] as u64).min(64))), fi));
    }
    for &x in b.blocks.row(f) {
        out.push((mk(BLOCK, x as u64), fi));
    }
    for &x in b.strs.row(f) {
        out.push((mk(STR, x), fi));
    }
    if b.strs.row(f).len() >= 2 {
        let mut v = b.strs.row(f).to_vec();
        v.sort_unstable();
        out.push((mk(STRSET, hseq(&v)), fi));
    }
    for &x in b.istrs.row(f) {
        out.push((mk(ISTR, x), fi));
    }
    for &x in b.consts.row(f) {
        out.push((mk(CONST, x), fi));
    }
    for &x in b.imms.row(f) {
        out.push((mk(IMM, h2(x, 0)), fi));
    }
    if !b.imports.row(f).is_empty() {
        let lg = 32 - (b.n_insn[f].max(1)).leading_zeros() as u64;
        out.push((mk(IMPORTS, h2(hseq(b.imports.row(f)), lg)), fi));
    }
    if b.export[f] != 0 {
        out.push((mk(EXPORT, b.export[f]), fi));
    }
}

/// Label-free structural signatures.
fn structural(b: &CBuild, out: &mut Vec<(u64, u32)>) {
    use kind::*;
    for f in 0..b.n {
        let fi = f as u32;
        let cs = b.callees.row(f);
        if !cs.is_empty() {
            let mut v: Vec<u64> = cs.iter().map(|&c| b.h_pic[c as usize]).collect();
            v.sort_unstable();
            v.dedup();
            out.push((mk(CALLEE_SHAPES, h2(hseq(&v), b.h_bag[f])), fi));
        }
        let cr = b.callers.row(f);
        if !cr.is_empty() && cr.len() <= 64 {
            let mut v: Vec<u64> = cr.iter().map(|&c| b.h_pic[c as usize]).collect();
            v.sort_unstable();
            v.dedup();
            out.push((mk(CALLER_SHAPES, h2(hseq(&v), b.h_bag[f])), fi));
        }
        if !cs.is_empty() || !cr.is_empty() {
            let mut a: Vec<u64> = cs.iter().map(|&c| b.h_bag[c as usize]).collect();
            a.sort_unstable();
            let mut c: Vec<u64> = cr.iter().take(64).map(|&c| b.h_bag[c as usize]).collect();
            c.sort_unstable();
            out.push((mk(WL1, h3(b.h_bag[f], hseq(&a), hseq(&c))), fi));
        }
        if f > 0 && f + 1 < b.n {
            out.push((mk(LAYOUT3, h3(b.h_bag[f - 1], b.h_bag[f], b.h_bag[f + 1])), fi));
        }
    }
}

/// Relation signatures where each neighbour is identified by `id[f]` (0 = unidentified): an
/// anchor (one of its unique code/data signatures) or a symbol name hash. `base` is
/// kind::ANCHOR or kind::SYMBOL.
pub fn relations(b: &CBuild, id: &[u64], base: u8, reach: usize, out: &mut Vec<(u64, u32)>) {
    use kind::*;
    let n = b.n;
    let k = |r: u8| base + r;
    for f in 0..n {
        let cs = b.callees.row(f);
        if id[f] != 0 {
            for (j, &c) in cs.iter().enumerate() {
                out.push((mk(k(R_CALLEE_ORD), h3(id[f], j as u64, b.h_bag[c as usize])), c));
            }
            for (j, &t) in b.fnptrs.row(f).iter().enumerate() {
                out.push((mk(k(R_FNPTR), h2(id[f], j as u64)), t));
            }
        }
        for &c in cs {
            if id[c as usize] != 0 {
                out.push((mk(k(R_CALLER), h2(id[c as usize], b.h_pic[f])), f as u32));
            }
        }
        if cs.len() >= 2 && cs.iter().all(|&c| id[c as usize] != 0) {
            let mut v: Vec<u64> = cs.iter().map(|&c| id[c as usize]).collect();
            v.sort_unstable();
            out.push((mk(k(R_CALLSET), hseq(&v)), f as u32));
        }
        for w in cs.windows(2) {
            let (a, c) = (id[w[0] as usize], id[w[1] as usize]);
            if a != 0 && c != 0 {
                out.push((mk(k(R_CALLEE_PAIR), h2(a, c)), f as u32));
            }
        }
        let t = b.thunk_to[f];
        if t != u32::MAX && id[t as usize] != 0 {
            out.push((mk(k(R_THUNK), id[t as usize]), f as u32));
        }
        if id[f] != 0 {
            for kk in 1..=reach {
                if f + kk < n {
                    out.push((mk(k(R_LAYOUT_PREV), h3(id[f], kk as u64, b.h_bag[f + kk])), (f + kk) as u32));
                }
                if f >= kk {
                    out.push((mk(k(R_LAYOUT_NEXT), h3(id[f], kk as u64, b.h_bag[f - kk])), (f - kk) as u32));
                }
            }
        }
    }
    // vtables: identity from slot 0 and from the functions that take the vtable's address
    let mut refs: Vec<Vec<u32>> = vec![Vec::new(); b.vtables.len()];
    for f in 0..n {
        for &v in b.vtrefs.row(f) {
            if (v as usize) < refs.len() {
                refs[v as usize].push(f as u32);
            }
        }
    }
    for (vi, slots) in b.vtables.iter().enumerate() {
        let s0 = slots.first().copied().unwrap_or(u32::MAX);
        let p0 = if s0 != u32::MAX { id[s0 as usize] } else { 0 };
        for (kk, &s) in slots.iter().enumerate() {
            if s == u32::MAX {
                continue;
            }
            if kk > 0 && p0 != 0 {
                out.push((mk(k(R_VTSLOT), h3(p0, kk as u64, 0)), s));
            }
            for &r in &refs[vi] {
                if id[r as usize] != 0 {
                    out.push((mk(k(R_VTSLOT), h3(id[r as usize], kk as u64, 1)), s));
                }
            }
        }
    }
    // data tables of code pointers
    for t in &b.tables {
        for (i, &e) in t.iter().enumerate() {
            if e == u32::MAX || id[e as usize] == 0 {
                continue;
            }
            for kk in 1..=reach {
                if i + kk < t.len() && t[i + kk] != u32::MAX {
                    let x = t[i + kk];
                    out.push((mk(k(R_TABLE_PREV), h3(id[e as usize], kk as u64, b.h_bag[x as usize])), x));
                }
                if i >= kk && t[i - kk] != u32::MAX {
                    let x = t[i - kk];
                    out.push((mk(k(R_TABLE_NEXT), h3(id[e as usize], kk as u64, b.h_bag[x as usize])), x));
                }
            }
        }
    }
    // shared writable globals (popular globals carry no identity)
    let mut users: HashMap<u32, Vec<u32>> = HashMap::new();
    for f in 0..n {
        for &g in b.globals.row(f) {
            users.entry(g).or_default().push(f as u32);
        }
    }
    for f in 0..n {
        if id[f] == 0 {
            continue;
        }
        for (j, g) in b.globals.row(f).iter().enumerate() {
            let us = &users[g];
            if us.len() > 32 {
                continue;
            }
            for &u in us {
                if u as usize != f {
                    out.push((mk(k(R_GLOBAL), h3(id[f], j as u64, b.h_bag[u as usize])), u));
                }
            }
        }
    }
}

/// Keep only signatures that belong to exactly one function; returns (sigs, funcs) sorted by sig.
pub fn unique(mut v: Vec<(u64, u32)>) -> (Vec<u64>, Vec<u32>) {
    v.par_sort_unstable();
    v.dedup();
    let mut sigs = Vec::with_capacity(v.len());
    let mut funcs = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        let mut j = i + 1;
        while j < v.len() && v[j].0 == v[i].0 {
            j += 1;
        }
        if j == i + 1 {
            sigs.push(v[i].0);
            funcs.push(v[i].1);
        }
        i = j;
    }
    (sigs, funcs)
}

/// Anchors: for each function up to two of its unique code/data signatures, in a fixed priority
/// order, used to identify it inside label-free relation signatures.
fn anchors(b: &CBuild, abs_sigs: &[u64], abs_funcs: &[u32]) -> [Vec<u64>; 2] {
    use kind::*;
    const PRIO: [u8; 9] = [PIC, STRSET, STR, ISTR, EXACT, BAGCFG, CONST, IMM, UNWIND];
    let mut best: Vec<[(u8, u64); 2]> = vec![[(u8::MAX, 0), (u8::MAX, 0)]; b.n];
    for (&s, &f) in abs_sigs.iter().zip(abs_funcs) {
        let kd = sig_kind(s);
        let Some(p) = PRIO.iter().position(|&x| x == kd) else { continue };
        if kd == PIC && b.n_insn[f as usize] < 6 {
            continue;
        }
        let p = p as u8;
        let slot = &mut best[f as usize];
        // keep the two best priorities, one signature per kind (lowest hash for multi-valued kinds)
        let cand = (p, s);
        if slot[0].0 == p {
            slot[0].1 = slot[0].1.min(s);
        } else if slot[1].0 == p {
            slot[1].1 = slot[1].1.min(s);
        } else if p < slot[0].0 {
            slot[1] = slot[0];
            slot[0] = cand;
        } else if p < slot[1].0 {
            slot[1] = cand;
        }
    }
    let a0 = best.iter().map(|x| if x[0].0 == u8::MAX { 0 } else { x[0].1 | 1 }).collect();
    let a1 = best.iter().map(|x| if x[1].0 == u8::MAX { 0 } else { x[1].1 | 1 }).collect();
    [a0, a1]
}

/// The per-executable output: function table, PDB names and unique signatures.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigFile {
    pub format: u32,
    pub meta: BuildMeta,
    pub rva: Vec<u32>,
    /// end of the primary range
    pub end: Vec<u32>,
    pub size: Vec<u32>,
    pub n_insn: Vec<u32>,
    /// owning function of C++ EH funclets (u32::MAX otherwise) and funclet kind
    pub eh_parent: Vec<u32>,
    pub eh_kind: Vec<u8>,
    /// normalized PDB names per function (empty for stripped builds)
    pub names: Vec<Vec<String>>,
    /// unique signatures sorted ascending, and the function each belongs to
    pub sigs: Vec<u64>,
    pub funcs: Vec<u32>,
    /// signatures generated per kind before and after the uniqueness filter
    pub kind_counts: Vec<(u8, u32, u32)>,
}

impl SigFile {
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("sig.tmp");
        {
            let f = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            let mut z = zstd::Encoder::new(std::io::BufWriter::new(f), 6)?;
            z.write_all(&postcard::to_stdvec(self)?)?;
            z.finish()?.flush()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
    pub fn load(path: &Path) -> Result<SigFile> {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut z = zstd::Decoder::new(std::io::BufReader::new(f))?;
        let mut bytes = Vec::new();
        z.read_to_end(&mut bytes)?;
        let s: SigFile = postcard::from_bytes(&bytes).with_context(|| format!("decode {}", path.display()))?;
        anyhow::ensure!(s.format == SIG_FORMAT, "{}: sig format {} != {}", path.display(), s.format, SIG_FORMAT);
        Ok(s)
    }
    pub fn has_names(&self) -> bool {
        self.names.iter().any(|v| !v.is_empty())
    }
}

/// Primary-name hash per function (0 = no name): the smallest normalized name.
pub fn symbol_ids(names: &[Vec<String>]) -> Vec<u64> {
    names.iter().map(|v| v.iter().min().map_or(0, |s| name_hash(s))).collect()
}

pub const REACH: usize = 4;

/// Label-free signatures of a build (code/data, structure, anchored relations), before the
/// uniqueness filter.
pub fn free_signatures(b: &CBuild) -> Vec<(u64, u32)> {
    let mut abs: Vec<(u64, u32)> = (0..b.n)
        .into_par_iter()
        .fold(Vec::new, |mut v, f| {
            absolute(b, f, &mut v);
            v
        })
        .reduce(Vec::new, |mut a, mut c| {
            a.append(&mut c);
            a
        });
    let (us, uf) = unique(abs.clone());
    let [a0, a1] = anchors(b, &us, &uf);
    structural(b, &mut abs);
    relations(b, &a0, kind::ANCHOR, REACH, &mut abs);
    relations(b, &a1, kind::ANCHOR, REACH, &mut abs);
    abs
}

/// Evaluate one executable: its extract (and PDB names, if any) into a SigFile.
pub fn evaluate(b: Build) -> SigFile {
    let norm = NameNorm::new();
    let meta = b.meta.clone();
    let has_pdb = b.has_pdb();
    let (c, names) = crate::corpusdb::compact(b, 0, &norm);
    let names: Vec<Vec<String>> = if has_pdb {
        names.into_iter().map(|mut v| {
            v.sort();
            v.dedup();
            v
        }).collect()
    } else {
        vec![Vec::new(); c.n]
    };
    let mut all = free_signatures(&c);
    if has_pdb {
        let ids = symbol_ids(&names);
        relations(&c, &ids, kind::SYMBOL, REACH, &mut all);
    }
    let mut before = vec![0u32; kind::COUNT.max(64)];
    for (s, _) in &all {
        before[sig_kind(*s) as usize] += 1;
    }
    let (sigs, funcs) = unique(all);
    let mut after = vec![0u32; before.len()];
    for s in &sigs {
        after[sig_kind(*s) as usize] += 1;
    }
    let kind_counts = (0..before.len()).filter(|&k| before[k] > 0).map(|k| (k as u8, before[k], after[k])).collect();
    SigFile {
        format: SIG_FORMAT,
        meta,
        rva: c.rva.clone(),
        end: (0..c.n).map(|f| c.ranges.row(f).first().map_or(c.rva[f], |r| r.1)).collect(),
        size: c.size.clone(),
        n_insn: c.n_insn.clone(),
        eh_parent: c.eh_parent.clone(),
        eh_kind: c.eh_kind.clone(),
        names,
        sigs,
        funcs,
        kind_counts,
    }
}
