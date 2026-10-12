//! Compact in-memory corpus for the solver: every build's functions as flat arrays (CSR for
//! variable-length features), global label interning, timeline order.

use crate::model::{Build, BuildMeta, Ref};
use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed};

/// Compressed sparse rows: `data[off[i]..off[i+1]]` belongs to row i.
#[derive(Debug, Clone, Default)]
pub struct Csr<T> {
    pub off: Vec<u32>,
    pub data: Vec<T>,
}

impl<T: Copy> Csr<T> {
    pub fn new() -> Self {
        Csr { off: vec![0], data: Vec::new() }
    }
    pub fn push_row<I: IntoIterator<Item = T>>(&mut self, it: I) {
        self.data.extend(it);
        self.off.push(self.data.len() as u32);
    }
    #[inline]
    pub fn row(&self, i: usize) -> &[T] {
        &self.data[self.off[i] as usize..self.off[i + 1] as usize]
    }
    pub fn rows(&self) -> usize {
        self.off.len() - 1
    }
}

/// One build in compact form.
pub struct CBuild {
    pub meta: BuildMeta,
    /// position on the timeline (index into Corpus.builds)
    pub idx: usize,
    /// names from a readable PDB
    pub has_pdb: bool,
    pub n: usize,
    pub rva: Vec<u32>,
    /// end of the primary range (for address -> function lookups use `ranges`)
    pub ranges: Csr<(u32, u32)>,
    pub size: Vec<u32>,
    pub n_insn: Vec<u32>,
    pub n_blocks: Vec<u32>,
    pub flags: Vec<u16>,
    pub h_exact: Vec<u64>,
    pub h_pic: Vec<u64>,
    pub h_mnem: Vec<u64>,
    pub h_bag: Vec<u64>,
    pub h_cfg: Vec<u64>,
    pub h_unwind: Vec<u64>,
    pub blocks: Csr<u32>,
    /// string content hashes, address order of reference, deduplicated
    pub strs: Csr<u64>,
    /// indirect string hashes (strings pointed to by referenced data objects), deduplicated
    pub istrs: Csr<u64>,
    pub consts: Csr<u64>,
    pub imms: Csr<u64>,
    /// import (dll!name) hashes, deduplicated
    pub imports: Csr<u64>,
    /// distinct direct callees (call or tail jump), in order of first reference
    pub callees: Csr<u32>,
    /// call-site count per entry of `callees`
    pub ncalls: Csr<u16>,
    /// function pointers taken (function indices), deduplicated
    pub fnptrs: Csr<u32>,
    /// writable globals referenced (rva), deduplicated, address order of first reference
    pub globals: Csr<u32>,
    /// virtual-call displacements, sorted
    pub vcalls: Csr<u32>,
    /// for `jmp target` thunks (one instruction, a tail jump), the target
    pub thunk_to: Vec<u32>,
    /// C++ EH funclets: owning function (u32::MAX otherwise) and kind (1 unwind, 2 catch)
    pub eh_parent: Vec<u32>,
    pub eh_kind: Vec<u8>,
    /// vtable slots (function index or u32::MAX)
    pub vtables: Vec<Vec<u32>>,
    /// data tables of code pointers (function index or u32::MAX)
    pub tables: Vec<Vec<u32>>,
    /// vtables referenced by each function (lea of the vtable address)
    pub vtrefs: Csr<u32>,
    /// distinct direct callers of each function
    pub callers: Csr<u32>,
    /// export name hash per function (0 = none)
    pub export: Vec<u64>,
    /// ground-truth label set (0 = no names) from the PDB
    pub truth: Vec<u32>,
}

impl CBuild {
    pub fn func_containing(&self, rva: u32) -> Option<usize> {
        let i = self.rva.partition_point(|&r| r <= rva);
        if i > 0 && self.ranges.row(i - 1).iter().any(|&(s, e)| rva >= s && rva < e) {
            return Some(i - 1);
        }
        (0..self.n).find(|&k| self.ranges.row(k).iter().any(|&(s, e)| rva >= s && rva < e))
    }
}

/// Global interning of names and label sets.
#[derive(Default)]
pub struct Labels {
    pub names: Vec<String>,
    pub name_ids: HashMap<String, u32>,
    /// label sets: sorted name ids; set 0 is the empty set
    pub sets: Vec<Vec<u32>>,
    pub set_ids: HashMap<Vec<u32>, u32>,
}

impl Labels {
    pub fn new() -> Labels {
        let mut l = Labels::default();
        l.sets.push(Vec::new());
        l.set_ids.insert(Vec::new(), 0);
        l
    }
    pub fn name(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.name_ids.get(s) {
            return i;
        }
        let i = self.names.len() as u32;
        self.names.push(s.to_string());
        self.name_ids.insert(s.to_string(), i);
        i
    }
    pub fn set(&mut self, mut v: Vec<u32>) -> u32 {
        v.sort_unstable();
        v.dedup();
        if let Some(&i) = self.set_ids.get(&v) {
            return i;
        }
        let i = self.sets.len() as u32;
        self.sets.push(v.clone());
        self.set_ids.insert(v, i);
        i
    }
    /// Intersection of two label sets (as a new or existing set id); 0 when disjoint.
    pub fn intersect(&mut self, a: u32, b: u32) -> u32 {
        if a == b {
            return a;
        }
        let (sa, sb) = (&self.sets[a as usize], &self.sets[b as usize]);
        let v: Vec<u32> = sa.iter().filter(|x| sb.binary_search(x).is_ok()).copied().collect();
        if v.is_empty() {
            0
        } else {
            self.set(v)
        }
    }
    pub fn compatible(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        let (sa, sb) = (&self.sets[a as usize], &self.sets[b as usize]);
        let (mut i, mut j) = (0, 0);
        while i < sa.len() && j < sb.len() {
            match sa[i].cmp(&sb[j]) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
            }
        }
        false
    }
    /// representative name id of a set (smallest name string, stable across builds)
    pub fn primary(&self, set: u32) -> Option<u32> {
        self.sets[set as usize].iter().copied().min_by(|a, b| self.names[*a as usize].cmp(&self.names[*b as usize]))
    }
    pub fn display(&self, set: u32) -> String {
        let s = &self.sets[set as usize];
        let mut v: Vec<&str> = s.iter().map(|&i| self.names[i as usize].as_str()).collect();
        v.sort();
        v.join(" | ")
    }
}

pub struct NameNorm {
    lambda: Regex,
    anon: Regex,
    funclet: Regex,
}

impl NameNorm {
    pub fn new() -> NameNorm {
        NameNorm {
            lambda: Regex::new(r"<lambda_[0-9a-f]+>").unwrap(),
            anon: Regex::new(r"\?A0x[0-9a-f]+").unwrap(),
            funclet: Regex::new(r"'::`\d+'::(dtor|catch|fin|filt)\$\d+$").unwrap(),
        }
    }
    /// Normalize a PDB name; None for names that are not functions we label (EH/SEH funclets
    /// such as "`CPop::Foo'::`1'::dtor$0").
    pub fn norm(&self, s: &str) -> Option<String> {
        if s.is_empty() || self.funclet.is_match(s) {
            return None;
        }
        let s = self.lambda.replace_all(s, "<lambda>");
        let s = self.anon.replace_all(&s, "?A0x");
        Some(s.into_owned())
    }
}

fn dedup_keep_order<T: Copy + Eq + std::hash::Hash>(v: impl Iterator<Item = T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    v.filter(|x| seen.insert(*x)).collect()
}

/// Convert an extracted build into compact form; names are returned for global interning.
pub fn compact(b: Build, idx: usize, norm: &NameNorm) -> (CBuild, Vec<Vec<String>>) {
    let n = b.funcs.len();
    let has_pdb = b.has_pdb();
    let str_hash: Vec<u64> = b.strings.iter().map(|s| xxh3_64(s.as_bytes())).collect();
    let imp_hash: Vec<u64> = b.imports.iter().map(|i| xxh3_64(format!("{}!{}", i.dll, i.name).as_bytes())).collect();
    let mut c = CBuild {
        meta: b.meta.clone(),
        idx,
        has_pdb,
        n,
        rva: Vec::with_capacity(n),
        ranges: Csr::new(),
        size: Vec::with_capacity(n),
        n_insn: Vec::with_capacity(n),
        n_blocks: Vec::with_capacity(n),
        flags: Vec::with_capacity(n),
        h_exact: Vec::with_capacity(n),
        h_pic: Vec::with_capacity(n),
        h_mnem: Vec::with_capacity(n),
        h_bag: Vec::with_capacity(n),
        h_cfg: Vec::with_capacity(n),
        h_unwind: Vec::with_capacity(n),
        blocks: Csr::new(),
        strs: Csr::new(),
        istrs: Csr::new(),
        consts: Csr::new(),
        imms: Csr::new(),
        imports: Csr::new(),
        callees: Csr::new(),
        ncalls: Csr::new(),
        fnptrs: Csr::new(),
        globals: Csr::new(),
        vcalls: Csr::new(),
        thunk_to: vec![u32::MAX; n],
        eh_parent: Vec::with_capacity(n),
        eh_kind: Vec::with_capacity(n),
        vtables: b.vtables.iter().map(|v| v.slots.clone()).collect(),
        tables: b.tables.clone(),
        vtrefs: Csr::new(),
        callers: Csr::new(),
        export: vec![0; n],
        truth: vec![0; n],
    };
    let mut names: Vec<Vec<String>> = Vec::new();
    if has_pdb {
        names.resize(n, Vec::new());
    }
    for (i, f) in b.funcs.iter().enumerate() {
        c.rva.push(f.rva);
        c.ranges.push_row(f.ranges.iter().copied());
        c.size.push(f.size);
        c.n_insn.push(f.n_insn);
        c.n_blocks.push(f.n_blocks);
        c.flags.push(f.flags);
        c.h_exact.push(f.h_exact);
        c.h_pic.push(f.h_pic);
        c.h_mnem.push(f.h_mnem);
        c.h_bag.push(f.h_mnem_bag);
        c.h_cfg.push(f.h_cfg);
        c.h_unwind.push(f.h_unwind);
        c.eh_parent.push(f.eh_parent);
        c.eh_kind.push(f.eh_kind);
        c.blocks.push_row(f.blocks.iter().copied());
        c.strs.push_row(dedup_keep_order(f.strings.iter().map(|&s| str_hash[s as usize])));
        c.istrs.push_row(dedup_keep_order(f.istrings.iter().map(|&s| str_hash[s as usize])));
        let mut cs = f.consts.clone();
        cs.sort_unstable();
        cs.dedup();
        c.consts.push_row(cs);
        c.imms.push_row(f.imms.iter().copied());
        let mut imps: Vec<u64> = f
            .refs
            .iter()
            .filter_map(|r| match r {
                Ref::CallImport(i) | Ref::JumpImport(i) => Some(imp_hash[*i as usize]),
                _ => None,
            })
            .collect();
        imps.sort_unstable();
        imps.dedup();
        c.imports.push_row(imps);
        let mut order: Vec<u32> = Vec::new();
        let mut counts: HashMap<u32, u16> = HashMap::new();
        for r in &f.refs {
            if let Ref::Call(t) | Ref::Jump(t) = r {
                let e = counts.entry(*t).or_insert(0);
                if *e == 0 {
                    order.push(*t);
                }
                *e = e.saturating_add(1);
            }
        }
        c.ncalls.push_row(order.iter().map(|t| counts[t]));
        c.callees.push_row(order.iter().copied());
        c.fnptrs.push_row(dedup_keep_order(f.refs.iter().filter_map(|r| if let Ref::FnPtr(t) = r { Some(*t) } else { None })));
        c.globals.push_row(dedup_keep_order(f.globals.iter().copied()));
        let mut vc: Vec<u32> = f.refs.iter().filter_map(|r| if let Ref::CallVirt(d) = r { Some(*d) } else { None }).collect();
        vc.sort_unstable();
        c.vcalls.push_row(vc);
        if f.n_insn == 1 {
            if let [Ref::Jump(t)] = f.refs.as_slice() {
                c.thunk_to[i] = *t;
            }
        }
        c.vtrefs.push_row(dedup_keep_order(f.vtrefs.iter().copied()));
        if has_pdb {
            let mut v: Vec<String> = f.names.iter().filter_map(|&k| norm.norm(&b.names[k as usize])).collect();
            if v.is_empty() && f.names.is_empty() {
                v = f.publics.iter().filter_map(|&k| norm.norm(&b.names[k as usize])).collect();
            }
            names[i] = v;
        }
    }
    for e in &b.exports {
        if let Some(fi) = e.func {
            c.export[fi as usize] = xxh3_64_with_seed(e.name.as_bytes(), 7);
        }
    }
    // reverse adjacency: distinct callers of each function, in caller order
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n];
    for f in 0..n {
        for &t in c.callees.row(f) {
            if (t as usize) < n {
                callers[t as usize].push(f as u32);
            }
        }
    }
    for v in callers {
        c.callers.push_row(v);
    }
    (c, names)
}

pub struct CorpusDb {
    pub builds: Vec<CBuild>,
    pub labels: Labels,
    /// global node id offset of each build
    pub base: Vec<u32>,
    pub total: usize,
}

impl CorpusDb {
    /// Load all `.fnx` files of the corpus (in timeline order). `exclude` ids are skipped.
    pub fn load(corpus: &crate::corpus::Corpus, dir: &Path, exclude: &[String], threads: usize) -> Result<CorpusDb> {
        let metas: Vec<&BuildMeta> = corpus.builds.iter().filter(|m| !exclude.contains(&m.id)).filter(|m| dir.join(format!("{}.fnx", m.id)).exists()).collect();
        let norm = NameNorm::new();
        let labels = Mutex::new(Labels::new());
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
        let builds: Vec<Result<CBuild>> = pool.install(|| {
            metas
                .par_iter()
                .enumerate()
                .map(|(idx, m)| {
                    let b = Build::load(&dir.join(format!("{}.fnx", m.id)))?;
                    let (mut c, names) = compact(b, idx, &norm);
                    if c.has_pdb {
                        let mut l = labels.lock().unwrap();
                        for (i, ns) in names.into_iter().enumerate() {
                            if !ns.is_empty() {
                                let ids: Vec<u32> = ns.iter().map(|s| l.name(s)).collect();
                                c.truth[i] = l.set(ids);
                            }
                        }
                    }
                    Ok(c)
                })
                .collect()
        });
        let mut builds: Vec<CBuild> = builds.into_iter().collect::<Result<_>>()?;
        // broken downloads (zero-filled executables) extract to almost nothing
        builds.retain(|b| {
            let ok = b.n >= 1000;
            if !ok {
                eprintln!("skipping {}: only {} functions", b.meta.id, b.n);
            }
            ok
        });
        for (i, b) in builds.iter_mut().enumerate() {
            b.idx = i;
        }
        let mut base = Vec::with_capacity(builds.len());
        let mut total = 0usize;
        for b in &builds {
            base.push(total as u32);
            total += b.n;
        }
        Ok(CorpusDb { builds, labels: labels.into_inner().unwrap(), base, total })
    }

    #[inline]
    pub fn gid(&self, b: usize, f: usize) -> u32 {
        self.base[b] + f as u32
    }

    #[inline]
    pub fn split(&self, gid: u32) -> (usize, usize) {
        let b = self.base.partition_point(|&x| x <= gid) - 1;
        (b, (gid - self.base[b]) as usize)
    }

    pub fn build_index(&self, id: &str) -> Option<usize> {
        self.builds.iter().position(|b| b.meta.id == id)
    }
}


