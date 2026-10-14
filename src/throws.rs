//! Which functions may throw a C++ exception, from the call graph of an extract (`.fnx`): a
//! function may throw when a chain of direct calls or tail jumps reaches `_CxxThrowException` or
//! a throwing helper of the C++ runtime. Calls through pointers (virtual and indirect calls) are
//! not followed: a function that only reaches those is "maybe".
//!
//! Throws are told apart by where they come from, so that callers can judge them:
//! - `alloc`: `operator new` and the array-size checks (`std::bad_alloc`, `bad_array_new_length`)
//! - `std`: the C++ library's other errors (`std::_Xlength_error`, `_Xout_of_range`, ...)
//! - `game`: any other `throw`
//! - `seh`: `RaiseException` (a structured exception, not C++)

use crate::model::{Build, Ref};

pub const ALLOC: u8 = 1;
pub const STD: u8 = 2;
pub const GAME: u8 = 4;
pub const SEH: u8 = 8;

#[derive(Debug, Clone, Copy, Default)]
pub struct Throws {
    /// sources reached through direct calls (bits above)
    pub via: u8,
    /// reaches an indirect or virtual call (whose target is not known)
    pub indirect: bool,
    /// calls `_CxxThrowException` itself
    pub site: bool,
}

impl Throws {
    pub fn level(&self) -> &'static str {
        if self.via != 0 {
            "yes"
        } else if self.indirect {
            "maybe"
        } else {
            "no"
        }
    }
    pub fn via_names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (b, n) in [(ALLOC, "alloc"), (STD, "std"), (GAME, "game"), (SEH, "seh")] {
            if self.via & b != 0 {
                v.push(n);
            }
        }
        v
    }
}

fn import_kind(dll: &str, name: &str) -> u8 {
    let dll = dll.to_ascii_lowercase();
    if name == "_CxxThrowException" {
        return GAME; // refined by the caller's name below
    }
    if name == "RaiseException" && dll.starts_with("kernel") {
        return SEH;
    }
    if dll.starts_with("msvcp") && (name.starts_with("?_X") || name.starts_with("?_Throw")) {
        if name.starts_with("?_Xbad_alloc") {
            return ALLOC;
        }
        return STD;
    }
    0
}

fn name_kind(name: &str) -> u8 {
    let n = name;
    if n.contains("throw_std_bad_alloc") || n.contains("bad_array_new_length") || n.contains("_Xbad_alloc") || n.ends_with("_Throw_bad_array_new_length") {
        ALLOC
    } else if n.starts_with("std::") || n.starts_with("__scrt") || n.starts_with("__std") || n.starts_with("Concurrency::") {
        STD
    } else {
        GAME
    }
}

/// Per function of the build (same indices as `b.funcs`).
pub fn analyse(b: &Build) -> Vec<Throws> {
    let n = b.funcs.len();
    let mut t = vec![Throws::default(); n];
    // reverse edges: callee -> callers (direct calls, tail jumps, funclet -> owner)
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, f) in b.funcs.iter().enumerate() {
        let fname = f.names.first().map(|&k| b.names[k as usize].as_str()).unwrap_or("");
        for r in &f.refs {
            match *r {
                Ref::Call(c) | Ref::Jump(c) => callers[c as usize].push(i as u32),
                Ref::CallImport(k) | Ref::JumpImport(k) => {
                    let im = &b.imports[k as usize];
                    let mut kind = import_kind(&im.dll, &im.name);
                    if im.name == "_CxxThrowException" {
                        t[i].site = true;
                        kind = name_kind(fname);
                    }
                    t[i].via |= kind;
                }
                Ref::CallVirt(_) | Ref::CallIndirect => t[i].indirect = true,
                _ => {}
            }
        }
        if f.eh_parent != u32::MAX && (f.eh_parent as usize) < n {
            callers[i].push(f.eh_parent);
        }
    }
    // propagate to fixed point
    let mut work: Vec<u32> = (0..n as u32).filter(|&i| t[i as usize].via != 0 || t[i as usize].indirect).collect();
    while let Some(c) = work.pop() {
        let (via, ind) = (t[c as usize].via, t[c as usize].indirect);
        for &p in &callers[c as usize] {
            let e = &mut t[p as usize];
            let (v0, i0) = (e.via, e.indirect);
            e.via |= via;
            e.indirect |= ind;
            if e.via != v0 || e.indirect != i0 {
                work.push(p);
            }
        }
    }
    t
}
