//! Which functions may throw a C++ exception, from the call graph of an extract (`.fnx`): a
//! function may throw when a chain of direct calls or tail jumps reaches a throw site, a function
//! that calls `_CxxThrowException` (statically linked in the GOG builds, imported from
//! vcruntime140.dll when the CRT is a DLL) or a throwing helper of the C++ library. Calls through
//! pointers (virtual and indirect calls) are not followed: a function that only reaches those is
//! "maybe".
//!
//! Throws are told apart by the throw site, so that callers can judge them:
//! - `alloc`: `operator new` and the array-size checks (`std::bad_alloc`, `bad_array_new_length`)
//! - `std`: the C++ library's other errors (`std::_Xlength_error`, `_Xout_of_range`, ...)
//! - `game`: any other `throw`, and `std::rethrow_exception`
//! - `seh`: `RaiseException` outside the C++ runtime (a structured exception, not C++)

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
    /// "yes": reaches a C++ throw through direct calls; "maybe": only through calls the analysis
    /// cannot follow; "no". `RaiseException` (SEH) is reported in `via` but does not count: it is
    /// not a C++ exception.
    pub fn level(&self) -> &'static str {
        if self.via & (ALLOC | STD | GAME) != 0 {
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

/// The C++ runtime's own throwing machinery: its calls to RaiseException are the C++ throw.
fn is_runtime_thrower(name: &str) -> bool {
    matches!(name, "_CxxThrowException" | "__ExceptionPtrRethrow" | "__ExceptionPtrCurrentException")
}

fn import_kind(dll: &str, name: &str) -> u8 {
    let dll = dll.to_ascii_lowercase();
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

/// The kind of a throw site, by the name of the function that throws.
pub fn site_kind(name: &str) -> u8 {
    let n = name;
    if n.contains("throw_std_bad_alloc") || n.contains("bad_array_new_length") || n.contains("_Xbad_alloc") || n.starts_with("operator new") {
        ALLOC
    } else if n.starts_with("std::") || n.starts_with("__scrt") || n.starts_with("__std") || n.starts_with("Concurrency::") || n.starts_with("__crt") {
        STD
    } else {
        GAME
    }
}

/// Per function of the build (same indices as `b.funcs`).
pub fn analyse(b: &Build) -> Vec<Throws> {
    let n = b.funcs.len();
    let name_of = |i: usize| b.funcs[i].names.first().map(|&k| b.names[k as usize].as_str()).unwrap_or("");
    // `_CxxThrowException` itself (static CRT), or the thunk that jumps to its import (DLL CRT)
    let thrower: Vec<bool> = (0..n)
        .map(|i| {
            name_of(i) == "_CxxThrowException"
                || matches!(b.funcs[i].refs.as_slice(), [Ref::JumpImport(k)] if b.imports[*k as usize].name == "_CxxThrowException")
        })
        .collect();
    let rethrow: Vec<bool> = (0..n).map(|i| matches!(name_of(i), "__ExceptionPtrRethrow" | "std::rethrow_exception")).collect();
    let mut t = vec![Throws::default(); n];
    // reverse edges: callee -> callers (direct calls, tail jumps, funclet -> owner)
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, f) in b.funcs.iter().enumerate() {
        let me = name_of(i);
        let runtime = is_runtime_thrower(me);
        for r in &f.refs {
            match *r {
                Ref::Call(c) | Ref::Jump(c) => {
                    let c = c as usize;
                    if thrower[c] {
                        t[i].site = true;
                        t[i].via |= site_kind(me);
                    } else if rethrow[c] {
                        t[i].via |= GAME;
                    } else if !runtime {
                        callers[c].push(i as u32);
                    }
                }
                Ref::CallImport(k) | Ref::JumpImport(k) => {
                    let im = &b.imports[k as usize];
                    if im.name == "_CxxThrowException" {
                        t[i].site = true;
                        t[i].via |= site_kind(me);
                    } else if !runtime {
                        t[i].via |= import_kind(&im.dll, &im.name);
                    }
                }
                Ref::CallVirt(_) | Ref::CallIndirect => t[i].indirect = true,
                _ => {}
            }
        }
        if f.eh_parent != u32::MAX && (f.eh_parent as usize) < n {
            callers[i].push(f.eh_parent);
        }
    }
    // the runtime's throwers are reached through their callers' sites only
    for i in 0..n {
        if is_runtime_thrower(name_of(i)) {
            t[i] = Throws::default();
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
