//! `stellar-fnmatch ffi-check`: checks the function declarations of `cdef` against evidence that
//! does not come from the PDB's type records:
//!
//! - the Linux build's symbols (Itanium-mangled, demangled by `nm -C`): each function's parameter
//!   list, count and kind of every parameter (pointer, reference, const, fundamental, by value);
//! - the vftables of the Windows build (`??_7...` publics, read from the executable): the function
//!   in each computed slot;
//! - the Windows build's code: callers set up the argument registers, and callees return the
//!   hidden result pointer in RAX, as the declarations say.

use crate::cdecl::{FuncDecl, Funcs};
use crate::cdef::Db;
use crate::model::{Build, Ref};
use crate::pdbtypes::PdbInfo;
use crate::pe::Pe;
use anyhow::Result;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

// ---------------------------------------------------------------------------------------------
// names

/// A name in a form both demanglers agree on: no spaces next to punctuation, `__int64` as
/// `long`, no `class`/`struct`/`enum` keywords, GCC's anonymous namespace.
pub fn norm_name(s: &str) -> String {
    let mut t = s.replace("`anonymous namespace'", "(anonymous namespace)");
    for (a, b) in [("unsigned __int64", "unsigned long"), ("__int64", "long"), ("unsigned __int8", "unsigned char"), ("__int8", "signed char"), ("unsigned __int16", "unsigned short"), ("__int16", "short"), ("unsigned __int32", "unsigned int"), ("__int32", "int")] {
        t = t.replace(a, b);
    }
    for kw in ["class ", "struct ", "enum ", "union "] {
        loop {
            let Some(i) = t.find(kw) else { break };
            let before = t[..i].chars().last();
            if before.map_or(true, |c| !c.is_alphanumeric() && c != '_') {
                t.replace_range(i..i + kw.len(), "");
            } else {
                break;
            }
        }
    }
    let b: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(b.len());
    for (i, &c) in b.iter().enumerate() {
        if c == ' ' {
            let p = out.chars().last();
            let n = b.get(i + 1).copied();
            let ident = |x: Option<char>| x.map_or(false, |x| x.is_alphanumeric() || x == '_');
            if ident(p) && ident(n) {
                out.push(' ');
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn split_top(s: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                v.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        v.push(cur.trim().to_string());
    }
    v
}

/// (qualified name, parameters, const method) of a `nm -C` function name.
pub fn parse_linux(s: &str) -> Option<(String, Vec<String>, bool)> {
    let mut s = s.trim().to_string();
    while let Some(i) = s.rfind(" [clone ") {
        s.truncate(i);
    }
    let mut konst = false;
    loop {
        let t = s.trim_end();
        if let Some(x) = t.strip_suffix(" const") {
            konst = true;
            s = x.to_string();
        } else if let Some(x) = t.strip_suffix(" volatile").or_else(|| t.strip_suffix(" &&")).or_else(|| t.strip_suffix(" &")).or_else(|| t.strip_suffix(" noexcept")) {
            s = x.to_string();
        } else {
            break;
        }
    }
    let s = s.trim_end();
    if !s.ends_with(')') {
        return None;
    }
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for i in (0..b.len()).rev() {
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open?;
    let params_text = &s[open + 1..s.len() - 1];
    let mut name = s[..open].replace("[abi:cxx11]", "");
    // a template function's demangled name starts with its return type
    let cut = |text: &str| -> Option<usize> {
        let mut depth = 0i32;
        let mut last = None;
        for (i, c) in text.char_indices() {
            match c {
                '<' | '(' | '[' => depth += 1,
                '>' | ')' | ']' => depth -= 1,
                ' ' if depth == 0 => last = Some(i),
                _ => {}
            }
        }
        last
    };
    let anon_fix = name.replace("(anonymous namespace)", "\u{1}");
    let (work, restore) = (anon_fix, true);
    let idx = if let Some(op) = work.find("operator") { cut(&work[..op]).map(|i| (i, op)) } else { cut(&work).map(|i| (i, 0)) };
    let mut nm = match idx {
        Some((i, _)) => work[i + 1..].to_string(),
        None => work.clone(),
    };
    if restore {
        nm = nm.replace('\u{1}', "(anonymous namespace)");
    }
    name = nm;
    let mut params = split_top(params_text);
    if params.len() == 1 && (params[0] == "void" || params[0].is_empty()) {
        params.clear();
    }
    Some((name, params, konst))
}

fn linux_fund(t: &str) -> Option<&'static str> {
    Some(match t {
        "int" => "i32",
        "unsigned int" => "u32",
        "long" | "long long" => "i64",
        "unsigned long" | "unsigned long long" => "u64",
        "short" => "i16",
        "unsigned short" => "u16",
        "signed char" => "i8",
        "unsigned char" => "u8",
        "char" => "char",
        "bool" => "bool",
        "float" => "f32",
        "double" => "f64",
        "long double" => "f80",
        "wchar_t" | "char16_t" => "wchar",
        "char32_t" => "u32",
        "__int128" => "i128",
        "unsigned __int128" => "i128",
        "decltype(nullptr)" | "std::nullptr_t" => "p",
        _ => return None,
    })
}

/// Category of a demangled parameter type, as `cdecl::Param::cat`.
pub fn linux_cat(p: &str) -> String {
    let t = p.trim();
    if t == "..." {
        return "va".into();
    }
    if t.ends_with("&&") {
        return "rr".into();
    }
    if t.contains("::*") {
        return "m".into();
    }
    if let Some(inner) = t.strip_suffix('&') {
        return if inner.trim_end().ends_with("const") { "rc".into() } else { "r".into() };
    }
    if t.contains("(*)") || t.contains("(&)") {
        return if t.contains("(&)") { "r".into() } else { "p".into() };
    }
    let t2 = t.strip_suffix(" const").unwrap_or(t);
    if let Some(inner) = t2.strip_suffix('*') {
        return if inner.trim_end().ends_with("const") { "pc".into() } else { "p".into() };
    }
    match linux_fund(t2) {
        Some("p") => "p".into(),
        Some(k) => format!("f:{}", k),
        None => "v".into(),
    }
}

fn shape(c: &str) -> &str {
    match c {
        "p" | "pc" => "p",
        "r" | "rc" => "r",
        "v" | "e" => "v",
        x if x.starts_with("f:") => "f",
        x => x,
    }
}

fn exact(c: &str) -> String {
    match c {
        "e" => "v".into(),
        "f:wchar" => "f:wchar".into(),
        x => x.to_string(),
    }
}

#[derive(Default, Debug, serde::Serialize)]
pub struct LinuxReport {
    pub linux_functions: usize,
    pub pdb_names: usize,
    pub names_on_both: usize,
    pub pairs_unique: usize,
    pub pairs_by_count: usize,
    pub overloads_unpaired: usize,
    pub count_agree: usize,
    pub count_disagree: usize,
    pub params_compared: usize,
    pub params_shape_agree: usize,
    pub params_exact_agree: usize,
    pub functions_exact_agree: usize,
    pub const_method_agree: usize,
    pub const_method_disagree: usize,
    /// "pdb vs linux" -> count, with an example
    pub disagreements: BTreeMap<String, (usize, String)>,
}

pub fn check_linux(decls: &[FuncDecl], nm_text: &str) -> LinuxReport {
    let mut r = LinuxReport::default();
    // linux: name -> distinct (params, const)
    let mut lx: HashMap<String, Vec<(Vec<String>, bool)>> = HashMap::new();
    for line in nm_text.lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(_addr), Some(ty), Some(name)) = (it.next(), it.next(), it.next()) else { continue };
        if !matches!(ty, "T" | "t" | "W" | "w") {
            continue;
        }
        let Some((n, ps, k)) = parse_linux(name) else { continue };
        let cats: Vec<String> = ps.iter().map(|p| linux_cat(p)).collect();
        let e = lx.entry(norm_name(&n)).or_default();
        if !e.iter().any(|(c, kk)| *c == cats && *kk == k) {
            e.push((cats, k));
            r.linux_functions += 1;
        }
    }
    // pdb: name -> distinct signatures
    let mut px: HashMap<String, Vec<&FuncDecl>> = HashMap::new();
    for f in decls {
        let e = px.entry(norm_name(&f.name)).or_default();
        let cats: Vec<&str> = f.params.iter().map(|p| p.cat.as_str()).collect();
        if !e.iter().any(|g| g.params.iter().map(|p| p.cat.as_str()).collect::<Vec<_>>() == cats && g.this_const == f.this_const && g.va == f.va) {
            e.push(f);
        }
    }
    r.pdb_names = px.len();
    let mut names: Vec<&String> = px.keys().collect();
    names.sort();
    for name in names {
        let Some(ls) = lx.get(name) else { continue };
        r.names_on_both += 1;
        let ps = &px[name];
        let mut pairs: Vec<(&FuncDecl, &(Vec<String>, bool))> = Vec::new();
        if ps.len() == 1 && ls.len() == 1 {
            pairs.push((ps[0], &ls[0]));
            r.pairs_unique += 1;
        } else {
            for f in ps {
                let n = f.params.len() + f.va as usize;
                let same: Vec<&(Vec<String>, bool)> = ls.iter().filter(|(c, _)| c.len() == n).collect();
                let pcount = ps.iter().filter(|g| g.params.len() + g.va as usize == n).count();
                if same.len() == 1 && pcount == 1 {
                    pairs.push((f, same[0]));
                    r.pairs_by_count += 1;
                } else {
                    r.overloads_unpaired += 1;
                }
            }
        }
        for (f, (lc, lk)) in pairs {
            let mut pc: Vec<String> = f.params.iter().map(|p| p.cat.clone()).collect();
            if f.va {
                pc.push("va".into());
            }
            if f.kind == "method" || f.kind == "ctor" || f.kind == "dtor" {
                if f.this_const == *lk {
                    r.const_method_agree += 1;
                } else {
                    r.const_method_disagree += 1;
                }
            }
            if pc.len() != lc.len() {
                r.count_disagree += 1;
                let key = format!("count {} vs {}", pc.len(), lc.len());
                let e = r.disagreements.entry(key).or_insert((0, String::new()));
                e.0 += 1;
                if e.1.is_empty() {
                    e.1 = format!("{} | linux ({})", f.cpp, lc.join(", "));
                }
                continue;
            }
            r.count_agree += 1;
            let mut all = true;
            for (i, (a, b)) in pc.iter().zip(lc).enumerate() {
                r.params_compared += 1;
                if shape(a) == shape(b) {
                    r.params_shape_agree += 1;
                }
                if exact(a) == exact(b) {
                    r.params_exact_agree += 1;
                } else {
                    all = false;
                    let key = format!("{} vs {}", a, b);
                    let e = r.disagreements.entry(key).or_insert((0, String::new()));
                    e.0 += 1;
                    if e.1.is_empty() {
                        e.1 = format!("{} (parameter {}: {})", f.cpp, i + 1, f.params.get(i).map_or("...", |p| p.cpp.as_str()));
                    }
                }
            }
            if all {
                r.functions_exact_agree += 1;
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------------------------
// vtables

#[derive(Default, Debug, serde::Serialize)]
pub struct VtableReport {
    pub vftable_symbols: usize,
    pub vftables_mapped: usize,
    pub methods_checked: usize,
    pub slot_agree: usize,
    pub slot_disagree: usize,
    /// of the agreeing: virtual destructors whose slot holds a deleting destructor
    pub dtor_agree: usize,
    /// of the agreeing: the slot holds a byte-identical copy of the function
    pub identical_code: usize,
    /// slots holding an adjustor thunk, followed to its target
    pub thunks: usize,
    /// not counted: the slot holds _purecall (an abstract class; a pure virtual destructor)
    pub purecall: usize,
    pub no_vftable: usize,
    pub examples: Vec<String>,
}

pub fn check_vtables(info: &PdbInfo, db: &Db, funcs: &Funcs, decls: &[FuncDecl], b: &Build, pe: &Pe) -> VtableReport {
    let mut r = VtableReport::default();
    // mangled class name -> definition
    let mut by_mangled: HashMap<String, u32> = HashMap::new();
    for &d in &db.udts {
        if let Some(crate::tpi::Rec::Class { unique: Some(u), .. }) = db.t.get(d) {
            if let Some(m) = u.strip_prefix(".?AV").or_else(|| u.strip_prefix(".?AU")) {
                by_mangled.insert(m.to_string(), d);
            }
        }
    }
    // (class, vfptr offset) -> vftable rva. `??_7C@@6B<base>@@@` is the vftable of the vfptr of
    // that base's subobject; `??_7C@@6B@` is that of the one vfptr the qualified names leave.
    // The qualifier names a base that tells the vftable apart from the class's others; that base
    // can hold several vfptrs, so each symbol gets the one vfptr of its base that no other symbol
    // of the class takes (by elimination).
    let mut vft: HashMap<(u32, u64), u32> = HashMap::new();
    // class -> (rva, candidate vfptrs)
    let mut per_class: HashMap<u32, Vec<(u32, Vec<u64>)>> = HashMap::new();
    for (rva, name, _) in &info.publics {
        let Some(rest) = name.strip_prefix("??_7") else { continue };
        r.vftable_symbols += 1;
        let Some(q) = rest.strip_suffix('@') else { continue };
        let mut found = None;
        for (i, _) in q.match_indices("6B") {
            if let Some(&d) = by_mangled.get(&q[..i]) {
                found = Some((d, &q[i + 2..]));
                break;
            }
        }
        let Some((d, qual)) = found else { continue };
        let Some(l) = db.layout(d) else { continue };
        let cands: Vec<u64> = if qual.is_empty() {
            l.vfptrs.clone()
        } else {
            let Some(&base) = by_mangled.get(qual) else { continue };
            let size = db.size_of(base).unwrap_or(0);
            let mut v = Vec::new();
            for (x, bo, _) in l.bases.iter().filter(|(x, _, _)| *x == base) {
                let _ = x;
                v.extend(l.vfptrs.iter().copied().filter(|o| *o >= *bo && *o < bo + size.max(1)));
            }
            v.sort();
            v.dedup();
            v
        };
        per_class.entry(d).or_default().push((*rva, cands));
    }
    // (identical vftables of different classes are folded into one by the linker, so an rva can
    // belong to several classes)
    for (d, mut syms) in per_class {
        let mut taken: HashSet<u64> = HashSet::new();
        let mut done = vec![false; syms.len()];
        loop {
            let mut progress = false;
            for (k, (rva, cands)) in syms.iter_mut().enumerate() {
                if done[k] {
                    continue;
                }
                cands.retain(|o| !taken.contains(o));
                if cands.len() == 1 {
                    vft.insert((d, cands[0]), *rva);
                    taken.insert(cands[0]);
                    done[k] = true;
                    r.vftables_mapped += 1;
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }
    for f in decls {
        let (Some(v), Some(c)) = (&f.virt, f.class) else { continue };
        if v.pure {
            continue;
        }
        let Some(&vrva) = vft.get(&(c, v.vfptr)) else {
            r.no_vftable += 1;
            continue;
        };
        r.methods_checked += 1;
        let mut slot = pe.u64(vrva + v.slot * 8).and_then(|va| pe.va_to_rva(va));
        // an adjustor thunk (`sub rcx, N; jmp f`): its target
        if let Some(t) = slot.and_then(|s| b.func_at(s)).and_then(|i| {
            let fx = &b.funcs[i];
            match fx.refs.as_slice() {
                [Ref::Jump(t)] if fx.size <= 16 && fx.n_insn <= 3 => Some(b.funcs[*t as usize].rva),
                _ => None,
            }
        }) {
            slot = Some(t);
            r.thunks += 1;
        }
        let dtor_ok = v.deleting && slot.and_then(|s| b.func_at(s)).map_or(false, |i| b.funcs[i].names.iter().any(|&k| b.names[k as usize].contains("deleting destructor")));
        if dtor_ok { r.dtor_agree += 1; }
        // identical code at another address (functions the linker did not fold together)
        let same_code = slot.and_then(|s| b.func_at(s)).zip(b.func_at(f.rva)).map_or(false, |(a, c)| a != c && b.funcs[a].h_pic == b.funcs[c].h_pic && b.funcs[a].size == b.funcs[c].size);
        let purecall = slot.and_then(|s| b.func_at(s)).map_or(false, |i| b.funcs[i].names.iter().any(|&k| b.names[k as usize] == "_purecall"));
        if purecall && !same_code { r.purecall += 1; continue; }
        if same_code { r.identical_code += 1; }
        if slot == Some(f.rva) || dtor_ok || same_code {
            r.slot_agree += 1;
        } else {
            r.slot_disagree += 1;
            if r.examples.len() < 15 {
                let what = slot.and_then(|s| b.func_at(s)).and_then(|i| b.funcs[i].names.first()).map(|&k| b.names[k as usize].clone()).unwrap_or_else(|| format!("{:x?}", slot));
                r.examples.push(format!("{} (rva {:x}): slot {} of the vftable at {:x} (vfptr +{}) holds {}", f.cpp, f.rva, v.slot, vrva, v.vfptr, what));
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------------------------
// code

const ARG_GPR: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];

#[derive(Default, Debug, serde::Serialize)]
pub struct CodeReport {
    /// callee side: hidden-result functions whose every `ret` has RAX = the hidden pointer
    pub hidden_ret_functions: usize,
    pub hidden_ret_all_rets: usize,
    pub hidden_ret_some_rets: usize,
    pub hidden_ret_no_rets: usize,
    pub hidden_ret_unknown: usize,
    /// control: instance methods returning an integer or bool whose `ret` has RAX = RDX at entry
    pub control_functions: usize,
    pub control_rax_is_rdx: usize,
    /// caller side, per (declared passing, what the caller does before the call) -> call sites
    pub call_sites: usize,
    pub arg_setup: BTreeMap<String, usize>,
    /// small classes passed by value: (declared, setup) per class
    pub small_classes: BTreeMap<String, BTreeMap<String, usize>>,
}

fn decode_range(pe: &Pe, start: u32, end: u32) -> Vec<Instruction> {
    let s = start as usize;
    let e = (end as usize).min(pe.image.len());
    if s >= e {
        return Vec::new();
    }
    let mut d = Decoder::with_ip(64, &pe.image[s..e], start as u64, DecoderOptions::NONE);
    let mut v = Vec::new();
    let mut i = Instruction::default();
    while d.can_decode() {
        d.decode_out(&mut i);
        if i.is_invalid() {
            break;
        }
        v.push(i);
    }
    v
}

/// Does RAX hold the value `entry` had at function entry, at each `ret`? (all, some, none)
fn rax_tracks(ins: &[Instruction], entry: Register, hidden_callee: &dyn Fn(u32) -> Option<Register>) -> Option<(usize, usize)> {
    let mut regs: HashSet<Register> = HashSet::from([entry]);
    let mut slots: HashSet<i64> = HashSet::new();
    let mut rsp: i64 = 0;
    let mut rets = 0;
    let mut good = 0;
    let mut fac = InstructionInfoFactory::new();
    for i in ins {
        let m = i.mnemonic();
        if i.flow_control() == FlowControl::Return {
            rets += 1;
            if regs.contains(&Register::RAX) {
                good += 1;
            }
            continue;
        }
        // stack pointer
        match (m, i.op0_kind()) {
            (Mnemonic::Push, _) => rsp -= 8,
            (Mnemonic::Pop, _) => rsp += 8,
            (Mnemonic::Sub, OpKind::Register) if i.op0_register() == Register::RSP && i.op1_kind() != OpKind::Register => rsp -= i.immediate(1) as i64,
            (Mnemonic::Add, OpKind::Register) if i.op0_register() == Register::RSP && i.op1_kind() != OpKind::Register => rsp += i.immediate(1) as i64,
            _ => {}
        }
        if m == Mnemonic::Mov && i.op_count() == 2 {
            match (i.op0_kind(), i.op1_kind()) {
                (OpKind::Register, OpKind::Register) => {
                    let (d, s) = (i.op0_register(), i.op1_register());
                    if d.size() == 8 {
                        if regs.contains(&s) {
                            regs.insert(d);
                        } else {
                            regs.remove(&d);
                        }
                        continue;
                    }
                }
                (OpKind::Memory, OpKind::Register) if i.memory_base() == Register::RSP && i.memory_index() == Register::None => {
                    let s = i.op1_register();
                    let slot = rsp + i.memory_displacement64() as i64;
                    if regs.contains(&s) {
                        slots.insert(slot);
                    } else {
                        slots.remove(&slot);
                    }
                    continue;
                }
                (OpKind::Register, OpKind::Memory) if i.memory_base() == Register::RSP && i.memory_index() == Register::None => {
                    let d = i.op0_register();
                    let slot = rsp + i.memory_displacement64() as i64;
                    if d.size() == 8 {
                        if slots.contains(&slot) {
                            regs.insert(d);
                        } else {
                            regs.remove(&d);
                        }
                        continue;
                    }
                }
                _ => {}
            }
        }
        if i.flow_control() == FlowControl::Call {
            // a call that gets the tracked pointer as its own hidden result pointer returns it
            let fwd = i.code() == Code::Call_rel32_64 && hidden_callee(i.near_branch_target() as u32).map_or(false, |r| regs.contains(&r));
            for r in [Register::RAX, Register::RCX, Register::RDX, Register::R8, Register::R9, Register::R10, Register::R11] {
                regs.remove(&r);
            }
            if fwd {
                regs.insert(Register::RAX);
            }
            continue;
        }
        // any other write to a tracked register kills it
        let info = fac.info(i);
        for u in info.used_registers() {
            if matches!(u.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite) {
                regs.remove(&u.register().full_register());
            }
        }
    }
    if rets == 0 {
        None
    } else {
        Some((good, rets))
    }
}

/// What a caller last did to a register before a call: (kind, found)
fn last_write(ins: &[Instruction], call: usize, reg: Register, xmm: Option<u32>, fac: &mut InstructionInfoFactory) -> &'static str {
    let lo = call.saturating_sub(32);
    for j in (lo..call).rev() {
        let i = &ins[j];
        if matches!(i.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Return | FlowControl::IndirectBranch | FlowControl::IndirectCall) {
            return "unseen";
        }
        let info = fac.info(i);
        let writes = info.used_registers().iter().any(|u| {
            let r = u.register();
            let hit = match xmm {
                Some(n) => (r.is_xmm() || r.is_ymm() || r.is_zmm()) && r.number() as u32 == n,
                None => r.full_register() == reg,
            };
            hit && matches!(u.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite)
        });
        if !writes {
            continue;
        }
        if xmm.is_some() {
            return "xmm";
        }
        return match i.mnemonic() {
            Mnemonic::Lea if matches!(i.memory_base(), Register::RSP | Register::RBP) => "lea stack",
            Mnemonic::Lea if i.memory_base() == Register::RIP => "lea global",
            Mnemonic::Lea => "lea other",
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd if i.op1_kind() == OpKind::Memory => "load",
            Mnemonic::Mov if matches!(i.op1_kind(), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64 | OpKind::Immediate8) => "constant",
            Mnemonic::Xor if i.op1_kind() == OpKind::Register && i.op0_register() == i.op1_register() => "constant",
            Mnemonic::Mov => "register",
            Mnemonic::Movd | Mnemonic::Movq => "from xmm",
            _ => "computed",
        };
    }
    "unseen"
}

pub fn check_code(decls: &[FuncDecl], b: &Build, pe: &Pe) -> CodeReport {
    let mut r = CodeReport::default();
    let mut by_rva: HashMap<u32, Vec<&FuncDecl>> = HashMap::new();
    for f in decls {
        by_rva.entry(f.rva).or_default().push(f);
    }
    // the register a callee takes its hidden result pointer in
    let hidden_callee = |rva: u32| -> Option<Register> {
        let f = by_rva.get(&rva)?.first()?;
        (f.ret == "hidden").then(|| if f.this_c.is_some() { Register::RDX } else { Register::RCX })
    };
    // callee side
    for f in decls.iter().filter(|f| f.ret == "hidden") {
        let Some(k) = b.func_at(f.rva) else { continue };
        let fx = &b.funcs[k];
        let (s, e) = fx.ranges[0];
        let ins = decode_range(pe, s, e);
        let entry = if f.this_c.is_some() { Register::RDX } else { Register::RCX };
        r.hidden_ret_functions += 1;
        match rax_tracks(&ins, entry, &hidden_callee) {
            Some((g, n)) if g == n => r.hidden_ret_all_rets += 1,
            Some((0, _)) => r.hidden_ret_no_rets += 1,
            Some(_) => r.hidden_ret_some_rets += 1,
            None => r.hidden_ret_unknown += 1,
        }
    }
    // control: instance methods returning an integer or bool, with a pointer or reference in RDX
    let int_ret = |c: &str| matches!(c, "int" | "unsigned int" | "bool" | "short" | "unsigned short" | "char" | "unsigned char" | "long" | "unsigned long");
    for f in decls.iter().filter(|f| f.ret == "value" && f.this_c.is_some() && int_ret(&f.ret_cpp) && f.params.first().map_or(false, |p| p.pass == "pointer" || p.pass == "ref")) {
        let Some(k) = b.func_at(f.rva) else { continue };
        let (s, e) = b.funcs[k].ranges[0];
        if let Some((g, n)) = rax_tracks(&decode_range(pe, s, e), Register::RDX, &hidden_callee) {
            r.control_functions += 1;
            if g == n {
                r.control_rax_is_rdx += 1;
            }
        }
    }
    // caller side
    let mut fac = InstructionInfoFactory::new();
    for fx in &b.funcs {
        if !fx.refs.iter().any(|x| matches!(x, Ref::Call(_))) {
            continue;
        }
        let Some(&(s, e)) = fx.ranges.first() else { continue };
        let ins = decode_range(pe, s, e);
        for (ci, i) in ins.iter().enumerate() {
            if i.code() != Code::Call_rel32_64 {
                continue;
            }
            let t = i.near_branch_target() as u32;
            let Some(ds) = by_rva.get(&t) else { continue };
            let f = ds[0];
            // folded functions with different shapes: skip
            let shape = |g: &FuncDecl| g.params.iter().map(|p| p.pass).collect::<Vec<_>>();
            if ds.iter().any(|g| shape(g) != shape(f) || g.ret != f.ret || g.this_c.is_some() != f.this_c.is_some()) {
                continue;
            }
            r.call_sites += 1;
            let mut pos = 0usize;
            if f.this_c.is_some() {
                pos += 1;
            }
            if f.ret == "hidden" {
                if pos < 4 {
                    let w = last_write(&ins, ci, ARG_GPR[pos], None, &mut fac);
                    *r.arg_setup.entry(format!("hidden result pointer <- {}", w)).or_default() += 1;
                }
                pos += 1;
            }
            for p in &f.params {
                if pos >= 4 {
                    break;
                }
                let key = match (p.pass, p.cat.as_str()) {
                    ("copy", _) => Some(if p.why == "size" { "class by value (not 1, 2, 4 or 8 bytes), declared as a pointer to a copy" } else { "class by value (small, not trivially copyable), declared as a pointer to a copy" }),
                    ("value", "v") => Some("class by value, declared in a register"),
                    ("float", _) => Some("float/double"),
                    ("value", c) if c.starts_with("f:") => Some("integer"),
                    _ => None,
                };
                if let Some(key) = key {
                    let w = if p.pass == "float" { last_write(&ins, ci, Register::None, Some(pos as u32), &mut fac) } else { last_write(&ins, ci, ARG_GPR[pos], None, &mut fac) };
                    *r.arg_setup.entry(format!("{} <- {}", key, w)).or_default() += 1;
                    if p.cat == "v" && p.why != "size" {
                        *r.small_classes.entry(p.cpp.trim_end_matches(" const").to_string()).or_default().entry(format!("{}{}", if p.pass == "copy" { "ptr:" } else { "reg:" }, w)).or_default() += 1;
                    }
                    if p.pass == "float" {
                        // and the GPR of the same position is not what carries it
                        let g = last_write(&ins, ci, ARG_GPR[pos], None, &mut fac);
                        if g != "unseen" {
                            *r.arg_setup.entry(format!("float/double, GPR of the same position <- {}", g)).or_default() += 1;
                        }
                    }
                }
                pos += 1;
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------------------------
// returns: the PDB's ReturnUDT flag against the POD rule

#[derive(Default, Debug, serde::Serialize)]
pub struct ReturnReport {
    pub free_class_returns_small: usize,
    pub flag_and_not_pod: usize,
    pub no_flag_and_pod: usize,
    pub flag_but_pod: usize,
    pub no_flag_not_pod: usize,
    pub methods_class_returns: usize,
    pub methods_flag: usize,
    pub examples: Vec<String>,
}

pub fn check_returns(db: &Db, funcs: &Funcs, decls: &[FuncDecl]) -> ReturnReport {
    let mut r = ReturnReport::default();
    for f in decls {
        let Some(rec) = db.t.get(f.ty) else { continue };
        let ret = match rec {
            crate::tpi::Rec::Procedure { ret, .. } | crate::tpi::Rec::MFunction { ret, .. } => *ret,
            _ => continue,
        };
        let (rt, _) = db.strip(ret);
        let Some(d) = (match db.t.get(rt) {
            Some(crate::tpi::Rec::Class { .. }) | Some(crate::tpi::Rec::Union { .. }) => db.def_of(rt),
            _ => None,
        }) else {
            continue;
        };
        if f.this_c.is_some() {
            r.methods_class_returns += 1;
            r.methods_flag += f.cxx_return_udt as usize;
            continue;
        }
        let size = db.size_of(d).unwrap_or(0);
        if !matches!(size, 1 | 2 | 4 | 8) {
            continue;
        }
        r.free_class_returns_small += 1;
        let pod = funcs.pod(d);
        match (f.cxx_return_udt, pod) {
            (true, false) => r.flag_and_not_pod += 1,
            (false, true) => r.no_flag_and_pod += 1,
            (true, true) => {
                r.flag_but_pod += 1;
                if r.examples.len() < 10 {
                    r.examples.push(format!("flag, but POD by the rule: {}", f.cpp));
                }
            }
            (false, false) => {
                r.no_flag_not_pod += 1;
                if r.examples.len() < 10 {
                    r.examples.push(format!("no flag, not POD by the rule: {}", f.cpp));
                }
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------------------------

#[derive(Default, Debug, serde::Serialize)]
pub struct ThrowReport {
    pub throw_sites: BTreeMap<String, usize>,
    pub seh_sites: Vec<String>,
    pub site_examples: BTreeMap<String, Vec<String>>,
}

pub fn check_throws(b: &Build) -> ThrowReport {
    let mut r = ThrowReport::default();
    let t = crate::throws::analyse(b);
    for (i, f) in b.funcs.iter().enumerate() {
        let name = f.names.first().map(|&k| b.names[k as usize].as_str()).unwrap_or("?");
        let raises = f.refs.iter().any(|x| matches!(x, Ref::CallImport(k) | Ref::JumpImport(k) if b.imports[*k as usize].name == "RaiseException"));
        if raises && r.seh_sites.len() < 30 {
            r.seh_sites.push(format!("{:x} {}", f.rva, name));
        }
        if t[i].site {
            let k = t[i].via_names().join(",");
            *r.throw_sites.entry(k.clone()).or_default() += 1;
            let e = r.site_examples.entry(k).or_default();
            if e.len() < 8 {
                e.push(name.to_string());
            }
        }
    }
    r
}

pub fn summary_text(lin: Option<&LinuxReport>, vt: &VtableReport, code: &CodeReport, ret: &ReturnReport, thr: &ThrowReport) -> String {
    let mut s = String::new();
    let pct = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
    if let Some(l) = lin {
        let _ = writeln!(s, "## Linux cross-check");
        let _ = writeln!(s, "names on both sides {} (PDB {}, Linux functions {}); pairs: {} unique, {} by parameter count; {} overloads not paired", l.names_on_both, l.pdb_names, l.linux_functions, l.pairs_unique, l.pairs_by_count, l.overloads_unpaired);
        let n = l.count_agree + l.count_disagree;
        let _ = writeln!(s, "parameter count agrees: {} of {} ({:.2}%)", l.count_agree, n, pct(l.count_agree, n));
        let _ = writeln!(s, "parameters: shape agrees {} of {} ({:.2}%), exactly {} ({:.2}%)", l.params_shape_agree, l.params_compared, pct(l.params_shape_agree, l.params_compared), l.params_exact_agree, pct(l.params_exact_agree, l.params_compared));
        let _ = writeln!(s, "functions agreeing exactly: {} of {} ({:.2}%)", l.functions_exact_agree, n, pct(l.functions_exact_agree, n));
        let _ = writeln!(s, "const methods: agree {}, disagree {}", l.const_method_agree, l.const_method_disagree);
        let mut d: Vec<(&String, &(usize, String))> = l.disagreements.iter().collect();
        d.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
        for (k, (n, ex)) in d.iter().take(25) {
            let _ = writeln!(s, "  {:>6}  {:<14} e.g. {}", n, k, ex);
        }
    }
    let _ = writeln!(s, "## vtables");
    let _ = writeln!(s, "{} vftable symbols, {} mapped to (class, vfptr); {} virtual methods checked: slot holds the method {} ({:.2}%; {} of them destructors whose slot holds the deleting destructor, {} an identical copy of the code; {} slots were adjustor thunks, followed), something else {}; {} slots hold _purecall (not counted); {} without a vftable symbol", vt.vftable_symbols, vt.vftables_mapped, vt.methods_checked - vt.purecall, vt.slot_agree, pct(vt.slot_agree, vt.methods_checked - vt.purecall), vt.dtor_agree, vt.identical_code, vt.thunks, vt.slot_disagree, vt.purecall, vt.no_vftable);
    for e in &vt.examples {
        let _ = writeln!(s, "  {}", e);
    }
    let _ = writeln!(s, "## code");
    let _ = writeln!(
        s,
        "hidden-result functions: {}; RAX = the hidden pointer at every ret {} ({:.1}%), at some {}, at none {}, no ret {}",
        code.hidden_ret_functions,
        code.hidden_ret_all_rets,
        pct(code.hidden_ret_all_rets, code.hidden_ret_functions - code.hidden_ret_unknown),
        code.hidden_ret_some_rets,
        code.hidden_ret_no_rets,
        code.hidden_ret_unknown
    );
    let _ = writeln!(s, "control (instance methods returning an integer or bool, pointer in RDX): RAX = RDX at every ret in {} of {}", code.control_rax_is_rdx, code.control_functions);
    let _ = writeln!(s, "call sites checked {}:", code.call_sites);
    for (k, n) in &code.arg_setup {
        let _ = writeln!(s, "  {:>8}  {}", n, k);
    }
    let mut sc: Vec<(&String, &BTreeMap<String, usize>)> = code.small_classes.iter().collect();
    sc.sort_by_key(|(_, m)| std::cmp::Reverse(m.values().sum::<usize>()));
    let _ = writeln!(s, "small classes by value, by class (declared ptr:/reg: <- caller setup):");
    for (c, m) in sc.iter().take(30) {
        let v: Vec<String> = m.iter().map(|(k, n)| format!("{} {}", k, n)).collect();
        let _ = writeln!(s, "  {}: {}", c, v.join(", "));
    }
    let _ = writeln!(s, "## returns of free/static functions (class of 1, 2, 4 or 8 bytes)");
    let _ = writeln!(s, "{} such functions: PDB ReturnUDT and not POD {}, no flag and POD {}, flag but POD {}, no flag but not POD {}", ret.free_class_returns_small, ret.flag_and_not_pod, ret.no_flag_and_pod, ret.flag_but_pod, ret.no_flag_not_pod);
    let _ = writeln!(s, "instance methods returning a class: {}, with the flag {}", ret.methods_class_returns, ret.methods_flag);
    for e in &ret.examples {
        let _ = writeln!(s, "  {}", e);
    }
    let _ = writeln!(s, "## throw sites (functions calling _CxxThrowException), by kind");
    for (k, n) in &thr.throw_sites {
        let _ = writeln!(s, "  {:>6}  {}  e.g. {}", n, k, thr.site_examples.get(k).map(|v| v.join("; ")).unwrap_or_default());
    }
    let _ = writeln!(s, "RaiseException callers: {}", thr.seh_sites.join("; "));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_names() {
        let (n, p, k) = parse_linux("CShip::CalcRegenAmount(CFixedPoint, CFixedPoint, CFixedPoint) const").unwrap();
        assert_eq!((n.as_str(), p.len(), k), ("CShip::CalcRegenAmount", 3, true));
        let (n, p, _) = parse_linux("bool CFoo::operator<<CBar>(CBar const&) [clone .cold]").unwrap();
        assert_eq!((n.as_str(), p[0].as_str()), ("CFoo::operator<<CBar>", "CBar const&"));
        let (n, p, _) = parse_linux("void (anonymous namespace)::Helper(int (*)(void*), std::map<int, int>&)").unwrap();
        assert_eq!((n.as_str(), p.len()), ("(anonymous namespace)::Helper", 2));
        assert_eq!(linux_cat("CString const&"), "rc");
        assert_eq!(linux_cat("CCountry const* const&"), "rc");
        assert_eq!(linux_cat("char const*"), "pc");
        assert_eq!(linux_cat("SForceData const* const*"), "pc");
        assert_eq!(linux_cat("char const**"), "p");
        assert_eq!(linux_cat("unsigned long"), "f:u64");
        assert_eq!(linux_cat("void (*)(int)"), "p");
        assert_eq!(linux_cat("CFixedPoint"), "v");
        assert_eq!(norm_name("CPdxArray<unsigned __int64,int>::Reserve"), "CPdxArray<unsigned long,int>::Reserve");
        assert_eq!(norm_name("CPdxModifier<enum ModifierType,class CModifier>"), "CPdxModifier<ModifierType,CModifier>");
    }
}
