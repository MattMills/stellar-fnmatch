//! C declarations of functions for the LuaJIT FFI, following the MSVC x64 calling convention,
//! with the vtable slot of every virtual method. docs/ffi.md lists the rules and what is verified.
//!
//! - `this` is the first parameter (a pointer to the class whose subobject the code expects: for an
//!   override reached through a secondary base, that base, `this_adjust` bytes into the object);
//! - a class, struct or union result goes through a hidden pointer when MSVC returns it in
//!   memory: always for instance methods (after `this`), and for other functions when the PDB says
//!   "C++ style ReturnUDT" or the size is not 1, 2, 4 or 8 (first parameter). The declaration then
//!   takes the pointer and returns it (MSVC returns it in RAX);
//! - references are pointers; function pointers `void*`;
//! - a class passed by value whose size is not 1, 2, 4 or 8, or that is not trivially copyable,
//!   is passed as a pointer to a copy the caller makes (the callee owns it: MSVC destroys by-value
//!   arguments in the callee);
//! - float and double parameters stay float and double: LuaJIT passes them in the SSE register
//!   of their position, as MSVC does.

use crate::cdef::{prim, Db, Deps, Kind, CT};
use crate::pdbtypes::Proc;
use crate::tpi::{pm, Field, FieldAttr, Rec};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Param {
    pub cpp: String,
    pub c: String,
    /// value | float | pointer | ref | copy | vararg
    pub pass: &'static str,
    /// category for the cross-check: p, pc, r, rc, rr, v, e, m, f:<kind>
    pub cat: String,
    /// for `copy`: why the class is not passed in a register ("size" or "nontrivial")
    pub why: &'static str,
}

#[derive(Debug, Clone)]
pub struct Virt {
    /// offset of the vfptr in the object, slot index, class that introduced the method
    pub vfptr: u64,
    pub slot: u32,
    pub intro: u32,
    pub pure: bool,
    /// a virtual destructor: the slot holds the deleting destructor, `void *(C *, uint32_t flags)`
    pub deleting: bool,
}

#[derive(Debug, Clone)]
pub struct FuncDecl {
    pub name: String,
    pub rva: u32,
    pub ty: u32,
    /// `R (*)(A, B)`
    pub decl: String,
    pub deps: Deps,
    pub cpp: String,
    /// free | static | method | ctor | dtor
    pub kind: &'static str,
    pub class: Option<u32>,
    /// C name of the class `this` points to, and how far into the object that is
    pub this_c: Option<String>,
    pub this_adjust: i32,
    pub this_const: bool,
    /// void | value | hidden
    pub ret: &'static str,
    pub ret_cpp: String,
    pub cxx_return_udt: bool,
    pub params: Vec<Param>,
    pub va: bool,
    pub virt: Option<Virt>,
    pub rewrites: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct MethodRec {
    pub attr: FieldAttr,
    pub ty: u32,
    pub vtoff: Option<u32>,
}

pub struct Funcs<'a, 'b> {
    pub db: &'b Db<'a>,
    /// (class definition, method name) -> declarations in the class
    pub methods: HashMap<(u32, String), Vec<MethodRec>>,
    /// destructors declared in each class
    dtors: HashMap<u32, Vec<MethodRec>>,
    triv_copy: std::cell::RefCell<HashMap<u32, bool>>,
    pod: std::cell::RefCell<HashMap<u32, bool>>,
}

/// Splits `A::B<C::D>::f` into (`A::B<C::D>`, `f`) at the last `::` outside brackets.
pub fn split_scope(name: &str) -> Option<(&str, &str)> {
    let b = name.as_bytes();
    let mut depth = 0i32;
    let mut last = None;
    let mut i = 0;
    // `operator<` and friends: brackets after "operator" are not nesting
    while i < b.len() {
        match b[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            b':' if depth == 0 && b.get(i + 1) == Some(&b':') => {
                last = Some(i);
                i += 1;
            }
            b'o' if depth == 0 && name[i..].starts_with("operator") && last.map_or(i == 0, |l| l + 2 == i) => break,
            _ => {}
        }
        i += 1;
    }
    last.map(|l| (&name[..l], &name[l + 2..]))
}

impl<'a, 'b> Funcs<'a, 'b> {
    pub fn new(db: &'b Db<'a>) -> Self {
        let mut methods: HashMap<(u32, String), Vec<MethodRec>> = HashMap::new();
        for &d in &db.udts {
            let Some(Rec::Class { fields, .. }) = db.t.get(d) else { continue };
            for f in db.t.fields(*fields) {
                match f {
                    Field::OneMethod { attr, ty, vtoff, name } => methods.entry((d, name.clone())).or_default().push(MethodRec { attr: *attr, ty: *ty, vtoff: *vtoff }),
                    Field::Method { list, name, .. } => {
                        if let Some(Rec::MethodList(ms)) = db.t.get(*list) {
                            for m in ms {
                                methods.entry((d, name.clone())).or_default().push(MethodRec { attr: m.attr, ty: m.ty, vtoff: m.vtoff });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut dtors: HashMap<u32, Vec<MethodRec>> = HashMap::new();
        for ((c, n), v) in &methods {
            if n.starts_with('~') {
                dtors.entry(*c).or_default().extend(v.iter().copied());
            }
        }
        Funcs { db, methods, dtors, triv_copy: Default::default(), pod: Default::default() }
    }

    fn class_fields(&self, d: u32) -> Vec<&'a Field> {
        match self.db.t.get(d) {
            Some(Rec::Class { fields, .. }) | Some(Rec::Union { fields, .. }) => self.db.t.fields(*fields),
            _ => Vec::new(),
        }
    }

    /// Is `ti` an lvalue or rvalue reference to (cv) class `d`?
    /// Is `ti` an lvalue reference to (cv) class `d`?
    fn is_lref_to(&self, ti: u32, d: u32) -> bool {
        matches!(self.db.t.get(ti), Some(Rec::Pointer { attr, .. }) if Rec::ptr_mode(*attr) == pm::LREF) && self.is_ref_to(ti, d)
    }

    fn is_ref_to(&self, ti: u32, d: u32) -> bool {
        if let Some(Rec::Pointer { referent, attr, .. }) = self.db.t.get(ti) {
            if matches!(Rec::ptr_mode(*attr), pm::LREF | pm::RREF) {
                let (r, _) = self.db.strip(*referent);
                return self.db.def_of(r) == Some(d);
            }
        }
        false
    }

    fn has_vfptr_or_vbase(&self, d: u32) -> bool {
        self.class_fields(d).iter().any(|f| matches!(f, Field::VFuncTab { .. } | Field::VBase { .. }))
            || self.class_fields(d).iter().any(|f| match f {
                Field::Base { ty, .. } => self.db.def_of(*ty).map_or(false, |b| self.has_vfptr_or_vbase(b)),
                _ => false,
            })
    }

    /// Copy constructors (`C(C&)`, `C(const C&)`) the class declares. Move constructors do not
    /// count: the GOG 4.5.2 call sites pass small classes that only declare one (`TPdxRef<T>`,
    /// `CSimpleBitMask<E>`) in a register, and those with a copy constructor (`CPdxPtr<T>`,
    /// `fpml::fixed_point`) by address (docs/ffi.md). Compiler-generated ones are judged through
    /// the members and bases.
    fn copy_ctors(&self, d: u32) -> usize {
        let mut n = 0;
        for f in self.class_fields(d) {
            let tys: Vec<(FieldAttr, u32)> = match f {
                Field::OneMethod { attr, ty, .. } => vec![(*attr, *ty)],
                Field::Method { list, .. } => match self.db.t.get(*list) {
                    Some(Rec::MethodList(ms)) => ms.iter().map(|m| (m.attr, m.ty)).collect(),
                    _ => vec![],
                },
                _ => vec![],
            };
            for (attr, ty) in tys {
                if attr.pseudo() || attr.compgenx() {
                    continue;
                }
                if let Some(Rec::MFunction { fattr, args, .. }) = self.db.t.get(ty) {
                    let a = self.db.t.args(*args);
                    if fattr.ctor() && a.len() == 1 && self.is_lref_to(a[0], d) {
                        n += 1;
                    }
                }
            }
        }
        n
    }

    /// Trivially copyable for the purposes of a call (MSVC x64 passes such a class of 1, 2, 4 or 8
    /// bytes in a register): no virtual functions or bases, no declared copy/move constructor,
    /// bases and members alike.
    pub fn trivially_copyable(&self, d: u32) -> bool {
        if let Some(&v) = self.triv_copy.borrow().get(&d) {
            return v;
        }
        self.triv_copy.borrow_mut().insert(d, true); // cycles: assume yes
        let v = match self.db.kind_of(d) {
            Some(Kind::Enum) => true,
            Some(_) => {
                !self.has_vfptr_or_vbase(d)
                    && self.copy_ctors(d) == 0
                    && self.class_fields(d).iter().all(|f| match f {
                        Field::Base { ty, .. } => self.db.def_of(*ty).map_or(true, |b| self.trivially_copyable(b)),
                        Field::Member { ty, .. } => self.member_trivial(*ty, true),
                        _ => true,
                    })
            }
            None => true,
        };
        self.triv_copy.borrow_mut().insert(d, v);
        v
    }

    fn member_trivial(&self, ti: u32, copy: bool) -> bool {
        let (t, _) = self.db.strip(ti);
        match self.db.t.get(t) {
            Some(Rec::Array { elem, .. }) => self.member_trivial(*elem, copy),
            Some(Rec::Class { .. }) | Some(Rec::Union { .. }) => self.db.def_of(t).map_or(true, |d| if copy { self.trivially_copyable(d) } else { self.pod(d) }),
            Some(Rec::Pointer { attr, .. }) if !copy => !matches!(Rec::ptr_mode(*attr), pm::LREF | pm::RREF),
            _ => true,
        }
    }

    /// MSVC's rule for returning a class in RAX from a free or static function (C++03 POD): no
    /// user-declared constructor, destructor or copy assignment, no private or protected data
    /// members, no reference members, no bases, no virtual functions, members alike.
    pub fn pod(&self, d: u32) -> bool {
        if let Some(&v) = self.pod.borrow().get(&d) {
            return v;
        }
        self.pod.borrow_mut().insert(d, true);
        let mut ok = !self.has_vfptr_or_vbase(d);
        let short = self.db.cpp_name_of_def(d).rsplit("::").next().unwrap_or("").to_string();
        for f in self.class_fields(d) {
            match f {
                Field::Base { .. } => ok = false,
                Field::Member { attr, ty, .. } => {
                    if attr.access() != 3 || !self.member_trivial(*ty, false) {
                        ok = false;
                    }
                }
                Field::OneMethod { attr, ty, name, .. } => ok &= self.pod_method(*attr, *ty, name, &short, d),
                Field::Method { list, name, .. } => {
                    if let Some(Rec::MethodList(ms)) = self.db.t.get(*list) {
                        for m in ms {
                            ok &= self.pod_method(m.attr, m.ty, name, &short, d);
                        }
                    }
                }
                _ => {}
            }
        }
        self.pod.borrow_mut().insert(d, ok);
        ok
    }

    fn pod_method(&self, attr: FieldAttr, ty: u32, name: &str, _short: &str, d: u32) -> bool {
        if attr.pseudo() || attr.compgenx() {
            return true;
        }
        let Some(Rec::MFunction { fattr, args, .. }) = self.db.t.get(ty) else { return true };
        if fattr.ctor() || name.starts_with('~') {
            return false;
        }
        if name == "operator=" {
            let a = self.db.t.args(*args);
            if a.len() == 1 && self.is_ref_to(a[0], d) {
                return false;
            }
        }
        true
    }

    /// Offset of the vfptr new virtual methods of a class go into.
    pub fn primary_vfptr(&self, d: u32, depth: usize) -> Option<u64> {
        if depth > 32 {
            return None;
        }
        let fs = self.class_fields(d);
        if fs.iter().any(|f| matches!(f, Field::VFuncTab { .. })) {
            return Some(0);
        }
        let mut bases: Vec<(u64, u32)> = fs
            .iter()
            .filter_map(|f| match f {
                Field::Base { ty, offset, .. } => self.db.def_of(*ty).map(|b| (*offset, b)),
                _ => None,
            })
            .collect();
        bases.sort();
        bases.into_iter().find_map(|(o, b)| self.primary_vfptr(b, depth + 1).map(|v| v + o))
    }

    fn same_signature(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        let (Some(Rec::MFunction { args: aa, this_ty: at, .. }), Some(Rec::MFunction { args: ba, this_ty: bt, .. })) = (self.db.t.get(a), self.db.t.get(b)) else { return false };
        let norm = |t: u32| -> String { self.db.cpp(t) };
        let x = self.db.t.args(*aa);
        let y = self.db.t.args(*ba);
        x.len() == y.len() && x.iter().zip(y).all(|(p, q)| p == q || norm(*p) == norm(*q)) && self.this_const(*at) == self.this_const(*bt)
    }

    fn this_const(&self, this_ty: u32) -> bool {
        match self.db.t.get(this_ty) {
            Some(Rec::Pointer { referent, .. }) => self.db.strip(*referent).1,
            _ => false,
        }
    }

    /// The vtable slot of the virtual method `name` with type `mf` (of `d` or of a derived class):
    /// the introducing declaration gives the slot, in the primary vfptr of the class that
    /// introduces it; an override finds it in its bases (the vfptr offset adds up along the way).
    pub fn virt(&self, d: u32, name: &str, mf: u32, depth: usize) -> Option<Virt> {
        if depth > 32 {
            return None;
        }
        if let Some(ms) = self.methods.get(&(d, name.to_string())) {
            if let Some(m) = ms.iter().find(|m| m.ty == mf).or_else(|| ms.iter().find(|m| self.same_signature(m.ty, mf))) {
                if !m.attr.is_virtual() {
                    return None;
                }
                if let (true, Some(off)) = (m.attr.is_intro(), m.vtoff) {
                    return Some(Virt { vfptr: self.primary_vfptr(d, 0)?, slot: off / 8, intro: d, pure: m.attr.is_pure(), deleting: name.starts_with('~') || name == "__vecDelDtor" });
                }
            }
        }
        let mut bases: Vec<(u64, u32)> = self
            .class_fields(d)
            .iter()
            .filter_map(|f| match f {
                Field::Base { ty, offset, .. } => self.db.def_of(*ty).map(|b| (*offset, b)),
                _ => None,
            })
            .collect();
        bases.sort();
        for (offset, b) in bases {
            if let Some(mut v) = self.virt(b, name, mf, depth + 1) {
                v.vfptr += offset;
                return Some(v);
            }
        }
        None
    }

    /// The slot of the deleting destructor of `d`: its own `__vecDelDtor`, or that of the base
    /// whose vfptr is the primary one.
    ///
    /// MSVC lists `__vecDelDtor` as introduced in every class that has one, but the slot is in the
    /// vftable of the first base (by offset) that already has a virtual destructor; only a class
    /// none of whose bases has one introduces it, in its primary vftable.
    pub fn dtor_slot(&self, d: u32, depth: usize) -> Option<Virt> {
        if depth > 32 {
            return None;
        }
        let mut bases: Vec<(u64, u32)> = self
            .class_fields(d)
            .iter()
            .filter_map(|f| match f {
                Field::Base { ty, offset, .. } => self.db.def_of(*ty).map(|b| (*offset, b)),
                _ => None,
            })
            .collect();
        bases.sort();
        for (o, b) in bases {
            if self.has_virtual_dtor(b, depth + 1) {
                if let Some(mut v) = self.dtor_slot(b, depth + 1) {
                    v.vfptr += o;
                    return Some(v);
                }
            }
        }
        let own = self.methods.get(&(d, "__vecDelDtor".to_string())).into_iter().flatten().chain(
            self.dtors.get(&d).into_iter().flatten(),
        );
        for m in own {
            if let (true, Some(off)) = (m.attr.is_intro(), m.vtoff) {
                let pure = self.dtors.get(&d).map_or(false, |v| v.iter().any(|x| x.attr.is_pure()));
                return Some(Virt { vfptr: self.primary_vfptr(d, 0)?, slot: off / 8, intro: d, pure, deleting: true });
            }
        }
        None
    }

    /// Does the class or one of its bases declare a virtual destructor?
    pub fn has_virtual_dtor(&self, d: u32, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        let own = self.methods.get(&(d, "__vecDelDtor".to_string())).map_or(false, |v| v.iter().any(|m| m.attr.is_virtual())) || self.dtors.get(&d).map_or(false, |v| v.iter().any(|m| m.attr.is_virtual()));
        own || self.class_fields(d).iter().any(|f| match f {
            Field::Base { ty, .. } => self.db.def_of(*ty).map_or(false, |b| self.has_virtual_dtor(b, depth + 1)),
            _ => false,
        })
    }

    /// The base class (path from `d`) whose subobject starts `adjust` bytes into `d` and has a
    /// vfptr there: what an override with this adjustment receives as `this`.
    pub fn subobject_at(&self, d: u32, adjust: u64) -> Option<u32> {
        if adjust == 0 {
            return Some(d);
        }
        let l = self.db.layout(d)?;
        l.bases.iter().filter(|(_, o, _)| *o == adjust).map(|(b, _, _)| *b).find(|&b| self.primary_vfptr(b, 0) == Some(0)).or_else(|| l.bases.iter().find(|(_, o, _)| *o == adjust).map(|(b, ..)| *b))
    }

    /// C type and category of a parameter or result type.
    fn arg(&self, ti: u32, d: &mut Deps) -> (CT, String, &'static str, Option<u32>) {
        let (t, konst) = self.db.strip(ti);
        if t < crate::tpi::TI_FIRST {
            let (c, _, _, cat) = prim(t);
            let pass = if cat == "f32" || cat == "f64" { "float" } else if cat == "p" { "pointer" } else { "value" };
            let cat = if cat == "p" { "p".to_string() } else { format!("f:{}", cat) };
            return (c, cat, pass, None);
        }
        match self.db.t.get(t) {
            Some(Rec::Pointer { referent, attr, .. }) => {
                let mode = Rec::ptr_mode(*attr);
                let (r, rc) = self.db.strip(*referent);
                // a const pointer is const in the pointer record, not in a modifier
                let rc = rc || matches!(self.db.t.get(r), Some(Rec::Pointer { attr: pa, .. }) if Rec::ptr_const(*pa));
                match mode {
                    pm::PMEM | pm::PMFUNC => {
                        let s = self.db.size_of(t).unwrap_or(8);
                        let c = match s {
                            4 => CT::base("int32_t"),
                            8 => CT::base("uint64_t"),
                            _ => CT::void_ptr(),
                        };
                        (c, "m".into(), if s == 4 || s == 8 { "value" } else { "copy" }, None)
                    }
                    _ => {
                        let is_fn = matches!(self.db.t.get(r), Some(Rec::Procedure { .. } | Rec::MFunction { .. }));
                        let c = if is_fn {
                            CT::void_ptr()
                        } else {
                            let (pt, _) = self.db.ctype(*referent, true, d);
                            CT::ptr(pt)
                        };
                        let k = if rc { "c" } else { "" };
                        let (cat, pass) = match mode {
                            pm::LREF => (format!("r{}", k), "ref"),
                            pm::RREF => ("rr".to_string(), "ref"),
                            _ => (format!("p{}", k), "pointer"),
                        };
                        let _ = konst;
                        (c, cat, pass, None)
                    }
                }
            }
            Some(Rec::Class { .. }) | Some(Rec::Union { .. }) | Some(Rec::Enum { .. }) => {
                let Some(def) = self.db.def_of(t) else { return (CT::void_ptr(), "v".into(), "copy", None) };
                let (c, _) = self.db.ctype(t, false, d);
                if self.db.kind_of(def) == Some(Kind::Enum) {
                    return (c, "e".into(), "value", None);
                }
                (c, "v".into(), "value", Some(def))
            }
            Some(Rec::Array { .. }) => {
                let (c, _) = self.db.ctype(t, true, d);
                (c, "p".into(), "pointer", None)
            }
            _ => (CT::void_ptr(), "?".into(), "value", None),
        }
    }

    /// The declaration of a procedure, or None when it has no function type.
    pub fn declare(&self, p: &Proc) -> Option<FuncDecl> {
        let db = self.db;
        let rec = db.t.get(p.ty)?;
        let (ret, args, fattr, class, this_ty, this_adjust) = match rec {
            Rec::Procedure { ret, args, fattr, .. } => (*ret, *args, *fattr, None, 0, 0),
            Rec::MFunction { ret, args, fattr, class, this_ty, this_adjust, .. } => (*ret, *args, *fattr, db.def_of(*class), *this_ty, *this_adjust),
            _ => return None,
        };
        let mut d = Deps::default();
        let mut rewrites = Vec::new();
        let instance = class.is_some() && this_ty != 0;
        // the method's name in its class
        let mname: Option<String> = class.map(|c| {
            let cn = db.cpp_name_of_def(c);
            let rest = p.name.strip_prefix(cn).and_then(|r| r.strip_prefix("::")).map(|s| s.to_string());
            let rest = rest.unwrap_or_else(|| split_scope(&p.name).map(|(_, m)| m.to_string()).unwrap_or_else(|| p.name.clone()));
            if rest == "`scalar deleting destructor'" || rest == "`vector deleting destructor'" {
                "__vecDelDtor".to_string()
            } else {
                rest
            }
        });
        let mrec = match (class, &mname) {
            (Some(c), Some(m)) => self.methods.get(&(c, m.clone())).and_then(|v| v.iter().find(|x| x.ty == p.ty).copied()),
            _ => None,
        };
        let kind = if fattr.ctor() {
            "ctor"
        } else if mname.as_deref().map_or(false, |m| m.starts_with('~')) {
            "dtor"
        } else if class.is_some() && !instance {
            "static"
        } else if instance {
            "method"
        } else {
            "free"
        };

        let mut params_c: Vec<CT> = Vec::new();
        let mut params: Vec<Param> = Vec::new();
        let mut this_c = None;
        let this_const = instance && self.this_const(this_ty);
        if instance {
            let c = class.unwrap();
            let sub = if this_adjust != 0 { self.subobject_at(c, this_adjust as u64).unwrap_or(c) } else { c };
            if this_adjust != 0 {
                rewrites.push(format!(
                    "this: the {} subobject, {:#x} bytes into the {} (fnmatch.ffi casts it)",
                    db.cpp_name_of_def(sub),
                    this_adjust,
                    db.cpp_name_of_def(c)
                ));
            }
            d.opaque.insert(sub);
            let tc = CT::ptr(CT::base(&db.cname[&sub]).with_const(this_const));
            params_c.push(tc);
            this_c = Some(db.cname[&sub].clone());
        }

        // result
        let (rt, _) = db.strip(ret);
        let ret_cpp = db.cpp(ret);
        let rclass = match db.t.get(rt) {
            Some(Rec::Class { .. }) | Some(Rec::Union { .. }) => db.def_of(rt),
            _ => None,
        };
        let ret_size = db.size_of(rt).unwrap_or(0);
        let (ret_ct, ret_kind) = if let Some(rc) = rclass {
            let hidden = instance || fattr.cxx_return_udt() || !matches!(ret_size, 1 | 2 | 4 | 8);
            let name = db.cname[&rc].clone();
            d.full.insert(rc);
            if hidden {
                let why = if instance {
                    "instance method"
                } else if fattr.cxx_return_udt() {
                    "not a C++03 POD (PDB: C++ style ReturnUDT)"
                } else {
                    "size not 1, 2, 4 or 8"
                };
                let pos = params_c.len();
                params_c.push(CT::ptr(CT::base(&name)));
                rewrites.push(format!("result {}: through a hidden pointer, parameter {} ({}); returns that pointer", ret_cpp, pos + 1, why));
                (CT::ptr(CT::base(&name)), "hidden")
            } else {
                (CT::base(&name), "value")
            }
        } else if rt == 3 || rt == 0 {
            (CT::base("void"), "void")
        } else {
            let (c, _, _, _) = self.arg(ret, &mut d);
            (c.unconst(), "value")
        };

        let mut va = false;
        for (i, &a) in db.t.args(args).iter().enumerate() {
            if a == 0 {
                va = true;
                continue;
            }
            if a == 3 && db.t.args(args).len() == 1 {
                break; // (void)
            }
            let cpp = db.cpp(a);
            let (c, cat, mut pass, by_value) = self.arg(a, &mut d);
            let mut c = c.unconst();
            let mut why = "";
            if let Some(def) = by_value {
                let size = db.size_of(def).unwrap_or(0);
                let small = matches!(size, 1 | 2 | 4 | 8);
                let direct = small && self.trivially_copyable(def);
                if !direct {
                    why = if small { "nontrivial" } else { "size" };
                    let w = if !small { format!("{} bytes", size) } else { "not trivially copyable".to_string() };
                    rewrites.push(format!("parameter {} {}: by value ({}), so a pointer to a copy the caller makes; the callee destroys it", i + 1, cpp, w));
                    c = CT::ptr(c);
                    pass = "copy";
                }
            }
            params.push(Param { cpp, c: c.decl(""), pass, cat, why });
            params_c.push(c);
        }
        if va {
            rewrites.push("variadic: LuaJIT passes Lua numbers as double and mirrors the vararg registers in both register sets, as MSVC expects".into());
        }

        let virt = match (class, &mname, mrec) {
            // a virtual destructor's slot holds the deleting destructor (`__vecDelDtor` in the
            // class's method list), whose name does not change from base to derived class
            (Some(c), Some(m), Some(r)) if r.attr.is_virtual() && (m.starts_with('~') || m == "__vecDelDtor") => self.dtor_slot(c, 0),
            (Some(c), Some(m), Some(r)) if r.attr.is_virtual() => self.virt(c, m, p.ty, 0),
            _ => None,
        };
        if let Some(v) = &virt {
            if v.deleting {
                rewrites.push(format!(
                    "virtual destructor: slot {} holds the deleting destructor, void *(*)({} *, uint32_t flags), flags 1 = free the memory (fnmatch.ffi's vcall knows)",
                    v.slot,
                    db.cname[&class.unwrap()]
                ));
            }
        }
        let f = CT::Func { ret: Box::new(ret_ct.clone()), params: params_c, va };
        let decl = CT::ptr(f).decl("");
        let cpp = format!(
            "{} {}({}){}",
            ret_cpp,
            p.name,
            db.t.args(args).iter().map(|&a| if a == 0 { "...".to_string() } else { db.cpp(a) }).collect::<Vec<_>>().join(", "),
            if this_const { " const" } else { "" }
        );
        Some(FuncDecl {
            name: p.name.clone(),
            rva: p.rva,
            ty: p.ty,
            decl,
            deps: d,
            cpp,
            kind,
            class,
            this_c,
            this_adjust,
            this_const,
            ret: ret_kind,
            ret_cpp,
            cxx_return_udt: fattr.cxx_return_udt(),
            params,
            va,
            virt,
            rewrites,
        })
    }
}
