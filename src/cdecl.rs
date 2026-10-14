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

/// How a class of 1, 2, 4 or 8 bytes is passed by value (the worst of its parts wins)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Passing {
    Register,
    Unknown,
    Address,
}

const ARG_REGS: [iced_x86::Register; 4] = [iced_x86::Register::RCX, iced_x86::Register::RDX, iced_x86::Register::R8, iced_x86::Register::R9];

/// Does the function at `rva` use its argument register `reg` as an address (Some(true)) or as a
/// value (Some(false))? Follows copies of the register, stops at its first telling use.
pub fn first_use(pe: &crate::pe::Pe, rva: u32, len: u32, reg: iced_x86::Register) -> Option<bool> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
    let s = rva as usize;
    let e = (rva as usize + (len.max(16) as usize).min(256)).min(pe.image.len());
    if s >= e {
        return None;
    }
    let mut d = Decoder::with_ip(64, &pe.image[s..e], rva as u64, DecoderOptions::NONE);
    let mut aliases: Vec<Register> = vec![reg];
    let mut fac = InstructionInfoFactory::new();
    let mut i = Instruction::default();
    for _ in 0..64 {
        if !d.can_decode() {
            break;
        }
        d.decode_out(&mut i);
        if i.is_invalid() {
            return None;
        }
        let full = |r: Register| r.full_register();
        let is_alias = |r: Register| r != Register::None && aliases.contains(&full(r));
        // a memory operand built on it: an address
        let mem = (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::Memory);
        if mem && i.mnemonic() != Mnemonic::Lea && (is_alias(i.memory_base()) || is_alias(i.memory_index())) {
            return Some(true);
        }
        if i.mnemonic() == Mnemonic::Lea && (is_alias(i.memory_base()) || is_alias(i.memory_index())) {
            if i.op0_register().size() == 8 && i.memory_index() == Register::None {
                aliases.push(full(i.op0_register())); // pointer arithmetic, follow it
                continue;
            }
            return Some(false); // arithmetic on a value (lea eax, [rcx+rcx*4])
        }
        match i.flow_control() {
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => return None,
            FlowControl::Call | FlowControl::IndirectCall => {
                // the call reads it: no telling; volatile registers die
                aliases.retain(|r| !matches!(r, Register::RAX | Register::RCX | Register::RDX | Register::R8 | Register::R9 | Register::R10 | Register::R11));
                if aliases.is_empty() {
                    return None;
                }
                continue;
            }
            _ => {}
        }
        // copies: mov r64, alias
        if i.mnemonic() == Mnemonic::Mov && i.op_count() == 2 && i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register && is_alias(i.op1_register()) {
            if i.op1_register().size() == 8 {
                aliases.push(full(i.op0_register()));
                continue;
            }
            return Some(false); // a 32-bit or smaller copy: a value
        }
        // stores of it: 8 bytes could be either (a spill), smaller is a value
        if i.mnemonic() == Mnemonic::Mov && i.op0_kind() == OpKind::Memory && i.op1_kind() == OpKind::Register && is_alias(i.op1_register()) {
            if i.op1_register().size() < 8 {
                return Some(false);
            }
            continue;
        }
        let info = fac.info(&i);
        let mut read = false;
        let mut written = Vec::new();
        for u in info.used_registers() {
            if !is_alias(u.register()) {
                continue;
            }
            match u.access() {
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => read = true,
                OpAccess::Write | OpAccess::CondWrite => written.push(full(u.register())),
                _ => {}
            }
        }
        if read {
            // a null test says nothing; anything else that reads it uses the value
            if matches!(i.mnemonic(), Mnemonic::Test | Mnemonic::Cmp) && i.op0_register().size() == 8 {
                continue;
            }
            return Some(false);
        }
        aliases.retain(|r| !written.contains(r));
        if aliases.is_empty() {
            return None;
        }
    }
    None
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
    triv_copy: std::cell::RefCell<HashMap<u32, Passing>>,
    /// classes whose passing the PDB cannot tell (a move constructor, no copy constructor listed):
    /// (by-address votes, in-register votes) from the code of the functions that take them by value
    pub evidence: HashMap<u32, (usize, usize)>,
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
        Funcs { db, methods, dtors, triv_copy: Default::default(), evidence: HashMap::new(), pod: Default::default() }
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

    /// Copy and move constructors the class declares (`C(C&)`, `C(const C&)`; `C(C&&)`).
    /// Compiler-generated ones are judged through the members and bases. A defaulted copy
    /// constructor is not listed at all, a defaulted move constructor is (docs/ffi.md).
    fn copy_move_ctors(&self, d: u32) -> (usize, usize) {
        let (mut copy, mut moves) = (0, 0);
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
                    if fattr.ctor() && a.len() == 1 && self.is_ref_to(a[0], d) {
                        if self.is_lref_to(a[0], d) {
                            copy += 1;
                        } else {
                            moves += 1;
                        }
                    }
                }
            }
        }
        (copy, moves)
    }

    /// How MSVC x64 passes a class of 1, 2, 4 or 8 bytes by value, by the PDB: in a register when
    /// it has a trivial copy constructor (no virtual functions or bases, no declared copy
    /// constructor, members and bases alike; a destructor does not matter), by address otherwise.
    /// A declared move constructor without a listed copy constructor is `Unknown`: the copy
    /// constructor is either deleted (by address) or defaulted (in a register), which the PDB does
    /// not tell apart; the code of the functions that take the class decides (`learn`).
    pub fn passing(&self, d: u32) -> Passing {
        if let Some(&v) = self.triv_copy.borrow().get(&d) {
            return v;
        }
        self.triv_copy.borrow_mut().insert(d, Passing::Register); // cycles
        let v = match self.db.kind_of(d) {
            Some(Kind::Enum) | None => Passing::Register,
            Some(_) => {
                let (copy, moves) = self.copy_move_ctors(d);
                let mut v = if self.has_vfptr_or_vbase(d) || copy > 0 {
                    Passing::Address
                } else if moves > 0 {
                    Passing::Unknown
                } else {
                    Passing::Register
                };
                for f in self.class_fields(d) {
                    let w = match f {
                        Field::Base { ty, .. } => self.db.def_of(*ty).map_or(Passing::Register, |b| self.passing(b)),
                        Field::Member { ty, .. } => self.member_passing(*ty),
                        _ => Passing::Register,
                    };
                    v = v.max(w);
                }
                v
            }
        };
        self.triv_copy.borrow_mut().insert(d, v);
        v
    }

    fn member_passing(&self, ti: u32) -> Passing {
        let (t, _) = self.db.strip(ti);
        match self.db.t.get(t) {
            Some(Rec::Array { elem, .. }) => self.member_passing(*elem),
            Some(Rec::Class { .. }) | Some(Rec::Union { .. }) => self.db.def_of(t).map_or(Passing::Register, |d| self.passing(d)),
            _ => Passing::Register,
        }
    }

    /// In a register? `Unknown` classes go by the code's evidence, by address without it.
    pub fn trivially_copyable(&self, d: u32) -> bool {
        match self.passing(d) {
            Passing::Register => true,
            Passing::Address => false,
            Passing::Unknown => self.evidence.get(&d).map_or(false, |&(addr, reg)| reg > addr),
        }
    }

    /// Votes from the code (`exe`: the build's PE image) for the classes whose passing the PDB
    /// cannot tell: each function that takes one by value in an argument register either
    /// dereferences that register (by address) or uses its value (in a register).
    pub fn learn(&mut self, procs: &[Proc], pe: &crate::pe::Pe) {
        let mut ev: HashMap<u32, (usize, usize)> = HashMap::new();
        for p in procs {
            let Some(rec) = self.db.t.get(p.ty) else { continue };
            let (ret, args, fattr, instance) = match rec {
                Rec::Procedure { ret, args, fattr, .. } => (*ret, *args, *fattr, false),
                Rec::MFunction { ret, args, fattr, this_ty, .. } => (*ret, *args, *fattr, *this_ty != 0),
                _ => continue,
            };
            let mut pos = instance as usize;
            let (rt, _) = self.db.strip(ret);
            if let Some(Rec::Class { .. } | Rec::Union { .. }) = self.db.t.get(rt) {
                let size = self.db.size_of(rt).unwrap_or(0);
                if instance || fattr.cxx_return_udt() || !matches!(size, 1 | 2 | 4 | 8) {
                    pos += 1;
                }
            }
            for &a in self.db.t.args(args) {
                if pos >= 4 {
                    break;
                }
                let (t, _) = self.db.strip(a);
                if let Some(Rec::Class { .. } | Rec::Union { .. }) = self.db.t.get(t) {
                    if let Some(d) = self.db.def_of(t) {
                        let size = self.db.size_of(d).unwrap_or(0);
                        if matches!(size, 1 | 2 | 4 | 8) && self.passing(d) == Passing::Unknown {
                            if let Some(by_address) = first_use(pe, p.rva, p.len, ARG_REGS[pos]) {
                                let e = ev.entry(d).or_default();
                                if by_address {
                                    e.0 += 1;
                                } else {
                                    e.1 += 1;
                                }
                            }
                        }
                    }
                }
                pos += 1;
            }
        }
        self.evidence = ev;
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
                if small && self.passing(def) == Passing::Unknown {
                    let (a, r) = self.evidence.get(&def).copied().unwrap_or((0, 0));
                    rewrites.push(format!(
                        "parameter {} {}: a move constructor and no listed copy constructor, so the PDB does not tell how it is passed; {} (the code of the functions taking it: {} by address, {} in a register)",
                        i + 1,
                        cpp,
                        if direct { "in a register" } else { "by address" },
                        a,
                        r
                    ));
                    if a + r == 0 {
                        why = "unknown";
                    }
                }
            }
            params.push(Param { cpp, c: c.decl(""), pass, cat, why });
            params_c.push(c);
        }
        if va {
            rewrites.push("variadic: pass integers as cdata (ffi.new('int32_t', v)): a Lua number goes as a double; LuaJIT mirrors vararg registers in both register sets, as MSVC expects".into());
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

#[cfg(test)]
mod tests {
    use super::split_scope;

    #[test]
    fn scopes() {
        assert_eq!(split_scope("CShip::CalcRegenAmount"), Some(("CShip", "CalcRegenAmount")));
        assert_eq!(split_scope("A<B::C>::f"), Some(("A<B::C>", "f")));
        assert_eq!(split_scope("CFixedPoint::operator<"), Some(("CFixedPoint", "operator<")));
        assert_eq!(split_scope("CFoo::operator()"), Some(("CFoo", "operator()")));
        assert_eq!(split_scope("Cooperator::Run"), Some(("Cooperator", "Run")));
        assert_eq!(split_scope("free_function"), None);
    }
}
