//! C declarations for the LuaJIT FFI from a PDB's type records: every class, struct, union and
//! enum gets a C name and, on demand, a definition with each data member at its PDB offset.
//!
//! The rules (docs/ffi.md has the reasons):
//! - only fixed-width types (`int32_t` for `int` and `long`, `uint16_t` for `wchar_t`, `double`
//!   for `long double`); references are pointers; function pointers are `void*`;
//! - base classes are flattened: their data members are emitted at their offsets in the derived
//!   class (a name used twice is qualified with the base's C name), and the base subobjects are
//!   listed in the metadata (`bases`) for casts;
//! - vtable pointers are `void** __vfptr` (or `__vfptr_<offset>` inside a base at that offset),
//!   virtual base pointers `void* __vbptr...`; the members of virtual bases are not emitted (their
//!   place is only known at run time);
//! - explicit padding between members and at the end; members that overlap (anonymous unions,
//!   unions with flattened anonymous structs) go into an anonymous union of "lanes", each lane a
//!   run of members that do not overlap;
//! - bitfields: one anonymous struct per MSVC storage unit (the members at one offset), declared
//!   with the unit's type, the fields at their bit positions (unnamed fields fill gaps): within one
//!   unit MSVC and the GCC rules LuaJIT follows place bits alike; validated with `ffi.offsetof`;
//! - when a member would not be at its natural alignment (`#pragma pack`), the struct and its
//!   anonymous parts are declared `__attribute__((packed))`;
//! - enums are `typedef <fixed-width int> E;`, their values go into the metadata, not into C
//!   (enumerators of different enums would collide in the C namespace).

use crate::tpi::{pm, ClassKind, Field, Rec, Tpi};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

/// A C type, rendered with a declarator by `decl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CT {
    Base { name: String, konst: bool },
    Ptr { to: Box<CT>, konst: bool },
    Arr { of: Box<CT>, n: u64 },
    Func { ret: Box<CT>, params: Vec<CT>, va: bool },
}

impl CT {
    pub fn base(name: &str) -> CT {
        CT::Base { name: name.to_string(), konst: false }
    }
    pub fn ptr(to: CT) -> CT {
        CT::Ptr { to: Box::new(to), konst: false }
    }
    pub fn void_ptr() -> CT {
        CT::ptr(CT::base("void"))
    }
    pub fn with_const(self, c: bool) -> CT {
        match self {
            CT::Base { name, konst } => CT::Base { name, konst: konst || c },
            CT::Ptr { to, konst } => CT::Ptr { to, konst: konst || c },
            x => x,
        }
    }
    /// without top-level const
    pub fn unconst(self) -> CT {
        match self {
            CT::Base { name, .. } => CT::Base { name, konst: false },
            CT::Ptr { to, .. } => CT::Ptr { to, konst: false },
            x => x,
        }
    }
    /// The declaration of `inner` (a name, or empty for an abstract declarator) with this type.
    pub fn decl(&self, inner: &str) -> String {
        match self {
            CT::Base { name, konst } => {
                let c = if *konst { "const " } else { "" };
                if inner.is_empty() {
                    format!("{}{}", c, name)
                } else {
                    format!("{}{} {}", c, name, inner)
                }
            }
            CT::Ptr { to, konst } => {
                let mut s = String::from("*");
                if *konst {
                    s.push_str("const");
                    if !inner.is_empty() {
                        s.push(' ');
                    }
                }
                s.push_str(inner);
                match **to {
                    CT::Arr { .. } | CT::Func { .. } => to.decl(&format!("({})", s)),
                    _ => to.decl(&s),
                }
            }
            CT::Arr { of, n } => of.decl(&format!("{}[{}]", inner, n)),
            CT::Func { ret, params, va } => {
                let mut ps: Vec<String> = params.iter().map(|p| p.decl("")).collect();
                if *va {
                    ps.push("...".into());
                }
                if ps.is_empty() {
                    ps.push("void".into());
                }
                ret.decl(&format!("{}({})", inner, ps.join(", ")))
            }
        }
    }
}

/// Kinds of named types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Struct,
    Union,
    Enum,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Struct => "struct",
            Kind::Union => "union",
            Kind::Enum => "enum",
        }
    }
}

/// A data member in the metadata (validation and introspection): every named C field, at its
/// absolute offset, with its PDB type and the bitfield position if any.
#[derive(Debug, Clone)]
pub struct FieldOut {
    pub name: String,
    pub cpp_name: String,
    pub offset: u64,
    pub size: u64,
    pub cpp: String,
    pub bits: Option<(u8, u8)>,
    /// for bitfields LuaJIT cannot declare (64-bit units with a field across bit 32): the integer
    /// member that holds the unit (read with fnmatch.ffi bit accessors)
    pub unit: Option<String>,
    /// the base class path the member comes from ("" for the class's own members)
    pub from: String,
}

#[derive(Debug, Clone)]
pub struct Layout {
    pub ti: u32,
    pub cname: String,
    pub cpp: String,
    pub kind: Kind,
    pub size: u64,
    pub align: u64,
    pub packed: bool,
    /// `struct X {...};` (or the typedef of an enum)
    pub cdef: String,
    /// named types needed complete before this one, and named types referenced through pointers
    pub deps: BTreeSet<u32>,
    pub refs: BTreeSet<u32>,
    pub fields: Vec<FieldOut>,
    /// non-virtual base subobjects: (definition, absolute offset, path)
    pub bases: Vec<(u32, u64, String)>,
    pub vfptrs: Vec<u64>,
    pub vbptrs: Vec<u64>,
    pub virtual_bases: bool,
    pub enum_values: Vec<(String, i128)>,
    pub notes: Vec<String>,
    /// the number of ctypes LuaJIT creates for the definition (fields, anonymous parts, arrays)
    pub ctypes: usize,
}

#[derive(Default, Debug, Clone)]
pub struct Deps {
    pub full: BTreeSet<u32>,
    pub opaque: BTreeSet<u32>,
}

/// C keywords and the names LuaJIT predefines, which a generated name must not take.
const RESERVED: &[&str] = &[
    "void", "_Bool", "bool", "char", "int", "__int8", "__int16", "__int32", "__int64", "float", "double", "long", "short", "_Complex", "complex", "__complex",
    "__complex__", "signed", "__signed", "__signed__", "unsigned", "const", "__const", "__const__", "volatile", "__volatile", "__volatile__", "restrict",
    "__restrict", "__restrict__", "inline", "__inline", "__inline__", "typedef", "extern", "static", "auto", "register", "__extension__", "__attribute",
    "__attribute__", "asm", "__asm", "__asm__", "__declspec", "__cdecl", "__thiscall", "__fastcall", "__stdcall", "__ptr32", "__ptr64", "struct", "union",
    "enum", "sizeof", "__alignof", "__alignof__", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "intptr_t",
    "uintptr_t", "ptrdiff_t", "size_t", "wchar_t", "va_list", "__builtin_va_list", "__gnuc_va_list", "ssize_t", "switch", "case", "default", "if", "else",
    "while", "do", "for", "goto", "continue", "break", "return", "typeof", "__typeof", "__typeof__",
];

pub fn sanitize(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b':' && b.get(i + 1) == Some(&b':') {
            out.push_str("__");
            i += 2;
            continue;
        }
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' => out.push(c as char),
            b'*' => out.push('P'),
            b'&' => out.push('R'),
            b' ' | b'`' | b'\'' => {}
            _ => out.push('_'),
        }
        i += 1;
    }
    if out.is_empty() {
        out.push_str("_anon");
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    if RESERVED.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

fn hash_hex(s: &str, n: usize) -> String {
    let h = xxhash_rust::xxh3::xxh3_64(s.as_bytes());
    format!("{:016x}", h)[..n].to_string()
}

/// Fixed-width C type of a primitive type index: (type, size, align, category for checks)
pub fn prim(ti: u32) -> (CT, u64, u64, &'static str) {
    let mode = (ti >> 8) & 0xf;
    let kind = ti & 0xff;
    if mode != 0 {
        let (inner, ..) = prim(kind);
        return (CT::ptr(inner), 8, 8, "p");
    }
    let (n, s, cat): (&str, u64, &'static str) = match kind {
        0x00 | 0x03 => ("void", 0, "void"),
        0x08 => ("int32_t", 4, "i32"),
        0x10 | 0x68 => ("int8_t", 1, "i8"),
        0x20 | 0x69 | 0x7c => ("uint8_t", 1, "u8"),
        0x70 => ("char", 1, "char"),
        0x71 | 0x7a => ("uint16_t", 2, "wchar"),
        0x7b => ("uint32_t", 4, "u32"),
        0x11 | 0x72 => ("int16_t", 2, "i16"),
        0x21 | 0x73 => ("uint16_t", 2, "u16"),
        0x12 | 0x74 => ("int32_t", 4, "i32"),
        0x22 | 0x75 => ("uint32_t", 4, "u32"),
        0x13 | 0x76 => ("int64_t", 8, "i64"),
        0x23 | 0x77 => ("uint64_t", 8, "u64"),
        0x30 => ("bool", 1, "bool"),
        0x31 => ("uint16_t", 2, "u16"),
        0x32 => ("uint32_t", 4, "u32"),
        0x33 => ("uint64_t", 8, "u64"),
        0x40 => ("float", 4, "f32"),
        0x41 | 0x42 => ("double", 8, "f64"),
        0x46 => ("uint16_t", 2, "f16"),
        0x14 | 0x24 | 0x78 | 0x79 | 0x43 => {
            return (CT::Arr { of: Box::new(CT::base("uint64_t")), n: 2 }, 16, 8, "i128");
        }
        _ => ("uint8_t", 1, "?"),
    };
    (CT::base(n), s, s.clamp(1, 8), cat)
}

pub struct Db<'a> {
    pub t: &'a Tpi,
    /// class/union/enum record (forward reference or not) -> its definition
    def: HashMap<u32, u32>,
    /// definitions in index order
    pub udts: Vec<u32>,
    pub cname: HashMap<u32, String>,
    pub by_cname: HashMap<String, u32>,
    pub by_cpp: HashMap<String, Vec<u32>>,
    /// definitions that share a unique name with an earlier one of another size
    pub conflicts: usize,
    layouts: RefCell<HashMap<u32, Rc<Layout>>>,
    in_progress: RefCell<HashSet<u32>>,
}

fn family(r: &Rec) -> Option<(char, &str, Option<&str>, bool)> {
    match r {
        Rec::Class { name, unique, props, .. } => Some(('c', name, unique.as_deref(), props.fwdref())),
        Rec::Union { name, unique, props, .. } => Some(('u', name, unique.as_deref(), props.fwdref())),
        Rec::Enum { name, unique, props, .. } => Some(('e', name, unique.as_deref(), props.fwdref())),
        _ => None,
    }
}

impl<'a> Db<'a> {
    pub fn new(t: &'a Tpi) -> Db<'a> {
        let mut by_unique: HashMap<(char, String), u32> = HashMap::new();
        let mut by_name: HashMap<(char, String), u32> = HashMap::new();
        let mut udts = Vec::new();
        let mut conflicts = 0;
        for (i, r) in t.recs.iter().enumerate() {
            let ti = t.begin + i as u32;
            let Some((fam, name, unique, fwd)) = family(r) else { continue };
            if fwd {
                continue;
            }
            let key = (fam, unique.unwrap_or(name).to_string());
            if let Some(&first) = by_unique.get(&key) {
                if size_rec(t.get(first).unwrap()) != size_rec(r) {
                    conflicts += 1;
                }
                continue;
            }
            by_unique.insert(key, ti);
            by_name.entry((fam, name.to_string())).or_insert(ti);
            udts.push(ti);
        }
        let mut def = HashMap::new();
        for (i, r) in t.recs.iter().enumerate() {
            let ti = t.begin + i as u32;
            let Some((fam, name, unique, _)) = family(r) else { continue };
            let d = unique.and_then(|u| by_unique.get(&(fam, u.to_string()))).or_else(|| by_name.get(&(fam, name.to_string())));
            if let Some(&d) = d {
                def.insert(ti, d);
            }
        }
        // C names, in index order: the first type to want a name gets it
        let mut cname = HashMap::new();
        let mut by_cname: HashMap<String, u32> = HashMap::new();
        let mut by_cpp: HashMap<String, Vec<u32>> = HashMap::new();
        for &ti in &udts {
            let (_, name, unique, _) = family(t.get(ti).unwrap()).unwrap();
            let mut c = sanitize(name);
            if c.len() > 100 {
                c = format!("{}_{}", &c[..80], hash_hex(name, 12));
            }
            if by_cname.contains_key(&c) {
                c = format!("{}_{}", c, hash_hex(unique.unwrap_or(name), 8));
                let mut k = 2;
                while by_cname.contains_key(&c) {
                    c = format!("{}_{}", c, k);
                    k += 1;
                }
            }
            by_cname.insert(c.clone(), ti);
            cname.insert(ti, c);
            by_cpp.entry(name.to_string()).or_default().push(ti);
        }
        Db { t, def, udts, cname, by_cname, by_cpp, conflicts, layouts: RefCell::new(HashMap::new()), in_progress: RefCell::new(HashSet::new()) }
    }

    /// The definition of a class/union/enum record.
    pub fn def_of(&self, ti: u32) -> Option<u32> {
        self.def.get(&ti).copied()
    }

    /// Follow modifiers.
    pub fn strip(&self, mut ti: u32) -> (u32, bool) {
        let mut konst = false;
        for _ in 0..16 {
            match self.t.get(ti) {
                Some(Rec::Modifier { ty, konst: k, .. }) => {
                    konst |= *k;
                    ti = *ty;
                }
                _ => break,
            }
        }
        (ti, konst)
    }

    pub fn cpp_name_of_def(&self, d: u32) -> &str {
        match self.t.get(d) {
            Some(Rec::Class { name, .. }) | Some(Rec::Union { name, .. }) | Some(Rec::Enum { name, .. }) => name,
            _ => "?",
        }
    }

    pub fn kind_of(&self, d: u32) -> Option<Kind> {
        match self.t.get(d) {
            Some(Rec::Class { .. }) => Some(Kind::Struct),
            Some(Rec::Union { .. }) => Some(Kind::Union),
            Some(Rec::Enum { .. }) => Some(Kind::Enum),
            _ => None,
        }
    }

    /// MSVC size of a type, None when unknown (a class without definition, a function type).
    pub fn size_of(&self, ti: u32) -> Option<u64> {
        if ti < crate::tpi::TI_FIRST {
            let s = prim(ti).1;
            return if ti & 0xff == 0 && ti >> 8 == 0 { None } else { Some(s) };
        }
        match self.t.get(ti)? {
            Rec::Modifier { ty, .. } => self.size_of(*ty),
            Rec::Pointer { attr, .. } => Some(match Rec::ptr_size(*attr) {
                0 => 8,
                s => s as u64,
            }),
            Rec::Array { size, .. } => Some(*size),
            Rec::Class { .. } | Rec::Union { .. } | Rec::Enum { .. } => {
                let d = self.def_of(ti)?;
                match self.t.get(d)? {
                    Rec::Class { size, .. } | Rec::Union { size, .. } => Some(*size),
                    Rec::Enum { utype, .. } => self.size_of(*utype),
                    _ => None,
                }
            }
            Rec::Bitfield { ty, .. } => self.size_of(*ty),
            _ => None,
        }
    }

    /// C++ spelling of a type (for the metadata and the checks).
    pub fn cpp(&self, ti: u32) -> String {
        self.cpp_depth(ti, 0)
    }

    fn cpp_depth(&self, ti: u32, depth: usize) -> String {
        if depth > 12 {
            return "...".into();
        }
        if ti < crate::tpi::TI_FIRST {
            let mode = (ti >> 8) & 0xf;
            let base = match ti & 0xff {
                0x00 => "<no type>",
                0x03 => "void",
                0x08 => "HRESULT",
                0x10 => "signed char",
                0x20 => "unsigned char",
                0x68 => "__int8",
                0x69 => "unsigned __int8",
                0x70 => "char",
                0x71 => "wchar_t",
                0x7a => "char16_t",
                0x7b => "char32_t",
                0x7c => "char8_t",
                0x11 => "short",
                0x21 => "unsigned short",
                0x72 => "__int16",
                0x73 => "unsigned __int16",
                0x12 => "long",
                0x22 => "unsigned long",
                0x74 => "int",
                0x75 => "unsigned int",
                0x13 => "__int64",
                0x23 => "unsigned __int64",
                0x76 => "__int64",
                0x77 => "unsigned __int64",
                0x30 => "bool",
                0x40 => "float",
                0x41 => "double",
                0x42 => "long double",
                _ => "<prim>",
            };
            return if mode != 0 { format!("{}*", base) } else { base.to_string() };
        }
        match self.t.get(ti) {
            Some(Rec::Modifier { ty, konst, volatile, .. }) => {
                let inner = self.cpp_depth(*ty, depth + 1);
                let mut s = inner;
                if *konst {
                    s.push_str(" const");
                }
                if *volatile {
                    s.push_str(" volatile");
                }
                s
            }
            Some(Rec::Pointer { referent, attr, containing, .. }) => {
                let inner = self.cpp_depth(*referent, depth + 1);
                let k = if Rec::ptr_const(*attr) { " const" } else { "" };
                match Rec::ptr_mode(*attr) {
                    pm::LREF => format!("{}&{}", inner, k),
                    pm::RREF => format!("{}&&{}", inner, k),
                    pm::PMEM | pm::PMFUNC => format!("{} {}::*{}", inner, self.cpp_depth(*containing, depth + 1), k),
                    _ => format!("{}*{}", inner, k),
                }
            }
            Some(Rec::Array { elem, size, .. }) => {
                let es = self.size_of(*elem).unwrap_or(0);
                let n = if es > 0 { size / es } else { 0 };
                format!("{}[{}]", self.cpp_depth(*elem, depth + 1), n)
            }
            Some(Rec::Class { name, .. }) | Some(Rec::Union { name, .. }) | Some(Rec::Enum { name, .. }) => name.clone(),
            Some(Rec::Procedure { ret, args, .. }) => {
                let ps: Vec<String> = self.t.args(*args).iter().map(|&a| if a == 0 { "...".into() } else { self.cpp_depth(a, depth + 1) }).collect();
                format!("{} ({})", self.cpp_depth(*ret, depth + 1), ps.join(","))
            }
            Some(Rec::MFunction { ret, class, args, .. }) => {
                let ps: Vec<String> = self.t.args(*args).iter().map(|&a| if a == 0 { "...".into() } else { self.cpp_depth(a, depth + 1) }).collect();
                format!("{} ({}::)({})", self.cpp_depth(*ret, depth + 1), self.cpp_depth(*class, depth + 1), ps.join(","))
            }
            Some(Rec::Bitfield { ty, len, .. }) => format!("{} : {}", self.cpp_depth(*ty, depth + 1), len),
            _ => format!("<type {:#x}>", ti),
        }
    }

    /// The C type of a type index. `under_ptr`: reached through a pointer (named types then only
    /// need a declaration). Returns the type and its LuaJIT alignment.
    pub fn ctype(&self, ti: u32, under_ptr: bool, d: &mut Deps) -> (CT, u64) {
        if ti < crate::tpi::TI_FIRST {
            let (c, _, a, _) = prim(ti);
            return (c, a);
        }
        match self.t.get(ti) {
            Some(Rec::Modifier { ty, konst, .. }) => {
                let (c, a) = self.ctype(*ty, under_ptr, d);
                (c.with_const(*konst), a)
            }
            Some(Rec::Pointer { referent, attr, .. }) => {
                let size = match Rec::ptr_size(*attr) {
                    0 => 8,
                    s => s as u64,
                };
                match Rec::ptr_mode(*attr) {
                    pm::PMEM => {
                        // pointers to data members: one int32 per word
                        if size == 4 {
                            (CT::base("int32_t"), 4)
                        } else {
                            (CT::Arr { of: Box::new(CT::base("int32_t")), n: size / 4 }, 4)
                        }
                    }
                    pm::PMFUNC => {
                        if size == 8 {
                            (CT::void_ptr(), 8)
                        } else {
                            (CT::Arr { of: Box::new(CT::base("uint64_t")), n: (size + 7) / 8 }, 8)
                        }
                    }
                    _ => {
                        let (r, _) = self.strip(*referent);
                        // function pointers are kept as void*: their types would pull in more types
                        if matches!(self.t.get(r), Some(Rec::Procedure { .. } | Rec::MFunction { .. })) {
                            return (CT::void_ptr().with_const(Rec::ptr_const(*attr)), 8);
                        }
                        let (c, _) = self.ctype(*referent, true, d);
                        (CT::Ptr { to: Box::new(c), konst: Rec::ptr_const(*attr) }, 8)
                    }
                }
            }
            Some(Rec::Array { elem, size, .. }) => {
                // an array needs its element type complete, even behind a pointer
                let (c, a) = self.ctype(*elem, false, d);
                let es = self.size_of(*elem).unwrap_or(0);
                if es == 0 {
                    return (CT::Arr { of: Box::new(CT::base("uint8_t")), n: *size }, 1);
                }
                (CT::Arr { of: Box::new(c), n: size / es }, a)
            }
            Some(Rec::Class { .. }) | Some(Rec::Union { .. }) | Some(Rec::Enum { .. }) => {
                let Some(def) = self.def_of(ti) else {
                    // declared but never defined: only usable through a pointer
                    return (CT::base("void"), 1);
                };
                let name = self.cname[&def].clone();
                let kind = self.kind_of(def).unwrap();
                if kind == Kind::Enum {
                    d.full.insert(def);
                    let a = self.size_of(def).unwrap_or(4).clamp(1, 8);
                    return (CT::base(&name), a);
                }
                if under_ptr {
                    d.opaque.insert(def);
                    (CT::base(&name), 1)
                } else {
                    d.full.insert(def);
                    let a = self.layout(def).map_or(1, |l| l.align);
                    (CT::base(&name), a)
                }
            }
            Some(Rec::Bitfield { ty, .. }) => self.ctype(*ty, under_ptr, d),
            Some(Rec::Procedure { .. }) | Some(Rec::MFunction { .. }) => (CT::base("void"), 1),
            _ => (CT::base("uint8_t"), 1),
        }
    }

    /// The layout of a definition (memoized).
    pub fn layout(&self, def: u32) -> Option<Rc<Layout>> {
        if let Some(l) = self.layouts.borrow().get(&def) {
            return Some(l.clone());
        }
        if !self.in_progress.borrow_mut().insert(def) {
            return None; // a type that contains itself by value: impossible in valid C++
        }
        let built = self.build(def);
        self.in_progress.borrow_mut().remove(&def);
        let l = Rc::new(built?);
        self.layouts.borrow_mut().insert(def, l.clone());
        Some(l)
    }

    fn build(&self, def: u32) -> Option<Layout> {
        let r = self.t.get(def)?;
        let cname = self.cname.get(&def)?.clone();
        match r {
            Rec::Enum { utype, fields, name, .. } => {
                let (c, _, a, _) = prim(*utype);
                let mut values = Vec::new();
                for f in self.t.fields(*fields) {
                    if let Field::Enumerate { value, name, .. } = f {
                        values.push((name.clone(), *value));
                    }
                }
                let size = self.size_of(*utype).unwrap_or(4);
                Some(Layout {
                    ti: def,
                    cdef: format!("typedef {};", c.decl(&cname)),
                    cname,
                    cpp: name.clone(),
                    kind: Kind::Enum,
                    size,
                    align: a,
                    packed: false,
                    deps: BTreeSet::new(),
                    refs: BTreeSet::new(),
                    fields: Vec::new(),
                    bases: Vec::new(),
                    vfptrs: Vec::new(),
                    vbptrs: Vec::new(),
                    virtual_bases: false,
                    enum_values: values,
                    notes: Vec::new(),
                    ctypes: 1,
                })
            }
            Rec::Class { size, name, .. } | Rec::Union { size, name, .. } => {
                let is_union = matches!(r, Rec::Union { .. });
                let mut c = Collect::default();
                self.collect(def, 0, "", 0, &mut c);
                let mut l = Layout {
                    ti: def,
                    cname: cname.clone(),
                    cpp: name.clone(),
                    kind: if is_union { Kind::Union } else { Kind::Struct },
                    size: *size,
                    align: 1,
                    packed: false,
                    cdef: String::new(),
                    deps: c.deps.full.clone(),
                    refs: c.deps.opaque.clone(),
                    fields: Vec::new(),
                    bases: c.bases.clone(),
                    vfptrs: c.vfptrs.clone(),
                    vbptrs: c.vbptrs.clone(),
                    virtual_bases: c.virtual_bases,
                    enum_values: Vec::new(),
                    notes: c.notes.clone(),
                    ctypes: 1,
                };
                l.refs.retain(|x| !l.deps.contains(x));
                self.emit(&mut l, c.items, is_union);
                Some(l)
            }
            _ => None,
        }
    }

    /// Items of a class at `base` (its members, and those of its non-virtual bases).
    fn collect(&self, def: u32, base: u64, path: &str, depth: usize, c: &mut Collect) {
        let Some(r) = self.t.get(def) else { return };
        let fl = match r {
            Rec::Class { fields, .. } | Rec::Union { fields, .. } => *fields,
            _ => return,
        };
        if depth > 32 {
            return;
        }
        for f in self.t.fields(fl) {
            match f {
                Field::Base { ty, offset, .. } => {
                    let Some(bd) = self.def_of(*ty) else {
                        c.notes.push(format!("base {:#x} has no definition", ty));
                        continue;
                    };
                    let bname = &self.cname[&bd];
                    let p = if path.is_empty() { bname.clone() } else { format!("{}.{}", path, bname) };
                    c.bases.push((bd, base + offset, p.clone()));
                    self.collect(bd, base + offset, &p, depth + 1, c);
                }
                Field::VBase { direct, vbptr_off, .. } => {
                    c.virtual_bases = true;
                    if *direct && !c.vbptrs.contains(&(base + vbptr_off)) {
                        c.vbptrs.push(base + vbptr_off);
                        let off = base + vbptr_off;
                        let n = if off == 0 { "__vbptr".to_string() } else { format!("__vbptr_{:x}", off) };
                        c.items.push(Item { off, size: 8, align: 8, depth, kind: IK::Member { name: n.clone(), cpp_name: n, ct: CT::void_ptr(), cpp: "vbptr".into(), from: path.to_string() } });
                    }
                }
                Field::VFuncTab { .. } => {
                    if !c.vfptrs.contains(&base) {
                        c.vfptrs.push(base);
                        let n = if base == 0 { "__vfptr".to_string() } else { format!("__vfptr_{:x}", base) };
                        c.items.push(Item {
                            off: base,
                            size: 8,
                            align: 8,
                            depth,
                            kind: IK::Member { name: n.clone(), cpp_name: n, ct: CT::ptr(CT::void_ptr()), cpp: "vfptr".into(), from: path.to_string() },
                        });
                    }
                }
                Field::Member { ty, offset, name, .. } => {
                    let off = base + offset;
                    if let Some(Rec::Bitfield { ty: bt, len, pos }) = self.t.get(*ty) {
                        let (bt, _) = self.strip(*bt);
                        let us = self.size_of(bt).unwrap_or(4).max(1);
                        let unit = match self.t.get(bt) {
                            // enum-typed bitfields use the enum's integer type
                            Some(Rec::Enum { .. }) => self.def_of(bt).and_then(|d| match self.t.get(d) {
                                Some(Rec::Enum { utype, .. }) => Some(prim(*utype).0),
                                _ => None,
                            }),
                            _ if bt < crate::tpi::TI_FIRST => Some(prim(bt).0),
                            _ => None,
                        }
                        .unwrap_or_else(|| CT::base("uint32_t"));
                        let key = (off, us);
                        let k = match c.units.get(&key) {
                            Some(&k) => k,
                            None => {
                                c.items.push(Item { off, size: us, align: us.clamp(1, 8), depth, kind: IK::Bits { unit: unit.clone(), fields: Vec::new() } });
                                c.units.insert(key, c.items.len() - 1);
                                c.items.len() - 1
                            }
                        };
                        if let IK::Bits { fields, .. } = &mut c.items[k].kind {
                            fields.push(BitF { name: name.clone(), cpp_name: name.clone(), pos: *pos, len: *len, ct: unit, cpp: self.cpp(*ty), from: path.to_string() });
                        }
                        continue;
                    }
                    let size = self.size_of(*ty);
                    let (ct, align) = self.ctype(*ty, false, &mut c.deps);
                    let ct = ct.unconst();
                    let cpp = self.cpp(*ty);
                    let size = match size {
                        Some(s) => s,
                        None => {
                            c.notes.push(format!("member {} ({}): no size, left as padding", name, cpp));
                            continue;
                        }
                    };
                    let ct = if ct == CT::base("void") {
                        c.notes.push(format!("member {} ({}): type without definition, kept as bytes", name, cpp));
                        CT::Arr { of: Box::new(CT::base("uint8_t")), n: size }
                    } else {
                        ct
                    };
                    c.items.push(Item { off, size, align, depth, kind: IK::Member { name: name.clone(), cpp_name: name.clone(), ct, cpp, from: path.to_string() } });
                }
                _ => {}
            }
        }
    }

    /// Lays the items out with padding, groups and lanes, decides `packed`, writes `cdef`.
    fn emit(&self, l: &mut Layout, mut items: Vec<Item>, is_union: bool) {
        // names: the class's own members first, then by base depth; repeats are qualified
        let mut used: HashSet<String> = HashSet::new();
        let mut order: Vec<usize> = (0..items.len()).collect();
        order.sort_by_key(|&i| items[i].depth);
        let fix = |name: &str, from: &str, used: &mut HashSet<String>| -> String {
            let mut n = sanitize(name);
            if n.starts_with("_anon") || name.starts_with('<') {
                n = "_anon".to_string();
            }
            if used.contains(&n) && !from.is_empty() {
                let last = from.rsplit('.').next().unwrap_or(from);
                n = format!("{}__{}", last, n);
            }
            let base = n.clone();
            let mut k = 2;
            while used.contains(&n) {
                n = format!("{}_{}", base, k);
                k += 1;
            }
            used.insert(n.clone());
            n
        };
        for i in order {
            match &mut items[i].kind {
                IK::Member { name, from, .. } => {
                    *name = fix(name, from, &mut used);
                }
                IK::Bits { fields, .. } => {
                    for f in fields.iter_mut() {
                        f.name = fix(&f.name, &f.from, &mut used);
                    }
                }
            }
        }
        // 64-bit bitfield units: LuaJIT's bitfields have at most 32-bit containers. Split the
        // unit into two 32-bit ones when no field crosses bit 32; otherwise keep the unit as an
        // integer member and the fields as accessors.
        let mut split: Vec<Item> = Vec::new();
        for it in items {
            match &it.kind {
                IK::Bits { unit, fields } if it.size == 8 => {
                    let straddle = fields.iter().any(|f| f.pos < 32 && f.pos as u32 + f.len as u32 > 32);
                    let signed = matches!(unit, CT::Base { name, .. } if name.starts_with("int"));
                    if straddle {
                        let n = format!("_bits_{:x}", it.off);
                        for f in fields {
                            l.fields.push(FieldOut {
                                name: f.name.clone(),
                                cpp_name: f.cpp_name.clone(),
                                offset: it.off,
                                size: 8,
                                cpp: f.cpp.clone(),
                                bits: Some((f.pos, f.len)),
                                unit: Some(n.clone()),
                                from: f.from.clone(),
                            });
                        }
                        l.notes.push(format!("bitfields {} in a 64-bit unit with a field across bit 32: member {} and accessors", fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "), n));
                        let ct = CT::base(if signed { "int64_t" } else { "uint64_t" });
                        split.push(Item { off: it.off, size: 8, align: 8, depth: it.depth, kind: IK::Member { name: n.clone(), cpp_name: n, ct, cpp: "bitfield unit".into(), from: String::new() } });
                    } else {
                        let half = CT::base(if signed { "int32_t" } else { "uint32_t" });
                        let lo: Vec<BitF> = fields.iter().filter(|f| f.pos < 32).cloned().map(|mut f| {
                            f.ct = half.clone();
                            f
                        }).collect();
                        let hi: Vec<BitF> = fields
                            .iter()
                            .filter(|f| f.pos >= 32)
                            .cloned()
                            .map(|mut f| {
                                f.pos -= 32;
                                f.ct = half.clone();
                                f
                            })
                            .collect();
                        for (k, fs) in [(0u64, lo), (4u64, hi)] {
                            if !fs.is_empty() {
                                split.push(Item { off: it.off + k, size: 4, align: 4, depth: it.depth, kind: IK::Bits { unit: half.clone(), fields: fs } });
                            }
                        }
                    }
                }
                _ => split.push(it),
            }
        }
        let mut items = split;
        items.sort_by_key(|it| it.off);
        // groups of overlapping items
        let mut groups: Vec<Vec<Item>> = Vec::new();
        let mut gend = 0u64;
        for it in items {
            let joins = match groups.last() {
                Some(_) if is_union => true,
                Some(_) => it.off < gend,
                None => false,
            };
            if joins {
                gend = gend.max(it.off + it.size);
                groups.last_mut().unwrap().push(it);
            } else {
                gend = it.off + it.size;
                groups.push(vec![it]);
            }
        }
        let mut pads = 0usize;
        // first pass: is the natural layout right?
        let natural = self.check_natural(&groups, l.size, is_union);
        l.packed = !natural.0;
        l.align = if l.packed { 1 } else { natural.1 };
        let attr = if l.packed { " __attribute__((packed))" } else { "" };
        let mut out = String::new();
        let mut ctypes = 1usize;
        out.push_str(&format!("{}{} {} {{\n", if is_union { "union" } else { "struct" }, attr, l.cname));
        let mut cur = 0u64;
        let push_field = |l: &mut Layout, it: &Item| match &it.kind {
            IK::Member { name, cpp_name, cpp, from, .. } => {
                if cpp != "bitfield unit" {
                    l.fields.push(FieldOut { name: name.clone(), cpp_name: cpp_name.clone(), offset: it.off, size: it.size, cpp: cpp.clone(), bits: None, unit: None, from: from.clone() })
                }
            }
            IK::Bits { fields, .. } => {
                for f in fields {
                    l.fields.push(FieldOut { name: f.name.clone(), cpp_name: f.cpp_name.clone(), offset: it.off, size: it.size, cpp: f.cpp.clone(), bits: Some((f.pos, f.len)), unit: None, from: f.from.clone() });
                }
            }
        };
        if is_union {
            if let Some(g) = groups.pop() {
                for it in &g {
                    push_field(l, it);
                }
                let lanes = lanes(g);
                for lane in &lanes {
                    out.push_str(&self.lane_text(lane, 0, attr, "  ", &mut pads, &mut ctypes));
                }
                let end = lanes.iter().map(|ln| ln.last().map_or(0, |x| x.off + x.size)).max().unwrap_or(0);
                if end < l.size || lanes.is_empty() {
                    out.push_str(&format!("  uint8_t _p{}[{}];\n", pads, l.size));
                    ctypes += 2;
                }
            } else {
                out.push_str(&format!("  uint8_t _p0[{}];\n", l.size));
                ctypes += 2;
            }
        } else {
            for g in groups {
                let start = g[0].off;
                if start > cur {
                    out.push_str(&format!("  uint8_t _p{}[{}];\n", pads, start - cur));
                    pads += 1;
                    ctypes += 2;
                }
                for it in &g {
                    push_field(l, it);
                }
                let mut end = g.iter().map(|x| x.off + x.size).max().unwrap();
                if g.len() == 1 {
                    out.push_str(&self.item_text(&g[0], attr, "  ", &mut ctypes));
                } else {
                    // LuaJIT rounds the anonymous union up to its alignment
                    if !l.packed {
                        let ga = g.iter().map(|x| x.align).max().unwrap();
                        end = start + (end - start + ga - 1) / ga * ga;
                    }
                    out.push_str(&format!("  union{} {{\n", attr));
                    ctypes += 2;
                    for lane in &lanes(g) {
                        out.push_str(&self.lane_text(lane, start, attr, "    ", &mut pads, &mut ctypes));
                    }
                    out.push_str("  };\n");
                }
                cur = cur.max(end);
            }
            if cur < l.size {
                out.push_str(&format!("  uint8_t _p{}[{}];\n", pads, l.size - cur));
                ctypes += 2;
            } else if cur > l.size {
                l.notes.push(format!("members end at {} past the size {}", cur, l.size));
            }
        }
        out.push_str("};");
        l.cdef = out;
        l.ctypes = ctypes;
    }

    /// Would LuaJIT, without `packed`, put every item where the PDB says? (ok, struct alignment)
    fn check_natural(&self, groups: &[Vec<Item>], size: u64, is_union: bool) -> (bool, u64) {
        let mut maxa = 1u64;
        let mut ok = true;
        for (gi, g) in groups.iter().enumerate() {
            let next = groups.get(gi + 1).map_or(size, |n| n[0].off);
            let start = g[0].off;
            for it in g {
                maxa = maxa.max(it.align);
                if it.off % it.align != 0 {
                    ok = false;
                }
            }
            if g.len() > 1 && !is_union {
                // the anonymous union takes the largest alignment of its lanes, and its size is
                // rounded up to it
                let ga = g.iter().map(|x| x.align).max().unwrap();
                let end = g.iter().map(|x| x.off + x.size).max().unwrap();
                if start % ga != 0 || start + (end - start + ga - 1) / ga * ga > next {
                    ok = false;
                }
            }
        }
        if size % maxa != 0 {
            ok = false;
        }
        (ok, maxa)
    }

    fn item_text(&self, it: &Item, attr: &str, ind: &str, ctypes: &mut usize) -> String {
        match &it.kind {
            IK::Member { name, ct, .. } => {
                *ctypes += 1 + count_derived(ct);
                format!("{}{};\n", ind, ct.decl(name))
            }
            IK::Bits { fields, .. } => {
                let mut s = format!("{}struct{} {{", ind, attr);
                *ctypes += 2;
                let mut bit = 0u32;
                let mut fs = fields.clone();
                fs.sort_by_key(|f| f.pos);
                let gap = match it.size {
                    1 => "uint8_t",
                    2 => "uint16_t",
                    8 => "uint64_t",
                    _ => "uint32_t",
                };
                for f in &fs {
                    if (f.pos as u32) > bit {
                        s.push_str(&format!(" {} : {};", gap, f.pos as u32 - bit));
                        *ctypes += 1;
                    }
                    s.push_str(&format!(" {} : {};", f.ct.decl(&f.name), f.len));
                    *ctypes += 1;
                    bit = f.pos as u32 + f.len as u32;
                }
                s.push_str(" };\n");
                s
            }
        }
    }

    /// One lane of a group: a single item at the group start, or an anonymous struct.
    fn lane_text(&self, lane: &[Item], start: u64, attr: &str, ind: &str, pads: &mut usize, ctypes: &mut usize) -> String {
        if lane.len() == 1 && lane[0].off == start {
            return self.item_text(&lane[0], attr, ind, ctypes);
        }
        let mut s = format!("{}struct{} {{\n", ind, attr);
        *ctypes += 2;
        let mut cur = start;
        let inner = format!("{}  ", ind);
        for it in lane {
            if it.off > cur {
                s.push_str(&format!("{}uint8_t _p{}[{}];\n", inner, pads, it.off - cur));
                *pads += 1;
                *ctypes += 2;
            }
            s.push_str(&self.item_text(it, attr, &inner, ctypes));
            cur = it.off + it.size;
        }
        s.push_str(&format!("{}}};\n", ind));
        s
    }

    /// The full closure of a set of definitions, in declaration order: (complete, opaque).
    pub fn closure(&self, roots: &[u32]) -> (Vec<u32>, BTreeSet<u32>) {
        let mut order = Vec::new();
        let mut done = HashSet::new();
        let mut opaque = BTreeSet::new();
        fn visit(db: &Db, d: u32, order: &mut Vec<u32>, done: &mut HashSet<u32>, opaque: &mut BTreeSet<u32>, depth: usize) {
            if !done.insert(d) || depth > 200 {
                return;
            }
            if let Some(l) = db.layout(d) {
                for &x in &l.deps {
                    visit(db, x, order, done, opaque, depth + 1);
                }
                opaque.extend(l.refs.iter().copied());
            }
            order.push(d);
        }
        for &r in roots {
            visit(self, r, &mut order, &mut done, &mut opaque, 0);
        }
        let set: HashSet<u32> = order.iter().copied().collect();
        opaque.retain(|x| !set.contains(x));
        (order, opaque)
    }

    pub fn opaque_decl(&self, d: u32) -> String {
        let n = &self.cname[&d];
        match self.kind_of(d) {
            Some(Kind::Union) => format!("union {n}; typedef union {n} {n};"),
            Some(Kind::Enum) => self.layout(d).map(|l| l.cdef.clone()).unwrap_or_default(),
            _ => format!("struct {n}; typedef struct {n} {n};"),
        }
    }
}

fn size_rec(r: &Rec) -> u64 {
    match r {
        Rec::Class { size, .. } | Rec::Union { size, .. } => *size,
        _ => 0,
    }
}

fn count_derived(ct: &CT) -> usize {
    match ct {
        CT::Base { konst, .. } => *konst as usize,
        CT::Ptr { to, .. } => 1 + count_derived(to),
        CT::Arr { of, .. } => 1 + count_derived(of),
        CT::Func { ret, params, .. } => 1 + count_derived(ret) + params.iter().map(count_derived).sum::<usize>(),
    }
}

#[derive(Debug, Clone)]
struct BitF {
    name: String,
    cpp_name: String,
    pos: u8,
    len: u8,
    ct: CT,
    cpp: String,
    from: String,
}

#[derive(Debug, Clone)]
enum IK {
    Member { name: String, cpp_name: String, ct: CT, cpp: String, from: String },
    Bits { unit: CT, fields: Vec<BitF> },
}

#[derive(Debug, Clone)]
struct Item {
    off: u64,
    size: u64,
    align: u64,
    depth: usize,
    kind: IK,
}

#[derive(Default)]
struct Collect {
    items: Vec<Item>,
    units: BTreeMap<(u64, u64), usize>,
    deps: Deps,
    bases: Vec<(u32, u64, String)>,
    vfptrs: Vec<u64>,
    vbptrs: Vec<u64>,
    virtual_bases: bool,
    notes: Vec<String>,
}

/// Splits a group of overlapping items into lanes of non-overlapping items, first fit.
fn lanes(g: Vec<Item>) -> Vec<Vec<Item>> {
    let mut lanes: Vec<Vec<Item>> = Vec::new();
    for it in g {
        let pos = lanes.iter().position(|ln| ln.last().map_or(true, |x| x.off + x.size <= it.off));
        match pos {
            Some(p) => lanes[p].push(it),
            None => lanes.push(vec![it]),
        }
    }
    lanes
}

/// Classes that are interfaces get `struct` too.
pub fn is_class_kind(k: ClassKind) -> bool {
    matches!(k, ClassKind::Class | ClassKind::Struct | ClassKind::Interface)
}
