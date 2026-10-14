//! CodeView type records of a PDB: the TPI stream (types) and the function ids of the IPI stream,
//! parsed from the raw streams (the `pdb` crate reads the MSF container), with every attribute bit
//! kept (`compgenx`, `pseudo`, the vtable shape), which the `pdb` crate's `TypeData` drops.
//!
//! Layout of the records: Microsoft's `cvinfo.h` (github.com/microsoft/microsoft-pdb). Only the
//! leaves that x64 MSVC and clang-cl PDBs contain are parsed; others become `Rec::Other`.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;

pub const TI_FIRST: u32 = 0x1000;

/// `CV_fldattr_t`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FieldAttr(pub u16);
impl FieldAttr {
    pub fn access(self) -> u8 {
        (self.0 & 3) as u8
    }
    /// `CV_methodprop_e`: 0 vanilla, 1 virtual, 2 static, 3 friend, 4 intro, 5 pure virtual, 6 pure intro
    pub fn mprop(self) -> u8 {
        ((self.0 >> 2) & 7) as u8
    }
    pub fn is_static(self) -> bool {
        self.mprop() == 2
    }
    pub fn is_virtual(self) -> bool {
        matches!(self.mprop(), 1 | 4 | 5 | 6)
    }
    pub fn is_intro(self) -> bool {
        matches!(self.mprop(), 4 | 6)
    }
    pub fn is_pure(self) -> bool {
        matches!(self.mprop(), 5 | 6)
    }
    /// compiler generated function that does not exist
    pub fn pseudo(self) -> bool {
        self.0 & 0x20 != 0
    }
    /// compiler generated function that does exist
    pub fn compgenx(self) -> bool {
        self.0 & 0x100 != 0
    }
}

/// `CV_prop_t`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Props(pub u32);
impl Props {
    pub fn packed(self) -> bool {
        self.0 & 0x1 != 0
    }
    /// constructors or destructors present
    pub fn ctor(self) -> bool {
        self.0 & 0x2 != 0
    }
    pub fn ovlops(self) -> bool {
        self.0 & 0x4 != 0
    }
    pub fn nested(self) -> bool {
        self.0 & 0x8 != 0
    }
    pub fn opassign(self) -> bool {
        self.0 & 0x20 != 0
    }
    pub fn fwdref(self) -> bool {
        self.0 & 0x80 != 0
    }
    pub fn scoped(self) -> bool {
        self.0 & 0x100 != 0
    }
    pub fn has_unique_name(self) -> bool {
        self.0 & 0x200 != 0
    }
    pub fn intrinsic(self) -> bool {
        self.0 & 0x2000 != 0
    }
}

/// `CV_funcattr_t` (the byte after the calling convention)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuncAttr(pub u8);
impl FuncAttr {
    /// "C++ style ReturnUDT": the result goes through a hidden pointer
    pub fn cxx_return_udt(self) -> bool {
        self.0 & 1 != 0
    }
    pub fn ctor(self) -> bool {
        self.0 & 2 != 0
    }
    pub fn ctor_vbase(self) -> bool {
        self.0 & 4 != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKind {
    Class,
    Struct,
    Interface,
}

/// Pointer mode (`CV_ptrmode_e`)
pub mod pm {
    pub const PTR: u8 = 0;
    pub const LREF: u8 = 1;
    pub const PMEM: u8 = 2;
    pub const PMFUNC: u8 = 3;
    pub const RREF: u8 = 4;
}

#[derive(Debug, Clone)]
pub enum Field {
    Base { attr: FieldAttr, ty: u32, offset: u64 },
    VBase { direct: bool, attr: FieldAttr, ty: u32, vbptr_ty: u32, vbptr_off: u64, vb_index: u64 },
    VFuncTab { ty: u32 },
    Member { attr: FieldAttr, ty: u32, offset: u64, name: String },
    StaticMember { attr: FieldAttr, ty: u32, name: String },
    /// overloaded methods: `list` is an `LF_METHODLIST`
    Method { count: u16, list: u32, name: String },
    OneMethod { attr: FieldAttr, ty: u32, vtoff: Option<u32>, name: String },
    Nested { ty: u32, name: String },
    Enumerate { attr: FieldAttr, value: i128, name: String },
    Other(u16),
}

#[derive(Debug, Clone)]
pub struct MethodEntry {
    pub attr: FieldAttr,
    pub ty: u32,
    pub vtoff: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum Rec {
    Modifier { ty: u32, konst: bool, volatile: bool, unaligned: bool },
    Pointer { referent: u32, attr: u32, containing: u32, pm_repr: u16 },
    Procedure { ret: u32, cc: u8, fattr: FuncAttr, nparams: u16, args: u32 },
    MFunction { ret: u32, class: u32, this_ty: u32, cc: u8, fattr: FuncAttr, nparams: u16, args: u32, this_adjust: i32 },
    ArgList(Vec<u32>),
    FieldList { fields: Vec<Field>, cont: Option<u32> },
    Bitfield { ty: u32, len: u8, pos: u8 },
    MethodList(Vec<MethodEntry>),
    Array { elem: u32, index: u32, size: u64 },
    Class { kind: ClassKind, count: u16, props: Props, fields: u32, derived: u32, vshape: u32, size: u64, name: String, unique: Option<String> },
    Union { count: u16, props: Props, fields: u32, size: u64, name: String, unique: Option<String> },
    Enum { count: u16, props: Props, utype: u32, fields: u32, name: String, unique: Option<String> },
    VtShape(u16),
    Other(u16),
}

impl Rec {
    pub fn ptr_mode(attr: u32) -> u8 {
        ((attr >> 5) & 7) as u8
    }
    pub fn ptr_size(attr: u32) -> u8 {
        ((attr >> 13) & 0x3f) as u8
    }
    pub fn ptr_const(attr: u32) -> bool {
        attr & 0x400 != 0
    }
}

/// A function id of the IPI stream: `LF_FUNC_ID` / `LF_MFUNC_ID`
#[derive(Debug, Clone)]
pub struct FuncId {
    /// scope id (`LF_FUNC_ID`) or the class type (`LF_MFUNC_ID`)
    pub parent: u32,
    pub member: bool,
    pub ty: u32,
    pub name: String,
}

pub struct Tpi {
    pub begin: u32,
    pub recs: Vec<Rec>,
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn need(&self, n: usize) -> Result<()> {
        if self.p + n > self.b.len() {
            bail!("record truncated");
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        self.p += 1;
        Ok(self.b[self.p - 1])
    }
    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        self.p += 2;
        Ok(u16::from_le_bytes([self.b[self.p - 2], self.b[self.p - 1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        self.p += 4;
        Ok(u32::from_le_bytes(self.b[self.p - 4..self.p].try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    fn u64(&mut self) -> Result<u64> {
        self.need(8)?;
        self.p += 8;
        Ok(u64::from_le_bytes(self.b[self.p - 8..self.p].try_into().unwrap()))
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.p += n;
        Ok(())
    }
    /// numeric leaf (`LF_CHAR` ... `LF_UQUADWORD`); reals and octwords are skipped as 0
    fn num(&mut self) -> Result<i128> {
        let v = self.u16()?;
        if v < 0x8000 {
            return Ok(v as i128);
        }
        Ok(match v {
            0x8000 => self.u8()? as i8 as i128,
            0x8001 => self.u16()? as i16 as i128,
            0x8002 => self.u16()? as i128,
            0x8003 => self.i32()? as i128,
            0x8004 => self.u32()? as i128,
            0x8009 => self.u64()? as i64 as i128,
            0x800a => self.u64()? as i128,
            0x8005 => {
                self.skip(4)?;
                0
            }
            0x8006 => {
                self.skip(8)?;
                0
            }
            0x8007 => {
                self.skip(10)?;
                0
            }
            0x8008 | 0x8017 | 0x8018 => {
                self.skip(16)?;
                0
            }
            0x8010 => {
                let n = self.u16()? as usize;
                self.skip(n)?;
                0
            }
            _ => bail!("unknown numeric leaf {:#x}", v),
        })
    }
    fn unum(&mut self) -> Result<u64> {
        Ok(self.num()? as u64)
    }
    fn cstr(&mut self) -> Result<String> {
        let rest = &self.b[self.p..];
        let n = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        let s = String::from_utf8_lossy(&rest[..n]).into_owned();
        self.p += (n + 1).min(rest.len());
        Ok(s)
    }
    /// skip `LF_PADn` bytes after a field list member
    fn pad(&mut self) {
        while self.p < self.b.len() && self.b[self.p] > 0xf0 {
            self.p += ((self.b[self.p] & 0x0f) as usize).max(1);
        }
    }
}

fn parse_field(c: &mut Cur) -> Result<Field> {
    let leaf = c.u16()?;
    Ok(match leaf {
        0x1400 | 0x151a => {
            let attr = FieldAttr(c.u16()?);
            let ty = c.u32()?;
            let offset = c.unum()?;
            Field::Base { attr, ty, offset }
        }
        0x1401 | 0x1402 => {
            let attr = FieldAttr(c.u16()?);
            let ty = c.u32()?;
            let vbptr_ty = c.u32()?;
            let vbptr_off = c.unum()?;
            let vb_index = c.unum()?;
            Field::VBase { direct: leaf == 0x1401, attr, ty, vbptr_ty, vbptr_off, vb_index }
        }
        0x1404 => unreachable!("LF_INDEX is handled by the field list"),
        0x1409 => {
            c.u16()?;
            Field::VFuncTab { ty: c.u32()? }
        }
        0x140b => {
            c.u16()?;
            c.u32()?;
            Field::Other(leaf)
        }
        0x140c => {
            c.u16()?;
            c.u32()?;
            c.i32()?;
            Field::Other(leaf)
        }
        0x1502 => {
            let attr = FieldAttr(c.u16()?);
            let value = c.num()?;
            Field::Enumerate { attr, value, name: c.cstr()? }
        }
        0x150c => {
            c.u16()?;
            c.u32()?;
            c.cstr()?;
            Field::Other(leaf)
        }
        0x150d => {
            let attr = FieldAttr(c.u16()?);
            let ty = c.u32()?;
            let offset = c.unum()?;
            Field::Member { attr, ty, offset, name: c.cstr()? }
        }
        0x150e => {
            let attr = FieldAttr(c.u16()?);
            let ty = c.u32()?;
            Field::StaticMember { attr, ty, name: c.cstr()? }
        }
        0x150f => {
            let count = c.u16()?;
            let list = c.u32()?;
            Field::Method { count, list, name: c.cstr()? }
        }
        0x1510 | 0x1512 => {
            c.u16()?;
            let ty = c.u32()?;
            Field::Nested { ty, name: c.cstr()? }
        }
        0x1511 => {
            let attr = FieldAttr(c.u16()?);
            let ty = c.u32()?;
            let vtoff = if attr.is_intro() { Some(c.u32()?) } else { None };
            Field::OneMethod { attr, ty, vtoff, name: c.cstr()? }
        }
        0x1513 => {
            c.u16()?;
            c.u32()?;
            c.cstr()?;
            Field::Other(leaf)
        }
        _ => bail!("unknown field leaf {:#x}", leaf),
    })
}

fn parse_rec(kind: u16, data: &[u8]) -> Result<Rec> {
    let mut c = Cur { b: data, p: 0 };
    let c = &mut c;
    Ok(match kind {
        0x1001 => {
            let ty = c.u32()?;
            let a = c.u16()?;
            Rec::Modifier { ty, konst: a & 1 != 0, volatile: a & 2 != 0, unaligned: a & 4 != 0 }
        }
        0x1002 => {
            let referent = c.u32()?;
            let attr = c.u32()?;
            let (mut containing, mut pm_repr) = (0, 0);
            if matches!(Rec::ptr_mode(attr), pm::PMEM | pm::PMFUNC) && c.p + 6 <= data.len() {
                containing = c.u32()?;
                pm_repr = c.u16()?;
            }
            Rec::Pointer { referent, attr, containing, pm_repr }
        }
        0x1008 => {
            let ret = c.u32()?;
            let cc = c.u8()?;
            let fattr = FuncAttr(c.u8()?);
            let nparams = c.u16()?;
            let args = c.u32()?;
            Rec::Procedure { ret, cc, fattr, nparams, args }
        }
        0x1009 => {
            let ret = c.u32()?;
            let class = c.u32()?;
            let this_ty = c.u32()?;
            let cc = c.u8()?;
            let fattr = FuncAttr(c.u8()?);
            let nparams = c.u16()?;
            let args = c.u32()?;
            let this_adjust = c.i32()?;
            Rec::MFunction { ret, class, this_ty, cc, fattr, nparams, args, this_adjust }
        }
        0x000a => Rec::VtShape(c.u16()?),
        0x1201 => {
            let n = c.u32()? as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(c.u32()?);
            }
            Rec::ArgList(v)
        }
        0x1203 => {
            let mut fields = Vec::new();
            let mut cont = None;
            while c.p < data.len() {
                if data[c.p] > 0xf0 {
                    c.pad();
                    continue;
                }
                let leaf = u16::from_le_bytes([data[c.p], *data.get(c.p + 1).unwrap_or(&0)]);
                if leaf == 0x1404 {
                    c.u16()?;
                    c.u16()?;
                    cont = Some(c.u32()?);
                } else {
                    fields.push(parse_field(c)?);
                }
                c.pad();
            }
            Rec::FieldList { fields, cont }
        }
        0x1205 => {
            let ty = c.u32()?;
            let len = c.u8()?;
            let pos = c.u8()?;
            Rec::Bitfield { ty, len, pos }
        }
        0x1206 => {
            let mut v = Vec::new();
            while c.p + 8 <= data.len() {
                let attr = FieldAttr(c.u16()?);
                c.u16()?;
                let ty = c.u32()?;
                let vtoff = if attr.is_intro() { Some(c.u32()?) } else { None };
                v.push(MethodEntry { attr, ty, vtoff });
            }
            Rec::MethodList(v)
        }
        0x1503 => {
            let elem = c.u32()?;
            let index = c.u32()?;
            let size = c.unum()?;
            Rec::Array { elem, index, size }
        }
        0x1504 | 0x1505 | 0x1519 => {
            let count = c.u16()?;
            let props = Props(c.u16()? as u32);
            let fields = c.u32()?;
            let derived = c.u32()?;
            let vshape = c.u32()?;
            let size = c.unum()?;
            let name = c.cstr()?;
            let unique = if props.has_unique_name() { Some(c.cstr()?) } else { None };
            let kind = match kind {
                0x1504 => ClassKind::Class,
                0x1505 => ClassKind::Struct,
                _ => ClassKind::Interface,
            };
            Rec::Class { kind, count, props, fields, derived, vshape, size, name, unique }
        }
        // LF_CLASS2 / LF_STRUCT2 (newer compilers): 32-bit properties first
        0x1608 | 0x1609 => {
            let props = Props(c.u32()?);
            let fields = c.u32()?;
            let derived = c.u32()?;
            let vshape = c.u32()?;
            let count = c.u16()?;
            let size = c.unum()?;
            let name = c.cstr()?;
            let unique = if props.has_unique_name() { Some(c.cstr()?) } else { None };
            let kind = if kind == 0x1608 { ClassKind::Class } else { ClassKind::Struct };
            Rec::Class { kind, count, props, fields, derived, vshape, size, name, unique }
        }
        0x1506 => {
            let count = c.u16()?;
            let props = Props(c.u16()? as u32);
            let fields = c.u32()?;
            let size = c.unum()?;
            let name = c.cstr()?;
            let unique = if props.has_unique_name() { Some(c.cstr()?) } else { None };
            Rec::Union { count, props, fields, size, name, unique }
        }
        0x1507 => {
            let count = c.u16()?;
            let props = Props(c.u16()? as u32);
            let utype = c.u32()?;
            let fields = c.u32()?;
            let name = c.cstr()?;
            let unique = if props.has_unique_name() { Some(c.cstr()?) } else { None };
            Rec::Enum { count, props, utype, fields, name, unique }
        }
        _ => Rec::Other(kind),
    })
}

/// Records of a TPI-format stream (TPI or IPI): (first index, (kind, data) per record).
fn records(stream: &[u8]) -> Result<(u32, Vec<(u16, &[u8])>)> {
    anyhow::ensure!(stream.len() >= 56, "type stream too short");
    let rd = |o: usize| u32::from_le_bytes(stream[o..o + 4].try_into().unwrap());
    let header = rd(4) as usize;
    let begin = rd(8);
    let end = rd(12);
    let bytes = rd(16) as usize;
    let mut p = header;
    let stop = (header + bytes).min(stream.len());
    let mut out = Vec::with_capacity((end - begin) as usize);
    while p + 4 <= stop {
        let len = u16::from_le_bytes([stream[p], stream[p + 1]]) as usize;
        let kind = u16::from_le_bytes([stream[p + 2], stream[p + 3]]);
        let s = p + 4;
        let e = (p + 2 + len).min(stop);
        out.push((kind, &stream[s.min(e)..e]));
        p += 2 + len;
    }
    Ok((begin, out))
}

impl Tpi {
    pub fn parse(stream: &[u8]) -> Result<Tpi> {
        let (begin, raw) = records(stream)?;
        let mut recs = Vec::with_capacity(raw.len());
        for (i, (kind, data)) in raw.iter().enumerate() {
            let r = parse_rec(*kind, data).unwrap_or(Rec::Other(*kind));
            let _ = i;
            recs.push(r);
        }
        Ok(Tpi { begin, recs })
    }

    pub fn get(&self, ti: u32) -> Option<&Rec> {
        if ti < self.begin {
            return None;
        }
        self.recs.get((ti - self.begin) as usize)
    }

    pub fn end(&self) -> u32 {
        self.begin + self.recs.len() as u32
    }

    /// All fields of a field list, following continuations.
    pub fn fields(&self, mut ti: u32) -> Vec<&Field> {
        let mut out = Vec::new();
        let mut guard = 0;
        while let Some(Rec::FieldList { fields, cont }) = self.get(ti) {
            out.extend(fields.iter());
            guard += 1;
            match cont {
                Some(c) if guard < 10_000 => ti = *c,
                _ => break,
            }
        }
        out
    }

    pub fn args(&self, ti: u32) -> &[u32] {
        match self.get(ti) {
            Some(Rec::ArgList(v)) => v,
            _ => &[],
        }
    }
}

/// Function ids of the IPI stream, by id index.
pub fn parse_ipi(stream: &[u8]) -> Result<HashMap<u32, FuncId>> {
    let (begin, raw) = records(stream).context("IPI stream")?;
    let mut out = HashMap::new();
    for (i, (kind, data)) in raw.iter().enumerate() {
        if *kind != 0x1601 && *kind != 0x1602 {
            continue;
        }
        let mut c = Cur { b: data, p: 0 };
        let (Ok(parent), Ok(ty)) = (c.u32(), c.u32()) else { continue };
        let name = c.cstr().unwrap_or_default();
        out.insert(begin + i as u32, FuncId { parent, member: *kind == 0x1602, ty, name });
    }
    Ok(out)
}
