//! MSVC x64 C++ exception metadata: find the funclets (unwind destructors, catch handlers) that
//! belong to each function, from the FuncInfo of `__CxxFrameHandler3` (classic layout, magic
//! 0x1993052x) or `__CxxFrameHandler4` (compressed layout, VS2019+).

use crate::pe::Pe;

pub const KIND_UNWIND: u8 = 1;
pub const KIND_CATCH: u8 = 2;

/// (funclet rva, kind) for the function whose primary `.pdata` entry has unwind info at `unwind`.
pub fn funclets(pe: &Pe, unwind: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    let u = unwind & !1;
    let Some(hdr) = pe.bytes(u, 4) else { return out };
    let flags = hdr[0] >> 3;
    if flags & 0x3 == 0 || flags & 0x4 != 0 {
        return out;
    }
    let count = hdr[2] as u32;
    let h = u + 4 + ((count + 1) & !1) * 2;
    // handler rva, then handler data: the FuncInfo rva for the C++ handlers
    let Some(fi) = pe.u32(h + 4) else { return out };
    if fi == 0 || !pe.in_image(fi, 8) || pe.is_code(fi) {
        return out;
    }
    let magic = pe.u32(fi).unwrap_or(0);
    if (0x1993_0520..=0x1993_0522).contains(&magic) {
        fh3(pe, fi, &mut out);
    } else {
        fh4(pe, fi, &mut out);
    }
    out.retain(|&(r, _)| pe.is_code(r));
    out.sort_unstable();
    out.dedup();
    out
}

fn fh3(pe: &Pe, fi: u32, out: &mut Vec<(u32, u8)>) {
    // magic, maxState, dispUnwindMap, nTryBlocks, dispTryBlockMap, ...
    let (Some(max_state), Some(unwind_map), Some(ntry), Some(try_map)) = (pe.u32(fi + 4), pe.u32(fi + 8), pe.u32(fi + 12), pe.u32(fi + 16)) else { return };
    if max_state < 0x10000 && unwind_map != 0 {
        for s in 0..max_state {
            // UnwindMapEntry { toState, action }
            if let Some(a) = pe.u32(unwind_map + s * 8 + 4) {
                if a != 0 {
                    out.push((a, KIND_UNWIND));
                }
            }
        }
    }
    if ntry < 0x10000 && try_map != 0 {
        for t in 0..ntry {
            // TryBlockMapEntry { tryLow, tryHigh, catchHigh, nCatches, dispHandlerArray }
            let e = try_map + t * 20;
            let (Some(nc), Some(ha)) = (pe.u32(e + 12), pe.u32(e + 16)) else { continue };
            if nc > 0x1000 {
                continue;
            }
            for c in 0..nc {
                // HandlerType { adjectives, dispType, dispCatchObj, dispOfHandler, dispFrame }
                if let Some(a) = pe.u32(ha + c * 20 + 12) {
                    if a != 0 {
                        out.push((a, KIND_CATCH));
                    }
                }
            }
        }
    }
}

/// FH4 compressed reader.
struct R<'a> {
    pe: &'a Pe,
    p: u32,
}

const NEG_LEN: [u32; 16] = [1, 2, 1, 3, 1, 2, 1, 4, 1, 2, 1, 3, 1, 2, 1, 5];
const SHIFT: [u32; 16] = [25, 18, 25, 11, 25, 18, 25, 4, 25, 18, 25, 11, 25, 18, 25, 0];

impl<'a> R<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = self.pe.bytes(self.p, 1)?[0];
        self.p += 1;
        Some(b)
    }
    fn unsigned(&mut self) -> Option<u32> {
        let first = self.pe.bytes(self.p, 1)?[0];
        let lb = (first & 0x0f) as usize;
        let len = NEG_LEN[lb];
        // the value is the 4 bytes ending at p + len, shifted right
        let end = self.p + len;
        let v = self.pe.u32(end.checked_sub(4)?)?;
        self.p = end;
        Some(if SHIFT[lb] >= 32 { 0 } else { v >> SHIFT[lb] })
    }
    fn int(&mut self) -> Option<u32> {
        let v = self.pe.u32(self.p)?;
        self.p += 4;
        Some(v)
    }
}

fn fh4(pe: &Pe, fi: u32, out: &mut Vec<(u32, u8)>) {
    let mut r = R { pe, p: fi };
    let Some(h) = r.byte() else { return };
    let (is_catch, _separated, bbt, has_unwind, has_try) = (h & 1 != 0, h & 2 != 0, h & 4 != 0, h & 8 != 0, h & 16 != 0);
    let _ = is_catch;
    if bbt && r.unsigned().is_none() {
        return;
    }
    let unwind_map = if has_unwind { r.int() } else { None };
    let try_map = if has_try { r.int() } else { None };
    if let Some(um) = unwind_map.filter(|&x| x != 0) {
        let mut u = R { pe, p: um };
        if let Some(n) = u.unsigned() {
            for _ in 0..n.min(0x10000) {
                let Some(nt) = u.unsigned() else { break };
                match nt & 3 {
                    1 | 2 => {
                        // destructor called with an object: a regular function, not a funclet
                        if u.int().is_none() || u.unsigned().is_none() {
                            break;
                        }
                    }
                    3 => match u.int() {
                        Some(a) => out.push((a, KIND_UNWIND)),
                        None => break,
                    },
                    _ => {}
                }
            }
        }
    }
    if let Some(tm) = try_map.filter(|&x| x != 0) {
        let mut t = R { pe, p: tm };
        let Some(ntry) = t.unsigned() else { return };
        for _ in 0..ntry.min(0x1000) {
            // tryLow, tryHigh, catchHigh, dispHandlerArray
            if t.unsigned().is_none() || t.unsigned().is_none() || t.unsigned().is_none() {
                return;
            }
            let Some(ha) = t.int() else { return };
            let mut hr = R { pe, p: ha };
            let Some(nh) = hr.unsigned() else { continue };
            for _ in 0..nh.min(0x100) {
                let Some(hh) = hr.byte() else { break };
                if hh & 1 != 0 && hr.unsigned().is_none() {
                    break;
                }
                if hh & 2 != 0 && hr.int().is_none() {
                    break;
                }
                if hh & 4 != 0 && hr.unsigned().is_none() {
                    break;
                }
                let Some(a) = hr.int() else { break };
                out.push((a, KIND_CATCH));
                let cont_rva = hh & 8 != 0;
                let ncont = (hh >> 4) & 3;
                for _ in 0..ncont {
                    let ok = if cont_rva { hr.int().is_some() } else { hr.unsigned().is_some() };
                    if !ok {
                        break;
                    }
                }
            }
        }
    }
}
