//! Build extraction: function discovery from `.pdata` plus reachable leaf functions, recursive
//! descent disassembly with MSVC jump-table resolution, and per-function features.

use crate::model::{self, ff, Build, BuildMeta, ExtractStats, Func, Ref};
use crate::pe::Pe;
use crate::pdbnames;
use anyhow::Result;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use xxhash_rust::xxh3::{xxh3_64, Xxh3};

/// Upper bound for a leaf function (no `.pdata`) discovered by recursive descent.
const MAX_LEAF_SPAN: u32 = 0x4000;
const MAX_JUMP_TABLE: u32 = 2048;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TargetKind {
    Call,
    Jump,
    AddrTaken,
}

/// Result of decoding one function.
struct Decoded {
    insns: Vec<Instruction>,
    /// extra block leaders from resolved jump tables
    table_targets: Vec<u32>,
    jump_tables: u32,
    unresolved: u32,
    bad: bool,
    /// code addresses outside the function referenced by it
    targets: Vec<(u32, TargetKind)>,
}

struct Ctx<'a> {
    pe: &'a Pe,
    import_by_iat: HashMap<u32, u32>,
    /// sorted (start, end, func entry) of all known code ranges
    ranges: Vec<(u32, u32, u32)>,
    starts: HashSet<u32>,
}

impl<'a> Ctx<'a> {
    fn containing(&self, rva: u32) -> Option<(u32, u32, u32)> {
        let i = self.ranges.partition_point(|r| r.0 <= rva);
        if i > 0 {
            let r = self.ranges[i - 1];
            if rva < r.1 {
                return Some(r);
            }
        }
        None
    }

    fn add_ranges(&mut self, entry: u32, rs: &[(u32, u32)]) {
        for &(s, e) in rs {
            let i = self.ranges.partition_point(|r| r.0 < s);
            self.ranges.insert(i, (s, e, entry));
        }
        self.starts.insert(entry);
    }
}

fn reg_full(r: Register) -> Register {
    r.full_register()
}

/// Decode a function by recursive descent. `chunks` bounds a `.pdata` function; leaf functions
/// (chunks = None) are bounded by other known functions and MAX_LEAF_SPAN.
fn decode(ctx: &Ctx, entry: u32, chunks: Option<&[(u32, u32)]>) -> Decoded {
    let pe = ctx.pe;
    let mut out = Decoded { insns: Vec::new(), table_targets: Vec::new(), jump_tables: 0, unresolved: 0, bad: false, targets: Vec::new() };
    let allowed = |ip: u32| -> bool {
        match chunks {
            Some(cs) => cs.iter().any(|&(s, e)| ip >= s && ip < e),
            None => {
                ip >= entry
                    && ip < entry.saturating_add(MAX_LEAF_SPAN)
                    && pe.is_code(ip)
                    && (ip == entry || (!ctx.starts.contains(&ip) && ctx.containing(ip).is_none()))
            }
        }
    };
    let mut visited: HashSet<u32> = HashSet::new();
    let mut work: Vec<u32> = vec![entry];
    if let Some(cs) = chunks {
        for &(s, _) in cs.iter().skip(1) {
            work.push(s);
        }
    }
    while let Some(start) = work.pop() {
        if visited.contains(&start) || !allowed(start) {
            continue;
        }
        let Some(sec) = pe.section_of(start) else { continue };
        let sec_end = (sec.rva + sec.vsize.max(sec.raw_size)).min(pe.image.len() as u32);
        let data = &pe.image[start as usize..sec_end as usize];
        let mut dec = Decoder::with_ip(64, data, start as u64, DecoderOptions::NONE);
        let mut recent: Vec<Instruction> = Vec::with_capacity(16);
        let mut instr = Instruction::default();
        while dec.can_decode() {
            let ip = dec.ip() as u32;
            if visited.contains(&ip) || (ip != start && !allowed(ip)) {
                break;
            }
            dec.decode_out(&mut instr);
            if instr.is_invalid() {
                out.bad = true;
                break;
            }
            // an instruction straddling the end of the allowed region
            let last = ip + instr.len() as u32 - 1;
            if last != ip && !allowed(last) && chunks.is_some() {
                out.bad = true;
                break;
            }
            visited.insert(ip);
            out.insns.push(instr);
            if recent.len() == 12 {
                recent.remove(0);
            }
            recent.push(instr);
            let mut stop = false;
            match instr.flow_control() {
                FlowControl::Next | FlowControl::XbeginXabortXend => {}
                FlowControl::Call => {
                    let t = instr.near_branch_target() as u32;
                    out.targets.push((t, TargetKind::Call));
                }
                FlowControl::IndirectCall => {}
                FlowControl::ConditionalBranch => {
                    let t = instr.near_branch_target() as u32;
                    if allowed(t) {
                        work.push(t);
                    } else {
                        out.targets.push((t, TargetKind::Jump));
                    }
                }
                FlowControl::UnconditionalBranch => {
                    let t = instr.near_branch_target() as u32;
                    if allowed(t) {
                        work.push(t);
                    } else {
                        out.targets.push((t, TargetKind::Jump));
                    }
                    stop = true;
                }
                FlowControl::IndirectBranch => {
                    if instr.op0_kind() == OpKind::Register {
                        match jump_table(pe, &recent, instr.op0_register(), &allowed) {
                            Some(ts) => {
                                out.jump_tables += 1;
                                for t in ts {
                                    out.table_targets.push(t);
                                    work.push(t);
                                }
                            }
                            None => out.unresolved += 1,
                        }
                    }
                    stop = true;
                }
                FlowControl::Return | FlowControl::Exception => stop = true,
                FlowControl::Interrupt => {
                    // int3 padding / __debugbreak
                    if instr.code() == Code::Int3 {
                        stop = true;
                    }
                }
            }
            // address-taken code refs (lea rcx,[rip+fn] / mov reg, imm64)
            if instr.is_ip_rel_memory_operand() && instr.mnemonic() == Mnemonic::Lea {
                let t = instr.ip_rel_memory_address() as u32;
                if pe.is_code(t) {
                    out.targets.push((t, TargetKind::AddrTaken));
                }
            }
            if stop {
                break;
            }
        }
    }
    out.insns.sort_by_key(|i| i.ip());
    out.insns.dedup_by_key(|i| i.ip());
    out.table_targets.sort_unstable();
    out.table_targets.dedup();
    out
}

/// MSVC x64 switch: `lea B,[__ImageBase]; [movzx idx, byte [B+idx+tbl1]]; mov R32,[B+idx*4+tbl];
/// add R,B; jmp R`. Returns the code targets of the table.
fn jump_table(pe: &Pe, recent: &[Instruction], jreg: Register, allowed: &dyn Fn(u32) -> bool) -> Option<Vec<u32>> {
    let n = recent.len();
    if n < 3 {
        return None;
    }
    let jreg = reg_full(jreg);
    // find add jreg, B
    let mut base = None;
    let mut k = n - 1; // recent[n-1] is the jmp itself
    while k > 0 {
        k -= 1;
        let i = &recent[k];
        if i.mnemonic() == Mnemonic::Add && i.op_count() == 2 && i.op0_kind() == OpKind::Register && reg_full(i.op0_register()) == jreg && i.op1_kind() == OpKind::Register {
            base = Some((k, reg_full(i.op1_register())));
            break;
        }
    }
    let (kadd, b) = base?;
    // find mov R32, dword [B + idx*4 + disp] writing jreg
    let mut table = None;
    let mut idx_reg = Register::None;
    let mut k = kadd;
    while k > 0 {
        k -= 1;
        let i = &recent[k];
        if (i.mnemonic() == Mnemonic::Mov || i.mnemonic() == Mnemonic::Movsxd)
            && i.op0_kind() == OpKind::Register
            && reg_full(i.op0_register()) == jreg
            && i.op1_kind() == OpKind::Memory
            && reg_full(i.memory_base()) == b
            && i.memory_index_scale() == 4
        {
            table = Some(i.memory_displacement64() as u32);
            idx_reg = reg_full(i.memory_index());
            break;
        }
    }
    let table = table?;
    // bound from `cmp idx, imm` when there is no byte index table in between
    let mut bound = None;
    let mut byte_table = false;
    for i in recent[..kadd].iter().rev() {
        if i.mnemonic() == Mnemonic::Movzx && i.op1_kind() == OpKind::Memory && reg_full(i.memory_base()) == b {
            byte_table = true;
        }
        if i.mnemonic() == Mnemonic::Cmp && i.op0_kind() == OpKind::Register && reg_full(i.op0_register()) == idx_reg {
            if matches!(i.op1_kind(), OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate16) {
                bound = Some(i.immediate(1) as u32 + 1);
            }
            break;
        }
    }
    let limit = match (bound, byte_table) {
        (Some(b), false) => b.min(MAX_JUMP_TABLE),
        _ => MAX_JUMP_TABLE,
    };
    let mut out = Vec::new();
    for e in 0..limit {
        let Some(t) = pe.u32(table + e * 4) else { break };
        if !allowed(t) {
            if bound.is_some() && !byte_table {
                // a bounded table must be fully valid
                return if out.is_empty() { None } else { Some(out) };
            }
            break;
        }
        out.push(t);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Discover all function entries and their chunk ranges.
fn discover<'a>(pe: &'a Pe, stats: &mut ExtractStats, import_by_iat: HashMap<u32, u32>, extra_seeds: &[(u32, u16)]) -> (Ctx<'a>, BTreeMap<u32, (Vec<(u32, u32)>, u16)>) {
    let pdata = pe.pdata();
    stats.pdata_entries = pdata.len() as u32;
    let mut funcs: BTreeMap<u32, (Vec<(u32, u32)>, u16)> = BTreeMap::new();
    for (i, rf) in pdata.iter().enumerate() {
        let mut r = i;
        let mut steps = 0;
        let flagged_chain = rf.flags & 0x4 != 0;
        while let Some(p) = pdata[r].chained_to {
            if p as usize == r || steps > 32 {
                break;
            }
            r = p as usize;
            steps += 1;
        }
        if flagged_chain {
            if r == i {
                stats.pdata_chain_unresolved += 1;
            } else {
                stats.pdata_chained += 1;
            }
        }
        if rf.end <= rf.begin {
            continue;
        }
        let root = pdata[r].begin;
        let e = funcs.entry(root).or_insert_with(|| (Vec::new(), ff::PDATA));
        if r == i {
            e.0.insert(0, (rf.begin, rf.end));
        } else {
            e.0.push((rf.begin, rf.end));
        }
    }
    stats.funcs_pdata = funcs.len() as u32;
    let mut ctx = Ctx { pe, import_by_iat, ranges: Vec::new(), starts: HashSet::new() };
    let mut all: Vec<(u32, u32, u32)> = Vec::new();
    for (&entry, (rs, _)) in &funcs {
        for &(s, e) in rs {
            all.push((s, e, entry));
        }
        ctx.starts.insert(entry);
    }
    all.sort_unstable();
    ctx.ranges = all;

    // seeds: decoded targets of the pdata functions, plus the extra seeds
    let decoded: Vec<Vec<(u32, TargetKind)>> = funcs
        .par_iter()
        .map(|(&entry, (rs, _))| decode(&ctx, entry, Some(rs)).targets)
        .collect();
    let mut pending: Vec<(u32, u16)> = extra_seeds.to_vec();
    for ts in decoded {
        for (t, k) in ts {
            pending.push((t, kind_flag(k)));
        }
    }
    let mut flags_extra: HashMap<u32, u16> = HashMap::new();
    let mut round = 0;
    while !pending.is_empty() && round < 64 {
        round += 1;
        pending.sort_unstable();
        let mut next: Vec<(u32, u16)> = Vec::new();
        let mut i = 0;
        while i < pending.len() {
            let t = pending[i].0;
            let mut fl = 0;
            while i < pending.len() && pending[i].0 == t {
                fl |= pending[i].1;
                i += 1;
            }
            *flags_extra.entry(t).or_insert(0) |= fl;
            if ctx.starts.contains(&t) || !pe.is_code(t) {
                continue;
            }
            if ctx.containing(t).is_some() {
                stats.interior_refs += 1;
                continue;
            }
            let d = decode(&ctx, t, None);
            if d.insns.is_empty() {
                continue;
            }
            let rs = runs(&d.insns);
            ctx.add_ranges(t, &rs);
            funcs.insert(t, (rs, 0));
            stats.funcs_leaf += 1;
            for (tt, k) in d.targets {
                next.push((tt, kind_flag(k)));
            }
        }
        pending = next;
    }
    for (rva, fl) in flags_extra {
        if let Some(f) = funcs.get_mut(&rva) {
            f.1 |= fl;
        }
    }
    (ctx, funcs)
}

fn kind_flag(k: TargetKind) -> u16 {
    match k {
        TargetKind::Call => ff::CALLED,
        TargetKind::Jump => ff::JUMPED,
        TargetKind::AddrTaken => ff::ADDR_TAKEN,
    }
}

/// contiguous [start, end) runs of decoded instructions
fn runs(insns: &[Instruction]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for i in insns {
        let s = i.ip() as u32;
        let e = s + i.len() as u32;
        match out.last_mut() {
            Some(l) if l.1 == s => l.1 = e,
            _ => out.push((s, e)),
        }
    }
    out
}

/// Data reference classification for rip-relative operands.
enum DataKind {
    Code,
    Import(u32),
    Str(u32),
    Const(u64),
    Global(u32),
    Vtable(u32),
    Other,
}

struct StringTable {
    map: HashMap<String, u32>,
    list: Vec<String>,
}

impl StringTable {
    fn id(&mut self, s: String) -> u32 {
        if let Some(&i) = self.map.get(&s) {
            return i;
        }
        let i = self.list.len() as u32;
        self.list.push(s.clone());
        self.map.insert(s, i);
        i
    }
}

fn read_string(pe: &Pe, rva: u32) -> Option<String> {
    let b = pe.cstr(rva, 2048)?;
    if b.len() >= 2 && b.len() < 2048 && b.iter().all(|&c| c == b'\t' || c == b'\n' || c == b'\r' || (0x20..0x7f).contains(&c) || c >= 0x80) {
        if let Ok(s) = std::str::from_utf8(b) {
            if s.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 1 {
                return Some(s.to_string());
            }
        }
    }
    // UTF-16LE
    let mut s = String::new();
    let mut o = rva;
    loop {
        let w = pe.bytes(o, 2)?;
        let c = u16::from_le_bytes([w[0], w[1]]);
        if c == 0 {
            break;
        }
        if !(0x20..0x7f).contains(&c) && c != 9 && c != 10 && c != 13 {
            return None;
        }
        s.push(c as u8 as char);
        o += 2;
        if s.len() > 1024 {
            return None;
        }
    }
    if s.len() >= 2 {
        Some(format!("L\"{}", s))
    } else {
        None
    }
}

struct FeatureCtx<'a> {
    pe: &'a Pe,
    import_by_iat: &'a HashMap<u32, u32>,
    func_index: &'a HashMap<u32, u32>,
    vtable_index: &'a HashMap<u32, u32>,
    strings_at: &'a HashMap<u32, u32>,
    istr_at: &'a HashMap<u32, Vec<u32>>,
}

impl<'a> FeatureCtx<'a> {
    fn classify(&self, t: u32, instr: &Instruction) -> DataKind {
        if let Some(&i) = self.import_by_iat.get(&t) {
            return DataKind::Import(i);
        }
        let Some(sec) = self.pe.section_of(t) else { return DataKind::Other };
        if sec.is_exec() {
            return DataKind::Code;
        }
        if let Some(&v) = self.vtable_index.get(&t) {
            return DataKind::Vtable(v);
        }
        if let Some(&s) = self.strings_at.get(&t) {
            return DataKind::Str(s);
        }
        if sec.is_writable() {
            return DataKind::Global(t);
        }
        if instr.mnemonic() != Mnemonic::Lea {
            let sz = instr.memory_size().size();
            if sz > 0 && sz <= 32 {
                if let Some(b) = self.pe.bytes(t, sz) {
                    let mut buf = Vec::with_capacity(sz + 1);
                    buf.push(sz as u8);
                    buf.extend_from_slice(b);
                    return DataKind::Const(xxh3_64(&buf));
                }
            }
        }
        DataKind::Other
    }
}

fn is_image_va(pe: &Pe, v: u64) -> bool {
    v >= pe.image_base && v < pe.image_base + pe.size_of_image as u64
}

/// Compute the features of one function from its decoded instructions.
fn features(fc: &FeatureCtx, entry: u32, d: &Decoded, f: &mut Func) {
    let pe = fc.pe;
    let insns = &d.insns;
    let n = insns.len();
    f.n_insn = n as u32;
    f.size = insns.iter().map(|i| i.len() as u32).sum();
    if n == 0 {
        return;
    }
    let ip_index: HashMap<u32, usize> = insns.iter().enumerate().map(|(k, i)| (i.ip() as u32, k)).collect();
    let in_fn = |t: u32| ip_index.contains_key(&t);

    // basic block leaders
    let mut leader = vec![false; n];
    leader[0] = true;
    for (k, i) in insns.iter().enumerate() {
        if k > 0 && insns[k - 1].next_ip() != i.ip() {
            leader[k] = true;
        }
        match i.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(&tk) = ip_index.get(&(i.near_branch_target() as u32)) {
                    leader[tk] = true;
                }
                if k + 1 < n {
                    leader[k + 1] = true;
                }
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Exception => {
                if k + 1 < n {
                    leader[k + 1] = true;
                }
            }
            _ => {}
        }
    }
    for t in &d.table_targets {
        if let Some(&tk) = ip_index.get(t) {
            leader[tk] = true;
        }
    }
    if let Some(&ek) = ip_index.get(&entry) {
        leader[ek] = true;
    }
    let block_of: Vec<u32> = {
        let mut b = 0u32;
        let mut v = Vec::with_capacity(n);
        for k in 0..n {
            if leader[k] && k > 0 {
                b += 1;
            }
            v.push(b);
        }
        v
    };
    let n_blocks = block_of[n - 1] + 1;
    f.n_blocks = n_blocks;

    let mut h_exact = Xxh3::new();
    let mut h_pic = Xxh3::new();
    let mut h_mnem = Xxh3::new();
    let mut h_cfg = Xxh3::new();
    let mut mnem_hist: HashMap<u16, u32> = HashMap::new();
    let mut block_h = Xxh3::new();
    let mut block_len = 0u32;
    let mut blocks: Vec<u32> = Vec::new();
    let mut edges = 0u32;
    let mut imms: Vec<u64> = Vec::new();
    let mut tok: Vec<u8> = Vec::with_capacity(64);

    for (k, i) in insns.iter().enumerate() {
        let ip = i.ip() as u32;
        if let Some(b) = pe.bytes(ip, i.len()) {
            h_exact.update(b);
        }
        let m = i.mnemonic() as u16;
        h_mnem.update(&m.to_le_bytes());
        *mnem_hist.entry(m).or_insert(0) += 1;

        // normalized token
        tok.clear();
        tok.extend_from_slice(&(i.code() as u16).to_le_bytes());
        let mut branch_delta: Option<i64> = None;
        for op in 0..i.op_count() {
            match i.op_kind(op) {
                OpKind::Register => tok.push(i.op_register(op) as u8),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    let t = i.near_branch_target() as u32;
                    if let Some(&tk) = ip_index.get(&t) {
                        tok.push(0xB1);
                        branch_delta = Some(tk as i64 - k as i64);
                    } else {
                        tok.push(0xB2);
                    }
                }
                OpKind::Memory => {
                    tok.push(0xA0);
                    tok.push(i.memory_base() as u8);
                    tok.push(i.memory_index() as u8);
                    tok.push(i.memory_index_scale() as u8);
                    tok.push(i.segment_prefix() as u8);
                    if i.is_ip_rel_memory_operand() {
                        let t = i.ip_rel_memory_address() as u32;
                        let kind = match fc.classify(t, i) {
                            DataKind::Code => 1u8,
                            DataKind::Import(_) => 2,
                            DataKind::Str(_) => 3,
                            DataKind::Const(_) => 4,
                            DataKind::Global(_) => 5,
                            DataKind::Vtable(_) => 6,
                            DataKind::Other => 7,
                        };
                        tok.push(kind);
                    } else {
                        let disp = i.memory_displacement64();
                        if is_image_va(pe, disp) || (i.memory_base() != Register::None && disp as u32 >= 0x1000 && pe.section_of(disp as u32).is_some() && i.memory_index_scale() > 1) {
                            // absolute address or [B+idx*4+table_rva]
                            tok.push(0xA1);
                        } else {
                            tok.extend_from_slice(&disp.to_le_bytes());
                        }
                    }
                }
                OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => {
                    let v = i.immediate(op);
                    if is_image_va(pe, v) {
                        tok.push(0xC1);
                    } else {
                        tok.push(0xC0);
                        tok.extend_from_slice(&v.to_le_bytes());
                        if (v as i64).unsigned_abs() >= 0x100 && !matches!(i.mnemonic(), Mnemonic::Sub | Mnemonic::Add) || (v as i64).unsigned_abs() >= 0x10000 {
                            imms.push(v);
                        }
                    }
                }
                _ => tok.push(0xEE),
            }
        }
        // block hash ignores branch deltas, the function hash includes them
        block_h.update(&tok);
        block_len += 1;
        h_pic.update(&tok);
        if let Some(dl) = branch_delta {
            h_pic.update(&dl.to_le_bytes());
        }

        // successors (for edge counts and CFG shape)
        let last_of_block = k + 1 == n || leader[k + 1];
        if last_of_block {
            let b = block_of[k] as i64;
            let mut succ: Vec<i64> = Vec::new();
            let ft = k + 1 < n && insns[k + 1].ip() == i.next_ip();
            match i.flow_control() {
                FlowControl::ConditionalBranch => {
                    if let Some(&tk) = ip_index.get(&(i.near_branch_target() as u32)) {
                        succ.push(block_of[tk] as i64 - b);
                    }
                    if ft {
                        succ.push(1);
                    }
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(&tk) = ip_index.get(&(i.near_branch_target() as u32)) {
                        succ.push(block_of[tk] as i64 - b);
                    }
                }
                FlowControl::IndirectBranch => {
                    // jump table: all table targets are successors of the last indirect jump block;
                    // approximated by counting them once per function below
                }
                FlowControl::Return | FlowControl::Exception => {}
                _ => {
                    if ft {
                        succ.push(1);
                    }
                }
            }
            edges += succ.len() as u32;
            h_cfg.update(&block_len.to_le_bytes());
            for s in &succ {
                h_cfg.update(&s.to_le_bytes());
            }
            h_cfg.update(&[0xff]);
            if block_len >= 3 {
                blocks.push(block_h.digest() as u32);
            }
            block_h = Xxh3::new();
            block_len = 0;
        }

        // return addresses of call sites (crash stacks report these)
        if matches!(i.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            f.call_rets.push(i.next_ip() as u32);
        }
        // references
        match i.flow_control() {
            FlowControl::Call => {
                let t = i.near_branch_target() as u32;
                f.refs.push(match fc.func_index.get(&t) {
                    Some(&fi) => Ref::Call(fi),
                    None => Ref::Interior(t),
                });
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                let t = i.near_branch_target() as u32;
                if !in_fn(t) {
                    f.refs.push(match fc.func_index.get(&t) {
                        Some(&fi) => Ref::Jump(fi),
                        None => Ref::Interior(t),
                    });
                }
            }
            FlowControl::IndirectCall | FlowControl::IndirectBranch => {
                let is_call = i.flow_control() == FlowControl::IndirectCall;
                if i.op0_kind() == OpKind::Memory {
                    if i.is_ip_rel_memory_operand() {
                        let t = i.ip_rel_memory_address() as u32;
                        if let Some(&imp) = fc.import_by_iat.get(&t) {
                            f.refs.push(if is_call { Ref::CallImport(imp) } else { Ref::JumpImport(imp) });
                        } else if is_call {
                            f.refs.push(Ref::CallIndirect);
                        }
                    } else if is_call {
                        f.refs.push(Ref::CallVirt(i.memory_displacement64() as u32));
                    }
                } else if is_call {
                    f.refs.push(Ref::CallIndirect);
                }
            }
            _ => {
                if i.is_ip_rel_memory_operand() {
                    let t = i.ip_rel_memory_address() as u32;
                    if let Some(ids) = fc.istr_at.get(&t) {
                        f.istrings.extend_from_slice(ids);
                    }
                    match fc.classify(t, i) {
                        DataKind::Code => {
                            if let Some(&fi) = fc.func_index.get(&t) {
                                f.refs.push(Ref::FnPtr(fi));
                            }
                        }
                        DataKind::Import(imp) => f.refs.push(Ref::CallImport(imp)),
                        DataKind::Str(s) => f.strings.push(s),
                        DataKind::Const(h) => f.consts.push(h),
                        DataKind::Global(g) => f.globals.push(g),
                        DataKind::Vtable(v) => f.vtrefs.push(v),
                        DataKind::Other => {}
                    }
                }
                // mov reg, imm64 absolute address
                for op in 0..i.op_count() {
                    if i.op_kind(op) == OpKind::Immediate64 {
                        let v = i.immediate64();
                        if is_image_va(pe, v) {
                            let t = (v - pe.image_base) as u32;
                            if let Some(&fi) = fc.func_index.get(&t) {
                                f.refs.push(Ref::FnPtr(fi));
                            }
                        }
                    }
                }
            }
        }
    }
    edges += d.table_targets.len() as u32;
    f.n_edges = edges;
    f.h_exact = h_exact.digest();
    f.h_pic = h_pic.digest();
    f.h_mnem = h_mnem.digest();
    let mut hist: Vec<(u16, u32)> = mnem_hist.into_iter().collect();
    hist.sort_unstable();
    let mut hb = Xxh3::new();
    for (m, c) in &hist {
        hb.update(&m.to_le_bytes());
        hb.update(&c.to_le_bytes());
    }
    f.h_mnem_bag = hb.digest();
    f.h_cfg = h_cfg.digest();
    blocks.sort_unstable();
    blocks.dedup();
    f.blocks = blocks;
    imms.sort_unstable();
    imms.dedup();
    imms.truncate(64);
    f.imms = imms;
    if d.unresolved > 0 {
        f.flags |= ff::UNRESOLVED_JMP;
    }
    if d.bad {
        f.flags |= ff::BAD_DECODE;
    }
}

/// Extract one build. `pdb` adds names (and PDB diagnostics) but never changes the function set.
pub fn extract(exe: &[u8], pdb: Option<&std::path::Path>, meta: BuildMeta) -> Result<Build> {
    let t0 = std::time::Instant::now();
    let pe = Pe::parse(exe)?;
    let mut stats = ExtractStats::default();
    let imports = pe.imports();
    let import_by_iat: HashMap<u32, u32> = imports.iter().enumerate().map(|(i, im)| (im.iat_rva, i as u32)).collect();
    let exports = pe.exports();
    let relocs = pe.relocs();

    let mut seeds: Vec<(u32, u16)> = vec![(pe.entry, ff::ENTRY)];
    for e in &exports {
        if pe.is_code(e.rva) {
            seeds.push((e.rva, ff::EXPORT));
        }
    }
    for &loc in &relocs {
        if pe.is_code(loc) {
            continue;
        }
        if let Some(t) = pe.u64(loc).and_then(|v| pe.va_to_rva(v)) {
            if pe.is_code(t) {
                seeds.push((t, ff::DATAPTR));
            }
        }
    }
    // C++ EH funclets from the FuncInfo of every function with a handler: (funclet, kind, parent)
    let mut eh: Vec<(u32, u8, u32)> = Vec::new();
    for rf in pe.pdata() {
        if rf.flags & 0x4 != 0 || rf.flags & 0x3 == 0 {
            continue;
        }
        for (r, k) in crate::eh::funclets(&pe, rf.unwind) {
            if r != rf.begin {
                eh.push((r, k, rf.begin));
            }
        }
    }
    eh.sort_unstable();
    eh.dedup_by_key(|x| x.0);
    stats.eh_funclets = eh.len() as u32;
    for &(r, _, _) in &eh {
        seeds.push((r, ff::EH_FUNCLET));
    }
    let npdata_starts: std::collections::HashSet<u32> = pe.pdata().iter().map(|r| r.begin).collect();
    stats.eh_funclets_new = eh.iter().filter(|x| !npdata_starts.contains(&x.0)).count() as u32;
    let (ctx, funcs) = discover(&pe, &mut stats, import_by_iat.clone(), &seeds);
    // seed flags also apply to pdata functions
    let mut seed_flags: HashMap<u32, u16> = HashMap::new();
    for &(t, f) in &seeds {
        *seed_flags.entry(t).or_insert(0) |= f;
    }

    let entries: Vec<(u32, Vec<(u32, u32)>, u16)> = funcs.into_iter().map(|(e, (rs, fl))| (e, rs, fl | seed_flags.get(&e).copied().unwrap_or(0))).collect();
    let func_index: HashMap<u32, u32> = entries.iter().enumerate().map(|(i, e)| (e.0, i as u32)).collect();
    // decode everything once more with the final function set, in parallel
    let decoded: Vec<Decoded> = entries
        .par_iter()
        .map(|(e, rs, _)| decode(&ctx, *e, Some(rs)))
        .collect();

    // string literals referenced by lea, assigned ids in address order of first reference
    let mut lea_targets: Vec<u32> = Vec::new();
    for d in &decoded {
        for i in &d.insns {
            if i.is_ip_rel_memory_operand() && i.mnemonic() == Mnemonic::Lea {
                let t = i.ip_rel_memory_address() as u32;
                if !pe.is_code(t) && !import_by_iat.contains_key(&t) {
                    lea_targets.push(t);
                }
            }
        }
    }
    lea_targets.sort_unstable();
    lea_targets.dedup();
    let vtables = pe.vtables(&relocs, &lea_targets);
    let vtable_index: HashMap<u32, u32> = vtables.iter().enumerate().map(|(i, v)| (v.rva, i as u32)).collect();
    let mut entries = entries;
    for vt in &vtables {
        for s in &vt.slots {
            if let Some(&fi) = func_index.get(s) {
                entries[fi as usize].2 |= ff::VTABLE;
            }
        }
    }
    let mut st = StringTable { map: HashMap::new(), list: Vec::new() };
    let mut strings_at: HashMap<u32, u32> = HashMap::new();
    for &t in &lea_targets {
        if vtable_index.contains_key(&t) {
            continue;
        }
        if let Some(s) = read_string(&pe, t) {
            strings_at.insert(t, st.id(s));
        }
    }
    // indirect strings: relocated pointers to strings inside the first 64 bytes of any data object
    // the code references (registration descriptors, static tables of names)
    let mut data_targets: Vec<u32> = Vec::new();
    for d in &decoded {
        for i in &d.insns {
            if i.is_ip_rel_memory_operand() {
                let t = i.ip_rel_memory_address() as u32;
                if !pe.is_code(t) && !import_by_iat.contains_key(&t) && !strings_at.contains_key(&t) && !vtable_index.contains_key(&t) {
                    data_targets.push(t);
                }
            }
        }
    }
    data_targets.sort_unstable();
    data_targets.dedup();
    let mut istr_at: HashMap<u32, Vec<u32>> = HashMap::new();
    for &t in &data_targets {
        let lo = relocs.partition_point(|&r| r < t);
        let mut ids = Vec::new();
        for &loc in relocs[lo..].iter().take_while(|&&r| r < t.saturating_add(64)) {
            if let Some(p) = pe.u64(loc).and_then(|v| pe.va_to_rva(v)) {
                if !pe.is_code(p) {
                    if let Some(s) = read_string(&pe, p) {
                        ids.push(st.id(s));
                    }
                }
            }
        }
        if !ids.is_empty() {
            istr_at.insert(t, ids);
        }
    }
    // data tables: runs of relocated code pointers in data sections (vtables, CRT initializer
    // tables, registration and dispatch tables); one NULL entry may sit inside a run
    let mut tables: Vec<Vec<u32>> = Vec::new();
    {
        let mut cur: Vec<u32> = Vec::new();
        let mut last: u32 = 0;
        for &loc in &relocs {
            if pe.is_code(loc) {
                continue;
            }
            let Some(t) = pe.u64(loc).and_then(|v| pe.va_to_rva(v)).filter(|&t| pe.is_code(t)) else { continue };
            let contiguous = !cur.is_empty() && (loc == last + 8 || (loc == last + 16 && pe.u64(last + 8) == Some(0)));
            if !contiguous {
                if cur.len() >= 2 {
                    tables.push(std::mem::take(&mut cur));
                }
                cur.clear();
            }
            cur.push(func_index.get(&t).copied().unwrap_or(u32::MAX));
            last = loc;
        }
        if cur.len() >= 2 {
            tables.push(cur);
        }
    }

    let fc = FeatureCtx { pe: &pe, import_by_iat: &import_by_iat, func_index: &func_index, vtable_index: &vtable_index, strings_at: &strings_at, istr_at: &istr_at };
    let mut out_funcs: Vec<Func> = entries
        .par_iter()
        .zip(decoded.par_iter())
        .map(|((e, rs, fl), d)| {
            let mut f = Func { rva: *e, ranges: rs.clone(), flags: *fl, eh_parent: u32::MAX, ..Default::default() };
            features(&fc, *e, d, &mut f);
            f
        })
        .collect();
    for &(r, k, parent) in &eh {
        if let (Some(&fi), Some(&pi)) = (func_index.get(&r), func_index.get(&parent)) {
            let f = &mut out_funcs[fi as usize];
            f.eh_parent = pi;
            f.eh_kind = k;
            f.flags |= ff::EH_FUNCLET;
        }
    }
    for d in &decoded {
        stats.jump_tables += d.jump_tables;
        stats.unresolved_indirect_jumps += d.unresolved;
        stats.bad_decodes += d.bad as u32;
    }

    // names
    let mut names: Vec<String> = Vec::new();
    let mut name_ids: HashMap<String, u32> = HashMap::new();
    let mut name_id = |s: &str, names: &mut Vec<String>| -> u32 {
        if let Some(&i) = name_ids.get(s) {
            return i;
        }
        let i = names.len() as u32;
        names.push(s.to_string());
        name_ids.insert(s.to_string(), i);
        i
    };
    let mut pdb_unmatched = Vec::new();
    let pn = match pdb.map(pdbnames::read) {
        Some(Ok(pn)) => Some(pn),
        Some(Err(e)) => {
            stats.pdb_error = Some(format!("{:#}", e));
            None
        }
        None => None,
    };
    if let Some(pn) = pn {
        stats.pdb_procs = pn.procs.len() as u32;
        stats.pdb_publics = pn.publics.len() as u32;
        let starts: Vec<u32> = out_funcs.iter().map(|f| f.rva).collect();
        for pr in &pn.procs {
            let id = name_id(&pr.name, &mut names);
            if let Ok(fi) = starts.binary_search(&pr.rva) {
                let f = &mut out_funcs[fi];
                f.names.push(id);
                f.flags |= ff::PDB_PROC;
                f.pdb_len = f.pdb_len.max(pr.len);
                stats.pdb_procs_at_func_start += 1;
            } else {
                if ctx.containing(pr.rva).is_some() {
                    stats.pdb_procs_inside_func += 1;
                } else {
                    stats.pdb_procs_outside += 1;
                }
                pdb_unmatched.push(model::PdbProc { rva: pr.rva, len: pr.len, name: id });
            }
        }
        for (rva, nm) in &pn.publics {
            if let Ok(fi) = starts.binary_search(rva) {
                let id = name_id(nm, &mut names);
                out_funcs[fi].publics.push(id);
            }
        }
    }

    let code_sections = pe.sections.iter().filter(|s| s.is_exec()).map(|s| (s.name.clone(), s.rva, s.vsize)).collect();
    let starts: Vec<u32> = out_funcs.iter().map(|f| f.rva).collect();
    let exports_rec = exports
        .iter()
        .map(|e| model::ExportRec { name: e.name.clone(), rva: e.rva, func: starts.binary_search(&e.rva).ok().map(|i| i as u32) })
        .collect();
    let vtables_rec = vtables
        .iter()
        .map(|v| model::VtableRec {
            rva: v.rva,
            type_name: v.type_name.clone(),
            offset: v.offset,
            slots: v.slots.iter().map(|s| starts.binary_search(s).map(|i| i as u32).unwrap_or(u32::MAX)).collect(),
        })
        .collect();
    // unwind info of the primary .pdata entry: stack frame layout survives most body edits
    let mut unwind_of: HashMap<u32, u32> = HashMap::new();
    for rf in pe.pdata() {
        if rf.flags & 0x4 == 0 {
            unwind_of.insert(rf.begin, rf.unwind);
        }
    }
    for f in out_funcs.iter_mut() {
        if let Some(&u) = unwind_of.get(&f.rva) {
            if let Some(hdr) = pe.bytes(u & !1, 4) {
                let n = 4 + hdr[2] as usize * 2;
                if let Some(b) = pe.bytes(u & !1, n) {
                    f.h_unwind = xxh3_64(b);
                }
            }
        }
    }
    stats.seconds = t0.elapsed().as_secs_f64();
    Ok(Build {
        format_version: model::FORMAT_VERSION,
        meta,
        image_base: pe.image_base,
        timestamp: pe.timestamp,
        code_sections,
        funcs: out_funcs,
        strings: st.list,
        imports: imports.into_iter().map(|i| model::ImportRec { dll: i.dll, name: i.name, iat_rva: i.iat_rva }).collect(),
        exports: exports_rec,
        vtables: vtables_rec,
        tables,
        names,
        pdb_unmatched,
        stats,
    })
}
