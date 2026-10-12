# File formats

All binary files are [postcard](https://docs.rs/postcard) serializations compressed with zstd.
The Rust structs in `src/model.rs` (`.fnx`) and `src/sigs.rs` (`.sig`) are the authoritative
definitions; postcard is not self-describing, so a file can only be read with the matching
format version (`format_version` / `format`), which the loaders check.

## corpus.json (`scan`)

`{ "builds": [BuildMeta...], "skipped": [[id, reason]...] }`, builds in timeline order (build
date from the version string). `BuildMeta`:

| field | meaning |
|---|---|
| `id` | `steam-<manifest>` or `gog-<directory>` |
| `platform` | `steam` or `gog` |
| `version` | `3.12.5`, or `?` when the build string is unknown |
| `build_string` | e.g. `Andromeda v3.12.5  00c910f0... (Jun 13 2024 15:58:38)` |
| `commit`, `build_date` | parsed from the build string (Steam and GOG builds of one version share the commit) |
| `exe_path`, `pdb_path` | inputs; `pdb_path` is null for stripped builds |
| `exe_md5`, `exe_size` | filled in by `extract` |

## `<build id>.fnx`: extract (`extract`, format 4)

`Build`:

| field | meaning |
|---|---|
| `meta` | BuildMeta (with `exe_md5`) |
| `image_base`, `timestamp`, `code_sections` | PE header data |
| `funcs` | functions sorted by RVA (below) |
| `strings` | string literals referenced by the code (UTF-8; wide strings prefixed `L"`) |
| `imports` | `dll`, `name`, `iat_rva` (normal and delay-load) |
| `exports` | `name` (MSVC-mangled), `rva`, `func` index |
| `vtables` | `rva`, RTTI `type_name` when present (Stellaris is mostly built without RTTI), `slots` (function indices, `u32::MAX` for non-functions) |
| `tables` | runs of relocated code pointers in data sections (vtables, CRT initializer tables, registration tables), function index per entry |
| `names` | PDB names; procedure names are undecorated, publics are mangled |
| `pdb_unmatched` | PDB procedures that do not start an extracted function (diagnostics) |
| `stats` | discovery statistics (see `ExtractStats`) |

`Func`:

| field | meaning |
|---|---|
| `rva`, `ranges` | entry and code chunks `[start, end)`: primary `.pdata` range first, then chained chunks |
| `flags` | `model::ff`: PDATA, CALLED, VTABLE, EXPORT, DATAPTR, ADDR_TAKEN, JUMPED, ENTRY, PDB_PROC, UNRESOLVED_JMP, BAD_DECODE, EH_FUNCLET |
| `size`, `n_insn`, `n_blocks`, `n_edges` | over the instructions reached by recursive descent (jump tables resolved) |
| `h_exact` | xxh3 of the raw instruction bytes |
| `h_pic` | position-independent hash: instruction forms, registers, immediates and non-RIP displacements; RIP-relative targets reduced to their kind (code, import, string, constant, global, vtable); intra-function branches as instruction-index deltas |
| `h_mnem`, `h_mnem_bag` | mnemonic sequence, sorted mnemonic histogram |
| `h_cfg` | CFG shape (block sizes and successor deltas) |
| `h_unwind` | hash of the primary UNWIND_INFO (prolog, frame register, unwind codes) |
| `blocks` | 32-bit hashes of basic blocks with at least 3 instructions |
| `refs` | outgoing references in address order: `Call`, `Jump` (tail), `CallImport`, `JumpImport`, `CallVirt(displacement)`, `CallIndirect`, `FnPtr`, `Interior` |
| `strings`, `istrings` | string ids referenced directly / through relocated pointers inside a referenced data object |
| `consts` | hashes of read-only data loaded by the code (size byte + bytes) |
| `globals` | RVAs of writable globals referenced |
| `vtrefs` | vtables whose address the code takes (constructors, destructors) |
| `imms` | notable immediates |
| `names`, `publics`, `pdb_len` | PDB data when the build has a PDB |
| `eh_parent`, `eh_kind` | for C++ EH funclets: the owning function (from its FH3/FH4 FuncInfo) and 1 = unwind, 2 = catch |

## `<build id>.sig`: per-executable signatures (`sigs`, format 1)

One file per executable; everything needed to match it, evaluated once. `SigFile`:

| field | meaning |
|---|---|
| `meta` | BuildMeta |
| `rva`, `end`, `size`, `n_insn` | function table (parallel arrays) |
| `eh_parent`, `eh_kind` | funclet owners |
| `names` | normalized PDB names per function (empty for stripped builds). Normalization: `<lambda_hash>` becomes `<lambda>`, `?A0x<hash>` becomes `?A0x`; EH funclet names are dropped |
| `sigs`, `funcs` | signatures unique within this executable, sorted ascending, with their function index |
| `kind_counts` | per kind: signatures generated, and kept after the uniqueness filter |

A signature is `kind << 58 | hash58`. Kinds (`sigs::kind`):

| kind | value |
|---|---|
| 0 exact, 1 pic, 2 mnem, 3 bagcfg, 4 unwind | code-shape hashes (bagcfg = mnemonic histogram + CFG; unwind with block count) |
| 5 block | one per basic block hash |
| 6 str, 7 strset, 8 istr | each string, the sorted string set, each indirect string |
| 9 const, 10 imm, 11 imports, 12 export | constants, immediates, import set (with size class), export name |
| 13 callee_shapes, 14 caller_shapes, 15 wl1, 16 layout3 | label-free structure: PIC hashes of callees / callers, a one-step Weisfeiler-Lehman colour, mnemonic bags of the previous/own/next function |
| 20 + r | anchored relation `r`: the neighbour is identified by one of its own unique code/data signatures (up to two anchors per function) |
| 40 + r | symbol relation `r`: the neighbour is identified by the hash of its (smallest) PDB name; present in PDB builds, and generated for targets from assigned names |

Relations `r`: 0 callee ordinal (with the callee's shape), 1 caller (with the caller's PIC
hash), 2 call set, 3 consecutive callee pair, 4 thunk target, 5 vtable slot (by slot 0 or by a
function taking the vtable's address), 6/7 code-layout neighbour before/after (offset and own
shape, reach 4), 8/9 data-table neighbour before/after, 10 shared writable global (ordinal and
own shape), 11 function pointer taken.

## Labels: `runs/<run>/labels/<build id>.csv` (`match`, `solve`)

`rva,end,size,score,second,round,evidence,label`, one row per function. `label` is empty when
the function was not labelled; several names (identical code folded by the linker) are joined
with ` | `; EH funclets carry their owner's label with ` [unwind funclet]` / ` [catch funclet]`.
`score` is the weighted signature count of the label, `second` that of the best competing label,
`evidence` the signature kinds that supported it, `round` the pass that assigned it.

## `runs/<run>/export.csv` (`match`)

`build_id,version,platform,exe_md5,start_va,end_va,score,evidence,symbol` for every labelled
function of every target, with virtual addresses (image base 0x140000000 + RVA) like the
stellar-fnaddr tables, ready for loading into a new table.
