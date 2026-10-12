# stellar-fnmatch: corpus-wide function identity matching

Goal: for every function in every Stellaris Windows build we have, decide which *source function*
it is, using all builds at once, so a stripped Steam build can be labelled with symbol names from
the PDB builds. Output feeds the exception translator (stellar-except), which needs
`(steam build, function start address) -> symbol name`.

## Why the current method falls short

The translator today matches one Steam build against the GOG build (with PDB) of the same version,
by Kaiju fn2hash equality, trying hash types in order and taking the first match. Measured on 3.8.4:

| | GOG (PDB) | Steam (stripped) |
|---|---|---|
| functions Ghidra created | 98,717 (98% named by the PDB) | 65,368 |
| `.pdata` unwind entries | 91,549 | 91,743 |
| PIC hash unique within the build | | 42,375 of 65,145 |

- About a third of Steam functions never exist in the Ghidra analysis (no PDB to seed function
  starts), so they cannot be matched at all, although the translator takes its function bounds from
  `.pdata`.
- Of the ones that exist, about a third have a PIC hash that is not unique in their own build
  (thunks, getters, destructors, template instances), so equality matching is ambiguous.
- Every pair is solved from zero, with only that pair's evidence, and only where a same-version PDB
  build exists.

## The idea

Treat the whole corpus as one graph and solve for identity classes globally instead of pairwise.

- Node: `(build, function)`. About 200 Windows builds (Steam manifests including betas, GOG builds)
  at roughly 100k functions each, so on the order of 20M nodes.
- Edges inside a build: calls (caller to callee, with call-site counts), references to string
  literals, imported APIs, globals, vtables (functions that share a table, and their slot).
- Identity class: a set of nodes, at most one per build, that are the same source function. A class
  takes its name from any PDB build among its members. Members of one class with different PDB names
  are either renames or mistakes, which makes this a built-in correctness check.

Why corpus-wide wins over pairwise:

1. Uniqueness is measured against everything. A weak fingerprint (say a mnemonic-count hash) that
   occurs exactly once in each of 40 builds is a strong anchor; inside a single pair it is
   indistinguishable from coincidence.
2. Evidence chains through versions. A function that changed a lot between 3.9 and 4.5 is still
   linked through the intermediate builds, where each step is small.
3. Ambiguity in one build is resolved by structure learned in the others: once callers and callees
   are anchored, a function that is one of ten identical-hash thunks usually has a unique
   neighbourhood.
4. After solving, each class gets a *discriminating signature*: the smallest set of keys that is
   unique within every build. Those signatures form an index that labels a brand-new build (the next
   patch) in seconds, without re-solving the corpus.

## Algorithm (seed and extend, iterated to a fixed point)

### Keys

Each function gets many keys (u64 hashes), each tagged with its key type:

- code shape: exact hash, PIC hash, composite PIC hash, mnemonic / category count hashes (Kaiju or
  recomputed), size bucket, basic blocks, CFG edges, loops
- semantics: each referenced string literal, the sorted set of them, imported APIs called, rare
  immediate constants, export name (stellaris.exe exports PHYSFS_* etc.), vtable membership
- relational, recomputed every iteration from the current classes: the multiset of
  `(edge type, neighbour class)`. This is a Weisfeiler-Lehman style colour, but built from anchored
  identities instead of raw refined colours, so one changed neighbour does not cascade into every
  colour around it.

### Seeding

For each key type and value, count occurrences per build. A value is an anchor when it occurs in at
least two builds and exactly once in each build where it occurs. A value that is unique in most
builds but repeated in a few can still link the builds where it is unique, at a lower weight.

Join nodes that share an anchor value with a union-find that enforces "at most one member per build".
A join that would put two functions of the same build in one class is refused and recorded as a
conflict; conflicts lower the trust in that key value and key type.

### Propagation

- Neighbourhood matching: for an unassigned node, candidate classes are the classes reachable
  through its anchored neighbours (callees of its callers, callers of its callees). Score the
  candidates by weighted overlap of neighbour classes plus local similarity (size, mnemonic
  histogram), and accept only a unique best with a margin, into a class with no member from this
  build yet.
- Local uniqueness: among the callees of one anchored function (or the slots of one vtable), a hash
  that is common globally is usually unique, so match those directly (as BinDiff does).
- Layout alignment: builds of the same commit (the Steam and GOG builds of one version) and adjacent
  versions often keep function order. Align the address-ordered key sequences (patience or LCS diff)
  and accept aligned runs between anchors. Cheap, and very strong for same-commit pairs.

Repeat until an iteration assigns nothing new. Every assignment records its evidence (key types,
score, iteration), which becomes its confidence.

## Function boundaries

x64 PE `.pdata` gives compiler-exact ranges for every non-leaf function (chained entries are
chunks of a parent function and should be merged into it). Use `.pdata` as the authoritative
function list for stripped builds and add leaf functions from Ghidra. The Ghidra export should also
create functions at `.pdata` starts before analysis so their code features exist.

## Inputs

A new Ghidra export (Java GhidraScript for speed) run headless with `-process -noanalysis` against
the projects the analysis batch already saved, so nothing has to be re-analysed. Per build:

- per function: entry, body ranges, size, basic blocks / edges / instructions, Kaiju hashes,
  mnemonic histogram, PDB name when present
- callees with call-site counts, referenced strings (content), referenced imports, notable
  immediates, data references
- `.pdata` table, exports, vtables

Format: one compressed file per build with a documented schema (JSONL+zstd is simplest; a compact
binary is fine if load time matters).

## Outputs

- per build: `address -> class id, symbol name, confidence, evidence`, as CSV ready to load into a
  new table of the stellar-fnaddr database (loading is a separate, approved step)
- the class signature index, for labelling new builds
- an evaluation report

## Evaluation

- Leave-one-out on PDB builds: hide the names of GOG build X, solve, compare predicted with real
  names per confidence bucket, and plot precision against recall. Use several X (old, middle, new).
- Steam builds of 3.4.3 to 3.8.4: compare coverage and disagreements with the existing fn2hash
  results in stellar-fnaddr.
- End to end: the ~650 uploaded exception.txt files for 3.9 to 3.12.5 in
  `/var/www/html/stellar-except/exceptions/` on hippo.

## Scale and implementation

- About 20M nodes and a few hundred million edges: keep it compact. Use per-build CSR adjacency with
  u32 local ids, keys as u64 (xxh3) in sorted vectors, a union-find over global u32 ids, and no
  per-node heap allocation. That should fit in tens of GB (hippo has 125 GB, the second box 62 GB).
- Rust: rayon for per-build and per-key-type parallelism, memory-mapped inputs.
- Shape: a core library crate plus a CLI with `ingest`, `solve`, `eval`, `index`, `match` (a new
  build against the index) and `export`.

## Implementation notes (October 2026)

What the data changed relative to the plan above:

- **No Ghidra.** A native extractor (Rust, `iced-x86`, `pdb` crate) replaces the Ghidra export.
  It covers all 242 x64 builds in about 10 minutes instead of about an hour per build, and its
  function list (from `.pdata`, call/jump/pointer reachability and EH metadata) covers about 99%
  of the non-funclet PDB procedures, against Ghidra's 65k of about 92k functions on stripped
  builds.
- **RTTI is mostly absent** (about 770 type descriptors, nearly all for exception types), so
  vtables are found as tables of relocated code pointers whose address the code takes.
- **C++ EH funclets matter for crash reports**: unwind funclets appear in many uploaded stacks.
  They are found through the FH4 (`__CxxFrameHandler4`) and FH3 FuncInfo of every function and
  inherit their owner's name.
- **Per-executable signatures** (the user's refinement) instead of a global union-find: each
  executable is evaluated once into a file of signatures unique inside it, and matching takes,
  per function, the name with the most signatures. Relations without names are kept by
  identifying a neighbour through one of its own unique signatures (its anchor).
- **"Unique in every version" per signature**: a signature counts fully only when all PDB builds
  that contain it agree on the name. Without that rule, layout and table-position signatures
  of near-identical functions (static initializers, template instances) shift by one between
  versions and produce most of the errors.
- **Name normalization**: lambda hashes and anonymous-namespace hashes change between builds and
  are normalized; some names are inherently unstable (counter-numbered `CONSOLEVAR_N`).
- The corpus-wide solver (`solve`) is kept. On the 3.9 to 3.12 subset it reached similar accuracy;
  it can also chain names through other stripped builds, which may help builds far from any PDB
  build (2.4 to 2.8), but that has not been measured.
