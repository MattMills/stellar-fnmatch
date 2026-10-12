# stellar-fnmatch

Function matching for Stellaris Windows builds. It labels the functions of stripped
executables (Steam) with symbol names from the executables that ship a PDB (GOG, and a few
early Steam builds), using all of them at once. The output feeds the stellar-except exception
translator ([public web app](https://github.com/MattMills/stellar-except-web)), which needs
`(steam build, function address) -> symbol name`.

Standalone Rust: its own PE/x64 reader (`.pdata`, imports, exports, relocations, C++ EH
metadata), `iced-x86` disassembly and the `pdb` crate. No Ghidra or IDA.

## How it works

1. **Extract** (`extract`): each executable becomes a feature file (`.fnx`). Function bounds come
   from `.pdata` (chained entries merged into their parent), plus leaf functions reached by calls,
   tail jumps, address-taken code and relocated pointers, plus C++ EH funclets from the FH3/FH4
   FuncInfo of every function (each funclet records its owning function). Per function:
   code-shape hashes, basic blocks, strings (direct and through data objects), constants,
   immediates, imports, exports, callees, vtables, data tables and referenced globals.
2. **Signatures** (`sigs`): each executable is evaluated once into a `.sig` file holding every
   signature that is unique inside that executable, attached to the function address and, for
   PDB builds, its names:
   - code and data: exact / position-independent / mnemonic / CFG hashes, basic blocks, strings,
     constants, immediates, imports, exports
   - structure without names: callee and caller shapes, a Weisfeiler-Lehman colour, layout
   - relations anchored on a neighbour's own unique signature: callee ordinal, caller, call set,
     vtable slot, code-layout and data-table neighbours, shared globals, function pointers
   - in PDB builds, the same relations anchored on the neighbour's symbol name
3. **Match** (`match`): every signature of a stripped executable is looked up in all PDB builds.
   A signature counts fully when every PDB build that has it agrees on the name ("unique in
   every version"), and half for the name in the nearest build when they disagree. Each
   function takes the name supported by the most signatures (weighted by kind, tiny functions
   damped), the latest version breaking ties, if it clearly beats the runner-up and the name
   is not already taken in that executable. The names found then identify neighbours for
   symbol-relation signatures in the next pass, until nothing changes. EH funclets take their
   owner's name.

A corpus-wide solver (`solve`) with the same keys is also included: it votes from the nearest
labelled builds on the timeline and iterates over all builds together, including stripped
builds as intermediate links.

## Commands

```
stellar-fnmatch scan --out corpus.json
stellar-fnmatch extract --corpus corpus.json --out-dir extract
stellar-fnmatch sigs --corpus corpus.json --extract-dir extract --out-dir sigs
stellar-fnmatch match --corpus corpus.json --extract-dir extract --sig-dir sigs --out-dir runs/all
stellar-fnmatch match ... --holdout <pdb build ids> [--holdout-series]     # leave-one-out scoring
stellar-fnmatch extract-one --exe new/stellaris.exe --id new --out new.fnx  # a new patch:
stellar-fnmatch match ... --target-fnx new.fnx --out-dir runs/new
stellar-fnmatch exceptions --corpus corpus.json --extract-dir extract --labels-dir runs/all/labels \
    --input <exception.txt dir> --out-dir <private dir>
stellar-fnmatch info extract/<build>.fnx [--func <rva>|#<index>] [--dump-names]
```

Outputs are described in [SCHEMA.md](SCHEMA.md). `runs/<run>/export.csv` lists every labelled
function of every target with virtual addresses, ready to load into a database table.

## Results

Corpus: 242 x64 executables (117 Steam, 125 GOG; 115 with a PDB), 2.3.0 to 4.5.2. The 32-bit
builds (1.0 to 2.2.7) are not handled.

Leave-one-out with `match`: nine PDB builds held out together (none of them used as a reference),
each matched against the other 106 PDB builds. "Core" excludes compiler-generated static
initializers and atexit destructors, which are near-identical stubs reached only through the
CRT initializer table.

| held out | precision | recall | recall (core) |
|---|---|---|---|
| GOG 3.0.1 | 99.80% | 74.6% | 99.1% |
| GOG 3.4.5 | 99.88% | 83.8% | 98.8% |
| GOG 3.8.4 | 99.72% | 80.2% | 98.9% |
| GOG 3.11.2 | 99.97% | 89.6% | 98.8% |
| GOG 3.12.5 | 99.86% | 89.0% | 99.0% |
| GOG 4.0.23 | 99.82% | 88.5% | 97.8% |
| GOG 4.3.3 | 99.88% | 73.8% | 96.9% |
| GOG 4.5.2 | 99.52% | 74.2% | 97.9% |
| Steam 2.3.3 (PDB) | 99.96% | 80.2% | 98.9% |

Matching one executable takes 6 to 15 s once the 106 reference signature files (616M
signatures, about 9 GB) are loaded.

## License

MIT
