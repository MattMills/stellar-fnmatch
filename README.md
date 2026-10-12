# stellar-fnmatch

Corpus-wide function matching for Stellaris Windows builds. It labels the functions of stripped
builds (Steam) with symbol names from the builds that ship a PDB (GOG, and a few early Steam
builds), using every build at once instead of one pair at a time. The output feeds the
stellar-except exception translator ([public web app](https://github.com/MattMills/stellar-except-web)), which needs
`(steam build, function address) -> symbol name`.

Standalone: a Rust PE/x64 extractor (`.pdata`, imports, exports, relocations, `iced-x86`
disassembly, PDB names via the `pdb` crate). No Ghidra or IDA needed.

## How it works

1. **Extract** each build into a compact feature file (`.fnx`, postcard + zstd). Function bounds
   come from `.pdata` (chained entries merged into their parent), plus leaf functions reached by
   calls, tail jumps, address-taken code and relocated pointers. Each function gets code-shape
   hashes (exact, position-independent, mnemonic sequence and histogram, CFG shape, unwind info,
   basic blocks), referenced strings, strings reached through data objects, read-only constants,
   immediates, imports, exports, callees, vtable and data-table membership, and referenced globals.
2. **Fingerprints.** Every feature becomes a key. A key value votes for a function only when it
   occurs exactly once in that function's build, and the nearest builds on the timeline (before
   and after) where it also occurs exactly once on a named function agree on the name. Keys that
   are unique in every build carry full weight.
3. **Relational keys**, recomputed each round from the current labels: callee ordinal and shape
   under a named caller, caller shape over a named callee, call sets and pairs, thunks, vtable
   slots, code-layout and data-table neighbours (combined with the function's own shape), globals
   shared with a named function, and BinDiff-style residual matching of the unclaimed
   callers/callees against the nearest PDB builds.
4. **Decide** per function: the best label has to reach a score threshold and beat the runner-up
   by a margin, and a name can be claimed only as many times per build as it occurs in the PDB
   builds. Iterate until labels stop changing.

## Commands

```
stellar-fnmatch scan --out corpus.json                    # inventory the Steam and GOG archives
stellar-fnmatch extract --corpus corpus.json --out-dir extract
stellar-fnmatch solve --corpus corpus.json --extract-dir extract --out-dir runs/X [--holdout <pdb build ids>]
stellar-fnmatch exceptions --corpus corpus.json --extract-dir extract --labels-dir runs/X/labels --input <dir> --out-dir <private dir>
stellar-fnmatch info extract/<build>.fnx [--func <rva>|#<index>]
```

`solve --holdout` treats PDB builds as stripped and scores the predicted names against their
real ones (leave-one-out).

## Results so far

Corpus: 242 x64 builds (117 Steam, 125 GOG; 115 with a PDB), 2.3.0 to 4.5.2. 32-bit builds
(1.0 to 2.2.7) are not handled.

Leave-one-out on the 3.9 to 3.12 builds (41 builds):

| held out | precision | recall | recall without static init/atexit |
|---|---|---|---|
| GOG 3.11.2 alone | 100.00% (55,062 of 55,062) | 88.2% | about 98% |
| whole 3.11 series and 3.12.5 together | 99.92 to 99.97% | 85.5 to 85.6% | |

Most misses are compiler-generated static initializers and atexit destructors, whose code is
identical and which only the CRT initializer table references.

Crash reports (exception.txt uploads, 3.8 to 3.12.5): 95% of the stack frames that fall inside a
function get a name. Most of the rest fall in C++ EH unwind funclets, which the EH metadata parser
in `src/eh.rs` will attribute to their parent function.

See [DESIGN.md](DESIGN.md) for the original design notes.

## License

MIT
