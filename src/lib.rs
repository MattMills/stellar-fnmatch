//! stellar-fnmatch: corpus-wide function identity matching across Stellaris Windows builds.
//!
//! Pipeline: `corpus` (inventory) -> `extract` (per-build features, `model::Build`) ->
//! `corpusdb` (compact in-memory corpus) -> `solve` (fingerprints, global uniqueness, name voting,
//! relational iteration) -> `eval` / outputs.

pub mod corpus;
pub mod corpusdb;
pub mod eh;
pub mod eval;
pub mod exceptions;
pub mod extract;
pub mod matcher;
pub mod model;
pub mod pdbnames;
pub mod pe;
pub mod sigs;
pub mod solve;
