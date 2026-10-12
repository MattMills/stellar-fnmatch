//! stellar-fnmatch: corpus-wide function identity matching across Stellaris Windows builds.
//!
//! Pipeline: `corpus` (inventory) -> `extract` (per-build features, `model::Build`) ->
//! `solve` (fingerprints, global uniqueness, name voting, relational iteration) -> outputs.

pub mod corpus;
pub mod extract;
pub mod model;
pub mod pdbnames;
pub mod pe;
