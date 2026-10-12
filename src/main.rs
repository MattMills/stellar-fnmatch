use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fnmatch::{corpus, extract, model};
use md5::{Digest, Md5};
use rayon::prelude::*;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "stellar-fnmatch", about = "Corpus-wide function matching for Stellaris Windows builds")]
struct Cli {
    /// worker threads (default: all cores)
    #[arg(long, global = true)]
    threads: Option<usize>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enumerate the Steam and GOG archives into a corpus file
    Scan {
        #[arg(long, default_value = "/zpool0/share/stellaris_backups_steam/by_manifest/281992")]
        steam: PathBuf,
        #[arg(long, default_value = "/zpool0/share/stellaris_backups_gog")]
        gog: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Extract builds listed in a corpus file (skips builds whose .fnx exists unless --force)
    Extract {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// only these build ids (comma separated)
        #[arg(long)]
        only: Option<String>,
        /// builds extracted concurrently (each one is parallel inside)
        #[arg(long, default_value_t = 2)]
        jobs: usize,
        #[arg(long)]
        force: bool,
    },
    /// Extract one executable (and optional PDB) to a .fnx file
    ExtractOne {
        #[arg(long)]
        exe: PathBuf,
        #[arg(long)]
        pdb: Option<PathBuf>,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "steam")]
        platform: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print statistics of extracted builds
    Info {
        files: Vec<PathBuf>,
        /// also print the function at this RVA (hex)
        #[arg(long)]
        func: Option<String>,
        /// print a sample of N PDB procedures that are not extracted functions
        #[arg(long, default_value_t = 0)]
        unmatched: usize,
    },
}

fn md5_hex(b: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{:02x}", x)).collect()
}

fn extract_meta(meta: &model::BuildMeta, out: &Path) -> Result<model::Build> {
    let exe = std::fs::read(&meta.exe_path).with_context(|| format!("read {}", meta.exe_path))?;
    let mut meta = meta.clone();
    meta.exe_md5 = md5_hex(&exe);
    meta.exe_size = exe.len() as u64;
    let pdb = meta.pdb_path.clone().map(PathBuf::from);
    let b = extract::extract(&exe, pdb.as_deref(), meta)?;
    b.save(out)?;
    Ok(b)
}

fn summary(b: &model::Build) -> String {
    let s = &b.stats;
    let named = b.funcs.iter().filter(|f| !f.names.is_empty()).count();
    format!(
        "{} v{} funcs={} (pdata {} leaf {}) pdata_entries={} chained={} unresolved_chain={} jt={} unres_ijmp={} interior={} bad={} strings={} vtables={} pdb_procs={} at_start={} inside={} outside={} named={} {:.1}s",
        b.meta.id, b.meta.version, b.funcs.len(), s.funcs_pdata, s.funcs_leaf, s.pdata_entries, s.pdata_chained, s.pdata_chain_unresolved, s.jump_tables,
        s.unresolved_indirect_jumps, s.interior_refs, s.bad_decodes, b.strings.len(), b.vtables.len(), s.pdb_procs, s.pdb_procs_at_func_start,
        s.pdb_procs_inside_func, s.pdb_procs_outside, named, s.seconds
    )
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(t) = cli.threads {
        rayon::ThreadPoolBuilder::new().num_threads(t).build_global()?;
    }
    match cli.cmd {
        Cmd::Scan { steam, gog, out } => {
            let c = corpus::scan(&steam, &gog)?;
            eprintln!("{} x64 builds ({} with pdb), {} skipped", c.builds.len(), c.builds.iter().filter(|b| b.pdb_path.is_some()).count(), c.skipped.len());
            std::fs::write(&out, serde_json::to_string_pretty(&c)?)?;
        }
        Cmd::Extract { corpus, out_dir, only, jobs, force } => {
            let c: corpus::Corpus = serde_json::from_str(&std::fs::read_to_string(&corpus)?)?;
            std::fs::create_dir_all(&out_dir)?;
            let only: Option<Vec<String>> = only.map(|s| s.split(',').map(|x| x.to_string()).collect());
            let todo: Vec<&model::BuildMeta> = c
                .builds
                .iter()
                .filter(|b| only.as_ref().map_or(true, |o| o.contains(&b.id)))
                .filter(|b| force || !out_dir.join(format!("{}.fnx", b.id)).exists())
                .collect();
            eprintln!("{} builds to extract", todo.len());
            let pool = rayon::ThreadPoolBuilder::new().num_threads(jobs).build()?;
            pool.install(|| {
                todo.par_iter().for_each(|m| {
                    let out = out_dir.join(format!("{}.fnx", m.id));
                    match extract_meta(m, &out) {
                        Ok(b) => eprintln!("{}", summary(&b)),
                        Err(e) => eprintln!("{} FAILED: {:#}", m.id, e),
                    }
                })
            });
        }
        Cmd::ExtractOne { exe, pdb, id, platform, out } => {
            let meta = model::BuildMeta {
                id,
                platform,
                version: "?".into(),
                exe_path: exe.to_string_lossy().into_owned(),
                pdb_path: pdb.map(|p| p.to_string_lossy().into_owned()),
                ..Default::default()
            };
            let b = extract_meta(&meta, &out)?;
            eprintln!("{}", summary(&b));
        }
        Cmd::Info { files, func, unmatched } => {
            for f in files {
                let b = model::Build::load(&f)?;
                println!("{}", summary(&b));
                if unmatched > 0 {
                    let mut by_len: std::collections::BTreeMap<u32, u32> = Default::default();
                    for p in &b.pdb_unmatched {
                        *by_len.entry(p.len.min(64)).or_insert(0) += 1;
                    }
                    println!("unmatched by len (capped 64): {:?}", by_len);
                    let real: Vec<&model::PdbProc> = b.pdb_unmatched.iter().filter(|p| !b.names[p.name as usize].starts_with('`')).collect();
                    println!("unmatched {} of which not EH funclets {}", b.pdb_unmatched.len(), real.len());
                    let step = (real.len() / unmatched).max(1);
                    for p in real.iter().step_by(step).take(unmatched) {
                        let near = b.funcs.partition_point(|f| f.rva <= p.rva);
                        let prev = near.checked_sub(1).map(|i| (b.funcs[i].rva, b.funcs[i].ranges.clone()));
                        println!("  {:08x} len {:5} {}  prev={:x?}", p.rva, p.len, b.names[p.name as usize], prev);
                    }
                }
                if let Some(rva) = &func {
                    let rva = u32::from_str_radix(rva.trim_start_matches("0x"), 16)?;
                    if let Some(i) = b.func_containing(rva) {
                        let fx = &b.funcs[i];
                        println!("{:#?}", fx);
                        for n in &fx.names {
                            println!("name: {}", b.names[*n as usize]);
                        }
                        for s in &fx.strings {
                            println!("str: {:?}", b.strings[*s as usize]);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
