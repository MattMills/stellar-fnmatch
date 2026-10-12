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
    /// Solve the whole corpus: label every function of every stripped build
    Solve {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        extract_dir: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// PDB builds to treat as stripped and score (comma separated build ids)
        #[arg(long)]
        holdout: Option<String>,
        /// only builds whose version is in [min, max] (e.g. 3.9 and 3.12.99)
        #[arg(long)]
        min_version: Option<String>,
        #[arg(long)]
        max_version: Option<String>,
        #[arg(long)]
        rounds: Option<usize>,
        /// parameter overrides as JSON (see solve::Params)
        #[arg(long)]
        params: Option<String>,
        /// threads used for loading extracts
        #[arg(long, default_value_t = 8)]
        load_threads: usize,
        /// do not write per-build label CSVs
        #[arg(long)]
        no_labels: bool,
    },
    /// Evaluate each executable once into a signature file (.sig): functions, PDB names and every
    /// signature that is unique inside that executable
    Sigs {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        extract_dir: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        only: Option<String>,
        #[arg(long, default_value_t = 2)]
        jobs: usize,
        #[arg(long)]
        force: bool,
    },
    /// Match stripped executables against the signature files of the PDB builds
    Match {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        extract_dir: PathBuf,
        #[arg(long)]
        sig_dir: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// PDB builds to treat as stripped: they are matched and scored, and not used as references
        #[arg(long)]
        holdout: Option<String>,
        /// with --holdout: also drop every reference build of the same version (major.minor)
        #[arg(long)]
        holdout_series: bool,
        /// targets (comma separated); default: all builds without PDB names (or the holdouts)
        #[arg(long)]
        targets: Option<String>,
        #[arg(long)]
        params: Option<String>,
        #[arg(long, default_value_t = 8)]
        load_threads: usize,
    },
    /// Resolve stellaris.exe frames of exception.txt files to labelled functions (end-to-end check)
    Exceptions {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        extract_dir: PathBuf,
        /// labels/ directory of a solve
        #[arg(long)]
        labels_dir: PathBuf,
        /// directory searched recursively for *.txt
        #[arg(long)]
        input: PathBuf,
        /// output directory (per-frame CSV and summary); keep it private
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 2.0)]
        hi_score: f32,
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
    if meta.version == "?" || meta.commit.is_none() {
        // the build string is embedded in the executable: "<name> v<ver> [tag] <32 hex> (<date>)"
        let re = regex::bytes::Regex::new(r"[A-Za-z ]{0,20} v\d+\.\d+(?:\.\d+)*[ -][ -~]{0,40}?[0-9a-f]{32} \([A-Z][a-z]{2} +\d{1,2} \d{4} \d\d:\d\d:\d\d\)").unwrap();
        if let Some(m) = re.find(&exe) {
            let s = String::from_utf8_lossy(m.as_bytes()).trim().to_string();
            let (v, c, d) = corpus::parse_build_string(&s);
            meta.build_string = s;
            meta.version = v;
            meta.commit = c;
            meta.build_date = d;
        }
    }
    let pdb = meta.pdb_path.clone().map(PathBuf::from);
    let b = extract::extract(&exe, pdb.as_deref(), meta)?;
    b.save(out)?;
    Ok(b)
}

fn summary(b: &model::Build) -> String {
    let s = &b.stats;
    let named = b.funcs.iter().filter(|f| !f.names.is_empty()).count();
    format!(
        "{} v{} funcs={} (pdata {} leaf {} eh_funclets {} new {}) pdata_entries={} chained={} unresolved_chain={} jt={} unres_ijmp={} interior={} bad={} strings={} vtables={} pdb_procs={} at_start={} inside={} outside={} named={} {:.1}s",
        b.meta.id, b.meta.version, b.funcs.len(), s.funcs_pdata, s.funcs_leaf, s.eh_funclets, s.eh_funclets_new, s.pdata_entries, s.pdata_chained, s.pdata_chain_unresolved, s.jump_tables,
        s.unresolved_indirect_jumps, s.interior_refs, s.bad_decodes, b.strings.len(), b.vtables.len(), s.pdb_procs, s.pdb_procs_at_func_start,
        s.pdb_procs_inside_func, s.pdb_procs_outside, named, s.seconds
    )
}

/// Per target build: `rva,end,size,score,second,round,evidence,label` (label = names joined by " | ").
fn write_labels(s: &fnmatch::solve::Solver, dir: &Path) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let db = &*s.db;
    for (bi, b) in db.builds.iter().enumerate() {
        if !s.target[bi] {
            continue;
        }
        let f = std::fs::File::create(dir.join(format!("{}.csv", b.meta.id)))?;
        let mut w = std::io::BufWriter::new(f);
        writeln!(w, "rva,end,size,score,second,round,evidence,label")?;
        for k in 0..b.n {
            let mut a = s.assign[db.gid(bi, k) as usize];
            if a.reject != fnmatch::solve::reject::NONE {
                a = Default::default();
            }
            let end = b.ranges.row(k).first().map_or(b.rva[k], |r| r.1);
            let mut label = if a.set != 0 { db.labels.display(a.set).replace('"', "\"\"") } else { String::new() };
            // EH funclets take the name of the function that owns them
            if a.set == 0 && b.eh_parent[k] != u32::MAX {
                let mut p = b.eh_parent[k];
                for _ in 0..4 {
                    if p == u32::MAX {
                        break;
                    }
                    let pa = s.assign[db.gid(bi, p as usize) as usize];
                    if pa.set != 0 && pa.reject == fnmatch::solve::reject::NONE {
                        let what = if b.eh_kind[k] == fnmatch::eh::KIND_CATCH { "catch funclet" } else { "unwind funclet" };
                        label = format!("{} [{}]", db.labels.display(pa.set), what).replace('"', "\"\"");
                        a = pa;
                        a.types = 0;
                        break;
                    }
                    p = b.eh_parent[p as usize];
                }
            }
            writeln!(
                w,
                "0x{:x},0x{:x},{},{:.3},{:.3},{},{},\"{}\"",
                b.rva[k],
                end,
                b.size[k],
                a.score,
                a.second,
                a.round,
                fnmatch::solve::kt_names(a.types),
                label
            )?;
        }
    }
    Ok(())
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
        Cmd::Solve { corpus, extract_dir, out_dir, holdout, min_version, max_version, rounds, params, load_threads, no_labels } => {
            let mut c: corpus::Corpus = serde_json::from_str(&std::fs::read_to_string(&corpus)?)?;
            let vk = |v: &str| corpus::version_key(v);
            if let Some(mn) = &min_version {
                c.builds.retain(|b| b.version == "?" || vk(&b.version) >= vk(mn));
            }
            if let Some(mx) = &max_version {
                c.builds.retain(|b| b.version == "?" || vk(&b.version) <= vk(mx));
            }
            std::fs::create_dir_all(&out_dir)?;
            let holdout: Vec<String> = holdout.map(|s| s.split(',').map(|x| x.to_string()).collect()).unwrap_or_default();
            let t0 = std::time::Instant::now();
            let mut db = fnmatch::corpusdb::CorpusDb::load(&c, &extract_dir, &[], load_threads)?;
            eprintln!(
                "loaded {} builds, {} functions, {} names, {} label sets in {:.1}s",
                db.builds.len(),
                db.total,
                db.labels.names.len(),
                db.labels.sets.len(),
                t0.elapsed().as_secs_f64()
            );
            let mut p = match &params {
                Some(js) => serde_json::from_str::<fnmatch::solve::Params>(js)?,
                None => fnmatch::solve::Params::default(),
            };
            if let Some(r) = rounds {
                p.rounds = r;
            }
            let mut s = fnmatch::solve::Solver::new(&mut db, p, &holdout);
            s.run();
            if !holdout.is_empty() {
                let ev = fnmatch::eval::evaluate(&s, &holdout);
                fnmatch::eval::print(&ev);
                std::fs::write(out_dir.join("eval.json"), serde_json::to_string_pretty(&ev)?)?;
            }
            std::fs::write(out_dir.join("solve.log"), s.log.join("\n"))?;
            if !no_labels {
                write_labels(&s, &out_dir.join("labels"))?;
            }
        }
        Cmd::Sigs { corpus, extract_dir, out_dir, only, jobs, force } => {
            let c: corpus::Corpus = serde_json::from_str(&std::fs::read_to_string(&corpus)?)?;
            std::fs::create_dir_all(&out_dir)?;
            let only: Option<Vec<String>> = only.map(|s| s.split(',').map(|x| x.to_string()).collect());
            let todo: Vec<&model::BuildMeta> = c
                .builds
                .iter()
                .filter(|b| only.as_ref().map_or(true, |o| o.contains(&b.id)))
                .filter(|b| extract_dir.join(format!("{}.fnx", b.id)).exists())
                .filter(|b| force || !out_dir.join(format!("{}.sig", b.id)).exists())
                .collect();
            eprintln!("{} builds to evaluate", todo.len());
            let pool = rayon::ThreadPoolBuilder::new().num_threads(jobs).build()?;
            pool.install(|| {
                todo.par_iter().for_each(|m| {
                    let t0 = std::time::Instant::now();
                    let r = model::Build::load(&extract_dir.join(format!("{}.fnx", m.id))).and_then(|b| {
                        let s = fnmatch::sigs::evaluate(b);
                        s.save(&out_dir.join(format!("{}.sig", m.id)))?;
                        Ok(s)
                    });
                    match r {
                        Ok(s) => {
                            let named = s.names.iter().filter(|v| !v.is_empty()).count();
                            let with_sig = {
                                let mut v = vec![false; s.rva.len()];
                                for &f in &s.funcs {
                                    v[f as usize] = true;
                                }
                                v.iter().filter(|&&x| x).count()
                            };
                            eprintln!("{} v{}: funcs {} named {} sigs {} funcs with a unique sig {} ({:.1}s)", m.id, s.meta.version, s.rva.len(), named, s.sigs.len(), with_sig, t0.elapsed().as_secs_f64());
                        }
                        Err(e) => eprintln!("{} FAILED: {:#}", m.id, e),
                    }
                })
            });
        }
        Cmd::Match { corpus, extract_dir, sig_dir, out_dir, holdout, holdout_series, targets, params, load_threads } => {
            let c: corpus::Corpus = serde_json::from_str(&std::fs::read_to_string(&corpus)?)?;
            let holdout: Vec<String> = holdout.map(|s| s.split(',').map(|x| x.to_string()).collect()).unwrap_or_default();
            let series = |v: &str| v.split('.').take(2).collect::<Vec<_>>().join(".");
            let held_series: std::collections::HashSet<String> =
                if holdout_series { c.builds.iter().filter(|b| holdout.contains(&b.id)).map(|b| series(&b.version)).collect() } else { Default::default() };
            let ref_ids: Vec<(String, String, u16)> = c
                .builds
                .iter()
                .filter(|b| b.pdb_path.is_some() && sig_dir.join(format!("{}.sig", b.id)).exists())
                .filter(|b| !holdout.contains(&b.id) && !held_series.contains(&series(&b.version)))
                .map(|b| (b.id.clone(), b.version.clone(), c.builds.iter().position(|x| x.id == b.id).unwrap() as u16))
                .collect();
            let t0 = std::time::Instant::now();
            let mut refs = fnmatch::matcher::RefSet::load(&sig_dir, &ref_ids, load_threads)?;
            let nsig: usize = refs.builds.iter().map(|r| r.sigs.len()).sum();
            eprintln!("loaded {} reference builds, {} signatures, {} names in {:.1}s", refs.builds.len(), nsig, refs.labels.names.len(), t0.elapsed().as_secs_f64());
            let target_ids: Vec<String> = match targets {
                Some(t) => t.split(',').map(|x| x.to_string()).collect(),
                None if !holdout.is_empty() => holdout.clone(),
                None => c.builds.iter().filter(|b| b.pdb_path.is_none() && extract_dir.join(format!("{}.fnx", b.id)).exists()).map(|b| b.id.clone()).collect(),
            };
            let p: fnmatch::matcher::MatchParams = match &params {
                Some(js) => serde_json::from_str(js)?,
                None => Default::default(),
            };
            std::fs::create_dir_all(out_dir.join("labels"))?;
            let norm = fnmatch::corpusdb::NameNorm::new();
            let mut log = Vec::new();
            let mut evals = Vec::new();
            for tid in &target_ids {
                let t1 = std::time::Instant::now();
                let b = model::Build::load(&extract_dir.join(format!("{}.fnx", tid)))?;
                let has_pdb = b.has_pdb();
                let (cb, names) = fnmatch::corpusdb::compact(b, 0, &norm);
                let tpos = c.builds.iter().position(|x| &x.id == tid).unwrap_or(c.builds.len()) as u16;
                let res = fnmatch::matcher::match_build(&mut refs, &cb, tpos, &p, &mut log);
                fnmatch::matcher::write_labels(&refs, &cb, &res, &out_dir.join("labels").join(format!("{}.csv", tid)))?;
                let accepted = res.iter().filter(|r| r.set != 0 && r.reject == 0).count();
                eprintln!("{}: labelled {} of {} ({:.1}s)", tid, accepted, cb.n, t1.elapsed().as_secs_f64());
                if has_pdb && holdout.contains(tid) {
                    let e = fnmatch::matcher::evaluate(&refs, &cb, &names, &res);
                    fnmatch::matcher::print_eval(&e);
                    evals.push(e);
                }
            }
            std::fs::write(out_dir.join("match.log"), log.join("\n"))?;
            if !evals.is_empty() {
                std::fs::write(out_dir.join("eval.json"), serde_json::to_string_pretty(&evals)?)?;
            }
        }
        Cmd::Exceptions { corpus, extract_dir, labels_dir, input, out_dir, hi_score } => {
            let c: corpus::Corpus = serde_json::from_str(&std::fs::read_to_string(&corpus)?)?;
            let mut files = Vec::new();
            let mut stack = vec![input];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d)? {
                    let p = e?.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.extension().map_or(false, |x| x == "txt") {
                        files.push(p);
                    }
                }
            }
            files.sort();
            let (frames, summary) = fnmatch::exceptions::run(&c, &extract_dir, &labels_dir, &files, hi_score)?;
            std::fs::create_dir_all(&out_dir)?;
            {
                use std::io::Write;
                let mut w = std::io::BufWriter::new(std::fs::File::create(out_dir.join("frames.csv"))?);
                writeln!(w, "file,frame,build,rva,func_rva,status,score,evidence,label")?;
                for f in &frames {
                    writeln!(w, "{},{},{},{},{},{},{:.3},{},\"{}\"", f.file, f.frame, f.build, f.rva, f.func_rva, f.status, f.score, f.evidence, f.label.replace('"', "\"\""))?;
                }
            }
            std::fs::write(out_dir.join("summary.json"), serde_json::to_string_pretty(&summary)?)?;
            // unlabelled crash functions, aggregated (no file names)
            {
                use std::io::Write;
                let mut agg: std::collections::BTreeMap<(String, String), (usize, std::collections::BTreeSet<usize>)> = Default::default();
                for f in frames.iter().filter(|f| f.status == "unlabelled") {
                    let e = agg.entry((f.build.clone(), f.func_rva.clone())).or_default();
                    e.0 += 1;
                    e.1.insert(f.file);
                }
                let mut w = std::io::BufWriter::new(std::fs::File::create(out_dir.join("unlabelled.csv"))?);
                writeln!(w, "build,func_rva,frames,files")?;
                for ((b, r), (n, fs)) in &agg {
                    writeln!(w, "{},{},{},{}", b, r, n, fs.len())?;
                }
            }
            let mut tot = fnmatch::exceptions::VersionSummary::default();
            println!("{:>8} {:>5} {:>6} {:>7} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}  platforms", "version", "files", "frames", "no_sym", "in_func", "labelled", "lab>=hi", "all_lab", "distinctF", "distinctL");
            for (v, s) in &summary {
                println!(
                    "{:>8} {:>5} {:>6} {:>7} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}  {:?}",
                    v, s.files, s.frames, s.frames_no_symbol, s.frames_in_function, s.frames_labelled, s.frames_labelled_hi, s.files_all_labelled, s.distinct_functions, s.distinct_labelled, s.files_by_platform
                );
                tot.files += s.files;
                tot.frames += s.frames;
                tot.frames_no_symbol += s.frames_no_symbol;
                tot.frames_in_function += s.frames_in_function;
                tot.frames_labelled += s.frames_labelled;
                tot.frames_labelled_hi += s.frames_labelled_hi;
                tot.files_all_labelled += s.files_all_labelled;
                tot.distinct_functions += s.distinct_functions;
                tot.distinct_labelled += s.distinct_labelled;
            }
            println!(
                "{:>8} {:>5} {:>6} {:>7} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}",
                "total", tot.files, tot.frames, tot.frames_no_symbol, tot.frames_in_function, tot.frames_labelled, tot.frames_labelled_hi, tot.files_all_labelled, tot.distinct_functions, tot.distinct_labelled
            );
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
                    // "#N" selects function index N
                    let rva = match rva.strip_prefix('#') {
                        Some(ix) => b.funcs[ix.parse::<usize>()?].rva,
                        None => u32::from_str_radix(rva.trim_start_matches("0x"), 16)?,
                    };
                    let mut lens: Vec<usize> = b.tables.iter().map(|t| t.len()).collect();
                    lens.sort_unstable_by(|a, c| c.cmp(a));
                    println!("tables {} total entries {} largest {:?}", b.tables.len(), lens.iter().sum::<usize>(), &lens[..lens.len().min(10)]);
                    if let Some(i) = b.func_containing(rva) {
                        for (ti, t) in b.tables.iter().enumerate() {
                            if let Some(p) = t.iter().position(|&e| e == i as u32) {
                                println!("in table {} (len {}) at {}", ti, t.len(), p);
                            }
                        }
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
