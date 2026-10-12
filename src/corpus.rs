//! Corpus inventory: enumerate the Steam and GOG archives into a list of builds with metadata.

use crate::model::BuildMeta;
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub builds: Vec<BuildMeta>,
    /// builds that were skipped (not x64, unreadable) with the reason
    pub skipped: Vec<(String, String)>,
}

fn machine(path: &Path) -> Result<u16> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 4096];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    anyhow::ensure!(buf.len() >= 0x40 && &buf[..2] == b"MZ", "not MZ");
    let pe = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap()) as usize;
    anyhow::ensure!(pe + 6 <= buf.len(), "short header");
    Ok(u16::from_le_bytes([buf[pe + 4], buf[pe + 5]]))
}

/// Parse `Andromeda v3.12.5  00c910f0... (Jun 13 2024 15:58:38)` into (version, commit, ISO date).
pub fn parse_build_string(s: &str) -> (String, Option<String>, Option<String>) {
    let ver = Regex::new(r"v(\d+(?:\.\d+)+)").unwrap();
    let hash = Regex::new(r"\b([0-9a-f]{32})\b").unwrap();
    let date = Regex::new(r"\(([A-Z][a-z]{2}) +(\d{1,2}) (\d{4}) (\d\d:\d\d:\d\d)\)").unwrap();
    let version = ver.captures(s).map(|c| c[1].to_string()).unwrap_or_else(|| "?".into());
    let commit = hash.captures(s).map(|c| c[1].to_string());
    let iso = date.captures(s).and_then(|c| {
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let m = months.iter().position(|&m| m == &c[1])? + 1;
        Some(format!("{}-{:02}-{:02}T{}", &c[3], m, c[2].parse::<u32>().ok()?, &c[4]))
    });
    (version, commit, iso)
}

fn read_meta_string(path: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
    v.get("string_value")?.as_str().map(|s| s.to_string())
}

fn entry(id: String, platform: &str, source: String, exe: PathBuf, meta_json: PathBuf, pdb: PathBuf, out: &mut Corpus) {
    match machine(&exe) {
        Ok(0x8664) => {}
        Ok(m) => {
            out.skipped.push((id, format!("machine 0x{:x}", m)));
            return;
        }
        Err(e) => {
            out.skipped.push((id, format!("{:#}", e)));
            return;
        }
    }
    let bs = read_meta_string(&meta_json).unwrap_or_default();
    let (version, commit, build_date) = parse_build_string(&bs);
    let exe_size = std::fs::metadata(&exe).map(|m| m.len()).unwrap_or(0);
    out.builds.push(BuildMeta {
        id,
        platform: platform.into(),
        version,
        build_string: bs,
        commit,
        build_date,
        source,
        exe_path: exe.to_string_lossy().into_owned(),
        pdb_path: pdb.is_file().then(|| pdb.to_string_lossy().into_owned()),
        exe_md5: String::new(),
        exe_size,
    });
}

pub fn scan(steam_root: &Path, gog_root: &Path) -> Result<Corpus> {
    let mut out = Corpus { builds: Vec::new(), skipped: Vec::new() };
    let mut dirs: Vec<_> = std::fs::read_dir(steam_root).with_context(|| format!("read {}", steam_root.display()))?.filter_map(|e| e.ok()).collect();
    dirs.sort_by_key(|e| e.file_name());
    for d in dirs {
        let p = d.path();
        let exe = p.join("stellaris.exe");
        if !exe.is_file() {
            continue;
        }
        let man = d.file_name().to_string_lossy().into_owned();
        entry(format!("steam-{}", man), "steam", man, exe, p.join("metadata.json"), p.join("stellaris.pdb"), &mut out);
    }
    let mut dirs: Vec<_> = std::fs::read_dir(gog_root).with_context(|| format!("read {}", gog_root.display()))?.filter_map(|e| e.ok()).collect();
    dirs.sort_by_key(|e| e.file_name());
    for d in dirs {
        let p = d.path().join("windows");
        let exe = p.join("depots").join("stellaris.exe");
        if !exe.is_file() {
            continue;
        }
        let name = d.file_name().to_string_lossy().into_owned();
        entry(format!("gog-{}", name), "gog", name, exe, p.join("metadata.json"), p.join("depots").join("stellaris.pdb"), &mut out);
    }
    out.builds.sort_by(|a, b| (a.build_date.as_deref().unwrap_or(""), &a.id).cmp(&(b.build_date.as_deref().unwrap_or(""), &b.id)));
    Ok(out)
}

/// Numeric version key for sorting (`3.12.5` -> [3, 12, 5]).
pub fn version_key(v: &str) -> Vec<u32> {
    v.split('.').map(|x| x.parse().unwrap_or(0)).collect()
}
