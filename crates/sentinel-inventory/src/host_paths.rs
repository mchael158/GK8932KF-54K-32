//! Default scan roots and MSYS2/pacman paths per OS.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn path_dirs_from_env(var: &str) -> Vec<PathBuf> {
    std::env::var_os(var)
        .map(|v| std::env::split_paths(&v).collect::<Vec<_>>())
        .unwrap_or_default()
}

fn dedupe_existing(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let canonical = p.canonicalize().unwrap_or(p.clone());
        if !canonical.is_dir() || !seen.insert(canonical.clone()) {
            continue;
        }
        out.push(canonical);
    }
    out
}

#[cfg(windows)]
pub fn default_scan_roots() -> Vec<PathBuf> {
    dedupe_existing(path_dirs_from_env("PATH"))
}

#[cfg(windows)]
pub fn default_lib_roots() -> Vec<PathBuf> {
    if let Some(msys) = detect_msys_install_prefix() {
        let usr = msys.join("usr").join("lib");
        if usr.is_dir() {
            return dedupe_existing(vec![usr]);
        }
    }
    Vec::new()
}

#[cfg(windows)]
pub fn detect_msys_install_prefix() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHRONOS_INSTALL_PREFIX") {
        let t = p.trim();
        if !t.is_empty() {
            let pb = PathBuf::from(t);
            if pb.is_dir() {
                return Some(pb);
            }
        }
    }
    for var in ["MSYSTEM_PREFIX", "MSYSTEM_PREFIX_64"] {
        if let Ok(p) = std::env::var(var) {
            let t = p.trim();
            if !t.is_empty() {
                let pb = PathBuf::from(t);
                if pb.is_dir() {
                    return Some(pb);
                }
            }
        }
    }
    for candidate in [r"C:\msys64", r"C:\tools\msys64", r"D:\msys64"] {
        let pb = PathBuf::from(candidate);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    None
}

#[cfg(windows)]
pub fn default_pacman_db() -> PathBuf {
    if let Ok(p) = std::env::var("CHRONOS_PACMAN_DB") {
        let t = p.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    if let Some(msys) = detect_msys_install_prefix() {
        let db = msys.join("var").join("lib").join("pacman").join("local");
        if db.is_dir() {
            return db;
        }
    }
    PathBuf::from(".chronos/pacman-local")
}

#[cfg(windows)]
pub fn default_install_prefix() -> PathBuf {
    detect_msys_install_prefix().unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(target_os = "linux")]
pub fn default_scan_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")]
}

#[cfg(target_os = "linux")]
pub fn default_lib_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/usr/lib")]
}

#[cfg(target_os = "linux")]
pub fn default_pacman_db() -> PathBuf {
    PathBuf::from("/var/lib/pacman/local")
}

#[cfg(target_os = "linux")]
pub fn default_install_prefix() -> PathBuf {
    PathBuf::from("/")
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_scan_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_lib_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_pacman_db() -> PathBuf {
    PathBuf::from(".chronos/pacman-local")
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_install_prefix() -> PathBuf {
    PathBuf::from("/")
}

pub fn scan_roots_available(roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| r.is_dir())
}

pub async fn load_packages_for_collect_with_roots(
    db_path: &Path,
    scan_roots: &[PathBuf],
) -> Result<Vec<crate::InstalledPackage>, crate::InventoryError> {
    match crate::pacman::list_local_packages(db_path).await {
        Ok(packages) => Ok(packages),
        Err(crate::InventoryError::PacmanDb(_)) if scan_roots_available(scan_roots) => {
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
}
