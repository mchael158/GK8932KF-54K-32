use crate::{InventoryError, TrackedExecutable};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub async fn scan_executables(
    roots: &[PathBuf],
    hash_files: bool,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    scan_paths(roots, hash_files, ScanKind::Executable).await
}

pub async fn scan_libraries(
    roots: &[PathBuf],
    hash_files: bool,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    scan_paths(roots, hash_files, ScanKind::SharedLibrary).await
}

enum ScanKind {
    Executable,
    SharedLibrary,
}

async fn scan_paths(
    roots: &[PathBuf],
    hash_files: bool,
    kind: ScanKind,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !entry.file_type().is_file() {
                continue;
            }
            let include = match kind {
                ScanKind::Executable => is_executable(path),
                ScanKind::SharedLibrary => is_shared_library(path),
            };
            if !include {
                continue;
            }
            let owner = resolve_owner(path).await;
            let content_hash = if hash_files {
                sentinel_integrity::hash_file_blake3(path).ok()
            } else {
                None
            };
            out.push(TrackedExecutable {
                path: path.display().to_string(),
                owning_package: owner,
                content_hash,
            });
        }
    }
    Ok(out)
}

fn is_shared_library(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| matches!(ext, "so" | "0" | "1" | "2" | "3" | "4" | "5" | "6"))
        || path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".so"))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

async fn resolve_owner(path: &Path) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = tokio::process::Command::new("pacman")
            .args(["-Qo", &path.display().to_string()])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let first = line.lines().next()?;
        first.split_whitespace().nth(4).map(|s| s.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}
