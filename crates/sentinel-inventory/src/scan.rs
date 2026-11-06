use crate::{InventoryError, TrackedExecutable};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub async fn scan_executables(
    roots: &[PathBuf],
    hash_files: bool,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !entry.file_type().is_file() {
                continue;
            }
            if !is_executable(path) {
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
        // "sshd 9.7p1-1 is owned by openssh 9.7p1-1"
        first.split_whitespace().nth(4).map(|s| s.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}
