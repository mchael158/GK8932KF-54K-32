//! Build tracked artifacts from pacman `%FILES%` (primary integrity surface).

use crate::{InstalledPackage, InventoryError, TrackedExecutable};

/// Paths worth hashing (binaries, libs, critical ssh config tree).
pub fn integrity_relevant_rel_path(rel: &str) -> bool {
    let rel = rel.trim_start_matches('/');
    rel.starts_with("usr/bin/")
        || rel.starts_with("usr/sbin/")
        || rel.starts_with("usr/local/bin/")
        || rel.starts_with("usr/lib/")
        || rel.starts_with("lib/")
        || rel.starts_with("etc/ssh/")
}

pub fn pacman_rel_to_abs(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/").join(rel.trim_start_matches('/'))
}

pub async fn artifacts_from_package_files(
    packages: &[InstalledPackage],
    hash_files: bool,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    let mut out = Vec::new();
    for pkg in packages {
        for rel in &pkg.installed_files {
            if !integrity_relevant_rel_path(rel) {
                continue;
            }
            let path = pacman_rel_to_abs(rel);
            if !path.is_file() {
                continue;
            }
            let content_hash = if hash_files {
                sentinel_integrity::hash_file_blake3(&path).ok()
            } else {
                None
            };
            out.push(TrackedExecutable {
                path: path.display().to_string(),
                owning_package: Some(pkg.name.clone()),
                content_hash,
            });
        }
    }
    Ok(out)
}

pub fn count_relevant_file_entries(packages: &[InstalledPackage]) -> usize {
    packages
        .iter()
        .flat_map(|p| p.installed_files.iter())
        .filter(|rel| integrity_relevant_rel_path(rel))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relevant_paths() {
        assert!(integrity_relevant_rel_path("usr/lib/liblzma.so.5"));
        assert!(integrity_relevant_rel_path("usr/bin/sshd"));
        assert!(!integrity_relevant_rel_path("usr/share/doc/xz/README"));
    }

    #[test]
    fn abs_join() {
        assert_eq!(
            pacman_rel_to_abs("usr/bin/xz").display().to_string(),
            "/usr/bin/xz"
        );
    }
}
