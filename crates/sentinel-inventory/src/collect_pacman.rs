//! Build tracked artifacts from pacman `%FILES%` (primary integrity surface).

use crate::scope::{package_file_in_scope, PacmanFilesScope};
use crate::{InstalledPackage, InventoryError, TrackedExecutable};

pub fn pacman_rel_to_abs(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/").join(rel.trim_start_matches('/'))
}

pub async fn artifacts_from_package_files(
    packages: &[InstalledPackage],
    hash_files: bool,
    scope: PacmanFilesScope,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    let mut out = Vec::new();
    for pkg in packages {
        for rel in &pkg.installed_files {
            if !package_file_in_scope(rel, scope) {
                continue;
            }
            let path = pacman_rel_to_abs(rel);
            let content_hash = if path.is_file() {
                if hash_files {
                    sentinel_integrity::hash_file_blake3(&path).ok()
                } else {
                    None
                }
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

pub fn count_scoped_file_entries(packages: &[InstalledPackage], scope: PacmanFilesScope) -> usize {
    packages
        .iter()
        .flat_map(|p| p.installed_files.iter())
        .filter(|rel| package_file_in_scope(rel, scope))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_scope_excludes_doc() {
        assert!(package_file_in_scope(
            "usr/lib/liblzma.so.5",
            PacmanFilesScope::IntegrityPrefixes
        ));
        assert!(!package_file_in_scope(
            "usr/share/doc/xz/README",
            PacmanFilesScope::IntegrityPrefixes
        ));
        assert!(package_file_in_scope(
            "usr/share/doc/xz/README",
            PacmanFilesScope::AllPackageFiles
        ));
    }

    #[test]
    fn abs_join() {
        assert_eq!(
            pacman_rel_to_abs("usr/bin/xz").display().to_string(),
            "/usr/bin/xz"
        );
    }
}
