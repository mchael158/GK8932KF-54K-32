//! Build tracked artifacts from pacman `%FILES%` (primary integrity surface).

use crate::scope::{package_file_in_scope, pacman_rel_to_abs, PacmanFilesScope};
use crate::{InstalledPackage, InventoryError, TrackedExecutable};
use std::path::Path;

pub async fn artifacts_from_package_files(
    packages: &[InstalledPackage],
    hash_files: bool,
    scope: PacmanFilesScope,
    integrity_prefixes: &[String],
    install_prefix: &Path,
) -> Result<Vec<TrackedExecutable>, InventoryError> {
    let mut out = Vec::new();
    for pkg in packages {
        for rel in &pkg.installed_files {
            if !package_file_in_scope(rel, scope, integrity_prefixes) {
                continue;
            }
            let path = pacman_rel_to_abs(rel, install_prefix);
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

pub fn count_scoped_file_entries(
    packages: &[InstalledPackage],
    scope: PacmanFilesScope,
    integrity_prefixes: &[String],
) -> usize {
    packages
        .iter()
        .flat_map(|p| p.installed_files.iter())
        .filter(|rel| package_file_in_scope(rel, scope, integrity_prefixes))
        .count()
}
