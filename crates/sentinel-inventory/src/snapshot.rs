use crate::host_paths::{
    default_install_prefix, default_lib_roots, default_pacman_db, default_scan_roots,
    load_packages_for_collect_with_roots,
};
use crate::scope::PacmanFilesScope;
use crate::InventoryError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;

use crate::collect_pacman::{artifacts_from_package_files, count_scoped_file_entries};
use crate::scan;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub struct CollectOptions {
    pub pacman_db: PathBuf,
    /// MSYS2 root or `/` on Linux — maps pacman `%FILES%` lines to host paths.
    pub install_prefix: PathBuf,
    pub scan_roots: Vec<PathBuf>,
    pub lib_roots: Vec<PathBuf>,
    pub hash_executables: bool,
    pub scan_libraries: bool,
    /// Default [`PacmanFilesScope::IntegrityPrefixes`] — not full `%FILES%` (size).
    pub files_scope: PacmanFilesScope,
    /// Empty = built-in [`crate::scope::INTEGRITY_PREFIXES`]; set via config TOML or API.
    pub integrity_prefixes: Vec<String>,
    pub demo: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            pacman_db: default_pacman_db(),
            install_prefix: default_install_prefix(),
            scan_roots: default_scan_roots(),
            lib_roots: default_lib_roots(),
            hash_executables: true,
            scan_libraries: true,
            files_scope: PacmanFilesScope::default(),
            integrity_prefixes: Vec::new(),
            demo: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionMeta {
    pub pacman_packages: usize,
    /// Total paths listed under `%FILES%` across packages.
    pub pacman_file_records: usize,
    /// Subset of `%FILES%` selected by `files_scope` (prefixes or all).
    pub integrity_paths_in_db: usize,
    pub integrity_scope: String,
    pub artifacts_tracked: usize,
    pub artifacts_hashed: usize,
    /// Relevant `%FILES%` paths that were not present on disk at collect time.
    pub artifacts_missing_on_disk: usize,
    pub bin_scan_orphans: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySnapshot {
    pub collected_at: OffsetDateTime,
    pub packages: Vec<InstalledPackage>,
    pub tracked_executables: Vec<TrackedExecutable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphan_executables: Vec<TrackedExecutable>,
    #[serde(default, skip_serializing_if = "CollectionMeta::is_empty")]
    pub collection: CollectionMeta,
}

impl CollectionMeta {
    fn is_empty(&self) -> bool {
        self.pacman_packages == 0 && self.artifacts_tracked == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub installed_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedExecutable {
    pub path: String,
    pub owning_package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<sentinel_core::ContentHash>,
}

pub async fn collect(opts: &CollectOptions) -> Result<InventorySnapshot, InventoryError> {
    if opts.demo {
        return Ok(demo_snapshot());
    }
    collect_live(opts).await
}

async fn collect_live(opts: &CollectOptions) -> Result<InventorySnapshot, InventoryError> {
    let packages =
        load_packages_for_collect_with_roots(&opts.pacman_db, &opts.scan_roots).await?;
    let hash_files = opts.hash_executables;
    let scope = opts.files_scope;
    let prefixes = &opts.integrity_prefixes;
    let install_prefix = &opts.install_prefix;

    let mut tracked =
        artifacts_from_package_files(&packages, hash_files, scope, prefixes, install_prefix)
            .await?;
    let mut seen: HashSet<String> = tracked.iter().map(|t| t.path.clone()).collect();
    let mut orphan_executables = Vec::new();

    if opts.scan_libraries {
        let libs = scan::scan_libraries(&opts.lib_roots, hash_files).await?;
        for item in libs {
            if !seen.insert(item.path.clone()) {
                continue;
            }
            if item.owning_package.is_none() {
                orphan_executables.push(item);
            } else {
                tracked.push(item);
            }
        }
    }

    for item in scan::scan_executables(&opts.scan_roots, hash_files).await? {
        if seen.contains(&item.path) {
            continue;
        }
        seen.insert(item.path.clone());
        if item.owning_package.is_none() {
            orphan_executables.push(item);
        } else {
            tracked.push(item);
        }
    }

    if packages.is_empty() && tracked.is_empty() && orphan_executables.is_empty() {
        return Err(InventoryError::NothingToCollect);
    }

    let hashed = tracked
        .iter()
        .chain(orphan_executables.iter())
        .filter(|t| t.content_hash.is_some())
        .count();
    let missing_on_disk = tracked
        .iter()
        .filter(|t| {
            t.owning_package.is_some() && !std::path::Path::new(&t.path).is_file()
        })
        .count();

    let collection = CollectionMeta {
        pacman_packages: packages.len(),
        pacman_file_records: packages.iter().map(|p| p.installed_files.len()).sum(),
        integrity_paths_in_db: count_scoped_file_entries(&packages, scope, prefixes),
        integrity_scope: scope.as_str().into(),
        artifacts_tracked: tracked.len() + orphan_executables.len(),
        artifacts_hashed: hashed,
        artifacts_missing_on_disk: missing_on_disk,
        bin_scan_orphans: orphan_executables.len(),
    };

    Ok(InventorySnapshot {
        collected_at: OffsetDateTime::now_utc(),
        packages,
        tracked_executables: tracked,
        orphan_executables,
        collection,
    })
}

fn demo_snapshot() -> InventorySnapshot {
    use sentinel_core::{ContentHash, HashAlgorithm};
    InventorySnapshot {
        collected_at: OffsetDateTime::now_utc(),
        packages: vec![
            InstalledPackage {
                name: "xz".into(),
                version: "5.4.6-1".into(),
                installed_files: vec!["usr/lib/liblzma.so.5".into()],
            },
            InstalledPackage {
                name: "openssh".into(),
                version: "9.7p1-1".into(),
                installed_files: vec!["usr/bin/sshd".into()],
            },
        ],
        tracked_executables: vec![
            TrackedExecutable {
                path: "/usr/lib/liblzma.so.5".into(),
                owning_package: Some("xz".into()),
                content_hash: Some(ContentHash {
                    algorithm: HashAlgorithm::Blake3,
                    hex: "demo_lzma_hash".into(),
                }),
            },
            TrackedExecutable {
                path: "/usr/bin/sshd".into(),
                owning_package: Some("openssh".into()),
                content_hash: Some(ContentHash {
                    algorithm: HashAlgorithm::Blake3,
                    hex: "demo_sshd_hash".into(),
                }),
            },
        ],
        orphan_executables: vec![TrackedExecutable {
            path: "/usr/local/bin/custom-tool".into(),
            owning_package: None,
            content_hash: None,
        }],
        collection: CollectionMeta {
            pacman_packages: 2,
            pacman_file_records: 2,
            integrity_paths_in_db: 2,
            integrity_scope: PacmanFilesScope::IntegrityPrefixes.as_str().into(),
            artifacts_tracked: 3,
            artifacts_hashed: 2,
            artifacts_missing_on_disk: 2,
            bin_scan_orphans: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn demo_snapshot_collects() {
        let snap = collect(&CollectOptions {
            demo: true,
            ..CollectOptions::default()
        })
        .await
        .unwrap();
        assert_eq!(snap.packages.len(), 2);
        assert_eq!(snap.orphan_executables.len(), 1);
    }
}
