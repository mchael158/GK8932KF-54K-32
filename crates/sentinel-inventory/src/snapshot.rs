use crate::InventoryError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;

#[cfg(target_os = "linux")]
use crate::scan;

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub pacman_db: PathBuf,
    pub scan_roots: Vec<PathBuf>,
    pub lib_roots: Vec<PathBuf>,
    pub hash_executables: bool,
    pub scan_libraries: bool,
    pub demo: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            pacman_db: default_pacman_db(),
            scan_roots: default_scan_roots(),
            lib_roots: default_lib_roots(),
            hash_executables: false,
            scan_libraries: false,
            demo: false,
        }
    }
}

fn default_pacman_db() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/pacman/local")
    }
    #[cfg(not(target_os = "linux"))]
    {
        PathBuf::from(".chronos/pacman-local")
    }
}

fn default_scan_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
        ]
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

fn default_lib_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![PathBuf::from("/usr/lib")]
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySnapshot {
    pub collected_at: OffsetDateTime,
    pub packages: Vec<InstalledPackage>,
    pub tracked_executables: Vec<TrackedExecutable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphan_executables: Vec<TrackedExecutable>,
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

    #[cfg(not(target_os = "linux"))]
    {
        let _ = opts;
        return Err(InventoryError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        let packages = crate::pacman::list_local_packages(&opts.pacman_db).await?;
        let mut tracked =
            scan::scan_executables(&opts.scan_roots, opts.hash_executables).await?;
        if opts.scan_libraries {
            let mut libs = scan::scan_libraries(&opts.lib_roots, opts.hash_executables).await?;
            tracked.append(&mut libs);
        }
        let mut orphan_executables = Vec::new();
        tracked.retain(|exe| {
            if exe.owning_package.is_none() {
                orphan_executables.push(exe.clone());
                false
            } else {
                true
            }
        });

        Ok(InventorySnapshot {
            collected_at: OffsetDateTime::now_utc(),
            packages,
            tracked_executables: tracked,
            orphan_executables,
        })
    }
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
        tracked_executables: vec![TrackedExecutable {
            path: "/usr/bin/sshd".into(),
            owning_package: Some("openssh".into()),
            content_hash: Some(ContentHash {
                algorithm: HashAlgorithm::Blake3,
                hex: "demo_sshd_hash".into(),
            }),
        }],
        orphan_executables: vec![TrackedExecutable {
            path: "/usr/local/bin/custom-tool".into(),
            owning_package: None,
            content_hash: None,
        }],
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
