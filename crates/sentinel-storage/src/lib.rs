mod compress;
mod error;
mod paths;
mod run_lock;
mod signing;

pub use error::StorageError;
pub use paths::{
    baseline_path, ensure_state_dir, last_check_path, resolve_state_dir,
};
pub use run_lock::{run_lock_path, try_acquire_run_lock, RunLock, RunLockError};
pub use compress::{compress_snapshot_file, compressed_sidecar_path};
pub use signing::{
    discover_signing_key, sign_snapshot_file, signature_path, verify_snapshot_file, write_keypair,
    SnapshotSignature, SigningKeyFile,
};

use sentinel_inventory::InventorySnapshot;
use std::path::Path;

pub fn write_snapshot(path: &Path, snapshot: &InventorySnapshot) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn read_snapshot(path: &Path) -> Result<InventorySnapshot, StorageError> {
    let json = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_inventory::{CollectionMeta, InstalledPackage, InventorySnapshot};
    use time::OffsetDateTime;

    #[test]
    fn baseline_roundtrip_preserves_integrity_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let snap = InventorySnapshot {
            collected_at: OffsetDateTime::now_utc(),
            packages: vec![InstalledPackage {
                name: "xz".into(),
                version: "5.6.0-1".into(),
                installed_files: vec!["usr/bin/xz".into()],
            }],
            tracked_executables: vec![],
            orphan_executables: vec![],
            collection: CollectionMeta {
                pacman_packages: 1,
                artifacts_tracked: 1,
                integrity_scope: "integrity_prefixes".into(),
                ..CollectionMeta::default()
            },
        };
        write_snapshot(&path, &snap).unwrap();
        let again = read_snapshot(&path).unwrap();
        assert_eq!(again.collection.integrity_scope, "integrity_prefixes");
        assert_eq!(again.packages[0].name, "xz");
    }
}
