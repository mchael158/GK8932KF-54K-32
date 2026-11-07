mod collect_pacman;
mod diff;
mod error;
#[cfg(target_os = "linux")]
mod pacman;
mod scope;
#[cfg(target_os = "linux")]
mod scan;
mod snapshot;
mod verify;

pub use diff::{compare_snapshots, ExecutableHashChange, InventoryDiff, PackageChange};
pub use error::InventoryError;
pub use scope::{PacmanFilesScope, INTEGRITY_PREFIXES};
pub use snapshot::{CollectOptions, CollectionMeta, InstalledPackage, InventorySnapshot, TrackedExecutable};
pub use verify::{count_problems, verify_snapshot, verify_snapshot_demo_aware, VerifyFinding, VerifyStatus};

use std::path::Path;

/// Collect local inventory (Arch: pacman + configured path scans).
pub async fn collect_snapshot(opts: &CollectOptions) -> Result<InventorySnapshot, InventoryError> {
    snapshot::collect(opts).await
}

/// Shorthand using only the pacman database path (default scan roots and flags).
pub async fn collect_snapshot_from_db(
    pacman_db: &Path,
) -> Result<InventorySnapshot, InventoryError> {
    collect_snapshot(&CollectOptions {
        pacman_db: pacman_db.to_path_buf(),
        ..CollectOptions::default()
    })
    .await
}
