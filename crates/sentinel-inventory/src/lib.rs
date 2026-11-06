mod diff;
mod error;
#[cfg(target_os = "linux")]
mod pacman;
#[cfg(target_os = "linux")]
mod scan;
mod snapshot;

pub use diff::{compare_snapshots, InventoryDiff, PackageChange};
pub use error::InventoryError;
pub use snapshot::{CollectOptions, InventorySnapshot, InstalledPackage, TrackedExecutable};

use std::path::Path;

/// Coleta inventário local (Arch: pacman + varredura de paths configuráveis).
pub async fn collect_snapshot(opts: &CollectOptions) -> Result<InventorySnapshot, InventoryError> {
    snapshot::collect(opts).await
}

/// Atalho com apenas o caminho do banco pacman (paths e hash padrão).
pub async fn collect_snapshot_from_db(pacman_db: &Path) -> Result<InventorySnapshot, InventoryError> {
    collect_snapshot(&CollectOptions {
        pacman_db: pacman_db.to_path_buf(),
        ..CollectOptions::default()
    })
    .await
}
