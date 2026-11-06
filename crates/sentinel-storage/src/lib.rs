mod error;

pub use error::StorageError;

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
