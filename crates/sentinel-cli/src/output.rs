use sentinel_inventory::InventorySnapshot;
use std::path::Path;

pub fn print_inventory_summary(snapshot: &InventorySnapshot, written: Option<&Path>) {
    eprintln!(
        "Packages: {}  tracked: {}  orphans: {}",
        snapshot.packages.len(),
        snapshot.tracked_executables.len(),
        snapshot.orphan_executables.len()
    );
    if let Some(path) = written {
        eprintln!("Snapshot: {}", path.display());
    }
}

pub fn print_hash_line(path: &Path, hex: &str) {
    eprintln!("{}  blake3  {}", path.display(), hex);
}
