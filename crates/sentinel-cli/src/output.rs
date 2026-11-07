use sentinel_inventory::InventorySnapshot;
use std::path::Path;

pub fn print_inventory_summary(snapshot: &InventorySnapshot, written: Option<&Path>) {
    let c = &snapshot.collection;
    eprintln!(
        "Packages: {}  tracked: {}  orphans: {}",
        snapshot.packages.len(),
        snapshot.tracked_executables.len(),
        snapshot.orphan_executables.len()
    );
    if c.pacman_packages > 0 {
        eprintln!(
            "Collection: {} pacman file records, {} in scope [{}], {} hashed",
            c.pacman_file_records,
            c.integrity_paths_in_db,
            if c.integrity_scope.is_empty() {
                "integrity_prefixes"
            } else {
                c.integrity_scope.as_str()
            },
            c.artifacts_hashed,
        );
    }
    if let Some(path) = written {
        eprintln!("Snapshot: {}", path.display());
    }
}

pub fn print_hash_line(path: &Path, hex: &str) {
    eprintln!("{}  blake3  {}", path.display(), hex);
}
