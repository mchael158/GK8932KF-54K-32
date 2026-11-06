use crate::{InstalledPackage, InventorySnapshot, TrackedExecutable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryDiff {
    pub packages_added: Vec<InstalledPackage>,
    pub packages_removed: Vec<InstalledPackage>,
    pub packages_changed: Vec<PackageChange>,
    pub executables_added: Vec<TrackedExecutable>,
    pub executables_removed: Vec<TrackedExecutable>,
    pub executables_hash_changed: Vec<ExecutableHashChange>,
    pub orphans_added: Vec<TrackedExecutable>,
    pub orphans_removed: Vec<TrackedExecutable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageChange {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableHashChange {
    pub path: String,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
}

#[cfg(test)]
mod diff_tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn diff_detects_package_version_change() {
        let before = InventorySnapshot {
            collected_at: OffsetDateTime::now_utc(),
            packages: vec![InstalledPackage {
                name: "xz".into(),
                version: "5.4.6-1".into(),
                installed_files: vec![],
            }],
            tracked_executables: vec![],
            orphan_executables: vec![],
        };
        let after = InventorySnapshot {
            collected_at: OffsetDateTime::now_utc(),
            packages: vec![InstalledPackage {
                name: "xz".into(),
                version: "5.6.0-1".into(),
                installed_files: vec![],
            }],
            tracked_executables: vec![],
            orphan_executables: vec![],
        };
        let diff = compare_snapshots(&before, &after);
        assert_eq!(diff.packages_changed.len(), 1);
        assert_eq!(diff.packages_changed[0].old_version, "5.4.6-1");
    }
}

pub fn compare_snapshots(before: &InventorySnapshot, after: &InventorySnapshot) -> InventoryDiff {
    let packages_added = after
        .packages
        .iter()
        .filter(|p| !before.packages.iter().any(|b| b.name == p.name))
        .cloned()
        .collect();
    let packages_removed = before
        .packages
        .iter()
        .filter(|p| !after.packages.iter().any(|a| a.name == p.name))
        .cloned()
        .collect();
    let packages_changed = after
        .packages
        .iter()
        .filter_map(|a| {
            let b = before.packages.iter().find(|b| b.name == a.name)?;
            if b.version == a.version {
                return None;
            }
            Some(PackageChange {
                name: a.name.clone(),
                old_version: b.version.clone(),
                new_version: a.version.clone(),
            })
        })
        .collect();

    let exe_diff = diff_executables(&before.tracked_executables, &after.tracked_executables);
    let orphan_diff = diff_executables(&before.orphan_executables, &after.orphan_executables);

    InventoryDiff {
        packages_added,
        packages_removed,
        packages_changed,
        executables_added: exe_diff.added,
        executables_removed: exe_diff.removed,
        executables_hash_changed: exe_diff.hash_changed,
        orphans_added: orphan_diff.added,
        orphans_removed: orphan_diff.removed,
    }
}

struct ExeDiff {
    added: Vec<TrackedExecutable>,
    removed: Vec<TrackedExecutable>,
    hash_changed: Vec<ExecutableHashChange>,
}

fn diff_executables(before: &[TrackedExecutable], after: &[TrackedExecutable]) -> ExeDiff {
    let added = after
        .iter()
        .filter(|a| !before.iter().any(|b| b.path == a.path))
        .cloned()
        .collect();
    let removed = before
        .iter()
        .filter(|b| !after.iter().any(|a| a.path == b.path))
        .cloned()
        .collect();
    let hash_changed = after
        .iter()
        .filter_map(|a| {
            let b = before.iter().find(|b| b.path == a.path)?;
            let old_h = b.content_hash.as_ref().map(|h| h.hex.clone());
            let new_h = a.content_hash.as_ref().map(|h| h.hex.clone());
            if old_h == new_h {
                return None;
            }
            Some(ExecutableHashChange {
                path: a.path.clone(),
                old_hash: old_h,
                new_hash: new_h,
            })
        })
        .collect();
    ExeDiff {
        added,
        removed,
        hash_changed,
    }
}
