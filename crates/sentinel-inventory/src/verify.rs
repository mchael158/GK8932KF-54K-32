use crate::{InventorySnapshot, TrackedExecutable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    Ok,
    Missing,
    NoBaseline,
    HashMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFinding {
    pub path: String,
    pub status: VerifyStatus,
    pub owning_package: Option<String>,
}

pub fn verify_snapshot(snapshot: &InventorySnapshot) -> Vec<VerifyFinding> {
    verify_snapshot_inner(snapshot, false)
}

pub fn verify_snapshot_demo_aware(snapshot: &InventorySnapshot, demo: bool) -> Vec<VerifyFinding> {
    verify_snapshot_inner(snapshot, demo)
}

fn verify_snapshot_inner(snapshot: &InventorySnapshot, demo: bool) -> Vec<VerifyFinding> {
    let mut findings = Vec::new();
    for exe in snapshot
        .tracked_executables
        .iter()
        .chain(snapshot.orphan_executables.iter())
    {
        findings.push(verify_entry(exe, demo));
    }
    findings
}

fn verify_entry(entry: &TrackedExecutable, demo: bool) -> VerifyFinding {
    let path = std::path::Path::new(&entry.path);
    let Some(expected) = entry.content_hash.as_ref() else {
        return VerifyFinding {
            path: entry.path.clone(),
            status: VerifyStatus::NoBaseline,
            owning_package: entry.owning_package.clone(),
        };
    };
    if !path.exists() {
        if demo && expected.hex.starts_with("demo_") {
            return VerifyFinding {
                path: entry.path.clone(),
                status: VerifyStatus::Ok,
                owning_package: entry.owning_package.clone(),
            };
        }
        return VerifyFinding {
            path: entry.path.clone(),
            status: VerifyStatus::Missing,
            owning_package: entry.owning_package.clone(),
        };
    }
    match sentinel_integrity::hash_file_blake3(path) {
        Ok(actual) if actual.hex == expected.hex => VerifyFinding {
            path: entry.path.clone(),
            status: VerifyStatus::Ok,
            owning_package: entry.owning_package.clone(),
        },
        Ok(actual) => VerifyFinding {
            path: entry.path.clone(),
            status: VerifyStatus::HashMismatch {
                expected: expected.hex.clone(),
                actual: actual.hex,
            },
            owning_package: entry.owning_package.clone(),
        },
        Err(_) => VerifyFinding {
            path: entry.path.clone(),
            status: VerifyStatus::Missing,
            owning_package: entry.owning_package.clone(),
        },
    }
}

pub fn count_problems(findings: &[VerifyFinding]) -> usize {
    findings
        .iter()
        .filter(|f| !matches!(f.status, VerifyStatus::Ok | VerifyStatus::NoBaseline))
        .count()
}
