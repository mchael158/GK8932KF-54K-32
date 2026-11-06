use crate::identity::ProcessStartId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Single execution observation (execve through exit or partial sample).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionObservation {
    pub start_id: ProcessStartId,
    pub parent_start_id: Option<ProcessStartId>,

    pub executable: String,
    pub argv_hash: Option<String>,

    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,

    pub cpu_time_ns: u64,
    pub wall_time_ns: Option<u64>,

    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SentinelEvent {
    ProcessExec {
        observation: ExecutionObservation,
    },
    ProcessExit {
        start_id: ProcessStartId,
        exit_code: i32,
        cpu_time_ns: u64,
        wall_time_ns: u64,
    },
    PackageTransaction {
        manager: PackageManager,
        action: PackageAction,
        package_name: String,
        old_version: Option<String>,
        new_version: Option<String>,
        recorded_at: OffsetDateTime,
    },
    FileIntegrityChange {
        path: String,
        previous_hash: Option<ContentHashRef>,
        current_hash: ContentHashRef,
        owner_package: Option<String>,
        recorded_at: OffsetDateTime,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Pacman,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageAction {
    Install,
    Upgrade,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentHashRef {
    pub algorithm: crate::identity::HashAlgorithm,
    pub hex: String,
}
