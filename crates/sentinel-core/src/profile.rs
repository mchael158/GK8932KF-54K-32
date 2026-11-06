use crate::identity::ContentHash;
use serde::{Deserialize, Serialize};

/// Historical profile for an executable (behavioral baseline + integrity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProfile {
    pub executable_path: String,
    pub package_name: Option<String>,

    pub execution_count: u64,

    /// Accumulated CPU time (nanoseconds).
    pub cpu_time_ns: u64,
    /// Accumulated wall time (nanoseconds) — not the same as operation latency.
    pub wall_time_ns: u64,

    pub latency: LatencyStats,

    pub executable_hash: ContentHash,
    pub loaded_libraries: Vec<String>,
}

/// Robust stats for detection (median + MAD spread).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    pub sample_count: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    /// Median absolute deviation (nanoseconds).
    pub mad_ns: u64,
}
