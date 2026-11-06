use crate::identity::ContentHash;
use serde::{Deserialize, Serialize};

/// Perfil histórico de um executável (baseline comportamental + integridade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProfile {
    pub executable_path: String,
    pub package_name: Option<String>,

    pub execution_count: u64,

    /// Tempo de CPU acumulado observado (nanosegundos).
    pub cpu_time_ns: u64,
    /// Tempo de parede acumulado (nanosegundos) — distinto de latência de operação.
    pub wall_time_ns: u64,

    pub latency: LatencyStats,

    pub executable_hash: ContentHash,
    pub loaded_libraries: Vec<String>,
}

/// Estatísticas robustas para detecção (mediana + dispersão via MAD).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    pub sample_count: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    /// Median absolute deviation (nanosegundos).
    pub mad_ns: u64,
}
