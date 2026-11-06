use serde::{Deserialize, Serialize};

/// Identificador estável de uma instância de processo (evita reutilização de PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStartId {
    pub pid: u32,
    /// Tempo de início do processo em nanosegundos desde boot (clock monotônico do kernel).
    pub start_time_ns: u64,
}

/// Hash de conteúdo de executável ou biblioteca (hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash {
    pub algorithm: HashAlgorithm,
    pub hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
}
