//! Contratos compartilhados entre agente, inventário, profiler e analisador.

mod event;
mod identity;
mod profile;

pub use event::{ExecutionObservation, SentinelEvent};
pub use identity::{ContentHash, HashAlgorithm, ProcessStartId};
pub use profile::{LatencyStats, ProcessProfile};
