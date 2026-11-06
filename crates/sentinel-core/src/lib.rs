//! Shared types, events, and internal contracts.

mod event;
mod identity;
mod profile;

pub use event::{ContentHashRef, ExecutionObservation, SentinelEvent};
pub use identity::{ContentHash, HashAlgorithm, ProcessStartId};
pub use profile::{LatencyStats, ProcessProfile};
