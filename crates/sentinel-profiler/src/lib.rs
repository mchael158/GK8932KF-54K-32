//! Incremental updates to `ProcessProfile` from observations.

use sentinel_core::{ExecutionObservation, LatencyStats, ProcessProfile};

/// Simple threshold: observed latency above P50 + k * MAD (Phase 3 placeholder).
pub fn is_latency_anomaly(stats: &LatencyStats, observed_ns: u64, k: f64) -> bool {
    if stats.sample_count < 30 {
        return false;
    }
    let threshold = stats.p50_ns as f64 + k * stats.mad_ns as f64;
    (observed_ns as f64) > threshold
}

pub fn touch_profile(profile: &mut ProcessProfile, obs: &ExecutionObservation) {
    profile.execution_count += 1;
    profile.cpu_time_ns += obs.cpu_time_ns;
    if let Some(w) = obs.wall_time_ns {
        profile.wall_time_ns += w;
    }
}
