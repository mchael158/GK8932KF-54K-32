//! User-space agent: Byteflow runtime + host inventory hooks.

pub mod byteflow_bridge;
pub mod mitigation;
pub mod brain;
pub mod supervisor;

pub use brain::{BrainOptions, BrainResult, OpCode};

pub async fn run_agent(
    opts: BrainOptions,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    brain::run_daemon(opts, interval_secs).await
}

#[cfg(test)]
mod tests {
    use super::byteflow_bridge::{format_security_event, to_sentinel_event};
    use byteflow::SecurityEvent;

    #[test]
    fn maps_module_rejected() {
        let ev = SecurityEvent::ModuleRejected {
            reason: "verify_failed",
        };
        assert!(format_security_event(&ev).contains("module_rejected"));
        assert!(to_sentinel_event(&ev).is_some());
    }
}
