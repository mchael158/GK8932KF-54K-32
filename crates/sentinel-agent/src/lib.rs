//! Phase 2: agent loop, event ingestion, storage/analyzer hooks.

#[cfg(feature = "byteflow")]
pub mod byteflow_bridge;

pub async fn run_agent() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "byteflow")]
    {
        eprintln!(
            "sentinel-agent (byteflow {}): supervisor wiring TBD — use `on`/`off` for inventory today",
            env!("CARGO_PKG_VERSION")
        );
        let _ = byteflow_bridge::SentinelAuditSink::new();
    }
    #[cfg(not(feature = "byteflow"))]
    {
        eprintln!("sentinel-agent: not implemented yet (Phase 2 — eBPF/execve)");
        eprintln!("  tip: cargo build -p sentinel-agent --features byteflow");
    }
    Ok(())
}

#[cfg(all(test, feature = "byteflow"))]
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
