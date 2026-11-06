//! Maps Byteflow [`SecurityEvent`] into Chronos audit records.

use byteflow::SecurityEvent;
use sentinel_core::{ContentHashRef, HashAlgorithm, SentinelEvent};
use std::sync::Mutex;
use time::OffsetDateTime;

/// Attach to [`byteflow::RuntimeConfig::security_audit`].
#[derive(Debug, Default)]
pub struct SentinelAuditSink {
    log: Mutex<Vec<String>>,
}

impl SentinelAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drain_lines(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().expect("audit log poisoned"))
    }
}

impl byteflow::SecurityAuditSink for SentinelAuditSink {
    fn record(&self, event: &SecurityEvent) {
        let line = format_security_event(event);
        self.log.lock().expect("audit log poisoned").push(line);
    }
}

pub fn format_security_event(event: &SecurityEvent) -> String {
    event.to_string()
}

pub fn to_sentinel_event(event: &SecurityEvent) -> Option<SentinelEvent> {
    let recorded_at = OffsetDateTime::now_utc();
    match event {
        SecurityEvent::ModuleRejected { reason } => Some(SentinelEvent::FileIntegrityChange {
            path: format!("byteflow:module:{reason}"),
            previous_hash: None,
            current_hash: ContentHashRef {
                algorithm: HashAlgorithm::Blake3,
                hex: "rejected".into(),
            },
            owner_package: None,
            recorded_at,
        }),
        SecurityEvent::NativeDenied { index } => Some(SentinelEvent::FileIntegrityChange {
            path: format!("byteflow:native:{index}"),
            previous_hash: None,
            current_hash: ContentHashRef {
                algorithm: HashAlgorithm::Blake3,
                hex: "denied".into(),
            },
            owner_package: None,
            recorded_at,
        }),
        _ => None,
    }
}
