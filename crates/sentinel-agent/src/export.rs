//! SIEM JSONL append and HTTP webhooks after integrity scans (egress policy).

use sentinel_inventory::{count_problems, InventoryDiff, VerifyFinding};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebhookWhen {
    #[default]
    Dirty,
    Always,
    Never,
}

impl From<sentinel_inventory::WebhookWhenToml> for WebhookWhen {
    fn from(v: sentinel_inventory::WebhookWhenToml) -> Self {
        match v {
            sentinel_inventory::WebhookWhenToml::Dirty => Self::Dirty,
            sentinel_inventory::WebhookWhenToml::Always => Self::Always,
            sentinel_inventory::WebhookWhenToml::Never => Self::Never,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExportPolicy {
    pub siem_file: Option<PathBuf>,
    pub webhook_url: Option<String>,
    pub webhook_when: WebhookWhen,
    pub compress_snapshots: bool,
}

impl ExportPolicy {
    pub fn webhook_enabled(&self, dirty: bool) -> bool {
        if self.webhook_url.as_deref().is_none_or(str::is_empty) {
            return false;
        }
        match self.webhook_when {
            WebhookWhen::Never => false,
            WebhookWhen::Always => true,
            WebhookWhen::Dirty => dirty,
        }
    }
}

fn now_ts() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

pub fn build_scan_event(
    exit_code: i32,
    dirty: bool,
    baseline: &str,
    current: &str,
    diff: &InventoryDiff,
    findings: &[VerifyFinding],
) -> serde_json::Value {
    json!({
        "ts": now_ts(),
        "event": "integrity_scan",
        "exit_code": exit_code,
        "dirty": dirty,
        "baseline": baseline,
        "current": current,
        "summary": {
            "packages_changed": diff.packages_changed.len(),
            "hash_changed": diff.executables_hash_changed.len(),
            "orphans_added": diff.orphans_added.len(),
            "verify_problems": count_problems(findings),
        },
    })
}

pub fn append_siem_line(path: &Path, event: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn post_webhook(url: &str, event: serde_json::Value) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(url)
        .header("User-Agent", "chronos-sentinel/0.1")
        .json(&event)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("webhook HTTP {}", resp.status()))
    }
}

pub async fn emit_scan_exports(
    policy: &ExportPolicy,
    dirty: bool,
    exit_code: i32,
    baseline: &str,
    current: &str,
    diff: &InventoryDiff,
    findings: &[VerifyFinding],
    quiet: bool,
) {
    let event = build_scan_event(exit_code, dirty, baseline, current, diff, findings);
    if let Some(path) = &policy.siem_file {
        match append_siem_line(path, &event) {
            Ok(()) => {
                if !quiet {
                    eprintln!("SIEM append → {}", path.display());
                }
            }
            Err(e) => eprintln!("SIEM export failed: {e}"),
        }
    }
    if policy.webhook_enabled(dirty) {
        let url = policy.webhook_url.clone().expect("checked");
        match post_webhook(&url, event).await {
            Ok(()) => {
                if !quiet {
                    eprintln!("Webhook delivered");
                }
            }
            Err(e) => eprintln!("Webhook failed: {e}"),
        }
    }
}
