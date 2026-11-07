//! Text reports for the CLI (no GUI).

use sentinel_inventory::{InventoryDiff, VerifyFinding, VerifyStatus};
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct AnomalyReport {
    pub summary: String,
    pub recommendation: String,
}

pub fn summarize_inventory_diff(diff: &InventoryDiff) -> AnomalyReport {
    let mut parts = Vec::new();
    if !diff.packages_changed.is_empty() {
        parts.push(format!(
            "{} package(s) upgraded",
            diff.packages_changed.len()
        ));
    }
    if !diff.executables_hash_changed.is_empty() {
        parts.push(format!(
            "{} artifact(s) with hash change",
            diff.executables_hash_changed.len()
        ));
    }
    if !diff.orphans_added.is_empty() {
        parts.push(format!("{} new orphan(s)", diff.orphans_added.len()));
    }
    let summary = if parts.is_empty() {
        "No relevant changes".into()
    } else {
        parts.join("; ")
    };
    let recommendation = if !diff.executables_hash_changed.is_empty() {
        "Correlate hash changes with package upgrades and inspect shared libraries.".into()
    } else if !diff.packages_changed.is_empty() {
        "Confirm package upgrades were intentional.".into()
    } else {
        "Review the full diff if anything looks unexpected.".into()
    };
    AnomalyReport {
        summary,
        recommendation,
    }
}

pub fn format_diff_report(before_label: &str, after_label: &str, diff: &InventoryDiff) -> String {
    let report = summarize_inventory_diff(diff);
    let mut out = String::new();
    let _ = writeln!(out, "CHRONOS SENTINEL — DIFF");
    let _ = writeln!(out, "Before:  {before_label}");
    let _ = writeln!(out, "After:   {after_label}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Packages:    +{}  -{}  ~{}",
        diff.packages_added.len(),
        diff.packages_removed.len(),
        diff.packages_changed.len()
    );
    let _ = writeln!(
        out,
        "Artifacts:   +{}  -{}  hash~{}",
        diff.executables_added.len(),
        diff.executables_removed.len(),
        diff.executables_hash_changed.len()
    );
    let _ = writeln!(
        out,
        "Orphans:     +{}  -{}",
        diff.orphans_added.len(),
        diff.orphans_removed.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Summary: {}", report.summary);
    let _ = writeln!(out, "-> {}", report.recommendation);

    if !diff.packages_changed.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Changed packages:");
        for ch in diff.packages_changed.iter().take(20) {
            let _ = writeln!(
                out,
                "  {}  {} -> {}",
                ch.name, ch.old_version, ch.new_version
            );
            for f in ch.files_added.iter().take(8) {
                let _ = writeln!(out, "    + {f}");
            }
            for f in ch.files_removed.iter().take(8) {
                let _ = writeln!(out, "    - {f}");
            }
        }
    }
    if !diff.executables_hash_changed.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Hash changes:");
        for h in diff.executables_hash_changed.iter().take(20) {
            let _ = writeln!(
                out,
                "  {}  {} -> {}",
                h.path,
                h.old_hash.as_deref().unwrap_or("?"),
                h.new_hash.as_deref().unwrap_or("?")
            );
        }
    }
    if !diff.orphans_added.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "New orphans:");
        for o in diff.orphans_added.iter().take(20) {
            let _ = writeln!(out, "  {}", o.path);
        }
    }
    out
}

pub fn format_verify_report(findings: &[VerifyFinding]) -> String {
    let mut out = String::new();
    let problems: Vec<_> = findings
        .iter()
        .filter(|f| !matches!(f.status, VerifyStatus::Ok | VerifyStatus::NoBaseline))
        .collect();
    let _ = writeln!(out, "CHRONOS SENTINEL — VERIFY");
    let _ = writeln!(out, "Items: {}  issues: {}", findings.len(), problems.len());
    if problems.is_empty() {
        let _ = writeln!(out, "No mismatches (items with a baseline hash).");
        return out;
    }
    let _ = writeln!(out);
    for f in problems.iter().take(50) {
        let detail = match &f.status {
            VerifyStatus::Missing => "file missing".to_string(),
            VerifyStatus::NoBaseline => continue,
            VerifyStatus::Ok => continue,
            VerifyStatus::HashMismatch { expected, actual } => {
                format!("hash {expected} -> {actual}")
            }
        };
        let owner = f
            .owning_package
            .as_deref()
            .map(|p| format!(" ({p})"))
            .unwrap_or_default();
        let _ = writeln!(out, "  {}{} — {}", f.path, owner, detail);
    }
    out
}
