//! Linux: match `/proc/pid/exe`, signal processes from policy paths (conservative, auditable).

use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct MitigationAction {
    pub pid: u32,
    pub signal: i32,
    pub reason: String,
    /// `false` for dry-run or allowlisted processes.
    pub applied: bool,
}

/// How process signals are applied (policy layer — separate from inventory).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MitigationPolicy {
    /// Never call `kill`; only record what would happen.
    pub dry_run: bool,
    /// PIDs that must never receive a signal.
    pub allow_pids: HashSet<u32>,
    /// Names from `/proc/<pid>/comm` (exact match) that are never signaled.
    pub allow_comm: Vec<String>,
    /// Required to send signals when `mitigate` is enabled (unless `dry_run`).
    pub confirmed: bool,
}

impl MitigationPolicy {
    pub fn applies_signals(&self) -> bool {
        !self.dry_run && self.confirmed
    }
}

pub fn find_pids_by_exe_path(target: &str) -> Vec<u32> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        Vec::new()
    }
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let exe = PathBuf::from(format!("/proc/{pid}/exe"));
            if path_matches_target(&exe, target) {
                out.push(pid);
            }
        }
        out
    }
}

#[cfg(target_os = "linux")]
fn path_matches_target(exe_link: &Path, target: &str) -> bool {
    let Ok(link) = std::fs::read_link(exe_link) else {
        return false;
    };
    let path = link.to_string_lossy();
    path == target || path.ends_with(target.trim_start_matches('/'))
}

#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{pid}/comm");
    let text = std::fs::read_to_string(comm_path).ok()?;
    Some(text.trim().to_string())
}

#[cfg(target_os = "linux")]
fn pid_is_allowlisted(pid: u32, policy: &MitigationPolicy) -> bool {
    if policy.allow_pids.contains(&pid) {
        return true;
    }
    if let Some(comm) = read_proc_comm(pid) {
        return policy.allow_comm.iter().any(|c| c == &comm);
    }
    false
}

pub fn signal_pid(pid: u32, signal: i32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(pid.to_string())
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill exited with {status}"))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, signal);
        Err("process mitigation requires Linux".into())
    }
}

pub fn mitigate_paths(
    paths: &[String],
    signal: i32,
    policy: &MitigationPolicy,
) -> Vec<MitigationAction> {
    let mut actions = Vec::new();
    for path in paths {
        for pid in find_pids_by_exe_path(path) {
            if pid <= 1 {
                continue;
            }
            #[cfg(target_os = "linux")]
            if pid_is_allowlisted(pid, policy) {
                actions.push(MitigationAction {
                    pid,
                    signal,
                    reason: format!("allowlisted: skipped pid {pid} for {path}"),
                    applied: false,
                });
                continue;
            }
            let base = format!("suspicious artifact {path}");
            if !policy.applies_signals() {
                let mode = if policy.dry_run {
                    "dry-run"
                } else {
                    "awaiting --mitigate-confirm"
                };
                actions.push(MitigationAction {
                    pid,
                    signal,
                    reason: format!("{mode}: would SIGTERM pid {pid} ({base})"),
                    applied: false,
                });
                continue;
            }
            let reason = format!("sentinel policy: {base}");
            let applied = signal_pid(pid, signal).is_ok();
            actions.push(MitigationAction {
                pid,
                signal,
                reason,
                applied,
            });
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_to_no_signals() {
        let p = MitigationPolicy::default();
        assert!(!p.applies_signals());
    }

    #[test]
    fn confirm_without_dry_run_applies() {
        let p = MitigationPolicy {
            confirmed: true,
            ..Default::default()
        };
        assert!(p.applies_signals());
    }
}
