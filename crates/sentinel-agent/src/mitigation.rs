//! Linux: match `/proc/pid/exe`, signal processes from policy paths.

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct MitigationAction {
    pub pid: u32,
    pub signal: i32,
    pub reason: String,
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

pub fn mitigate_paths(paths: &[String], signal: i32) -> Vec<MitigationAction> {
    let mut actions = Vec::new();
    for path in paths {
        for pid in find_pids_by_exe_path(path) {
            if pid <= 1 {
                continue;
            }
            let reason = format!("sentinel policy: suspicious artifact {path}");
            if signal_pid(pid, signal).is_ok() {
                actions.push(MitigationAction {
                    pid,
                    signal,
                    reason,
                });
            }
        }
    }
    actions
}
