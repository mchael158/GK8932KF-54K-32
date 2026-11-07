//! One scan/brain run at a time per state directory (`run.lock`).

use crate::paths::ensure_state_dir;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

const LOCK_NAME: &str = "run.lock";

#[derive(Debug, Error)]
pub enum RunLockError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "outra instância em execução (PID {pid}, comando «{command}», desde {started}). \
Espere o prompt voltar ou encerre o processo; se travou, apague {lock_path}"
    )]
    Busy {
        pid: u32,
        command: String,
        started: String,
        lock_path: PathBuf,
    },
}

/// Held for the whole `on` / `off` / `try` / `inventory` / `agent` run; removes `run.lock` on drop.
#[derive(Debug)]
pub struct RunLock {
    path: PathBuf,
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn run_lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCK_NAME)
}

pub fn try_acquire_run_lock(state_dir: &Path, command: &str) -> Result<RunLock, RunLockError> {
    ensure_state_dir(state_dir)?;
    let path = run_lock_path(state_dir);
    match try_create_lock(&path, command) {
        Ok(()) => Ok(RunLock { path }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if let Some(stale) = read_lock(&path).filter(|rec| !process_alive(rec.pid)) {
                let _ = std::fs::remove_file(&path);
                let _ = stale;
                try_create_lock(&path, command)?;
                return Ok(RunLock { path });
            }
            if let Some(rec) = read_lock(&path) {
                return Err(RunLockError::Busy {
                    pid: rec.pid,
                    command: rec.command,
                    started: rec.started,
                    lock_path: path,
                });
            }
            Err(RunLockError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("lock exists at {}", path.display()),
            )))
        }
        Err(e) => Err(RunLockError::Io(e)),
    }
}

struct LockRecord {
    pid: u32,
    command: String,
    started: String,
}

fn try_create_lock(path: &Path, command: &str) -> std::io::Result<()> {
    let pid = std::process::id();
    let started = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into());
    let body = format!("pid={pid}\ncommand={command}\nstarted={started}\n");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn read_lock(path: &Path) -> Option<LockRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut pid = None;
    let mut command = String::new();
    let mut started = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("pid=") {
            pid = v.parse().ok();
        } else if let Some(v) = line.strip_prefix("command=") {
            command = v.to_string();
        } else if let Some(v) = line.strip_prefix("started=") {
            started = v.to_string();
        }
    }
    Some(LockRecord {
        pid: pid?,
        command,
        started,
    })
}

fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let out = String::from_utf8_lossy(&o.stdout);
                let line = out.lines().next().unwrap_or("");
                !line.is_empty() && !line.starts_with("INFO:")
            }
            _ => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let lock = try_acquire_run_lock(dir.path(), "test").unwrap();
        assert!(run_lock_path(dir.path()).is_file());
        drop(lock);
        assert!(!run_lock_path(dir.path()).exists());
    }

    #[test]
    fn second_acquire_busy() {
        let dir = tempfile::tempdir().unwrap();
        let _a = try_acquire_run_lock(dir.path(), "on").unwrap();
        let err = try_acquire_run_lock(dir.path(), "off").unwrap_err();
        assert!(matches!(err, RunLockError::Busy { .. }));
    }
}
