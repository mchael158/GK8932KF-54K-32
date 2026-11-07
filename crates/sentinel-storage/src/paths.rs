//! Where baseline JSON lives: `CHRONOS_STATE_DIR`, XDG, or cwd fallback.

use std::path::{Path, PathBuf};

const APP_DIR: &str = "chronos-sentinel";

/// Resolve state directory (creates nothing).
pub fn resolve_state_dir(override_dir: Option<&Path>) -> PathBuf {
    if let Some(p) = override_dir {
        return p.to_path_buf();
    }
    if let Ok(dir) = std::env::var("CHRONOS_STATE_DIR") {
        let p = dir.trim();
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        let p = xdg.trim();
        if !p.is_empty() {
            return PathBuf::from(p).join(APP_DIR);
        }
    }
    #[cfg(unix)]
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(APP_DIR);
    }
    PathBuf::from(".chronos")
}

pub fn baseline_path(state_dir: &Path) -> PathBuf {
    state_dir.join("baseline.json")
}

pub fn last_check_path(state_dir: &Path) -> PathBuf {
    state_dir.join("last-check.json")
}

pub fn ensure_state_dir(state_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn chronos_state_dir_wins() {
        let _g = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom-state");
        std::env::set_var("CHRONOS_STATE_DIR", &custom);
        std::env::remove_var("XDG_STATE_HOME");
        assert_eq!(resolve_state_dir(None), custom);
        std::env::remove_var("CHRONOS_STATE_DIR");
    }

    #[test]
    fn xdg_state_home_when_no_chronos() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var("CHRONOS_STATE_DIR");
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_STATE_HOME", dir.path());
        let resolved = resolve_state_dir(None);
        assert_eq!(resolved, dir.path().join(APP_DIR));
        std::env::remove_var("XDG_STATE_HOME");
    }

    #[test]
    fn override_skips_env() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("CHRONOS_STATE_DIR", "/should/not/use");
        let explicit = PathBuf::from("/explicit/state");
        assert_eq!(resolve_state_dir(Some(&explicit)), explicit);
        std::env::remove_var("CHRONOS_STATE_DIR");
    }
}
