use sentinel_storage::{baseline_path as storage_baseline, resolve_state_dir};
use std::path::{Path, PathBuf};

pub fn state_dir(cli_override: Option<&Path>) -> PathBuf {
    resolve_state_dir(cli_override)
}

pub fn baseline_path(cli_override: Option<&Path>) -> PathBuf {
    storage_baseline(&state_dir(cli_override))
}

pub fn baseline_missing_message(cli_override: Option<&Path>) -> String {
    let path = baseline_path(cli_override);
    #[cfg(target_os = "linux")]
    {
        format!(
            "No baseline at {}. Run: chronos-sentinel on",
            path.display()
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!(
            "No baseline at {}. Run: chronos-sentinel on -d   (or: chronos-sentinel try)",
            path.display()
        )
    }
}

pub fn print_off_header() {
    eprintln!("OFF — comparing to baseline");
}
