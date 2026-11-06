use sentinel_inventory::CollectOptions;
use std::path::{Path, PathBuf};

pub fn state_dir() -> PathBuf {
    PathBuf::from(".chronos")
}

pub fn baseline_path() -> PathBuf {
    state_dir().join("baseline.json")
}

pub fn last_check_path() -> PathBuf {
    state_dir().join("last-check.json")
}

pub fn collect_opts(pacman_db: PathBuf, demo: bool) -> CollectOptions {
    CollectOptions {
        pacman_db,
        hash_executables: true,
        scan_libraries: true,
        demo,
        ..CollectOptions::default()
    }
}

pub fn baseline_missing_message() -> &'static str {
    "No baseline yet. Run: chronos-sentinel on"
}

pub fn print_on_ok(path: &Path, package_count: usize) {
    eprintln!("ON");
    eprintln!("  baseline: {}", path.display());
    eprintln!("  packages: {package_count}");
}

pub fn print_off_header() {
    eprintln!("OFF — comparing to baseline");
}

pub fn print_status(active: bool, baseline: &Path, collected_at: Option<&str>) {
    if active {
        eprintln!("status: ON");
        eprintln!("  baseline: {}", baseline.display());
        if let Some(t) = collected_at {
            eprintln!("  captured: {t}");
        }
    } else {
        eprintln!("status: OFF (no baseline)");
        eprintln!("  run: chronos-sentinel on");
    }
}
