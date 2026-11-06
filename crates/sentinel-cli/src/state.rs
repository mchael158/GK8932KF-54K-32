use std::path::PathBuf;

pub fn state_dir() -> PathBuf {
    PathBuf::from(".chronos")
}

pub fn baseline_path() -> PathBuf {
    state_dir().join("baseline.json")
}

pub fn baseline_missing_message() -> &'static str {
    "No baseline yet. Run: chronos-sentinel on -d   (or: chronos-sentinel try)"
}

pub fn print_off_header() {
    eprintln!("OFF — comparing to baseline");
}
