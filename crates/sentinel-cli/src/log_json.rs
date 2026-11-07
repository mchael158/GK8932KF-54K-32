//! One JSON object per line on stderr (SIEM-friendly).

use serde_json::{json, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn enabled(cli_flag: bool) -> bool {
    cli_flag
        || std::env::var("CHRONOS_LOG_JSON")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

pub fn emit(event: &str, fields: Value) {
    let line = json!({
        "ts": timestamp(),
        "event": event,
        "chronos": fields,
    });
    eprintln!("{line}");
}

pub fn command_start(command: &str) {
    emit("command_start", json!({ "command": command }));
}

pub fn command_done(command: &str, exit_code: i32) {
    emit(
        "command_done",
        json!({ "command": command, "exit_code": exit_code }),
    );
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
    fn env_enables_json_logs() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var("CHRONOS_LOG_JSON");
        assert!(!enabled(false));
        std::env::set_var("CHRONOS_LOG_JSON", "1");
        assert!(enabled(false));
        std::env::remove_var("CHRONOS_LOG_JSON");
    }
}

pub fn config_loaded(path: Option<&std::path::Path>) {
    emit(
        "config_loaded",
        json!({
            "path": path.map(|p| p.display().to_string()),
            "discovered": path.is_some(),
        }),
    );
}
