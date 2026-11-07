pub fn print_quickstart() {
    eprintln!(
        r#"chronos-sentinel — pacman integrity (Arch). State: CHRONOS_STATE_DIR or XDG (~/.local/state/chronos-sentinel); else .chronos/

Quick start (Windows / dev — synthetic data):
  chronos-sentinel try              one shot: on → status → off (all demo)
  chronos-sentinel on  -d           baseline (state dir/baseline.json)
  chronos-sentinel off -d           diff + verify
  chronos-sentinel status

Production (Arch Linux, real pacman):
  chronos-sentinel on
  chronos-sentinel off

Config: --config <toml>  |  CHRONOS_CONFIG  |  XDG  |  /etc/chronos-sentinel/config.toml
Flags:  -d  demo   |  -v  audit   |  --pacman-db   |  --state-dir   |  --full-files   |  off --json
Mitigate:  --mitigate (audit)  --mitigate-dry-run  --mitigate-confirm (SIGTERM, destructive)
          --mitigate-allow-pid / --mitigate-allow-comm

Run one command per line (PowerShell: use `;` between commands, not newlines in paste).
  .\target\debug\chronos-sentinel.exe try

Completions: chronos-sentinel completions bash
Logs: --log-json  |  Docs: docs/OPERATIONS.pt-BR.md  |  Help: chronos-sentinel help on"#
    );
}

pub fn require_demo_on_host(demo: bool, verb: &str) {
    #[cfg(not(target_os = "linux"))]
    if !demo {
        eprintln!(
            "{verb}: sem pacman no host — use -d/--demo ou: chronos-sentinel try"
        );
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    if !demo {
        let _ = verb;
    }
}
