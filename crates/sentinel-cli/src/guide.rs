pub fn print_quickstart() {
    eprintln!(
        r#"chronos-sentinel — pacman integrity (Arch). Snapshots in .chronos/

Quick start (Windows / dev — synthetic data):
  chronos-sentinel try              one shot: on → status → off (all demo)
  chronos-sentinel on  -d           baseline (.chronos/baseline.json)
  chronos-sentinel off -d           diff + verify
  chronos-sentinel status

Production (Arch Linux, real pacman):
  chronos-sentinel on
  chronos-sentinel off

Flags:  -d, --demo, --dem   demo snapshot   |   -v  Byteflow audit   |   off --json

Run one command per line (PowerShell: use `;` between commands, not newlines in paste).
  .\target\debug\chronos-sentinel.exe try

Help:  chronos-sentinel help on"#
    );
}

pub fn require_demo_on_host(demo: bool, verb: &str) {
    #[cfg(not(target_os = "linux"))]
    if !demo {
        eprintln!(
            "{verb}: this OS has no pacman DB — add -d (or --demo), or run: chronos-sentinel try"
        );
        std::process::exit(2);
    }
}
