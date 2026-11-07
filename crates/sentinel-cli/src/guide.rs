pub fn print_quickstart() {
    eprintln!(
        r#"chronos-sentinel — pacman integrity (Arch). State: CHRONOS_STATE_DIR or XDG (~/.local/state/chronos-sentinel); else .chronos/

Windows / produção local (um comando por vez — espere o prompt):
  chronos-sentinel on               baseline real (PATH + MSYS2 se houver)
  chronos-sentinel off              diff + verify (re-varre; pode levar minutos)
  chronos-sentinel on -d / off -d   demo sintético (segundos)
  chronos-sentinel try              on + status + off (2 varreduras — só teste)
  chronos-sentinel status           leitura (sem lock de varredura)

Segunda instância on/off/try/agent no mesmo state dir → recusada (run.lock, código 2).

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
    let _ = (demo, verb);
}
