# chronos-sentinel

Pacman inventory, BLAKE3 baselines, diff/verify on Arch Linux. State: `.chronos/*.json` (gitignored). Supervisor: Byteflow `byteflow-actors` 0.9.23 (required).

Toolchain: Rust 1.99.1, `rust-toolchain.toml`.

## Commands

```text
chronos-sentinel on [--demo]
chronos-sentinel off [--demo] [--json] [--mitigate]
chronos-sentinel status
chronos-sentinel agent [--interval 300] [--demo] [--mitigate]
```

`on` → `.chronos/baseline.json`. `off` → `.chronos/last-check.json`, report on stderr, exit `1` on drift (exit `2` without baseline). `--mitigate`: Linux, SIGTERM on `/proc/*/exe` matching changed/orphan paths from diff.

While a one-shot subcommand runs, a 60s Byteflow `status` loop shares the process (skipped for `agent`, which runs periodic `off` in the foreground).

## Build

```bash
cargo build -p sentinel-cli
cargo test --workspace
```

## Manual export (no Byteflow)

```bash
chronos-sentinel inventory --hash --libs -o snap.json
chronos-sentinel diff --before a.json --after b.json
chronos-sentinel verify --snapshot snap.json
chronos-sentinel hash /path/to/file
```

`--pacman-db` (hidden): pacman local DB path.

Override Byteflow crate path in `crates/sentinel-agent/Cargo.toml` if needed.

## Layout

- `sentinel-cli` — binary
- `sentinel-agent` — Byteflow brain, mitigation, heartbeat
- `sentinel-inventory`, `sentinel-integrity`, `sentinel-storage`, `sentinel-analyzer`, `sentinel-core`
- `sentinel-ebpf`, `sentinel-profiler` — stubs

MIT OR Apache-2.0
