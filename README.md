# GK8932KF-54K-32

Rust CLI (**chronos-sentinel**): pacman inventory, binary and library scans, BLAKE3 hashes, JSON snapshot diff, and on-disk verification. CLI only — no GUI, no Tauri, no embedded database.

Use real collection on Linux/Arch; use `--demo` on Windows for smoke tests.

## Build

```bash
cargo build -p sentinel-cli
```

## Commands

```bash
# Inventory
chronos-sentinel inventory
chronos-sentinel inventory --hash --libs -o snap.json

# Diff
chronos-sentinel diff --before a.json --after b.json
chronos-sentinel diff --before a.json --after b.json --verbose

# Integrity (snapshot must be created with --hash)
chronos-sentinel verify --snapshot snap.json

# Standalone hash
chronos-sentinel hash /usr/bin/sshd

# Dev
chronos-sentinel inventory --demo -o demo.json
```

Global flag `--pacman-db` overrides `/var/lib/pacman/local`.

Persistence is plain JSON you choose (`-o` or `--json`).

## Crates

`sentinel-core`, `sentinel-inventory`, `sentinel-integrity`, `sentinel-storage` (JSON I/O), `sentinel-analyzer` (text reports), `sentinel-cli`. Stubs: `agent`, `ebpf`, `profiler`.

## License

MIT OR Apache-2.0 — see `LICENSE-MIT` and `LICENSE-APACHE`.
