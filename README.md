# chronos-sentinel

Integrity baseline for **Arch Linux**: pacman inventory, BLAKE3 hashes, diff and on-disk verify. Snapshots live under `.chronos/` (gitignored). Policy and scheduling run on **Byteflow** [`byteflow-actors`](https://docs.rs/byteflow-actors) **0.9.23** (hard dependency).

| Requirement | Value |
|-------------|--------|
| OS (production) | Arch Linux + pacman |
| Rust | 1.99.1 (`rust-toolchain.toml`, MSVC on Windows for dev builds) |
| Binary | `cargo build -p sentinel-cli` → `chronos-sentinel` |
| State dir | `CHRONOS_STATE_DIR` → `$XDG_STATE_HOME/chronos-sentinel` → `~/.local/state/chronos-sentinel` (Linux) → `.chronos/` (fallback) |
| Packages | `packaging/aur/PKGBUILD` · GitHub release binaries on tag `v*` |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |

## Commands

```bash
chronos-sentinel try              # demo: on → status → off (Windows-friendly)
chronos-sentinel on   [-d|--demo|--dem]
chronos-sentinel off  [-d] [--json] [--mitigate] [--mitigate-confirm] [--mitigate-dry-run]
chronos-sentinel status
chronos-sentinel agent [-d] [--interval 300] [--mitigate ...]
chronos-sentinel --state-dir /var/lib/chronos-sentinel on
```

Run **`chronos-sentinel`** with no subcommand to print a quick-start on stderr.

### Windows / dev

Pacman paths do not exist on Windows. Use **`try`** or **`-d`** on `on`/`off`. Without `-d`, the CLI exits with a short hint (exit `2`).

```powershell
cargo build -p sentinel-cli
.\target\debug\chronos-sentinel.exe try
```

One command per line (do not paste `on`, `status`, `off` on the same line unless separated with `;`).

### Configuration (inventory TOML)

Inventory paths and scans are configured separately from mitigation policy:

| Source | Precedence |
|--------|------------|
| Built-in defaults | lowest |
| Config file (`[inventory]`) | middle |
| CLI (`--config`, `--pacman-db`, `--full-files`) | highest |

Search order for config: `--config` → `CHRONOS_CONFIG` → `$XDG_CONFIG_HOME/chronos-sentinel/config.toml` → `~/.config/chronos-sentinel/config.toml` → `/etc/chronos-sentinel/config.toml`.

Example: [`packaging/chronos-sentinel.example.toml`](packaging/chronos-sentinel.example.toml) — customize `integrity_prefixes`, `scan_roots`, `lib_roots`, `files_scope`.

```bash
sudo install -Dm644 packaging/chronos-sentinel.example.toml /etc/chronos-sentinel/config.toml
chronos-sentinel on
```

### Data collection (Linux)

1. **Pacman** — `pacman -Q` plus `%NAME%`, `%VERSION%`, `%FILES%` from `/var/lib/pacman/local/*/desc` (one indexed pass over the DB).
2. **Primary hashes** — by default only **prefix subsets** of `%FILES%` (not the full list, on purpose — size): `usr/bin/`, `usr/sbin/`, `usr/local/bin/`, `usr/lib/`, `lib/`, `etc/ssh/`. Use global `--full-files` for every `%FILES%` row. Each in-scope path becomes an artifact even if **missing on disk** (hash when present).
3. **Supplemental walk** — scan of `/usr/bin`, `/usr/local/bin`, `/usr/lib` for items not already in the pacman-derived set; unowned → `orphan_executables`.
4. **Snapshot** — JSON includes `collection` (`pacman_file_records`, `integrity_paths_in_db`, `integrity_scope`, `artifacts_hashed`, `artifacts_missing_on_disk`, `bin_scan_orphans`). Diff reports `%FILES%` adds/removes per package (same version included).

`on` / `off` enable hashing and lib scan by default. Demo mode uses synthetic packages only (no disk walk).

### `on` / `off` / `status`

| Step | Files | Output |
|------|--------|--------|
| `on` | writes `.chronos/baseline.json` | stderr summary |
| `off` | writes `.chronos/last-check.json` | diff + verify report on stderr (or JSON with `--json`) |
| `status` | reads baseline path | whether baseline exists |

**Exit codes (`off`):** `0` OK · `1` drift or verify failure · `2` no baseline (run `on` first). With `--demo`, drift does not force exit `1`.

**Mitigation (Linux):** `--mitigate` evaluates suspicious paths after a dirty diff. **No signals by default** — use `--mitigate-dry-run` for explicit audit-only, or `--mitigate-confirm` to send SIGTERM. Skip PIDs with `--mitigate-allow-pid` / `--mitigate-allow-comm`. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### systemd

```bash
sudo install -Dm644 packaging/systemd/chronos-sentinel.service /usr/lib/systemd/system/
sudo mkdir -p /var/lib/chronos-sentinel
sudo systemctl enable --now chronos-sentinel.service
```

The unit sets `CHRONOS_STATE_DIR=/var/lib/chronos-sentinel` and runs `agent` without destructive mitigation.

### Byteflow in this process

- **`on` / `off` / `status`:** one sandboxed flow per invocation (`sentinel_run` native → inventory/diff in Rust).
- **Heartbeat:** removed from one-shot CLI (was interleaving output). **`agent`** is the long-running Byteflow loop.
- **`agent`:** foreground loop — repeated `off` every **300s** by default (systemd-friendly).

## Build & test

```bash
cargo build -p sentinel-cli
cargo test --workspace
```

## Inventory CLI (direct crates, no Byteflow)

```bash
chronos-sentinel inventory --hash --libs -o snap.json
chronos-sentinel diff --before a.json --after b.json
chronos-sentinel verify --snapshot snap.json
chronos-sentinel hash /usr/bin/sshd
```

Global flags: `--config`, `--pacman-db`, `--state-dir`, `--full-files` (see `chronos-sentinel help`).

To use a local Byteflow tree, edit `crates/sentinel-agent/Cargo.toml`:

```toml
byteflow = { package = "byteflow-actors", path = "../../../Bytecode/byteflow" }
```

## Workspace

| Crate | Role |
|-------|------|
| `sentinel-cli` | `chronos-sentinel` entrypoint |
| `sentinel-agent` | Byteflow runtime, mitigation, heartbeat |
| `sentinel-inventory` | pacman, snapshot, diff, verify |
| `sentinel-integrity` | BLAKE3 |
| `sentinel-storage` | JSON I/O |
| `sentinel-analyzer` | Text reports |
| `sentinel-core` | Shared types |
| `sentinel-ebpf`, `sentinel-profiler` | Reserved |

## License

Dual-licensed under **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`).
