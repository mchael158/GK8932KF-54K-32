# chronos-sentinel

Integrity baseline for **Arch Linux**: pacman inventory, BLAKE3 hashes, diff and on-disk verify. Snapshots live under `.chronos/` (gitignored). Policy and scheduling run on **Byteflow** [`byteflow-actors`](https://docs.rs/byteflow-actors) **0.9.23** (hard dependency).

| Requirement | Value |
|-------------|--------|
| OS (production) | Arch Linux + pacman |
| Rust | 1.99.1 (`rust-toolchain.toml`, MSVC on Windows for dev builds) |
| Binary | `cargo build -p sentinel-cli` → `chronos-sentinel` |

## Commands

```bash
chronos-sentinel try              # demo: on → status → off (Windows-friendly)
chronos-sentinel on   [-d|--demo|--dem]
chronos-sentinel off  [-d] [--json] [--mitigate]
chronos-sentinel status
chronos-sentinel agent [-d] [--interval 300] [--mitigate]
```

Run **`chronos-sentinel`** with no subcommand to print a quick-start on stderr.

### Windows / dev

Pacman paths do not exist on Windows. Use **`try`** or **`-d`** on `on`/`off`. Without `-d`, the CLI exits with a short hint (exit `2`).

```powershell
cargo build -p sentinel-cli
.\target\debug\chronos-sentinel.exe try
```

One command per line (do not paste `on`, `status`, `off` on the same line unless separated with `;`).

### Data collection (Linux)

1. **Pacman** — `pacman -Q` plus `%NAME%`, `%VERSION%`, `%FILES%` from `/var/lib/pacman/local/*/desc` (one indexed pass over the DB).
2. **Primary hashes** — for each relevant `%FILES%` path (`usr/bin`, `usr/sbin`, `usr/local/bin`, `usr/lib`, `lib`, `etc/ssh`), if the file exists on disk → BLAKE3 and owner = package name (no per-file `pacman -Qo`).
3. **Supplemental walk** — optional scan of `/usr/bin`, `/usr/local/bin`, `/usr/lib` for executables/libs **not** already covered; unowned hits → `orphan_executables`.
4. **Snapshot** — JSON includes `collection` stats (`pacman_file_records`, `integrity_paths_in_db`, `artifacts_hashed`, `bin_scan_orphans`).

`on` / `off` enable hashing and lib scan by default. Demo mode uses synthetic packages only (no disk walk).

### `on` / `off` / `status`

| Step | Files | Output |
|------|--------|--------|
| `on` | writes `.chronos/baseline.json` | stderr summary |
| `off` | writes `.chronos/last-check.json` | diff + verify report on stderr (or JSON with `--json`) |
| `status` | reads baseline path | whether baseline exists |

**Exit codes (`off`):** `0` OK · `1` drift or verify failure · `2` no baseline (run `on` first). With `--demo`, drift does not force exit `1`.

**`off --mitigate` (Linux):** after a dirty diff, send SIGTERM to processes whose `/proc/<pid>/exe` matches executables with hash changes or new orphans from the report.

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

Global hidden flag: `--pacman-db <path>` (default: `/var/lib/pacman/local`).

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
