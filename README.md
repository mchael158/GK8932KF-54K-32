# chronos-sentinel

Pacman integrity baseline for **Arch Linux**: inventory, BLAKE3 hashes, diff, verify. Optional Ed25519 signing, SIEM/webhook export, and conservative process mitigation. **`on` / `off` / `status`** run through **Byteflow** [`byteflow-actors`](https://docs.rs/byteflow-actors) **0.9.23**; collection and diff are plain Rust.

**Production:** Arch + pacman only (v1). **Dev on Windows:** demo data (`try`, `-d`) — no real pacman.

| Requirement | Value |
|-------------|--------|
| OS (production) | Arch Linux + pacman |
| Rust | 1.99.1 (`rust-toolchain.toml`) |
| Releases | GitHub tag `v*` → Linux/Windows binaries · [`packaging/aur/PKGBUILD`](packaging/aur/PKGBUILD) |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |

---

## How it runs

### Operator flow

```text
  keygen (once)          on (baseline)              off / agent (compare)
        │                      │                            │
        ▼                      ▼                            ▼
   signing.key            baseline.json               last-check.json
   signing.pub                 │                     diff + verify (stderr)
                        baseline.json.sig          optional SIEM / webhook
                        [optional .json.zst]       exit 0 / 1 / 2
```

1. **`keygen`** — Ed25519 key pair (`signing.key`, `signing.pub.json`).
2. **`on`** — collect pacman + configured scans → write **baseline**; optionally **sign** and **compress** (`.zst` sidecar).
3. **`off`** — collect again, diff + verify vs baseline; optional mitigation (audit-first).
4. **`agent`** — loop: same as `off` every N seconds (use with **systemd**).

Exit codes on **`off`:** `0` clean · `1` drift or verify problems · `2` no baseline. Demo (`-d`) does not force `1` on drift.

### Where state and config live

**State directory** (baseline JSON), highest precedence first:

| Order | Source |
|-------|--------|
| 1 | `--state-dir` |
| 2 | `CHRONOS_STATE_DIR` |
| 3 | `$XDG_STATE_HOME/chronos-sentinel` (Linux) |
| 4 | `~/.local/state/chronos-sentinel` (Linux) |
| 5 | `.chronos/` in the current working directory |

Typical files: `baseline.json`, `last-check.json`, `baseline.json.sig`, `baseline.json.zst`.

**Config TOML** (`[inventory]`, `[export]`):

`--config` → `CHRONOS_CONFIG` → `$XDG_CONFIG_HOME/chronos-sentinel/config.toml` → `~/.config/chronos-sentinel/config.toml` → `/etc/chronos-sentinel/config.toml`.

Example: [`packaging/chronos-sentinel.example.toml`](packaging/chronos-sentinel.example.toml).

**Signing key:** `--signing-key` → `CHRONOS_SIGNING_KEY` → XDG → `/etc/chronos-sentinel/signing.key`.

### What goes into the baseline

1. **Pacman** — `pacman -Q` plus `%FILES%` from `/var/lib/pacman/local/*/desc`.
2. **Scope** — default: **prefix subsets** of `%FILES%` only (`usr/bin/`, `usr/lib/`, `etc/ssh/`, …), not the full file list. Override with `--full-files` or TOML `integrity_prefixes`.
3. **Supplemental walk** — `scan_roots` / `lib_roots` for orphans (on-disk files not owned by pacman in the tracked set).
4. **Snapshot JSON** — includes `collection.*` counters and `integrity_scope`.

Inventory (TOML `[inventory]`) is separate from policy (mitigation, export, signing flags on the CLI).

### Architecture (crates)

| Crate | Role |
|-------|------|
| `sentinel-inventory` | pacman, snapshot, diff, verify, config |
| `sentinel-storage` | JSON paths, Ed25519 signing, zstd sidecars |
| `sentinel-agent` | Byteflow brain, mitigation policy, SIEM/webhook |
| `sentinel-cli` | `chronos-sentinel` binary |

Byteflow sandboxes the control op only; hashing and diff always run in host Rust.

---

## Installing and invoking the binary

The command **`chronos-sentinel` is not on PATH** until you install it or call the built executable.

### Windows (development)

No pacman — use **`try`** or **`-d`** on `on`/`off`.

```powershell
cd path\to\GK8932KF-54K-32
cargo build -p sentinel-cli
.\target\debug\chronos-sentinel.exe try
.\target\debug\chronos-sentinel.exe on -d
.\target\debug\chronos-sentinel.exe off -d --log-json
```

Without building first:

```powershell
cargo run -p sentinel-cli -- try
```

Optional alias for the current session:

```powershell
Set-Alias chronos-sentinel "$PWD\target\debug\chronos-sentinel.exe"
```

Release binary: download `chronos-sentinel-windows-msvc.exe` from [GitHub Releases](https://github.com/mchael158/GK8932KF-54K-32/releases) (tag `v*`), rename to `chronos-sentinel.exe`, add its folder to PATH.

### Arch Linux (production)

```bash
# From release tarball or AUR PKGBUILD, or:
cargo build --release -p sentinel-cli
sudo install -m755 target/release/chronos-sentinel /usr/local/bin/

sudo install -Dm644 packaging/chronos-sentinel.example.toml /etc/chronos-sentinel/config.toml
sudo mkdir -p /var/lib/chronos-sentinel
chronos-sentinel keygen --output-dir /etc/chronos-sentinel

export CHRONOS_STATE_DIR=/var/lib/chronos-sentinel
chronos-sentinel on          # after a known-good system state
chronos-sentinel off         # ad-hoc check
```

**Continuous monitoring:**

```bash
sudo install -Dm644 packaging/systemd/chronos-sentinel.service /usr/lib/systemd/system/
sudo systemctl enable --now chronos-sentinel.service
```

The unit sets `CHRONOS_STATE_DIR=/var/lib/chronos-sentinel` and runs `agent` (default 300s) **without** destructive mitigation.

---

## Commands (reference)

```bash
chronos-sentinel try
chronos-sentinel on   [-d|--demo]
chronos-sentinel off  [-d] [--json] [--log-json] [--mitigate ...]
chronos-sentinel status
chronos-sentinel agent [--interval 300] [--mitigate ...]
chronos-sentinel keygen [--output-dir DIR]
chronos-sentinel sign-verify [--snapshot PATH]
chronos-sentinel completions {bash,fish,zsh}
chronos-sentinel gen-man --output packaging/man/chronos-sentinel.1
```

Run **`chronos-sentinel`** with no subcommand for a quick-start on stderr.

### Configuration precedence

| Layer | Applies to |
|-------|------------|
| Built-in defaults | inventory scan roots, prefixes |
| TOML `[inventory]` / `[export]` | paths, SIEM, webhook, compress |
| CLI globals | `--config`, `--pacman-db`, `--full-files`, `--state-dir`, `--signing-key`, `--siem-file`, `--webhook-url`, `--compress`, signing flags |

### Mitigation (Linux)

`--mitigate` never sends signals by default. Use `--mitigate-dry-run` or require `--mitigate-confirm` for SIGTERM. Allowlists: `--mitigate-allow-pid`, `--mitigate-allow-comm`. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Signing (Ed25519)

Sidecar `baseline.json.sig` covers BLAKE3(bytes of `baseline.json`) + Ed25519. Defaults: sign on `on` when a key exists; verify on `off` when `.sig` exists. Docs: [`docs/SIGNING.pt-BR.md`](docs/SIGNING.pt-BR.md).

### Export (SIEM / webhook / zstd)

`[export]` in TOML or `--siem-file`, `--webhook-url`, `--webhook-on {dirty,always,never}`, `--compress`. Webhook/SIEM failures log to stderr and **do not** change scan exit codes. Docs: [`docs/ENTERPRISE.pt-BR.md`](docs/ENTERPRISE.pt-BR.md) · [`docs/CONFIG.pt-BR.md`](docs/CONFIG.pt-BR.md) · [`docs/OPERATIONS.pt-BR.md`](docs/OPERATIONS.pt-BR.md).

### Completions, man, JSON logs

- `--log-json` or `CHRONOS_LOG_JSON=1` — one JSON object per line on stderr (`command_start`, `command_done`, `agent_scan`).
- Human diff/verify reports stay on stderr unless `off --json` (diff on stdout).

---

## Build and test

```bash
cargo build -p sentinel-cli
cargo test --workspace
```

### Inventory subcommands (no Byteflow)

```bash
chronos-sentinel inventory --hash --libs -o snap.json
chronos-sentinel diff --before a.json --after b.json
chronos-sentinel verify --snapshot snap.json
chronos-sentinel hash /usr/bin/sshd
```

### Local Byteflow source

```toml
# crates/sentinel-agent/Cargo.toml
byteflow = { package = "byteflow-actors", path = "../../../Bytecode/byteflow" }
```

## License

Dual-licensed under **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`).
