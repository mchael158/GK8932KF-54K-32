# chronos-sentinel

ON/OFF integrity watch for Arch/Linux. No GUI, no database — baseline lives in `.chronos/` (gitignored).

**Toolchain:** Rust **1.99.1** (`rust-toolchain.toml`).

## Daily use

| Action | Command |
|--------|---------|
| **ON** — save baseline | `chronos-sentinel on` |
| **OFF** — scan & report | `chronos-sentinel off` |
| **Status** | `chronos-sentinel status` |

**ON** writes `.chronos/baseline.json` (packages, binaries, `/usr/lib`, BLAKE3 hashes).

**OFF** collects again, diffs against baseline, verifies hashes on disk, prints one report. Exit code `1` if something changed or failed verification (good for scripts).

Windows / smoke test: add `--demo` to `on` and `off`.

## Build

```bash
cargo build -p sentinel-cli
cargo test --workspace
# ./target/debug/chronos-sentinel on
```

Agent + Byteflow (optional):

```bash
cargo build -p sentinel-agent --features byteflow
```

## Advanced

Manual paths and exports — when you need more control:

```bash
chronos-sentinel inventory --hash --libs -o snap.json
chronos-sentinel diff --before a.json --after b.json
chronos-sentinel verify --snapshot snap.json
chronos-sentinel hash /usr/bin/sshd
```

`--pacman-db` overrides `/var/lib/pacman/local`.

## Byteflow (optional, Phase 2+)

[Byteflow](https://docs.rs/byteflow-actors) **0.9.23** — flow runtime (capabilities, monitors, `SecurityAuditSink`). Does **not** replace `on` / `off`; use it for a supervised **agent**.

| Fits Chronos | Keep plain Rust |
|--------------|-----------------|
| Supervised capture / diff workers | One-shot `on` / `off` |
| Sandboxed policy bytecode + audit sink | pacman, BLAKE3, JSON |
| `Runtime::monitor` when a worker exits | Static diff reports |

Bridge: `sentinel-agent::byteflow_bridge::SentinelAuditSink`.

Local checkout instead of crates.io: in `sentinel-agent/Cargo.toml`, replace the optional dep with `path = "../../../Bytecode/byteflow"`.

## Crates

`sentinel-cli` (binary), `sentinel-inventory`, `sentinel-integrity`, `sentinel-storage`, `sentinel-analyzer`, `sentinel-core`. Stubs: `ebpf`, `profiler`. `sentinel-agent` (+ optional `byteflow` feature).

## License

MIT OR Apache-2.0 — `LICENSE-MIT`, `LICENSE-APACHE`.
