# GK8932KF-54K-32 — Chronos Sentinel

Monitoramento comportamental e de integridade para Linux (prioridade Arch Linux), inspirado em lições do caso XZ Utils (CVE-2024-3094): inventário de pacotes, baseline de execução, hashes e correlação de anomalias.

## Status

| Fase | Escopo | Estado |
|------|--------|--------|
| 1 | Inventário pacman, executáveis, diff, SQLite | Implementado |
| 2 | Agente eBPF / execve | Esqueleto |
| 3–6 | Baseline, integridade contínua, correlação, UI | Planejado |

## Requisitos

- Rust 1.76+ (o repositório fixa **MSVC** no Windows via `rust-toolchain.toml`)
- **Linux / Arch** para inventário real (`pacman`, `/usr/bin`, …)
- No Windows: use `--demo` ou WSL2/VM Arch para testes completos

## Build

```bash
cargo build --workspace
cargo test --workspace
```

Binário CLI:

```bash
cargo run -p sentinel-cli -- --help
```

## Uso rápido

```bash
# Inventário real (Arch)
cargo run -p sentinel-cli -- inventory --hash

# Modo demonstração (qualquer OS)
cargo run -p sentinel-cli -- inventory --demo

# Comparar últimos dois snapshots no banco local
cargo run -p sentinel-cli -- diff --json
```

Banco padrão: `chronos-sentinel.db` (ignorado pelo git).

## Crates

| Crate | Função |
|-------|--------|
| `sentinel-core` | Tipos e eventos |
| `sentinel-inventory` | Pacotes, scan, diff |
| `sentinel-integrity` | BLAKE3 de arquivos |
| `sentinel-storage` | Persistência SQLite |
| `sentinel-profiler` | Baseline de latência |
| `sentinel-analyzer` | Resumo de anomalias |
| `sentinel-agent` / `sentinel-ebpf` | Monitoramento (futuro) |
| `sentinel-cli` | `chronos-sentinel` |

## Licença

Dual-licensed under **MIT OR Apache-2.0** — see `LICENSE-MIT` and `LICENSE-APACHE`.
