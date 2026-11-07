# Operations guide

## Shell completions

```bash
chronos-sentinel completions bash  > /etc/bash_completion.d/chronos-sentinel
chronos-sentinel completions zsh   > /usr/share/zsh/site-functions/_chronos-sentinel
chronos-sentinel completions fish  > ~/.config/fish/completions/chronos-sentinel.fish
```

## Man page

Prebuilt: `packaging/man/chronos-sentinel.1`. Regenerate after CLI changes:

```bash
chronos-sentinel gen-man --output packaging/man/chronos-sentinel.1
man ./packaging/man/chronos-sentinel.1   # local preview on Linux
```

## Structured logs (JSON lines)

Enable with `--log-json` or `CHRONOS_LOG_JSON=1`. Events go to **stderr** (one JSON object per line).

| Event | When |
|-------|------|
| `config_loaded` | After resolving TOML |
| `command_start` | Subcommand begins |
| `command_done` | Exit with `exit_code` |
| `agent_scan` | Each agent loop iteration |

Example:

```json
{"ts":"2026-03-20T12:00:00Z","event":"command_done","chronos":{"command":"off","exit_code":1}}
```

Human-readable reports stay on stderr unless `--json` (diff) is set for `off`.

See also: [`CONFIG.pt-BR.md`](CONFIG.pt-BR.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md).
