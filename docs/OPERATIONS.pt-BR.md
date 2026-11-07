# Guia de operação

## Completions (Bash, Fish, Zsh)

```bash
chronos-sentinel completions bash  > /etc/bash_completion.d/chronos-sentinel
chronos-sentinel completions zsh   > /usr/share/zsh/site-functions/_chronos-sentinel
chronos-sentinel completions fish  > ~/.config/fish/completions/chronos-sentinel.fish
```

## Página de manual

Arquivo no repositório: `packaging/man/chronos-sentinel.1`. Para regenerar:

```bash
chronos-sentinel gen-man --output packaging/man/chronos-sentinel.1
```

## Logs estruturados

Use `--log-json` ou `CHRONOS_LOG_JSON=1`. Cada linha em **stderr** é um JSON.

| Evento | Momento |
|--------|---------|
| `config_loaded` | Config TOML resolvida |
| `command_start` | Início do subcomando |
| `command_done` | Saída com `exit_code` |
| `agent_scan` | Cada ciclo do `agent` |

Os relatórios legíveis continuam no stderr; `off --json` envia o diff para stdout.

Ver também: [`CONFIG.pt-BR.md`](CONFIG.pt-BR.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md).
