# Fase 5 — exportação (SIEM, webhook, compressão)

Produção inicial: **Arch + pacman** (sem backend para outras distros).

## SIEM (JSONL)

Cada `off` (e cada ciclo do `agent`) pode acrescentar uma linha em um arquivo:

```toml
[export]
siem_file = "/var/log/chronos/siem.jsonl"
```

Ou: `--siem-file` / `CHRONOS_SIEM_FILE`.

Evento `integrity_scan`: `exit_code`, `dirty`, resumo do diff, `verify_problems`.

## Webhook

POST JSON no mesmo schema para `webhook_url` quando `webhook_on = "dirty"` (padrão) ou `always`.

```toml
[export]
webhook_url = "https://seu-servidor/hooks/chronos"
webhook_on = "dirty"
```

CLI: `--webhook-url` / `CHRONOS_WEBHOOK_URL` · `--webhook-on {dirty,always,never}`.

Falhas de webhook/SIEM são logadas em stderr; **não alteram** o código de saída do scan.

## Compressão

Com `compress_snapshots = true` ou `--compress`, após gravar `baseline.json` / `last-check.json` o CLI gera sidecars `*.json.zst` (JSON legível inalterado; assinatura Ed25519 continua no `.json`).

## Assinatura

Ver [`SIGNING.pt-BR.md`](SIGNING.pt-BR.md) (Ed25519 já implementado).
