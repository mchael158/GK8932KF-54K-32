# Assinatura Ed25519 do baseline

O inventário continua em `baseline.json`. A **assinatura** é um sidecar `baseline.json.sig` (JSON com BLAKE3 do arquivo + Ed25519).

## Gerar chaves

```bash
chronos-sentinel keygen
# ou: chronos-sentinel keygen --output-dir /etc/chronos-sentinel
```

Cria `signing.key` (secreta, modo 0600 no Linux) e `signing.pub.json`.

Ordem de busca da chave no `on`: `--signing-key` → `CHRONOS_SIGNING_KEY` → `~/.config/chronos-sentinel/signing.key` → `/etc/chronos-sentinel/signing.key`.

## Assinar no `on`

Por padrão `--sign` está ligado: se houver chave, gera `baseline.json.sig` após gravar o JSON.

- `--no-sign` — não assina.
- `--require-sign` — falha o `on` se não houver chave.

## Verificar no `off`

Por padrão, se existir `.sig`, o digest e a Ed25519 são validados antes do diff.

- `--no-verify-signature` — ignora verificação (não recomendado).
- `--require-signed-baseline` — falha se não houver `.sig`.

Pin opcional da chave pública: `CHRONOS_TRUSTED_PUBKEY_HEX=<hex>`.

## Comando dedicado

```bash
chronos-sentinel sign-verify
chronos-sentinel sign-verify --snapshot /caminho/baseline.json
```

## Formato do sidecar

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "public_key_hex": "...",
  "payload_digest": { "algorithm": "blake3", "hex": "..." },
  "signature_hex": "...",
  "signed_at": "..."
}
```

A assinatura cobre o **digest BLAKE3** do conteúdo exato de `baseline.json` no disco.
