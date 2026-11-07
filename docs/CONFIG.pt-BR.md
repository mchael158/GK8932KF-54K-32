# Configuração — inventário

O arquivo TOML configura **só coleta** (pacman, prefixos, pastas de varredura). Mitigação e diretório de estado continuam na CLI / variáveis de ambiente.

## Onde colocar o arquivo

1. `--config /caminho/config.toml`
2. `CHRONOS_CONFIG`
3. `$XDG_CONFIG_HOME/chronos-sentinel/config.toml`
4. `~/.config/chronos-sentinel/config.toml`
5. `/etc/chronos-sentinel/config.toml`

Modelo: `packaging/chronos-sentinel.example.toml`

## Seção `[inventory]`

| Chave | Função |
|-------|--------|
| `pacman_db` | Base local do pacman |
| `integrity_prefixes` | Prefixos em `%FILES%` (lista vazia = padrão embutido) |
| `scan_roots` / `lib_roots` | Varredura suplementar de binários e bibliotecas |
| `files_scope` | `integrity_prefixes` ou `all_package_files` |
| `hash_executables` / `scan_libraries` | Liga/desliga hash e scan de libs |

## Precedência

Padrões do binário → TOML → flags globais (`--pacman-db`, `--full-files`).

```bash
sudo install -Dm644 packaging/chronos-sentinel.example.toml /etc/chronos-sentinel/config.toml
chronos-sentinel on
chronos-sentinel off
```

No Windows: rode **um** comando por vez (`on`, depois `off`). Teste rápido: `on -d` / `off -d`. Um `run.lock` no state dir impede segunda instância. O TOML pode limitar `scan_roots` para varreduras menores.
