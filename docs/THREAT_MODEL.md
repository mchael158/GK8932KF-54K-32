# Threat model — Chronos Sentinel

Chronos Sentinel is an **integrity baseline** tool for **Arch Linux** systems managed with **pacman**. It is not a full endpoint detection and response (EDR) product.

## Assets

- Executables and libraries under configured `%FILES%` prefixes (default: `usr/bin/`, `usr/lib/`, `etc/ssh/`, …).
- The JSON baseline (`baseline.json`) and last scan (`last-check.json`) under the state directory.

## Trust assumptions

- The host kernel and file system faithfully report file contents to unprivileged reads (root improves coverage for pacman DB and scans).
- Pacman’s local database (`/var/lib/pacman/local`) reflects what pacman believes is installed.
- Operators protect the state directory from unauthorized modification.

## What the tool detects

- Package add/remove/upgrade and `%FILES%` list changes between snapshots.
- BLAKE3 content changes on tracked artifacts (in-scope `%FILES%` and supplemental bin/lib walks).
- New **orphan** executables under scanned directories without a pacman owner.
- On-disk verify failures when a snapshot records a hash and the file content differs.

## What the tool does **not** detect

- Malware that only touches paths outside the scope (e.g. `usr/share/doc`, home directories) unless `--full-files` or future config expands scope.
- Runtime-only attacks (`LD_PRELOAD`, in-memory-only payloads, kernel rootkits).
- Changes hidden by bind mounts or namespaces unless the same view is used at baseline and check time.
- Adversarial modification of the baseline JSON **without** breaking Ed25519: use `baseline.json.sig` (see [`SIGNING.pt-BR.md`](SIGNING.pt-BR.md)). Protect `signing.key` like any TLS private key.

## Mitigation (`--mitigate`)

Process mitigation matches running PIDs via `/proc/<pid>/exe` against suspicious paths from a **dirty diff**. By default it is **audit-only**:

- Without `--mitigate-confirm`, no `kill` is performed (dry-run or “awaiting confirm” messages).
- `--mitigate-dry-run` never signals, even if confirm is set.
- `--mitigate-allow-pid` and `--mitigate-allow-comm` skip listed PIDs or `comm` names.

Risks:

- False positives (legitimate local rebuilds, orphan tooling).
- `/proc/pid/exe` can show `(deleted)` or misleading paths.
- SIGTERM can disrupt legitimate services — use allowlists and confirm only after reviewing diff output.

**Policy is separate from inventory:** collection and hashing never send signals; only explicit mitigation flags after a diff.

## Recommended operational posture

1. Run `chronos-sentinel on` after a known-good system state (post-install or post-`pacman -Syu` you trust).
2. Schedule `off` or `agent` on a timer; treat exit code `1` as investigation, not auto-kill.
3. Keep state under `CHRONOS_STATE_DIR` or XDG with restricted permissions (e.g. `/var/lib/chronos-sentinel`).
4. Enable `--mitigate-confirm` only with documented allowlists and monitoring.

## Byteflow

Byteflow (`byteflow-actors`) sandboxes the **control plane** (op dispatch, audit hooks). It does not replace kernel security modules. Inventory and hashing run in Rust host code invoked from audited natives.
