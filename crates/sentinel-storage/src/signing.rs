//! Ed25519 signatures over BLAKE3(snapshot file bytes). Sidecar: `*.json.sig`.

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEY_FILE_VERSION: u32 = 1;
const SIG_FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSignature {
    pub version: u32,
    pub algorithm: String,
    pub public_key_hex: String,
    pub payload_digest: DigestRef,
    pub signature_hex: String,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestRef {
    pub algorithm: String,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyFile {
    pub version: u32,
    pub algorithm: String,
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

pub fn signature_path(snapshot_json: &Path) -> PathBuf {
    let name = snapshot_json
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("snapshot.json");
    snapshot_json
        .parent()
        .map(|p| p.join(format!("{name}.sig")))
        .unwrap_or_else(|| PathBuf::from(format!("{name}.sig")))
}

pub fn discover_signing_key(override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        return None;
    }
    if let Ok(path) = std::env::var("CHRONOS_SIGNING_KEY") {
        let p = path.trim();
        if !p.is_empty() {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let candidate = PathBuf::from(xdg)
            .join("chronos-sentinel")
            .join("signing.key");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    #[cfg(unix)]
    {
        let system = PathBuf::from("/etc/chronos-sentinel/signing.key");
        if system.is_file() {
            return Some(system);
        }
        if let Ok(home) = std::env::var("HOME") {
            let user = PathBuf::from(home)
                .join(".config")
                .join("chronos-sentinel")
                .join("signing.key");
            if user.is_file() {
                return Some(user);
            }
        }
    }
    None
}

pub fn generate_keypair() -> SigningKeyFile {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    SigningKeyFile {
        version: KEY_FILE_VERSION,
        algorithm: "ed25519".into(),
        secret_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verify_key.to_bytes()),
    }
}

pub fn write_keypair(dir: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let key = generate_keypair();
    let secret_path = dir.join("signing.key");
    let public_path = dir.join("signing.pub.json");
    let secret_json = serde_json::to_string_pretty(&key)?;
    std::fs::write(&secret_path, secret_json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let public_only = serde_json::json!({
        "version": KEY_FILE_VERSION,
        "algorithm": "ed25519",
        "public_key_hex": key.public_key_hex,
    });
    std::fs::write(&public_path, serde_json::to_string_pretty(&public_only)?)?;
    Ok((secret_path, public_path))
}

fn load_signing_key(path: &Path) -> Result<ed25519_dalek::SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let file: SigningKeyFile = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if file.algorithm != "ed25519" {
        return Err(format!("unsupported signing key algorithm: {}", file.algorithm));
    }
    let bytes = hex::decode(file.secret_key_hex.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "secret_key_hex must be 32 bytes".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

fn snapshot_digest(bytes: &[u8]) -> blake3::Hash {
    blake3::hash(bytes)
}

/// Sign snapshot file on disk; writes sidecar next to JSON.
pub fn sign_snapshot_file(
    snapshot_json: &Path,
    key_path: &Path,
) -> Result<SnapshotSignature, String> {
    let signing_key = load_signing_key(key_path)?;
    let bytes = std::fs::read(snapshot_json).map_err(|e| e.to_string())?;
    let digest = snapshot_digest(&bytes);
    let digest_hex = digest.to_hex().to_string();
    let signature = signing_key.sign(digest.as_bytes());
    let verify_key = signing_key.verifying_key();
    let record = SnapshotSignature {
        version: SIG_FILE_VERSION,
        algorithm: "ed25519".into(),
        public_key_hex: hex::encode(verify_key.to_bytes()),
        payload_digest: DigestRef {
            algorithm: "blake3".into(),
            hex: digest_hex,
        },
        signature_hex: hex::encode(signature.to_bytes()),
        signed_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    };
    let sidecar = signature_path(snapshot_json);
    let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(&sidecar, json).map_err(|e| e.to_string())?;
    Ok(record)
}

/// If sidecar exists, verify digest + signature. If missing, Ok (unsigned baseline).
pub fn verify_snapshot_file(snapshot_json: &Path) -> Result<Option<SnapshotSignature>, String> {
    let sidecar = signature_path(snapshot_json);
    if !sidecar.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&sidecar).map_err(|e| e.to_string())?;
    let record: SnapshotSignature = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    verify_record(snapshot_json, &record)?;
    Ok(Some(record))
}

pub fn verify_record(snapshot_json: &Path, record: &SnapshotSignature) -> Result<(), String> {
    if record.version != SIG_FILE_VERSION {
        return Err(format!("unsupported signature version {}", record.version));
    }
    if record.algorithm != "ed25519" || record.payload_digest.algorithm != "blake3" {
        return Err("unsupported signature or digest algorithm".into());
    }
    if let Ok(trusted) = std::env::var("CHRONOS_TRUSTED_PUBKEY_HEX") {
        let t = trusted.trim();
        if !t.is_empty() && !record.public_key_hex.eq_ignore_ascii_case(t) {
            return Err("baseline signature public key not in CHRONOS_TRUSTED_PUBKEY_HEX".into());
        }
    }
    let bytes = std::fs::read(snapshot_json).map_err(|e| e.to_string())?;
    let digest = snapshot_digest(&bytes);
    if digest.to_hex().to_string() != record.payload_digest.hex {
        return Err("baseline file digest does not match signature sidecar".into());
    }
    let pubkey_bytes = hex::decode(record.public_key_hex.trim()).map_err(|e| e.to_string())?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "public_key_hex must be 32 bytes".to_string())?;
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(record.signature_hex.trim()).map_err(|e| e.to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature_hex must be 64 bytes".to_string())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(digest.as_bytes(), &signature)
        .map_err(|_| "Ed25519 signature verification failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_inventory::{CollectionMeta, InstalledPackage, InventorySnapshot};
    use time::OffsetDateTime;

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (key_path, _) = write_keypair(dir.path()).unwrap();
        let snap_path = dir.path().join("baseline.json");
        let snap = InventorySnapshot {
            collected_at: OffsetDateTime::now_utc(),
            packages: vec![InstalledPackage {
                name: "xz".into(),
                version: "1".into(),
                installed_files: vec![],
            }],
            tracked_executables: vec![],
            orphan_executables: vec![],
            collection: CollectionMeta {
                pacman_packages: 1,
                artifacts_tracked: 1,
                ..CollectionMeta::default()
            },
        };
        crate::write_snapshot(&snap_path, &snap).unwrap();
        sign_snapshot_file(&snap_path, &key_path).unwrap();
        verify_snapshot_file(&snap_path).unwrap().expect("sig file");
        assert!(signature_path(&snap_path).is_file());
    }

    #[test]
    fn tampered_snapshot_fails_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (key_path, _) = write_keypair(dir.path()).unwrap();
        let snap_path = dir.path().join("baseline.json");
        std::fs::write(&snap_path, r#"{"packages":[]}"#).unwrap();
        sign_snapshot_file(&snap_path, &key_path).unwrap();
        std::fs::write(&snap_path, r#"{"packages":["tampered"]}"#).unwrap();
        assert!(verify_snapshot_file(&snap_path).is_err());
    }
}
