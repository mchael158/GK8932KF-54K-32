//! TOML configuration for inventory collection (not policy / mitigation).

use crate::scope::PacmanFilesScope;
use crate::CollectOptions;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

/// On-disk layout (`config.toml`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ChronosConfigFile {
    #[serde(default)]
    pub inventory: InventoryToml,
    #[serde(default)]
    pub export: ExportToml,
}

/// `[export]` — SIEM JSONL, webhooks, ZSTD sidecars (policy / egress).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExportToml {
    #[serde(default)]
    pub siem_file: Option<PathBuf>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_on: Option<WebhookWhenToml>,
    #[serde(default)]
    pub compress_snapshots: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookWhenToml {
    #[default]
    Dirty,
    Always,
    Never,
}

/// `[inventory]` — pacman paths, scans, `%FILES%` scope.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InventoryToml {
    #[serde(default)]
    pub pacman_db: Option<PathBuf>,
    #[serde(default)]
    pub scan_roots: Vec<PathBuf>,
    #[serde(default)]
    pub lib_roots: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub hash_executables: Option<bool>,
    #[serde(default = "default_true")]
    pub scan_libraries: Option<bool>,
    #[serde(default)]
    pub files_scope: Option<PacmanFilesScope>,
    /// When non-empty, replaces built-in [`crate::scope::INTEGRITY_PREFIXES`].
    #[serde(default)]
    pub integrity_prefixes: Vec<String>,
}

fn default_true() -> Option<bool> {
    Some(true)
}

impl InventoryToml {
    pub fn apply_to(&self, opts: &mut CollectOptions) {
        if let Some(db) = &self.pacman_db {
            opts.pacman_db = db.clone();
        }
        if !self.scan_roots.is_empty() {
            opts.scan_roots = self.scan_roots.clone();
        }
        if !self.lib_roots.is_empty() {
            opts.lib_roots = self.lib_roots.clone();
        }
        if let Some(v) = self.hash_executables {
            opts.hash_executables = v;
        }
        if let Some(v) = self.scan_libraries {
            opts.scan_libraries = v;
        }
        if let Some(scope) = self.files_scope {
            opts.files_scope = scope;
        }
        if !self.integrity_prefixes.is_empty() {
            opts.integrity_prefixes = self.integrity_prefixes.clone();
        }
    }
}

/// Search order after an explicit `--config` path.
pub fn discover_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CHRONOS_CONFIG") {
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
            .join("config.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    #[cfg(unix)]
    {
        let system = PathBuf::from("/etc/chronos-sentinel/config.toml");
        if system.is_file() {
            return Some(system);
        }
        if let Ok(home) = std::env::var("HOME") {
            let user = PathBuf::from(home)
                .join(".config")
                .join("chronos-sentinel")
                .join("config.toml");
            if user.is_file() {
                return Some(user);
            }
        }
    }
    None
}

pub fn load_config_file(path: &Path) -> Result<ChronosConfigFile, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

pub fn load_chronos_config(explicit_config: Option<&Path>) -> Result<(CollectOptions, ExportToml), ConfigError> {
    let mut opts = CollectOptions::default();
    let mut export = ExportToml::default();
    let path = explicit_config
        .map(|p| p.to_path_buf())
        .or_else(discover_config_path);
    if let Some(path) = path {
        let file = load_config_file(&path)?;
        file.inventory.apply_to(&mut opts);
        export = file.export;
    }
    Ok((opts, export))
}

pub fn load_merged_collect_options(explicit_config: Option<&Path>) -> Result<CollectOptions, ConfigError> {
    Ok(load_chronos_config(explicit_config)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_section() {
        let raw = r#"
[export]
siem_file = "/var/log/siem.jsonl"
webhook_url = "https://example/hook"
webhook_on = "always"
compress_snapshots = true
"#;
        let file: ChronosConfigFile = toml::from_str(raw).unwrap();
        assert_eq!(
            file.export.siem_file.as_deref().map(|p| p.to_str().unwrap()),
            Some("/var/log/siem.jsonl")
        );
        assert!(file.export.compress_snapshots.unwrap());
    }

    #[test]
    fn parses_inventory_section() {
        let raw = r#"
[inventory]
pacman_db = "/var/lib/pacman/local"
integrity_prefixes = ["usr/bin/", "etc/ssh/"]
scan_roots = ["/usr/bin"]
files_scope = "all_package_files"
"#;
        let file: ChronosConfigFile = toml::from_str(raw).unwrap();
        let mut opts = CollectOptions::default();
        file.inventory.apply_to(&mut opts);
        assert_eq!(opts.pacman_db, PathBuf::from("/var/lib/pacman/local"));
        assert_eq!(opts.integrity_prefixes.len(), 2);
        assert_eq!(opts.files_scope, PacmanFilesScope::AllPackageFiles);
        assert_eq!(opts.scan_roots, vec![PathBuf::from("/usr/bin")]);
    }
}
