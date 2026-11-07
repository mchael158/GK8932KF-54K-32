//! Which `%FILES%` rows enter the integrity baseline (size vs coverage).

use serde::{Deserialize, Serialize};

/// Default: only high-risk prefixes (fast baseline). Optional: every file path in `%FILES%`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacmanFilesScope {
    #[default]
    IntegrityPrefixes,
    AllPackageFiles,
}

impl PacmanFilesScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntegrityPrefixes => "integrity_prefixes",
            Self::AllPackageFiles => "all_package_files",
        }
    }
}

/// Pacman `%FILES%` lines under these roots are tracked when scope is [`PacmanFilesScope::IntegrityPrefixes`].
pub const INTEGRITY_PREFIXES: &[&str] = &[
    "usr/bin/",
    "usr/sbin/",
    "usr/local/bin/",
    "usr/lib/",
    "lib/",
    "etc/ssh/",
];

pub fn integrity_prefix_match(rel: &str) -> bool {
    let rel = rel.trim_start_matches('/');
    INTEGRITY_PREFIXES
        .iter()
        .any(|prefix| rel.starts_with(prefix))
}

pub fn package_file_in_scope(rel: &str, scope: PacmanFilesScope) -> bool {
    let rel = rel.trim();
    if rel.is_empty() || rel.ends_with('/') {
        return false;
    }
    match scope {
        PacmanFilesScope::IntegrityPrefixes => integrity_prefix_match(rel),
        PacmanFilesScope::AllPackageFiles => true,
    }
}
