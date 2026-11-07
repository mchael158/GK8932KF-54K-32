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

pub fn integrity_prefix_match(rel: &str, custom_prefixes: &[String]) -> bool {
    let rel = rel.trim_start_matches('/');
    if custom_prefixes.is_empty() {
        return INTEGRITY_PREFIXES
            .iter()
            .any(|prefix| rel.starts_with(prefix));
    }
    custom_prefixes
        .iter()
        .any(|prefix| rel.starts_with(prefix.trim_start_matches('/')))
}

pub fn package_file_in_scope(rel: &str, scope: PacmanFilesScope, custom_prefixes: &[String]) -> bool {
    let rel = rel.trim();
    if rel.is_empty() || rel.ends_with('/') {
        return false;
    }
    match scope {
        PacmanFilesScope::IntegrityPrefixes => integrity_prefix_match(rel, custom_prefixes),
        PacmanFilesScope::AllPackageFiles => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_prefix_only_tracks_configured_roots() {
        let custom = vec!["etc/sudoers.d/".into()];
        assert!(package_file_in_scope(
            "etc/sudoers.d/10-install",
            PacmanFilesScope::IntegrityPrefixes,
            &custom,
        ));
        assert!(!package_file_in_scope(
            "usr/bin/bash",
            PacmanFilesScope::IntegrityPrefixes,
            &custom,
        ));
    }
}
