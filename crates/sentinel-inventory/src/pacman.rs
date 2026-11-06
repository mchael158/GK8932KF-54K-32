use crate::{InstalledPackage, InventoryError};
use std::path::Path;
use tokio::process::Command;

/// Lista pacotes via `pacman -Q` quando disponível; fallback: diretórios em `local/`.
pub async fn list_local_packages(db_path: &Path) -> Result<Vec<InstalledPackage>, InventoryError> {
    if let Ok(output) = Command::new("pacman")
        .args(["-Q", "--quiet"])
        .output()
        .await
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut packages = Vec::new();
            for line in text.lines() {
                let Some((name, version)) = line.split_once(' ') else {
                    continue;
                };
                packages.push(InstalledPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    installed_files: Vec::new(),
                });
            }
            return Ok(packages);
        }
    }

    if !db_path.exists() {
        return Err(InventoryError::PacmanDb(db_path.display().to_string()));
    }

    let mut packages = Vec::new();
    let mut read_dir = tokio::fs::read_dir(db_path).await.map_err(InventoryError::Io)?;
    while let Some(entry) = read_dir.next_entry().await.map_err(InventoryError::Io)? {
        if !entry.file_type().await.map_err(InventoryError::Io)?.is_dir() {
            continue;
        }
        let desc = entry.path().join("desc");
        if let Ok(desc_text) = tokio::fs::read_to_string(&desc).await {
            if let Some(pkg) = parse_desc(&desc_text) {
                packages.push(pkg);
            }
        }
    }
    Ok(packages)
}

fn parse_desc(desc: &str) -> Option<InstalledPackage> {
    let mut name = None;
    let mut version = None;
    let mut files = Vec::new();
    let mut in_files = false;
    let mut pending_field: Option<&str> = None;

    for line in desc.lines() {
        if line == "%FILES%" {
            in_files = true;
            pending_field = None;
            continue;
        }
        if line.starts_with('%') {
            in_files = false;
            pending_field = match line {
                "%NAME%" => Some("name"),
                "%VERSION%" => Some("version"),
                _ => None,
            };
            continue;
        }
        if in_files {
            if !line.is_empty() {
                files.push(line.to_string());
            }
            continue;
        }
        match pending_field.take() {
            Some("name") => name = Some(line.trim().to_string()),
            Some("version") => version = Some(line.trim().to_string()),
            _ => {}
        }
    }

    Some(InstalledPackage {
        name: name?,
        version: version?,
        installed_files: files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_desc_reads_name_version_and_files() {
        let desc = "\
%NAME%
xz
%VERSION%
5.6.0-1
%FILES%
usr/lib/liblzma.so.5
usr/bin/xz
";
        let pkg = parse_desc(desc).unwrap();
        assert_eq!(pkg.name, "xz");
        assert_eq!(pkg.version, "5.6.0-1");
        assert_eq!(pkg.installed_files.len(), 2);
    }
}
