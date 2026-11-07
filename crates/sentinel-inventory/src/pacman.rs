use crate::{InstalledPackage, InventoryError};
use std::path::Path;
use tokio::process::Command;

/// List packages via `pacman -Q` and enrich file lists from `local/*/desc`.
pub async fn list_local_packages(db_path: &Path) -> Result<Vec<InstalledPackage>, InventoryError> {
    let mut packages = Vec::new();

    if let Ok(output) = Command::new("pacman")
        .args(["-Q", "--quiet"])
        .output()
        .await
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
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
        }
    }

    if packages.is_empty() {
        if !db_path.exists() {
            return Err(InventoryError::PacmanDb(db_path.display().to_string()));
        }
        packages = load_packages_from_db(db_path).await?;
    } else if db_path.exists() {
        enrich_installed_files(&mut packages, db_path).await?;
    }

    Ok(packages)
}

async fn load_packages_from_db(db_path: &Path) -> Result<Vec<InstalledPackage>, InventoryError> {
    let mut packages = Vec::new();
    let mut read_dir = tokio::fs::read_dir(db_path)
        .await
        .map_err(InventoryError::Io)?;
    while let Some(entry) = read_dir.next_entry().await.map_err(InventoryError::Io)? {
        if !entry
            .file_type()
            .await
            .map_err(InventoryError::Io)?
            .is_dir()
        {
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

async fn enrich_installed_files(
    packages: &mut [InstalledPackage],
    db_path: &Path,
) -> Result<(), InventoryError> {
    let index = file_lists_by_package_name(db_path).await?;
    for pkg in packages.iter_mut() {
        if let Some(files) = index.get(&pkg.name) {
            pkg.installed_files = files.clone();
        }
    }
    Ok(())
}

async fn file_lists_by_package_name(
    db_path: &Path,
) -> Result<std::collections::HashMap<String, Vec<String>>, InventoryError> {
    let mut index = std::collections::HashMap::new();
    let mut read_dir = tokio::fs::read_dir(db_path)
        .await
        .map_err(InventoryError::Io)?;
    while let Some(entry) = read_dir.next_entry().await.map_err(InventoryError::Io)? {
        if !entry
            .file_type()
            .await
            .map_err(InventoryError::Io)?
            .is_dir()
        {
            continue;
        }
        let desc = entry.path().join("desc");
        let Ok(desc_text) = tokio::fs::read_to_string(&desc).await else {
            continue;
        };
        if let Some(parsed) = parse_desc(&desc_text) {
            index.insert(parsed.name, parsed.installed_files);
        }
    }
    Ok(index)
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
    fn fixture_desc_on_disk() {
        let desc = include_str!("../../../tests/fixtures/pacman-local/xz-5.6.0-1/desc");
        let pkg = parse_desc(desc).unwrap();
        assert_eq!(pkg.name, "xz");
        assert_eq!(pkg.installed_files.len(), 3);
    }

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
