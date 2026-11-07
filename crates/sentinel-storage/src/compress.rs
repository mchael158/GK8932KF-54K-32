//! Optional ZSTD copies of snapshot JSON (sidecar `*.json.zst`).

use std::io::Write;
use std::path::{Path, PathBuf};

pub fn compressed_sidecar_path(json_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.zst", json_path.display()))
}

/// Write `path.json.zst` from the current contents of `json_path`.
pub fn compress_snapshot_file(json_path: &Path) -> std::io::Result<PathBuf> {
    let bytes = std::fs::read(json_path)?;
    let out_path = compressed_sidecar_path(json_path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut encoder = zstd::stream::write::Encoder::new(
        std::fs::File::create(&out_path)?,
        3,
    )?;
    encoder.write_all(&bytes)?;
    encoder.finish()?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_smaller_for_repetitive_json() {
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("snap.json");
        let body = "{\"packages\":[".to_string() + &"\"x\",".repeat(200) + "\"z\"]}";
        std::fs::write(&json, &body).unwrap();
        let zst = compress_snapshot_file(&json).unwrap();
        assert!(zst.is_file());
        assert!(std::fs::metadata(&zst).unwrap().len() < body.len() as u64);
    }
}
