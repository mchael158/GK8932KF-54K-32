use sentinel_core::{ContentHash, HashAlgorithm};
use std::io::Read;
use std::path::Path;

pub fn hash_file_blake3(path: &Path) -> std::io::Result<ContentHash> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ContentHash {
        algorithm: HashAlgorithm::Blake3,
        hex: hasher.finalize().to_hex().to_string(),
    })
}
