use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("unsupported platform for this phase (requires Linux/Arch)")]
    UnsupportedPlatform,
    #[error("failed to read pacman database: {0}")]
    PacmanDb(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
