use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("no pacman database and no executables found under configured scan roots")]
    NothingToCollect,
    #[error("failed to read pacman database: {0}")]
    PacmanDb(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
