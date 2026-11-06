use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("plataforma não suportada nesta fase (requer Linux/Arch)")]
    UnsupportedPlatform,
    #[error("falha ao ler banco pacman: {0}")]
    PacmanDb(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
