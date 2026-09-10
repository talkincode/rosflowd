use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid netflow packet: {0}")]
    Decode(&'static str),
    #[error("unsupported netflow version {0}")]
    UnsupportedVersion(u16),
    #[error("store error: {0}")]
    Store(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
