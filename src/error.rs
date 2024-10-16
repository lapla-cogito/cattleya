#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid option: {0}")]
    InvalidOption(&'static str),

    #[error("failed to open file: {0}")]
    OpenFile(std::io::Error),

    #[error("failed to create file: {0}")]
    CreateFile(std::io::Error),

    #[error("invalid ELF magic")]
    InvalidMagic,

    #[error("failed to mmap: {0}")]
    Mmap(std::io::Error),

    #[error("failed in I/O operation: {0}")]
    Io(std::io::Error),

    #[error("failed to process obfuscation: {0}")]
    Obfuscation(&'static str),

    #[error("failed to remove file: {0}")]
    RemoveFile(std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
