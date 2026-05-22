//! Error types for the AFF4 reader.

/// Errors that can occur while opening or reading an AFF4 image.
#[derive(Debug, thiserror::Error)]
pub enum Aff4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("not a valid AFF4 image: {0}")]
    BadFormat(String),
}
