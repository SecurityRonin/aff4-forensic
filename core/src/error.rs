//! Error types for the AFF4 reader.

/// Errors that can occur while opening or reading an AFF4 image.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Aff4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip_core::ZipCoreError),
    #[error("not a valid AFF4 image: {0}")]
    BadFormat(String),
    /// The image (or a stream within it) is encrypted; decryption is unsupported,
    /// so the reader refuses rather than emit plausible-but-wrong plaintext.
    #[error("encrypted AFF4 stream is not supported: {0}")]
    Encrypted(String),
}
