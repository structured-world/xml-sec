//! Error types for xml-sec.

/// Errors that can occur during XML security operations.
#[derive(Debug, thiserror::Error)]
pub enum XmlSecError {
    /// XML parsing error.
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// Canonicalization error.
    #[error("C14N error: {0}")]
    Canonicalization(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Unsupported algorithm.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Certificate error.
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Key not found or invalid.
    #[error("Key error: {0}")]
    Key(String),
}
