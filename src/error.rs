//! Typed operation errors. Invalid signature evidence is not a processing error.

/// Processing failures retain their original typed cause, without string conversion.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XmlSecError {
    /// Retained XML document processing failed.
    #[error(transparent)]
    Document(#[from] crate::XmlDocumentError),
    /// Canonical XML processing failed.
    #[error(transparent)]
    Canonicalization(#[from] crate::c14n::C14nError),
    /// An immutable policy rejected configuration or processing.
    #[cfg(feature = "xmldsig")]
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyViolation),
    /// The compiled policy disabled this operation.
    #[cfg(feature = "xmldsig")]
    #[error("{0:?} is disabled by the compiled policy")]
    OperationDisabled(crate::api::Operation),
    /// Verification could not complete. Mathematical invalidity stays in evidence.
    #[cfg(feature = "xmldsig")]
    #[error(transparent)]
    Verification(#[from] crate::xmldsig::DsigError),
    /// Signature generation failed.
    #[cfg(feature = "xmldsig")]
    #[error(transparent)]
    Signing(#[from] crate::xmldsig::SigningError),
    /// Caller-owned key inventory selection or import failed.
    #[cfg(feature = "xmldsig")]
    #[error(transparent)]
    KeyStore(#[from] crate::key_manager::KeyStoreError),
    /// XML encryption or decryption failed.
    #[cfg(feature = "xmlenc")]
    #[error(transparent)]
    Encryption(#[from] crate::xmlenc::XmlEncError),
}
