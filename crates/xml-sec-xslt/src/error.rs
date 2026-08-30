use crate::{BudgetKind, ResourceIdentity};

/// Result type returned by the XSLT engine.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable processing-error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Xml,
    Static,
    Dynamic,
    Resource,
    Resolver,
    Budget,
    Serialization,
    Unsupported,
}

/// Typed XSLT compilation or execution failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("XML input is not well formed: {0}")]
    Xml(String),
    #[error("stylesheet static error: {0}")]
    Static(String),
    #[error("XSLT dynamic error: {0}")]
    Dynamic(String),
    #[error("resource {identity:?} changed while compiling the stylesheet")]
    StaleResource { identity: ResourceIdentity },
    #[error("resource not found: {uri}")]
    ResourceNotFound { uri: String },
    #[error("resource resolution failed for {uri}: {message}")]
    Resolver { uri: String, message: String },
    #[error("{kind:?} budget exceeded: limit {limit}, attempted {actual}")]
    Budget {
        kind: BudgetKind,
        limit: usize,
        actual: usize,
    },
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("unsupported XSLT feature: {0}")]
    Unsupported(String),
}

impl Error {
    /// Returns a stable error category without parsing the display message.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Xml(_) => ErrorKind::Xml,
            Self::Static(_) => ErrorKind::Static,
            Self::Dynamic(_) => ErrorKind::Dynamic,
            Self::StaleResource { .. } | Self::ResourceNotFound { .. } => ErrorKind::Resource,
            Self::Resolver { .. } => ErrorKind::Resolver,
            Self::Budget { .. } => ErrorKind::Budget,
            Self::Serialization(_) => ErrorKind::Serialization,
            Self::Unsupported(_) => ErrorKind::Unsupported,
        }
    }
}
