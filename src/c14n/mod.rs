//! XML Canonicalization (C14N).
//!
//! Implements:
//! - [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/)
//! - [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/)
//! - [Exclusive XML Canonicalization](https://www.w3.org/TR/xml-exc-c14n/)

/// Canonicalization algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C14nAlgorithm {
    /// Canonical XML 1.0 (with comments).
    Inclusive10WithComments,
    /// Canonical XML 1.0 (without comments).
    Inclusive10,
    /// Canonical XML 1.1 (with comments).
    Inclusive11WithComments,
    /// Canonical XML 1.1 (without comments).
    Inclusive11,
    /// Exclusive Canonical XML (with comments).
    Exclusive10WithComments,
    /// Exclusive Canonical XML (without comments).
    Exclusive10,
}
