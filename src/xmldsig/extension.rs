//! Borrowed, accounted XML reads for signature-extension consumers.
//!
//! Reading a scalar does not authenticate its owning node, validate a signature
//! or authorize a profile. Consumers retain those independent obligations.

use crate::document::{DocumentView, NodeIdentity, XmlDocumentError};
use structured_asn1::memory::{MemoryError, Work};

mod scalar;
pub use scalar::*;
mod tree;
pub use tree::*;

/// Schema boolean attribute without an invented default for an absent value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanAttribute {
    /// No attribute with the selected expanded name exists.
    Absent,
    /// An explicitly supplied XML Schema boolean value.
    Value(bool),
    /// The attribute exists but is outside the schema lexical space.
    Malformed,
}

/// Processing failure, independent of an absent or malformed scalar value.
#[derive(Debug, thiserror::Error)]
pub enum ScalarError {
    /// The identity is absent, foreign or stale in this original document view.
    #[error(transparent)]
    Document(#[from] XmlDocumentError),
    /// Attributes can only be selected from an element.
    #[error("XML scalar owner is not an element")]
    NotElement,
    /// Current shared execution refused the work before it was performed.
    #[error("XML scalar resource failure: {0}")]
    Resource(MemoryError),
}

pub(super) fn charge_bytes<W: Work>(work: &W, bytes: usize) -> Result<(), ScalarError> {
    let bytes =
        u64::try_from(bytes).map_err(|_| ScalarError::Resource(MemoryError::WorkExceeded))?;
    work.charge_work(bytes).map_err(ScalarError::Resource)
}

/// Read an original attribute by expanded name with no allocation or reparsing.
///
/// `view` preserves document/generation identity. `work` is the caller's current
/// execution, not a new account; lookup and lexical scans are admitted before
/// execution. This mechanism does not prove the owner is authenticated and does
/// not supply profile-specific defaults or permission.
///
/// # Errors
///
/// Returns [`ScalarError::NotElement`] for a non-element owner,
/// [`ScalarError::Document`] for a foreign or stale identity and
/// [`ScalarError::Resource`] when current work is exhausted.
pub fn boolean_attribute<W: Work>(
    view: DocumentView<'_>,
    owner: NodeIdentity,
    namespace: Option<&str>,
    local_name: &str,
    work: &W,
) -> Result<BooleanAttribute, ScalarError> {
    work.charge_work(1).map_err(ScalarError::Resource)?;
    let node = view.resolve_node(owner)?;
    if !node.is_element() {
        return Err(ScalarError::NotElement);
    }
    for attribute in node.attributes() {
        work.charge_work(1).map_err(ScalarError::Resource)?;
        charge_bytes(work, attribute.name().len())?;
        if attribute.name() != local_name {
            continue;
        }
        if let Some(uri) = attribute.namespace() {
            charge_bytes(work, uri.len())?;
        }
        if attribute.namespace() != namespace {
            continue;
        }
        let value = attribute.value();
        charge_bytes(work, value.len())?;
        work.charge_work(5).map_err(ScalarError::Resource)?;
        // XSD 1.0 Second Edition §§3.2.2.1, 4.3.6: boolean admits only
        // true/false/1/0, with fixed whiteSpace=collapse. None contains interior
        // whitespace, so trimming XML whitespace suffices without a new String.
        // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#boolean
        // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#rf-whiteSpace
        return Ok(match value.trim_matches([' ', '\t', '\r', '\n']) {
            "true" | "1" => BooleanAttribute::Value(true),
            "false" | "0" => BooleanAttribute::Value(false),
            _ => BooleanAttribute::Malformed,
        });
    }
    Ok(BooleanAttribute::Absent)
}
