//! XAdES baseline validation of signatures verified by xml-sec.
//!
//! [`Document`] implements the `structured-xades` XML access traits over a
//! [`VerifiedSession`]: the document generation, authenticated reference
//! catalogue, scalar kernels, hash-use and selected-key receipts that the
//! XMLDSig verification produced. No second XML representation is built and
//! no signature is verified again. [`validate_basic`] runs the B-B checks of
//! ETSI EN 319 132-1 for one selected signature.
//!
//! Certificate paths are the paths xml-sec already validated: the adapter
//! selects the exact certificates recorded in each signature's X.509 trust
//! evidence and re-checks them through the shared path processor with the
//! operation's provider and certificate policy.

use structured_asn1::memory::{MemoryError, Work};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::xmldsig::extension::{ScalarError, TreeError};
use xml_sec::xmldsig::{DsigError, VerifiedSession, X509ChainError};

mod basic;
mod binary;
mod path;
mod signature;
mod xml;

pub use basic::{CounterError, Outcome, PathFailure, Report, ValidationError, validate_basic};
pub use binary::DigestIdentity;
pub use path::CounterPathError;

/// Original document identity and generation, as seen by the shared core.
pub type Snapshot = structured_xades::xml::Snapshot<DocumentIdentity, u64>;

/// The structured-xades view of one verified document.
///
/// Every query checks the supplied snapshot against the session's view and
/// charges the caller's execution before data-dependent work.
pub struct Document<'s, 'view, 'scope, 'inputs, W: Work> {
    session: &'s VerifiedSession<'view, 'scope, 'inputs, W>,
}

impl<'s, 'view, 'scope, 'inputs, W: Work> Document<'s, 'view, 'scope, 'inputs, W> {
    /// Attach the adapter to a verified session; this performs no work.
    #[must_use]
    pub fn new(session: &'s VerifiedSession<'view, 'scope, 'inputs, W>) -> Self {
        Self { session }
    }

    /// The verified session this adapter reads.
    #[must_use]
    pub fn session(&self) -> &'s VerifiedSession<'view, 'scope, 'inputs, W> {
        self.session
    }

    fn check(&self, snapshot: Snapshot) -> Result<(), Error> {
        let view = self.session.view();
        if snapshot.document != view.identity() || snapshot.generation != view.generation() {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

/// Adapter failure, distinct from every completed XAdES fact.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The query named a different document or generation than the session.
    #[error("XAdES query uses a different document generation")]
    Changed,
    /// Original tree navigation or binary decoding failed.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// Original scalar or attribute reading failed.
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    /// The verified session refused the lookup.
    #[error(transparent)]
    Verification(#[from] DsigError),
    /// A validated path certificate could not be processed again.
    #[error(transparent)]
    Certificate(#[from] X509ChainError),
    /// The current execution refused work or storage.
    #[error("XAdES adapter resource failure: {0}")]
    Resource(MemoryError),
    /// The signature is not part of the verified request.
    #[error("signature is not part of the verified request")]
    UnknownSignature,
    /// The ordinal is outside the verified SignedInfo references.
    #[error("reference ordinal outside the verified SignedInfo")]
    ReferenceOrdinal,
    /// The verified reference result carries no original node identity.
    #[error("verified reference has no original node identity")]
    ReferenceIdentity,
    /// A URI read from simple content contains element children.
    #[error("reference URI source contains element content")]
    MalformedUri,
    /// A prohibited digest reached computation; the format check refuses it
    /// before any hashing, so this marks a broken invariant.
    #[error("prohibited digest algorithm cannot be computed")]
    ProhibitedDigest,
    /// The replay receiver refused further bytes.
    #[error("reference replay receiver refused output")]
    ReceiverRefused,
    /// The request supplied no bytes for this admitted external reference.
    #[error("external reference bytes were not supplied")]
    Unavailable {
        /// Original authenticated reference.
        reference: NodeIdentity,
    },
}

impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

fn source(
    source: structured_xades::reference::LexicalSource<'_>,
) -> xml_sec::xmldsig::LexicalSource<'_> {
    match source {
        structured_xades::reference::LexicalSource::Attribute(name) => {
            xml_sec::xmldsig::LexicalSource::Attribute {
                namespace: (!name.namespace.is_empty()).then_some(name.namespace),
                local_name: name.local,
            }
        }
        structured_xades::reference::LexicalSource::SimpleContent => {
            xml_sec::xmldsig::LexicalSource::SimpleContent
        }
    }
}
