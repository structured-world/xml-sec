//! The XAdES B-B pipeline for one verified signature.

use crate::path::{self, PathFailure as Failure};
use crate::{Document, Error};
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, Work};
use structured_xades::baseline::{self, Basic, BasicInput};
use structured_xades::certificate::{self, KeyAssociation};
use structured_xades::counter::WalkError;
use structured_xades::hashes::{self, HashError, ParticipantBinding, ParticipantProblem};
use structured_xades::pki::{self, CounterSelectionError};
use structured_xades::prepare;
use structured_xades::unsigned::Requirements;
use structured_xades::xml::{Access, Xml};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::xmldsig::VerifiedSession;

pub use crate::path::PathFailure;

/// The assembled B-B facts handed to the caller's visitor. Inspect
/// [`Basic::all_root_requirements_met`] and the individual facts; the report
/// asserts no timestamp, revocation or application trust decision.
pub type Report<'a> = Basic<'a, 'a, 'a, 'a, NodeIdentity, DocumentIdentity, u64>;

/// A completed B-B validation, or the completed negative fact that stopped it.
#[derive(Debug)]
pub enum Outcome<R> {
    /// The B-B facts were assembled; this is the visitor's result.
    Assessed(R),
    /// A signer of the root or of an incorporated countersignature has no
    /// checked certificate path.
    Path {
        /// Original signature whose signer lacks the path.
        signature: NodeIdentity,
        /// Why no path is available.
        failure: PathFailure,
    },
    /// A countersignature's verification key is not its path target's key.
    CounterKey {
        /// Original countersignature.
        signature: NodeIdentity,
        /// The completed or unproven association.
        association: KeyAssociation,
    },
    /// An original actor used MD5 or an unsupported or unprocessed hash
    /// (EN 319 132-1 §6.2.1).
    Hashes(ParticipantProblem<NodeIdentity>),
}

/// Countersignature traversal failure with the original selection cause.
pub type CounterError =
    WalkError<Error, CounterSelectionError<Failure, Error, NodeIdentity>, NodeIdentity>;

/// Processing failure of one pipeline stage, with the stage's original cause.
///
/// Stage causes nest the adapter's error with original locations; they are
/// boxed so the successful result stays small. The box is allocated only on
/// the failure path.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Adapter, path selection or session failure.
    #[error("XAdES adapter failure: {0}")]
    Adapter(#[from] Error),
    /// Qualifying-property structure, binding or reading failed.
    #[error("XAdES preparation failed: {0:?}")]
    Prepare(Box<prepare::Error<Error, NodeIdentity>>),
    /// Signed property attributes, URIs or the claimed signing time failed.
    #[error("XAdES signed field check failed: {0:?}")]
    Fields(Box<prepare::FieldError<Error, NodeIdentity, DocumentIdentity, u64>>),
    /// Countersignature traversal or binding failed.
    #[error("countersignature traversal failed: {0:?}")]
    Counters(Box<CounterError>),
    /// Hash-use receipts could not be checked.
    #[error("hash-use check failed: {0:?}")]
    Hashes(Box<HashError<Error, NodeIdentity>>),
    /// Signing-certificate references could not be checked against the path.
    #[error("signing certificate check failed: {0:?}")]
    Certificate(Box<certificate::CheckError<Error, Error, NodeIdentity, DocumentIdentity, u64>>),
    /// The final B-B assembly failed.
    #[error("B-B assembly failed: {0:?}")]
    Basic(Box<baseline::BasicError<Error, NodeIdentity, DocumentIdentity, u64>>),
    /// The ASN.1 operation for binary values could not start.
    #[error("ASN.1 operation could not start: {0:?}")]
    Operation(structured_asn1::Error),
}

/// Validate the B-B level (ETSI EN 319 132-1 §6.3) of `signature`.
///
/// `signature` must belong to `session`'s request. `certificates` are the
/// caller's DER certificates beyond the Signature's `KeyInfo`: the trust
/// anchors and intermediates the verification's key resolver used. The
/// signer's path is the exact path verification validated, re-checked by the
/// shared processor; countersignatures need validated paths of their own.
/// `memory` funds all work and storage of this call.
///
/// The visitor receives the assembled report; nothing borrowed from it can
/// escape. A completed negative fact returns as an [`Outcome`] variant.
///
/// # Errors
/// Returns the original cause of the stage that could not complete.
pub fn validate_basic<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    certificates: &[&[u8]],
    memory: &Memory,
    visitor: impl for<'a> FnOnce(&Report<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let signers = path::signers(session, signature, memory)?;
    let decoded = path::key_info_certificates(session, &signers, memory)?;
    let mut candidates = memory.vector();
    for bytes in decoded.iter() {
        candidates.try_push(&bytes[..]).map_err(Error::from)?;
    }
    for bytes in certificates {
        candidates.try_push(*bytes).map_err(Error::from)?;
    }
    let parser = Parser::der(memory.clone());
    let selection = path::select(session, &signers, &candidates, &parser, memory)?;
    let paths = path::check(session, &selection, memory)?;
    let root = match paths.get(signature) {
        Ok(root) => root,
        Err(failure) => return Ok(Outcome::Path { signature, failure }),
    };

    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), memory);
    let prepared = prepare::prepare(&access, signature, Requirements::Basic, None)
        .map_err(|error| ValidationError::Prepare(Box::new(error)))?;
    let fields = prepare::check_fields(&prepared, &access)
        .map_err(|error| ValidationError::Fields(Box::new(error)))?;
    let counters = match pki::bind_counters(prepared.bound(), &access, |binding, _| {
        paths.get(binding.original().child())
    }) {
        Ok(counters) => counters,
        Err(WalkError::Visitor(CounterSelectionError::Selection { signature, cause })) => {
            return Ok(Outcome::Path {
                signature,
                failure: cause,
            });
        }
        Err(WalkError::Visitor(CounterSelectionError::Differs { signature })) => {
            return Ok(Outcome::CounterKey {
                signature,
                association: KeyAssociation::Differs,
            });
        }
        Err(WalkError::Visitor(CounterSelectionError::Unproven { signature })) => {
            return Ok(Outcome::CounterKey {
                signature,
                association: KeyAssociation::Unproven,
            });
        }
        Err(error) => return Err(ValidationError::Counters(Box::new(error))),
    };
    let hashes = match hashes::check_participants(&prepared, &counters, &access)
        .map_err(|error| ValidationError::Hashes(Box::new(error)))?
    {
        ParticipantBinding::Bound(hashes) => hashes,
        ParticipantBinding::Unproven(problem) => return Ok(Outcome::Hashes(problem)),
    };
    let certificate = certificate::check_path(
        &document,
        prepared.bound(),
        prepared.certificates(),
        root,
        &document,
        memory,
    )
    .map_err(|error| ValidationError::Certificate(Box::new(error)))?;
    let operation = parser.read(&[], 0).map_err(ValidationError::Operation)?;
    let report = baseline::basic(
        BasicInput {
            fields: &fields,
            hashes: &hashes,
            certificate: &certificate,
            counters: &counters,
        },
        &document,
        &operation,
    )
    .map_err(|error| ValidationError::Basic(Box::new(error)))?;
    Ok(Outcome::Assessed(visitor(&report)))
}
