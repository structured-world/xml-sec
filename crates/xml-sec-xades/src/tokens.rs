//! Each timestamp token's own checks, apart from the signer's path and the
//! level's requirements.

use alloc::boxed::Box;
use core::convert::Infallible;

use crate::basic::{Outcome, ValidationError, enclosing_counter};
use crate::level::{Inputs, OwnCheck, TimestampFailure, incorporated_certificates};
use crate::{Document, Error, accuracy, path};
use structured_pkix::temporal::Instant;
use structured_xades::container::Syntax;
use structured_xades::material;
use structured_xades::prepare;
pub use structured_xades::timestamp::Role as TimestampRole;
use structured_xades::timestamp::{self, TokenProfile};
use structured_xades::xml::{Access, Xml as _};
use xml_sec::document::NodeIdentity;
use xml_sec::policy::TimestampTokenEncoding;
use xml_sec::xmldsig::VerifiedSession;

/// The comparison instant of a token's own checks: the last second any
/// `GeneralizedTime` can name, 9999-12-31T23:59:59Z (RFC 5280 4.1.2.5.2). The
/// check refuses a token generated after its reference and cannot place one
/// with no reference at all; a token's own checks bound no generation time,
/// which the level's requirements judge.
const END_OF_TIME: Instant = match Instant::new(253_402_300_799, 0) {
    Some(instant) => instant,
    None => panic!("9999-12-31T23:59:59Z is an instant"),
};

/// What the own checks of one timestamp token established (ETSI EN 319 102-1
/// V1.4.1 clause 5.4, building on 5.2.7): its message imprint and its named
/// signer's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenIntegrity {
    /// The imprint binds and the named signer's key verifies the token.
    Intact,
    /// The token's imprint, signature or profile facts did not hold.
    Rejected,
    /// No available certificate is the one the token names as its signer.
    MissingSigner,
}

/// One timestamp token of a signature and what its own checks established.
#[derive(Debug, Clone, Copy)]
pub struct TokenResult<'a> {
    role: TimestampRole,
    property: NodeIdentity,
    token: &'a [u8],
    integrity: TokenIntegrity,
}

impl<'a> TokenResult<'a> {
    /// What its timestamp property stamps, which decides what it covers.
    #[must_use]
    pub fn role(&self) -> TimestampRole {
        self.role
    }

    /// Its timestamp property.
    #[must_use]
    pub fn property(&self) -> NodeIdentity {
        self.property
    }

    /// The token as the document carries it, decoded from its element.
    #[must_use]
    pub fn token(&self) -> &'a [u8] {
        self.token
    }

    /// What its own checks established.
    #[must_use]
    pub fn integrity(&self) -> TokenIntegrity {
        self.integrity
    }
}

/// Check every timestamp token of `signature`'s own properties, in document
/// order, each on its own (EN 319 102-1 V1.4.1 clause 5.4): its imprint over
/// what its property stamps and its named signer's signature.
///
/// Unlike [`crate::validate`], which stops at the first token that fails,
/// no token is left unchecked by another's failure, and neither the signer's
/// path nor the time a token was generated at is judged: a token stays
/// checkable after the signing certificate expired, which is what it
/// preserves. The signed properties a token stamps are read from the
/// signature's authenticated references, so the signature itself must have
/// verified. A countersignature's tokens belong to its own signature. The
/// signer of a token is found among the certificates it carries, the
/// caller's [`Inputs::certificates`] and [`Inputs::anchors`], and the
/// document's validation data; `Intact` says nothing of its path.
///
/// # Errors
/// Returns the original cause of a stage that could not complete, and
/// [`Error::UnknownSignature`] for an identity outside the request.
pub fn check_tokens<W: structured_asn1::memory::Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    inputs: &Inputs<'_>,
    visitor: impl for<'a> FnOnce(&[TokenResult<'a>]) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let work = session.execution();
    path::require_member(session, signature, work)?;
    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), work);
    if crate::ts101903::ts101903_signature(session, &access, signature)? {
        return Ok(Outcome::Syntax {
            signature,
            syntax: Syntax::Ts101903V122,
        });
    }
    let enclosing = enclosing_counter(&document, &access, signature)?;
    let prepared = prepare::prepare(&access, signature, inputs.requirements, enclosing.as_ref())
        .map_err(|error| ValidationError::Prepare(Box::new(error)))?;
    let parser = session.certificate_parser();
    let memory = parser.memory();
    let reader = parser.read(&[], 0).map_err(ValidationError::Operation)?;
    let stated = accuracy::read(&parser, inputs.accuracies)?;
    // The token's signer may be any certificate the caller supplies, its
    // anchors included: finding it checks the token's signature only.
    let mut candidates = memory.vector();
    // Both are slices in memory, so their lengths' sum fits a usize.
    candidates
        .try_reserve_exact(inputs.certificates.len() + inputs.anchors.len())
        .map_err(Error::from)?;
    for certificate in inputs.certificates.iter().chain(inputs.anchors) {
        candidates.try_push(*certificate).map_err(Error::from)?;
    }
    let supplied = crate::level::read_certificates(&parser, &candidates)?;
    let supplied_parent = parser.read(&[], 0).map_err(ValidationError::Operation)?;
    let cms = session.cms_provider();
    let profile = match session.timestamp_token_encoding() {
        TimestampTokenEncoding::Declared => TokenProfile::Etsi,
        TimestampTokenEncoding::Ber => TokenProfile::Cms,
    };
    timestamp::with_tokens(
        &document,
        &prepared,
        &reader,
        profile,
        |operation, tokens| {
            Ok::<_, Infallible>(
                material::with_values(&document, &prepared, operation, |operation, view| {
                    Ok::<_, Infallible>((|| {
                        let document_der = incorporated_certificates(&view, memory)?;
                        let incorporated = crate::level::read_certificates(&parser, &document_der)?;
                        let check = OwnCheck {
                            document: &document,
                            prepared: &prepared,
                            stamps: None,
                            stated: &stated,
                            reader: &reader,
                            utc: inputs.utc,
                            reference: Some(END_OF_TIME),
                            tokens: &tokens,
                            operation,
                            supplied: [&supplied, &incorporated],
                            supplied_parent: &supplied_parent,
                        };
                        let sources = tokens.sources();
                        let mut results = memory.vector();
                        results
                            .try_reserve_exact(sources.len())
                            .map_err(Error::from)?;
                        for (ordinal, source) in sources.iter().enumerate() {
                            let integrity = match check.token(&cms, ordinal)? {
                                Ok(_) => TokenIntegrity::Intact,
                                Err(TimestampFailure::MissingSigner) => {
                                    TokenIntegrity::MissingSigner
                                }
                                Err(_) => TokenIntegrity::Rejected,
                            };
                            results
                                .try_push(TokenResult {
                                    role: source.role(),
                                    property: source.property(),
                                    token: source.bytes(),
                                    integrity,
                                })
                                .map_err(Error::from)?;
                        }
                        Ok(Outcome::Assessed(visitor(&results.into_owned())))
                    })())
                })
                .map_err(|error| ValidationError::Material(Box::new(error)))
                .and_then(core::convert::identity),
            )
        },
    )
    .map_err(|error| ValidationError::Tokens(Box::new(error)))?
}
