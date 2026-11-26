//! Signatures whose qualifying properties use ETSI TS 101 903 V1.2.2, which
//! the operation's policy admits through `XadesSyntax::WithTs101903V122`.
//! EN 319 132-1 baseline levels do not apply to them; their BES form (§4.4.1)
//! is the authenticated signed properties and the signer's certificate.
//! <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.02.02_60/ts_101903v010202p.pdf>

use crate::basic::{Outcome, ValidationError};
use crate::path::{self, CounterPathError};
use crate::{Document, Error};
use alloc::boxed::Box;
use structured_asn1::memory::Work;
use structured_xades::certificate::KeyAssociation;
use structured_xades::container::{self, ContainerError, Selected, Syntax, Syntaxes};
use structured_xades::legacy::{
    self as v122, CertificateMatch, Property, SignerCheck, SignerError,
};
use structured_xades::xml::{Access, Xml as _};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::policy::XadesSyntax;
use xml_sec::xmldsig::VerifiedSession;

/// The original syntaxes the shared reader may select under `policy`.
pub(crate) fn syntaxes(policy: XadesSyntax) -> Syntaxes {
    match policy {
        XadesSyntax::En319132 => Syntaxes::En319132,
        XadesSyntax::WithTs101903V122 => Syntaxes::WithTs101903V122,
    }
}

/// Whether the operation's policy admits V1.2.2 and `signature`'s qualifying
/// properties use it.
///
/// # Errors
/// Under that policy, why the containers of both syntaxes could not be
/// located. A container of each syntax is one such cause: the EN 319 132-1
/// reader alone would not see the V1.2.2 one and would assess the other.
pub(crate) fn ts101903_signature<W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    access: &Access<'_, Document<'_, '_, '_, '_, W>, Q>,
    signature: NodeIdentity,
) -> Result<bool, ValidationError> {
    if session.xades_syntax() != XadesSyntax::WithTs101903V122 {
        return Ok(false);
    }
    match container::locate_with_syntax(access, signature, Syntaxes::WithTs101903V122) {
        Ok(selected) => Ok(matches!(selected, Selected::Ts101903V122(_))),
        // No container of either syntax is the EN 319 132-1 reader's to
        // report, with the requirements it reads.
        Err(ContainerError::Missing { .. }) => Ok(false),
        Err(cause) => Err(ValidationError::Ts101903(Box::new(
            Ts101903Error::Container(cause),
        ))),
    }
}

/// Why a V1.2.2 signature could not be processed, with the original cause.
#[derive(Debug)]
pub enum Ts101903Error {
    /// The qualifying-property containers could not be located.
    Container(ContainerError<Error, NodeIdentity>),
    /// The signed properties are not bound to the signature, or a property
    /// sequence violates the V1.2.2 schema.
    Properties(v122::Error<Error, NodeIdentity>),
    /// The signer's certificate could not be compared with its protection.
    Signer(SignerError<Error, Error, NodeIdentity, DocumentIdentity, u64>),
}

/// The BES facts (TS 101 903 V1.2.2 §4.4.1) of one verified signature.
pub struct Ts101903Report<'a> {
    signer: SignerCheck<NodeIdentity>,
    signed: &'a [Property<NodeIdentity>],
    unsigned: &'a [Property<NodeIdentity>],
}

impl Ts101903Report<'_> {
    /// How the signature protects its checked path's target certificate, and
    /// whether that certificate holds the key that verified it.
    #[must_use]
    pub fn signer(&self) -> SignerCheck<NodeIdentity> {
        self.signer
    }

    /// The signed signature properties, in document order.
    #[must_use]
    pub fn signed(&self) -> &[Property<NodeIdentity>] {
        self.signed
    }

    /// The unsigned signature properties, in document order.
    #[must_use]
    pub fn unsigned(&self) -> &[Property<NodeIdentity>] {
        self.unsigned
    }

    /// Whether the BES requirements hold: the signed properties are
    /// authenticated (checked before this report exists), and the signature
    /// protects the signing certificate, through `SigningCertificate` or its
    /// signed `KeyInfo` (§4.4.1), that holds the verifying key.
    #[must_use]
    pub fn bes_met(&self) -> bool {
        self.signer.key == KeyAssociation::Same
            && matches!(
                self.signer.certificate,
                CertificateMatch::Digest(_) | CertificateMatch::Embedded(_)
            )
    }
}

/// Validate the BES form of a TS 101 903 V1.2.2 `signature`.
///
/// A signature in the EN 319 132-1 syntax is the completed fact
/// [`Outcome::Syntax`]. Under a policy that reads EN 319 132-1 alone the
/// V1.2.2 namespace names no qualifying properties, so a V1.2.2 signature has
/// none and is refused as [`Ts101903Error::Container`]. The signer's path is the one
/// verification validated, re-checked as [`crate::validate_basic`] re-checks
/// it; `certificates` are the caller's DER certificates beyond `KeyInfo`.
///
/// # Errors
/// Returns the original cause of the stage that could not complete, and
/// [`Error::UnknownSignature`] for an identity outside the request.
pub fn validate_ts101903<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    certificates: &[&[u8]],
    visitor: impl for<'a> FnOnce(&Ts101903Report<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let fail = |error| ValidationError::Ts101903(Box::new(error));
    let work = session.execution();
    path::require_member(session, signature, work)?;
    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), work);
    let layout =
        match container::locate_with_syntax(&access, signature, syntaxes(session.xades_syntax()))
            .map_err(|cause| fail(Ts101903Error::Container(cause)))?
        {
            Selected::Ts101903V122(layout) => layout,
            Selected::En319132(_) => {
                return Ok(Outcome::Syntax {
                    signature,
                    syntax: Syntax::En319132,
                });
            }
        };
    let prepared =
        v122::prepare(&access, &layout).map_err(|cause| fail(Ts101903Error::Properties(cause)))?;

    let parser = session.certificate_parser();
    let x509 = parser.memory();
    let signers = path::signers(session, signature, &[], x509)?;
    let decoded = path::key_info_certificates(session, &signers, x509)?;
    let candidates = path::candidates(&decoded, [certificates, &[]], x509)?;
    let selection = path::select(&signers, &candidates, &parser, x509)?;
    let paths = path::check(session, &selection, (signature, None), x509)?;
    let checked = match paths.get(signature, x509) {
        Ok(checked) => checked,
        Err(CounterPathError::Missing(failure)) => {
            return Ok(Outcome::Path { signature, failure });
        }
        Err(CounterPathError::Resource(cause)) => return Err(Error::from(cause).into()),
    };
    let target = checked.target();
    let signer = v122::check_signer(
        &document,
        &prepared,
        target.certificate(),
        target.key(),
        &document,
        work,
    )
    .map_err(|cause| fail(Ts101903Error::Signer(cause)))?;
    Ok(Outcome::Assessed(visitor(&Ts101903Report {
        signer,
        signed: prepared.signed(),
        unsigned: prepared.unsigned(),
    })))
}
