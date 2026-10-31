//! Caller-established TSA policy accuracy, selected per token.

use alloc::boxed::Box;
use core::convert::Infallible;

use crate::{Error, ValidationError};
use structured_asn1::memory::OwnedVec;
use structured_asn1::{Oid, Parser, Reader};
use structured_cms::directory::{CertificateAgreement, matches_certificate_in};
use structured_cms::timestamp::{PolicyAccuracy, Token};
use structured_pkix::Certificate;
use xml_sec::xmldsig::X509ChainError;

/// The accuracy one timestamp authority's policy states, for its tokens that
/// omit the field (RFC 3161 §2.4.2). The caller authenticates this association;
/// nothing in the document can supply or widen it.
#[derive(Clone, Copy)]
pub struct AuthorityAccuracy<'a> {
    /// DER certificate of the timestamp authority.
    pub authority: &'a [u8],
    /// The signed policy identifier and the accuracy it states.
    pub stated: PolicyAccuracy<'a>,
}

/// One caller entry, its authority parsed once for the whole validation.
pub(crate) struct Stated<'s> {
    authority: Certificate<'s>,
    stated: PolicyAccuracy<'s>,
}

/// Parse the caller's entries under the operation's certificate parser.
pub(crate) fn read<'s>(
    parser: &'s Parser,
    entries: &'s [AuthorityAccuracy<'s>],
) -> Result<OwnedVec<Stated<'s>>, Error> {
    let mut parsed = parser.memory().vector();
    parsed.try_reserve_exact(entries.len())?;
    for entry in entries {
        parsed.try_push(Stated {
            authority: Certificate::read(parser, entry.authority, 0)
                .map_err(X509ChainError::Processing)?,
            stated: entry.stated,
        })?;
    }
    Ok(parsed.into_owned())
}

/// The entry for the authority `token` names under its own signed `policy`.
/// Choosing by that policy keeps an unlisted one a completed negative fact
/// rather than the checker's refusal of a mismatched caller policy.
pub(crate) fn select<'s>(
    stated: &[Stated<'s>],
    token: &Token<'_>,
    policy: Oid<'_>,
    parent: &Reader<'s>,
) -> Result<Option<PolicyAccuracy<'s>>, ValidationError> {
    for entry in stated {
        // The cheap policy comparison rejects before the directory comparison.
        if policy != entry.stated.policy() {
            continue;
        }
        let named = matches_certificate_in(token.signer().sid(), &entry.authority, parent)
            .map_err(ValidationError::Token)?;
        if matches!(named, CertificateAgreement::Matches) {
            return Ok(Some(entry.stated));
        }
    }
    Ok(None)
}

/// As [`select`], reading the policy of a token outside its information scope.
/// Nothing is read for a request that states no accuracy.
pub(crate) fn select_outside<'s>(
    stated: &[Stated<'s>],
    token: &Token<'_>,
    token_reader: &Reader<'_>,
    parent: &Reader<'s>,
) -> Result<Option<PolicyAccuracy<'s>>, ValidationError> {
    if stated.is_empty() {
        return Ok(None);
    }
    token
        .with_info(token_reader, |info, _, _| {
            Ok::<_, Infallible>(select(stated, token, info.policy(), parent))
        })
        .map_err(|cause| ValidationError::TokenInfo(Box::new(cause)))?
}
