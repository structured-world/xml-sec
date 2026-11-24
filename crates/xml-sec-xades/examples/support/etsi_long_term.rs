//! The long-term validation process (ETSI EN 319 102-1 V1.4.1 clause 5.6)
//! over one corpus signature: the basic and with-time facts, each timestamp
//! the signature carries with what it covers, and every historical candidate
//! chain of the signer and of each TSA. The shared process decides.

use super::{History, Record, TokenFacts, instant};
use structured_asn1::memory::Memory;
use structured_ltv::validation::long_term::{
    self, Candidate, Inputs, Member, Object, RetryCause, Revocation, RevocationCheck,
    RevocationData, Signature, Stage, Timestamp, Validity, ValidityModel,
};
pub(super) use structured_ltv::validation::long_term::{Covered, Decision};
use structured_ltv::validation::{Chain, Facts, Requirements};
use structured_pkix::Certificate;

/// The original objects of one validation, each numbered once: the
/// signature value, its tokens, the certificates the comparison knows and
/// the document's CRLs and OCSP responses.
pub(super) struct Catalogue<'c> {
    pub(super) tokens: usize,
    pub(super) certificates: Vec<&'c Certificate<'c>>,
    pub(super) sources: usize,
}

impl Catalogue<'_> {
    pub(super) const VALUE: Object = Object(0);

    pub(super) const fn token(index: usize) -> Object {
        Object(1 + index)
    }

    fn certificate(&self, der: &[u8]) -> Option<(Object, Validity)> {
        let index = self
            .certificates
            .iter()
            .position(|certificate| certificate.as_bytes() == der)?;
        let (not_before, not_after) = super::validity(self.certificates[index]);
        Some((
            Object(1 + self.tokens + index),
            Validity {
                not_before,
                not_after,
            },
        ))
    }

    pub(super) fn source(&self, index: usize) -> Object {
        Object(1 + self.tokens + self.certificates.len() + index)
    }

    pub(super) fn count(&self) -> usize {
        1 + self.tokens + self.certificates.len() + self.sources
    }

    /// Every certificate and status source, as an archive timestamp covers
    /// the validation data incorporated before it.
    pub(super) fn material(&self) -> impl Iterator<Item = Object> + '_ {
        (0..self.certificates.len() + self.sources).map(|index| Object(1 + self.tokens + index))
    }
}

/// One non-anchor member and the revocation data about it.
type MemberData = (Object, Vec<RevocationData<'static>>);

/// Past-validation inputs of one signed object, owned.
pub(super) struct Past {
    value: Object,
    validity: Validity,
    chains: Vec<(Chain, Validity, Vec<MemberData>)>,
    own: Vec<RevocationData<'static>>,
}

/// The authenticated statements of one member as revocation data.
fn data(records: &[Record], catalogue: &Catalogue<'_>) -> Vec<RevocationData<'static>> {
    records
        .iter()
        .filter_map(|record| {
            let (issuer, issuer_validity) = catalogue.certificate(&record.signer)?;
            Some(RevocationData {
                object: catalogue.source(record.source),
                issuer,
                issuer_validity,
                issued: record.issued,
                // DSS's policy ignores revocation freshness.
                fresh_before: None,
                status: match record.revoked {
                    None => Revocation::Clear,
                    Some((at, reason)) => Revocation::Revoked { at, reason },
                },
                crypto: &[],
                delegated: None,
            })
        })
        .collect()
}

/// The past-validation inputs of the object `value` signed by `target`.
pub(super) fn past(
    value: Object,
    target: &Certificate<'_>,
    history: &[History],
    catalogue: &Catalogue<'_>,
) -> Past {
    let (not_before, not_after) = super::validity(target);
    let chains: Vec<_> = history
        .iter()
        .map(|chain| {
            let members = chain
                .members
                .iter()
                .filter_map(|(der, records)| {
                    let (object, _) = catalogue.certificate(der)?;
                    Some((object, data(records, catalogue)))
                })
                .collect();
            (
                chain.chain,
                Validity {
                    not_before: chain.validity.0,
                    not_after: chain.validity.1,
                },
                members,
            )
        })
        .collect();
    let own = chains
        .first()
        .and_then(|(_, _, members): &(_, _, Vec<(Object, Vec<_>)>)| members.last())
        .map(|(_, data)| data.clone())
        .unwrap_or_default();
    Past {
        value,
        validity: Validity {
            not_before,
            not_after,
        },
        chains,
        own,
    }
}

/// One timestamp token as the process consumes it, apart from its TSA's
/// past-validation inputs (`past`, an index into the pasts).
pub(super) struct Token {
    pub(super) object: Object,
    pub(super) facts: TokenFacts,
    pub(super) current: Decision,
    pub(super) covered: Vec<Covered>,
    pub(super) past: Option<usize>,
}

/// Clause 5.6.3 over `current`, the signer's past inputs (`pasts[0]`) and
/// `tokens`, newest first.
pub(super) fn validate(
    current: &Facts<'_>,
    requirements: &Requirements<'_>,
    catalogue: &Catalogue<'_>,
    pasts: &[Past],
    tokens: &mut [Token],
    long_term_attributes: bool,
    memory: &Memory,
) -> Result<(Decision, Stage), String> {
    let members: Vec<Vec<Vec<Member<'_>>>> = pasts
        .iter()
        .map(|past| {
            past.chains
                .iter()
                .map(|(_, _, members)| {
                    members
                        .iter()
                        .map(|(object, data)| Member {
                            object: *object,
                            crypto: &[],
                            revocations: RevocationCheck::Required(data),
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let candidates: Vec<Vec<Candidate<'_>>> = pasts
        .iter()
        .zip(&members)
        .map(|(past, members)| {
            past.chains
                .iter()
                .zip(members)
                .map(|((chain, validity, _), members)| Candidate {
                    chain: *chain,
                    recognized: true,
                    anchor_sunset: None,
                    validity: *validity,
                    members,
                })
                .collect()
        })
        .collect();
    let signatures: Vec<Signature<'_>> = pasts
        .iter()
        .zip(&candidates)
        .map(|(past, candidates)| Signature {
            value: past.value,
            validity: past.validity,
            candidates,
            model: ValidityModel::Shell,
            revoked_ca_at: None,
            revocations: &past.own,
            affected_crypto: &[],
            retry: RetryCause::Other,
        })
        .collect();
    let signer = *signatures.first().ok_or("no signer inputs")?;
    // Clause 5.6.3.4 processes the timestamps newest first.
    tokens.sort_by_key(|token| std::cmp::Reverse(token.facts.generated));
    let timestamps: Vec<Timestamp<'_>> = tokens
        .iter()
        .map(|token| Timestamp {
            object: token.object,
            generated: instant(token.facts.generated),
            not_before: None,
            imprint: token.facts.imprint,
            current: token.current,
            past: token.past.and_then(|index| signatures.get(index).copied()),
            acceptance: &[],
            covered: &token.covered,
            required: false,
        })
        .collect();
    let present: Vec<Object> = (0..catalogue.count()).map(Object).collect();
    let inputs = Inputs {
        object_count: catalogue.count(),
        present: &present,
        initial: &[],
        current,
        signature: signer,
        records: &[],
        timestamps: &timestamps,
        has_long_term_attributes: long_term_attributes,
        require_long_term_attributes: false,
    };
    let report =
        long_term::validate(&inputs, requirements, memory).map_err(|error| format!("{error:?}"))?;
    Ok((report.decision, report.stage))
}
