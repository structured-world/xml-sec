//! Adapter-owned execution domain for the published ASN.1 and PKIX mechanisms.

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::Certificate;

use super::x509::X509ChainError;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};

/// A certificate path's source bytes; display projections are not authority.
/// Both parsed public data and private borrowed pools use this same view.
pub(crate) trait X509DataSource {
    fn certificate_count(&self) -> usize;
    fn certificate(&self, index: usize) -> Option<&[u8]>;
    fn chain(&self) -> &[usize];
    fn crls(&self) -> &[Vec<u8>];

    fn encoded_certificates(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        (0..self.certificate_count())
            .map(|index| self.certificate(index).expect("source index is in range"))
    }
}

impl X509DataSource for super::X509DataInfo {
    fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
    fn certificate(&self, index: usize) -> Option<&[u8]> {
        self.certificates.get(index).map(Vec::as_slice)
    }
    fn chain(&self) -> &[usize] {
        &self.certificate_chain
    }
    fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }
}

enum XmlNameText<'a> {
    Borrowed(&'a str),
    Rewritten(structured_asn1::memory::OwnedString),
}

impl XmlNameText<'_> {
    fn text<'a>(&'a self, memory: &Memory) -> Result<&'a str, X509ChainError> {
        match self {
            Self::Borrowed(text) => Ok(text),
            Self::Rewritten(text) => text.as_str(memory).map_err(|reason| {
                X509ChainError::Processing(structured_pkix::Error::resource(
                    reason,
                    "name.selector",
                    0,
                ))
            }),
        }
    }
}

fn xml_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn escaped_at(bytes: &[u8], at: usize) -> bool {
    let mut start = at;
    while start > 0 && bytes[start - 1] == b'\\' {
        start -= 1;
    }
    (at - start) % 2 == 1
}

fn xml_name_pieces(
    text: &str,
    mut emit: impl FnMut(&str) -> Result<(), X509ChainError>,
) -> Result<bool, X509ChainError> {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() && xml_whitespace(bytes[start]) {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && xml_whitespace(bytes[end - 1]) && !escaped_at(bytes, end - 1) {
        end -= 1;
    }
    let mut changed = start != 0 || end != bytes.len();
    let mut piece = |segment: &str| -> Result<bool, X509ChainError> {
        let input = segment.as_bytes();
        let mut index = 0;
        while index < input.len() {
            if input[index] == b'\\' {
                index += 2;
                continue;
            }
            if input[index] == b'=' {
                // XMLDSig's recommended textual form historically accepts
                // this alias; the shared RFC 4514 codec uses emailAddress.
                let alias = segment[..index].eq_ignore_ascii_case("EMAIL");
                if alias {
                    emit("emailAddress")?;
                }
                // Preserve a historically accepted leading value space by
                // expressing it as RFC 4514's escaped space, not by deleting it.
                if index + 1 < input.len() && input[index + 1] == b' ' {
                    emit(if alias { "=" } else { &segment[..=index] })?;
                    emit("\\")?;
                    emit(&segment[index + 1..])?;
                    return Ok(true);
                }
                if alias {
                    emit(&segment[index..])?;
                    return Ok(true);
                }
                break;
            }
            index += 1;
        }
        emit(segment)?;
        Ok(false)
    };
    let mut at = start;
    let mut segment = start;
    while at < end {
        if bytes[at] == b'\\' {
            at += 2;
            continue;
        }
        if matches!(bytes[at], b',' | b'+') {
            let mut cut = at;
            while cut > segment && xml_whitespace(bytes[cut - 1]) && !escaped_at(bytes, cut - 1) {
                cut -= 1;
            }
            changed |= piece(&text[segment..cut])?;
            changed |= piece(&text[at..=at])?;
            let previous = at + 1;
            at = previous;
            while at < end && xml_whitespace(bytes[at]) {
                at += 1;
            }
            // Track removals separately from inserted escapes; equal lengths
            // do not prove that the source was already canonical.
            if cut != previous - 1 || at != previous {
                changed = true;
            }
            segment = at;
        } else {
            at += 1;
        }
    }
    changed |= piece(&text[segment..end])?;
    Ok(changed)
}

fn xml_name_text<'a>(text: &'a str, memory: &Memory) -> Result<XmlNameText<'a>, X509ChainError> {
    // XMLDSig 1.1 4.5.4.1 recommends RFC 4514, rather than requiring strict
    // lexical input. Preserve existing XML formatting tolerance here; the
    // shared codec remains strict and owns all DN value/equality semantics.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#dname-encrules
    let fail = |reason| {
        X509ChainError::Processing(structured_pkix::Error::resource(reason, "name.selector", 0))
    };
    let work = (text.len() as u64)
        .checked_mul(12)
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| fail(MemoryError::WorkExceeded))?;
    memory.charge_work(work).map_err(fail)?;
    if !xml_name_pieces(text, |_| Ok(()))? {
        return Ok(XmlNameText::Borrowed(text));
    }
    let mut output = memory.string();
    xml_name_pieces(text, |piece| output.try_push_str(piece).map_err(fail))?;
    Ok(XmlNameText::Rewritten(output))
}

impl CertificateSession {
    pub(crate) fn read_pool<'a>(
        &'a self,
        certificates: &'a [Vec<u8>],
    ) -> Result<OwnedVec<Certificate<'a>>, X509ChainError> {
        self.read_sources(certificates.iter().map(Vec::as_slice))
    }

    pub(crate) fn read_sources<'a>(
        &'a self,
        certificates: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<OwnedVec<Certificate<'a>>, X509ChainError> {
        let mut pool = self.memory().vector();
        pool.try_reserve_exact(certificates.len())
            .map_err(|reason| {
                self.error(structured_pkix::Error::resource(
                    reason,
                    "certificate.pool",
                    0,
                ))
            })?;
        for encoded in certificates {
            pool.try_push(self.read(encoded)?).map_err(|reason| {
                self.error(structured_pkix::Error::resource(
                    reason,
                    "certificate.pool",
                    0,
                ))
            })?;
        }
        Ok(pool)
    }

    pub(crate) fn source_names_equal(
        &self,
        left: &structured_pkix::name::Name<'_>,
        right: &structured_pkix::name::Name<'_>,
    ) -> Result<bool, X509ChainError> {
        left.matches(right, self.memory())
            .map_err(|error| self.error(error))
    }

    pub(crate) fn selector(
        &self,
        text: &str,
    ) -> Result<structured_pkix::name::Selector, X509ChainError> {
        let normalize = |error| match error {
            X509ChainError::Processing(error) => self.error(error),
            error => error,
        };
        let text = xml_name_text(text, self.memory()).map_err(normalize)?;
        structured_pkix::name::Selector::parse(
            text.text(self.memory()).map_err(normalize)?,
            self.memory(),
        )
        .map_err(|error| self.error(error))
    }

    #[cfg(test)]
    pub(crate) fn names_equal(&self, left: &str, right: &str) -> Result<bool, X509ChainError> {
        let left = self.selector(left)?;
        let right = self.selector(right)?;
        left.matches(&right, self.memory())
            .map_err(|error| self.error(error))
    }

    #[cfg(test)]
    fn read_name<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> Result<structured_pkix::name::Name<'a>, X509ChainError> {
        let mut reader = self.parser.read(bytes, 0).map_err(|error| {
            self.error(structured_pkix::Error::new(
                structured_pkix::ErrorCode::Encoding(error.code()),
                "name",
                error.offset(),
            ))
        })?;
        let element = reader
            .next_element()
            .map_err(|error| {
                self.error(structured_pkix::Error::new(
                    structured_pkix::ErrorCode::Encoding(error.code()),
                    "name",
                    error.offset(),
                ))
            })?
            .expect("test Name element");
        structured_pkix::name::read(&reader, &element, "name").map_err(|error| self.error(error))
    }
}

pub(crate) fn verification_instant(
    time: std::time::SystemTime,
) -> Result<structured_pkix::temporal::Instant, X509ChainError> {
    use std::time::UNIX_EPOCH;
    let nanos = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos())
            .map_err(|_| X509ChainError::CertificateNotValid(0))?,
        Err(error) => -i128::try_from(error.duration().as_nanos())
            .map_err(|_| X509ChainError::CertificateNotValid(0))?,
    };
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000))
        .map_err(|_| X509ChainError::CertificateNotValid(0))?;
    let fraction = u32::try_from(nanos.rem_euclid(1_000_000_000))
        .map_err(|_| X509ChainError::CertificateNotValid(0))?;
    structured_pkix::temporal::Instant::new(seconds, fraction)
        .ok_or(X509ChainError::CertificateNotValid(0))
}

#[cfg(test)]
pub(crate) fn test_utc_facts() -> structured_pkix::temporal::LeapTable<'static> {
    // Synthetic caller evidence for test labels; never used by a runtime default.
    structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .expect("test UTC coverage")
}

/// Consume only original sources and the already authenticated leaf-first path.
pub(crate) fn verify_crls<'a>(
    path: &'a [Certificate<'a>],
    embedded: &'a [Vec<u8>],
    additional: &'a [Vec<u8>],
    options: &super::x509::X509ChainOptions<'_>,
    provider: &dyn crate::provider::CryptoProvider,
    session: &'a CertificateSession,
) -> Result<(), X509ChainError> {
    use structured_pkix::crl::{Authentication, AuthenticationFailure};
    use structured_pkix::error::CallbackError;
    use structured_pkix::path::WorkingKey;

    if embedded.is_empty() && additional.is_empty() {
        return Ok(());
    }
    let Some(anchor) = path.last() else {
        return Ok(());
    };
    let execution = session.memory();
    let crls = read_crl_pool(embedded, additional, session)?;
    let verifier = ProviderVerifier {
        provider,
        allowed: options.certificate_signature_algorithms,
    };
    let now = verification_instant(options.verification_time)?.into();
    let mut issuer_key = WorkingKey::standing(anchor.tbs().public_key());
    // RFC 5280 §6.1.4: project effective parameters once from the validated
    // anchor toward its subjects. Original SPKI/TBS bytes are never rewritten.
    // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.4
    for position in (0..path.len() - 1).rev() {
        let issuer = &path[position + 1];
        let target = &path[position];
        let mut reasons = structured_pkix::crl::Reasons::NONE;
        for (index, crl) in crls.iter().enumerate() {
            if !crl
                .tbs()
                .issuer()
                .matches(issuer.tbs().subject(), execution)
                .map_err(|error| session.error(error))?
            {
                continue;
            }
            let identified = match crl_key_identifier_match(crl, issuer, session)? {
                KeyIdentifierMatch::Mismatch => continue,
                KeyIdentifierMatch::Identified => true,
                KeyIdentifierMatch::Unidentified => false,
            };
            let proof = crl
                .authenticate(issuer, issuer_key, &verifier, execution)
                .map_err(|error| match error {
                    CallbackError::Processing(error) => session.error(error),
                    CallbackError::Callback(error) => error,
                })?;
            let proof = match proof {
                Authentication::Authenticated(proof) => proof,
                Authentication::Rejected(AuthenticationFailure::KeyUsage) => {
                    return Err(X509ChainError::InvalidKeyUsage {
                        position: position + 1,
                        required: "cRLSign",
                    });
                }
                Authentication::Rejected(AuthenticationFailure::Signature) if !identified => {
                    continue;
                }
                Authentication::Rejected(_) | Authentication::Unsupported => {
                    return Err(X509ChainError::InvalidCrl(index));
                }
            };
            let Some(covered) = crl_reasons(
                &proof,
                crl,
                target,
                CrlEvaluation {
                    utc: options.utc_facts.as_ref(),
                    now,
                    index,
                    position,
                },
                session,
            )?
            else {
                continue;
            };
            // RFC 5280 §6.3.3(d),(l): partial-list absence cannot establish
            // non-revocation. All contributors share this authenticated path,
            // target and operation time by construction; no new evidence pool.
            // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
            reasons = reasons.union(covered);
        }
        // The existing policy validates supplied applicable lists, rather than
        // requiring callers to provide a list for every path certificate.
        if !reasons.is_empty() && !reasons.is_complete() {
            return Err(X509ChainError::IncompleteCrlCoverage(position));
        }
        issuer_key = issuer_key
            .subject(target, execution)
            .map_err(|error| session.error(error))?;
    }
    Ok(())
}

/// How a CRL's authority key identifier relates to a candidate issuer.
enum KeyIdentifierMatch {
    /// Both carry key identifiers and they are equal.
    Identified,
    /// Either side lacks a key identifier.
    Unidentified,
    /// Both carry key identifiers and they differ.
    Mismatch,
}

fn crl_key_identifier_match(
    crl: &structured_pkix::crl::CertificateList<'_>,
    issuer: &Certificate<'_>,
    session: &CertificateSession,
) -> Result<KeyIdentifierMatch, X509ChainError> {
    let execution = session.memory();
    let authority = crl
        .tbs()
        .extensions()
        .authority_key_identifier(execution)
        .map_err(|error| session.error(error))?;
    let subject = issuer
        .tbs()
        .extensions()
        .subject_key_identifier(execution)
        .map_err(|error| session.error(error))?;
    let Some((authority, subject)) = authority
        .as_ref()
        .and_then(structured_pkix::identifier::AuthorityKeyIdentifier::key_id)
        .zip(subject.map(structured_pkix::identifier::SubjectKeyIdentifier::as_bytes))
    else {
        return Ok(KeyIdentifierMatch::Unidentified);
    };
    execution
        .charge_work(authority.len().max(subject.len()) as u64 + 1)
        .map_err(|reason| {
            session.error(structured_pkix::Error::resource(
                reason,
                "certificateList.authorityKeyIdentifier",
                crl.span().start,
            ))
        })?;
    Ok(if authority == subject {
        KeyIdentifierMatch::Identified
    } else {
        KeyIdentifierMatch::Mismatch
    })
}

/// The operation facts one authenticated CRL is evaluated under.
#[derive(Clone, Copy)]
struct CrlEvaluation<'u> {
    utc: Option<&'u structured_pkix::temporal::LeapTable<'u>>,
    now: structured_pkix::temporal::Reading,
    index: usize,
    position: usize,
}

/// Reason coverage an authenticated CRL contributes for `target`, or `None`
/// when it does not apply. Revocation and unusable lists are errors.
fn crl_reasons<'a>(
    proof: &structured_pkix::crl::Authenticated<'_, 'a>,
    crl: &structured_pkix::crl::CertificateList<'_>,
    target: &'a Certificate<'a>,
    evaluation: CrlEvaluation<'_>,
    session: &CertificateSession,
) -> Result<Option<structured_pkix::crl::Reasons>, X509ChainError> {
    use structured_pkix::crl::{CompleteEvidence, Evaluation, ScopeOutcome, SourceOrigin};
    let execution = session.memory();
    validate_crl_serials(crl, session)?;
    // UTC history is a caller fact, not an implicit clock/table default.
    let Some(utc) = evaluation.utc else {
        if matches!(
            proof
                .scope(target, execution)
                .map_err(|error| session.error(error))?,
            ScopeOutcome::NotApplicable(_)
        ) {
            return Ok(None);
        }
        return Err(X509ChainError::MissingUtcFacts);
    };
    let evidence = proof
        .evaluate(
            target,
            &Evaluation {
                now: evaluation.now,
                utc,
                execution,
                origin: SourceOrigin::Cached,
            },
        )
        .map_err(|error| session.error(error))?;
    let facts = match evidence {
        CompleteEvidence::Facts(facts) => facts,
        CompleteEvidence::NotApplicable(_) => return Ok(None),
        CompleteEvidence::DeltaNeedsBase => {
            return Err(X509ChainError::InvalidCrl(evaluation.index));
        }
    };
    validate_complete_crl(
        facts,
        evaluation.now,
        utc,
        session,
        evaluation.index,
        evaluation.position,
    )?;
    execution.charge_work(1).map_err(|reason| {
        session.error(structured_pkix::Error::resource(
            reason,
            "certificateList.reasons",
            crl.span().start,
        ))
    })?;
    Ok(Some(facts.reasons()))
}

fn read_crl_pool<'a>(
    embedded: &'a [Vec<u8>],
    additional: &'a [Vec<u8>],
    session: &'a CertificateSession,
) -> Result<OwnedVec<structured_pkix::crl::CertificateList<'a>>, X509ChainError> {
    let mut crls = session.memory().vector();
    let resource_error = |reason| {
        session.error(structured_pkix::Error::resource(
            reason,
            "certificateList.pool",
            0,
        ))
    };
    let count = embedded
        .len()
        .checked_add(additional.len())
        .ok_or_else(|| resource_error(MemoryError::CapacityOverflow))?;
    crls.try_reserve_exact(count).map_err(resource_error)?;
    for bytes in embedded.iter().chain(additional) {
        let crl = session.read_crl(bytes)?;
        crls.try_push(crl).map_err(resource_error)?;
    }
    Ok(crls)
}

fn validate_complete_crl(
    facts: structured_pkix::crl::CompleteFacts<'_, '_, '_>,
    now: structured_pkix::temporal::Reading,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    session: &CertificateSession,
    index: usize,
    position: usize,
) -> Result<(), X509ChainError> {
    use structured_pkix::crl::{EntryLookup, Freshness};
    use structured_pkix::time::Relation;
    match facts.freshness() {
        Freshness::Current | Freshness::AtNextUpdate => (),
        Freshness::Uncertain(reason) => {
            return Err(X509ChainError::CrlTimeUncertain { index, reason });
        }
        _ => return Err(X509ChainError::InvalidCrl(index)),
    }
    match facts.entry() {
        EntryLookup::Absent => (),
        EntryLookup::Found(entry) => {
            match entry
                .time_relation(now, utc, session.memory())
                .map_err(|error| session.error(error))?
            {
                Relation::Before | Relation::At => return Err(X509ChainError::Revoked(position)),
                Relation::After => (),
                Relation::Uncertain(reason) => {
                    return Err(X509ChainError::CrlTimeUncertain { index, reason });
                }
            }
        }
        EntryLookup::Conflict { .. } | EntryLookup::Unsupported { .. } => {
            return Err(X509ChainError::InvalidCrl(index));
        }
    }
    Ok(())
}

fn validate_crl_serials(
    crl: &structured_pkix::crl::CertificateList<'_>,
    session: &CertificateSession,
) -> Result<(), X509ChainError> {
    // Preserve the consumer's conforming-positive serial profile while the
    // shared mechanism exposes arbitrary-width signed INTEGER facts.
    for entry in crl.tbs().revoked_certificates() {
        let bytes = entry.serial().as_bytes();
        session
            .memory()
            .charge_work(bytes.len() as u64 + 1)
            .map_err(|reason| {
                session.error(structured_pkix::Error::resource(
                    reason,
                    "certificateList.serial",
                    entry.span().start,
                ))
            })?;
        super::x509::validate_positive_serial_bytes(bytes, "CRL revoked certificate serial")?;
    }
    Ok(())
}

/// Shared path-processor bounds for a maximum path length that includes the
/// anchor; RFC 5280 §6.1 counts only the certificates below it.
pub(crate) fn path_bounds(max_chain_depth: usize) -> structured_pkix::path::ValidationBounds {
    structured_pkix::path::ValidationBounds {
        depth: max_chain_depth.saturating_sub(1),
        // The operation account owns the work/storage ceilings. These
        // mechanism limits must not divide or reset that shared budget.
        work: u64::MAX,
        policies: usize::MAX,
    }
}

pub(crate) fn validate_supplied_path<'a>(
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    options: &super::x509::X509ChainOptions<'_>,
    provider: &dyn crate::provider::CryptoProvider,
    session: &CertificateSession,
) -> Result<structured_pkix::path::ValidationFacts<'a>, X509ChainError> {
    use structured_pkix::path::{
        Anchor, BuildError, Interval, Policy, Validation, ValidationContext,
    };
    let verifier = CertificatePathVerifier {
        signatures: ProviderVerifier {
            provider,
            allowed: options.certificate_signature_algorithms,
        },
        chain,
        anchor,
        rsa_keys: options.rsa_keys,
        dsa_keys: options.dsa_keys,
    };
    let context = ValidationContext {
        execution: session.memory(),
        interval: Interval::at_instant(verification_instant(options.verification_time)?),
        policy: Policy::default(),
        bounds: path_bounds(options.max_chain_depth),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let result = structured_pkix::path::validate(chain, Anchor::from_certificate(anchor), &context)
        .map_err(|error| match error {
            BuildError::Processing(error)
            | BuildError::Verification(X509ChainError::Processing(error)) => session.error(error),
            BuildError::Verification(error) => error,
            BuildError::Recognition(never) => match never {},
        })?;
    match result {
        Validation::Accepted(facts) => Ok(facts),
        Validation::Incomplete(reason) => Err(X509ChainError::PathIncomplete(reason)),
        Validation::Rejected(rejection) => Err(path_rejection(&rejection, chain.len(), session)?),
    }
}

/// The chain error for a shared path-processor rejection; the anchor sits
/// at position `chain_len`.
fn path_rejection(
    rejection: &structured_pkix::path::Rejection<'_>,
    chain_len: usize,
    session: &CertificateSession,
) -> Result<X509ChainError, X509ChainError> {
    use structured_pkix::path::{ConstraintSource, RejectionReason};
    let position = |source| match source {
        ConstraintSource::Anchor => chain_len,
        ConstraintSource::Certificate(position) => position,
    };
    let Some(at) = rejection.at.map(position) else {
        // A whole-input rejection has no certificate position.
        return Ok(X509ChainError::UntrustedRoot);
    };
    Ok(match rejection.reason {
        RejectionReason::EmptyPath | RejectionReason::AnchorIncluded => {
            X509ChainError::UntrustedRoot
        }
        RejectionReason::Validity => X509ChainError::CertificateNotValid(at),
        RejectionReason::NotAuthority | RejectionReason::EmptyAuthorityName => {
            X509ChainError::IssuerNotCa(at)
        }
        RejectionReason::KeyCertSign => X509ChainError::InvalidKeyUsage {
            position: at,
            required: "keyCertSign",
        },
        RejectionReason::PathLength { source, limit } => X509ChainError::PathLengthExceeded {
            position: position(source),
            limit,
        },
        RejectionReason::NameConstraints { source, .. } => {
            X509ChainError::NameConstraintViolation {
                position: at,
                constraining_position: position(source),
            }
        }
        RejectionReason::NameConstraintsOnNonAuthority => {
            X509ChainError::InvalidNameConstraints { position: at }
        }
        RejectionReason::CriticalExtension(oid) => X509ChainError::UnsupportedCriticalExtension {
            position: at,
            oid: critical_extension_text(oid, session)?,
        },
        RejectionReason::MalformedExtension { extension, .. }
            if extension == structured_pkix::oid::NAME_CONSTRAINTS =>
        {
            X509ChainError::InvalidNameConstraints { position: at }
        }
        RejectionReason::MalformedExtension {
            code,
            field,
            offset,
            ..
        } => X509ChainError::Processing(structured_pkix::Error::new(code, field, offset)),
        RejectionReason::Policies => X509ChainError::CertificatePolicies,
        RejectionReason::Issuer | RejectionReason::Signature => {
            X509ChainError::InvalidSignature(at)
        }
        RejectionReason::UnsupportedSignature => X509ChainError::UnsupportedSignature(at),
        RejectionReason::DuplicateCertificate { .. } => X509ChainError::InvalidDer {
            kind: "certificate path",
            message: "repeated certificate".into(),
        },
        _ => X509ChainError::InvalidDer {
            kind: "certificate path",
            message: "unhandled static path rejection".into(),
        },
    })
}

fn critical_extension_text(
    oid: structured_asn1::Oid<'_>,
    session: &CertificateSession,
) -> Result<String, X509ChainError> {
    let resource_error = |reason| {
        X509ChainError::Processing(structured_pkix::Error::resource(
            reason,
            "certificate.extensions",
            0,
        ))
    };
    let text = oid.text(session.memory()).map_err(resource_error)?;
    Ok(text
        .as_str(session.memory())
        .map_err(resource_error)?
        .to_owned())
}

fn materialize_effective_spki<W: Work>(
    key: structured_pkix::path::WorkingKey<'_>,
    execution: &W,
) -> Result<OwnedVec<u8>, X509ChainError> {
    use structured_pkix::key::effective::{EffectiveSpki, VisitError};

    // RFC 3279 2.3.2: inheritance cannot repair written DSA NULL. Framing
    // proves no algorithm-specific validity, so inspect the original key first.
    // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
    let own = key.key().algorithm();
    let effective = EffectiveSpki::read(key, execution).map_err(X509ChainError::Processing)?;
    let source = effective.execution_in(execution);
    if own.has_null_parameter() {
        source
            .charge_work(own.algorithm().as_bytes().len() as u64)
            .map_err(|reason| {
                X509ChainError::Processing(structured_pkix::Error::resource(
                    reason,
                    "issuer.public_key",
                    own.offset(),
                ))
            })?;
        if own.algorithm().as_bytes() == dsa::OID.as_bytes() {
            structured_pkix::key::dsa::read(key, execution).map_err(X509ChainError::Processing)?;
        }
    }

    let resource = |reason| {
        X509ChainError::Processing(structured_pkix::Error::resource(
            reason,
            "issuer.public_key",
            own.offset(),
        ))
    };
    let length = usize::try_from(effective.encoded_len())
        .map_err(|_| resource(MemoryError::CapacityOverflow))?;
    let mut bytes = source.vector();
    bytes.try_reserve_exact(length).map_err(resource)?;
    let mut output = Some(bytes.into_owned());
    effective
        .visit(execution, |_, chunk, work| {
            // Transfer the same allocation into each part's original/current
            // execution. OwnedVec pays for the copy once, without losing the
            // independent inherited-parameter source ceiling or reallocating.
            let mut bytes = output
                .take()
                .expect("previous part completed")
                .with_execution(work)
                .expect("EffectiveSpki parts use the current allocation account");
            bytes.try_extend_from_slice(chunk)?;
            output = Some(bytes.into_owned());
            Ok::<_, MemoryError>(())
        })
        .map_err(|error| match error {
            VisitError::Processing { source, .. } => X509ChainError::Processing(source),
            VisitError::Callback {
                context, source, ..
            } => X509ChainError::Processing(structured_pkix::Error::resource(
                source,
                "issuer.public_key",
                context.start,
            )),
        })?;
    Ok(output.expect("all parts completed"))
}

fn with_effective_spki<T, W: Work>(
    key: structured_pkix::path::WorkingKey<'_>,
    execution: &W,
    verify: impl FnOnce(&[u8]) -> Result<T, X509ChainError>,
) -> Result<T, X509ChainError> {
    let original = key.key();
    if key.parameters().is_none() || !original.algorithm().has_no_parameters() {
        return verify(original.as_bytes());
    }
    let effective = materialize_effective_spki(key, execution)?;
    verify(&effective)
}

/// An authenticated path may supply parameters absent from the target SPKI.
/// Retaining the owned projection also retains its execution-account charge.
#[derive(Debug)]
pub(crate) struct ValidatedX509Key {
    pub(crate) effective_spki: Option<OwnedVec<u8>>,
}

pub(crate) fn effective_target_spki(
    key: structured_pkix::path::WorkingKey<'_>,
    execution: &Memory,
) -> Result<ValidatedX509Key, X509ChainError> {
    let original = key.key();
    if !original.algorithm().has_no_parameters() {
        return Ok(ValidatedX509Key {
            effective_spki: None,
        });
    }
    match key.parameters() {
        Some(_) => materialize_effective_spki(key, execution).map(|spki| ValidatedX509Key {
            effective_spki: Some(spki),
        }),
        None => Ok(ValidatedX509Key {
            effective_spki: None,
        }),
    }
}

/// Certificate signatures use the same selected engine and permissions as CRLs.
#[derive(Clone, Copy)]
pub(crate) struct ProviderVerifier<'a> {
    pub(crate) provider: &'a dyn crate::provider::CryptoProvider,
    pub(crate) allowed: Option<&'a crate::policy::CertificateSignatureAlgorithms>,
}

impl<W: Work> structured_pkix::path::Verify<W> for ProviderVerifier<'_> {
    type Error = X509ChainError;

    fn verify(
        &self,
        algorithm: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        execution: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        self.verify_with_key_check(algorithm, key, signed, signature, execution, |_| Ok(()))
    }
}

impl ProviderVerifier<'_> {
    fn verify_with_key_check<W: Work>(
        &self,
        algorithm: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        execution: &W,
        check: impl FnOnce(&[u8]) -> Result<(), X509ChainError>,
    ) -> Result<structured_pkix::path::Verified, X509ChainError> {
        let key_algorithm = key.key().algorithm();
        let parameters = key.parameters();
        execution
            .charge_work(
                algorithm.as_bytes().len() as u64
                    + key_algorithm.algorithm().as_bytes().len() as u64
                    + parameters.map_or(0, |bytes| bytes.len() as u64),
            )
            .map_err(|reason| {
                X509ChainError::Processing(structured_pkix::Error::resource(
                    reason,
                    "certificate.signature",
                    0,
                ))
            })?;
        let original_signature = signature;
        let signature = signature
            .octets()
            .ok_or_else(|| X509ChainError::InvalidDer {
                kind: "certificate signature",
                message: "signature is not octet-aligned".into(),
            })?;
        // Permission and capability checks precede inherited-key allocation.
        let algorithm = signature_algorithm(*algorithm, execution)?;
        crate::policy::KeyTrustPolicy::check_certificate_signature_algorithm(
            algorithm,
            self.allowed,
        )?;
        self.provider.require_capability(
            crate::provider::ProviderCapability::VerifyCertificate(algorithm),
        )?;
        if matches!(
            algorithm,
            crate::provider::X509SignatureAlgorithm::Dsa(_)
                | crate::provider::X509SignatureAlgorithm::Ecdsa(_)
        ) {
            // RFC 3279 §2.2: decode at the original signature offset/depth,
            // funded by the same source and current operation as the key.
            // https://www.rfc-editor.org/rfc/rfc3279#section-2.2
            let mut reader = original_signature
                .reader_in(execution)
                .map_err(X509ChainError::Processing)?;
            structured_pkix::signature::DssValue::read(&mut reader, "certificate.signature")
                .map_err(X509ChainError::Processing)?;
        }
        if matches!(algorithm, crate::provider::X509SignatureAlgorithm::Dsa(_))
            && key_algorithm.algorithm().as_bytes() == dsa::OID.as_bytes()
            && parameters.is_none()
        {
            // RFC 5280 6.1.4(e) needs the prospective path's working parameters.
            // An isolated discovery edge cannot prove rejection from their absence.
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
            return Ok(structured_pkix::path::Verified::Unsupported);
        }
        let verify = |spki: &[u8]| {
            check(spki)?;
            self.provider
                .verify_x509_signature(algorithm, signed, signature, spki)
                .map_err(X509ChainError::from)
        };
        // RFC 5280 6.1.4(e): inherit only the effective working-key parameters.
        // Shared framing retains source provenance; the provider buffer is paid.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
        let valid = with_effective_spki(key, execution, verify)?;
        Ok(if valid {
            structured_pkix::path::Verified::Yes
        } else {
            structured_pkix::path::Verified::No
        })
    }
}

/// Digests this crate implements, by their shared PKIX identity.
fn digest_algorithm(
    value: structured_pkix::algorithm::digest::Algorithm,
) -> Option<super::DigestAlgorithm> {
    use structured_pkix::algorithm::digest::Algorithm as Hash;
    Some(match value {
        Hash::Sha1 => super::DigestAlgorithm::Sha1,
        Hash::Sha224 => super::DigestAlgorithm::Sha224,
        Hash::Sha256 => super::DigestAlgorithm::Sha256,
        Hash::Sha384 => super::DigestAlgorithm::Sha384,
        Hash::Sha512 => super::DigestAlgorithm::Sha512,
        Hash::Sha3_224 => super::DigestAlgorithm::Sha3_224,
        Hash::Sha3_256 => super::DigestAlgorithm::Sha3_256,
        Hash::Sha3_384 => super::DigestAlgorithm::Sha3_384,
        Hash::Sha3_512 => super::DigestAlgorithm::Sha3_512,
        _ => return None,
    })
}

fn signature_algorithm<W: Work>(
    identifier: structured_pkix::algorithm::AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<crate::provider::X509SignatureAlgorithm, X509ChainError> {
    use crate::provider::X509SignatureAlgorithm as Signature;
    use structured_asn1::digest::Resolution;
    use structured_pkix::algorithm::{digest::Algorithm as Hash, signature::Algorithm};
    let unsupported = || {
        // Preserve branch-local discovery semantics for unknown identifiers.
        // PKIX has already validated the OID's original encoding; its dotted
        // text is rendered under the current operation's account.
        let memory = execution.memory();
        let resource = |reason| {
            X509ChainError::Processing(structured_pkix::Error::resource(
                reason,
                "certificate.signature",
                identifier.offset(),
            ))
        };
        match identifier.algorithm().text(memory) {
            Ok(text) => match text.as_str(memory) {
                Ok(oid) => X509ChainError::UnsupportedSignatureAlgorithm {
                    oid: oid.to_owned(),
                },
                Err(reason) => resource(reason),
            },
            Err(reason) => resource(reason),
        }
    };
    let hash = |value: Hash| digest_algorithm(value).ok_or_else(unsupported);
    // Shared PKIX owns ASN.1 signature syntax and parameters, retaining the
    // original reader/depth and both source and current Work. The XML adapter
    // maps only provider capability; it never encodes/reparses the identifier.
    structured_pkix::algorithm::signature::with_algorithm(identifier, execution, |value| {
        Ok(match value {
            Some(Algorithm::RsaPkcs1v15(value)) => Signature::RsaPkcs1v15(hash(value)?),
            Some(Algorithm::Dsa(value)) => Signature::Dsa(hash(value)?),
            Some(Algorithm::Ecdsa(value)) => Signature::Ecdsa(hash(value)?),
            Some(Algorithm::Ed25519) => Signature::Ed25519,
            Some(Algorithm::Ed448) => Signature::Ed448,
            Some(Algorithm::MlDsa(set)) => Signature::PostQuantum(match set {
                structured_pkix::algorithm::ml_dsa::ParameterSet::MlDsa44 => {
                    super::PqAlgorithm::MlDsa44
                }
                structured_pkix::algorithm::ml_dsa::ParameterSet::MlDsa65 => {
                    super::PqAlgorithm::MlDsa65
                }
                structured_pkix::algorithm::ml_dsa::ParameterSet::MlDsa87 => {
                    super::PqAlgorithm::MlDsa87
                }
            }),
            Some(Algorithm::RsaPss(parameters)) => {
                let profile = match parameters
                    .profile(execution)
                    .map_err(X509ChainError::Processing)?
                {
                    Resolution::Supported(profile) => profile,
                    Resolution::Unsupported | Resolution::Malformed => return Err(unsupported()),
                };
                let salt_len = profile
                    .salt()
                    .as_u64()
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(unsupported)?;
                Signature::RsaPss {
                    digest: hash(profile.hash())?,
                    mgf_digest: hash(profile.mask_hash())?,
                    salt_len,
                }
            }
            None => {
                // Explicit existing compatibility capabilities outside the
                // shared resolver's documented set, not an engine fallback.
                let oid = identifier.algorithm().as_bytes();
                let parameters = identifier.parameters();
                match oid {
                    [0x2b, 0x0e, 0x03, 0x02, 0x1d]
                        if parameters.is_none() || identifier.has_null_parameter() =>
                    {
                        Signature::RsaPkcs1v15(super::DigestAlgorithm::Sha1)
                    }
                    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03]
                        if parameters.is_none() =>
                    {
                        Signature::Dsa(super::DigestAlgorithm::Sha384)
                    }
                    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04]
                        if parameters.is_none() =>
                    {
                        Signature::Dsa(super::DigestAlgorithm::Sha512)
                    }
                    _ if parameters.is_none() => Signature::PostQuantum(
                        super::PqAlgorithm::ALL
                            .into_iter()
                            .find(|value| {
                                der::asn1::ObjectIdentifier::new_unwrap(value.oid()).as_bytes()
                                    == oid
                            })
                            .ok_or_else(unsupported)?,
                    ),
                    _ => return Err(unsupported()),
                }
            }
            _ => return Err(unsupported()),
        })
    })
    .map_err(X509ChainError::Processing)?
}

/// Certificate-path signature checks through the selected provider, under the
/// operation's certificate-signature permissions and issuer key-strength policy.
/// It verifies only keys of the supplied chain or anchor; any other key is a
/// processing error, so a discovery edge cannot borrow this permission.
pub struct CertificatePathVerifier<'a, 'p> {
    signatures: ProviderVerifier<'p>,
    chain: &'p [&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    rsa_keys: crate::policy::RsaKeyPolicy,
    dsa_keys: crate::policy::DsaKeyPolicy,
}

impl<'a, 'p> CertificatePathVerifier<'a, 'p> {
    pub(crate) fn new(
        provider: &'p dyn crate::provider::CryptoProvider,
        trust: &'p crate::policy::KeyTrustPolicy,
        chain: &'p [&'a Certificate<'a>],
        anchor: &'a Certificate<'a>,
    ) -> Self {
        Self {
            signatures: ProviderVerifier {
                provider,
                allowed: trust.certificate_signature_algorithms.as_ref(),
            },
            chain,
            anchor,
            rsa_keys: trust.rsa_keys,
            dsa_keys: trust.dsa_keys,
        }
    }
}

impl<W: Work> structured_pkix::path::Verify<W> for CertificatePathVerifier<'_, '_> {
    type Error = X509ChainError;

    fn verify(
        &self,
        algorithm: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        execution: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        let raw = key.key().as_bytes();
        execution
            .charge_work(self.chain.len() as u64)
            .map_err(|reason| {
                X509ChainError::Processing(structured_pkix::Error::resource(
                    reason,
                    "issuer.public_key",
                    0,
                ))
            })?;
        let position = if std::ptr::eq(raw, self.anchor.tbs().public_key().as_bytes()) {
            self.chain.len()
        } else {
            self.chain
                .iter()
                .position(|certificate| {
                    std::ptr::eq(raw, certificate.tbs().public_key().as_bytes())
                })
                .ok_or_else(|| X509ChainError::InvalidDer {
                    kind: "issuer public key",
                    message: "key outside supplied path".into(),
                })?
        };
        self.signatures.verify_with_key_check(
            algorithm,
            key,
            signed,
            signature,
            execution,
            |effective| {
                super::x509::validate_issuer_spki_policy(
                    effective,
                    position,
                    self.rsa_keys,
                    self.dsa_keys,
                )
            },
        )
    }
}

/// Key family of a standalone `SubjectPublicKeyInfo` algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpkiAlgorithm {
    RsaEncryption,
    RsaPss,
    Dsa,
    Ec,
    Ed25519,
    Ed448,
    PostQuantum(super::PqAlgorithm),
    Other,
}

/// Structure of an RSA or EC public key, borrowed from its SPKI encoding.
pub(crate) enum PublicKey<'a> {
    Rsa(structured_pkix::key::rsa::PublicKey<'a>),
    Ec(structured_pkix::key::ec::PublicKey<'a>),
}

/// A single account covers all candidates, nested decodes and retries.
#[derive(Debug)]
pub(crate) struct CertificateSession {
    parser: Parser,
    work_limit: usize,
    memory_limit: usize,
}

impl CertificateSession {
    pub(crate) fn new(resources: &ResourcePolicy) -> Self {
        let work_limit = resources
            .max_x509_work
            .min(crate::hard_limits::X509_WORK_CEILING);
        let memory_limit = resources
            .max_x509_workspace_bytes
            .min(crate::hard_limits::X509_WORKSPACE_BYTE_CEILING);
        let memory = Memory::new(Arc::new(MemoryAccount::new(memory_limit, work_limit)));
        Self::with_account(work_limit, memory_limit, memory)
    }

    /// The bounded parser, keeping its fresh policy-limited account.
    pub(crate) fn into_parser(self) -> Parser {
        self.parser
    }

    pub(crate) fn share(&self) -> Self {
        Self::with_account(self.work_limit, self.memory_limit, self.memory().clone())
    }

    fn with_account(work_limit: usize, memory_limit: usize, memory: Memory) -> Self {
        Self {
            parser: Parser::new(
                Encoding::Der,
                Limits {
                    max_depth: crate::hard_limits::ASN1_DEPTH_CEILING,
                    max_elements: work_limit as u64,
                    // This reader borrows contents; admission limits belong
                    // to each source boundary. Work and allocated capacity
                    // remain bounded even for caller-owned certificate bytes.
                    max_element_length: u64::MAX,
                    max_work: work_limit as u64,
                },
                memory,
            ),
            work_limit,
            memory_limit,
        }
    }

    pub(crate) fn require_resources(
        &self,
        resources: &ResourcePolicy,
    ) -> Result<(), PolicyViolation> {
        if self.work_limit != resources.max_x509_work
            || self.memory_limit != resources.max_x509_workspace_bytes
        {
            return Err(PolicyViolation::KeyTrust {
                reason: "certificate accounting must retain one immutable resource policy",
            });
        }
        Ok(())
    }

    pub(crate) fn memory(&self) -> &Memory {
        self.parser.memory()
    }

    pub(crate) fn read<'a>(&'a self, bytes: &'a [u8]) -> Result<Certificate<'a>, X509ChainError> {
        Certificate::read(&self.parser, bytes, 0).map_err(|error| self.error(error))
    }

    /// Structural RSA or EC public key of a standalone SPKI, read with this
    /// session's work.
    pub(crate) fn read_public_key<'a>(
        &'a self,
        spki: &'a [u8],
    ) -> Result<PublicKey<'a>, structured_pkix::Error> {
        use structured_pkix::key::{ec, rsa};
        self.with_public_key_info(spki, |info, execution| {
            // Each reader repeats the algorithm check, paid; this only dispatches.
            if info.algorithm().algorithm() == structured_pkix::oid::EC_PUBLIC_KEY {
                ec::read(structured_pkix::path::WorkingKey::standing(info), execution)
                    .map(PublicKey::Ec)
            } else {
                rsa::read(info, execution).map(PublicKey::Rsa)
            }
        })
    }

    pub(crate) fn read_dsa_public_key<'a>(
        &'a self,
        spki: &'a [u8],
    ) -> Result<structured_pkix::key::dsa::PublicKey<'a>, structured_pkix::Error> {
        self.with_public_key_info(spki, |info, execution| {
            structured_pkix::key::dsa::read(
                structured_pkix::path::WorkingKey::standing(info),
                execution,
            )
        })
    }

    /// RSA key of a standalone SPKI whose algorithm admits the signature
    /// scheme: PKCS#1 v1.5 when `pss` is `None`, otherwise RSASSA-PSS with
    /// `pss`. `None` is a non-matching or malformed key.
    ///
    /// `rsaEncryption` keys (NULL or absent parameters, as RFC 3279 2.3.1
    /// readers accept) admit both schemes. RFC 4055 section 3.3: an
    /// `id-RSASSA-PSS` key admits only PSS; its parameters, when present, fix
    /// both digests and the trailer and set a minimum salt. Readable written
    /// DEFAULT fields are recognized as RFC 4055 section 3.1 requires.
    /// <https://www.rfc-editor.org/rfc/rfc4055.html#section-3.3>
    pub(crate) fn rsa_public_key<'a>(
        &'a self,
        spki: &'a [u8],
        pss: Option<super::RsaPssParameters>,
    ) -> Option<structured_pkix::key::rsa::PublicKey<'a>> {
        use structured_asn1::digest::Resolution;
        self.admitted_rsa_public_key(spki, |identifier, execution| {
            let algorithm = identifier.algorithm();
            if algorithm == structured_pkix::oid::RSA_ENCRYPTION {
                return Ok(identifier.has_null_parameter() || identifier.has_no_parameters());
            }
            let Some(signature) = pss else {
                return Ok(false);
            };
            if algorithm != structured_pkix::oid::RSASSA_PSS {
                return Ok(false);
            }
            let Some(reading) = structured_pkix::algorithm::pss::inspect(identifier, execution)?
            else {
                return Ok(true);
            };
            let Resolution::Supported(profile) = reading.parameters().profile(execution)? else {
                return Ok(false);
            };
            let minimum_salt = profile
                .salt()
                .as_u64()
                .and_then(|value| usize::try_from(value).ok());
            Ok(digest_algorithm(profile.hash()) == Some(signature.digest)
                && digest_algorithm(profile.mask_hash()) == Some(signature.mgf_digest)
                && minimum_salt.is_some_and(|minimum| signature.salt_len >= minimum))
        })
    }

    /// RFC 8410 raw public key of a standalone SPKI, or `None` for another
    /// algorithm, present parameters or a wrong key width.
    pub(crate) fn rfc8410_public_key<'a>(
        &'a self,
        spki: &'a [u8],
    ) -> Option<structured_pkix::key::rfc8410::PublicKey<'a>> {
        self.with_public_key_info(spki, |info, execution| {
            structured_pkix::key::rfc8410::read(info, execution)
        })
        .ok()
    }

    /// Key family named by a standalone SPKI's algorithm identifier.
    ///
    /// # Errors
    /// The shared reader's refusal, keeping resource exhaustion distinct.
    pub(crate) fn spki_algorithm(
        &self,
        spki: &[u8],
    ) -> Result<SpkiAlgorithm, structured_pkix::Error> {
        self.with_public_key_info(spki, |info, _| {
            let algorithm = info.algorithm().algorithm();
            Ok(if algorithm == structured_pkix::oid::RSA_ENCRYPTION {
                SpkiAlgorithm::RsaEncryption
            } else if algorithm == structured_pkix::oid::RSASSA_PSS {
                SpkiAlgorithm::RsaPss
            } else if algorithm == structured_pkix::oid::EC_PUBLIC_KEY {
                SpkiAlgorithm::Ec
            } else if algorithm.as_bytes() == dsa::OID.as_bytes() {
                SpkiAlgorithm::Dsa
            } else if algorithm == structured_pkix::oid::ED25519 {
                SpkiAlgorithm::Ed25519
            } else if algorithm == structured_pkix::oid::ED448 {
                SpkiAlgorithm::Ed448
            } else if let Some(parameter) = super::PqAlgorithm::from_oid(algorithm.as_bytes()) {
                SpkiAlgorithm::PostQuantum(parameter)
            } else {
                SpkiAlgorithm::Other
            })
        })
    }

    /// Supported named curve and range of the SEC1 point inside a standalone
    /// EC SPKI; `None` for another key, curve choice or malformed encoding.
    pub(crate) fn ec_named_point(
        &self,
        spki: &[u8],
    ) -> Option<(super::signature::EcCurve, core::ops::Range<usize>)> {
        let PublicKey::Ec(key) = self.read_public_key(spki).ok()? else {
            return None;
        };
        let structured_pkix::key::ec::Curve::Named(curve) = key.curve() else {
            return None;
        };
        let curve = super::signature::EcCurve::from_oid_bytes(curve.as_bytes())?;
        // The SPKI is read at document offset zero, so source offsets index it.
        let start = usize::try_from(key.offset()).ok()?;
        Some((curve, start..start.checked_add(key.as_bytes().len())?))
    }

    /// RSA key of a standalone SPKI whose algorithm identifier `admit` accepts.
    /// `None` is a refused identifier or a malformed key.
    pub(crate) fn admitted_rsa_public_key<'a>(
        &'a self,
        spki: &'a [u8],
        admit: impl FnOnce(
            structured_pkix::AlgorithmIdentifier<'a>,
            &structured_asn1::memory::Execution<'_>,
        ) -> Result<bool, structured_pkix::Error>,
    ) -> Option<structured_pkix::key::rsa::PublicKey<'a>> {
        self.with_public_key_info(spki, |info, execution| {
            if !admit(info.algorithm(), execution)? {
                return Ok(None);
            }
            structured_pkix::key::rsa::read(info, execution).map(Some)
        })
        .ok()
        .flatten()
    }

    /// Reads exactly one standalone SPKI under this session's work and hands
    /// its borrowed structure to `inspect`.
    pub(crate) fn with_public_key_info<'a, T>(
        &'a self,
        spki: &'a [u8],
        inspect: impl FnOnce(
            structured_pkix::PublicKeyInfo<'a>,
            &structured_asn1::memory::Execution<'_>,
        ) -> Result<T, structured_pkix::Error>,
    ) -> Result<T, structured_pkix::Error> {
        use structured_pkix::key::PublicKeyInfo;
        use structured_pkix::{Error, ErrorCode};
        const FIELD: &str = "subjectPublicKeyInfo";
        let encoding = |error: structured_asn1::Error| {
            Error::new(ErrorCode::Encoding(error.code()), FIELD, error.offset())
        };
        let mut reader = self.parser.read(spki, 0).map_err(encoding)?;
        let element = reader
            .next_element()
            .map_err(encoding)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, 0))?;
        let info = PublicKeyInfo::read_element(&reader, &element, FIELD)?;
        // RFC 5280 4.1.2.7: the encoding is exactly one SubjectPublicKeyInfo.
        if !reader.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, FIELD, reader.offset()));
        }
        let execution = reader.execution();
        inspect(info, &execution)
    }

    pub(crate) fn read_crl<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> Result<structured_pkix::crl::CertificateList<'a>, X509ChainError> {
        structured_pkix::crl::CertificateList::read(&self.parser, bytes, 0)
            .map_err(|error| self.error(error))
    }

    /// A shared-reader failure under this session's limits, as a parse error.
    pub(crate) fn parse_failure(&self, error: structured_pkix::Error) -> super::ParseError {
        self.error(error).into()
    }

    #[cfg(test)]
    pub(crate) fn metadata(
        &self,
        bytes: &[u8],
    ) -> Result<super::parse::ParsedX509Certificate, X509ChainError> {
        let certificate = self.read(bytes)?;
        super::parse::certificate_metadata(&certificate, self).map_err(|error| match error {
            super::ParseError::Policy(error) => X509ChainError::Policy(error),
            super::ParseError::Certificate(error) => X509ChainError::Processing(error),
            error => X509ChainError::InvalidDer {
                kind: "certificate metadata",
                message: error.to_string(),
            },
        })
    }

    pub(crate) fn error(&self, error: structured_pkix::Error) -> X509ChainError {
        if error.is_resource() {
            use structured_asn1::{ErrorCode, Limit};
            let memory = matches!(
                error.code(),
                structured_pkix::ErrorCode::Encoding(
                    ErrorCode::LimitExceeded(Limit::Memory)
                        | ErrorCode::AllocatorExhausted
                        | ErrorCode::CapacityOverflow
                )
            );
            return PolicyViolation::ResourceLimitExceeded {
                resource: if memory {
                    resource_name::X509_WORKSPACE_BYTES
                } else {
                    resource_name::X509_WORK
                },
                maximum: if memory {
                    self.memory_limit
                } else {
                    self.work_limit
                },
            }
            .into();
        }
        X509ChainError::Processing(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use structured_pkix::path::{Verified, Verify as _, WorkingKey};

    fn dsa_projection_sources(written: Option<der::asn1::AnyRef<'_>>) -> (Vec<u8>, Vec<u8>) {
        use der::{Decode as _, Encode as _};
        let parameters = der::asn1::AnyRef::from_der(&[0x30, 9, 2, 1, 23, 2, 1, 11, 2, 1, 2])
            .expect("structural DSA parameters");
        let spki = |parameters| {
            pkcs8::SubjectPublicKeyInfoRef {
                algorithm: pkcs8::AlgorithmIdentifierRef {
                    oid: dsa::OID,
                    parameters,
                },
                subject_public_key: der::asn1::BitStringRef::new(0, &[2, 1, 1])
                    .expect("octet-aligned DSA public component"),
            }
            .to_der()
            .expect("test DSA SPKI encoding")
        };
        // A small structural certificate, not an authenticated path. Projecting
        // its WorkingKey tests framing/provenance, never signature acceptance.
        let algorithm = [0x30, 9, 6, 7, 0x2a, 0x86, 0x48, 0xce, 0x38, 4, 3];
        let mut tbs = vec![2, 1, 1];
        tbs.extend_from_slice(&algorithm);
        let name = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, b'x'];
        tbs.extend_from_slice(&name);
        tbs.extend_from_slice(b"\x30\x1e\x17\x0d250101000000Z\x17\x0d270101000000Z");
        tbs.extend_from_slice(&name);
        tbs.extend_from_slice(&spki(written));
        let mut certificate = vec![
            0x30,
            u8::try_from(tbs.len() + 2 + algorithm.len() + 4)
                .expect("test certificate fits short-form length"),
        ];
        certificate.extend_from_slice(&[
            0x30,
            u8::try_from(tbs.len()).expect("test TBS fits short-form length"),
        ]);
        certificate.extend_from_slice(&tbs);
        certificate.extend_from_slice(&algorithm);
        certificate.extend_from_slice(&[3, 2, 0, 0]);
        (spki(Some(parameters)), certificate)
    }

    fn projected_dsa<'a>(
        session: &'a CertificateSession,
        issuer: &'a [u8],
        subject: &'a Certificate<'a>,
    ) -> WorkingKey<'a> {
        session
            .with_public_key_info(issuer, |info, work| {
                WorkingKey::standing(info).subject(subject, work)
            })
            .expect("project original inherited DSA parameters")
    }

    #[test]
    fn shared_effective_spki_preserves_original_sources_and_retained_capacity() {
        // A projection is one accounted provider buffer, not a rewritten
        // certificate or a retained parser/operation borrow.
        let (issuer, certificate) = dsa_projection_sources(None);
        let original = certificate.clone();
        let session = CertificateSession::new(&ResourcePolicy::default());
        let subject = session.read(&certificate).expect("structural DSA subject");
        let key = projected_dsa(&session, &issuer, &subject);
        let before = session.memory().used();
        let result = materialize_effective_spki(key, session.memory())
            .expect("shared effective SPKI framing");
        assert_eq!(&*result, issuer);
        assert_eq!(certificate, original);
        assert_eq!(session.memory().used() - before, result.capacity());
        drop(result);
        assert_eq!(session.memory().used(), before);
    }

    #[test]
    fn shared_signature_resolution_preserves_current_work_and_parameters() {
        // Retained identifiers borrow their source provenance; a new query
        // cannot reset its own work ceiling or accept ECDSA NULL parameters.
        let session = CertificateSession::new(&ResourcePolicy::default());
        let bytes = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
        let mut reader = session
            .parser
            .read(bytes, 400)
            .expect("funded original reader");
        let element = reader
            .next_element()
            .expect("encoded sequence")
            .expect("one identifier");
        let identifier = structured_pkix::algorithm::read(&reader, &element, "signatureAlgorithm")
            .expect("valid ECDSA identifier");
        assert_eq!(
            signature_algorithm(identifier, session.memory()).expect("supported ECDSA signature"),
            crate::provider::X509SignatureAlgorithm::Ecdsa(super::super::DigestAlgorithm::Sha256)
        );
        let refused = Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 0),
        ));
        assert!(
            matches!(signature_algorithm(identifier, &refused), Err(X509ChainError::Processing(error)) if error.is_resource())
        );
        let bad = b"\x30\x0c\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x05\x00";
        let mut reader = session
            .parser
            .read(bad, 700)
            .expect("funded malformed-parameter source");
        let element = reader
            .next_element()
            .expect("encoded sequence")
            .expect("one bad identifier");
        let identifier = structured_pkix::algorithm::read(&reader, &element, "signatureAlgorithm")
            .expect("structurally valid identifier");
        assert!(
            matches!(signature_algorithm(identifier, session.memory()), Err(X509ChainError::Processing(error)) if !error.is_resource() && error.offset() >= 700)
        );
    }

    #[test]
    fn dsa_public_key_keeps_borrowed_components_and_absent_parameters() {
        // Structural inspection must not allocate bigints or invent parameters
        // for an isolated DSA key; the resolver requires the latter separately.
        let bytes =
            b"\x30\x12\x30\x09\x06\x07\x2a\x86\x48\xce\x38\x04\x01\x03\x05\x00\x02\x02\x00\x80";
        let session = CertificateSession::new(&ResourcePolicy::default());
        let key = session.read_dsa_public_key(bytes).expect("DSA structure");
        assert!(key.parameters().is_none());
        assert_eq!(key.y().as_bytes(), [0x80]);
        assert_eq!(key.y().integer().as_bytes(), [0, 0x80]);
        assert_eq!(key.y().as_bytes().as_ptr(), bytes[19..].as_ptr());
    }

    #[test]
    fn algorithm_inspection_faults_never_become_strict_crypto_identifiers() {
        // The released inspection API preserves diagnostic bytes and offsets;
        // our Certificate/CRL crypto path must still require strict identifiers.
        let session = CertificateSession::new(&ResourcePolicy::default());
        let bytes = [0x30, 0x05, 0x06, 0x01, 0x2a, 0x25, 0x00];
        let mut reader = session
            .parser
            .read(&bytes, 500)
            .expect("funded source reader");
        let element = reader
            .next_element()
            .expect("structural sequence")
            .expect("one algorithm element");
        let reading = structured_pkix::algorithm::read_inspection(&reader, &element, "algorithm")
            .expect("recoverable parameter fault");
        assert!(reading.fault().is_some());
        assert!(reading.identifier().is_none());
        assert_eq!(reading.parameters(), Some(&bytes[5..]));
        assert_eq!(
            reading
                .parameters_span()
                .expect("original parameter range")
                .start,
            505
        );
        assert!(std::ptr::eq(reading.as_bytes().as_ptr(), bytes.as_ptr()));
        assert!(structured_pkix::algorithm::read(&reader, &element, "algorithm").is_err());
    }

    #[test]
    fn shared_general_name_queries_keep_semantics_and_work_limits() {
        // GeneralName equality is not raw text equality or mailbox local-part folding.
        use structured_pkix::general_name::{self, GeneralName};
        let session = CertificateSession::new(&ResourcePolicy::default());
        for (left, right, expected) in [
            (
                GeneralName::Dns("EXAMPLE.test"),
                GeneralName::Dns("example.TEST"),
                true,
            ),
            (
                GeneralName::Email("User@example.test"),
                GeneralName::Email("user@example.test"),
                false,
            ),
            (
                GeneralName::Uri("HTTP://Example.test:80/a/../%7e"),
                GeneralName::Uri("http://example.test/~"),
                true,
            ),
        ] {
            assert_eq!(
                left.matches(&right, session.memory())
                    .expect("funded GeneralName comparison"),
                expected
            );
        }
        let resources = ResourcePolicy {
            max_x509_work: 1,
            ..Default::default()
        };
        let limited = CertificateSession::new(&resources);
        let reader = limited
            .parser
            .read(&[], 500)
            .expect("empty producing reader");
        let error = general_name::matches(
            &reader,
            &GeneralName::Dns("example.test"),
            &GeneralName::Dns("EXAMPLE.test"),
            777,
            "certificate.generalName",
        )
        .expect_err("GeneralName work must be denied");
        assert!(error.is_resource());
        assert_eq!(error.offset(), 777);
        assert!(matches!(limited.error(error), X509ChainError::Policy(_)));
    }

    #[test]
    fn xml_name_adapter_preserves_escaped_delimiters_and_spaces() {
        // XML formatting tolerance must not erase escaped DN value bytes.
        let session = CertificateSession::new(&ResourcePolicy::default());
        for (input, expected) in [
            ("CN=Alice,O=Example", "CN=Alice,O=Example"),
            (" \tCN=Alice ,\n O=Example\r ", "CN=Alice,O=Example"),
            (
                r"CN=Alice\,Bob + OU=Ops\+Dev , O=Example",
                r"CN=Alice\,Bob+OU=Ops\+Dev,O=Example",
            ),
            (r"CN= Alice\ , O=Example", r"CN=\ Alice\ ,O=Example"),
            ("CN=Ștefan, O=Exemplu", "CN=Ștefan,O=Exemplu"),
        ] {
            let adapted = xml_name_text(input, session.memory()).expect("lexical adaptation");
            assert_eq!(
                adapted.text(session.memory()).expect("funded text"),
                expected
            );
            let _ = session.selector(input).expect("strict shared selector");
        }
        let canonical =
            xml_name_text("CN=Alice,O=Example", session.memory()).expect("canonical text");
        assert!(matches!(canonical, XmlNameText::Borrowed(_)));
        assert_eq!(session.memory().used(), 0);
    }

    #[test]
    fn xml_name_adapter_reserves_before_rewriting() {
        // Input scans and any rewritten storage belong to the operation account.
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        assert!(xml_name_text("CN=Alice", &memory).is_err());
        assert_eq!(memory.work_used(), 0);
        assert_eq!(memory.used(), 0);
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        assert!(xml_name_text(" CN=Alice ", &memory).is_err());
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn xml_name_selector_preserves_pseudonym_case_exact_semantics() {
        // RFC 2985 5.2.9 assigns caseExactMatch, not caseIgnoreMatch.
        // https://www.rfc-editor.org/rfc/rfc2985.html#section-5.2.9
        let session = CertificateSession::new(&ResourcePolicy::default());
        assert!(
            !session
                .names_equal("pseudonym=Alice", "pseudonym=alice")
                .expect("supported pseudonym")
        );
        assert!(
            !session
                .names_equal("pseudonym=Straße", "pseudonym=STRASSE")
                .expect("supported Unicode pseudonym")
        );
        assert!(
            session
                .names_equal(r" pseudonym=\ Alice\  ", "pseudonym=Alice")
                .expect("insignificant space preparation")
        );
        let bytes = [
            0x30, 16, 0x31, 14, 0x30, 12, 6, 3, 0x55, 4, 65, 12, 5, b'A', b'l', b'i', b'c', b'e',
        ];
        let name = session.read_name(&bytes).expect("borrowed pseudonym Name");
        assert!(
            session
                .selector("pseudonym=Alice")
                .expect("same selector")
                .matches_name(&name, session.memory())
                .expect("same comparison")
        );
        assert!(
            !session
                .selector("pseudonym=alice")
                .expect("different selector")
                .matches_name(&name, session.memory())
                .expect("different comparison")
        );
    }

    #[test]
    fn name_wire_rendering_preserves_invalid_text_without_accepting_it_as_text() {
        // RFC 4514 2.4's #BER form preserves an AttributeValue encoding;
        // retaining bytes must not silently turn invalid UTF-8 into readable text.
        // https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4
        let session = CertificateSession::new(&ResourcePolicy::default());
        let bytes = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, 0xff];
        let name = session.read_name(&bytes).expect("wire Name");
        let text = name
            .rfc4514(session.memory())
            .expect("lossless wire rendering");
        assert_eq!(
            text.as_str(session.memory()).expect("rendered text"),
            "CN=#0C01FF"
        );
        let selector = session.selector("CN=#0C01FF").expect("opaque selector");
        assert!(
            selector
                .matches_name(&name, session.memory())
                .expect("opaque wire identity")
        );
    }

    #[test]
    fn inherited_parameters_do_not_repair_written_dsa_null() {
        // RFC 3279 2.3.2 permits omission, not a NULL Dss-Parms value.
        // A synthesized provider key must not hide that original spelling.
        // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
        let (issuer, certificate) = dsa_projection_sources(Some(der::asn1::AnyRef::NULL));
        let session = CertificateSession::new(&ResourcePolicy::default());
        let subject = session
            .read(&certificate)
            .expect("retain written NULL for inspection");
        let key = projected_dsa(&session, &issuer, &subject);
        let before = session.memory().used();
        let called = std::cell::Cell::new(false);
        let result = with_effective_spki(key, session.memory(), |_| {
            called.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(X509ChainError::Processing(error))
            if !error.is_resource() && error.offset() > key.key().algorithm().offset()));
        assert!(!called.get());
        assert_eq!(session.memory().used(), before);
    }

    #[test]
    fn inherited_issuer_parameters_are_provided_without_changing_source() {
        // RFC 5280 6.1.4(e) supplies inherited parameters to the working key only.
        use der::{Decode as _, Encode as _};
        let y = [2, 1, 1];
        let parameters = [0x30, 9, 2, 1, 23, 2, 1, 11, 2, 1, 2];
        {
            let (issuer, certificate) = dsa_projection_sources(None);
            let source = certificate.clone();
            let session = CertificateSession::new(&ResourcePolicy::default());
            let subject = session
                .read(&certificate)
                .expect("DSA parameter-less subject");
            let key = projected_dsa(&session, &issuer, &subject);
            let before = session.memory().used();
            with_effective_spki(key, session.memory(), |effective| {
                let parsed =
                    pkcs8::SubjectPublicKeyInfoRef::from_der(effective).expect("effective SPKI");
                assert_eq!(
                    parsed
                        .algorithm
                        .parameters
                        .expect("inherited params")
                        .to_der()
                        .expect("DER"),
                    parameters
                );
                assert_eq!(parsed.subject_public_key.raw_bytes(), y);
                assert!(session.memory().used() >= effective.len());
                Ok(())
            })
            .expect("inherited key is supported");
            assert_eq!(certificate, source);
            assert_eq!(session.memory().used(), before);
        }
    }

    #[test]
    fn inherited_key_workspace_is_reserved_before_provider_execution() {
        // No cryptographic callback runs when the effective-key allocation is refused.
        let (issuer, certificate) = dsa_projection_sources(None);
        let session = CertificateSession::new(&ResourcePolicy::default());
        let subject = session
            .read(&certificate)
            .expect("funded source certificate");
        let key = projected_dsa(&session, &issuer, &subject);
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
        let called = std::cell::Cell::new(false);
        let result = with_effective_spki(key, &current, |_| {
            called.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(X509ChainError::Processing(error)) if error.is_resource()));
        assert!(!called.get());
        assert_eq!(current.used(), 0);
    }

    #[test]
    fn standalone_issuer_key_borrows_original_without_workspace() {
        // The ordinary path requires no normalization buffer or key copy.
        use der::Encode as _;
        let key = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: dsa::OID,
                parameters: None,
            },
            subject_public_key: der::asn1::BitStringRef::new(0, &[2, 1, 1]).expect("public bits"),
        }
        .to_der()
        .expect("SPKI encoding");
        let session = CertificateSession::new(&ResourcePolicy::default());
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        session
            .with_public_key_info(&key, |info, _| {
                with_effective_spki(WorkingKey::standing(info), &current, |effective| {
                    assert_eq!(effective.as_ptr(), key.as_ptr());
                    assert_eq!(effective.len(), key.len());
                    Ok(())
                })
                .expect("ordinary key borrows original DER");
                Ok(())
            })
            .expect("read the original standalone SPKI");
        assert_eq!(current.used(), 0);
        assert_eq!(current.work_used(), 0);
    }

    #[test]
    fn effective_spki_obeys_exact_current_work_and_releases_failed_output() {
        // A retained foreign key must not substitute Memory for the current
        // local ceiling. Refusal after partial copying releases all capacity.
        let (issuer, certificate) = dsa_projection_sources(None);
        let session = CertificateSession::new(&ResourcePolicy::default());
        let subject = session.read(&certificate).expect("funded original subject");
        let key = projected_dsa(&session, &issuer, &subject);
        let measured = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
        let measuring_parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 100_000,
                ..Limits::default()
            },
            measured.clone(),
        );
        let measuring_reader = measuring_parser
            .read(&[], 0)
            .expect("measurement execution");
        let measuring_work = measuring_reader.execution();
        drop(
            materialize_effective_spki(key, &measuring_work).expect("measure complete projection"),
        );
        let aggregate_required = measured.work_used();
        let local_required = 100_000 - measuring_work.work_remaining();
        assert!(aggregate_required > issuer.len());
        for local in [false, true] {
            let required = if local {
                local_required
            } else {
                aggregate_required
            };
            for limit in [0, required - 1, required] {
                let current = Memory::new(Arc::new(MemoryAccount::new(
                    4096,
                    if local { 100_000 } else { limit },
                )));
                let parser = Parser::new(
                    Encoding::Der,
                    Limits {
                        max_work: if local { limit as u64 } else { 100_000 },
                        ..Limits::default()
                    },
                    current.clone(),
                );
                let reader = parser.read(&[], 0).expect("bounded current execution");
                let called = std::cell::Cell::new(false);
                let result = with_effective_spki(key, &reader.execution(), |bytes| {
                    called.set(true);
                    assert_eq!(bytes, issuer);
                    Ok(())
                });
                if limit == required {
                    result
                        .unwrap_or_else(|error| panic!("local={local}, limit={limit}: {error:?}"));
                    assert!(called.get());
                    assert_eq!(current.work_used(), aggregate_required);
                } else {
                    assert!(
                        matches!(result, Err(X509ChainError::Processing(error)) if error.is_resource())
                    );
                    assert!(!called.get());
                }
                assert_eq!(current.used(), 0);
            }
        }
    }

    #[test]
    fn effective_spki_cannot_reset_its_original_source_ceiling() {
        // A fresh current account cannot buy back the retained key parser's
        // spent local work, and no provider/output allocation may run first.
        let (issuer, certificate) = dsa_projection_sources(None);
        let session = CertificateSession::new(&ResourcePolicy::default());
        let subject = session
            .read(&certificate)
            .expect("original source certificate");
        let key = projected_dsa(&session, &issuer, &subject);
        let source_reader = session
            .parser
            .read(&[], 0)
            .expect("original source execution");
        let source_work = source_reader.execution();
        source_work
            .charge_work(source_work.work_remaining() as u64)
            .expect("exhaust the original ceiling exactly");
        let current = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
        let called = std::cell::Cell::new(false);
        let result = with_effective_spki(key, &current, |_| {
            called.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(X509ChainError::Processing(error)) if error.is_resource()));
        assert!(!called.get());
        assert_eq!(current.used(), 0);
        assert_eq!(current.work_used(), 0);
    }

    #[test]
    fn inherited_parameter_copy_keeps_its_independent_source_ceiling() {
        // Parameter bytes belong to the issuer's parser, not the subject's.
        // Leave only metadata admission: the subsequent copy must refuse even
        // though the current account can afford the entire output allocation.
        let (issuer, certificate) = dsa_projection_sources(None);
        let parent = CertificateSession::with_account(
            10_000,
            4096,
            Memory::new(Arc::new(MemoryAccount::new(4096, 100_000))),
        );
        let target = CertificateSession::new(&ResourcePolicy::default());
        let subject = target
            .read(&certificate)
            .expect("independently parsed subject");
        let key = projected_dsa(&parent, &issuer, &subject);
        let parameters = key.parameters().expect("inherited original parameters");
        let at = (parameters.as_ptr() as usize - issuer.as_ptr() as usize) as u64;
        let reader = parent.parser.read(&[], 0).expect("issuer source execution");
        let work = reader.execution();
        assert!(work.work_remaining() > 1);
        work.charge_work((work.work_remaining() - 1) as u64)
            .expect("leave only parameter metadata admission");
        assert!(parent.memory().work_remaining() > 0);
        let current = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
        let called = std::cell::Cell::new(false);
        let result = with_effective_spki(key, &current, |_| {
            called.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(X509ChainError::Processing(error))
            if error.is_resource() && error.offset() == at));
        assert!(!called.get());
        assert!(
            current.work_used() > 0,
            "framing and allocation were admitted"
        );
        assert_eq!(current.used(), 0, "partial output is released on refusal");
    }

    #[test]
    fn certificate_decoding_shares_work_across_failed_candidates() {
        // A malformed candidate still spends work; a retry cannot buy a fresh budget.
        let resources = ResourcePolicy {
            max_x509_work: 2,
            ..ResourcePolicy::default()
        };
        let session = CertificateSession::new(&resources);
        assert!(session.read(&[0x30, 0]).is_err());
        assert!(matches!(
            session.read(&[0x30, 0]),
            Err(X509ChainError::Policy(_))
        ));
    }

    #[test]
    fn certificate_parser_keeps_exact_signed_and_key_ranges() {
        // Shared decoding borrows the original authenticated bytes, with no re-encoding.
        let pair = rcgen::KeyPair::generate().expect("test key generation");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty SAN list")
            .self_signed(&pair)
            .expect("test certificate signing");
        let resources = ResourcePolicy::default();
        let session = CertificateSession::new(&resources);
        let parsed = session.read(cert.der()).expect("generated certificate");
        let start = cert.der().as_ptr() as usize;
        let end = start + cert.der().len();
        for bytes in [parsed.signed_bytes(), parsed.tbs().public_key().as_bytes()] {
            assert!((start..end).contains(&(bytes.as_ptr() as usize)));
            assert!(bytes.as_ptr() as usize + bytes.len() <= end);
        }
    }

    #[test]
    fn issuer_edge_cannot_reset_exhausted_certificate_work() {
        // Candidate signature checks must retain the caller's spent account.
        let pair = rcgen::KeyPair::generate().expect("test key generation");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty SAN list")
            .self_signed(&pair)
            .expect("test certificate signing");
        let resources = ResourcePolicy {
            max_x509_work: 0,
            ..ResourcePolicy::default()
        };
        let session = CertificateSession::new(&resources);
        let result = super::super::x509::certificate_signature_matches_with_provider(
            cert.der(),
            cert.der(),
            crate::provider::default_provider(),
            None,
            &session,
        );
        assert!(session.read(cert.der()).is_err());
        assert!(matches!(result, Err(X509ChainError::Policy(_))));
    }

    #[test]
    fn completed_candidate_does_not_mask_path_resource_exhaustion() {
        // A selected prefix cannot turn exhausted continuation work into success.
        let pair = rcgen::KeyPair::generate().expect("test key generation");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty SAN list")
            .self_signed(&pair)
            .expect("test certificate signing");
        let info = super::super::parse::X509DataInfo {
            certificates: vec![cert.der().to_vec()],
            parsed_certificates: vec![
                super::super::parse::parse_x509_certificate(cert.der())
                    .expect("generated certificate metadata"),
            ],
            ..Default::default()
        };
        let resources = ResourcePolicy {
            max_x509_work: 0,
            ..ResourcePolicy::default()
        };
        let session = CertificateSession::new(&resources);
        let result = super::super::parse::build_x509_certificate_paths_to_selector_targets(
            &info,
            0,
            &[0],
            super::super::parse::X509PathBounds {
                max_depth: 2,
                max_candidate_paths: 2,
            },
            crate::provider::default_provider(),
            None,
            &session,
        );
        assert!(matches!(
            result,
            Err(super::super::parse::X509ChainBuildError::Policy(_))
        ));
    }

    #[test]
    fn shared_certificate_verifier_uses_exact_source_ranges() {
        // The provider receives original TBS and SPKI bytes; corruption remains a No.
        let pair = rcgen::KeyPair::generate().expect("test key generation");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty SAN list")
            .self_signed(&pair)
            .expect("test certificate signing");
        let session = CertificateSession::new(&ResourcePolicy::default());
        let parsed = session.read(cert.der()).expect("generated certificate");
        let verifier = ProviderVerifier {
            provider: crate::provider::default_provider(),
            allowed: None,
        };
        assert_eq!(
            verifier
                .verify(
                    &parsed.tbs().signature(),
                    WorkingKey::standing(parsed.tbs().public_key()),
                    parsed.signed_bytes(),
                    parsed.signature_value(),
                    session.memory()
                )
                .expect("signature execution succeeds"),
            Verified::Yes
        );
        let mut altered = parsed.signed_bytes().to_vec();
        *altered.last_mut().expect("nonempty signed bytes") ^= 1;
        assert_eq!(
            verifier
                .verify(
                    &parsed.tbs().signature(),
                    WorkingKey::standing(parsed.tbs().public_key()),
                    &altered,
                    parsed.signature_value(),
                    session.memory()
                )
                .expect("corrupt signature execution succeeds"),
            Verified::No
        );
    }

    #[test]
    fn published_scoped_verifier_preserves_both_current_work_ceilings() {
        // Actual registry Verify<Execution>, not Verify<Memory>: either the
        // caller's local ceiling or aggregate account can refuse before crypto.
        let pair = rcgen::KeyPair::generate().expect("generate scoped verifier test key");
        let certificate = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("valid scoped verifier certificate parameters")
            .self_signed(&pair)
            .expect("sign scoped verifier test certificate");
        let source = CertificateSession::new(&ResourcePolicy::default());
        let certificate = source
            .read(certificate.der())
            .expect("read original certificate");
        let verifier = ProviderVerifier {
            provider: crate::provider::default_provider(),
            allowed: None,
        };
        for (local, aggregate) in [(0, 100_000), (100_000, 0), (100_000, 100_000)] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, aggregate)));
            let operation = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local,
                    ..Limits::default()
                },
                memory,
            );
            let reader = operation.read(&[], 0).expect("create current execution");
            let result = verifier.verify(
                &certificate.tbs().signature(),
                WorkingKey::standing(certificate.tbs().public_key()),
                certificate.signed_bytes(),
                certificate.signature_value(),
                &reader.execution(),
            );
            if local == 0 || aggregate == 0 {
                assert!(
                    matches!(result, Err(X509ChainError::Processing(error)) if error == structured_pkix::Error::resource(MemoryError::WorkExceeded, "certificate.signature", 0))
                );
            } else {
                assert_eq!(result.expect("funded verification succeeds"), Verified::Yes);
            }
        }
    }

    /// A self-issued DSA-SHA1 certificate whose DSA key omits its parameters.
    fn parameterless_dsa_certificate() -> Vec<u8> {
        use der::{Decode as _, Encode as _};
        let pair = rcgen::KeyPair::generate().expect("test key");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("test parameters")
            .self_signed(&pair)
            .expect("test certificate");
        let source = x509_cert::Certificate::from_der(cert.der()).expect("test schema");
        let tbs = source.tbs_certificate();
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10040.4.3"),
            parameters: None,
        };
        let key = x509_cert::SubjectPublicKeyInfo {
            algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: dsa::OID,
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(&[2, 1, 1]).expect("DSA integer"),
        };
        let mut body = Vec::new();
        for field in [
            tbs.serial_number().to_der(),
            algorithm.to_der(),
            tbs.issuer().to_der(),
            tbs.validity().to_der(),
            tbs.subject().to_der(),
            key.to_der(),
        ] {
            body.extend(field.expect("test TBS field"));
        }
        let tbs = der::asn1::Any::new(der::Tag::Sequence, body).expect("TBS sequence");
        let mut body = tbs.to_der().expect("test TBS");
        body.extend(algorithm.to_der().expect("test outer algorithm"));
        body.extend(source.signature().to_der().expect("test signature"));
        der::asn1::Any::new(der::Tag::Sequence, body)
            .expect("certificate sequence")
            .to_der()
            .expect("test encoding")
    }

    #[test]
    fn discovery_defers_a_dsa_key_whose_parameters_need_inheritance() {
        // RFC 5280 6.1.4(e) cannot be evaluated from this isolated pool edge.
        // Missing parameters are not a proved bad signature; path validation
        // must get a chance to supply the effective key before the provider.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
        let bytes = parameterless_dsa_certificate();
        let session = CertificateSession::new(&ResourcePolicy::default());
        let parsed = session.read(&bytes).expect("DSA certificate");
        let verifier = ProviderVerifier {
            provider: crate::provider::default_provider(),
            allowed: None,
        };
        let checked = core::cell::Cell::new(false);
        let result = verifier.verify_with_key_check(
            &parsed.tbs().signature(),
            WorkingKey::standing(parsed.tbs().public_key()),
            parsed.signed_bytes(),
            parsed.signature_value(),
            session.memory(),
            |_| {
                checked.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Ok(Verified::Unsupported)), "{result:?}");
        assert!(
            !checked.get(),
            "no strength/provider check of an incomplete key"
        );
        let mut other_bytes = bytes.clone();
        *other_bytes.last_mut().expect("signature bytes") ^= 1;
        let info = super::super::parse::X509DataInfo {
            parsed_certificates: vec![
                session.metadata(&bytes).expect("leaf metadata"),
                session.metadata(&other_bytes).expect("issuer metadata"),
            ],
            certificates: vec![bytes.clone(), other_bytes.clone()],
            ..Default::default()
        };
        let paths = super::super::parse::build_x509_certificate_paths_to_selector_targets(
            &info,
            0,
            &[1],
            super::super::parse::X509PathBounds {
                max_depth: 2,
                max_candidate_paths: 4,
            },
            crate::provider::default_provider(),
            None,
            &session,
        )
        .expect("deferred edge remains a prospective path");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], [0, 1]);
        let anchor = session.read(&other_bytes).expect("candidate anchor");
        let anchors = [other_bytes.clone()];
        let options = super::super::x509::X509ChainOptions {
            utc_facts: None,
            trusted_certs: &anchors,
            verification_time: std::time::SystemTime::now(),
            max_chain_depth: 2,
            check_crls: false,
            allowed_extended_key_usages: None,
            rsa_keys: crate::policy::RsaKeyPolicy::default(),
            dsa_keys: crate::policy::DsaKeyPolicy::default(),
            certificate_signature_algorithms: None,
        };
        let validation = validate_supplied_path(
            &[&parsed],
            &anchor,
            &options,
            crate::provider::default_provider(),
            &session,
        );
        assert!(
            matches!(validation, Err(X509ChainError::UnsupportedSignature(0))),
            "a deferred edge is never authenticated: {validation:?}"
        );
    }

    #[test]
    fn public_key_info_parser_enforces_certificate_workspace_policy() {
        // XML ingestion must not turn resource exhaustion into malformed DER.
        use base64::Engine as _;
        let pair = rcgen::KeyPair::generate().expect("test key generation");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty SAN list")
            .self_signed(&pair)
            .expect("test certificate signing");
        let encoded = base64::engine::general_purpose::STANDARD.encode(cert.der());
        let xml = format!(
            "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><X509Data><X509Certificate>{encoded}</X509Certificate></X509Data></KeyInfo>"
        );
        let document = crate::xml::dom::Document::parse(&xml).expect("generated XML");
        let resources = ResourcePolicy {
            max_x509_workspace_bytes: 0,
            ..ResourcePolicy::default()
        };
        let mut session = super::super::parse::KeyInfoParsingSession::new(&resources)
            .expect("valid resource policy");
        assert!(matches!(
            session.parse(document.root_element()),
            Err(super::super::ParseError::Policy(
                PolicyViolation::ResourceLimitExceeded {
                    resource: resource_name::X509_WORKSPACE_BYTES,
                    maximum: 0
                }
            ))
        ));
    }
}
