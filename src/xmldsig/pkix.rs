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
                    emit(if alias { "=" } else { &segment[..index + 1] })?;
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
            changed |= piece(&text[at..at + 1])?;
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
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    };
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000))
        .map_err(|_| X509ChainError::CertificateNotValid(0))?;
    let fraction = nanos.rem_euclid(1_000_000_000) as u32;
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
    use structured_pkix::crl::{
        Authentication, AuthenticationFailure, CompleteEvidence, EntryLookup, Evaluation,
        Freshness, ScopeOutcome, SourceOrigin,
    };
    use structured_pkix::error::CallbackError;
    use structured_pkix::path::WorkingKey;
    use structured_pkix::time::Relation;

    if embedded.is_empty() && additional.is_empty() {
        return Ok(());
    }
    let Some(anchor) = path.last() else {
        return Ok(());
    };
    let execution = session.memory();
    let mut crls = execution.vector();
    let count = embedded
        .len()
        .checked_add(additional.len())
        .ok_or_else(|| {
            session.error(structured_pkix::Error::resource(
                MemoryError::CapacityOverflow,
                "certificateList.pool",
                0,
            ))
        })?;
    crls.try_reserve_exact(count).map_err(|reason| {
        session.error(structured_pkix::Error::resource(
            reason,
            "certificateList.pool",
            0,
        ))
    })?;
    for bytes in embedded.iter().chain(additional) {
        let crl = session.read_crl(bytes)?;
        crls.try_push(crl).map_err(|reason| {
            session.error(structured_pkix::Error::resource(
                reason,
                "certificateList.pool",
                0,
            ))
        })?;
    }
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
            let identified = if let Some((authority, subject)) = authority
                .as_ref()
                .and_then(|authority| authority.key_id())
                .zip(subject.map(|id| id.as_bytes()))
            {
                execution
                    .charge_work(authority.len().max(subject.len()) as u64 + 1)
                    .map_err(|reason| {
                        session.error(structured_pkix::Error::resource(
                            reason,
                            "certificateList.authorityKeyIdentifier",
                            crl.span().start,
                        ))
                    })?;
                if authority != subject {
                    continue;
                }
                true
            } else {
                false
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
            // UTC history is a caller fact, not an implicit clock/table default.
            validate_crl_serials(crl, session)?;
            let utc = match options.utc_facts.as_ref() {
                Some(utc) => utc,
                None => {
                    if matches!(
                        proof
                            .scope(target, execution)
                            .map_err(|error| session.error(error))?,
                        ScopeOutcome::NotApplicable(_)
                    ) {
                        continue;
                    }
                    return Err(X509ChainError::MissingUtcFacts);
                }
            };
            let evidence = proof
                .evaluate(
                    target,
                    &Evaluation {
                        now,
                        utc,
                        execution,
                        origin: SourceOrigin::Cached,
                    },
                )
                .map_err(|error| session.error(error))?;
            let facts = match evidence {
                CompleteEvidence::Facts(facts) => facts,
                CompleteEvidence::NotApplicable(_) => continue,
                CompleteEvidence::DeltaNeedsBase => return Err(X509ChainError::InvalidCrl(index)),
            };
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
                        .time_relation(now, utc, execution)
                        .map_err(|error| session.error(error))?
                    {
                        Relation::Before | Relation::At => {
                            return Err(X509ChainError::Revoked(position));
                        }
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
            execution.charge_work(1).map_err(|reason| {
                session.error(structured_pkix::Error::resource(
                    reason,
                    "certificateList.reasons",
                    crl.span().start,
                ))
            })?;
            // RFC 5280 §6.3.3(d),(l): partial-list absence cannot establish
            // non-revocation. All contributors share this authenticated path,
            // target and operation time by construction; no new evidence pool.
            // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
            reasons = reasons.union(facts.reasons());
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

pub(crate) fn validate_supplied_path<'a>(
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    options: &super::x509::X509ChainOptions<'_>,
    provider: &dyn crate::provider::CryptoProvider,
    session: &CertificateSession,
) -> Result<structured_pkix::path::ValidationFacts<'a>, X509ChainError> {
    use structured_pkix::path::{
        Anchor, BuildError, ConstraintSource, Interval, Policy, RejectionReason, Validation,
        ValidationBounds, ValidationContext,
    };
    let verifier = PathVerifier {
        signatures: ProviderVerifier {
            provider,
            allowed: options.certificate_signature_algorithms,
        },
        chain,
        anchor,
        options,
    };
    let context = ValidationContext {
        execution: session.memory(),
        interval: Interval::at_instant(verification_instant(options.verification_time)?),
        policy: Policy::default(),
        bounds: ValidationBounds {
            depth: options.max_chain_depth.saturating_sub(1),
            // The operation account owns the work/storage ceilings. These
            // mechanism limits must not divide or reset that shared budget.
            work: u64::MAX,
            policies: usize::MAX,
        },
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let result = structured_pkix::path::validate(chain, Anchor::from_certificate(anchor), &context)
        .map_err(|error| match error {
            BuildError::Processing(error) => session.error(error),
            BuildError::Verification(X509ChainError::Processing(error)) => session.error(error),
            BuildError::Verification(error) => error,
            BuildError::Recognition(never) => match never {},
        })?;
    let position = |source| match source {
        ConstraintSource::Anchor => chain.len(),
        ConstraintSource::Certificate(position) => position,
    };
    match result {
        Validation::Accepted(facts) => Ok(facts),
        Validation::Incomplete(reason) => Err(X509ChainError::PathIncomplete(reason)),
        Validation::Rejected(rejection) => {
            let Some(at) = rejection.at.map(position) else {
                // A whole-input rejection has no certificate position.
                return Err(X509ChainError::UntrustedRoot);
            };
            Err(match rejection.reason {
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
                RejectionReason::PathLength { source, limit } => {
                    X509ChainError::PathLengthExceeded {
                        position: position(source),
                        limit,
                    }
                }
                RejectionReason::NameConstraints { source, .. } => {
                    X509ChainError::NameConstraintViolation {
                        position: at,
                        constraining_position: position(source),
                    }
                }
                RejectionReason::NameConstraintsOnNonAuthority => {
                    X509ChainError::InvalidNameConstraints { position: at }
                }
                RejectionReason::CriticalExtension(oid) => {
                    let text = oid.text(session.memory()).map_err(|reason| {
                        X509ChainError::Processing(structured_pkix::Error::resource(
                            reason,
                            "certificate.extensions",
                            0,
                        ))
                    })?;
                    X509ChainError::UnsupportedCriticalExtension {
                        position: at,
                        oid: text
                            .as_str(session.memory())
                            .map_err(|reason| {
                                X509ChainError::Processing(structured_pkix::Error::resource(
                                    reason,
                                    "certificate.extensions",
                                    0,
                                ))
                            })?
                            .to_owned(),
                    }
                }
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
    }
}

fn with_effective_spki<T, W: Work>(
    encoded: &[u8],
    parameters: Option<&[u8]>,
    execution: &W,
    verify: impl FnOnce(&[u8]) -> Result<T, X509ChainError>,
) -> Result<T, X509ChainError> {
    let Some(parameters) = parameters else {
        return verify(encoded);
    };
    let effective = encode_effective_spki(encoded, parameters, execution)?;
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
        Some(parameters) => {
            encode_effective_spki(original.as_bytes(), parameters, execution).map(|spki| {
                ValidatedX509Key {
                    effective_spki: Some(spki),
                }
            })
        }
        None => Ok(ValidatedX509Key {
            effective_spki: None,
        }),
    }
}

fn encode_effective_spki<W: Work>(
    encoded: &[u8],
    parameters: &[u8],
    execution: &W,
) -> Result<OwnedVec<u8, W>, X509ChainError> {
    use der::{Decode as _, Encode as _};
    execution
        .charge_work(encoded.len() as u64)
        .map_err(|reason| {
            X509ChainError::Processing(structured_pkix::Error::resource(
                reason,
                "issuer.public_key",
                0,
            ))
        })?;
    let key = pkcs8::SubjectPublicKeyInfoRef::from_der(encoded).map_err(|error| {
        X509ChainError::InvalidDer {
            kind: "issuer public key",
            message: error.to_string(),
        }
    })?;
    let parameters =
        der::asn1::AnyRef::from_der(parameters).map_err(|error| X509ChainError::InvalidDer {
            kind: "inherited issuer parameters",
            message: error.to_string(),
        })?;
    let effective = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: key.algorithm.oid,
            parameters: Some(parameters),
        },
        subject_public_key: key.subject_public_key,
    };
    let length = effective
        .encoded_len()
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "effective issuer public key",
            message: error.to_string(),
        })?;
    let mut writer = AccountedDerWriter {
        bytes: execution.vector(),
        failure: None,
    };
    writer
        .bytes
        .try_reserve_exact(usize::try_from(length).map_err(|_| {
            X509ChainError::Processing(structured_pkix::Error::resource(
                MemoryError::CapacityOverflow,
                "issuer.public_key",
                0,
            ))
        })?)
        .map_err(|error| {
            X509ChainError::Processing(structured_pkix::Error::resource(
                error,
                "issuer.public_key",
                0,
            ))
        })?;
    if let Err(error) = effective.encode(&mut writer) {
        return Err(match writer.failure {
            Some(reason) => X509ChainError::Processing(structured_pkix::Error::resource(
                reason,
                "issuer.public_key",
                0,
            )),
            None => X509ChainError::InvalidDer {
                kind: "effective issuer public key",
                message: error.to_string(),
            },
        });
    }
    Ok(writer.bytes)
}

struct AccountedDerWriter<W: Work> {
    bytes: OwnedVec<u8, W>,
    failure: Option<MemoryError>,
}

impl<W: Work> der::Writer for AccountedDerWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> der::Result<()> {
        self.bytes.try_extend_from_slice(bytes).map_err(|error| {
            self.failure = Some(error);
            der::ErrorKind::Failed.into()
        })
    }
}

/// Certificate signatures use the same selected engine and permissions as CRLs.
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
        signature: structured_asn1::BitString<'_>,
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
        signature: structured_asn1::BitString<'_>,
        execution: &W,
        check: impl FnOnce(&[u8]) -> Result<(), X509ChainError>,
    ) -> Result<structured_pkix::path::Verified, X509ChainError> {
        use x509_parser::prelude::FromDer as _;
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
        let (rest, identifier) = x509_parser::x509::AlgorithmIdentifier::from_der(
            algorithm.as_bytes(),
        )
        .map_err(|error| X509ChainError::InvalidDer {
            kind: "signature algorithm",
            message: error.to_string(),
        })?;
        if !rest.is_empty() {
            return Err(X509ChainError::InvalidDer {
                kind: "signature algorithm",
                message: "trailing data".into(),
            });
        }
        let signature = signature
            .octets()
            .ok_or_else(|| X509ChainError::InvalidDer {
                kind: "certificate signature",
                message: "signature is not octet-aligned".into(),
            })?;
        // Permission and capability checks precede inherited-key allocation.
        let algorithm = super::x509::authorize_x509_signature_algorithm(
            &identifier,
            self.provider,
            self.allowed,
        )?;
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
        let valid = if parameters.is_some() && parameters != key_algorithm.parameters() {
            // RFC 5280 6.1.4(e): inherit only the effective working-key parameters.
            // The temporary provider SPKI is accounted; original TBS stays borrowed.
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
            with_effective_spki(key.key().as_bytes(), parameters, execution, verify)?
        } else {
            verify(key.key().as_bytes())?
        };
        Ok(if valid {
            structured_pkix::path::Verified::Yes
        } else {
            structured_pkix::path::Verified::No
        })
    }
}

struct PathVerifier<'a, 'p> {
    signatures: ProviderVerifier<'p>,
    chain: &'p [&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    options: &'p super::x509::X509ChainOptions<'p>,
}

impl<W: Work> structured_pkix::path::Verify<W> for PathVerifier<'_, '_> {
    type Error = X509ChainError;

    fn verify(
        &self,
        algorithm: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_asn1::BitString<'_>,
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
                    self.options.rsa_keys,
                    self.options.dsa_keys,
                )
            },
        )
    }
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
        use structured_pkix::key::{PublicKeyInfo, ec, rsa};
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
        // Both readers compare the algorithm identifier again, paid; this only
        // selects which one to ask.
        if info.algorithm().algorithm() == structured_pkix::oid::EC_PUBLIC_KEY {
            ec::read(
                structured_pkix::path::WorkingKey::standing(info),
                &execution,
            )
            .map(PublicKey::Ec)
        } else {
            rsa::read(info, &execution).map(PublicKey::Rsa)
        }
    }

    pub(crate) fn read_crl<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> Result<structured_pkix::crl::CertificateList<'a>, X509ChainError> {
        structured_pkix::crl::CertificateList::read(&self.parser, bytes, 0)
            .map_err(|error| self.error(error))
    }

    pub(crate) fn parse_error(&self, error: X509ChainError) -> super::ParseError {
        match error {
            X509ChainError::Policy(error) => super::ParseError::Policy(error),
            X509ChainError::Processing(error) => super::ParseError::Certificate(error),
            error => super::ParseError::InvalidStructure(error.to_string()),
        }
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
    fn inherited_issuer_parameters_are_provided_without_changing_source() {
        // RFC 5280 6.1.4(e) supplies inherited parameters to the working key only.
        use der::{Decode as _, Encode as _};
        let y = [2, 1, 1];
        let parameters = [0x30, 9, 2, 1, 23, 2, 1, 11, 2, 1, 2];
        for encoded_parameters in [None, Some(der::asn1::AnyRef::NULL)] {
            let key = pkcs8::SubjectPublicKeyInfoRef {
                algorithm: pkcs8::AlgorithmIdentifierRef {
                    oid: dsa::OID,
                    parameters: encoded_parameters,
                },
                subject_public_key: der::asn1::BitStringRef::new(0, &y).expect("public bits"),
            }
            .to_der()
            .expect("SPKI encoding");
            let source = key.clone();
            let session = CertificateSession::new(&ResourcePolicy::default());
            with_effective_spki(&key, Some(&parameters), session.memory(), |effective| {
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
            assert_eq!(key, source);
            assert_eq!(session.memory().used(), 0);
        }
    }

    #[test]
    fn inherited_key_workspace_is_reserved_before_provider_execution() {
        // No cryptographic callback runs when the effective-key allocation is refused.
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
        let session = CertificateSession::new(&ResourcePolicy {
            max_x509_workspace_bytes: 0,
            ..ResourcePolicy::default()
        });
        let called = std::cell::Cell::new(false);
        let result = with_effective_spki(&key, Some(&[0x30, 0]), session.memory(), |_| {
            called.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(X509ChainError::Processing(error)) if error.is_resource()));
        assert!(!called.get());
        assert_eq!(session.memory().used(), 0);
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
        let session = CertificateSession::new(&ResourcePolicy {
            max_x509_workspace_bytes: 0,
            max_x509_work: 0,
            ..ResourcePolicy::default()
        });
        with_effective_spki(&key, None, session.memory(), |effective| {
            assert_eq!(effective.as_ptr(), key.as_ptr());
            assert_eq!(effective.len(), key.len());
            Ok(())
        })
        .expect("borrowed key needs no adapter workspace");
        assert_eq!(session.memory().used(), 0);
        assert_eq!(session.memory().work_used(), 0);
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
                    parsed.signature(),
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
                    parsed.signature(),
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
        for (local, aggregate) in [(0, 100000), (100000, 0), (100000, 100000)] {
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
                certificate.signature(),
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

    #[test]
    fn discovery_defers_a_dsa_key_whose_parameters_need_inheritance() {
        // RFC 5280 6.1.4(e) cannot be evaluated from this isolated pool edge.
        // Missing parameters are not a proved bad signature; path validation
        // must get a chance to supply the effective key before the provider.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
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
        let bytes = der::asn1::Any::new(der::Tag::Sequence, body)
            .expect("certificate sequence")
            .to_der()
            .expect("test encoding");
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
            parsed.signature(),
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
