//! The ETSI EN 319 102-1 V1.4.1 status indication of one corpus signature.
//!
//! The shared `structured_ltv::validation` process decides it; this module
//! only establishes its inputs: integrity through xml-sec's own
//! verification, the signing certificate through its signed reference
//! (clause 5.2.3), certification paths and revocation status through the
//! shared PKIX and LTV mechanisms with the verification's own verifiers, and
//! the cryptographic material the profile's constraints judge.

#[path = "etsi_long_term.rs"]
mod long_term;

use serde_json::{Value, json};
use structured_asn1::memory::Memory;
use structured_ltv::pki::status::{
    self as revocation, ExpiryEvidence, Query, Responder, Source, Status,
};
use structured_ltv::pki::{CheckedPath, CrlAuthority, PathOutcome};
use structured_ltv::validation::SubIndication;
use structured_ltv::validation::{
    Anchor as Trust, Chain, Changes, Context, Element, Elements, Facts, Family, Format, Hash,
    Material, Order, Path as EtsiPath, Recognition, Reference, Requirements, RevocationIssuer,
    Scheme, SignatureTimestamp, Signer, Time, Value as Computed,
};
use structured_pkix::Certificate;
use structured_pkix::crl::CertificateList;
use structured_pkix::ocsp::{BasicResponse, Response};
use structured_pkix::path::{
    Anchor, BuildError, EffectiveKey, Interval, Policy, ValidationContext,
};
use structured_pkix::temporal::{Instant, LeapTable};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, FailureReason, SignatureAlgorithm, VerifiedSession, VerifyResult,
    compute_digest,
};
use xml_sec_xades::TimestampRole;

/// What one `ds:Signature` declares, read from the document text.
#[derive(Default)]
pub struct Declared {
    /// The `SignatureMethod`, when recognized.
    pub method: Option<SignatureAlgorithm>,
    /// Each `SignedInfo` reference's `DigestMethod`, when recognized.
    pub digests: Vec<Option<DigestAlgorithm>>,
    /// The claimed `SigningTime`, as Unix seconds.
    pub signing_time: Option<i64>,
    /// Each `SigningCertificate(V2)/Cert` digest.
    pub certificate_references: Vec<(Option<DigestAlgorithm>, Vec<u8>)>,
    /// The `KeyInfo/X509Data/X509Certificate` values.
    pub key_info: Vec<Vec<u8>>,
    /// Each `SignatureTimeStamp` token, DER.
    pub signature_timestamps: Vec<Vec<u8>>,
    /// Each token of this signature's own properties xml-sec-xades checked
    /// on its own, in document order: its property's role, the token DER and
    /// whether its imprint and TSA signature held (EN 319 102-1 V1.4.1
    /// clause 5.4), none when it could not judge it.
    pub token_integrity: Vec<(TimestampRole, Vec<u8>, Option<bool>)>,
    /// Why xml-sec-xades checked none of this signature's tokens, when it
    /// refused to: each token then stays unjudged.
    pub token_refusal: Option<String>,
    /// Each `SigAndRefsTimeStamp` and `RefsOnlyTimeStamp` token, DER.
    pub validation_timestamps: Vec<Vec<u8>>,
    /// Whether each of [`Self::validation_timestamps`] is a
    /// `RefsOnlyTimeStamp`, which covers the references alone.
    pub refs_only: Vec<bool>,
    /// Each `ArchiveTimeStamp` token, DER.
    pub archive_timestamps: Vec<Vec<u8>>,
    /// Where each `ArchiveTimeStamp` is in the document, as a byte offset.
    pub archive_positions: Vec<usize>,
    /// Each `AllDataObjectsTimeStamp` and `IndividualDataObjectsTimeStamp`
    /// token with its role, DER: they stamp the signed data objects, not the
    /// signature.
    pub content_timestamps: Vec<(TimestampRole, Vec<u8>)>,
}

impl Declared {
    /// Whether the own checks of the `occurrence`th token of `role`, which is
    /// `token`, held, when xml-sec-xades judged it. Each property is told
    /// apart by its role and place, so a token copied into another property
    /// does not take the first one's result.
    pub fn intact(&self, role: TimestampRole, occurrence: usize, token: &[u8]) -> Option<bool> {
        let (_, checked, intact) = self
            .token_integrity
            .iter()
            .filter(|(of, _, _)| *of == role)
            .nth(occurrence)?;
        (checked.as_slice() == token).then_some(*intact).flatten()
    }

    /// Every token with its role and its place among the tokens of that
    /// role: signature, then validation, then archive timestamps.
    pub fn tokens(&self) -> Vec<(TimestampRole, usize, &[u8])> {
        let mut found = Vec::new();
        for (index, token) in self.signature_timestamps.iter().enumerate() {
            found.push((TimestampRole::Signature, index, token.as_slice()));
        }
        let (mut both, mut references) = (0, 0);
        for (token, refs_only) in self.validation_timestamps.iter().zip(&self.refs_only) {
            let (role, counter) = if *refs_only {
                (TimestampRole::ReferencesOnly, &mut references)
            } else {
                (TimestampRole::SignatureAndReferences, &mut both)
            };
            found.push((role, *counter, token.as_slice()));
            *counter += 1;
        }
        for (index, token) in self.archive_timestamps.iter().enumerate() {
            found.push((TimestampRole::Archive, index, token.as_slice()));
        }
        let (mut all, mut individual) = (0, 0);
        for (role, token) in &self.content_timestamps {
            let counter = if *role == TimestampRole::AllDataObjects {
                &mut all
            } else {
                &mut individual
            };
            found.push((*role, *counter, token.as_slice()));
            *counter += 1;
        }
        found
    }
}

/// The conditions and constraints every signature of one comparison shares.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// Every certificate the document and its tokens carry.
    pub pool: &'a [Vec<u8>],
    /// The trust anchors of the comparison.
    pub anchors: &'a [Vec<u8>],
    /// Every CRL the document incorporates.
    pub crls: &'a [Vec<u8>],
    /// Every `OCSPResponse` the document incorporates.
    pub responses: &'a [Vec<u8>],
    /// The validation time, Unix seconds.
    pub now: i64,
    /// The profile's constraints.
    pub requirements: &'a Requirements<'a>,
    /// Caller-approved UTC facts.
    pub utc: &'a LeapTable<'a>,
    /// Whether the profile takes a signer that is itself an anchor as trusted
    /// without further checks (clause 5.2.6.4 step 1(b)).
    pub direct_trust: bool,
    /// The first byte offset at which the document carries each DER value
    /// (certificate, CRL, OCSP response), the place an archive timestamp's
    /// coverage is decided by.
    pub positions: &'a [(Vec<u8>, usize)],
    /// The digests the profile accepts in a `Reference`, apart from the
    /// suites' hashes the requirements' one hash list also holds.
    pub reference_digests: &'a [Hash],
}

/// Freshness the comparison grants every status: DSS's policy ignores
/// revocation freshness (`RevocationFreshness Level="IGNORE"`), so neither
/// side may refuse a status as stale. A century in seconds.
const FRESHNESS_IGNORED: u64 = 100 * 366 * 86_400;

/// The DER content of the DSA public key OID 1.2.840.10040.4.1 (RFC 3279
/// 2.3.2), which `structured_pkix::oid` does not name.
const DSA_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];

fn instant(seconds: i64) -> Instant {
    Instant::new(seconds, 0).expect("corpus times are in range")
}

/// `name` in `SCREAMING_SNAKE_CASE`, the form DSS reports indications in.
fn screaming(name: &str) -> String {
    let mut text = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            text.push('_');
        }
        text.push(character.to_ascii_uppercase());
    }
    text
}

/// An indication and sub-indication in DSS's spelling.
fn verdict(indication: &str, sub: Option<&str>, basis: impl Into<String>) -> Value {
    json!({ "indication": indication, "sub": sub, "basis": basis.into() })
}

/// The digest methods TS 119 312 and DSS name, with their constraint hash.
/// SHA3-224 has neither name; the compatibility digests are outside the
/// `XAdES` profiles.
const HASHES: [(DigestAlgorithm, Hash); 8] = [
    (DigestAlgorithm::Sha1, Hash::Sha1),
    (DigestAlgorithm::Sha224, Hash::Sha224),
    (DigestAlgorithm::Sha256, Hash::Sha256),
    (DigestAlgorithm::Sha384, Hash::Sha384),
    (DigestAlgorithm::Sha512, Hash::Sha512),
    (DigestAlgorithm::Sha3_256, Hash::Sha3_256),
    (DigestAlgorithm::Sha3_384, Hash::Sha3_384),
    (DigestAlgorithm::Sha3_512, Hash::Sha3_512),
];

/// The hash `digest` computes in the constraint vocabulary, or
/// [`Hash::Other`] for one neither names.
pub fn hash_of(digest: DigestAlgorithm) -> Hash {
    HASHES
        .iter()
        .find(|(known, _)| *known == digest)
        .map_or(Hash::Other, |(_, hash)| *hash)
}

/// The scheme of a certificate's key: its family and size (TS 119 312 sizes
/// the modulus for RSA, p and q for DSA, the curve for ECDSA).
fn scheme_of(certificate: &Certificate<'_>, rsa: Family, memory: &Memory) -> Option<Scheme> {
    let spki = certificate.tbs().public_key();
    let oid = spki.algorithm().algorithm();
    let oid = oid.as_bytes();
    let scheme = |family, bits, subgroup_bits| Scheme {
        family,
        bits,
        exponent_bits: None,
        subgroup_bits,
    };
    let octets = |bytes: &[u8]| {
        let significant = bytes.iter().skip_while(|byte| **byte == 0).count();
        u32::try_from(significant * 8).ok()
    };
    if oid == structured_pkix::oid::RSA_ENCRYPTION.as_bytes()
        || oid == structured_pkix::oid::RSASSA_PSS.as_bytes()
    {
        let key = structured_pkix::key::rsa::read(spki, memory).ok()?;
        return Some(scheme(rsa, u32::try_from(key.modulus().bits()).ok()?, None));
    }
    if oid == structured_pkix::oid::EC_PUBLIC_KEY.as_bytes() {
        let key = structured_pkix::key::ec::read(EffectiveKey::standing(spki), memory).ok()?;
        let bits = match key.point().coordinate_len() {
            66 => 521,
            width => u32::try_from(width * 8).ok()?,
        };
        return Some(scheme(Family::Ecdsa, bits, None));
    }
    if oid == DSA_KEY {
        let key = structured_pkix::key::dsa::read(EffectiveKey::standing(spki), memory).ok()?;
        let parameters = key.parameters()?;
        return Some(scheme(
            Family::Dsa,
            octets(parameters.p().as_bytes())?,
            octets(parameters.q().as_bytes()),
        ));
    }
    if oid == structured_pkix::oid::ED25519.as_bytes() {
        return Some(scheme(Family::Ed25519, 0, None));
    }
    if oid == structured_pkix::oid::ED448.as_bytes() {
        return Some(scheme(Family::Ed448, 0, None));
    }
    None
}

/// The signing certificate (clause 5.2.3.4): the one a signed reference
/// digests to, trying every reference; without such references, the copy
/// the signature itself carries, which is the leaf of its `KeyInfo`
/// certificates (the one that issues none of the others).
pub fn signing_certificate<'c>(
    declared: &Declared,
    pool: &'c [Certificate<'c>],
    memory: &Memory,
) -> Option<&'c Certificate<'c>> {
    if declared.certificate_references.is_empty() {
        let carried: Vec<&Certificate<'c>> = pool
            .iter()
            .filter(|certificate| {
                declared
                    .key_info
                    .iter()
                    .any(|bytes| bytes.as_slice() == certificate.as_bytes())
            })
            .collect();
        let issues = |issuer: &Certificate<'_>, subject: &Certificate<'_>| {
            issuer.as_bytes() != subject.as_bytes()
                && subject
                    .tbs()
                    .issuer()
                    .matches(issuer.tbs().subject(), memory)
                    .unwrap_or(false)
        };
        let leaves: Vec<_> = carried
            .iter()
            .filter(|candidate| !carried.iter().any(|other| issues(candidate, other)))
            .collect();
        return leaves
            .first()
            .or(carried.first().as_ref())
            .copied()
            .copied();
    }
    declared
        .certificate_references
        .iter()
        .find_map(|(method, value)| {
            let method = (*method)?;
            pool.iter()
                .find(|certificate| compute_digest(method, certificate.as_bytes()) == *value)
        })
}

/// The indication of a signature whose integrity the widest profile
/// established (`computed`), when the compared profile's own verification
/// refused it with `trust`: a structural, transform, URI or bound refusal is
/// a constraint of that profile, which clause 5.2.8 applies last, so it
/// replaces only a passing indication. Algorithm and key refusals are
/// already the process's own through the profile's constraints.
pub fn under_profile(computed: Value, trust: &Value) -> Value {
    if trust["error"] != "Policy" {
        return computed;
    }
    let detail = trust["detail"].as_str().unwrap_or_default();
    let refused = refusal("Policy", detail);
    let constraint = refused["sub"] == "SIG_CONSTRAINTS_FAILURE" || refused["sub"] == "CUSTOM";
    if refused["sub"] == "FORMAT_FAILURE"
        || (constraint && computed["indication"] == "TOTAL_PASSED")
    {
        return refused;
    }
    computed
}

/// What xml-sec's verification refused, as the clause that decides it.
pub fn refusal(kind: &str, detail: &str) -> Value {
    let structural = [
        "XAdES",
        "SignedProperties",
        "QualifyingProperties",
        "Signature requires",
    ]
    .iter()
    .any(|word| detail.contains(word));
    match kind {
        // Clause 5.2.7.4 step 1: the signed data cannot be obtained.
        "Reference" => verdict("INDETERMINATE", Some("SIGNED_DATA_NOT_FOUND"), detail),
        // A mechanism this build lacks is not a finding about the signature
        // (Table 6 names none for it).
        _ if detail.contains("unsupported algorithm")
            || detail.contains("unsupported elliptic curve") =>
        {
            verdict("INDETERMINATE", Some("CUSTOM"), detail)
        }
        // Clause 5.3.4 step 2: no key and no certificate identify the signer.
        "KeyResolution" => verdict(
            "INDETERMINATE",
            Some("NO_SIGNING_CERTIFICATE_FOUND"),
            detail,
        ),
        "Policy" if detail.contains("authorized key") => verdict(
            "INDETERMINATE",
            Some("NO_SIGNING_CERTIFICATE_FOUND"),
            detail,
        ),
        // Conformance to the XAdES profile is signature acceptance, not
        // format checking (clause 5.2.2 NOTE, 5.2.8).
        "Policy" if structural => verdict("INDETERMINATE", Some("SIG_CONSTRAINTS_FAILURE"), detail),
        // An implementation bound is not a finding about the signature.
        "Policy" if detail.contains("exceeds policy maximum") => {
            verdict("INDETERMINATE", Some("CUSTOM"), detail)
        }
        // Clause 5.2.8: transforms and URIs the selected policy refuses.
        "Policy" if detail.contains("transform") || detail.contains("URI") => {
            verdict("INDETERMINATE", Some("SIG_CONSTRAINTS_FAILURE"), detail)
        }
        "Policy" if detail.contains("algorithm") => verdict(
            "INDETERMINATE",
            Some("CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
            detail,
        ),
        // Clause 5.2.8: a constraint of the selected policy (transforms,
        // URIs, key sources) the signature does not meet.
        "Policy" => verdict("INDETERMINATE", Some("SIG_CONSTRAINTS_FAILURE"), detail),
        // Clause 5.3.4 step 1: the signature cannot be processed.
        _ => verdict("TOTAL_FAILED", Some("FORMAT_FAILURE"), detail),
    }
}

/// The variant name of a debug rendering.
fn kind(debug: &str) -> &str {
    debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
}

/// Integrity facts of a verified signature (clause 5.2.7).
fn integrity(result: &VerifyResult) -> (Vec<Reference>, Computed) {
    let references = result
        .signed_info_references
        .iter()
        .map(|reference| match reference.status {
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { .. }) => {
                Reference::Mismatch
            }
            DsigStatus::Invalid(
                FailureReason::ReferenceUnavailable { .. }
                | FailureReason::ReferenceProcessingFailure { .. },
            ) => Reference::Missing,
            // A reference left unprocessed because the value failed is not
            // dereferenced (W3C XML Signature Best Practices 1). An external
            // one is still known to be unobtainable: the comparison supplies
            // its bytes to neither validator (clause 5.2.7.4 step 1).
            DsigStatus::NotProcessed
                if !reference.uri.is_empty() && !reference.uri.starts_with('#') =>
            {
                Reference::Missing
            }
            // Any other has no finding of its own (the value's decides).
            _ => Reference::Intact,
        })
        .collect();
    let value = match result.status {
        DsigStatus::Invalid(FailureReason::SignatureMismatch) => Computed::Mismatch,
        _ => Computed::Verified,
    };
    (references, value)
}

/// The parsed material one validation reads, all of one account.
struct Parsed<'a> {
    pool: Vec<Certificate<'a>>,
    anchors: Vec<Certificate<'a>>,
    crls: Vec<CertificateList<'a>>,
    responses: Vec<BasicResponse<'a>>,
    /// The DER of each status source, CRLs then OCSP responses, as the
    /// sources are numbered.
    sources: Vec<&'a [u8]>,
}

fn parse<'a>(parser: &'a structured_asn1::Parser, inputs: &'a Inputs<'_>) -> Parsed<'a> {
    let certificates = |list: &'a [Vec<u8>]| -> Vec<Certificate<'a>> {
        list.iter()
            .filter_map(|bytes| Certificate::read(parser, bytes, 0).ok())
            .collect()
    };
    let query = parser.read(&[], 0).ok();
    let mut sources = Vec::new();
    let mut crls = Vec::new();
    for bytes in inputs.crls {
        if let Ok(crl) = CertificateList::read(parser, bytes, 0) {
            crls.push(crl);
            sources.push(bytes.as_slice());
        }
    }
    let mut responses = Vec::new();
    for bytes in inputs.responses {
        let basic = match Response::read(parser, bytes, 0) {
            Ok(Response::Successful(body)) => query
                .as_ref()
                .and_then(|query| body.basic_in(query).ok().flatten()),
            // A protocol failure carries no signed status (RFC 6960 4.2.1).
            Ok(Response::Failure { .. }) | Err(_) => None,
        };
        if let Some(basic) = basic {
            responses.push(basic);
            sources.push(bytes.as_slice());
        }
    }
    Parsed {
        pool: certificates(inputs.pool),
        anchors: certificates(inputs.anchors),
        crls,
        responses,
        sources,
    }
}

/// Every instant after `inputs.now` at which a certificate the comparison
/// knows starts or stops being valid, as Unix seconds, ascending and once
/// each. Over the same evidence these are the only times after which the
/// process can decide otherwise: the profiles' constraints have no time
/// dimension, and DSS's policy ignores revocation freshness.
pub fn validity_bounds(parser: &structured_asn1::Parser, inputs: &Inputs<'_>) -> Vec<i64> {
    let parsed = parse(parser, inputs);
    let mut bounds: Vec<i64> = parsed
        .pool
        .iter()
        .chain(&parsed.anchors)
        .flat_map(|certificate| {
            let (not_before, not_after) = validity(certificate);
            [not_before.seconds(), not_after.seconds()]
        })
        .filter(|bound| *bound >= inputs.now)
        .collect();
    bounds.sort_unstable();
    bounds.dedup();
    bounds
}

/// The validity of `certificate`.
fn validity(certificate: &Certificate<'_>) -> (Instant, Instant) {
    let validity = certificate.tbs().validity();
    (
        validity.not_before().instant(),
        validity.not_after().instant(),
    )
}

/// One prospective chain (clause 5.2.6.4 step 2): leaf-first members and
/// the anchor certificate it ends at.
type Candidate<'a> = (Vec<&'a Certificate<'a>>, &'a Certificate<'a>);

/// The deepest prospective chain the comparison builds.
const CHAIN_DEPTH: usize = 8;

/// How many issuer candidates the search for one signer's chains may
/// consider, each anchor and pool certificate tried at each step counted.
/// Certificates sharing their names multiply the orderings; a search past
/// this bound ends as an incomplete process, never as "no chain".
const CANDIDATE_STEPS: usize = 100_000;

/// Every prospective chain (clause 5.2.6.4 step 2) from `signer` to an
/// anchor: each issuer named by the subject before it, with no condition on
/// time. The shared builder holds every certificate to one interval, which
/// is step 4's and step 7's check, not step 2's; `check` then validates each
/// chain in full. A search that exceeds [`CANDIDATE_STEPS`] is an error.
fn candidates<'a>(
    signer: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    memory: &Memory,
) -> Result<Vec<Candidate<'a>>, String> {
    candidates_within(
        signer,
        &parsed.pool,
        &parsed.anchors,
        memory,
        CANDIDATE_STEPS,
    )
}

/// [`candidates`] over `pool` and `anchors`, considering at most `limit`
/// candidates.
pub(super) fn candidates_within<'a>(
    signer: &'a Certificate<'a>,
    pool: &'a [Certificate<'a>],
    anchors: &'a [Certificate<'a>],
    memory: &Memory,
    limit: usize,
) -> Result<Vec<Candidate<'a>>, String> {
    struct Search<'a, 'm> {
        pool: &'a [Certificate<'a>],
        anchors: &'a [Certificate<'a>],
        memory: &'m Memory,
        found: Vec<Candidate<'a>>,
        steps: usize,
        limit: usize,
    }
    impl<'a> Search<'a, '_> {
        fn names(&self, subject: &Certificate<'_>, issuer: &Certificate<'_>) -> bool {
            subject
                .tbs()
                .issuer()
                .matches(issuer.tbs().subject(), self.memory)
                .unwrap_or(false)
        }
        /// Counts one considered candidate, before it is compared or kept.
        fn step(&mut self) -> Result<(), String> {
            // At most `limit` + 1, a count of considered certificates.
            self.steps += 1;
            if self.steps > self.limit {
                return Err(format!(
                    "the chain search exceeded {} candidates",
                    self.limit
                ));
            }
            Ok(())
        }
        fn extend(&mut self, chain: &mut Vec<&'a Certificate<'a>>) -> Result<(), String> {
            let last = *chain.last().expect("a chain starts at the signer");
            for anchor in self.anchors {
                self.step()?;
                if anchor.as_bytes() != last.as_bytes() && self.names(last, anchor) {
                    self.found.push((chain.clone(), anchor));
                }
            }
            if chain.len() >= CHAIN_DEPTH {
                return Ok(());
            }
            for issuer in self.pool {
                self.step()?;
                let used = chain
                    .iter()
                    .any(|member| member.as_bytes() == issuer.as_bytes());
                let anchored = self
                    .anchors
                    .iter()
                    .any(|anchor| anchor.as_bytes() == issuer.as_bytes());
                if !used && !anchored && self.names(last, issuer) {
                    chain.push(issuer);
                    self.extend(chain)?;
                    chain.pop();
                }
            }
            Ok(())
        }
    }
    let mut search = Search {
        pool,
        anchors,
        memory,
        found: Vec::new(),
        steps: 0,
        limit,
    };
    search.extend(&mut vec![signer])?;
    Ok(search.found)
}

/// `chain` checked by the shared processor over `at` with the
/// verification's own certificate verifier.
fn check<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    interval: Interval,
    memory: &Memory,
) -> Option<CheckedPath<'a>> {
    checked_over(session, chain, anchor, interval, memory).ok()
}

/// [`check`] at one instant, with the reason a chain was not accepted.
fn checked<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    at: Instant,
    memory: &Memory,
) -> Result<CheckedPath<'a>, String> {
    checked_over(session, chain, anchor, Interval::at_instant(at), memory)
}

/// `chain` checked over all of `interval`, with the reason it was not.
fn checked_over<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    interval: Interval,
    memory: &Memory,
) -> Result<CheckedPath<'a>, String> {
    let verifier = session.certificate_path_verifier(chain, anchor);
    let context = ValidationContext {
        execution: memory,
        interval,
        policy: Policy::default(),
        bounds: session.certificate_path_bounds(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    // Step 4's validity model is the X.509 validation constraint of the policy.
    match structured_ltv::pki::check_path_with_validity(
        chain,
        Anchor::from_certificate(anchor),
        &context,
        session.certificate_path_validity(),
    ) {
        Ok(PathOutcome::Accepted(path)) => Ok(path),
        Ok(PathOutcome::Rejected(reason)) => Err(format!("{reason:?}")),
        Ok(PathOutcome::Incomplete(reason)) => Err(format!("{reason:?}")),
        Err(BuildError::Processing(error)) => Err(format!("{error:?}")),
        Err(BuildError::Verification(error)) => Err(format!("{error:?}")),
        Err(BuildError::Recognition(never)) => match never {},
    }
}

/// The revocation status of `member` of `path` at `now` from every source
/// the document incorporates (clause 5.2.6.4 step 4 and RFC 5280 6.3), and
/// the validity of the certificates that issued the statements it rests on.
#[expect(clippy::too_many_arguments, reason = "one frozen input each")]
fn status_of<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    path: &CheckedPath<'a>,
    member: usize,
    parsed: &'a Parsed<'a>,
    authorities: &[CheckedPath<'a>],
    inputs: &Inputs<'_>,
    now: Instant,
    memory: &Memory,
) -> Result<Assessed, String> {
    let anchor_subject = path
        .anchor()
        .certificate()
        .map(|anchor| anchor.tbs().subject());
    let mut lists: Vec<Vec<CrlAuthority<'_, 'a>>> = Vec::new();
    for list in &parsed.crls {
        let mut found = Vec::new();
        if anchor_subject.is_some_and(|subject| {
            list.tbs()
                .issuer()
                .matches(subject, memory)
                .unwrap_or(false)
        }) {
            found.push(CrlAuthority::Anchor);
        }
        for authority in authorities {
            let target = authority
                .members()
                .last()
                .map(|member| member.certificate());
            if target.is_some_and(|target| {
                list.tbs()
                    .issuer()
                    .matches(target.tbs().subject(), memory)
                    .unwrap_or(false)
            }) {
                found.push(CrlAuthority::Path(authority));
            }
        }
        lists.push(found);
    }
    let delegates: Vec<Responder<'_, 'a>> = authorities
        .iter()
        .map(|path| Responder::Delegate {
            path,
            revocation: None,
        })
        .collect();
    let mut sources = Vec::new();
    for (list, found) in parsed.crls.iter().zip(&lists) {
        sources.push(Source::Crl {
            list,
            authorities: found,
        });
    }
    for response in &parsed.responses {
        sources.push(Source::Ocsp {
            response,
            nonce: None,
            intended_signer: None,
            responders: &delegates,
        });
    }
    let query = Query {
        interval: revocation::Interval {
            lower: None,
            upper: now,
        },
        now,
        utc: inputs.utc,
        max_freshness_seconds: Some(FRESHNESS_IGNORED),
    };
    let verifier = session.revocation_verifier();
    let context = ValidationContext {
        execution: memory,
        interval: Interval::at_instant(now),
        policy: Policy::default(),
        bounds: session.certificate_path_bounds(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let digest = session.cms_provider();
    // A source this member cannot use is part of the assessment; a failure of
    // the assessment itself ends the validation.
    let assessment =
        revocation::assess(path, member, &sources, &query, &context, &verifier, &digest)
            .map_err(|error| format!("status assessment failed: {error:?}"))?;
    let (issuers, records) = statements(assessment.statements());
    Ok(Assessed {
        status: assessment.status(),
        expiry: assessment.expiry_evidence(),
        issuers,
        records,
    })
}

/// One member's assessed status and what it rests on.
struct Assessed {
    status: Status,
    /// Support for non-revocation after the member expires (clause 5.2.6.4
    /// step 7, NOTE 8).
    expiry: ExpiryEvidence,
    issuers: Vec<RevocationIssuer>,
    records: Vec<Record>,
}

/// The certificates that authenticated `statements`, and each statement
/// that knows the status as historical evidence (clause 5.6.2.1).
fn statements(statements: &[revocation::Statement<'_>]) -> (Vec<RevocationIssuer>, Vec<Record>) {
    let mut issuers = Vec::new();
    let mut records = Vec::new();
    for statement in statements {
        let Some(
            revocation::Authentication::Crl { signer, .. }
            | revocation::Authentication::Ocsp { signer, .. },
        ) = statement.authentication
        else {
            continue;
        };
        let (not_before, not_after) = validity(signer);
        issuers.push(RevocationIssuer {
            not_before,
            not_after,
        });
        let revoked = match statement.finding {
            revocation::Finding::NotRevoked(_) => None,
            revocation::Finding::Revoked(revoked) => Some((revoked.at.instant(), revoked.reason)),
            _ => continue,
        };
        records.push(Record {
            source: statement.sources.primary,
            signer: signer.as_bytes().to_vec(),
            issued: statement.issued.instant(),
            revoked,
        });
    }
    (issuers, records)
}

/// One authenticated status statement about one path member, as the
/// long-term process reads it: its source (CRLs first, then OCSP responses,
/// in the document's order), the certificate that signed it, when it was
/// issued and what it says.
#[derive(Debug, Clone)]
struct Record {
    source: usize,
    signer: Vec<u8>,
    issued: Instant,
    revoked: Option<(Instant, Option<structured_pkix::crl::Reason>)>,
}

/// Every checked path that ends at a CA member of `path` or at a responder
/// a response carries: the authorities a status may be signed under.
fn authority_paths<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    memory: &Memory,
) -> Vec<CheckedPath<'a>> {
    // Each authority path is checked over the whole time all its members are
    // valid: a status binds to it at its own issuance (EN 319 102-1 V1.4.1
    // §5.2.6.4 step 4 checks that the issuance date lies within the issuer's
    // validity, not the validation time), which may be long before it.
    let checked_within = |path: &[&'a Certificate<'a>]| {
        let (from, until) = path
            .iter()
            .fold(validity(path[0]), |(from, until), member| {
                let (start, end) = validity(member);
                (from.max(start), until.min(end))
            });
        (from <= until)
            .then(|| {
                check(
                    session,
                    path,
                    anchor,
                    Interval::between_instants(from, until),
                    memory,
                )
            })
            .flatten()
    };
    let mut found = Vec::new();
    // The CA members, each with the part of the chain above it.
    for start in 1..chain.len() {
        if let Some(path) = checked_within(&chain[start..]) {
            found.push(path);
        }
    }
    // Delegated responders, issued by a chain member or the anchor (RFC 6960
    // 4.2.2.2): a response may carry its responder's certificate, or the
    // document may incorporate it with the other validation data.
    let mut responders: Vec<&'a Certificate<'a>> = Vec::new();
    for responder in parsed
        .responses
        .iter()
        .flat_map(BasicResponse::certificates)
        .chain(&parsed.pool)
    {
        let known = responders
            .iter()
            .chain(chain)
            .any(|other| other.as_bytes() == responder.as_bytes());
        if !known {
            responders.push(responder);
        }
    }
    for responder in responders {
        // Below each CA member, or directly below the anchor.
        for start in 1..=chain.len() {
            let mut delegated = vec![responder];
            delegated.extend_from_slice(&chain[start..]);
            if let Some(path) = checked_within(&delegated) {
                found.push(path);
                break;
            }
        }
    }
    found
}

/// What the X.509 validation building block (clause 5.2.6) establishes about
/// every prospective chain of one signing certificate, index-aligned.
struct PathFacts {
    chains: Vec<Chain>,
    statuses: Vec<Vec<Status>>,
    materials: Vec<Vec<Material>>,
    issuers: Vec<Vec<RevocationIssuer>>,
    /// The signing certificate's status, as the first accepted chain reads it.
    signer_status: Status,
    /// That status's support for non-revocation after expiry.
    signer_expiry: ExpiryEvidence,
    /// Why each rejected chain was rejected, for review.
    rejections: Vec<String>,
    /// Every chain the shared processor accepts inside the signing
    /// certificate's validity, as past certificate validation reads it
    /// (clause 5.6.2.1): a chain that fails only at the validation time is
    /// still a historical candidate.
    history: Vec<History>,
}

/// One historical candidate chain: its result, the intersection of its
/// members' validity (shell model) and each non-anchor member, issuer to
/// target, with its status statements.
#[derive(Debug)]
struct History {
    chain: Chain,
    validity: (Instant, Instant),
    members: Vec<(Vec<u8>, Vec<Record>)>,
}

impl PathFacts {
    /// The chains as the process's path inputs, every anchor recognized: the
    /// comparison's anchors are trusted at every time.
    fn lend(&self) -> Vec<EtsiPath<'_>> {
        self.chains
            .iter()
            .enumerate()
            .map(|(index, chain)| EtsiPath {
                chain: *chain,
                anchor: Trust {
                    current: Recognition::Recognized,
                    over_interval: Recognition::Recognized,
                },
                authorities: &self.statuses[index],
                materials: &self.materials[index],
                revocation_issuers: &self.issuers[index],
                revocation_retry: None,
            })
            .collect()
    }

    fn rejected(&mut self, reason: String) {
        self.chains.push(Chain::GeneralFailure);
        self.statuses.push(Vec::new());
        self.materials.push(Vec::new());
        self.issuers.push(Vec::new());
        self.rejections.push(reason);
    }
}

/// A scheme the constraints can never accept, for a key nothing could size.
const UNKNOWN_SCHEME: Scheme = Scheme {
    family: Family::Other,
    bits: 0,
    exponent_bits: None,
    subgroup_bits: None,
};

/// Clause 5.2.6.4 over every prospective chain of `signer` at `now`.
fn path_facts<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signer: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    inputs: &Inputs<'_>,
    now: Instant,
    memory: &Memory,
) -> Result<PathFacts, String> {
    let mut facts = PathFacts {
        chains: Vec::new(),
        statuses: Vec::new(),
        materials: Vec::new(),
        issuers: Vec::new(),
        signer_status: Status::NoEvidence,
        signer_expiry: ExpiryEvidence::Unestablished,
        rejections: Vec::new(),
        history: Vec::new(),
    };
    if parsed
        .anchors
        .iter()
        .any(|anchor| anchor.as_bytes() == signer.as_bytes())
    {
        // RFC 5280 6.1.1(d): a trust anchor is an input, not a path member,
        // so it has neither a revocation status nor issuer material here.
        // A profile that trusts it directly ends the X.509 block at step
        // 1(b); otherwise its validity is still the signing certificate's
        // (step 7).
        facts.chains.push(if inputs.direct_trust {
            Chain::DirectTrust
        } else {
            Chain::Valid
        });
        facts.statuses.push(Vec::new());
        facts.materials.push(Vec::new());
        facts.issuers.push(Vec::new());
        facts.signer_status = Status::NotRevoked {
            basis: 0,
            later: None,
        };
        return Ok(facts);
    }
    let (not_before, not_after) = validity(signer);
    let mut accepted = false;
    for (chain, anchor) in candidates(signer, parsed, memory)? {
        // The chain is checked where all its members are valid, as close to
        // `now` as they allow: clause 5.2.6.4 step 4 leaves the signing
        // certificate's own validity to step 7, the shell model holds every
        // other member to `now` below, and past certificate validation
        // (clause 5.6.2.1) needs the chain at the times it was valid.
        let (from, until) = chain
            .iter()
            .fold((not_before, not_after), |(from, until), member| {
                let (start, end) = validity(member);
                (from.max(start), until.min(end))
            });
        if from > until {
            facts.rejected("the members of the chain are never valid together".into());
            continue;
        }
        let chain_time = now.max(from).min(until);
        let checked = match checked(session, &chain, anchor, chain_time, memory) {
            Ok(checked) => checked,
            Err(reason) => {
                facts.rejected(reason);
                continue;
            }
        };
        let members_valid = chain.iter().skip(1).all(|member| {
            let (from, until) = validity(member);
            from <= now && now <= until
        });
        let authorities = authority_paths(session, &chain, anchor, parsed, memory);
        let members = member_facts(
            session,
            &checked,
            anchor,
            parsed,
            &authorities,
            inputs,
            now,
            memory,
        )?;
        // The signer's status is read off the first chain the shell model
        // accepts; a rejected chain neither supplies it nor hides a later one.
        if !accepted && members_valid {
            facts.signer_status = members.signer;
            facts.signer_expiry = members.signer_expiry;
            accepted = true;
        }
        // A CA member outside its validity at the validation time fails the
        // shell model (clause 5.2.6.4 step 4, RFC 5280 6.1.3(a)(2)).
        if !members_valid {
            facts
                .rejections
                .push("a CA member is outside its validity at the validation time".into());
        }
        facts.chains.push(if members_valid {
            Chain::Valid
        } else {
            Chain::GeneralFailure
        });
        facts.statuses.push(members.statuses);
        facts.issuers.push(members.issuers);
        facts.materials.push(members.materials);
        let intersection = chain
            .iter()
            .fold((not_before, not_after), |(from, until), member| {
                let (start, end) = validity(member);
                (from.max(start), until.min(end))
            });
        facts.history.push(History {
            chain: Chain::Valid,
            validity: intersection,
            members: members.history,
        });
    }
    Ok(facts)
}

/// The facts of every non-anchor member of one checked chain.
struct MemberFacts {
    statuses: Vec<Status>,
    issuers: Vec<RevocationIssuer>,
    materials: Vec<Material>,
    signer: Status,
    signer_expiry: ExpiryEvidence,
    history: Vec<(Vec<u8>, Vec<Record>)>,
}

/// Each member's status at `now` (the target's apart), the issuers of the
/// statements read, the material of each certificate signature and each
/// member's statements for past validation.
#[expect(clippy::too_many_arguments, reason = "one frozen input each")]
fn member_facts<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    checked: &CheckedPath<'a>,
    anchor: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    authorities: &[CheckedPath<'a>],
    inputs: &Inputs<'_>,
    now: Instant,
    memory: &Memory,
) -> Result<MemberFacts, String> {
    let count = checked.members().len();
    let mut facts = MemberFacts {
        statuses: Vec::new(),
        issuers: Vec::new(),
        materials: Vec::new(),
        signer: Status::NoEvidence,
        signer_expiry: ExpiryEvidence::Unestablished,
        history: Vec::new(),
    };
    for member in 0..count {
        let Assessed {
            status,
            expiry,
            issuers: used,
            records,
        } = status_of(
            session,
            checked,
            member,
            parsed,
            authorities,
            inputs,
            now,
            memory,
        )?;
        facts.issuers.extend(used);
        if member + 1 == count {
            facts.signer = status;
            facts.signer_expiry = expiry;
        } else {
            facts.statuses.push(status);
        }
        let certificate = checked.members()[member].certificate();
        facts
            .history
            .push((certificate.as_bytes().to_vec(), records));
        // The issuer's key signed this member: its scheme is the
        // certificate's material (clause 5.2.6.4 step 6). Certificate hashes
        // are not restricted by the profiles.
        let issuer = member
            .checked_sub(1)
            .map_or(anchor, |previous| checked.members()[previous].certificate());
        facts.materials.push(Material {
            hash: None,
            scheme: Some(scheme_of(issuer, Family::RsaPkcs1, memory).unwrap_or(UNKNOWN_SCHEME)),
        });
    }
    Ok(facts)
}

/// What a timestamp token states, read without checking anything.
pub struct TokenFacts {
    /// `genTime`, Unix seconds.
    pub generated: i64,
    /// The certificates its signed data carries (RFC 3161 2.4.2).
    pub certificates: Vec<Vec<u8>>,
    /// The `messageImprint` hash function.
    pub imprint: Hash,
}

/// The DER contents of the hash OIDs a `messageImprint` may name.
const IMPRINT_HASHES: [(&[u8], Hash); 8] = [
    (&[0x2b, 0x0e, 0x03, 0x02, 0x1a], Hash::Sha1),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
        Hash::Sha224,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        Hash::Sha256,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        Hash::Sha384,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
        Hash::Sha512,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
        Hash::Sha3_256,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
        Hash::Sha3_384,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
        Hash::Sha3_512,
    ),
];

/// [`TokenFacts`] of `token`.
pub fn token_details(token: &[u8]) -> Option<TokenFacts> {
    use std::sync::Arc;
    use structured_asn1::memory::MemoryAccount;
    let parser =
        structured_asn1::Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28))));
    let read = structured_cms::timestamp::Token::read(&parser, token, 0).ok()?;
    let parent = parser.read(&[], 0).ok()?;
    let (generated, imprint) = read
        .with_info(&parent, |info, _, _| {
            let imprint = match info.imprint().algorithm() {
                structured_cms::timestamp::HashAlgorithmReading::Identifier(identifier) => {
                    let oid = identifier.algorithm();
                    IMPRINT_HASHES
                        .iter()
                        .find(|(known, _)| *known == oid.as_bytes())
                        .map_or(Hash::Other, |(_, hash)| *hash)
                }
                structured_cms::timestamp::HashAlgorithmReading::Malformed { .. } => Hash::Other,
            };
            Ok::<_, core::convert::Infallible>((info.gen_time().start().seconds(), imprint))
        })
        .ok()?;
    let certificates = read
        .message()
        .certificates()
        .iter()
        .map(|certificate| certificate.as_bytes().to_vec())
        .collect();
    Some(TokenFacts {
        generated,
        certificates,
        imprint,
    })
}

/// The TSA of the DER `token`: the certificate its `SignerInfo` names (RFC
/// 5652 5.3), which xml-sec-xades verified the token with, found in the
/// parsed pool. A token may omit it, when the document carries it instead.
fn authority<'a>(token: &[u8], parsed: &'a Parsed<'a>) -> Option<&'a Certificate<'a>> {
    use std::sync::Arc;
    use structured_asn1::memory::MemoryAccount;
    use structured_cms::directory::{CertificateAgreement, matches_certificate_in};
    let parser =
        structured_asn1::Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28))));
    let read = structured_cms::timestamp::Token::read(&parser, token, 0).ok()?;
    let parent = parser.read(&[], 0).ok()?;
    let named = read.signer().sid();
    parsed.pool.iter().find(|candidate| {
        matches!(
            matches_certificate_in(named, candidate, &parent),
            Ok(CertificateAgreement::Matches)
        )
    })
}

/// Each signature timestamp's result at `now` (clause 5.4, as clause 5.5.4
/// step 3 consumes it): a token xml-sec-xades established passes when its
/// TSA's certificate validates now, the X.509 building block deciding
/// otherwise; a token it refused is discarded as one whose imprint does not
/// bind; one it could not judge is left out. A process failure ends the
/// validation rather than passing or dropping a token.
fn signature_timestamps<W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    declared: &Declared,
    parsed: &Parsed<'_>,
    inputs: &Inputs<'_>,
    now: Instant,
    memory: &Memory,
) -> Result<Vec<SignatureTimestamp>, String> {
    let mut found = Vec::new();
    for (index, token) in declared.signature_timestamps.iter().enumerate() {
        let Some(TokenFacts { generated, .. }) = token_details(token) else {
            continue;
        };
        match declared.intact(TimestampRole::Signature, index, token) {
            Some(true) => {
                let Some(tsa) = authority(token, parsed) else {
                    continue;
                };
                let outcome = authority_outcome(session, tsa, parsed, inputs, now, memory)?;
                found.push(match outcome.sub {
                    None => SignatureTimestamp::Passed(instant(generated)),
                    Some(sub) => SignatureTimestamp::Finding {
                        sub,
                        required: false,
                    },
                });
            }
            Some(false) => found.push(SignatureTimestamp::ImprintMismatch),
            None => {}
        }
    }
    Ok(found)
}

/// The basic validation (clause 5.3.4) of a token signed by `tsa`, whose
/// imprint and signature xml-sec-xades already established: its X.509
/// building block at `now` decides it.
fn authority_outcome<W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    tsa: &Certificate<'_>,
    parsed: &Parsed<'_>,
    inputs: &Inputs<'_>,
    now: Instant,
    memory: &Memory,
) -> Result<structured_ltv::validation::Outcome, String> {
    let paths = path_facts(session, tsa, parsed, inputs, now, memory)?;
    let etsi_paths = paths.lend();
    let (not_before, not_after) = validity(tsa);
    // The token's own signature is held to the compared profile's key sizes
    // (clause 5.2.8 via 5.4); the members' materials cover only the keys
    // that signed its certificates. RSA sizes are the family's either way.
    let materials = [Material {
        hash: None,
        scheme: Some(scheme_of(tsa, Family::RsaPkcs1, memory).unwrap_or(UNKNOWN_SCHEME)),
    }];
    let facts = Facts {
        format: Format::Conformant,
        context: Context::Ready,
        signer: Some(Signer {
            not_before,
            not_after,
            revocation: paths.signer_status,
            expiry_evidence: paths.signer_expiry,
        }),
        references: &[],
        value: Computed::Verified,
        materials: &materials,
        signed_attribute_materials: &[],
        elements: Elements::NONE,
        time: Time {
            after: None,
            before: None,
        },
        content_timestamp: None,
        paths: &etsi_paths,
        truncated: false,
        order: Order::Coherent,
        signature_timestamp: false,
        signature_timestamps: &[],
        claimed_signing_time: None,
        utc: Some(inputs.utc),
        changes: Changes::NotApplicable,
        now,
    };
    let requirements = Requirements {
        elements: Elements::NONE,
        ..*inputs.requirements
    };
    structured_ltv::validation::validate(&facts, &requirements, memory)
        .map_err(|error| format!("timestamp authority validation failed: {error:?}"))
}

/// The hash a `Reference` digest presents to clause 5.2.8: its own, when the
/// profile accepts it in a reference, otherwise none the constraints know.
/// One hash list serves every material there, as in DSS's policy, so a hash
/// a signature suite admits would otherwise pass as a reference digest the
/// profile refuses.
pub fn reference_hash(digest: Option<DigestAlgorithm>, permitted: &[Hash]) -> Hash {
    digest
        .map(hash_of)
        .filter(|hash| permitted.contains(hash))
        .unwrap_or(Hash::Other)
}

/// The signature value's material (its suite, sized by the signing
/// certificate's key) and each reference digest's, for clause 5.2.8.
fn own_materials(
    declared: &Declared,
    signer: &Certificate<'_>,
    permitted: &[Hash],
    memory: &Memory,
) -> Vec<Material> {
    let suite = declared.method.and_then(crate::suite_of);
    let family = suite.map_or(Family::Other, |(family, _)| family);
    let mut materials = vec![Material {
        hash: suite.and_then(|(_, hash)| hash),
        scheme: Some(
            scheme_of(signer, family, memory)
                .map_or(UNKNOWN_SCHEME, |scheme| Scheme { family, ..scheme }),
        ),
    }];
    for digest in &declared.digests {
        materials.push(Material {
            hash: Some(reference_hash(*digest, permitted)),
            scheme: None,
        });
    }
    materials
}

/// The ETSI indication of one signature verified in `session` (whose policy
/// trusts every carried key directly, so `result` is its integrity alone).
/// `uncountersigned` says the signature is a countersignature none of whose
/// references matches the countersigned `SignatureValue`, a signed data item
/// of its own (EN 319 132-1 §5.2.7.2) whose hash then fails (clause 5.2.7.4
/// step 2).
pub fn indication<W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    result: &Result<VerifyResult, xml_sec::xmldsig::DsigError>,
    declared: &Declared,
    inputs: &Inputs<'_>,
    uncountersigned: bool,
) -> Value {
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let debug = format!("{error:?}");
            let detail = error.to_string();
            // The widest profile admits every same-document reference, so
            // the class it refuses is an external one, whose bytes the
            // comparison supplies to neither validator: the signed data
            // cannot be obtained (clause 5.2.7.4 step 1).
            if detail.contains("reference URI class") {
                return verdict("INDETERMINATE", Some("SIGNED_DATA_NOT_FOUND"), detail);
            }
            return refusal(kind(&debug), &detail);
        }
    };
    let parser = session.certificate_parser();
    let memory = parser.memory().clone();
    let parsed = parse(&parser, inputs);
    let now = instant(inputs.now);
    let Some(signer) = signing_certificate(declared, &parsed.pool, &memory)
        .or_else(|| signing_certificate(declared, &parsed.anchors, &memory))
    else {
        // Clause 5.3.4 step 2.
        return verdict("INDETERMINATE", Some("NO_SIGNING_CERTIFICATE_FOUND"), "ISC");
    };
    let (not_before, not_after) = validity(signer);
    let stamped = path_facts(session, signer, &parsed, inputs, now, &memory).and_then(|paths| {
        signature_timestamps(session, declared, &parsed, inputs, now, &memory)
            .map(|stamps| (paths, stamps))
    });
    // A process that could not complete decides nothing about the signature.
    let (paths, stamps) = match stamped {
        Ok(found) => found,
        Err(error) => return verdict("INDETERMINATE", Some("CUSTOM"), error),
    };
    let etsi_paths = paths.lend();
    let (references, value) = integrity(result);
    let materials = own_materials(declared, signer, inputs.reference_digests, &memory);
    let mut elements = Elements::NONE;
    if declared.signing_time.is_some() {
        elements = elements.with(Element::ClaimedSigningTime);
    }
    if !declared.certificate_references.is_empty() {
        elements = elements.with(Element::SigningCertificate);
    }
    let mut references = references;
    if uncountersigned {
        references.push(Reference::Mismatch);
    }
    let facts = Facts {
        format: Format::Conformant,
        context: Context::Ready,
        signer: Some(Signer {
            not_before,
            not_after,
            revocation: paths.signer_status,
            expiry_evidence: paths.signer_expiry,
        }),
        references: &references,
        value,
        materials: &materials,
        signed_attribute_materials: &[],
        elements,
        time: Time {
            after: None,
            before: None,
        },
        content_timestamp: None,
        paths: &etsi_paths,
        truncated: false,
        order: Order::Coherent,
        signature_timestamp: !declared.signature_timestamps.is_empty(),
        signature_timestamps: &stamps,
        claimed_signing_time: declared.signing_time.map(instant),
        utc: Some(inputs.utc),
        changes: Changes::NotApplicable,
        now,
    };
    let context = TokenContext {
        session,
        parsed: &parsed,
        inputs,
        now,
        memory: &memory,
        catalogue: &catalogue(&parsed, declared, inputs),
    };
    let mut rendered = context.long_term(&facts, signer, &paths, declared);
    rendered["detail"] = json!({
        "chains": format!("{:?}", paths.chains),
        "rejections": paths.rejections,
        "timestamps": format!(
            "{:?} {stamps:?}",
            declared
                .tokens()
                .into_iter()
                .map(|(role, occurrence, token)| declared.intact(role, occurrence, token))
                .collect::<Vec<_>>()
        ),
        "revocation": format!("{:?} {:?}", paths.signer_status, paths.statuses),
    });
    rendered
}

/// Every token, certificate and status source the historical process of one
/// signature may cite.
fn catalogue<'a>(
    parsed: &'a Parsed<'a>,
    declared: &Declared,
    inputs: &Inputs<'_>,
) -> long_term::Catalogue<'a> {
    // A delegated responder's certificate may travel only inside its
    // response (RFC 6960 4.2.2.2); `authority_paths` accepts it from there,
    // so the records it signs must find it here too.
    let position = |der: &[u8]| {
        inputs
            .positions
            .iter()
            .find(|(value, _)| value.as_slice() == der)
            .map(|(_, at)| *at)
    };
    let mut certificates: Vec<&Certificate<'a>> =
        parsed.pool.iter().chain(&parsed.anchors).collect();
    let mut positions: Vec<Option<usize>> = certificates
        .iter()
        .map(|certificate| position(certificate.as_bytes()))
        .collect();
    // A certificate inside a response is where that response is.
    let responses = &parsed.sources[parsed.crls.len()..];
    for (response, der) in parsed.responses.iter().zip(responses) {
        for certificate in response.certificates() {
            certificates.push(certificate);
            positions.push(position(der));
        }
    }
    positions.extend(parsed.sources.iter().map(|der| position(der)));
    long_term::Catalogue {
        tokens: declared.tokens().len(),
        certificates,
        sources: parsed.sources.len(),
        positions,
    }
}

/// A completed ETSI decision in DSS's spelling.
fn decided(decision: long_term::Decision, basis: &str) -> Value {
    let indication = screaming(&format!("{:?}", decision.indication()));
    let sub = match decision {
        long_term::Decision::Passed => None,
        long_term::Decision::Finding(sub) => {
            let debug = format!("{sub:?}");
            Some(if debug.starts_with("Custom") {
                "CUSTOM".to_owned()
            } else {
                screaming(&debug)
            })
        }
    };
    json!({ "indication": indication, "sub": sub, "basis": basis })
}

/// Sets the current decision of the token `each` names last.
fn record(each: &mut [Value], current: long_term::Decision) {
    if let Some(entry) = each.last_mut() {
        let decision = decided(current, "");
        entry["current"] = json!({ "indication": decision["indication"], "sub": decision["sub"] });
    }
}

/// What establishing one signature's timestamp tokens reads.
struct TokenContext<'s, 'a, 'v, 'x, 'i, W: structured_asn1::memory::Work> {
    session: &'s VerifiedSession<'v, 'x, 'i, W>,
    parsed: &'a Parsed<'a>,
    inputs: &'a Inputs<'a>,
    now: Instant,
    memory: &'a Memory,
    catalogue: &'a long_term::Catalogue<'a>,
}

impl<W: structured_asn1::memory::Work> TokenContext<'_, '_, '_, '_, '_, W> {
    /// Clause 5.6 over `current` (the basic and with-time facts), the
    /// signer's historical chains and every token the signature carries.
    fn long_term(
        &self,
        current: &Facts<'_>,
        signer: &Certificate<'_>,
        paths: &PathFacts,
        declared: &Declared,
    ) -> Value {
        let mut tokens = Vec::new();
        let mut pasts = vec![long_term::past(
            long_term::Catalogue::VALUE,
            signer,
            &paths.history,
            self.catalogue,
        )];
        let mut each = Vec::new();
        if let Err(error) = self.tokens(declared, &mut tokens, &mut pasts, &mut each) {
            return verdict("INDETERMINATE", Some("CUSTOM"), error);
        }
        let long_term_attributes = !tokens.is_empty() || self.catalogue.sources > 0;
        let mut rendered = match long_term::validate(
            current,
            self.inputs.requirements,
            self.catalogue,
            &pasts,
            &mut tokens,
            long_term_attributes,
            self.memory,
        ) {
            Ok((decision, stage)) => decided(decision, &format!("{stage:?}")),
            Err(error) => verdict("INDETERMINATE", Some("CUSTOM"), error),
        };
        rendered["tokens"] = Value::Array(each);
        rendered
    }

    /// Every token of `declared` the long-term process can place, with its
    /// TSA's past-validation inputs appended to `pasts`. A token xml-sec-xades
    /// refused has a broken imprint or signature (clause 5.4 via 5.2.7); one
    /// it could not judge is left out; a process failure ends the validation.
    /// `each` receives every token's current decision in declaration order,
    /// none for one that is left out: the timestamp validation of each token
    /// at the validation time (clause 5.4), as DSS reports it per token.
    fn tokens(
        &self,
        declared: &Declared,
        tokens: &mut Vec<long_term::Token>,
        pasts: &mut Vec<long_term::Past>,
        each: &mut Vec<Value>,
    ) -> Result<(), String> {
        let signature = declared.signature_timestamps.len();
        let validation = declared.validation_timestamps.len();
        for (index, (role, occurrence, der)) in declared.tokens().into_iter().enumerate() {
            let role_name = format!("{role:?}");
            each.push(json!({ "role": role_name, "current": null }));
            let (Some(facts), Some(intact)) =
                (token_details(der), declared.intact(role, occurrence, der))
            else {
                continue;
            };
            let object = long_term::Catalogue::token(index);
            // EN 319 132-1: a signature timestamp covers the signature
            // value; a SigAndRefs timestamp also covers the signature
            // timestamps; an archive timestamp covers all of these, the
            // earlier archive timestamps and the incorporated validation
            // data. A RefsOnly timestamp covers the certificate and revocation
            // references alone (TS 101 903 V1.4.2 7.5.2), no object here,
            // and a content timestamp the signed data objects before signing
            // (EN 319 132-1 5.2.8), no object of the signature either.
            if matches!(
                role,
                TimestampRole::ReferencesOnly
                    | TimestampRole::AllDataObjects
                    | TimestampRole::IndividualDataObjects
            ) {
                let (current, past) = self.token_outcomes(der, intact, object, pasts)?;
                let Some(current) = current else {
                    continue;
                };
                record(each, current);
                tokens.push(long_term::Token {
                    object,
                    facts,
                    current,
                    covered: Vec::new(),
                    past,
                });
                continue;
            }
            let mut covered = vec![long_term::Covered::Direct(long_term::Catalogue::VALUE)];
            if index >= signature {
                covered.extend(
                    (0..signature).map(|other| {
                        long_term::Covered::Direct(long_term::Catalogue::token(other))
                    }),
                );
            }
            if index >= signature + validation {
                covered.extend(
                    (signature..signature + validation).map(|other| {
                        long_term::Covered::Direct(long_term::Catalogue::token(other))
                    }),
                );
                // The earlier archive timestamps are those before it in the
                // document, whatever their genTime says (two of one second
                // included), and so is the validation data it covers.
                covered.extend(
                    (signature + validation..index).map(|other| {
                        long_term::Covered::Direct(long_term::Catalogue::token(other))
                    }),
                );
                let at = declared
                    .archive_positions
                    .get(index - signature - validation)
                    .copied()
                    .unwrap_or(usize::MAX);
                covered.extend(
                    self.catalogue
                        .material_before(at)
                        .map(long_term::Covered::Direct),
                );
            }
            let (current, past) = self.token_outcomes(der, intact, object, pasts)?;
            let Some(current) = current else {
                continue;
            };
            record(each, current);
            tokens.push(long_term::Token {
                object,
                facts,
                current,
                covered,
                past,
            });
        }
        Ok(())
    }

    /// The current decision about token `der` (none when its TSA is not
    /// among the known certificates and its checks held) and the index of
    /// its TSA's past-validation inputs, appended to `pasts`.
    fn token_outcomes(
        &self,
        der: &[u8],
        intact: bool,
        object: long_term::Object,
        pasts: &mut Vec<long_term::Past>,
    ) -> Result<(Option<long_term::Decision>, Option<usize>), String> {
        let tsa = authority(der, self.parsed);
        let current = if !intact {
            Some(long_term::Decision::Finding(SubIndication::HashFailure))
        } else if let Some(tsa) = tsa {
            Some(long_term::Decision::from(authority_outcome(
                self.session,
                tsa,
                self.parsed,
                self.inputs,
                self.now,
                self.memory,
            )?))
        } else {
            None
        };
        let past = match tsa {
            Some(tsa) if current.is_some() => {
                let history = path_facts(
                    self.session,
                    tsa,
                    self.parsed,
                    self.inputs,
                    self.now,
                    self.memory,
                )?
                .history;
                pasts.push(long_term::past(object, tsa, &history, self.catalogue));
                Some(pasts.len() - 1)
            }
            _ => None,
        };
        Ok((current, past))
    }
}
