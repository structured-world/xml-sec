//! The ETSI EN 319 102-1 V1.4.1 status indication of one corpus signature.
//!
//! The shared `structured_ltv::validation` process decides it; this module
//! only establishes its inputs: integrity through xml-sec's own
//! verification, the signing certificate through its signed reference
//! (clause 5.2.3), certification paths and revocation status through the
//! shared PKIX and LTV mechanisms with the verification's own verifiers, and
//! the cryptographic material the profile's constraints judge.

use serde_json::{Value, json};
use structured_asn1::memory::Memory;
use structured_ltv::pki::status::{self as revocation, Query, Responder, Source, Status};
use structured_ltv::pki::{CheckedPath, CrlAuthority, PathOutcome};
use structured_ltv::validation::{
    Anchor as Trust, Chain, Changes, Context, Element, Elements, Facts, Family, Format, Hash,
    Material, Order, Path as EtsiPath, Recognition, Reference, Requirements, RevocationIssuer,
    Scheme, Signer, Time, Value as Computed,
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
}

/// The conditions and constraints every signature of one comparison shares.
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
/// refused it with `trust`: a structural refusal is a format failure
/// (clause 5.3.4 step 1), and a transform, URI or bound refusal is a
/// constraint of that profile, which clause 5.2.8 applies last, so it
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
        _ if detail.contains("unsupported algorithm") => {
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
        "Policy" if structural => verdict("TOTAL_FAILED", Some("FORMAT_FAILURE"), detail),
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
            // A reference left unprocessed because the value failed has no
            // finding of its own (the value's decides the block).
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
}

fn parse<'a>(parser: &'a structured_asn1::Parser, inputs: &'a Inputs<'_>) -> Parsed<'a> {
    let certificates = |list: &'a [Vec<u8>]| -> Vec<Certificate<'a>> {
        list.iter()
            .filter_map(|bytes| Certificate::read(parser, bytes, 0).ok())
            .collect()
    };
    let query = parser.read(&[], 0).ok();
    let responses = inputs
        .responses
        .iter()
        .filter_map(|bytes| match Response::read(parser, bytes, 0).ok()? {
            Response::Successful(body) => body.basic_in(query.as_ref()?).ok()?,
            // A protocol failure carries no signed status (RFC 6960 4.2.1).
            Response::Failure { .. } => None,
        })
        .collect();
    Parsed {
        pool: certificates(inputs.pool),
        anchors: certificates(inputs.anchors),
        crls: inputs
            .crls
            .iter()
            .filter_map(|bytes| CertificateList::read(parser, bytes, 0).ok())
            .collect(),
        responses,
    }
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

/// Every prospective chain (clause 5.2.6.4 step 2) from `signer` to an
/// anchor: each issuer named by the subject before it, with no condition on
/// time. The shared builder holds every certificate to one interval, which
/// is step 4's and step 7's check, not step 2's; `check` then validates each
/// chain in full.
fn candidates<'a>(
    signer: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    memory: &Memory,
) -> Vec<Candidate<'a>> {
    fn names(subject: &Certificate<'_>, issuer: &Certificate<'_>, memory: &Memory) -> bool {
        subject
            .tbs()
            .issuer()
            .matches(issuer.tbs().subject(), memory)
            .unwrap_or(false)
    }
    fn extend<'a>(
        chain: &mut Vec<&'a Certificate<'a>>,
        parsed: &'a Parsed<'a>,
        memory: &Memory,
        found: &mut Vec<Candidate<'a>>,
    ) {
        let last = *chain.last().expect("a chain starts at the signer");
        for anchor in &parsed.anchors {
            if anchor.as_bytes() != last.as_bytes() && names(last, anchor, memory) {
                found.push((chain.clone(), anchor));
            }
        }
        if chain.len() >= CHAIN_DEPTH {
            return;
        }
        for issuer in &parsed.pool {
            let used = chain
                .iter()
                .any(|member| member.as_bytes() == issuer.as_bytes());
            let anchored = parsed
                .anchors
                .iter()
                .any(|anchor| anchor.as_bytes() == issuer.as_bytes());
            if !used && !anchored && names(last, issuer, memory) {
                chain.push(issuer);
                extend(chain, parsed, memory, found);
                chain.pop();
            }
        }
    }
    let mut found = Vec::new();
    extend(&mut vec![signer], parsed, memory, &mut found);
    found
}

/// `chain` checked by the shared processor over `at` with the
/// verification's own certificate verifier.
fn check<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    at: Instant,
    memory: &Memory,
) -> Option<CheckedPath<'a>> {
    checked(session, chain, anchor, at, memory).ok()
}

/// [`check`], with the reason a chain was not accepted.
fn checked<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    at: Instant,
    memory: &Memory,
) -> Result<CheckedPath<'a>, String> {
    let verifier = session.certificate_path_verifier(chain, anchor);
    let context = ValidationContext {
        execution: memory,
        interval: Interval::at_instant(at),
        policy: Policy::default(),
        bounds: session.certificate_path_bounds(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    match structured_ltv::pki::check_path(chain, Anchor::from_certificate(anchor), &context) {
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
) -> (Status, Vec<RevocationIssuer>) {
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
    match revocation::assess(path, member, &sources, &query, &context, &verifier, &digest) {
        Ok(assessment) => {
            let issuers = assessment
                .statements()
                .iter()
                .filter_map(|statement| match statement.authentication? {
                    revocation::Authentication::Crl { signer, .. }
                    | revocation::Authentication::Ocsp { signer, .. } => Some(signer),
                })
                .map(|signer| {
                    let (not_before, not_after) = validity(signer);
                    RevocationIssuer {
                        not_before,
                        not_after,
                    }
                })
                .collect();
            (assessment.status(), issuers)
        }
        Err(_) => (Status::NoEvidence, Vec::new()),
    }
}

/// Every checked path that ends at a CA member of `path` or at a responder
/// a response carries: the authorities a status may be signed under.
fn authority_paths<'a, W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'a Certificate<'a>],
    anchor: &'a Certificate<'a>,
    parsed: &'a Parsed<'a>,
    at: Instant,
    memory: &Memory,
) -> Vec<CheckedPath<'a>> {
    let mut found = Vec::new();
    // The CA members, each with the part of the chain above it.
    for start in 1..chain.len() {
        if let Some(path) = check(session, &chain[start..], anchor, at, memory) {
            found.push(path);
        }
    }
    // Delegated responders the responses carry, issued by a chain member or
    // the anchor (RFC 6960 4.2.2.2).
    for response in &parsed.responses {
        for responder in response.certificates() {
            // Below each CA member, or directly below the anchor.
            for start in 1..=chain.len() {
                let mut delegated = vec![responder];
                delegated.extend_from_slice(&chain[start..]);
                if let Some(path) = check(session, &delegated, anchor, at, memory) {
                    found.push(path);
                    break;
                }
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
    /// Why each rejected chain was rejected, for review.
    rejections: Vec<String>,
}

impl PathFacts {
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
) -> PathFacts {
    let mut facts = PathFacts {
        chains: Vec::new(),
        statuses: Vec::new(),
        materials: Vec::new(),
        issuers: Vec::new(),
        signer_status: Status::NoEvidence,
        rejections: Vec::new(),
    };
    if parsed
        .anchors
        .iter()
        .any(|anchor| anchor.as_bytes() == signer.as_bytes())
    {
        // RFC 5280 6.1.1(d): a trust anchor is an input, not a path member,
        // so it has neither a revocation status nor issuer material here;
        // its validity is still the signing certificate's (step 7).
        facts.chains.push(Chain::Valid);
        facts.statuses.push(Vec::new());
        facts.materials.push(Vec::new());
        facts.issuers.push(Vec::new());
        facts.signer_status = Status::NotRevoked {
            basis: 0,
            later: None,
        };
        return facts;
    }
    let (not_before, not_after) = validity(signer);
    // Clause 5.2.6.4 step 4 validates the chain apart from the signing
    // certificate's own validity period, which step 7 checks: the chain is
    // checked inside that period, and every other member is held to `now`
    // (shell model).
    let chain_time = now.max(not_before).min(not_after);
    let mut accepted = false;
    for (chain, anchor) in candidates(signer, parsed, memory) {
        let checked = match checked(session, &chain, anchor, chain_time, memory) {
            Ok(checked) => checked,
            Err(reason) => {
                facts.rejected(reason);
                continue;
            }
        };
        if !chain.iter().skip(1).all(|member| {
            let (from, until) = validity(member);
            from <= now && now <= until
        }) {
            facts.rejected("a CA member is outside its validity at the validation time".into());
            continue;
        }
        let authorities = authority_paths(session, &chain, anchor, parsed, chain_time, memory);
        let count = checked.members().len();
        let mut own_signer = Status::NoEvidence;
        let (mut statuses, mut issuers, mut materials) = (Vec::new(), Vec::new(), Vec::new());
        for member in 0..count {
            let (status, used) = status_of(
                session,
                &checked,
                member,
                parsed,
                &authorities,
                inputs,
                now,
                memory,
            );
            issuers.extend(used);
            if member + 1 == count {
                own_signer = status;
            } else {
                statuses.push(status);
            }
            // The issuer's key signed this member: its scheme is the
            // certificate's material (clause 5.2.6.4 step 6). Certificate
            // hashes are not restricted by the profiles.
            let issuer = member
                .checked_sub(1)
                .map_or(anchor, |previous| checked.members()[previous].certificate());
            materials.push(Material {
                hash: None,
                scheme: Some(scheme_of(issuer, Family::RsaPkcs1, memory).unwrap_or(UNKNOWN_SCHEME)),
            });
        }
        if !accepted {
            facts.signer_status = own_signer;
        }
        // Step 4 includes revocation checking for each certificate of the
        // chain; with no status at all RFC 5280 6.1.3(a)(3) is not
        // established, so path validation fails "with any other reason"
        // (step 4(e)), while a status that exists but is stale or on hold is
        // the process's own TRY_LATER (steps 4(a) and 4(c)).
        let undetermined = statuses
            .iter()
            .chain([&own_signer])
            .any(|status| matches!(status, Status::NoEvidence));
        facts.chains.push(if undetermined {
            Chain::GeneralFailure
        } else {
            Chain::Valid
        });
        facts.statuses.push(statuses);
        facts.issuers.push(issuers);
        facts.materials.push(materials);
        accepted = true;
    }
    facts
}

/// The signature value's material (its suite, sized by the signing
/// certificate's key) and each reference digest's, for clause 5.2.8.
fn own_materials(declared: &Declared, signer: &Certificate<'_>, memory: &Memory) -> Vec<Material> {
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
            hash: Some(digest.map_or(Hash::Other, hash_of)),
            scheme: None,
        });
    }
    materials
}

/// The ETSI indication of one signature verified in `session` (whose policy
/// trusts every carried key directly, so `result` is its integrity alone).
pub fn indication<W: structured_asn1::memory::Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    result: &Result<VerifyResult, xml_sec::xmldsig::DsigError>,
    declared: &Declared,
    inputs: &Inputs<'_>,
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
    let paths = path_facts(session, signer, &parsed, inputs, now, &memory);
    let etsi_paths: Vec<EtsiPath<'_>> = paths
        .chains
        .iter()
        .enumerate()
        .map(|(index, chain)| EtsiPath {
            chain: *chain,
            anchor: Trust {
                current: Recognition::Recognized,
                over_interval: Recognition::Recognized,
            },
            authorities: &paths.statuses[index],
            materials: &paths.materials[index],
            revocation_issuers: &paths.issuers[index],
            revocation_retry: None,
        })
        .collect();
    let (references, value) = integrity(result);
    let materials = own_materials(declared, signer, &memory);
    let mut elements = Elements::NONE;
    if declared.signing_time.is_some() {
        elements = elements.with(Element::ClaimedSigningTime);
    }
    if !declared.certificate_references.is_empty() {
        elements = elements.with(Element::SigningCertificate);
    }
    let facts = Facts {
        format: Format::Conformant,
        context: Context::Ready,
        signer: Some(Signer {
            not_before,
            not_after,
            revocation: paths.signer_status,
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
        signature_timestamp: false,
        signature_timestamps: &[],
        claimed_signing_time: declared.signing_time.map(instant),
        utc: Some(inputs.utc),
        changes: Changes::NotApplicable,
        now,
    };
    match structured_ltv::validation::validate(&facts, inputs.requirements, &memory) {
        Ok(outcome) => {
            let indication = screaming(&format!("{:?}", outcome.indication));
            let sub = outcome.sub.map(|sub| {
                let debug = format!("{sub:?}");
                if debug.starts_with("Custom") {
                    "CUSTOM".to_owned()
                } else {
                    screaming(&debug)
                }
            });
            json!({
                "indication": indication,
                "sub": sub,
                "basis": outcome.basis.map(|basis| format!("{basis:?}")),
                "chains": format!("{:?}", paths.chains),
                "rejections": paths.rejections,
                "revocation": format!("{:?} {:?}", paths.signer_status, paths.statuses),
            })
        }
        Err(error) => verdict("INDETERMINATE", Some("CUSTOM"), format!("{error:?}")),
    }
}
