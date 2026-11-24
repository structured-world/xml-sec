//! The facts the EU DSS corpus comparison reads, through the public API under
//! one of the `XAdES` policy profiles.
//!
//! `corpus_probe conditions XML ANCHORS_DIR` writes, as `0.der`, `1.der`, ...
//! in `ANCHORS_DIR`, every certificate where a chain the document carries
//! ends, and prints the document's claimed signing time and whether it
//! carries a timestamp.
//!
//! `corpus_probe facts XML ANCHORS_DIR UNIX_TIME PROFILE` verifies the
//! document at that time with those certificates as the only trust anchors
//! and prints, for each Signature in document order, its verification outcome
//! and the `XAdES` facts of every baseline level. `PROFILE` is `xades`,
//! `xades-extended` or `xades-conformant`.
//!
//! The anchors, the time and the stated accuracy of tokens that omit theirs
//! (zero, the generation time read as exact) are conditions of the
//! comparison, the same ones the other validator receives, never a trust
//! decision. The policy is the compiled profile, narrowed only to check
//! X.509 chains at that time.

#[path = "support/tokens.rs"]
mod tokens;

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::validation::{Family, Hash};
use structured_pkix::Certificate;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::policy::{
    Instant, PolicyCompileContext, PolicyCompiler, PolicyProfile, VerificationPolicy,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, SignatureAlgorithm, SignatureEvidence,
    VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{Inputs, Level, Outcome, Requirements, validate, validate_basic};

type Failure = Box<dyn std::error::Error>;

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)))
}

/// Where the chain of `certificate` ends among `pool`: it is self-issued, or
/// `pool` holds no other certificate naming its issuer.
fn terminal(certificate: &[u8], pool: &[Vec<u8>]) -> bool {
    let account = account();
    let parser = Parser::der(account.clone());
    let Ok(parsed) = Certificate::read(&parser, certificate, 0) else {
        return false;
    };
    let issuer = parsed.tbs().issuer();
    let names = |other: &Certificate<'_>| {
        other
            .tbs()
            .subject()
            .matches(issuer, &account)
            .unwrap_or(false)
    };
    names(&parsed)
        || !pool
            .iter()
            .filter(|other| other.as_slice() != certificate)
            .filter_map(|other| Certificate::read(&parser, other, 0).ok())
            .any(|other| names(&other))
}

/// Every certificate the document and its tokens carry, once.
fn pool(text: &str) -> Vec<Vec<u8>> {
    let carried = tokens::values(text, "X509Certificate");
    // A token that cannot be read carries no certificate the comparison could
    // anchor; the verification reports the token itself.
    let authorities = tokens::token_authorities(text, &carried).unwrap_or_default();
    let mut pool = carried;
    pool.extend(authorities.into_iter().map(|(certificate, _)| certificate));
    pool.sort();
    pool.dedup();
    pool
}

/// The first `SigningTime` of the document as Unix seconds, if it has one in
/// the `xs:dateTime` form `YYYY-MM-DDThh:mm:ss[.fraction][Z|(+|-)hh:mm]`.
fn signing_time(text: &str) -> Option<i64> {
    let start = text.find("SigningTime>")? + "SigningTime>".len();
    let value = text[start..].split('<').next()?.trim();
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let zone = value[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let offset = match zone {
        "" | "Z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let hours: i64 = zone.get(1..3)?.parse().ok()?;
            let minutes: i64 = zone.get(4..6)?.parse().ok()?;
            sign * (hours * 3600 + minutes * 60)
        }
    };
    // Days from the civil date (proleptic Gregorian), as Howard Hinnant's
    // days_from_civil computes them.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    let days = era * 146_097 + of_cycle - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// The document's text for reading its ASCII values (base64, `SigningTime`,
/// IDs): a byte outside UTF-8, as in a Latin-1 document, becomes U+FFFD,
/// which none of those values contains. The verification parses the bytes.
fn ascii_view(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn conditions(xml: &str, anchors: &Path) -> Result<Value, Failure> {
    let text = ascii_view(&std::fs::read(xml)?);
    let pool = pool(&text);
    std::fs::create_dir_all(anchors)?;
    let ends: Vec<&Vec<u8>> = pool.iter().filter(|c| terminal(c, &pool)).collect();
    for (index, certificate) in ends.iter().enumerate() {
        std::fs::write(anchors.join(format!("{index}.der")), certificate)?;
    }
    Ok(json!({
        "anchors": ends.len(),
        "signing_time": signing_time(&text),
        "timestamps": text.contains("EncapsulatedTimeStamp"),
    }))
}

/// The variant name of a debug rendering: its first identifier.
fn kind(debug: &str) -> String {
    debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The `Id` of every `ds:Signature` in document order.
fn signature_ids(text: &str) -> Vec<Option<String>> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "Signature"
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
        })
        .map(|node| node.attribute("Id").map(str::to_owned))
        .collect()
}

/// A same-document object a data `Reference` names.
#[derive(Clone, PartialEq, Eq)]
enum Target {
    /// The whole document: `URI=""` or `#xpointer(/)`.
    Root,
    /// The element with this ID: `#name` or `#xpointer(id('name'))`.
    Id(String),
}

/// What every `Signature`'s data `Reference`s name in the document, the
/// `SignedProperties` reference excluded: the objects a validator reports as
/// the signature's scope, which the strict profile needs as expected targets.
fn targets(text: &str) -> Vec<Target> {
    const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let references = document.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Reference"
            && node.tag_name().namespace() == Some(DS)
            && node.parent_element().is_some_and(|parent| {
                parent.tag_name().name() == "SignedInfo"
                    && parent.tag_name().namespace() == Some(DS)
            })
            && node.attribute("Type") != Some("http://uri.etsi.org/01903#SignedProperties")
    });
    for reference in references {
        let target = match reference.attribute("URI") {
            Some("" | "#xpointer(/)") => Target::Root,
            Some(uri) => {
                let Some(fragment) = uri.strip_prefix('#') else {
                    continue;
                };
                let id = fragment
                    .strip_prefix("xpointer(id('")
                    .and_then(|rest| rest.strip_suffix("'))"))
                    .unwrap_or(fragment);
                Target::Id(id.to_owned())
            }
            None => continue,
        };
        if !found.contains(&target) {
            found.push(target);
        }
    }
    found
}

/// Whether every requirement of the requested level holds.
fn met(level: &Level<'_>) -> bool {
    level.all_requirements_met()
}

/// A level outcome, or the typed refusal that stopped it.
fn level<E: std::fmt::Debug>(result: Result<Outcome<bool>, E>) -> Value {
    match result {
        Ok(Outcome::Assessed(met)) => json!({ "assessed": met }),
        Ok(outcome) => {
            json!({ "negative": kind(&format!("{outcome:?}")), "detail": format!("{outcome:?}") })
        }
        Err(error) => {
            let debug = format!("{error:?}");
            json!({ "error": kind(&debug), "detail": debug })
        }
    }
}

/// The `XAdES` profile a comparison names.
fn named_profile(name: &str) -> Result<PolicyProfile, Failure> {
    Ok(match name {
        "xades" => PolicyProfile::Xades,
        "xades-extended" => PolicyProfile::XadesExtended,
        "xades-conformant" => PolicyProfile::XadesConformant,
        _ => return Err(format!("unknown profile {name}").into()),
    })
}

/// The compiled `profile` at time `at`, narrowed to check X.509 chains when
/// `chains` is set; without it a key the resolver trusts directly is the only
/// key accepted, which establishes integrity apart from any path.
fn profile_policy(
    profile: PolicyProfile,
    at: i64,
    chains: bool,
) -> Result<VerificationPolicy, Failure> {
    let profile = PolicyCompiler::new(profile, &RustCryptoProvider, None)?;
    let mut layer = profile.policies().clone();
    if let Some(verification) = layer.verification.as_mut() {
        verification.key_trust.verify_x509_chains = chains;
        verification.key_trust.verification_time =
            Some(Instant::new(at, 0).ok_or("the time is out of range")?);
    }
    let snapshot = profile.restrict(&layer)?.compile(&PolicyCompileContext {
        external_resources: false,
        target_evidence: true,
    })?;
    Ok(snapshot
        .verification()
        .ok_or("the XAdES profiles verify")?
        .clone())
}

/// One signature's `XMLDSig` outcome: its status, key trust and references,
/// or the typed refusal that stopped it.
fn verification(entry: &SignatureEvidence) -> Value {
    match entry.result() {
        Ok(result) => json!({
            "status": format!("{:?}", result.status),
            "trust": kind(&format!("{:?}", result.key_trust)),
            "references": result
                .signed_info_references
                .iter()
                .map(|reference| format!("{:?}", reference.status))
                .collect::<Vec<_>>(),
        }),
        Err(error) => {
            let debug = format!("{error:?}");
            json!({ "error": kind(&debug), "detail": error.to_string() })
        }
    }
}

fn facts(xml: &str, anchors: &Path, at: i64, profile: PolicyProfile) -> Result<Value, Failure> {
    let bytes = std::fs::read(xml)?;
    let text = ascii_view(&bytes);
    let mut trusted = Vec::new();
    for entry in std::fs::read_dir(anchors)? {
        trusted.push(std::fs::read(entry?.path())?);
    }
    trusted.sort();
    let carried = pool(&text);
    let policy = profile_policy(profile, at, true)?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: trusted.clone(),
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = match XmlDocument::parse_bytes(&bytes) {
        Ok(document) => document,
        Err(error) => return Ok(json!({ "parse": error.to_string() })),
    };
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let authorities = tokens::token_authorities(&text, &carried).unwrap_or_default();
    let accuracies = tokens::stated(&authorities, 0)?;
    let anchor_refs: Vec<&[u8]> = trusted.iter().map(Vec::as_slice).collect();
    let others: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
    let caller: Vec<&[u8]> = anchor_refs.iter().chain(&others).copied().collect();
    let inputs = |requirements| Inputs {
        requirements,
        anchors: &anchor_refs,
        certificates: &others,
        utc: &utc,
        accuracies: &accuracies,
        responders: &[],
        crls: &[],
        responses: &[],
    };
    let ids = signature_ids(&text);
    let mut signatures = Vec::new();
    let account = account();
    // A target the document does not resolve, or a signature over detached
    // data alone, leaves the whole document as the expected target.
    let expected: Vec<_> = document.with_view(|view| {
        let mut found: Vec<_> = targets(&text)
            .into_iter()
            .filter_map(|target| match target {
                Target::Root => Some(view.root_element()),
                Target::Id(id) => view.node_for_id(&id, &[]),
            })
            .collect();
        if found.is_empty() {
            found.push(view.root_element());
        }
        found.dedup();
        found
    });
    let request = VerificationRequest {
        expected_targets: &expected,
        ..VerificationRequest::default()
    };
    // EN 319 102-1 5.2.7 establishes integrity with the signing certificate's
    // key whatever its path: every certificate the document carries is
    // trusted directly, so the references and value are checked even where
    // no path validates at `at`.
    let direct = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: carried.clone(),
        ..KeyResolverConfig::default()
    });
    let integrity_context = VerifyContext::new()
        .policy(profile_policy(profile, at, false)?)
        .key_resolver(&direct);
    let mut integrity = Vec::new();
    let integrity_run = with_verified_request(
        &document,
        &integrity_context,
        &request,
        &account,
        |session| {
            for entry in session.evidence().signatures() {
                integrity.push(verification(entry));
            }
            Ok(())
        },
    );
    let verified = with_verified_request(&document, &context, &request, &account, |session| {
        let entries = session.evidence().signatures();
        // Ids are reported only when both readings see the same signatures.
        let aligned = ids.len() == entries.len();
        for (index, entry) in entries.iter().enumerate() {
            let mut row = json!({
                "index": index,
                "id": if aligned { ids[index].clone() } else { None },
                "verification": verification(entry),
                "integrity": integrity.get(index).cloned().unwrap_or(Value::Null),
            });
            if entry.result().is_ok() {
                let identity = entry.identity();
                row["basic"] = match validate_basic(&session, identity, &caller, |report| {
                    (
                        report.inputs().certificate.is_bound(),
                        report.included().is_some(),
                        report.all_root_requirements_met(),
                    )
                }) {
                    Ok(Outcome::Assessed((bound, included, met))) => {
                        json!({ "bound": bound, "included": included, "assessed": met })
                    }
                    other => level(other.map(|outcome| outcome.map(|_| false))),
                };
                for (name, requirements) in [
                    ("timestamped", Requirements::Timestamped),
                    ("long_term", Requirements::LongTerm),
                    ("archival", Requirements::Archival),
                ] {
                    row[name] = level(validate(&session, identity, &inputs(requirements), met));
                }
            }
            signatures.push(row);
        }
        Ok(())
    });
    let mut facts = json!({ "signatures": signatures });
    if let Err(error) = integrity_run {
        let debug = format!("{error:?}");
        facts["integrity_request"] = json!({ "error": kind(&debug), "detail": error.to_string() });
    }
    if let Err(error) = verified {
        let debug = format!("{error:?}");
        facts["request"] = json!({ "error": kind(&debug), "detail": error.to_string() });
    }
    Ok(facts)
}

/// The hash a digest method computes, as cryptographic constraints name it.
fn hash_of(digest: DigestAlgorithm) -> Option<Hash> {
    Some(match digest {
        DigestAlgorithm::Sha1 => Hash::Sha1,
        DigestAlgorithm::Sha224 => Hash::Sha224,
        DigestAlgorithm::Sha256 => Hash::Sha256,
        DigestAlgorithm::Sha384 => Hash::Sha384,
        DigestAlgorithm::Sha512 => Hash::Sha512,
        DigestAlgorithm::Sha3_256 => Hash::Sha3_256,
        DigestAlgorithm::Sha3_384 => Hash::Sha3_384,
        DigestAlgorithm::Sha3_512 => Hash::Sha3_512,
        // SHA3-224 has no TS 119 312 entry nor DSS name.
        DigestAlgorithm::Sha3_224 => return None,
    })
}

/// The family and message hash of a fixed asymmetric signature method.
/// Parameterized RSA-PSS, HMAC, the prehashed and context `EdDSA` variants
/// and post-quantum methods have no entry in either constraint vocabulary.
fn suite_of(algorithm: SignatureAlgorithm) -> Option<(Family, Option<Hash>)> {
    use SignatureAlgorithm as S;
    let (family, digest) = match algorithm {
        S::Ed25519 => return Some((Family::Ed25519, None)),
        S::Ed448 => return Some((Family::Ed448, None)),
        S::DsaSha1 => (Family::Dsa, DigestAlgorithm::Sha1),
        S::DsaSha256 => (Family::Dsa, DigestAlgorithm::Sha256),
        S::RsaSha1 => (Family::RsaPkcs1, DigestAlgorithm::Sha1),
        S::RsaSha224 => (Family::RsaPkcs1, DigestAlgorithm::Sha224),
        S::RsaSha256 => (Family::RsaPkcs1, DigestAlgorithm::Sha256),
        S::RsaSha384 => (Family::RsaPkcs1, DigestAlgorithm::Sha384),
        S::RsaSha512 => (Family::RsaPkcs1, DigestAlgorithm::Sha512),
        S::RsaPssSha1 => (Family::RsaPss, DigestAlgorithm::Sha1),
        S::RsaPssSha224 => (Family::RsaPss, DigestAlgorithm::Sha224),
        S::RsaPssSha256 => (Family::RsaPss, DigestAlgorithm::Sha256),
        S::RsaPssSha384 => (Family::RsaPss, DigestAlgorithm::Sha384),
        S::RsaPssSha512 => (Family::RsaPss, DigestAlgorithm::Sha512),
        S::RsaPssSha3_256 => (Family::RsaPss, DigestAlgorithm::Sha3_256),
        S::RsaPssSha3_384 => (Family::RsaPss, DigestAlgorithm::Sha3_384),
        S::RsaPssSha3_512 => (Family::RsaPss, DigestAlgorithm::Sha3_512),
        S::EcdsaSha1 => (Family::Ecdsa, DigestAlgorithm::Sha1),
        S::EcdsaSha224 => (Family::Ecdsa, DigestAlgorithm::Sha224),
        S::EcdsaSha256 => (Family::Ecdsa, DigestAlgorithm::Sha256),
        S::EcdsaSha384 => (Family::Ecdsa, DigestAlgorithm::Sha384),
        S::EcdsaSha512 => (Family::Ecdsa, DigestAlgorithm::Sha512),
        S::EcdsaSha3_256 => (Family::Ecdsa, DigestAlgorithm::Sha3_256),
        S::EcdsaSha3_384 => (Family::Ecdsa, DigestAlgorithm::Sha3_384),
        S::EcdsaSha3_512 => (Family::Ecdsa, DigestAlgorithm::Sha3_512),
        _ => return None,
    };
    Some((family, Some(hash_of(digest)?)))
}

/// What a compiled profile accepts, in the vocabulary both comparisons
/// share: the `SignatureValue` suites, the `Reference` digests and the
/// smallest key of each family, signer and issuer keys alike.
struct Catalogue {
    suites: Vec<(Family, Option<Hash>)>,
    digests: Vec<Hash>,
    minimum_bits: Vec<(Family, u32)>,
}

fn catalogue(policy: &VerificationPolicy) -> Result<Catalogue, Failure> {
    let mut suites: Vec<_> = SignatureAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| policy.check_signature_algorithm(*algorithm).is_ok())
        .filter_map(suite_of)
        .collect();
    suites.dedup();
    let digests = DigestAlgorithm::ALL
        .into_iter()
        .filter(|digest| policy.check_digest_algorithm(*digest).is_ok())
        .filter_map(hash_of)
        .collect();
    let rsa = u32::try_from(policy.key_trust.rsa_keys.minimum_modulus_bits)?;
    let dsa = u32::try_from(policy.key_trust.dsa_keys.minimum_modulus_bits)?;
    Ok(Catalogue {
        suites,
        digests,
        // The provider implements P-256 and larger curves only, and the fixed
        // EdDSA variants have no size dimension.
        minimum_bits: vec![
            (Family::RsaPkcs1, rsa),
            (Family::RsaPss, rsa),
            (Family::Dsa, dsa),
            (Family::Ecdsa, 256),
            (Family::Ed25519, 0),
            (Family::Ed448, 0),
        ],
    })
}

/// DSS's name of a signature family (`EncryptionAlgorithm`).
fn dss_family(family: Family) -> &'static str {
    match family {
        Family::RsaPkcs1 => "RSA",
        Family::RsaPss => "RSASSA-PSS",
        Family::Dsa => "DSA",
        Family::Ecdsa => "ECDSA",
        Family::Ed25519 | Family::Ed448 => "EdDSA",
        Family::Other => "other",
    }
}

/// DSS's name of a hash function (`DigestAlgorithm`).
fn dss_hash(hash: Hash) -> &'static str {
    match hash {
        Hash::Md5 => "MD5",
        Hash::Sha1 => "SHA1",
        Hash::Sha224 => "SHA224",
        Hash::Sha256 => "SHA256",
        Hash::Sha384 => "SHA384",
        Hash::Sha512 => "SHA512",
        Hash::Sha3_256 => "SHA3-256",
        Hash::Sha3_384 => "SHA3-384",
        Hash::Sha3_512 => "SHA3-512",
        Hash::Ripemd160 => "RIPEMD160",
        Hash::Whirlpool => "WHIRLPOOL",
        Hash::Other => "other",
    }
}

/// The profile's constraints in DSS's policy vocabulary, for the harness to
/// write the DSS validation policy both comparisons run under.
fn constraints(profile: PolicyProfile) -> Result<Value, Failure> {
    let catalogue = catalogue(&profile_policy(profile, INSTANT_ANY, true)?)?;
    let mut families: Vec<&str> = catalogue
        .suites
        .iter()
        .map(|(family, _)| dss_family(*family))
        .collect();
    families.sort_unstable();
    families.dedup();
    let mut hashes: Vec<&str> = catalogue
        .suites
        .iter()
        .filter_map(|(_, hash)| *hash)
        .chain(catalogue.digests.iter().copied())
        .map(dss_hash)
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    let minimum: Map<String, Value> = catalogue
        .minimum_bits
        .iter()
        .filter(|(family, _)| families.contains(&dss_family(*family)))
        .map(|(family, bits)| (dss_family(*family).to_owned(), json!(bits)))
        .collect();
    Ok(json!({
        "signature": { "families": families, "hashes": hashes },
        "minimum_bits": minimum,
    }))
}

/// Any time inside the compiled policies' range: the constraints a profile
/// accepts do not depend on it.
const INSTANT_ANY: i64 = 1_800_000_000;

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().collect();
    let result = match &args[1..] {
        [mode, profile] if mode == "constraints" => constraints(named_profile(profile)?)?,
        [mode, xml, anchors] if mode == "conditions" => conditions(xml, Path::new(anchors))?,
        [mode, xml, anchors, at, profile] if mode == "facts" => facts(
            xml,
            Path::new(anchors),
            at.parse()?,
            named_profile(profile)?,
        )?,
        _ => {
            return Err("usage: corpus_probe constraints PROFILE | conditions XML ANCHORS_DIR | facts XML ANCHORS_DIR UNIX_TIME PROFILE, PROFILE xades|xades-extended|xades-conformant".into());
        }
    };
    println!("{result}");
    Ok(())
}
