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

#[path = "support/etsi.rs"]
mod etsi;
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
use xml_sec::document::NodeIdentity;
use xml_sec::policy::{
    Instant, PolicyCompileContext, PolicyCompiler, PolicyProfile, SignatureConstraints,
    TrustAnchorSigner, VerificationPolicy,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::UriTypeSet;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, KeyInfo, KeyInfoSource, KeyResolver,
    KeyResolverConfig, ResolvedVerificationKey, SignatureAlgorithm, SignatureEvidence,
    VerificationKey, VerificationRequest, VerifyContext, VerifyingKey, with_verified_request,
};
use xml_sec_xades::{
    EnclosingError, Inputs, Level, Outcome, Requirements, ValidationError, validate, validate_basic,
};

type Failure = Box<dyn std::error::Error>;

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)))
}

/// Whether the key of `certificate` decodes as its algorithm defines it. A
/// trust anchor's public key is part of its information (RFC 5280 §6.1.1
/// (d)), so a certificate whose key does not decode anchors nothing for
/// either validator.
fn readable_key(certificate: &Certificate<'_>, account: &Memory) -> bool {
    use structured_pkix::key::{ec, rsa};
    let info = certificate.tbs().public_key();
    let algorithm = info.algorithm().algorithm();
    if algorithm == structured_pkix::oid::EC_PUBLIC_KEY {
        ec::read(structured_pkix::path::EffectiveKey::standing(info), account).is_ok()
    } else if algorithm == structured_pkix::oid::RSA_ENCRYPTION
        || algorithm == structured_pkix::oid::RSASSA_PSS
    {
        rsa::read(info, account).is_ok()
    } else {
        true
    }
}

/// Where the chain of `certificate` ends among `pool`: it is self-issued, or
/// `pool` holds no other certificate naming its issuer. Only a certificate
/// whose key decodes is such an end.
fn terminal(certificate: &[u8], pool: &[Vec<u8>]) -> bool {
    let account = account();
    let parser = Parser::der(account.clone());
    let Ok(parsed) = Certificate::read(&parser, certificate, 0) else {
        return false;
    };
    if !readable_key(&parsed, &account) {
        return false;
    }
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
    date_time(text[start..].split('<').next()?.trim())
}

/// An `xs:dateTime` value as Unix seconds.
fn date_time(value: &str) -> Option<i64> {
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

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// What each `ds:Signature` declares, in document order: the elements that
/// belong to it and to no signature nested inside it.
fn declarations(text: &str) -> Vec<etsi::Declared> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    let is = |node: &roxmltree::Node<'_, '_>, name: &str| {
        node.is_element() && node.tag_name().name() == name
    };
    let is_signature = |node: &roxmltree::Node<'_, '_>| {
        is(node, "Signature") && node.tag_name().namespace() == Some(DS)
    };
    let base64 = |node: roxmltree::Node<'_, '_>| -> Option<Vec<u8>> {
        let compact: String = node
            .text()
            .unwrap_or_default()
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        structured_base64::STANDARD.decode(compact.as_bytes()).ok()
    };
    let mut found = Vec::new();
    for signature in document.descendants().filter(is_signature) {
        let own: Vec<_> = signature
            .descendants()
            .skip(1)
            .filter(|node| node.ancestors().skip(1).find(is_signature) == Some(signature))
            .collect();
        let mut declared = etsi::Declared::default();
        for node in &own {
            if is(node, "SignatureMethod") {
                declared.method = node
                    .attribute("Algorithm")
                    .and_then(SignatureAlgorithm::from_uri);
            } else if is(node, "DigestMethod")
                && node
                    .parent()
                    .is_some_and(|reference| is(&reference, "Reference"))
                && node
                    .parent()
                    .and_then(|reference| reference.parent())
                    .is_some_and(|info| is(&info, "SignedInfo"))
            {
                declared.digests.push(
                    node.attribute("Algorithm")
                        .and_then(DigestAlgorithm::from_uri),
                );
            } else if is(node, "SigningTime") {
                declared.signing_time = date_time(node.text().unwrap_or_default().trim());
            } else if is(node, "CertDigest") {
                let method = node
                    .children()
                    .find(|child| is(child, "DigestMethod"))
                    .and_then(|method| method.attribute("Algorithm"))
                    .and_then(DigestAlgorithm::from_uri);
                if let Some(value) = node
                    .children()
                    .find(|child| is(child, "DigestValue"))
                    .and_then(base64)
                {
                    declared.certificate_references.push((method, value));
                }
            } else if is(node, "X509Certificate")
                && node.ancestors().any(|ancestor| is(&ancestor, "KeyInfo"))
            {
                declared.key_info.extend(base64(*node));
            } else if is(node, "EncapsulatedTimeStamp") {
                let list = match node.parent().map(|parent| parent.tag_name().name()) {
                    Some("SignatureTimeStamp") => &mut declared.signature_timestamps,
                    Some("SigAndRefsTimeStamp" | "RefsOnlyTimeStamp") => {
                        &mut declared.validation_timestamps
                    }
                    Some("ArchiveTimeStamp") => &mut declared.archive_timestamps,
                    _ => continue,
                };
                list.extend(base64(*node));
            }
        }
        found.push(declared);
    }
    found
}

/// The profile's constraints in the ETSI process's vocabulary, owned: none
/// of them expires, as the profiles have no time dimension.
struct Rules {
    hashes: Vec<structured_ltv::validation::HashRule>,
    schemes: Vec<structured_ltv::validation::SchemeRule>,
    suites: Vec<(Family, Vec<Hash>)>,
}

impl Rules {
    /// `then` over these rules as the ETSI process's requirements.
    fn lend<R>(&self, then: impl FnOnce(&structured_ltv::validation::Requirements<'_>) -> R) -> R {
        let suites: Vec<structured_ltv::validation::SuiteRule<'_>> = self
            .suites
            .iter()
            .map(|(family, hashes)| structured_ltv::validation::SuiteRule {
                family: *family,
                key_bits: None,
                hashes,
            })
            .collect();
        then(&structured_ltv::validation::Requirements {
            crypto: structured_ltv::validation::Constraints {
                hashes: &self.hashes,
                schemes: &self.schemes,
                suites: &suites,
                rsa_exponent_bits: None,
            },
            // DSS's policy fails a signature without a claimed signing time
            // (`SigningTime Level="FAIL"`); no other element is required.
            elements: structured_ltv::validation::Elements::NONE
                .with(structured_ltv::validation::Element::ClaimedSigningTime),
            timestamp_delay: None,
        })
    }
}

fn rules(catalogue: &Catalogue) -> Rules {
    let mut hashes: Vec<Hash> = catalogue.digests.clone();
    hashes.extend(catalogue.suites.iter().filter_map(|(_, hash)| *hash));
    hashes.dedup();
    let mut suites: Vec<(Family, Vec<Hash>)> = Vec::new();
    for (family, hash) in &catalogue.suites {
        let entry = if let Some(entry) = suites.iter_mut().find(|(known, _)| known == family) {
            entry
        } else {
            suites.push((*family, Vec::new()));
            suites.last_mut().expect("just pushed")
        };
        entry.1.extend(*hash);
    }
    Rules {
        hashes: hashes
            .into_iter()
            .map(|hash| structured_ltv::validation::HashRule { hash, until: None })
            .collect(),
        // Every family keeps its minimum: certificates are restricted by key
        // size alone, while the suites below restrict the signature itself.
        schemes: catalogue
            .minimum_bits
            .iter()
            .map(|(family, bits)| structured_ltv::validation::SchemeRule {
                family: *family,
                min_bits: *bits,
                // DSA's subgroup is sized as TS 119 312 Table D.2 sizes the
                // discontinued 1024-bit tier.
                min_subgroup_bits: if *family == Family::Dsa { 160 } else { 0 },
                until: None,
            })
            .collect(),
        suites,
    }
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
            // EN 319 132-1 §4.4.2 and TS 101 903 V1.2.2 §6.3.1 type it.
            && !matches!(
                node.attribute("Type"),
                Some(
                    "http://uri.etsi.org/01903#SignedProperties"
                        | "http://uri.etsi.org/01903/v1.2.2#SignedProperties"
                )
            )
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
    let direct_trust = policy.key_trust.trust_anchor_signer == TrustAnchorSigner::Accepted;
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
    let expected = expected_targets(&document, &text);
    let request = VerificationRequest {
        expected_targets: &expected,
        ..VerificationRequest::default()
    };
    let mut declared = declarations(&text);
    establish_timestamps(
        &document,
        &request,
        &account,
        &inputs(Requirements::Timestamped),
        &mut declared,
    )?;
    let rules = rules(&catalogue(&profile_policy(profile, at, true)?)?);
    let crls = tokens::values(&text, "EncapsulatedCRLValue");
    let responses = tokens::values(&text, "EncapsulatedOCSPValue");
    let (integrity, integrity_refusal) = rules.lend(|requirements| {
        let etsi_inputs = etsi::Inputs {
            pool: &carried,
            anchors: &trusted,
            crls: &crls,
            responses: &responses,
            now: at,
            requirements,
            utc: &utc,
            direct_trust,
        };
        integrity(&document, &request, &account, at, &declared, &etsi_inputs)
    })?;
    let verified = with_verified_request(&document, &context, &request, &account, |session| {
        let entries = session.evidence().signatures();
        // Ids are reported only when both readings see the same signatures.
        let aligned = ids.len() == entries.len();
        for (index, entry) in entries.iter().enumerate() {
            let trust = verification(entry);
            let (own, computed) = integrity.get(index).cloned().unwrap_or_default();
            let mut row = json!({
                "index": index,
                "id": if aligned { ids[index].clone() } else { None },
                "etsi": etsi::under_profile(computed, &trust),
                "verification": trust,
                "integrity": own,
            });
            if entry.result().is_ok() {
                for (name, value) in level_facts(&session, entry.identity(), &caller, &inputs) {
                    row[name] = value;
                }
            }
            signatures.push(row);
        }
        Ok(())
    });
    let mut facts = json!({ "signatures": signatures });
    if let Some(refusal) = integrity_refusal {
        facts["integrity_request"] = refusal;
    }
    if let Err(error) = verified {
        let debug = format!("{error:?}");
        facts["request"] = json!({ "error": kind(&debug), "detail": error.to_string() });
    }
    Ok(facts)
}

/// Sets each signature's [`etsi::Declared::timestamps_intact`] and
/// [`etsi::Declared::archive_intact`]: xml-sec-xades validates B-T and B-LTA
/// at the latest token's generation time, since it refuses any token
/// generated after the time it validates at, and so establishes each token's
/// imprint and TSA signature once, for the ETSI process to place against the
/// validation time.
fn establish_timestamps(
    document: &XmlDocument,
    request: &VerificationRequest<'_>,
    account: &Memory,
    level_inputs: &Inputs<'_>,
    declared: &mut [etsi::Declared],
) -> Result<(), Failure> {
    let Some(at) = declared
        .iter()
        .flat_map(|declared| {
            declared
                .signature_timestamps
                .iter()
                .chain(&declared.validation_timestamps)
                .chain(&declared.archive_timestamps)
        })
        .filter_map(|token| etsi::token_details(token).map(|token| token.generated))
        .max()
    else {
        return Ok(());
    };
    let anchors: Vec<Vec<u8>> = level_inputs
        .anchors
        .iter()
        .map(|anchor| anchor.to_vec())
        .collect();
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: anchors,
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(profile_policy(PolicyProfile::XadesConformant, at, true)?)
        .key_resolver(&resolver);
    let inputs = Inputs {
        requirements: Requirements::Timestamped,
        ..*level_inputs
    };
    let run = with_verified_request(document, &context, request, account, |session| {
        for (index, entry) in session.evidence().signatures().iter().enumerate() {
            let Some(declared) = declared.get_mut(index) else {
                continue;
            };
            if entry.result().is_err() || declared.signature_timestamps.is_empty() {
                continue;
            }
            let established = |requirements| match validate(
                &session,
                entry.identity(),
                &Inputs {
                    requirements,
                    ..inputs
                },
                met,
            ) {
                // Every token's imprint and signature are checked before
                // their paths, statuses and the level's requirements, which
                // are the ETSI process's to judge; a token whose own checks
                // failed is refused as Rejected. A refusal before the tokens
                // (the signer's path, a countersignature, the hashes)
                // establishes nothing about them.
                Ok(Outcome::Timestamp {
                    failure: xml_sec_xades::TimestampFailure::Rejected,
                    ..
                }) => Some(false),
                Ok(
                    Outcome::Assessed(_)
                    | Outcome::Timestamp { .. }
                    | Outcome::Status(_)
                    | Outcome::Credential { .. }
                    | Outcome::Renewal { .. },
                ) => Some(true),
                _ => None,
            };
            declared.timestamps_intact = established(Requirements::Timestamped);
            if !declared.archive_timestamps.is_empty() {
                declared.archive_intact = established(Requirements::Archival);
            }
        }
        Ok(())
    });
    // A refused request establishes no token of any signature.
    if run.is_err() {
        for declared in declared.iter_mut() {
            declared.timestamps_intact = None;
        }
    }
    Ok(())
}

/// The `XAdES` facts of every baseline level of one verified signature.
fn level_facts<'i, W: structured_asn1::memory::Work>(
    session: &xml_sec::xmldsig::VerifiedSession<'_, '_, '_, W>,
    identity: NodeIdentity,
    caller: &[&[u8]],
    inputs: &impl Fn(Requirements) -> Inputs<'i>,
) -> Vec<(&'static str, Value)> {
    let basic = match validate_basic(session, identity, caller, |report| {
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
    let mut found = vec![("basic", basic)];
    for (name, requirements) in [
        ("timestamped", Requirements::Timestamped),
        ("long_term", Requirements::LongTerm),
        ("archival", Requirements::Archival),
    ] {
        found.push((
            name,
            level(validate(session, identity, &inputs(requirements), met)),
        ));
    }
    found
}

/// The nodes the data `Reference`s of `text` name in `document`. A target
/// the document does not resolve, or a signature over detached data alone,
/// leaves the whole document as the expected target.
fn expected_targets(document: &XmlDocument, text: &str) -> Vec<NodeIdentity> {
    document.with_view(|view| {
        let mut found: Vec<_> = targets(text)
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
    })
}

/// The key of each signature's signing certificate, identified as clause
/// 5.2.3.4 identifies it, handed to verification as the caller's own trusted
/// key: clause 5.2.7.4 step 3 verifies "using the public key extracted from
/// the signing certificate", so `KeyInfo` is neither read nor required.
/// Verification asks once per signature in document order; a `KeyInfo` that
/// carries one of the identified certificates names its signer directly.
struct SigningKeys {
    signers: Vec<Option<Vec<u8>>>,
    next: std::cell::Cell<usize>,
}

impl SigningKeys {
    fn new(declared: &[etsi::Declared], carried: &[Vec<u8>]) -> Self {
        let parser = Parser::der(account());
        let pool: Vec<Certificate<'_>> = carried
            .iter()
            .filter_map(|bytes| Certificate::read(&parser, bytes, 0).ok())
            .collect();
        let signers = declared
            .iter()
            .map(|declared| {
                etsi::signing_certificate(declared, &pool, parser.memory())
                    .map(|certificate| certificate.as_bytes().to_vec())
            })
            .collect();
        Self {
            signers,
            next: std::cell::Cell::new(0),
        }
    }
}

impl KeyResolver for SigningKeys {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        Ok(None)
    }

    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        _policy: &VerificationPolicy,
        _provider: &dyn xml_sec::provider::CryptoProvider,
    ) -> Result<Option<ResolvedVerificationKey<'a>>, DsigError> {
        let index = self.next.get();
        self.next.set(index + 1);
        let named = key_info.and_then(|key_info| {
            key_info.sources.iter().find_map(|source| match source {
                KeyInfoSource::X509Data(data) => self
                    .signers
                    .iter()
                    .flatten()
                    .find(|signer| data.certificates.iter().any(|carried| carried == *signer)),
                _ => None,
            })
        });
        let Some(certificate) = named.or_else(|| self.signers.get(index).and_then(Option::as_ref))
        else {
            return Ok(None);
        };
        let parser = Parser::der(account());
        let Ok(parsed) = Certificate::read(&parser, certificate, 0) else {
            return Ok(None);
        };
        Ok(Some(ResolvedVerificationKey::CallerTrusted(Box::new(
            VerificationKey {
                algorithm,
                public_key_bytes: parsed.tbs().public_key().as_bytes().to_vec(),
                certificate_der: Some(certificate.clone()),
                name: None,
            },
        ))))
    }
}

/// Per signature, its integrity and its ETSI indication; then the refusal of
/// the whole request, if any.
type Established = (Vec<(Value, Value)>, Option<Value>);

/// Each signature's integrity (EN 319 102-1 5.2.7) and its ETSI indication
/// under the compared profile's constraints (`inputs`). Integrity is
/// established under the widest profile with the signing certificate's key
/// and no chain checked, so the references and value are known even where
/// no path validates at `at` or the compared profile refuses the signature.
fn integrity(
    document: &XmlDocument,
    request: &VerificationRequest<'_>,
    account: &Memory,
    at: i64,
    declared: &[etsi::Declared],
    inputs: &etsi::Inputs<'_>,
) -> Result<Established, Failure> {
    let direct = SigningKeys::new(declared, inputs.pool);
    // Format checking covers the base format only; conformance to a signature
    // profile such as XAdES is signature acceptance (EN 319 102-1 5.2.2 NOTE,
    // 5.2.8), so integrity is established over plain XMLDSig. External
    // references are admitted: their bytes are supplied to neither validator,
    // so they are signed data that cannot be obtained (5.2.7.4 step 1).
    let mut policy = profile_policy(PolicyProfile::XadesConformant, at, false)?;
    policy.signature_constraints = SignatureConstraints::General;
    policy.uris.references = UriTypeSet::new(true, true, true);
    let context = VerifyContext::new().policy(policy).key_resolver(&direct);
    let mut found = Vec::new();
    let unknown = etsi::Declared::default();
    let run = with_verified_request(document, &context, request, account, |session| {
        for (index, entry) in session.evidence().signatures().iter().enumerate() {
            let declared = declared.get(index).unwrap_or(&unknown);
            // EN 319 132-1 §5.2.7.2: a CounterSignature property's signature
            // signs the embedding signature's SignatureValue. Its format
            // still lets it be verified (EN 319 102-1 §5.2.2.1), so one that
            // covers no such value fails that data item's hash instead.
            let uncountersigned = matches!(
                validate_basic(&session, entry.identity(), &[], |_| ()),
                Err(ValidationError::Enclosing(error))
                    if matches!(*error, EnclosingError::Counter(_))
            );
            let at = |now| {
                let inputs = etsi::Inputs { now, ..*inputs };
                etsi::indication(&session, entry.result(), declared, &inputs, uncountersigned)
            };
            let mut computed = at(inputs.now);
            if computed["indication"] == "TOTAL_PASSED" {
                computed["valid_until"] = valid_until(
                    &etsi::validity_bounds(&session.certificate_parser(), inputs),
                    at,
                );
            }
            found.push((verification(entry), computed));
        }
        Ok(())
    });
    let refusal = run.err().map(|error| {
        let debug = format!("{error:?}");
        json!({ "error": kind(&debug), "detail": error.to_string() })
    });
    Ok((found, refusal))
}

/// Until when a signature that passes now keeps passing over the evidence it
/// carries: the last of `bounds` before the first one past which the ETSI
/// process `at` no longer reaches `TOTAL_PASSED`, as Unix seconds. `null`
/// when it passes past every bound, so no certificate limits it.
fn valid_until(bounds: &[i64], at: impl Fn(i64) -> Value) -> Value {
    bounds
        .iter()
        .find(|bound| at(**bound + 1)["indication"] != "TOTAL_PASSED")
        .map_or(Value::Null, |bound| json!(bound))
}

/// The hash a digest method computes, when both constraint vocabularies
/// name it.
fn hash_of(digest: DigestAlgorithm) -> Option<Hash> {
    Some(etsi::hash_of(digest)).filter(|hash| *hash != Hash::Other)
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
