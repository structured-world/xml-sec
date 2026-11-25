//! B-T, B-LT and B-LTA validation of independently produced signatures.
//!
//! `xml-sec-tools xades fixtures --levels` builds the fixtures: OpenSSL issues
//! every certificate, CRL, OCSP response and RFC 3161 token, libxml2 computes
//! each timestamp input and xmlsec1 the XML signature.

use std::collections::BTreeMap;
use std::sync::Arc;

use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::timestamp::{Accuracy, PolicyAccuracy};
use structured_ltv::pki::{CrlReading, MemberStatus};
use structured_pkix::crl::{CombinedEntry, EntryLookup};
use structured_pkix::temporal::LeapTable;
use structured_xades::baseline::Evidence;
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, ManifestProcessing, TimestampTokenEncoding, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, KeyResolverConfig, UriTypeSet, VerificationRequest,
    VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    AuthorityAccuracy, ConfiguredResponder, Inputs, Level, Outcome, RenewalFailure, Requirements,
    StatusFailure, TimestampFailure, TokenIntegrity, TokenResult, ValidationError, check_tokens,
    validate,
};

const ROOT: &[u8] = include_bytes!("fixtures/levels/root.der");
const ISSUER: &[u8] = include_bytes!("fixtures/levels/issuer.der");
const OUTSIDER: &[u8] = include_bytes!("fixtures/levels/outsider.der");
const B_LT_CONFIGURED: &str = include_str!("fixtures/levels/b-lt-configured-responder.xml");
const B_LT_UNCERTIFIED_RESPONDER: &str =
    include_str!("fixtures/levels/b-lt-uncertified-responder.xml");
const B_LT_UNCERTIFIED_TOKEN: &str = include_str!("fixtures/levels/b-lt-uncertified-token.xml");
const B_LT_CONFLICTING: &str = include_str!("fixtures/levels/b-lt-conflicting-status.xml");
const B_LT_CONFLICTING_DELTA: &str = include_str!("fixtures/levels/b-lt-conflicting-delta.xml");
const B_LT_TSA_DELTA: &str = include_str!("fixtures/levels/b-lt-tsa-delta.xml");
const B_LTA_RENEWED_DIGESTS: &str = include_str!("fixtures/levels/b-lta-renewed-digests.xml");
const B_T: &str = include_str!("fixtures/levels/b-t.xml");
const B_T_NO_ACCURACY: &str = include_str!("fixtures/levels/b-t-no-accuracy.xml");
const B_LT: &str = include_str!("fixtures/levels/b-lt.xml");
const B_LT_MISPLACED: &str = include_str!("fixtures/levels/b-lt-tsa-material-misplaced.xml");
const B_LT_REVOKED: &str = include_str!("fixtures/levels/b-lt-tsa-revoked.xml");
const B_LT_DETACHED: &str = include_str!("fixtures/levels/b-lt-detached.xml");
const B_T_PARALLEL: &str = include_str!("fixtures/levels/b-t-parallel.xml");
const B_LT_COUNTERSIGNED: &str = include_str!("fixtures/levels/b-lt-countersigned.xml");
const B_LT_BY_KEY: &str = include_str!("fixtures/levels/b-lt-responder-by-key.xml");
const B_LTA: &str = include_str!("fixtures/levels/b-lta.xml");
const B_LTA_RENEWED: &str = include_str!("fixtures/levels/b-lta-renewed.xml");
const DETACHED: &[u8] = include_bytes!("fixtures/levels/detached.txt");

/// `1.3.6.1.4.1.13762.3`, the policy of the test TSA.
const LEVELS_POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xeb, 0x42, 0x03];
/// `1.3.6.1.4.1.13762.4`, a policy no fixture token states.
const OTHER_POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xeb, 0x42, 0x04];

/// Unix time `1_800_000_000`, inside every fixture certificate and CRL window.
const AT: i64 = 500_000 * 3600;

/// The caller evidence of one validation, beyond its UTC facts and level.
#[derive(Default)]
struct Given<'a> {
    anchors: &'a [&'a [u8]],
    certificates: &'a [&'a [u8]],
    accuracies: &'a [AuthorityAccuracy<'a>],
    responders: &'a [ConfiguredResponder<'a>],
    crls: &'a [&'a [u8]],
    responses: &'a [&'a [u8]],
    /// [`TimestampTokenEncoding::Declared`] unless a case asks for the CMS reading.
    cms: bool,
}

/// `Memory` capacity and work ceiling of an ordinary validation.
const AMPLE: (usize, usize) = (1 << 25, 1 << 31);

/// `visitor` over `requirements` of the first signature of `xml` on an account
/// with these `(memory, work)` ceilings, or what stopped it.
fn level_in<R>(
    xml: &str,
    requirements: Requirements,
    given: &Given<'_>,
    (memory, work): (usize, usize),
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Result<Outcome<R>, ValidationError>, DsigError> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(AT, 0);
    if given.cms {
        policy.timestamp_token_encoding = TimestampTokenEncoding::Ber;
    }
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let request = VerificationRequest::default();
    let account = Memory::new(Arc::new(MemoryAccount::new(memory, work)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(&document, &context, &request, &account, |session| {
        let signature = session.evidence().signatures()[0].identity();
        let inputs = Inputs {
            requirements,
            anchors: given.anchors,
            certificates: given.certificates,
            utc: &utc,
            accuracies: given.accuracies,
            responders: given.responders,
            crls: given.crls,
            responses: given.responses,
        };
        Ok(validate(&session, signature, &inputs, visitor))
    })
}

fn level(
    xml: &str,
    requirements: Requirements,
    anchors: &[&[u8]],
    certificates: &[&[u8]],
) -> Result<Outcome<bool>, ValidationError> {
    met(
        xml,
        requirements,
        &Given {
            anchors,
            certificates,
            ..Given::default()
        },
    )
}

fn stated(
    xml: &str,
    requirements: Requirements,
    anchors: &[&[u8]],
    certificates: &[&[u8]],
    accuracies: &[AuthorityAccuracy<'_>],
) -> Result<Outcome<bool>, ValidationError> {
    met(
        xml,
        requirements,
        &Given {
            anchors,
            certificates,
            accuracies,
            ..Given::default()
        },
    )
}

fn all_met(level: &Level<'_>) -> bool {
    level.all_requirements_met()
}

fn met(
    xml: &str,
    requirements: Requirements,
    given: &Given<'_>,
) -> Result<Outcome<bool>, ValidationError> {
    level_in(xml, requirements, given, AMPLE, all_met).expect("fixture verifies as XMLDSig")
}

/// [`check_tokens`] over the first signature of `xml`: each token's integrity.
fn integrities(xml: &str) -> Result<Outcome<Vec<TokenIntegrity>>, ValidationError> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(AT, 0);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let account = Memory::new(Arc::new(MemoryAccount::new(AMPLE.0, AMPLE.1)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            let inputs = Inputs {
                requirements: Requirements::Timestamped,
                anchors: &[ROOT],
                certificates: &[],
                utc: &utc,
                accuracies: &[],
                responders: &[],
                crls: &[],
                responses: &[],
            };
            Ok(check_tokens(&session, signature, &inputs, |results| {
                results.iter().map(TokenResult::integrity).collect()
            }))
        },
    )
    .expect("fixture verifies as XMLDSig")
}

#[test]
fn every_token_is_checked_whatever_another_shows() {
    // A broken first signature timestamp stops the level at that token; each
    // token's own checks (EN 319 102-1 V1.4.1 clause 5.4) still answer for
    // every token, the intact one after it included.
    let start = B_T
        .find("<xades:SignatureTimeStamp")
        .expect("a signature timestamp");
    let end = B_T.find("</xades:SignatureTimeStamp>").expect("its end")
        + "</xades:SignatureTimeStamp>".len();
    let original = &B_T[start..end];
    let tampered = original.replace("ADozW5ea", "ADozX5ea");
    assert_ne!(tampered, original, "the token's signature changed");
    // A copied property needs an ID of its own, apart from the tampering.
    let broken = tampered.replace("Id=\"ts\"", "Id=\"ts-broken\"");
    let xml = format!("{}{broken}{}", &B_T[..start], &B_T[start..]);
    let level = level(&xml, Requirements::Timestamped, &[ROOT], &[]);
    assert!(
        matches!(
            level,
            Ok(Outcome::Timestamp {
                failure: TimestampFailure::Rejected,
                ..
            })
        ),
        "{level:?}"
    );
    let checked = integrities(&xml);
    assert!(
        matches!(&checked, Ok(Outcome::Assessed(found))
            if found == &[TokenIntegrity::Rejected, TokenIntegrity::Intact]),
        "{checked:?}"
    );
    assert!(
        matches!(&integrities(B_T), Ok(Outcome::Assessed(found)) if found == &[TokenIntegrity::Intact])
    );
}

#[test]
fn a_token_stays_checkable_after_the_signers_certificate_expired() {
    // A token's own checks are its imprint over the verified signature and
    // its TSA's signature; long after every certificate of the signer's
    // chain expired, which is what the token preserves, they still answer.
    // The level needs the signer's path there and cannot be assessed.
    let expired = 4_000_000_000;
    // The same chain-enabled run meets B-T at AT; only the time differs, and
    // past the chain's validity the signer's key no longer verifies the
    // signature, so it stays unchecked.
    let control = level_at(B_T, AT);
    assert!(
        matches!(control, Ok(Outcome::Assessed(true))),
        "{control:?}"
    );
    let level = level_at(B_T, expired);
    assert!(
        matches!(&level, Err(error)
            if error.starts_with("Prepare(Binding(Signature {") && error.contains("status: Unchecked")),
        "{level:?}"
    );
    let checked = signer_trusted_integrities(B_T, expired, &[ROOT]);
    assert!(
        matches!(&checked, Ok(Outcome::Assessed(found)) if found == &[TokenIntegrity::Intact]),
        "{checked:?}"
    );
}

#[test]
fn a_token_signer_the_caller_supplies_only_as_an_anchor_is_found() {
    // RFC 5652 5.1 lets the token omit its signer's certificate; with the
    // document's own copies removed, the caller's anchors are where it is.
    // Finding it there checks the token's signature, not its TSA's path.
    let mut xml = B_LT_UNCERTIFIED_TOKEN.to_owned();
    let mut removed = Vec::new();
    for (open, close) in [
        (
            "<xadesv141:TimeStampValidationData>",
            "</xadesv141:TimeStampValidationData>",
        ),
        ("<xades:CertificateValues>", "</xades:CertificateValues>"),
    ] {
        while let Some(start) = xml.find(open) {
            let end = xml[start..].find(close).expect("closed") + start + close.len();
            removed.push(xml[start..end].to_owned());
            xml.replace_range(start..end, "");
        }
    }
    let removed = removed.concat();
    let certificates: Vec<Vec<u8>> = removed
        .split("<xades:EncapsulatedX509Certificate>")
        .skip(1)
        .map(|value| {
            let value = value
                .split("</xades:EncapsulatedX509Certificate>")
                .next()
                .unwrap_or_default();
            let compact: String = value.split_ascii_whitespace().collect();
            structured_base64::STANDARD
                .decode(compact.as_bytes())
                .expect("base64 certificate")
        })
        .collect();
    assert_ne!(certificates.len(), 0);
    let missing = signer_trusted_integrities(&xml, AT, &[ROOT]);
    assert!(
        matches!(&missing, Ok(Outcome::Assessed(found)) if found == &[TokenIntegrity::MissingSigner]),
        "{missing:?}"
    );
    let mut anchors: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
    anchors.push(ROOT);
    let found = signer_trusted_integrities(&xml, AT, &anchors);
    assert!(
        matches!(&found, Ok(Outcome::Assessed(found)) if found == &[TokenIntegrity::Intact]),
        "{found:?}"
    );
}

/// [`check_tokens`] over the first signature of `xml`, verified at `at` with
/// its `KeyInfo` certificate's key as the caller's own trusted key for that
/// signature, so no chain of the signer is checked, and `anchors` as the
/// caller's trust anchors.
fn signer_trusted_integrities(
    xml: &str,
    at: i64,
    anchors: &[&[u8]],
) -> Result<Outcome<Vec<TokenIntegrity>>, ValidationError> {
    use xml_sec::xmldsig::{CallerTrustedSignatureKey, SignatureAlgorithm, VerificationKey};
    let source = roxmltree::Document::parse(xml).expect("fixture parses");
    let element = |name: &str| {
        source
            .descendants()
            .find(|node| node.tag_name().name() == name)
            .expect("the fixture names its signer")
    };
    let der = structured_base64::STANDARD
        .decode(
            element("X509Certificate")
                .text()
                .unwrap_or_default()
                .split_ascii_whitespace()
                .collect::<String>()
                .as_bytes(),
        )
        .expect("base64 certificate");
    let algorithm = element("SignatureMethod")
        .attribute("Algorithm")
        .and_then(SignatureAlgorithm::from_uri)
        .expect("a known signature method");
    let parser =
        structured_asn1::Parser::der(Memory::new(Arc::new(MemoryAccount::new(AMPLE.0, AMPLE.1))));
    let certificate =
        structured_pkix::Certificate::read(&parser, &der, 0).expect("the signer certificate reads");
    let key = VerificationKey {
        algorithm,
        public_key_bytes: certificate.tbs().public_key().as_bytes().to_vec(),
        certificate_der: Some(der.clone()),
        name: None,
    };
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = false;
    policy.key_trust.verification_time = Instant::new(at, 0);
    let context = VerifyContext::new().policy(policy);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let keys = [CallerTrustedSignatureKey {
        signature: context
            .signature_identities(&document)
            .expect("one signature")[0],
        key: &key,
    }];
    let request = VerificationRequest {
        trusted_keys: &keys,
        ..VerificationRequest::default()
    };
    let account = Memory::new(Arc::new(MemoryAccount::new(AMPLE.0, AMPLE.1)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(&document, &context, &request, &account, |session| {
        let signature = session.evidence().signatures()[0].identity();
        let inputs = Inputs {
            requirements: Requirements::Timestamped,
            anchors,
            certificates: &[],
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        Ok(check_tokens(&session, signature, &inputs, |results| {
            results.iter().map(TokenResult::integrity).collect()
        }))
    })
    .expect("fixture verifies as XMLDSig")
}

/// Whether B-T holds for the first signature of `xml` with its chain
/// checked at `at`, or what stopped it.
fn level_at(xml: &str, at: i64) -> Result<Outcome<bool>, String> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(at, 0);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let account = Memory::new(Arc::new(MemoryAccount::new(AMPLE.0, AMPLE.1)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            let inputs = Inputs {
                requirements: Requirements::Timestamped,
                anchors: &[ROOT],
                certificates: &[],
                utc: &utc,
                accuracies: &[],
                responders: &[],
                crls: &[],
                responses: &[],
            };
            Ok(validate(&session, signature, &inputs, all_met)
                .map_err(|error| format!("{error:?}")))
        },
    )
    .map_err(|error| format!("{error:?}"))
    .and_then(core::convert::identity)
}

#[test]
fn a_real_timestamp_token_meets_b_t() {
    // OpenSSL's TSA stamped libxml2's canonical SignatureValue: the imprint,
    // the CMS signature and the TSA path to the caller's anchor all hold.
    let result = level(B_T, Requirements::Timestamped, &[ROOT], &[]);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn incorporated_crl_and_delegated_ocsp_meet_b_lt() {
    // The signer's status is a delegated OCSP response whose noCheck responder
    // and every CA have their own status in the document.
    let result = level(B_LT, Requirements::LongTerm, &[ROOT], &[]);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn timestamp_material_outside_its_containers_fails_b_lt() {
    // EN 319 132-1 §6.3(x): every status is usable and incorporated, but the
    // TSA's own material sits in the ordinary signature values.
    let result = level(B_LT_MISPLACED, Requirements::LongTerm, &[ROOT], &[]);
    assert!(matches!(result, Ok(Outcome::Assessed(false))), "{result:?}");
}

#[test]
fn a_real_archive_timestamp_meets_b_lta() {
    // The archive token covers libxml2's output for every reference, the
    // signature and all earlier validation material.
    let result = level(B_LTA, Requirements::Archival, &[ROOT], &[]);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

/// `xml` with one base64 character of the `ordinal`-th token changed, far enough
/// in to land in signed content rather than the outer CMS framing.
fn tampered_token(xml: &str, ordinal: usize) -> String {
    let open = "<xades:EncapsulatedTimeStamp>";
    let start = xml.match_indices(open).nth(ordinal).expect("token").0 + open.len();
    let at = start + 400;
    let replacement = if &xml[at..=at] == "A" { "B" } else { "A" };
    format!("{}{replacement}{}", &xml[..at], &xml[at + 1..])
}

/// The base64 value of the `ordinal`-th token.
fn token_value(xml: &str, ordinal: usize) -> &str {
    let open = "<xades:EncapsulatedTimeStamp>";
    let start = xml.match_indices(open).nth(ordinal).expect("token").0 + open.len();
    let end = start + xml[start..].find('<').expect("token end");
    &xml[start..end]
}

#[test]
fn both_token_profiles_meet_every_level_on_der_tokens() {
    // A DER token is valid BER, so the CMS reading changes nothing for it.
    for (xml, requirements) in [
        (B_T, Requirements::Timestamped),
        (B_LT, Requirements::LongTerm),
        (B_LTA, Requirements::Archival),
    ] {
        let given = Given {
            anchors: &[ROOT],
            cms: true,
            ..Given::default()
        };
        let result = met(xml, requirements, &given);
        assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
    }
}

/// `xml` with its first token's outer `ContentInfo` re-encoded in the indefinite
/// length form: valid BER (X.690 §8.1.3.6) that DER forbids (X.690 §10.1), with
/// every signed byte unchanged.
fn indefinite_token(xml: &str) -> String {
    let value = token_value(xml, 0);
    let der = structured_base64::STANDARD
        .decode(value.as_bytes())
        .expect("base64");
    assert_eq!(der[..2], [0x30, 0x82], "a long-form SEQUENCE");
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[4..]);
    ber.extend_from_slice(&[0, 0]);
    xml.replace(
        value,
        &structured_base64::STANDARD
            .encode(&ber)
            .expect("test encoding"),
    )
}

#[test]
fn a_ber_root_token_meets_b_t_only_under_the_cms_reading() {
    // EN 319 132-1 §5.1.3 lets the declared reading refuse a non-DER token,
    // while the CMS reading accepts it; the evidence must come from the same
    // BER reading rather than a DER re-read of the root token.
    let xml = indefinite_token(B_T);
    let given = Given {
        anchors: &[ROOT],
        cms: true,
        ..Given::default()
    };
    let result = met(&xml, Requirements::Timestamped, &given);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
    let result = level(&xml, Requirements::Timestamped, &[ROOT], &[]);
    assert!(!matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn a_changed_token_never_yields_evidence() {
    // A change inside the signed token breaks its CMS signature or its imprint.
    let result = level(
        &tampered_token(B_T, 0),
        Requirements::Timestamped,
        &[ROOT],
        &[],
    );
    assert!(
        matches!(
            result,
            Ok(Outcome::Timestamp {
                failure: TimestampFailure::Rejected,
                ..
            }) | Err(ValidationError::Timestamp(_))
        ),
        "{result:?}"
    );
}

#[test]
fn another_input_token_in_the_archive_position_is_refused() {
    // The signature token is genuine, but it covers the SignatureValue rather
    // than the archive input, so its imprint must not satisfy the archive.
    let forged = B_LTA.replace(token_value(B_LTA, 1), token_value(B_LTA, 0));
    let result = level(&forged, Requirements::Archival, &[ROOT], &[]);
    assert!(
        matches!(
            result,
            Ok(Outcome::Timestamp {
                failure: TimestampFailure::Rejected,
                ..
            })
        ),
        "{result:?}"
    );
}

#[test]
fn a_member_without_any_status_stops_b_lt() {
    // With every OCSP response and CRL removed, the first path member has no
    // source. That is a missing input, not a statement about revocation.
    let start = B_LT.find("<xades:RevocationValues>").expect("values");
    let close = "</xadesv141:TimeStampValidationData>";
    let end = B_LT.find(close).expect("validation data") + close.len();
    let stripped = format!("{}{}", &B_LT[..start], &B_LT[end..]);
    let result = level(&stripped, Requirements::LongTerm, &[ROOT], &[]);
    assert!(
        matches!(result, Ok(Outcome::Status(StatusFailure::NoSource))),
        "{result:?}"
    );
}

#[test]
fn requesting_a_level_the_document_lacks_is_not_promotion() {
    // A B-T document has no validation material, and a B-LT one no archive:
    // neither is reported as the level it does not reach.
    let result = level(B_T, Requirements::LongTerm, &[ROOT], &[]);
    assert!(
        matches!(result, Ok(Outcome::Status(StatusFailure::NoSource))),
        "{result:?}"
    );
    let result = level(B_LT, Requirements::Archival, &[ROOT], &[]);
    assert!(
        matches!(result, Err(ValidationError::Prepare(_))),
        "{result:?}"
    );
}

#[test]
fn a_revoked_timestamp_authority_stays_a_fact_of_the_report() {
    // The material is complete, so the structural level holds; the TSA's
    // status must not disappear behind that, and is no absence evidence.
    let revoked = level_in(
        B_LT_REVOKED,
        Requirements::LongTerm,
        &Given {
            anchors: &[ROOT],
            ..Given::default()
        },
        AMPLE,
        |level| {
            let Evidence::LongTerm(report) = level.evidence() else {
                panic!("a B-LT request yields the B-LT reports");
            };
            let nodes = report.x509().timestamps().inputs().authorities().nodes();
            nodes
                .iter()
                .flat_map(|node| node.statuses.entries())
                .any(|status| {
                    matches!(status, MemberStatus::CrlReading(reading)
                        if matches!(reading.reading(), CrlReading::Complete(facts)
                            if matches!(facts.entry(), EntryLookup::Found(_))))
                })
        },
    )
    .expect("fixture verifies as XMLDSig");
    assert!(
        matches!(revoked, Ok(Outcome::Assessed(true))),
        "{revoked:?}"
    );
}

#[test]
fn a_crl_entry_is_not_hidden_by_a_good_ocsp_response() {
    // Conflicting evidence: OCSP says good, a complete CRL lists the signer.
    // The listed entry must reach the report rather than the answer read first.
    let listed = level_in(
        B_LT_CONFLICTING,
        Requirements::LongTerm,
        &Given {
            anchors: &[ROOT],
            ..Given::default()
        },
        AMPLE,
        |level| {
            let Evidence::LongTerm(report) = level.evidence() else {
                panic!("a B-LT request yields the B-LT reports");
            };
            report
                .x509()
                .timestamps()
                .inputs()
                .authorities()
                .nodes()
                .iter()
                .flat_map(|node| node.statuses.entries())
                .any(|status| {
                    matches!(status, MemberStatus::CrlReading(reading)
                        if matches!(reading.reading(), CrlReading::Complete(facts)
                            if matches!(facts.entry(), EntryLookup::Found(_))))
                })
        },
    )
    .expect("fixture verifies as XMLDSig");
    assert!(matches!(listed, Ok(Outcome::Assessed(true))), "{listed:?}");
}

#[test]
fn a_delta_entry_is_not_hidden_by_a_good_ocsp_response() {
    // RFC 5280 §5.2.4: only the delta names the signer; its complete base does not.
    let listed = level_in(
        B_LT_CONFLICTING_DELTA,
        Requirements::LongTerm,
        &Given {
            anchors: &[ROOT],
            ..Given::default()
        },
        AMPLE,
        |level| {
            let Evidence::LongTerm(report) = level.evidence() else {
                panic!("a B-LT request yields the B-LT reports");
            };
            report
                .x509()
                .timestamps()
                .inputs()
                .authorities()
                .nodes()
                .iter()
                .flat_map(|node| node.statuses.entries())
                .any(|status| {
                    matches!(status, MemberStatus::CrlReading(reading)
                        if matches!(reading.reading(), CrlReading::Delta(facts)
                            if !matches!(facts.entry(),
                                CombinedEntry::Absent | CombinedEntry::Removed { .. })))
                })
        },
    )
    .expect("fixture verifies as XMLDSig");
    assert!(matches!(listed, Ok(Outcome::Assessed(true))), "{listed:?}");
}

#[test]
fn a_delta_in_the_timestamp_validation_data_is_coverage() {
    // §6.3(x): the TSA's complete CRL and its delta both sit in the timestamp's
    // own validation data. The delta is an actual input, not an ignored extra:
    // the census holds exactly one artifact more than the same chain without it.
    let artifacts = |xml| {
        let given = Given {
            anchors: &[ROOT],
            ..Given::default()
        };
        level_in(xml, Requirements::LongTerm, &given, AMPLE, |level| {
            let Evidence::LongTerm(report) = level.evidence() else {
                panic!("a B-LT request yields the B-LT reports");
            };
            (
                level.all_requirements_met(),
                report.x509().presence().entries().len(),
            )
        })
        .expect("fixture verifies as XMLDSig")
    };
    let plain = artifacts(B_LT);
    let with_delta = artifacts(B_LT_TSA_DELTA);
    let (Ok(Outcome::Assessed((true, plain))), Ok(Outcome::Assessed((true, with_delta)))) =
        (plain, with_delta)
    else {
        panic!("both fixtures meet B-LT");
    };
    assert_eq!(with_delta, plain + 1);
}

/// `xml` at B-LTA with its `Manifest` processed and these detached bytes supplied.
fn renewal(xml: &str, detached: Option<&[u8]>) -> Result<Outcome<bool>, ValidationError> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(AT, 0);
    policy.uris.references = UriTypeSet::ALL;
    policy.manifest_processing = ManifestProcessing::Process;
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let resources: BTreeMap<String, Vec<u8>> = detached
        .map(|bytes| ("detached.txt".to_owned(), bytes.to_vec()))
        .into_iter()
        .collect();
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let account = Memory::new(Arc::new(MemoryAccount::new(AMPLE.0, AMPLE.1)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(&document, &context, &request, &account, |session| {
        let signature = session.evidence().signatures()[0].identity();
        let anchors: &[&[u8]] = &[ROOT];
        let inputs = Inputs {
            requirements: Requirements::Archival,
            anchors,
            certificates: &[],
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        Ok(validate(&session, signature, &inputs, all_met))
    })
    .expect("fixture verifies as XMLDSig")
}

/// `B_LTA_RENEWED_DIGESTS` with the content of `tag` changed in its first byte.
fn changed_renewal(tag: &str) -> String {
    let open = format!("<xadesv141:{tag}>");
    let at = B_LTA_RENEWED_DIGESTS.find(&open).expect("value") + open.len();
    let replacement = if &B_LTA_RENEWED_DIGESTS[at..=at] == "A" {
        "B"
    } else {
        "A"
    };
    format!(
        "{}{replacement}{}",
        &B_LTA_RENEWED_DIGESTS[..at],
        &B_LTA_RENEWED_DIGESTS[at + 1..]
    )
}

#[test]
fn renewed_digests_confirm_the_detached_object() {
    // EN 319 132-1 §5.5.3 under SHA-512, over a Manifest digested with SHA-256.
    let result = renewal(B_LTA_RENEWED_DIGESTS, Some(DETACHED));
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn a_renewal_that_disagrees_stops_the_level() {
    // §5.5.3 notifications stay typed facts: a wrong new digest, and a reference
    // digest naming no instruction.
    for (tag, expected) in [
        ("NewSDODigestValue", RenewalFailure::Differs),
        ("OriginalRefDigest", RenewalFailure::Unbound),
    ] {
        let result = renewal(&changed_renewal(tag), Some(DETACHED));
        assert!(
            matches!(result, Ok(Outcome::Renewal { failure, .. }) if failure == expected),
            "{expected:?}: {result:?}"
        );
    }
}

#[test]
fn a_detached_object_nobody_supplied_stops_before_its_renewal() {
    // The signed Manifest reference itself cannot be established, so §6.3(k)
    // refuses at preparation and no renewal is reached.
    let result = renewal(B_LTA_RENEWED_DIGESTS, None);
    assert!(
        matches!(result, Err(ValidationError::Prepare(_))),
        "{result:?}"
    );
}

/// Whether every signature of `xml` reaches `requirements`, given its resources.
fn every_signature(xml: &str, requirements: Requirements) -> Vec<String> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(AT, 0);
    policy.uris.references = UriTypeSet::ALL;
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let resources = BTreeMap::from([("detached.txt".to_owned(), DETACHED.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 25, 1 << 31)));
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    with_verified_request(&document, &context, &request, &account, |session| {
        let anchors: &[&[u8]] = &[ROOT];
        let inputs = Inputs {
            requirements,
            anchors,
            certificates: &[],
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        Ok(session
            .evidence()
            .signatures()
            .iter()
            .map(|entry| {
                let outcome = validate(&session, entry.identity(), &inputs, |level| {
                    level.all_requirements_met()
                });
                format!("{outcome:?}")
            })
            .collect())
    })
    .expect("fixture verifies as XMLDSig")
}

#[test]
fn a_token_without_stated_accuracy_is_a_rejected_timestamp() {
    // RFC 3161 §2.4.2: without accuracy the generation interval is unknown, so
    // the token is a completed negative fact, never a guessed interval.
    let result = level(B_T_NO_ACCURACY, Requirements::Timestamped, &[ROOT], &[]);
    assert!(
        matches!(
            result,
            Ok(Outcome::Timestamp {
                failure: TimestampFailure::Rejected,
                ..
            })
        ),
        "{result:?}"
    );
}

/// The test TSA's certificate, the first one of the timestamp's validation data.
fn tsa_certificate() -> Vec<u8> {
    let data = B_LT
        .find("<xadesv141:TimeStampValidationData>")
        .expect("data");
    let open = "<xades:EncapsulatedX509Certificate>";
    let start = data + B_LT[data..].find(open).expect("certificate") + open.len();
    let end = start + B_LT[start..].find('<').expect("certificate end");
    structured_base64::STANDARD
        .decode(&B_LT.as_bytes()[start..end])
        .expect("base64")
}

fn stated_second<'a>(policy: &'a [u8], authority: &'a [u8]) -> AuthorityAccuracy<'a> {
    AuthorityAccuracy {
        authority,
        stated: PolicyAccuracy::new(Oid::from_bytes(policy), Accuracy::new(1, 0, 0))
            .expect("accuracy"),
    }
}

#[test]
fn caller_policy_accuracy_gives_an_unstated_token_its_interval() {
    // RFC 3161 §2.4.2: the TSA's policy may define accuracy instead of the token.
    let tsa = tsa_certificate();
    let result = stated(
        B_T_NO_ACCURACY,
        Requirements::Timestamped,
        &[ROOT],
        &[],
        &[stated_second(LEVELS_POLICY, &tsa)],
    );
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn policy_accuracy_binds_the_signed_policy_and_the_authority() {
    // The accuracy of another policy, or of another authority, says nothing about
    // this token: it stays a completed negative fact, not a guessed interval.
    let tsa = tsa_certificate();
    for entry in [
        stated_second(OTHER_POLICY, &tsa),
        stated_second(LEVELS_POLICY, ROOT),
    ] {
        let result = stated(
            B_T_NO_ACCURACY,
            Requirements::Timestamped,
            &[ROOT],
            &[],
            &[entry],
        );
        assert!(
            matches!(
                result,
                Ok(Outcome::Timestamp {
                    failure: TimestampFailure::Rejected,
                    ..
                })
            ),
            "{result:?}"
        );
    }
}

#[test]
fn an_unlisted_policy_does_not_disturb_a_token_stating_accuracy() {
    // The token's own field comes first, so an entry for another policy of the
    // same authority is simply not selected.
    let tsa = tsa_certificate();
    let result = stated(
        B_T,
        Requirements::Timestamped,
        &[ROOT],
        &[],
        &[stated_second(OTHER_POLICY, &tsa)],
    );
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

/// `B_LT_CONFIGURED` at B-LT, given these configured responders.
fn configured(responders: &[ConfiguredResponder<'_>]) -> Result<Outcome<bool>, ValidationError> {
    met(
        B_LT_CONFIGURED,
        Requirements::LongTerm,
        &Given {
            anchors: &[ROOT],
            responders,
            ..Given::default()
        },
    )
}

/// Every base64 value of `tag` in `xml`.
fn encapsulated(xml: &str, tag: &str) -> Vec<Vec<u8>> {
    let open = format!("<xades:{tag}>");
    xml.match_indices(&open)
        .map(|(start, _)| {
            let body = start + open.len();
            let end = body + xml[body..].find('<').expect("value end");
            structured_base64::STANDARD
                .decode(&xml.as_bytes()[body..end])
                .expect("base64")
        })
        .collect()
}

#[test]
fn caller_status_answers_without_counting_as_incorporated() {
    // The document has no status, so it stops; the caller's own CRLs and OCSP
    // response answer it, but EN 319 132-1 B-LT still needs them in the document.
    let crls = encapsulated(B_LT, "EncapsulatedCRLValue");
    let responses = encapsulated(B_LT, "EncapsulatedOCSPValue");
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let responses: Vec<&[u8]> = responses.iter().map(Vec::as_slice).collect();
    let tsa = tsa_certificate();
    let certificates: &[&[u8]] = &[ISSUER, &tsa];
    let given = Given {
        anchors: &[ROOT],
        certificates,
        crls: &crls,
        responses: &responses,
        ..Given::default()
    };
    let result = met(B_T, Requirements::LongTerm, &given);
    assert!(matches!(result, Ok(Outcome::Assessed(false))), "{result:?}");
}

#[test]
fn unreadable_caller_status_is_refused() {
    let result = met(
        B_LT,
        Requirements::LongTerm,
        &Given {
            anchors: &[ROOT],
            crls: &[b"not a CRL"],
            ..Given::default()
        },
    );
    assert!(
        matches!(result, Err(ValidationError::Status(_))),
        "{result:?}"
    );
}

#[test]
fn a_responder_outside_the_issuer_counts_only_when_configured() {
    // RFC 6960 §4.2.2.2: the document's response alone authorizes nothing, and
    // configuring it for another issuer does not reach this certificate. The
    // signer then falls back to the issuer CRL, which only the timestamp's own
    // validation data carries: the level stays unmet.
    assert!(matches!(configured(&[]), Ok(Outcome::Assessed(false))));
    let result = configured(&[ConfiguredResponder {
        responder: OUTSIDER,
        issuer: ROOT,
    }]);
    assert!(matches!(result, Ok(Outcome::Assessed(false))), "{result:?}");
    let result = configured(&[ConfiguredResponder {
        responder: OUTSIDER,
        issuer: ISSUER,
    }]);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn a_responder_certificate_omitted_from_its_response_comes_from_the_caller() {
    // RFC 6960 §4.2.1: a response may carry no certificates, so the signer's key
    // may be only in the responder configuration or among the anchors. These
    // responses are the only status of the issuer's certificates: unauthenticated
    // they leave no source. Authenticated, the level is assessed, and stays
    // unmet because EN 319 132-1 §6.3 also wants the responder incorporated.
    let responders = [ConfiguredResponder {
        responder: OUTSIDER,
        issuer: ISSUER,
    }];
    for anchors in [&[ROOT][..], &[ROOT, OUTSIDER]] {
        let given = Given {
            anchors,
            responders: &responders,
            ..Given::default()
        };
        let result = met(B_LT_UNCERTIFIED_RESPONDER, Requirements::LongTerm, &given);
        assert!(matches!(result, Ok(Outcome::Assessed(false))), "{result:?}");
    }
}

#[test]
fn a_timestamp_signer_omitted_from_its_token_comes_from_the_document() {
    // RFC 5652 §5.1 makes the certificate optional in the token. The TSA's own
    // certificate is in the timestamp validation data, so nothing is missing.
    let result = level(B_LT_UNCERTIFIED_TOKEN, Requirements::LongTerm, &[ROOT], &[]);
    assert!(matches!(result, Ok(Outcome::Assessed(true))), "{result:?}");
}

#[test]
fn a_detached_signature_reaches_b_lt_over_its_supplied_bytes() {
    assert_eq!(
        every_signature(B_LT_DETACHED, Requirements::LongTerm),
        ["Ok(Assessed(true))"]
    );
}

#[test]
fn each_parallel_signature_has_its_own_timestamp() {
    assert_eq!(
        every_signature(B_T_PARALLEL, Requirements::Timestamped),
        ["Ok(Assessed(true))", "Ok(Assessed(true))"]
    );
}

#[test]
fn a_countersignature_is_an_actor_of_the_root_b_lt() {
    // The counter signer's own path and status belong to the root's census.
    assert_eq!(
        every_signature(B_LT_COUNTERSIGNED, Requirements::LongTerm)[0],
        "Ok(Assessed(true))"
    );
}

#[test]
fn a_responder_named_by_key_hash_is_authenticated() {
    // RFC 6960 §4.2.1 fixes SHA-1 for this identity; the default policy applies.
    assert_eq!(
        every_signature(B_LT_BY_KEY, Requirements::LongTerm),
        ["Ok(Assessed(true))"]
    );
}

#[test]
fn a_later_archive_covers_the_earlier_one() {
    assert_eq!(
        every_signature(B_LTA_RENEWED, Requirements::Archival),
        ["Ok(Assessed(true))"]
    );
}

#[test]
fn every_work_ceiling_refuses_without_a_partial_level() {
    // Scanning the ceilings through every stage: below what the document needs
    // a refusal surfaces as a typed error, never as a panic or a met level
    // assembled from a partial census.
    let mut met = false;
    let mut work = 1 << 12;
    while work <= 1 << 28 {
        let result = level_in(
            B_LTA,
            Requirements::Archival,
            &Given {
                anchors: &[ROOT],
                ..Given::default()
            },
            (AMPLE.0, work),
            all_met,
        );
        match result {
            Ok(Ok(Outcome::Assessed(true))) => met = true,
            Ok(Ok(other)) => panic!("resource refusal became a fact: {other:?}"),
            Ok(Err(_)) | Err(_) => assert!(!met, "a larger ceiling failed at {work}"),
        }
        work += work / 3;
    }
    assert!(met, "the largest ceiling completes");
}

#[test]
fn every_storage_ceiling_refuses_without_a_partial_level() {
    // The same scan over retained storage: allocation refusal is an error at
    // every stage, never a met level or a negative fact.
    let mut met = false;
    let mut memory = 1 << 10;
    while memory <= AMPLE.0 {
        let result = level_in(
            B_LTA,
            Requirements::Archival,
            &Given {
                anchors: &[ROOT],
                ..Given::default()
            },
            (memory, AMPLE.1),
            all_met,
        );
        match result {
            Ok(Ok(Outcome::Assessed(true))) => met = true,
            Ok(Ok(other)) => panic!("resource refusal became a fact: {other:?}"),
            Ok(Err(_)) | Err(_) => assert!(!met, "a larger ceiling failed at {memory}"),
        }
        memory += memory / 3;
    }
    assert!(met, "the largest ceiling completes");
}

#[test]
fn a_timestamp_without_a_trusted_authority_proves_nothing() {
    // The token is mathematically valid and its root is a known certificate,
    // but no supplied anchor ends its path.
    let result = level(B_T, Requirements::Timestamped, &[], &[ROOT]);
    assert!(
        matches!(
            result,
            Ok(Outcome::Timestamp {
                failure: TimestampFailure::Path(_),
                ..
            })
        ),
        "{result:?}"
    );
}
