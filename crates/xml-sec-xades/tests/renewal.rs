//! `RenewedDigestsV2` creation before an archive timestamp (EN 319 132-1
//! §5.5.3), over the level fixtures' `Manifest` signature.
//!
//! `xml-sec-tools xades fixtures --levels` signs `b-lt-manifest.xml` with
//! xmlsec1, its OpenSSL TSA answers the request `augment_probe renew-request`
//! makes for it (`renew.tsq`, `renew.tsr`), and the same generator computes
//! the renewal of `b-lta-renewed-digests.xml` itself, from OpenSSL digests
//! over xmllint canonicalization.
#![cfg(feature = "produce")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use structured_xades::certificate::Agreement;
use structured_xades::renewed::CreationError;
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, ManifestProcessing, PolicyViolation, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, KeyResolverConfig, UriTypeSet,
    VerificationRequest, VerifyContext,
};
use xml_sec_xades::{
    Assessment, AugmentError, Completion, DigestRenewal, Inputs, PendingTimestamp, Requirements,
    TimestampRequest, ValidationError, complete_timestamp, request_archive_timestamp,
    request_archive_timestamp_with_renewal,
};

const B_LT_MANIFEST: &str = include_str!("fixtures/levels/b-lt-manifest.xml");
const B_LTA_RENEWED_DIGESTS: &str = include_str!("fixtures/levels/b-lta-renewed-digests.xml");
const RENEW_TSQ: &[u8] = include_bytes!("fixtures/levels/renew.tsq");
const RENEW_TSR: &[u8] = include_bytes!("fixtures/levels/renew.tsr");
const ROOT: &[u8] = include_bytes!("fixtures/levels/root.der");
const DETACHED: &[u8] = include_bytes!("fixtures/levels/detached.txt");

/// Unix time `1_800_000_000`, inside every fixture certificate and CRL window.
const AT: i64 = 500_000 * 3600;
/// The nonce of the probe's request.
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const MD5: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";
/// The `Manifest` reference to the detached object.
const RENEWED: &str = "detached-object";

/// The archive request of the probe, for the signature `sig`.
fn request() -> TimestampRequest<'static> {
    TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    }
}

/// The verification of the fixtures: chains to the root at the fixed instant,
/// and the `Manifest` processed.
fn policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(AT, 0);
    policy.uris.references = UriTypeSet::ALL;
    policy.manifest_processing = ManifestProcessing::Process;
    policy
}

/// Run `test` with the assessment under `policy` and the B-LT evidence of the
/// fixtures, the detached object supplied.
fn with_evidence<R>(
    policy: VerificationPolicy,
    test: impl FnOnce(&Assessment<'_, '_>, &Inputs<'_>, &Memory) -> R,
) -> R {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let resources = BTreeMap::from([("detached.txt".to_owned(), DETACHED.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[],
    };
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage");
    let anchors: [&[u8]; 1] = [ROOT];
    let inputs = Inputs {
        requirements: Requirements::LongTerm,
        anchors: &anchors,
        certificates: &[],
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &[],
        responses: &[],
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    test(&assessment, &inputs, &work)
}

fn manifest() -> XmlDocument {
    XmlDocument::parse(B_LT_MANIFEST).expect("fixture parses")
}

/// The archive request over `document` with `renewal`.
fn renewing(
    document: &mut XmlDocument,
    renewal: &DigestRenewal<'_>,
    assessment: &Assessment<'_, '_>,
    inputs: &Inputs<'_>,
    work: &Memory,
) -> Result<PendingTimestamp, AugmentError> {
    request_archive_timestamp_with_renewal(document, &request(), renewal, assessment, inputs, work)
}

/// Complete `pending` with the TSA's response at B-LTA.
fn completed(
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    assessment: &Assessment<'_, '_>,
    inputs: &Inputs<'_>,
    work: &Memory,
) -> Result<(), AugmentError> {
    complete_timestamp(
        document,
        pending,
        RENEW_TSR,
        &Completion {
            assessment,
            inputs: &Inputs {
                requirements: Requirements::Archival,
                ..*inputs
            },
            window: None,
            id_attributes: &[],
        },
        work,
    )
}

/// The text of the first element named `local` in any prefix.
fn value<'x>(xml: &'x str, local: &str) -> &'x str {
    let open = format!(":{local}>");
    let start = xml.find(&open).expect("value") + open.len();
    &xml[start..start + xml[start..].find('<').expect("value end")]
}

#[test]
fn a_renewal_is_archived_with_the_digests_an_independent_generator_computes() {
    // EN 319 132-1 §5.5.3: the detached object and its canonical Manifest
    // Reference under SHA-512, then an archive (§5.5.2) that covers them.
    with_evidence(policy(), |assessment, inputs, work| {
        let mut document = manifest();
        let renewal = DigestRenewal {
            method: SHA512,
            references: &[RENEWED],
        };
        let pending = renewing(&mut document, &renewal, assessment, inputs, work)
            .expect("the renewal is requested");
        // The request is the one the TSA answered, and the renewal it covers
        // is not in the document until the archive completes it.
        assert_eq!(pending.request(), RENEW_TSQ);
        assert_eq!(document.as_xml(), B_LT_MANIFEST);
        completed(&mut document, &pending, assessment, inputs, work)
            .expect("the archive completes at B-LTA");
        let xml = document.as_xml();
        for local in ["NewSDODigestValue", "OriginalRefDigest"] {
            assert_eq!(
                value(xml, local),
                value(B_LTA_RENEWED_DIGESTS, local),
                "{local}"
            );
        }
        assert_eq!(value(B_LTA_RENEWED_DIGESTS, "NewSDODigestValue").len(), 88);
        let renewed = xml.find("RenewedDigestsV2").expect("renewal");
        let archived = xml.find("ArchiveTimeStamp").expect("archive");
        assert!(renewed < archived, "the archive follows the renewal");
    });
}

#[test]
fn the_renewal_is_part_of_what_the_archive_covers() {
    // A token over the input with the renewal is no token for the same
    // signature without it, and the failed completion publishes nothing.
    with_evidence(policy(), |assessment, inputs, work| {
        let mut document = manifest();
        let plain = request_archive_timestamp(&document, &request(), assessment, inputs, work)
            .expect("the plain archive is requested");
        assert_ne!(plain.request(), RENEW_TSQ);
        let result = completed(&mut document, &plain, assessment, inputs, work);
        assert!(
            matches!(
                result,
                Err(AugmentError::Unproven(_) | AugmentError::Check(_))
            ),
            "{result:?}"
        );
        assert_eq!(document.as_xml(), B_LT_MANIFEST);
    });
}

#[test]
fn a_completion_over_another_document_is_stale() {
    // The renewal was computed over the requested generation only.
    with_evidence(policy(), |assessment, inputs, work| {
        let renewal = DigestRenewal {
            method: SHA512,
            references: &[RENEWED],
        };
        let pending = renewing(&mut manifest(), &renewal, assessment, inputs, work)
            .expect("the renewal is requested");
        let mut other = manifest();
        let result = completed(&mut other, &pending, assessment, inputs, work);
        assert!(matches!(result, Err(AugmentError::Changed)), "{result:?}");
        assert_eq!(other.as_xml(), B_LT_MANIFEST);
    });
}

/// The refusal of a renewal of `references` under `method`, which must leave
/// the document as it was.
fn refused(policy: VerificationPolicy, method: &str, references: &[&str]) -> AugmentError {
    with_evidence(policy, |assessment, inputs, work| {
        let mut document = manifest();
        let renewal = DigestRenewal { method, references };
        let error = renewing(&mut document, &renewal, assessment, inputs, work)
            .expect_err("the renewal is refused");
        assert_eq!(document.as_xml(), B_LT_MANIFEST);
        error
    })
}

#[test]
fn only_references_of_an_authenticated_manifest_are_renewed() {
    // An absent ID and a SignedInfo Reference are each named by the ID the
    // caller gave.
    for id in ["nowhere", "sig-data"] {
        let error = refused(policy(), SHA512, &[RENEWED, id]);
        assert!(
            matches!(&error, AugmentError::UnknownReference(named) if named == id),
            "{id}: {error:?}"
        );
    }
    assert!(matches!(
        refused(policy(), SHA512, &[]),
        AugmentError::NothingToRenew
    ));
    // Unprocessed, the Manifest reference that DataObjectFormat names is an
    // unchecked signed object (§6.3(k)), so the signature is not B-LT at all.
    let unprocessed = VerificationPolicy {
        manifest_processing: ManifestProcessing::default(),
        ..policy()
    };
    let error = refused(unprocessed, SHA512, &[RENEWED]);
    assert!(
        matches!(error, AugmentError::Validation(ValidationError::Prepare(_))),
        "{error:?}"
    );
}

#[test]
fn the_new_method_must_be_a_usable_different_digest() {
    // §5.5.3 requires a digest other than the old one; §6.2.1 excludes MD5
    // before any deployment policy; the URI is written exactly as given, so
    // a spelling anyURI whitespace collapse would change is malformed.
    let padded = format!(" {SHA512}");
    for (method, expected) in [
        (MD5, Some(Agreement::ProhibitedAlgorithm)),
        ("urn:example:digest", Some(Agreement::Unsupported)),
        (padded.as_str(), Some(Agreement::MalformedMethod)),
        (SHA256, None),
    ] {
        let error = refused(policy(), method, &[RENEWED]);
        let AugmentError::Renewal(cause) = &error else {
            panic!("{method}: {error:?}");
        };
        match (expected, &**cause) {
            (Some(expected), CreationError::NewAlgorithm(answer)) => {
                assert_eq!(*answer, expected, "{method}");
            }
            (None, CreationError::Unchanged { .. }) => {}
            (_, cause) => panic!("{method}: {cause:?}"),
        }
    }
}

#[test]
fn the_operation_digest_policy_decides_the_new_method() {
    // A digest the compiled policy does not allow is its typed refusal, not
    // an unsupported method; the old SHA-256 digests stay verifiable.
    let mut restricted = policy();
    restricted.digest_algorithms = Some(BTreeSet::from([DigestAlgorithm::Sha256]));
    let error = refused(restricted, SHA512, &[RENEWED]);
    assert!(
        matches!(
            &error,
            AugmentError::Renewal(cause) if matches!(
                **cause,
                CreationError::NewProvider(xml_sec_xades::Error::Verification(
                    DsigError::Policy(PolicyViolation::Algorithm { .. })
                ))
            )
        ),
        "{error:?}"
    );
}
