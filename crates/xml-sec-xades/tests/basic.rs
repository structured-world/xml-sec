//! B-B validation of independently signed XAdES fixtures through the public entry.
//!
//! The fixtures come from scripts/generate-xades-fixtures.sh: xmlsec1 signs
//! every template with a real root -> intermediate -> signer path, so XMLDSig
//! verification succeeds and only the XAdES properties differ.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_xades::binding::BindingError;
use structured_xades::certificate::{Agreement, CheckError};
use structured_xades::prepare::{Error as PrepareError, FieldError};
use structured_xades::properties::{ClaimedTimeFailure, Error as PropertyError};
use xml_sec::XmlDocument;
use xml_sec::document::NodeIdentity;
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, UriTypeSet, VerificationRequest, VerifiedSession,
    VerifyContext, with_verified_request,
};
use xml_sec_xades::{Error, Outcome, PathFailure, Report, ValidationError, validate_basic};

const ROOT: &[u8] = include_bytes!("fixtures/root.der");
const SIGNER: &[u8] = include_bytes!("fixtures/signer.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/intermediate.der");
const DETACHED: &[u8] = include_bytes!("fixtures/detached.txt");

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)))
}

/// Facts a test asserts, copied out of the borrowed report.
#[derive(Debug, PartialEq, Eq)]
struct Facts {
    met: bool,
    included: bool,
    bound: bool,
    first_digest: Agreement,
}

fn facts(report: &Report<'_>) -> Facts {
    Facts {
        met: report.all_root_requirements_met(),
        included: report.included().is_some(),
        bound: report.inputs().certificate.is_bound(),
        first_digest: report.inputs().certificate.digests().entries()[0].agreement,
    }
}

const MET: Facts = Facts {
    met: true,
    included: true,
    bound: true,
    first_digest: Agreement::Matches,
};

/// Verify `xml` with X.509 path validation to the fixture root, then run
/// `check` over the verified session.
fn verified<R>(
    xml: &str,
    resolver: &DefaultKeyResolver,
    check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>, &Memory) -> R,
) -> R {
    verified_with(xml, resolver, true, check)
}

fn verified_with<R>(
    xml: &str,
    resolver: &DefaultKeyResolver,
    chains: bool,
    check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>, &Memory) -> R,
) -> R {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = chains;
    // Inside every fixture certificate's validity; never the system clock.
    policy.key_trust.verification_time =
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000));
    policy.uris.references = UriTypeSet::ALL;
    let context = VerifyContext::new().policy(policy).key_resolver(resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let resources = HashMap::from([("detached.txt".to_owned(), DETACHED.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let account = memory();
    let mut result = None;
    with_verified_request(&document, &context, &request, &account, |session| {
        result = Some(check(&session, &account));
        Ok(())
    })
    .expect("fixture verifies as XMLDSig");
    result.expect("continuation ran")
}

fn anchored() -> DefaultKeyResolver {
    DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        ..KeyResolverConfig::default()
    })
}

fn signature(session: &VerifiedSession<'_, '_, '_, Memory>, index: usize) -> NodeIdentity {
    session.evidence().signatures()[index].identity()
}

fn assess(xml: &str, index: usize) -> Result<Outcome<Facts>, ValidationError> {
    verified(xml, &anchored(), |session, memory| {
        validate_basic(session, signature(session, index), &[ROOT], memory, facts)
    })
}

fn assessed(xml: &str, index: usize) -> Facts {
    match assess(xml, index) {
        Ok(Outcome::Assessed(facts)) => facts,
        other => panic!("expected assembled B-B facts, got {other:?}"),
    }
}

#[test]
fn baseline_forms_meet_every_root_requirement() {
    // Enveloped, enveloping and detached data objects, and both independent
    // parallel signatures, satisfy EN 319 132-1 §6.3 B-B over a real path.
    for (xml, index) in [
        (include_str!("fixtures/enveloped.xml"), 0),
        (include_str!("fixtures/enveloping.xml"), 0),
        (include_str!("fixtures/detached.xml"), 0),
        (include_str!("fixtures/parallel.xml"), 0),
        (include_str!("fixtures/parallel.xml"), 1),
    ] {
        assert_eq!(assessed(xml, index), MET);
    }
}

#[test]
fn countersignature_joins_the_root_with_its_own_checked_path() {
    // §5.2.7.2 / §6.3(aa): an incorporated countersignature is an actor of its
    // own. Its validated path, key association and hash uses must all bind,
    // and the root keeps meeting its B-B requirements.
    let outcome = verified(
        include_str!("fixtures/countersigned.xml"),
        &anchored(),
        |session, memory| {
            let counter = signature(session, 1);
            validate_basic(session, signature(session, 0), &[ROOT], memory, |report| {
                let actors = report.inputs().counters.actors();
                (
                    facts(report),
                    actors.len(),
                    actors.first().is_some_and(|actor| {
                        actor.signer().counter().original().child() == counter
                    }),
                    report.inputs().hashes.counters().len(),
                )
            })
        },
    );
    let Ok(Outcome::Assessed((facts, actors, same_child, hashes))) = outcome else {
        panic!("expected assembled B-B facts, got {outcome:?}");
    };
    assert_eq!(facts, MET);
    assert_eq!((actors, hashes), (1, 1));
    assert!(same_child, "the actor is the document's countersignature");
}

#[test]
fn signing_certificate_digest_of_another_certificate_is_not_bound() {
    // §5.2.2: the first Cert digest names the signing certificate. A digest of
    // the root is a completed mismatch, not a processing error.
    let facts = assessed(include_str!("fixtures/certificate-digest-mismatch.xml"), 0);
    assert_eq!(
        facts,
        Facts {
            met: false,
            included: true,
            bound: false,
            first_digest: Agreement::Differs,
        }
    );
}

#[test]
fn md5_signing_certificate_digest_is_prohibited() {
    // §6.2.1 forbids MD5 whatever the provider supports.
    let facts = assessed(include_str!("fixtures/certificate-digest-md5.xml"), 0);
    assert!(!facts.met && !facts.bound);
    assert_eq!(facts.first_digest, Agreement::ProhibitedAlgorithm);
}

#[test]
fn baseline_certificate_reference_must_not_carry_a_uri() {
    // §6.3(i): a baseline signature shall not write Cert/@URI.
    let error = assess(include_str!("fixtures/certificate-uri.xml"), 0).unwrap_err();
    assert!(
        matches!(&error, ValidationError::Certificate(cause)
            if matches!(**cause, CheckError::ForbiddenCertificateUri { .. })),
        "{error:?}"
    );
}

#[test]
fn signing_time_needs_an_explicit_timezone() {
    // §6.3(h): the claimed signing time must be a UTC-qualified dateTime.
    let error = assess(include_str!("fixtures/signing-time-without-zone.xml"), 0).unwrap_err();
    assert!(
        matches!(&error, ValidationError::Fields(cause)
        if matches!(**cause, FieldError::UnprovenTime {
            cause: ClaimedTimeFailure::TimezoneUnstated,
            ..
        })),
        "{error:?}"
    );
}

#[test]
fn qualifying_properties_must_target_the_signature() {
    // §4.3.1: Target names the qualified Signature; another element is refused.
    let error = assess(include_str!("fixtures/wrong-target.xml"), 0).unwrap_err();
    assert!(
        matches!(&error, ValidationError::Prepare(cause)
            if matches!(**cause, PrepareError::Binding(BindingError::Target { .. }))),
        "{error:?}"
    );
}

#[test]
fn signed_properties_reference_needs_its_type() {
    // §4.4.2: only a reference typed SignedProperties binds the properties;
    // an untyped digest over the same element does not.
    let error = assess(include_str!("fixtures/untyped-signed-properties.xml"), 0).unwrap_err();
    assert!(
        matches!(&error, ValidationError::Prepare(cause)
            if matches!(**cause, PrepareError::Binding(BindingError::Missing { .. }))),
        "{error:?}"
    );
}

#[test]
fn key_info_must_carry_the_signing_certificate() {
    // §6.3(a): an issuer/serial selector resolves the key through the caller's
    // certificates, which XMLDSig accepts, but B-B needs the certificate itself
    // in KeyInfo. The structural refusal names the missing element.
    let lookup = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![ROOT.to_vec()],
        lookup_certs: vec![SIGNER.to_vec(), INTERMEDIATE.to_vec()],
        ..KeyResolverConfig::default()
    });
    let error = verified(
        include_str!("fixtures/issuer-serial-only.xml"),
        &lookup,
        |session, memory| {
            validate_basic(
                session,
                signature(session, 0),
                &[ROOT, SIGNER, INTERMEDIATE],
                memory,
                facts,
            )
        },
    )
    .unwrap_err();
    assert!(
        matches!(&error, ValidationError::Prepare(cause)
        if matches!(**cause, PrepareError::Property(PropertyError::Missing {
            local: "X509Certificate",
            ..
        }))),
        "{error:?}"
    );
}

#[test]
fn signer_trusted_as_its_own_anchor_has_no_certification_path() {
    // With the signer itself configured as the anchor, the validated path is
    // the anchor alone; RFC 5280 §6.1 excludes the anchor, so B-B has no
    // certification path to bind and reports that, not success.
    let pinned = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![SIGNER.to_vec()],
        ..KeyResolverConfig::default()
    });
    let outcome = verified(
        include_str!("fixtures/enveloped.xml"),
        &pinned,
        |session, memory| validate_basic(session, signature(session, 0), &[], memory, facts),
    );
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Path {
                failure: PathFailure::AnchorOnly,
                ..
            })
        ),
        "{outcome:?}"
    );
}

#[test]
fn caller_trusted_key_has_no_certificate_path() {
    // Without path validation a pinned certificate authorizes the key as a
    // caller decision; there is no validated path to re-check.
    let pinned = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![SIGNER.to_vec()],
        ..KeyResolverConfig::default()
    });
    let outcome = verified_with(
        include_str!("fixtures/enveloped.xml"),
        &pinned,
        false,
        |session, memory| validate_basic(session, signature(session, 0), &[], memory, facts),
    );
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Path {
                failure: PathFailure::NotValidated,
                ..
            })
        ),
        "{outcome:?}"
    );
}

#[test]
fn foreign_signature_identity_is_refused() {
    // An identity from another document must not select anything here.
    let foreign = verified(
        include_str!("fixtures/enveloping.xml"),
        &anchored(),
        |session, _| signature(session, 0),
    );
    let error = verified(
        include_str!("fixtures/enveloped.xml"),
        &anchored(),
        |session, memory| validate_basic(session, foreign, &[ROOT], memory, facts),
    )
    .unwrap_err();
    assert!(
        matches!(error, ValidationError::Adapter(Error::Tree(_))),
        "{error:?}"
    );
}

#[test]
fn every_unit_of_work_is_admitted_before_use() {
    // The exact work of a complete validation suffices; one unit less fails
    // with the resource cause and releases every retained allocation. A
    // charge after the work it pays for would let the short account succeed.
    verified(
        include_str!("fixtures/enveloped.xml"),
        &anchored(),
        |session, _| {
            let funded = memory();
            let outcome = validate_basic(session, signature(session, 0), &[ROOT], &funded, facts);
            assert!(matches!(outcome, Ok(Outcome::Assessed(MET))), "{outcome:?}");
            let needed = funded.work_used();
            for (limit, succeeds) in [(needed, true), (needed - 1, false)] {
                let account = Memory::new(Arc::new(MemoryAccount::new(1 << 24, limit)));
                let outcome =
                    validate_basic(session, signature(session, 0), &[ROOT], &account, facts);
                if succeeds {
                    assert!(matches!(outcome, Ok(Outcome::Assessed(MET))), "{outcome:?}");
                } else {
                    let error = format!("{:?}", outcome.unwrap_err());
                    assert!(error.contains("WorkExceeded"), "{error}");
                }
                assert_eq!(account.used(), 0);
            }
        },
    );
}
