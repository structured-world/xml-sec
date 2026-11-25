//! BES validation of ETSI TS 101 903 V1.2.2 signatures through the public entry.
//!
//! The fixtures come from `xml-sec-tools xades fixtures --ts101903`: xmlsec1
//! signs V1.2.2 templates over their own root -> intermediate -> signer path.

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_xades::container::ContainerError;
use structured_xades::legacy::CertificateMatch;
use xml_sec::XmlDocument;
use xml_sec::document::NodeIdentity;
use xml_sec::policy::{Instant, VerificationPolicy, XadesSyntax};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, VerificationRequest, VerifiedSession, VerifyContext,
    with_verified_request,
};
use xml_sec_xades::{
    Outcome, Syntax, Ts101903Error, Ts101903Report, ValidationError, validate_basic,
    validate_ts101903,
};

const ROOT: &[u8] = include_bytes!("fixtures/ts101903/root.der");
const EN_ROOT: &[u8] = include_bytes!("fixtures/root.der");
type Session<'v, 'c, 'i> = VerifiedSession<'v, 'c, 'i, Memory>;

/// Facts a test asserts, copied out of the borrowed report.
#[derive(Debug, PartialEq, Eq)]
struct Facts {
    met: bool,
    embedded: bool,
    digest: bool,
    signed: Vec<&'static str>,
}

fn facts(report: &Ts101903Report<'_>) -> Facts {
    let certificate = report.signer().certificate;
    Facts {
        met: report.bes_met(),
        embedded: matches!(certificate, CertificateMatch::Embedded(_)),
        digest: matches!(certificate, CertificateMatch::Digest(_)),
        signed: report
            .signed()
            .iter()
            .map(|property| property.name)
            .collect(),
    }
}

/// Verify `xml` with its path checked against `root` in 2027, under a policy
/// reading `syntax`, then run `check` over the verified session.
fn verified<R>(
    xml: &str,
    root: &[u8],
    syntax: XadesSyntax,
    check: impl FnOnce(&Session<'_, '_, '_>, NodeIdentity) -> R,
) -> R {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(1_800_000_000, 0);
    policy.xades_syntax = syntax;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.to_vec()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).expect("fixture parses");
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            Ok(check(&session, signature))
        },
    )
    .expect("fixture verifies as XMLDSig")
}

fn assess(xml: &str) -> Result<Outcome<Facts>, ValidationError> {
    verified(
        xml,
        ROOT,
        XadesSyntax::WithTs101903V122,
        |session, signature| validate_ts101903(session, signature, &[ROOT], facts),
    )
}

#[test]
fn a_signature_protecting_its_signing_certificate_meets_bes() {
    // TS 101 903 V1.2.2 4.4.1: the BES signs SigningCertificate or the
    // KeyInfo carrying the signing certificate. Either protects the checked
    // path's target, which holds the verifying key.
    let outcome = assess(include_str!("fixtures/ts101903/signing-certificate.xml"));
    assert!(
        matches!(
            &outcome,
            Ok(Outcome::Assessed(Facts { met: true, digest: true, signed, .. }))
                if signed == &["SigningTime", "SigningCertificate", "SignaturePolicyIdentifier"]
        ),
        "{outcome:?}"
    );
    let outcome = assess(include_str!("fixtures/ts101903/key-info.xml"));
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Assessed(Facts {
                met: true,
                embedded: true,
                ..
            }))
        ),
        "{outcome:?}"
    );
}

#[test]
fn a_signing_certificate_naming_another_certificate_does_not_meet_bes() {
    // The signed digest names the root, not the path's target.
    let outcome = assess(include_str!("fixtures/ts101903/other-certificate.xml"));
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Assessed(Facts {
                met: false,
                digest: false,
                embedded: false,
                ..
            }))
        ),
        "{outcome:?}"
    );
}

#[test]
fn each_syntax_is_validated_only_by_its_own_operation() {
    // EN 319 132-1 levels do not apply to a V1.2.2 signature, nor the V1.2.2
    // BES to an EN 319 132-1 one: each is the completed fact of its syntax.
    let outcome = verified(
        include_str!("fixtures/ts101903/signing-certificate.xml"),
        ROOT,
        XadesSyntax::WithTs101903V122,
        |session, signature| validate_basic(session, signature, &[ROOT], |_| ()),
    );
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Syntax {
                syntax: Syntax::Ts101903V122,
                ..
            })
        ),
        "{outcome:?}"
    );
    let outcome = verified(
        include_str!("fixtures/enveloped.xml"),
        EN_ROOT,
        XadesSyntax::WithTs101903V122,
        |session, signature| validate_ts101903(session, signature, &[EN_ROOT], |_| ()),
    );
    assert!(
        matches!(
            outcome,
            Ok(Outcome::Syntax {
                syntax: Syntax::En319132,
                ..
            })
        ),
        "{outcome:?}"
    );
}

#[test]
fn a_policy_reading_en_319_132_alone_finds_no_v122_properties() {
    // Without the policy's admission the V1.2.2 namespace names no qualifying
    // properties, so the signature has none.
    let outcome = verified(
        include_str!("fixtures/ts101903/signing-certificate.xml"),
        ROOT,
        XadesSyntax::En319132,
        |session, signature| validate_ts101903(session, signature, &[ROOT], |_| ()),
    );
    assert!(
        matches!(
            &outcome,
            Err(ValidationError::Ts101903(error))
                if matches!(**error, Ts101903Error::Container(ContainerError::Missing { .. }))
        ),
        "{outcome:?}"
    );
}
