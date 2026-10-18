//! Operation-bound lookups a verified session offers extension formats.

#![cfg(feature = "xmldsig")]

use std::collections::HashSet;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::policy::{PolicyViolation, VerificationPolicy};
use xml_sec::{XmlDocument, xmldsig::*};

const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

/// A verified HMAC signature over `#target`, next to DigestMethod elements
/// with a known, an unknown, an absent and a policy-restricted algorithm.
fn with_session(check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>, &Memory)) {
    let template = format!(
        r##"<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><target Id="target">payload</target><twin Id="twin"/><twin Id="twin"/><methods><ds:DigestMethod Id="known" Algorithm="{SHA256}"/><ds:DigestMethod Id="unknown" Algorithm="urn:example:digest"/><ds:DigestMethod Id="absent"/><ds:DigestMethod Id="restricted" Algorithm="{SHA1}"/><other Id="other"/></methods><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></r>"##
    );
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let key = HmacVerificationKey::new(vec![0x61; 32]).unwrap();
    let policy = VerificationPolicy {
        digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha256])),
        ..VerificationPolicy::default()
    };
    let context = VerifyContext::new().policy(policy).key(&key);
    let work = account();
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            check(&session, &work);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn bare_names_resolve_only_in_their_specified_form() {
    // XMLDSig 1.1 §4.4.3.3: "#id" names one element through the operation's
    // ID rules. Other URI forms are reported, never reinterpreted as an ID.
    with_session(|session, work| {
        let target = session.view().node_for_id("target", &[]).unwrap();
        assert_eq!(
            session.resolve_bare_name_in("#target", work).unwrap(),
            BareNameTarget::Element(target)
        );
        for uri in ["#missing", "#twin"] {
            assert_eq!(
                session.resolve_bare_name_in(uri, work).unwrap(),
                BareNameTarget::Unresolved,
                "{uri}"
            );
        }
        for uri in [
            "",
            "target",
            "#xpointer(id('target'))",
            "#1target",
            "other#target",
        ] {
            assert_eq!(
                session.resolve_bare_name_in(uri, work).unwrap(),
                BareNameTarget::NotBareName,
                "{uri}"
            );
        }
    });
}

#[test]
fn digest_methods_resolve_under_the_compiled_policy() {
    // Unknown and absent algorithms are facts; a known algorithm the policy
    // forbids is a policy error, never reported as merely unsupported.
    with_session(|session, work| {
        let node = |id| session.view().node_for_id(id, &[]).unwrap();
        assert_eq!(
            session
                .resolve_digest_method_in(node("known"), work)
                .unwrap(),
            DigestMethodResolution::Supported(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            session
                .resolve_digest_method_in(node("unknown"), work)
                .unwrap(),
            DigestMethodResolution::Unsupported
        );
        assert_eq!(
            session
                .resolve_digest_method_in(node("absent"), work)
                .unwrap(),
            DigestMethodResolution::Malformed
        );
        assert!(matches!(
            session.resolve_digest_method_in(node("restricted"), work),
            Err(DsigError::Policy(PolicyViolation::Algorithm { .. }))
        ));
        assert!(matches!(
            session.resolve_digest_method_in(node("other"), work),
            Err(DsigError::InvalidRequest { .. })
        ));
    });
}

#[test]
fn digests_use_the_selected_provider_and_policy() {
    // FIPS 180-4 Appendix B.1 known answer for SHA-256("abc"); the output is
    // charged to the caller's account and released with it.
    with_session(|session, work| {
        let held = work.used();
        let digest = session
            .digest_in(DigestAlgorithm::Sha256, b"abc", work)
            .unwrap();
        assert_eq!(
            &digest[..],
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert!(work.used() > held);
        drop(digest);
        assert_eq!(work.used(), held);
        assert!(matches!(
            session.digest_in(DigestAlgorithm::Sha1, b"abc", work),
            Err(DsigError::Policy(PolicyViolation::Algorithm { .. }))
        ));
        let starved = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 2)));
        assert!(matches!(
            session.digest_in(DigestAlgorithm::Sha256, b"abc", &starved),
            Err(DsigError::SharedExecution(MemoryError::WorkExceeded))
        ));
        assert_eq!(starved.used(), 0);
    });
}
