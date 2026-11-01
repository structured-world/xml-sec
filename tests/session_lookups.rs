//! Operation-bound lookups a verified session offers extension formats.

#![cfg(feature = "xmldsig-sign")]

use std::collections::BTreeSet;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::policy::{PolicyViolation, SameDocumentIdSemantics, VerificationPolicy};
use xml_sec::provider::ProviderError;
use xml_sec::{XmlDocument, xmldsig::*};

const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

/// A verified HMAC signature over `#target`, next to `DigestMethod` elements
/// with a known, an unknown, an absent and a policy-restricted algorithm.
fn with_session(check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>, &Memory)) {
    with_session_in(|_| {}, check);
}

fn with_session_in(
    configure: impl FnOnce(&mut VerificationPolicy),
    check: impl FnOnce(&VerifiedSession<'_, '_, '_, Memory>, &Memory),
) {
    let template = format!(
        r##"<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><target Id="target">payload</target><numeric Id="12345"/><twin Id="twin"/><twin Id="twin"/><methods><ds:DigestMethod Id="known" Algorithm="{SHA256}"/><ds:DigestMethod Id="padded" Algorithm="&#10; {SHA256}&#9;"/><ds:DigestMethod Id="unknown" Algorithm="urn:example:digest"/><ds:DigestMethod Id="absent"/><ds:DigestMethod Id="restricted" Algorithm="{SHA1}"/><other Id="other"/></methods><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></r>"##
    );
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let key = HmacVerificationKey::new(vec![0x61; 32]).unwrap();
    let mut policy = VerificationPolicy {
        digest_algorithms: Some(BTreeSet::from([DigestAlgorithm::Sha256])),
        ..VerificationPolicy::default()
    };
    configure(&mut policy);
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
            "#%78pointer(id('target'))",
            "#1target",
            "#12345",
            "#tar%6",
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
fn bare_names_follow_the_operation_fragment_rules() {
    // The lookup shares the dereference kernel: XPointer Framework §§3-4
    // unescaping applies to a specification bare name, and a compatibility
    // mode's own ID grammar decides, rather than a separate NCName check.
    // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#escaping
    with_session(|session, work| {
        let target = session.view().node_for_id("target", &[]).unwrap();
        assert_eq!(
            session.resolve_bare_name_in("#tar%67et", work).unwrap(),
            BareNameTarget::Element(target)
        );
    });
    let visa3d = |policy: &mut VerificationPolicy| {
        policy.transforms.same_document_id_semantics = SameDocumentIdSemantics::XmlSecVisa3d;
    };
    with_session_in(visa3d, |session, work| {
        let numeric = session.view().node_for_id("12345", &[]).unwrap();
        assert_eq!(
            session.resolve_bare_name_in("#12345", work).unwrap(),
            BareNameTarget::Element(numeric)
        );
        assert_eq!(
            session
                .resolve_bare_name_in("#xpointer(id('12345'))", work)
                .unwrap(),
            BareNameTarget::NotBareName
        );
    });
}

#[test]
fn certificate_processing_limits_come_from_the_policy() {
    // Extension formats re-checking certificates get no separate limit
    // surface: the parser's fresh account carries the operation's X.509 work
    // and workspace allowances, and the path bounds its maximum depth.
    let configure = |policy: &mut VerificationPolicy| {
        policy.resources.max_x509_work = 123_456;
        policy.resources.max_x509_workspace_bytes = 654_321;
        policy.key_trust.max_x509_chain_depth = 4;
    };
    with_session_in(configure, |session, work| {
        let parser = session.certificate_parser();
        assert_eq!(parser.memory().work_remaining(), 123_456);
        assert_eq!(parser.memory().limit(), 654_321);
        assert!(!parser.memory().same_account(work));
        // RFC 5280 §6.1: the anchor is not part of the bounded path.
        assert_eq!(session.certificate_path_bounds().depth, 3);
        assert!(std::ptr::eq(session.execution(), work));
    });
}

#[test]
fn digest_methods_resolve_under_the_compiled_policy() {
    // Unknown and absent algorithms are facts; a known algorithm the policy
    // forbids is a policy error, never reported as merely unsupported.
    // Algorithm is xs:anyURI, so edge XML whitespace collapses away.
    with_session(|session, work| {
        let node = |id| session.view().node_for_id(id, &[]).unwrap();
        for id in ["known", "padded"] {
            assert_eq!(
                session.resolve_digest_method_in(node(id), work).unwrap(),
                DigestMethodResolution::Supported(DigestAlgorithm::Sha256),
                "{id}"
            );
        }
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
    // FIPS 180-4 Appendix B.1 known answer for SHA-256("abc"), absorbed in two
    // chunks; each chunk is charged before the provider sees it.
    with_session(|session, work| {
        let mut digest = session.begin_digest(DigestAlgorithm::Sha256, work).unwrap();
        digest.update(b"a", work).unwrap();
        digest.update(b"bc", work).unwrap();
        let before_finish = work.work_used();
        let mut output = [0; 32];
        digest.finish(&mut output, work).unwrap();
        assert_eq!(
            output,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert!(
            work.work_used() >= before_finish + 32,
            "digest finalization and output must be admitted by the current query"
        );
        assert!(matches!(
            session.begin_digest(DigestAlgorithm::Sha1, work),
            Err(DsigError::Policy(PolicyViolation::Algorithm { .. }))
        ));
        let starved = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 2)));
        let mut digest = session.begin_digest(DigestAlgorithm::Sha256, work).unwrap();
        assert!(matches!(
            digest.update(b"abc", &starved),
            Err(DsigError::SharedExecution(MemoryError::WorkExceeded))
        ));
        assert_eq!(starved.used(), 0);
        // State creation answers to the same execution, with the same cause.
        let empty = Memory::new(Arc::new(MemoryAccount::new(0, 16)));
        assert!(matches!(
            session.begin_digest(DigestAlgorithm::Sha256, &empty),
            Err(DsigError::Provider(ProviderError::Resource(
                MemoryError::LimitExceeded
            )))
        ));
        let spent = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0)));
        assert!(matches!(
            session.begin_digest(DigestAlgorithm::Sha256, &spent),
            Err(DsigError::SharedExecution(MemoryError::WorkExceeded))
        ));
    });
}
