//! Public request/evidence integration with real cryptographic verification.

#![cfg(feature = "xmldsig")]

use std::collections::HashMap;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    CallerTrustedSignatureKey, DigestAlgorithm, DsigError, DsigStatus, HmacSigningKey,
    HmacVerificationKey, ReferenceBuilder, SignContext, SignatureAlgorithm, SignatureBuilder,
    SignatureRequirement, Transform, VerificationRequest, VerifyContext,
};
use xml_sec::{XmlDocument, XmlDocumentError};

fn signed_pair() -> (XmlDocument, HmacVerificationKey, HmacVerificationKey) {
    let first_secret = vec![0x31; 32];
    let second_secret = vec![0x72; 32];
    let first = HmacSigningKey::new(first_secret.clone()).unwrap();
    let second = HmacSigningKey::new(second_secret.clone()).unwrap();
    let builder = |id: &str| {
        SignatureBuilder::new(
            C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::HmacSha256,
        )
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri(format!("#{id}"))
                .transform(Transform::C14n(C14nAlgorithm::new(
                    C14nMode::Exclusive1_0,
                    false,
                ))),
        )
    };
    let xml = SignContext::new(&first)
        .sign_with_builder(
            "<root><payload ID=\"first\">one</payload><payload ID=\"second\">two</payload></root>",
            &builder("first"),
        )
        .unwrap();
    let xml = SignContext::new(&second)
        .sign_with_builder(&xml, &builder("second"))
        .unwrap();
    (
        XmlDocument::parse(xml).unwrap(),
        HmacVerificationKey::new(first_secret).unwrap(),
        HmacVerificationKey::new(second_secret).unwrap(),
    )
}

#[test]
fn empty_uri_authenticates_document_elements_but_not_its_signature() {
    // Whole-document digest success must retain its original root identity,
    // while the enveloped transform still excludes the owning Signature.
    let secret = vec![0x45; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let verifier = HmacVerificationKey::new(secret).unwrap();
    for uri in ["", "#xpointer(/)"] {
        let builder = SignatureBuilder::new(
            C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::HmacSha256,
        )
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri(uri)
                .transform(Transform::Enveloped),
        );
        let xml = SignContext::new(&signer)
            .sign_with_builder(
                "<root><payload ID=\"target\">signed</payload></root>",
                &builder,
            )
            .unwrap();
        let document = XmlDocument::parse(xml).unwrap();
        let (root, targets) = document.with_view(|view| {
            (
                view.root(),
                [
                    view.root_element(),
                    view.node_for_id("target", &[]).unwrap(),
                ],
            )
        });
        let evidence = VerifyContext::new()
            .key(&verifier)
            .verify_request(
                &document,
                &VerificationRequest {
                    expected_targets: &targets,
                    ..VerificationRequest::default()
                },
            )
            .unwrap();
        assert!(evidence.all_valid());
        assert_eq!(
            evidence.signatures()[0]
                .result()
                .as_ref()
                .unwrap()
                .signed_info_references[0]
                .target_identity,
            Some(root)
        );
        for target in targets {
            assert!(evidence.covers_element(&document, target).unwrap());
        }
        assert!(
            !evidence
                .covers_element(&document, evidence.signatures()[0].identity())
                .unwrap()
        );
        assert!(evidence.accepted(&document).unwrap());
    }
}

#[test]
fn distinct_authorized_keys_bind_each_signature_and_expected_element() {
    // Independent keys authenticate independent elements, without a resolver
    // silently substituting embedded material or conflating lookalike names.
    let (document, first, second) = signed_pair();
    let discovery = VerifyContext::new()
        .signature_identities(&document)
        .unwrap();
    let keys = [
        CallerTrustedSignatureKey {
            signature: discovery[0],
            key: &first,
        },
        CallerTrustedSignatureKey {
            signature: discovery[1],
            key: &second,
        },
    ];
    let targets = document.with_view(|view| {
        [
            view.node_for_id("first", &[]).unwrap(),
            view.node_for_id("second", &[]).unwrap(),
        ]
    });
    let request = VerificationRequest {
        expected_targets: &targets,
        trusted_keys: &keys,
        signatures: SignatureRequirement::Exactly(2),
        correlation: Some([0x55; 16]),
        ..VerificationRequest::default()
    };
    let evidence = VerifyContext::new()
        .verify_request(&document, &request)
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    assert!(evidence.all_valid());
    assert_eq!(evidence.correlation(), request.correlation);
    for (signature, target) in evidence.signatures().iter().zip(targets) {
        let result = signature.result().as_ref().unwrap();
        assert_eq!(result.status, DsigStatus::Valid);
        assert_eq!(
            result.signed_info_references[0].target_identity,
            Some(target)
        );
        assert!(
            result.signed_info_references[0]
                .reference_identity
                .is_some()
        );
        assert!(evidence.covers_element(&document, target).unwrap());
    }
}

#[test]
fn partial_success_requires_explicit_request_and_cannot_cover_failed_target() {
    // A correct digest under an invalid SignatureValue is not authentication.
    let (document, first, _) = signed_pair();
    let targets = document.with_view(|view| {
        [
            view.node_for_id("first", &[]).unwrap(),
            view.node_for_id("second", &[]).unwrap(),
        ]
    });
    let context = VerifyContext::new().key(&first);
    let evidence = context.verify_all(&document).unwrap();
    assert!(!evidence.accepted(&document).unwrap());
    assert!(!evidence.all_valid());
    assert!(evidence.covers_element(&document, targets[0]).unwrap());
    assert!(!evidence.covers_element(&document, targets[1]).unwrap());
    let request = VerificationRequest {
        expected_targets: &targets[..1],
        signatures: SignatureRequirement::AtLeast(1),
        ..VerificationRequest::default()
    };
    assert!(
        context
            .verify_request(&document, &request)
            .unwrap()
            .accepted(&document)
            .unwrap()
    );
    let request = VerificationRequest {
        expected_targets: &targets,
        ..request
    };
    assert!(
        !context
            .verify_request(&document, &request)
            .unwrap()
            .accepted(&document)
            .unwrap()
    );
}

#[test]
fn mutations_invalidate_report_and_request_identities() {
    // A proof is tied to a retained generation, even if the mutation changes
    // only an unsigned sibling and the earlier signature remains mathematical.
    let (mut document, first, _) = signed_pair();
    let target = document.with_view(|view| view.node_for_id("second", &[]).unwrap());
    let evidence = VerifyContext::new()
        .key(&first)
        .verify_all(&document)
        .unwrap();
    document.replace_content(target, "replacement").unwrap();
    let current = document.with_view(|view| view.node_for_id("first", &[]).unwrap());
    assert!(matches!(
        evidence.covers_element(&document, current),
        Err(DsigError::Document(XmlDocumentError::StaleIdentity { .. }))
    ));
    let targets = [target];
    let request = VerificationRequest {
        expected_targets: &targets,
        ..VerificationRequest::default()
    };
    assert!(matches!(
        VerifyContext::new()
            .key(&first)
            .verify_request(&document, &request),
        Err(DsigError::Document(XmlDocumentError::StaleIdentity { .. }))
    ));
}

#[test]
fn request_acceptance_cannot_authorize_a_mutated_document() {
    // Acceptance is an authorization decision about one generation, not a
    // cached boolean that may approve replacement content after verification.
    let (mut document, first, _) = signed_pair();
    let target = document.with_view(|view| view.node_for_id("first", &[]).unwrap());
    let targets = [target];
    let request = VerificationRequest {
        expected_targets: &targets,
        signatures: SignatureRequirement::AtLeast(1),
        ..VerificationRequest::default()
    };
    let evidence = VerifyContext::new()
        .key(&first)
        .verify_request(&document, &request)
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    let foreign = XmlDocument::parse(document.as_xml().to_owned()).unwrap();
    assert!(matches!(
        evidence.accepted(&foreign),
        Err(DsigError::Document(XmlDocumentError::ForeignIdentity))
    ));
    document
        .replace_content(target, "unsigned replacement")
        .unwrap();
    assert!(matches!(
        evidence.accepted(&document),
        Err(DsigError::Document(XmlDocumentError::StaleIdentity { .. }))
    ));
}

#[test]
fn ambiguous_key_authorization_is_rejected_instead_of_trying_keys() {
    // Request mappings are authorization, not an attacker-driven key search.
    let (document, first, second) = signed_pair();
    let evidence = VerifyContext::new()
        .key(&first)
        .verify_all(&document)
        .unwrap();
    let signature = evidence.signatures()[0].identity();
    let keys = [
        CallerTrustedSignatureKey {
            signature,
            key: &first,
        },
        CallerTrustedSignatureKey {
            signature,
            key: &second,
        },
    ];
    let request = VerificationRequest {
        trusted_keys: &keys,
        ..VerificationRequest::default()
    };
    assert!(matches!(
        VerifyContext::new().verify_request(&document, &request),
        Err(DsigError::InvalidRequest {
            reason: "ambiguous trusted keys for one Signature"
        })
    ));
}

#[test]
fn invalid_request_cardinality_and_foreign_keys_fail_before_verification() {
    // Empty success is forbidden, and a Signature handle from another retained
    // document cannot authorize any node in this one even with the right key.
    let (document, first, _) = signed_pair();
    for signatures in [
        SignatureRequirement::AtLeast(0),
        SignatureRequirement::Exactly(0),
    ] {
        let request = VerificationRequest {
            signatures,
            ..VerificationRequest::default()
        };
        assert!(matches!(
            VerifyContext::new()
                .key(&first)
                .verify_request(&document, &request),
            Err(DsigError::InvalidRequest {
                reason: "signature requirement must be nonzero"
            })
        ));
    }
    let foreign = XmlDocument::parse(document.as_xml().to_owned()).unwrap();
    let signature = VerifyContext::new().signature_identities(&foreign).unwrap()[0];
    let keys = [CallerTrustedSignatureKey {
        signature,
        key: &first,
    }];
    let request = VerificationRequest {
        trusted_keys: &keys,
        ..VerificationRequest::default()
    };
    assert!(matches!(
        VerifyContext::new().verify_request(&document, &request),
        Err(DsigError::Document(XmlDocumentError::ForeignIdentity))
    ));
}

#[test]
fn request_key_authorization_cannot_relax_compiled_policy() {
    // A request contributes trusted material, not permission to bypass the
    // immutable preset-key source rule.
    use xml_sec::policy::VerificationPolicy;
    let (document, first, second) = signed_pair();
    let identities = VerifyContext::new()
        .signature_identities(&document)
        .unwrap();
    let keys = [
        CallerTrustedSignatureKey {
            signature: identities[0],
            key: &first,
        },
        CallerTrustedSignatureKey {
            signature: identities[1],
            key: &second,
        },
    ];
    let request = VerificationRequest {
        trusted_keys: &keys,
        ..VerificationRequest::default()
    };
    let mut policy = VerificationPolicy::default();
    policy.key_sources.preset_key = false;
    let report = VerifyContext::new()
        .policy(policy)
        .verify_request(&document, &request)
        .unwrap();
    assert!(!report.accepted(&document).unwrap());
    assert!(report.signatures().iter().all(|entry| matches!(
        entry.result(),
        Err(DsigError::Policy(
            xml_sec::policy::PolicyViolation::KeyTrust { .. }
        ))
    )));
}

#[test]
fn external_evidence_identifies_resolved_bytes_not_the_lexical_uri() {
    // XML Base changes the supplied resource key; evidence must describe the
    // bytes actually digested, not a similarly named map entry.
    use sha2::{Digest, Sha256};
    use xml_sec::policy::{SigningPolicy, VerificationPolicy};
    use xml_sec::xmldsig::UriTypeSet;
    let secret = vec![0x31; 32];
    let signing_key = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let resources = HashMap::from([
        (
            "https://example.test/data/payload".to_owned(),
            b"authenticated bytes".to_vec(),
        ),
        ("payload".to_owned(), b"different bytes".to_vec()),
    ]);
    let mut signing_policy = SigningPolicy::default();
    signing_policy.uris.references = UriTypeSet::ALL;
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("payload"));
    let xml = SignContext::new(&signing_key)
        .policy(signing_policy)
        .external_resources(&resources)
        .sign_with_builder("<root xml:base=\"https://example.test/data/\"/>", &builder)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = VerificationPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let evidence = VerifyContext::new()
        .policy(policy)
        .key(&key)
        .verify_request(&document, &request)
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    let reference = &evidence.signatures()[0]
        .result()
        .as_ref()
        .unwrap()
        .signed_info_references[0];
    let expected: [u8; 32] = Sha256::digest(b"authenticated bytes").into();
    assert_eq!(reference.external_resource_fingerprint, Some(expected));
    assert_eq!(reference.target_identity, None);
}

#[test]
fn mathematical_embedded_key_success_is_not_authorized_coverage() {
    // XMLDSig core validation and application trust are distinct. The exact
    // real fixture is needed here to exercise certificate discovery end to end.
    use xml_sec::policy::{VerificationPolicy, VerificationTrustMode};
    use xml_sec::xmldsig::{DefaultKeyResolver, KeyTrustEvidence};
    let document = XmlDocument::parse(include_str!(
        "fixtures/saml/response_signed_by_idp_ecdsa.xml"
    ))
    .unwrap();
    let target = document.with_view(|view| view.root_element());
    let resolver = DefaultKeyResolver::default();
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    let evidence = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify_all(&document)
        .unwrap();
    assert!(evidence.all_valid());
    assert_eq!(
        evidence.signatures()[0]
            .result()
            .as_ref()
            .unwrap()
            .key_trust,
        KeyTrustEvidence::NotEstablished
    );
    assert!(!evidence.covers_element(&document, target).unwrap());
}

#[test]
fn duplicate_document_ids_never_become_ambiguous_coverage_proofs() {
    // Wrapping by duplicating an ID must fail even when both values are equal.
    let (document, first, _) = signed_pair();
    let xml = document.as_xml().replace("ID=\"second\"", "ID=\"first\"");
    match XmlDocument::parse(xml) {
        Err(_) => {}
        Ok(document) => {
            let evidence = VerifyContext::new()
                .key(&first)
                .verify_all(&document)
                .unwrap();
            assert!(!evidence.accepted(&document).unwrap());
            assert!(!evidence.all_valid());
        }
    }
}

#[cfg(all(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree"))]
#[test]
fn runtime_backend_matrix_preserves_identity_bound_coverage() {
    // Differential parsing must expose the same evidence contract, not a
    // backend-specific identity or an extra semantic validation layer.
    use xml_sec::XmlBackend;
    let (source, first, _) = signed_pair();
    for backend in [
        XmlBackend::Xmloxide,
        XmlBackend::Roxmltree,
        XmlBackend::Differential,
    ] {
        let document =
            XmlDocument::parse_with_backend(source.as_xml().to_owned(), backend).unwrap();
        let target = document.with_view(|view| view.node_for_id("first", &[]).unwrap());
        let context = VerifyContext::new().xml_backend(backend).key(&first);
        let report = context.verify_all(&document).unwrap();
        assert_eq!(context.signature_identities(&document).unwrap().len(), 2);
        assert!(!report.all_valid());
        assert!(report.covers_element(&document, target).unwrap());
    }
}
