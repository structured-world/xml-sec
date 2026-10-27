#![cfg(feature = "xmldsig-sign")]

use std::{cell::Cell, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use xml_sec::{XmlDocument, xmldsig::*};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

fn signed_manifest(digest: &str) -> (XmlDocument, HmacVerificationKey) {
    signed_manifest_named(digest, "")
}

fn signed_manifest_named(digest: &str, suffix: &str) -> (XmlDocument, HmacVerificationKey) {
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let template = format!(
        r##"<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><target Id="target">payload</target><ds:Signature Id="signature"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Id="method" Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference Id="direct" URI="#manifest"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="manifest"><ds:Reference Id="inside" URI="#target"><ds:DigestMethod Algorithm="{digest}"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature></r>"##
    );
    let mut template = template;
    for id in [
        "signature",
        "method",
        "direct",
        "manifest",
        "inside",
        "target",
    ] {
        template = template
            .replace(&format!("Id=\"{id}\""), &format!("Id=\"{id}{suffix}\""))
            .replace(&format!("URI=\"#{id}\""), &format!("URI=\"#{id}{suffix}\""));
    }
    let xml = SignContext::new(&signer).sign_template(&template).unwrap();
    (
        XmlDocument::parse(xml).unwrap(),
        HmacVerificationKey::new(vec![0x61; 32]).unwrap(),
    )
}

#[test]
fn completed_nested_manifest_hash_survives_a_later_frontier_error() {
    // A successful first Manifest digest authenticates a second Manifest whose
    // historical digest is unsupported. Losing VerifyResult must not erase
    // the actual first digest or fabricate execution of the second.
    use base64::Engine as _;
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
    let nested = r##"<ds:Manifest xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="nested"><ds:Reference Id="old" URI="#target"><ds:DigestMethod Algorithm="urn:example:historical-digest"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:Manifest>"##;
    let nested = nested.replace("</ds:Manifest>", r##"<ds:Reference Id="later" URI="#target"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:Manifest>"##);
    let bytes = canonicalize_xml(
        nested.as_bytes(),
        &C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
    )
    .unwrap();
    let digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, &bytes));
    let (original, key) = signed_manifest("http://www.w3.org/2001/04/xmlenc#sha256");
    let template = original.as_xml()
        .replace("Id=\"inside\" URI=\"#target\">", "Id=\"inside\" URI=\"#nested\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>")
        .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &digest)
        .replace("</r>", &format!("{nested}</r>"));
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            assert!(session.evidence().signatures()[0].result().is_err());
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let first = session.view().node_for_id("inside", &[]).unwrap();
            let old = session.view().node_for_id("old", &[]).unwrap();
            let parent = session.view().node_for_id("nested", &[]).unwrap();
            let later = session.view().node_for_id("later", &[]).unwrap();
            let mut seen = (false, false, false);
            assert_eq!(
                selected
                    .visit_hash_uses(|fact| {
                        if fact.instruction == first {
                            assert_eq!(fact.state, HashUseState::Complete);
                            seen.0 = true;
                        } else if fact.instruction == old {
                            assert_eq!(fact.state, HashUseState::Unsupported);
                            assert_eq!(
                                fact.role,
                                HashUseRole::Reference(ReferenceParent::Manifest(parent))
                            );
                            seen.1 = true;
                        } else if fact.instruction == later {
                            assert_eq!(fact.state, HashUseState::Unprocessed);
                            assert_eq!(
                                fact.algorithm,
                                HashUseAlgorithm::Digest(DigestAlgorithm::Sha384)
                            );
                            seen.2 = true;
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap(),
                HashUseCompleteness::Unsupported(old)
            );
            assert_eq!(seen, (true, true, true));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn selected_receipts_do_not_cross_signatures_or_document_generations() {
    // Two independently signed instruction sets must retain their own receipts;
    // foreign and stale handles cannot select either original operation.
    let (first, key) = signed_manifest_named("http://www.w3.org/2001/04/xmlenc#sha256", "1");
    let (second, _) = signed_manifest_named("http://www.w3.org/2001/04/xmlenc#sha256", "2");
    let mut document = XmlDocument::parse(format!(
        "<both>{}{}</both>",
        first.as_xml(),
        second.as_xml()
    ))
    .unwrap();
    let stale = document.with_view(|view| view.node_for_id("signature1", &[]).unwrap());
    let target = document.with_view(|view| view.node_for_id("target1", &[]).unwrap());
    document.replace_content(target, "payload").unwrap();
    let foreign = first.with_view(|view| view.node_for_id("signature1", &[]).unwrap());
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            assert!(session.select_signature(stale).is_err());
            assert!(session.select_signature(foreign).is_err());
            for suffix in ["1", "2"] {
                let signature = session
                    .view()
                    .node_for_id(&format!("signature{suffix}"), &[])
                    .unwrap();
                let selected = session.select_signature(signature)?;
                assert_eq!(
                    selected.signature_method()?.identity,
                    session
                        .view()
                        .node_for_id(&format!("method{suffix}"), &[])
                        .unwrap()
                );
                let mut count = 0;
                selected
                    .visit_hash_uses(|fact| {
                        assert_eq!(fact.signature, signature);
                        count += 1;
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!(count, 3);
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn pure_and_prehash_eddsa_keep_distinct_algorithm_semantics() {
    // Real PureEdDSA must not advertise a selectable message digest, while
    // prehash variants retain SHA-512 versus SHAKE256 with its exact output.
    use pkcs8::EncodePrivateKey as _;
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    let small = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let large = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..]).unwrap();
    for algorithm in [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Ed25519Ctx,
        SignatureAlgorithm::Ed25519Ph,
        SignatureAlgorithm::Ed448,
        SignatureAlgorithm::Ed448Ph,
    ] {
        let der = if matches!(
            algorithm,
            SignatureAlgorithm::Ed25519
                | SignatureAlgorithm::Ed25519Ctx
                | SignatureAlgorithm::Ed25519Ph
        ) {
            small.to_pkcs8_der().unwrap()
        } else {
            large.to_pkcs8_der().unwrap()
        };
        let signer = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
        let builder =
            SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
                .add_reference(
                    ReferenceBuilder::new(DigestAlgorithm::Sha256)
                        .uri("")
                        .transform(Transform::Enveloped),
                );
        let document = XmlDocument::parse(
            SignContext::new(&signer)
                .sign_with_builder("<r/>", &builder)
                .unwrap(),
        )
        .unwrap();
        let key = VerificationKey {
            algorithm,
            public_key_bytes: signer
                .public_key_info()
                .unwrap()
                .spki_der()
                .unwrap()
                .to_vec(),
            certificate_der: None,
            name: None,
        };
        let context = VerifyContext::new().key(&key);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let mut messages = 0;
                selected
                    .visit_hash_uses(|fact| {
                        if fact.role == HashUseRole::SignatureMessage {
                            messages += 1;
                            assert_eq!(fact.state, HashUseState::Complete);
                            assert_eq!(
                                fact.algorithm,
                                match algorithm {
                                    SignatureAlgorithm::Ed25519Ph =>
                                        HashUseAlgorithm::Digest(DigestAlgorithm::Sha512),
                                    SignatureAlgorithm::Ed448Ph => HashUseAlgorithm::Shake256_512,
                                    _ => HashUseAlgorithm::Intrinsic(algorithm),
                                }
                            );
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!(messages, 1);
                Ok(())
            },
        )
        .unwrap();
    }
}

struct CountedKey {
    key: HmacVerificationKey,
    calls: Cell<usize>,
}
impl VerifyingKey for CountedKey {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.calls.set(self.calls.get() + 1);
        self.key.verify(algorithm, data, signature)
    }
    fn validate_policy(
        &self,
        scope: &xml_sec::xmldsig::VerificationScope<'_>,
    ) -> Result<(), DsigError> {
        self.key.validate_policy(scope)
    }
}

#[test]
fn original_hash_receipts_do_not_repeat_signature_verification() {
    // A stale Manifest payload digest was computed, even though it mismatched.
    // Repeated metadata inspection must neither verify again nor lose provenance.
    let (document, key) = signed_manifest("http://www.w3.org/2001/04/xmlenc#sha256");
    let key = CountedKey {
        key,
        calls: Cell::new(0),
    };
    let context = VerifyContext::new().key(&key).process_manifests(true);
    let work = account();
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let signature = session.view().node_for_id("signature", &[]).unwrap();
            let selected = session.select_signature(signature)?;
            assert_eq!(key.calls.get(), 1);
            let method = selected.signature_method()?;
            assert_eq!(
                method.identity,
                session.view().node_for_id("method", &[]).unwrap()
            );
            assert_eq!(method.algorithm, SignatureAlgorithm::HmacSha256);
            for _ in 0..2 {
                let mut roles = Vec::new();
                assert_eq!(
                    selected
                        .visit_hash_uses(|fact| {
                            assert_eq!(fact.signature, signature);
                            assert_eq!(
                                fact.algorithm,
                                HashUseAlgorithm::Digest(DigestAlgorithm::Sha256)
                            );
                            assert_eq!(fact.state, HashUseState::Complete);
                            if let HashUseRole::Reference(ReferenceParent::Manifest(parent)) =
                                fact.role
                            {
                                assert_eq!(
                                    parent,
                                    session.view().node_for_id("manifest", &[]).unwrap()
                                );
                                assert_eq!(
                                    fact.instruction,
                                    session.view().node_for_id("inside", &[]).unwrap()
                                );
                            }
                            roles.push(fact.role);
                            Ok::<_, ()>(())
                        })
                        .unwrap(),
                    HashUseCompleteness::Complete
                );
                assert_eq!(roles.len(), 3);
                assert_eq!(roles[0], HashUseRole::SignatureMessage);
            }
            assert_eq!(key.calls.get(), 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(work.used(), 0);
}

#[test]
fn ignored_and_unsupported_historical_digests_are_not_empty_success() {
    // An ignored Manifest remains declared/unprocessed. An unsupported old
    // digest preserves its original URI even when verification returned Err.
    for (digest, process, state) in [
        (
            "http://www.w3.org/2001/04/xmlenc#sha256",
            false,
            HashUseState::Unprocessed,
        ),
        (
            "urn:example:historical-digest",
            true,
            HashUseState::Unsupported,
        ),
    ] {
        let (document, key) = signed_manifest(digest);
        let context = VerifyContext::new().key(&key).process_manifests(process);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let signature = session.evidence().signatures()[0].identity();
                let selected = session.select_signature(signature)?;
                let mut inner = 0;
                let completeness = selected
                    .visit_hash_uses(|fact| {
                        if matches!(
                            fact.role,
                            HashUseRole::Reference(ReferenceParent::Manifest(_))
                        ) {
                            inner += 1;
                            assert_eq!(fact.state, state);
                            if state == HashUseState::Unsupported {
                                assert_eq!(
                                    fact.algorithm,
                                    HashUseAlgorithm::Unsupported(Some(digest))
                                );
                            }
                        } else {
                            assert_eq!(fact.state, HashUseState::Complete);
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                let original = session.view().node_for_id("inside", &[]).unwrap();
                assert_eq!(inner, 1);
                match state {
                    HashUseState::Unsupported => {
                        assert_eq!(completeness, HashUseCompleteness::Unsupported(original));
                    }
                    HashUseState::Unprocessed => {
                        assert_eq!(completeness, HashUseCompleteness::Unprocessed(original));
                    }
                    HashUseState::Complete => unreachable!(),
                }
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn reference_metadata_scans_are_paid_but_hash_projection_skips_unused_attributes() {
    // URI/Type catalogue reads must pay their attribute scans. Hash projection
    // needs neither field and must not perform those unused scans at all.
    use std::fmt::Write as _;
    let (original, key) = signed_manifest("http://www.w3.org/2001/04/xmlenc#sha256");
    let mut attributes = String::new();
    for index in 0..1024 {
        write!(&mut attributes, " a{index}=\"x\"").unwrap();
    }
    let template = original
        .as_xml()
        .replace("Id=\"inside\"", &format!("Id=\"inside\"{attributes}"));
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    for hash_only in [true, false] {
        let work = account();
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &work,
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let remaining = work.work_remaining();
                assert!(remaining > 4096);
                Work::charge_work(&work, (remaining - 4096) as u64).unwrap();
                let mut calls = 0;
                if hash_only {
                    assert_eq!(
                        selected
                            .visit_hash_uses(|_| {
                                calls += 1;
                                Ok::<_, ()>(())
                            })
                            .unwrap(),
                        HashUseCompleteness::Complete
                    );
                    assert_eq!(calls, 3);
                } else {
                    let result = selected.visit_authenticated_references(|_| {
                        calls += 1;
                        Ok::<_, ()>(())
                    });
                    assert!(matches!(
                        result,
                        Err(CatalogueError::Processing(DsigError::SharedExecution(_)))
                    ));
                    assert_eq!(
                        calls, 1,
                        "expensive inner attributes must be admitted before its callback"
                    );
                }
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn malformed_authenticated_methods_keep_original_provenance() {
    // Missing method versus missing Algorithm are distinct original shapes,
    // neither an empty successful catalogue nor an invented digest method.
    for replacement in ["", "<ds:DigestMethod/>"] {
        let (original, key) = signed_manifest("urn:example:historical-digest");
        let template = original.as_xml().replace(
            "<ds:DigestMethod Algorithm=\"urn:example:historical-digest\"/>",
            replacement,
        );
        let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
        let document =
            XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap())
                .unwrap();
        let context = VerifyContext::new().key(&key).process_manifests(true);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let original = session.view().node_for_id("inside", &[]).unwrap();
                let mut found = false;
                assert_eq!(
                    selected
                        .visit_hash_uses(|fact| {
                            if fact.instruction == original {
                                assert_eq!(fact.algorithm, HashUseAlgorithm::Unsupported(None));
                                assert_eq!(fact.state, HashUseState::Unsupported);
                                assert_eq!(fact.method.is_some(), !replacement.is_empty());
                                found = true;
                            }
                            Ok::<_, ()>(())
                        })
                        .unwrap(),
                    HashUseCompleteness::Unsupported(original)
                );
                assert!(found);
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn visitor_refusal_is_typed_and_immediate() {
    // Metadata must stop at the first caller refusal, before any Reference walk.
    let (document, key) = signed_manifest("http://www.w3.org/2001/04/xmlenc#sha256");
    let context = VerifyContext::new().key(&key);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut calls = 0;
            let result = selected.visit_hash_uses(|_| {
                calls += 1;
                Err(47u8)
            });
            assert!(matches!(result, Err(CatalogueError::Visitor(47))));
            assert_eq!(calls, 1);
            Ok(())
        },
    )
    .unwrap();
}

fn exhausted_inspection(work: &impl Work) {
    let (document, key) = signed_manifest("http://www.w3.org/2001/04/xmlenc#sha256");
    let context = VerifyContext::new().key(&key);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            // Spend exactly the remaining test allowance, independently of how much
            // original verification needed. Failed admissions do not reset Work.
            for shift in (0..=28).rev() {
                while work.charge_work(1 << shift).is_ok() {}
            }
            let result = selected.visit_hash_uses(|_| -> Result<(), ()> {
                panic!("work refusal precedes callback")
            });
            assert!(matches!(
                result,
                Err(CatalogueError::Processing(DsigError::SharedExecution(_)))
            ));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn both_current_work_ceilings_gate_inspection() {
    // Retained verification is not prepayment for later metadata inspection;
    // independently exhaust aggregate Memory and a borrowed local Execution.
    exhausted_inspection(&account());
    let parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1 << 20,
            ..Default::default()
        },
        account(),
    );
    let reader = parser.read(&[], 0).unwrap();
    exhausted_inspection(&reader.execution());
}

#[test]
fn independently_parameterized_pss_hashes_come_from_the_original_method() {
    // Actual RSA signing/verification must preserve independent message/MGF1
    // hashes and salt length, not infer a method from its generic rsa-pss URI.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    let parameters = RsaPssParameters {
        digest: DigestAlgorithm::Sha256,
        mgf_digest: DigestAlgorithm::Sha512,
        salt_len: 17,
    };
    let algorithm = SignatureAlgorithm::RsaPss(parameters);
    let signer =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let builder =
        SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
            .add_reference(
                ReferenceBuilder::new(DigestAlgorithm::Sha384)
                    .uri("")
                    .transform(Transform::Enveloped),
            );
    let xml = SignContext::new(&signer)
        .policy(xml_sec::policy::SigningPolicy {
            parameterized_rsa_pss: xml_sec::policy::RsaPssPermission::AllSupported,
            ..Default::default()
        })
        .sign_with_builder("<root/>", &builder)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let key = VerificationKey {
        algorithm,
        public_key_bytes: pem::parse(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"))
            .unwrap()
            .into_contents(),
        certificate_der: None,
        name: None,
    };
    let context = VerifyContext::new()
        .key(&key)
        .policy(xml_sec::policy::VerificationPolicy {
            parameterized_rsa_pss: xml_sec::policy::RsaPssPermission::AllSupported,
            ..Default::default()
        });
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            assert_eq!(selected.signature_method()?.algorithm, algorithm);
            let mut hashes = Vec::new();
            assert_eq!(
                selected
                    .visit_hash_uses(|fact| {
                        assert_eq!(fact.state, HashUseState::Complete);
                        let HashUseAlgorithm::Digest(digest) = fact.algorithm else {
                            panic!("PSS and Reference roles require fixed digests")
                        };
                        hashes.push(digest);
                        Ok::<_, ()>(())
                    })
                    .unwrap(),
                HashUseCompleteness::Complete
            );
            assert_eq!(
                hashes,
                vec![
                    DigestAlgorithm::Sha256,
                    DigestAlgorithm::Sha512,
                    DigestAlgorithm::Sha384
                ]
            );
            Ok(())
        },
    )
    .unwrap();
}
