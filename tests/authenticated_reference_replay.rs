//! Scoped continuation qualification with actual HMAC signatures, not accepting
//! mock providers. Payload validity is deliberately separate from instruction authentication.
#![cfg(feature = "xmldsig")]

use std::{collections::HashMap, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::xmldsig::{
    CatalogueCompleteness, CatalogueError, DsigError, DsigStatus, HmacSigningKey,
    HmacVerificationKey, LexicalSource, ReferenceParent, ReferenceResolution, ReplayError,
    ReplayMode, ReplayOutcome, SignContext, UriTypeSet, VerificationRequest, VerifyContext,
    with_verified_request,
};
use xml_sec::{XmlBackend, XmlDocument};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

#[test]
fn current_query_continues_after_producer_work_is_exhausted() {
    // A completed producer's local ceiling must not fund later selection,
    // catalogue/hash inspection or replay; retained storage stays accounted.
    use structured_asn1::{Encoding, Limits, Parser, memory::Work as _};
    let memory = account();
    let producer = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1 << 20,
            ..Default::default()
        },
        memory.clone(),
    );
    let producer_reader = producer.read(&[], 0).unwrap();
    let producer_work = producer_reader.execution();
    let query = Parser::new(Encoding::Der, Limits::default(), memory.clone());
    let query_reader = query.read(&[], 0).unwrap();
    let query_work = query_reader.execution();
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document, &context, &VerificationRequest::default(), &producer_work,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            for shift in (0..=20).rev() {
                while producer_work.charge_work(1 << shift).is_ok() {}
            }
            assert!(session.select_signature(signature).is_err());
            let retained = memory.used();
            session.with_query(signature, &query_work, |selected| {
                selected.signature_method().unwrap();
                let mut references = 0;
                selected.visit_authenticated_references(|_| {
                    references += 1;
                    Ok::<_, ()>(())
                }).unwrap();
                assert_eq!(references, 2);
                selected.visit_hash_uses(|_| Ok::<_, ()>(())).unwrap();
                let mut output = Vec::new();
                assert_eq!(selected.replay_reference(
                    session.view().node_for_id("inside", &[]).unwrap(),
                    ReplayMode::ReferenceOutput,
                    &mut |bytes: &[u8]| {
                        output.extend_from_slice(bytes);
                        Ok::<_, ()>(())
                    },
                ).unwrap(), ReplayOutcome::Complete);
                assert_eq!(output, b"<target xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:unused\" Id=\"target\">payload</target>");
                Ok::<_, ()>(())
            }).unwrap();
            assert!(producer_work.charge_work(1).is_err());
            assert_eq!(memory.used(), retained);
            Ok(())
        },
    ).unwrap();
    assert_eq!(memory.used(), 0);
}

#[test]
fn current_query_admits_binary_xml_parser_storage_before_receiver() {
    // A small XPath projection does not bound its backing parsed document:
    // one large text value must also fit the current query's capacity ceiling.
    assert_binary_xml_storage_refused(format!("<root>{}</root>", "x".repeat(65536)).into_bytes());
}

#[test]
fn current_query_admits_transcoding_storage_before_receiver() {
    // A large UTF-16 result cannot hide its normalization allocation behind a
    // small XPath projection. Every backend receives the same strict decoder.
    let xml = format!(
        "<?xml version='1.0' encoding='UTF-16'?><root>{}</root>",
        "x".repeat(65536)
    );
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    assert_binary_xml_storage_refused(bytes);
}

fn assert_binary_xml_storage_refused(bytes: Vec<u8>) {
    let uri = "https://example.test/parser-storage";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms);
    let resources = HashMap::from([(uri.to_owned(), bytes)]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    for backend in backends() {
        let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
        let context = VerifyContext::new()
            .xml_backend(backend)
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .process_manifests(true);
        with_verified_request(&document, &context, &request, &account(), |session| {
            let current = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24)));
            let mut calls = 0;
            session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        let result = selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |_: &[u8]| {
                                calls += 1;
                                Ok::<_, ()>(())
                            },
                        );
                        assert!(
                            matches!(
                                result,
                                Err(ReplayError::Processing(DsigError::SharedExecution(
                                    structured_asn1::memory::MemoryError::LimitExceeded
                                )))
                            ),
                            "parser scratch must refuse, got {result:?}; receiver calls: {calls}"
                        );
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert_eq!(calls, 0);
            assert_eq!(current.used(), 0);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn current_query_replays_subtree_projection_without_node_storage() {
    // A same-document subtree projection is a range of the retained arena: a
    // query too small for one entry per projected node still replays it, and
    // releases all of its working storage afterwards.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document =
        XmlDocument::parse(xml.replace("payload", &"<child a='v'/>".repeat(1024))).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let current = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24)));
            let mut received = 0;
            session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        let result = selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |bytes: &[u8]| {
                                received += bytes.len();
                                Ok::<_, ()>(())
                            },
                        );
                        assert!(result.is_ok(), "subtree replay: {result:?}");
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert!(received > 1024 * "<child a=\"v\"></child>".len());
            assert_eq!(current.used(), 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn current_query_admits_nonterminal_c14n_before_receiver() {
    // Nonterminal serialization must not allocate an unaccounted Vec before
    // reparsing it for the next transform, even when terminal C14N is streamed.
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(
        "#target",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        transforms,
    );
    let document = XmlDocument::parse(xml.replace("payload", &"x".repeat(65536))).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let current = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24)));
            let mut calls = 0;
            session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        let result = selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |_: &[u8]| {
                                calls += 1;
                                Ok::<_, ()>(())
                            },
                        );
                        assert!(matches!(result, Err(ReplayError::Processing(_))));
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert_eq!(calls, 0);
            assert_eq!(current.used(), 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn current_query_admits_base64_capacity_before_receiver() {
    // A large decoded output cannot hide in an ordinary Vec while only the
    // small query index and replay records are charged to the supplied Work.
    use base64::Engine as _;
    let uri = "https://example.test/base64";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms);
    let document = XmlDocument::parse(xml).unwrap();
    let resources = HashMap::from([(
        uri.to_owned(),
        base64::engine::general_purpose::STANDARD
            .encode(vec![0x42; 65536])
            .into_bytes(),
    )]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    with_verified_request(&document, &context, &request, &account(), |session| {
        let current = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24)));
        let mut calls = 0;
        session
            .with_query(
                session.evidence().signatures()[0].identity(),
                &current,
                |selected| {
                    let result = selected.replay_reference(
                        session.view().node_for_id("inside", &[]).unwrap(),
                        ReplayMode::ReferenceOutput,
                        &mut |_: &[u8]| {
                            calls += 1;
                            Ok::<_, ()>(())
                        },
                    );
                    assert!(matches!(result, Err(ReplayError::Processing(_))));
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        assert_eq!(calls, 0);
        assert_eq!(current.used(), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn current_query_binary_chain_releases_consumed_input_capacity() {
    // Each new binary owns its paid allocation. Previous decoded inputs must
    // be released before downstream receiver work, not pinned by recursion.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let uri = "https://example.test/base64-chain";
    let transform = r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>"#;
    let transforms = format!("<ds:Transforms>{transform}{transform}</ds:Transforms>");
    let expected = vec![0x42; 65536];
    let resources = HashMap::from([(
        uri.to_owned(),
        STANDARD.encode(STANDARD.encode(&expected)).into_bytes(),
    )]);
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", &transforms);
    let document = XmlDocument::parse(xml).unwrap();
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    with_verified_request(&document, &context, &request, &account(), |session| {
        let current = account();
        session
            .with_query(
                session.evidence().signatures()[0].identity(),
                &current,
                |selected| {
                    let result = selected
                        .replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |bytes: &[u8]| {
                                assert_eq!(bytes, expected);
                                assert!(
                                    current.used() >= bytes.len(),
                                    "output capacity remains charged"
                                );
                                assert!(
                                    current.used() < bytes.len() * 2,
                                    "consumed input was released"
                                );
                                Ok::<_, ()>(())
                            },
                        )
                        .unwrap();
                    assert_eq!(result, ReplayOutcome::Complete);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        assert_eq!(current.used(), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn current_query_admits_external_uri_scratch_before_lookup_output() {
    // Resolving and normalizing a long external URI is current scratch, even
    // when the caller already owns the document and the one-byte payload.
    let uri = format!("https://example.test/{}", "x".repeat(16384));
    let (xml, key) = signed_manifest(&uri, "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let resources = HashMap::from([(uri, vec![0x42])]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    with_verified_request(&document, &context, &request, &account(), |session| {
        let current = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24)));
        let mut calls = 0;
        session
            .with_query(
                session.evidence().signatures()[0].identity(),
                &current,
                |selected| {
                    let result = selected.replay_reference(
                        session.view().node_for_id("inside", &[]).unwrap(),
                        ReplayMode::ReferenceOutput,
                        &mut |_: &[u8]| {
                            calls += 1;
                            Ok::<_, ()>(())
                        },
                    );
                    assert!(matches!(result, Err(ReplayError::Processing(_))));
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        assert_eq!(calls, 0);
        assert_eq!(current.used(), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn current_query_base64_charges_local_and_aggregate_once() {
    // Memory and a narrower Execution must pay the same aggregate cost.
    // Exact local work succeeds; one less refuses before receiver effects.
    // One original Reference makes the table's comparison count deterministic:
    // independently seeded tables with two keys can require different probes.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use structured_asn1::{Encoding, Limits, Parser};
    let uri = "https://example.test/base64-work";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms>"#;
    let expected = vec![0x42; 768];
    let encoded = STANDARD.encode(&expected).into_bytes();
    let input_length = encoded.len();
    let resources = HashMap::from([(uri.to_owned(), encoded)]);
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
<ds:Reference Id="inside" URI="{uri}">{transforms}
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/>
</ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"#
    );
    let mut signing_policy = xml_sec::policy::SigningPolicy::default();
    signing_policy.uris.references = UriTypeSet::ALL;
    let xml = SignContext::new(&signer)
        .policy(signing_policy)
        .external_resources(&resources)
        .sign_template(&template)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    with_verified_request(&document, &context, &request, &account(), |session| {
        let current = account();
        let signature = session.evidence().signatures()[0].identity();
        let reference = session.view().node_for_id("inside", &[]).unwrap();
        let before = current.work_used();
        session
            .with_query(signature, &current, |selected| {
                selected.replay_reference(
                    reference,
                    ReplayMode::ReferenceOutput,
                    &mut |bytes: &[u8]| {
                        assert_eq!(bytes, expected);
                        Ok::<_, ()>(())
                    },
                )
            })
            .unwrap();
        let cost = current.work_used() - before;
        assert!(
            cost > 3 * input_length,
            "input scanning and decoding were charged"
        );
        assert_eq!(current.used(), 0);
        for (limit, succeeds) in [(cost, true), (cost - 1, false), (0, false)] {
            let query = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: limit as u64,
                    ..Default::default()
                },
                current.clone(),
            );
            let reader = query.read(&[], 0).unwrap();
            let work = reader.execution();
            let mut called = false;
            let before = current.work_used();
            let outcome = session.with_query(signature, &work, |selected| {
                selected.replay_reference(
                    reference,
                    ReplayMode::ReferenceOutput,
                    &mut |bytes: &[u8]| {
                        called = true;
                        assert_eq!(bytes, expected);
                        Ok::<_, ()>(())
                    },
                )
            });
            assert_eq!(outcome.is_ok(), succeeds);
            assert_eq!(called, succeeds);
            if succeeds {
                assert_eq!(current.work_used() - before, cost);
            }
            assert_eq!(current.used(), 0);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn replay_enforces_the_compiled_transform_count_before_output() {
    // A valid Signature authenticates even a Manifest instruction whose
    // execution exceeded policy. Replay must not turn that into permission.
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(
        "#target",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        transforms,
    );
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.manifest_processing = xml_sec::policy::ManifestProcessing::Process;
    policy.resources.max_transforms_per_reference = 1;
    let context = VerifyContext::new().key(&key).policy(policy);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut calls = 0;
            let result = selected.replay_reference(
                session.view().node_for_id("inside", &[]).unwrap(),
                ReplayMode::ReferenceOutput,
                &mut |_: &[u8]| {
                    calls += 1;
                    Ok::<_, ()>(())
                },
            );
            assert!(matches!(
                result,
                Err(ReplayError::Processing(DsigError::Policy(
                    xml_sec::policy::PolicyViolation::ResourceLimit {
                        maximum: 1,
                        actual: 2,
                        ..
                    }
                )))
            ));
            assert_eq!(calls, 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn ignored_manifest_instructions_cannot_be_replayed() {
    // Historical unchecked catalogue entries are not permission to do Manifest
    // work under the immutable Ignore policy, even when their parent is signed.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
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
            let result = selected.replay_reference(
                session.view().node_for_id("inside", &[]).unwrap(),
                ReplayMode::ReferenceOutput,
                &mut |_: &[u8]| {
                    calls += 1;
                    Ok::<_, ()>(())
                },
            );
            assert!(matches!(
                result,
                Err(ReplayError::Processing(DsigError::Policy(_)))
            ));
            assert_eq!(calls, 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn outside_manifest_enveloped_replay_has_no_invented_signature_context() {
    // XMLDSig 1.1 §6.6.4's mandated XPath is false for every node when
    // here()/ancestor::Signature[1] is empty; no unrelated Signature is removed.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-EnvelopedSignature
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>"#;
    let template = manifest_template(
        "#target",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        transforms,
    )
    .replace("<ds:Object>", "</ds:Signature>")
    .replace("</ds:Object></ds:Signature>", "")
    .replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    );
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            assert!(
                matches!(
                    session.evidence().signatures()[0]
                        .result()
                        .as_ref()
                        .unwrap()
                        .manifest_references[0]
                        .status,
                    DsigStatus::Valid
                ),
                "historical verification must hash the same empty bytes as replay"
            );
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut bytes = Vec::new();
            assert!(matches!(
                selected
                    .replay_reference(
                        session.view().node_for_id("inside", &[]).unwrap(),
                        ReplayMode::ReferenceOutput,
                        &mut |chunk: &[u8]| {
                            bytes.extend_from_slice(chunk);
                            Ok::<_, ()>(())
                        }
                    )
                    .unwrap(),
                ReplayOutcome::Complete
            ));
            assert!(
                bytes.is_empty(),
                "absent containing Signature yields an empty node-set"
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn replay_excludes_the_actual_containing_signature_not_the_selected_one() {
    // An authenticated Manifest may live inside another Signature. Enveloped
    // removes that actual ancestor while retaining the selected verifier's one.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>"#;
    let other = r##"</ds:Signature><ds:Signature Id="other"><ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
<ds:Reference URI="#target"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>
</ds:SignedInfo><ds:SignatureValue/><ds:Object>"##;
    let template = manifest_template("", "http://www.w3.org/2001/04/xmlenc#sha256", transforms)
        .replace("<ds:Object>", other);
    let document = XmlDocument::parse(
        SignContext::new(&signer)
            .signature_template_selection(
                xml_sec::xmldsig::SignatureTemplateSelection::FirstDescendant,
            )
            .sign_template(&template)
            .unwrap(),
    )
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
            let mut bytes = Vec::new();
            selected
                .replay_reference(
                    session.view().node_for_id("inside", &[]).unwrap(),
                    ReplayMode::ReferenceOutput,
                    &mut |chunk: &[u8]| {
                        bytes.extend_from_slice(chunk);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            let output = String::from_utf8(bytes).unwrap();
            assert!(
                output.contains("<ds:Signature>"),
                "selected Signature remains"
            );
            assert!(output.contains("<ds:SignatureValue>"));
            assert!(
                !output.contains("Id=\"other\""),
                "actual containing Signature is excluded"
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn terminal_replay_memory_does_not_scale_with_output_length() {
    // Increasing final canonical text by 16x must not retain a final-output
    // allocation. Only document shape and accounted serializer scratch matter.
    let mut peaks = Vec::new();
    for length in [1 << 16, 1 << 20] {
        let secret = vec![0x61; 32];
        let signer = HmacSigningKey::new(secret.clone()).unwrap();
        let key = HmacVerificationKey::new(secret).unwrap();
        let template = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
            .replace("payload", &"x".repeat(length));
        let document =
            XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap())
                .unwrap();
        let work = Memory::new(Arc::new(MemoryAccount::new(16384, 1 << 28)));
        let context = VerifyContext::new().key(&key).process_manifests(true);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &work,
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let mut total = 0;
                let mut peak = work.used();
                selected
                    .replay_reference(
                        session.view().node_for_id("inside", &[]).unwrap(),
                        ReplayMode::ReferenceOutput,
                        &mut |bytes: &[u8]| {
                            total += bytes.len();
                            peak = peak.max(work.used());
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert!(total > length);
                peaks.push(peak);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(work.used(), 0);
    }
    assert_eq!(
        peaks[0], peaks[1],
        "final text must remain borrowed and streamed"
    );
}

#[test]
fn catalogue_cannot_bypass_the_original_reference_limit() {
    // Successful crypto is not permission to enumerate more instructions than
    // the original immutable policy admits, even if Manifest execution stopped.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.resources.max_references = 1;
    policy.manifest_processing = xml_sec::policy::ManifestProcessing::Process;
    let context = VerifyContext::new().key(&key).policy(policy);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut calls = 0;
            let result = selected.visit_authenticated_references(|_| {
                calls += 1;
                Ok::<_, ()>(())
            });
            assert!(matches!(
                result,
                Err(CatalogueError::Processing(DsigError::Policy(_)))
            ));
            assert_eq!(calls, 1, "excess instruction must not reach visitor");
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn unsigned_manifest_and_ambiguous_ids_cannot_authorize_replay() {
    // A valid signature does not cover unrelated Manifest instructions; a
    // duplicate ID cannot select an attacker-controlled alternative before crypto.
    use std::cell::Cell;
    use xml_sec::xmldsig::{SignatureAlgorithm, VerifyingKey};
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
    }
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let key = CountedKey {
        key,
        calls: Cell::new(0),
    };
    let unsigned = xml.replace("</root>", "<ds:Manifest Id=\"unsigned\"><ds:Reference Id=\"unsigned-ref\" URI=\"#target\"/></ds:Manifest></root>");
    let document = XmlDocument::parse(unsigned).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            assert!(matches!(
                selected.replay_reference(
                    session.view().node_for_id("unsigned-ref", &[]).unwrap(),
                    ReplayMode::ReferenceOutput,
                    &mut |_: &[u8]| -> Result<(), ()> { panic!("unsigned instruction cannot run") }
                ),
                Err(ReplayError::Processing(_))
            ));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(key.calls.get(), 1);
    key.calls.set(0);
    let document =
        XmlDocument::parse(xml.replace("</root>", "<other Id=\"manifest\"/></root>")).unwrap();
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            assert!(
                session
                    .select_signature(session.evidence().signatures()[0].identity())
                    .is_err()
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        key.calls.get(),
        0,
        "ambiguous resource must fail before signature crypto"
    );
}

fn backends() -> Vec<XmlBackend> {
    vec![
        #[cfg(feature = "xml-backend-xmloxide")]
        XmlBackend::Xmloxide,
        #[cfg(feature = "xml-backend-roxmltree")]
        XmlBackend::Roxmltree,
        #[cfg(all(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree"))]
        XmlBackend::Differential,
    ]
}

fn signed_manifest(uri: &str, algorithm: &str, transforms: &str) -> (String, HmacVerificationKey) {
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    // Default signing processes SignedInfo only. Its real signature covers
    // Manifest bytes, including intentionally stale/unsupported child digests.
    let xml = manifest_template(uri, algorithm, transforms);
    (
        SignContext::new(&signer).sign_template(&xml).unwrap(),
        HmacVerificationKey::new(secret).unwrap(),
    )
}

fn manifest_template(uri: &str, algorithm: &str, transforms: &str) -> String {
    format!(
        r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<target Id="target" xmlns:u="urn:unused">payload<!--comment--></target>
<ds:CanonicalizationMethod Id="timestamp-method" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:Signature><ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
<ds:Reference URI="#manifest"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>
</ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="manifest">
<ds:Reference Id="inside" URI="{uri}">{transforms}<ds:DigestMethod Algorithm="{algorithm}"/>
<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference>
</ds:Manifest></ds:Object></ds:Signature></root>"##
    )
}

#[test]
fn authenticated_manifest_outside_signature_uses_the_same_catalogue_and_replay() {
    // XMLDSig §5.1 authentication is a reference proof, not physical ancestry
    // under Signature/Object. The external-in-DOM Manifest is genuinely signed.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let xml = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replace("<ds:Object>", "</ds:Signature>")
        .replace("</ds:Object></ds:Signature>", "");
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&xml).unwrap()).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            assert_eq!(
                session.evidence().signatures()[0]
                    .result()
                    .as_ref()
                    .unwrap()
                    .manifest_references
                    .len(),
                1
            );
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut count = 0;
            assert_eq!(
                selected
                    .visit_authenticated_references(|reference| {
                        if let ReferenceParent::Manifest(parent) = reference.parent {
                            count += 1;
                            assert_eq!(
                                parent,
                                session.view().node_for_id("manifest", &[]).unwrap()
                            );
                            selected
                                .replay_reference(
                                    reference.identity,
                                    ReplayMode::ReferenceOutput,
                                    &mut |_: &[u8]| Ok::<_, ()>(()),
                                )
                                .unwrap();
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap(),
                CatalogueCompleteness::Complete
            );
            assert_eq!(count, 1);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn signed_manifest_replay_keeps_digest_status_and_terminal_c14n_distinct() {
    // EN §5.5.3 Note 2: stale old digest does not prevent a new digest of the
    // authenticated instruction's output. Timestamp coercion is NOT ReferenceOutput.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    for backend in backends() {
        let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
        let context = VerifyContext::new()
            .xml_backend(backend)
            .key(&key)
            .process_manifests(true);
        with_verified_request(&document, &context, &VerificationRequest::default(), &account(), |session| {
            assert!(!session.evidence().all_valid());
            assert_eq!(session.evidence().signatures()[0].result().as_ref().unwrap().status, DsigStatus::Valid);
            let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
            let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
            let mut manifests = 0;
            let completeness = selected.visit_authenticated_references(|reference| {
                if !matches!(reference.parent, ReferenceParent::Manifest(_)) { return Ok::<_, ()>(()); }
                manifests += 1;
                assert!(matches!(reference.result.unwrap().status, DsigStatus::Invalid(_)));
                let mut implicit = Vec::new();
                let mut timestamp = Vec::new();
                for (mode, bytes) in [(ReplayMode::ReferenceOutput, &mut implicit), (ReplayMode::Timestamp(method), &mut timestamp)] {
                    assert_eq!(selected.replay_reference(reference.identity, mode, &mut |chunk: &[u8]| { bytes.extend_from_slice(chunk); Ok::<_, ()>(()) }).unwrap(), ReplayOutcome::Complete);
                }
                assert_eq!(implicit, b"<target xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:unused\" Id=\"target\">payload</target>");
                assert_eq!(timestamp, b"<target Id=\"target\">payload</target>");
                Ok(())
            }).unwrap();
            assert_eq!(completeness, CatalogueCompleteness::Complete);
            assert_eq!(manifests, 1);
            Ok(())
        }).unwrap();
    }
}

#[test]
fn signed_manifest_with_unknown_historical_digest_can_be_replayed() {
    // Selecting and executing transforms must not require an obsolete digest
    // capability that the renewal operation never uses.
    let (xml, key) = signed_manifest("#target", "urn:example:historical-digest", "");
    let document = XmlDocument::parse(xml).unwrap();
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
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let mut output = Vec::new();
            assert_eq!(
                selected
                    .replay_reference(
                        reference,
                        ReplayMode::ReferenceOutput,
                        &mut |chunk: &[u8]| {
                            output.extend_from_slice(chunk);
                            Ok::<_, ()>(())
                        }
                    )
                    .unwrap(),
                ReplayOutcome::Complete
            );
            assert_ne!(output, b"");
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn only_admitted_missing_external_data_is_unavailable() {
    // A Missing external map entry is diagnostic. A malformed/absent local ID
    // remains a processing error, and neither case may call the receiver.
    for (uri, unavailable) in [
        ("https://example.test/absent", true),
        ("#absent", false),
        ("#", false),
    ] {
        let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", "");
        let document = XmlDocument::parse(xml).unwrap();
        let context = VerifyContext::new()
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .process_manifests(true);
        with_verified_request(&document, &context, &VerificationRequest::default(), &account(), |session| {
            let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let result = selected.replay_reference(reference, ReplayMode::ReferenceOutput, &mut |_: &[u8]| -> Result<(), ()> { panic!("no bytes available"); });
            if unavailable { assert!(matches!(result, Ok(ReplayOutcome::Unavailable(cause)) if cause.reference == reference)); }
            else { assert!(matches!(result, Err(ReplayError::Processing(_)))); }
            Ok(())
        }).unwrap();
    }
}

#[test]
fn missing_id_replay_retains_diagnostic_capacity_until_error_drop() {
    // A signed Manifest authenticates its instruction even when its ID is
    // absent. The returned error must retain only admitted query storage.
    let id = "x".repeat(65536);
    let (xml, key) = signed_manifest(
        &format!("#{id}"),
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "",
    );
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let current = account();
            let error = session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |_: &[u8]| -> Result<(), ()> {
                                panic!("missing ID cannot produce bytes")
                            },
                        )
                    },
                )
                .unwrap_err();
            assert!(
                current.used() >= id.len(),
                "escaping diagnostic retains its capacity charge"
            );
            assert!(format!("{error:?}").contains(&id));
            drop(error);
            assert_eq!(current.used(), 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn replay_layout_charges_inspected_whitespace_by_length() {
    // Legal whitespace inside an authenticated Reference is still scanned by
    // the current query, so its work must grow with the text, not the node count.
    let work = |whitespace: usize| {
        let (xml, key) = signed_manifest(
            "#target",
            "http://www.w3.org/2001/04/xmlenc#sha256",
            &" ".repeat(whitespace),
        );
        let document = XmlDocument::parse(xml).unwrap();
        let context = VerifyContext::new().key(&key).process_manifests(true);
        let current = account();
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                session
                    .with_query(
                        session.evidence().signatures()[0].identity(),
                        &current,
                        |selected| {
                            selected.replay_reference(
                                session.view().node_for_id("inside", &[]).unwrap(),
                                ReplayMode::ReferenceOutput,
                                &mut |_: &[u8]| Ok::<_, ()>(()),
                            )
                        },
                    )
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
        current.work_used()
    };
    // ID lookups use randomly seeded tables, so unrelated probes vary by a
    // few units per run; the slack is three orders below the scanned text.
    let length = 1 << 20;
    let slack = 1024;
    assert!(work(length) + slack >= work(1) + length);
}

#[test]
fn replay_layout_diagnostic_retains_current_capacity_until_error_drop() {
    // A signed Manifest authenticates a malformed Reference too. Its trailing
    // element name is attacker-sized, so the escaping diagnostic must stay
    // funded by the query that built it until the error is dropped.
    let name = "x".repeat(65536);
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replace(
            "</ds:DigestValue></ds:Reference>\n</ds:Manifest>",
            &format!("</ds:DigestValue><{name}/></ds:Reference>\n</ds:Manifest>"),
        );
    let xml = SignContext::new(&signer).sign_template(&template).unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let current = account();
            let error = session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            ReplayMode::ReferenceOutput,
                            &mut |_: &[u8]| -> Result<(), ()> {
                                panic!("malformed Reference cannot produce bytes")
                            },
                        )
                    },
                )
                .unwrap_err();
            assert!(format!("{error:?}").contains(&name));
            assert!(
                current.used() >= name.len(),
                "escaping diagnostic retains its capacity charge"
            );
            drop(error);
            assert_eq!(current.used(), 0);
            Ok(())
        },
    )
    .unwrap();
}

/// Replays `inside` in one funded query that must fail, and checks that the
/// escaping diagnostic names `text` and keeps its charge until it is dropped.
fn assert_query_diagnostic_retained(
    document: &XmlDocument,
    context: &VerifyContext<'_>,
    timestamp: bool,
    text: &str,
) {
    with_verified_request(
        document,
        context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let mode = if timestamp {
                ReplayMode::Timestamp(session.view().node_for_id("timestamp-method", &[]).unwrap())
            } else {
                ReplayMode::ReferenceOutput
            };
            let current = account();
            let error = session
                .with_query(
                    session.evidence().signatures()[0].identity(),
                    &current,
                    |selected| {
                        selected.replay_reference(
                            session.view().node_for_id("inside", &[]).unwrap(),
                            mode,
                            &mut |_: &[u8]| -> Result<(), ()> {
                                panic!("rejected instruction cannot produce bytes")
                            },
                        )
                    },
                )
                .unwrap_err();
            assert!(format!("{error:?}").contains(text));
            assert!(
                current.used() >= text.len(),
                "escaping diagnostic retains its capacity charge"
            );
            drop(error);
            assert_eq!(current.used(), 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn replay_transform_policy_diagnostic_retains_current_capacity_until_error_drop() {
    // An authenticated transform outside the allowlist names an attacker-sized
    // URI; the escaping policy rejection must stay funded by the query.
    let algorithm = format!("urn:example:{}", "x".repeat(65536));
    let (xml, key) = signed_manifest(
        "#target",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        &format!(r#"<ds:Transforms><ds:Transform Algorithm="{algorithm}"/></ds:Transforms>"#),
    );
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.manifest_processing = xml_sec::policy::ManifestProcessing::Process;
    policy.transforms.allowed_algorithms =
        Some(["http://www.w3.org/2001/10/xml-exc-c14n#".to_owned()].into());
    let context = VerifyContext::new().key(&key).policy(policy);
    assert_query_diagnostic_retained(&document, &context, false, &algorithm);
}

const TIMESTAMP_METHOD: &str = r#"<ds:CanonicalizationMethod Id="timestamp-method" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#;

#[test]
fn timestamp_method_whitespace_is_charged_by_length() {
    // The timestamp method is parsed by the current query, so legal whitespace
    // inside it must cost its bytes rather than run on unfunded work.
    let work = |whitespace: usize| {
        let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
        let method = TIMESTAMP_METHOD.replace(
            "/>",
            &format!(">{}</ds:CanonicalizationMethod>", " ".repeat(whitespace)),
        );
        let document = XmlDocument::parse(xml.replace(TIMESTAMP_METHOD, &method)).unwrap();
        let context = VerifyContext::new().key(&key).process_manifests(true);
        let current = account();
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
                session
                    .with_query(
                        session.evidence().signatures()[0].identity(),
                        &current,
                        |selected| {
                            selected.replay_reference(
                                session.view().node_for_id("inside", &[]).unwrap(),
                                ReplayMode::Timestamp(method),
                                &mut |_: &[u8]| Ok::<_, ()>(()),
                            )
                        },
                    )
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
        current.work_used()
    };
    // Same randomized ID-table slack as the Reference layout check.
    let length = 1 << 20;
    let slack = 1024;
    assert!(work(length) + slack >= work(1) + length);
}

#[test]
fn timestamp_method_diagnostic_retains_current_capacity_until_error_drop() {
    // An unsupported timestamp method URI is attacker-sized; its diagnostic
    // must be built in the query's storage, not copied outside it.
    let algorithm = format!("urn:example:{}", "x".repeat(65536));
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let method = TIMESTAMP_METHOD.replace("http://www.w3.org/2001/10/xml-exc-c14n#", &algorithm);
    let document = XmlDocument::parse(xml.replace(TIMESTAMP_METHOD, &method)).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    assert_query_diagnostic_retained(&document, &context, true, &algorithm);
}

#[test]
fn final_octets_are_borrowed_and_not_timestamp_recanonicalized() {
    // Final binary, including empty/non-XML input, is not XML-decoded merely
    // because a timestamp method was supplied. Pointer identity proves no copy.
    let uri = "https://example.test/binary";
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", "");
    for bytes in [vec![], vec![0xff, 0, 0x80, 1], vec![0xff; 16384]] {
        let resources = HashMap::from([(uri.to_owned(), bytes)]);
        let expected = resources.get(uri).unwrap();
        let document = XmlDocument::parse(xml.clone()).unwrap();
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        policy.resources.max_canonicalized_bytes = 8192;
        let context = VerifyContext::new()
            .policy(policy)
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .process_manifests(true);
        let request = VerificationRequest {
            external_resources: Some(&resources),
            ..VerificationRequest::default()
        };
        with_verified_request(&document, &context, &request, &account(), |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
            let mut calls = 0;
            let result = selected
                .replay_reference(
                    reference,
                    ReplayMode::Timestamp(method),
                    &mut |chunk: &[u8]| {
                        calls += 1;
                        assert_eq!(chunk, expected);
                        assert_eq!(chunk.as_ptr(), expected.as_ptr());
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert_eq!(result, ReplayOutcome::Complete);
            assert_eq!(calls, usize::from(!expected.is_empty()));
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn external_enveloped_replay_refuses_a_foreign_document() {
    // XMLDSig 1.1 §6.6.4 limits Enveloped to its parent XML document,
    // even when the original instruction has no Signature ancestor.
    let uri = "https://example.test/other.xml";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>"#;
    let template = manifest_template(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms)
        .replace("<ds:Object>", "</ds:Signature>")
        .replace("</ds:Object></ds:Signature>", "");
    let signer = HmacSigningKey::new(vec![0x61; 32]).unwrap();
    let key = HmacVerificationKey::new(vec![0x61; 32]).unwrap();
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let resources = HashMap::from([(uri.to_owned(), b"<payload/>".to_vec())]);
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    with_verified_request(&document, &context, &request, &account(), |session| {
        let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
        let result = selected.replay_reference(
            session.view().node_for_id("inside", &[]).unwrap(),
            ReplayMode::ReferenceOutput,
            &mut |_: &[u8]| -> Result<(), ()> {
                panic!("foreign Enveloped input must not reach receiver")
            },
        );
        assert!(
            result.is_err(),
            "foreign input must not become authenticated empty output"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn terminal_c14n_refusal_is_typed_and_exhausts_remaining_output() {
    // Partial streaming output spends the original allowance; subsequent
    // attempts cannot spend it again and retain the exact policy resource.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.resources.max_canonicalized_bytes = 4096;
    let context = VerifyContext::new()
        .key(&key)
        .policy(policy)
        .process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let mut refused = false;
            for _ in 0..100 {
                if let Err(error) = selected.replay_reference(
                    reference,
                    ReplayMode::ReferenceOutput,
                    &mut |_: &[u8]| Ok::<_, ()>(()),
                ) {
                    assert!(
                        matches!(
                            error,
                            ReplayError::Processing(DsigError::Policy(
                                xml_sec::policy::PolicyViolation::ResourceLimit {
                                    resource: "canonicalized bytes",
                                    maximum: 4096,
                                    ..
                                }
                            ))
                        ),
                        "{error:?}"
                    );
                    refused = true;
                    break;
                }
            }
            assert!(refused);
            let mut bytes = 0;
            let result = selected.replay_reference(
                reference,
                ReplayMode::ReferenceOutput,
                &mut |chunk: &[u8]| {
                    bytes += chunk.len();
                    Ok::<_, ()>(())
                },
            );
            assert!(matches!(
                result,
                Err(ReplayError::Processing(DsigError::Policy(_)))
            ));
            assert_eq!(bytes, 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn terminal_c14n_xml_base_refusals_keep_their_policy_resources() {
    // Timestamp C14N 1.1 fixup uses the same typed component/byte refusals
    // as collecting C14N, rather than losing them in Canonicalization errors.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replacen(
            "<root xmlns:ds=",
            "<root xml:base=\"https://example.test/a/b/\" xmlns:ds=",
            1,
        )
        .replacen(
            "<target Id=",
            "<group xml:base=\"nested/\"><target xml:base=\"../c/\" Id=",
            1,
        )
        .replacen("</target>", "</target></group>", 1)
        .replace(
            "Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"",
            "Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"",
        );
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    for components in [true, false] {
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        let expected = if components {
            policy.resources.max_xml_base_components = 1;
            "XML Base components"
        } else {
            policy.resources.max_xml_base_resolution_bytes = 1;
            "XML Base resolution bytes"
        };
        let context = VerifyContext::new()
            .key(&key)
            .policy(policy)
            .process_manifests(true);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let reference = session.view().node_for_id("inside", &[]).unwrap();
                let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
                let result = selected.replay_reference(
                    reference,
                    ReplayMode::Timestamp(method),
                    &mut |_: &[u8]| Ok::<_, ()>(()),
                );
                match result {
                    Err(ReplayError::Processing(DsigError::Policy(
                        xml_sec::policy::PolicyViolation::ResourceLimit {
                            resource,
                            maximum: 1,
                            ..
                        },
                    ))) => assert_eq!(resource, expected),
                    other => panic!("expected {expected} policy refusal, got {other:?}"),
                }
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn explicit_final_c14n_takes_precedence_over_timestamp_coercion() {
    // Explicit final C14N has already selected octets. A different implicit
    // timestamp mode cannot silently change those authenticated instructions.
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(
        "#target",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        transforms,
    );
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(&document, &context, &VerificationRequest::default(), &account(), |session| {
        let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
        let reference = session.view().node_for_id("inside", &[]).unwrap();
        let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
        let mut output = Vec::new();
        selected.replay_reference(reference, ReplayMode::Timestamp(method), &mut |chunk: &[u8]| { output.extend_from_slice(chunk); Ok::<_, ()>(()) }).unwrap();
        assert_eq!(output, b"<target xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:unused\" Id=\"target\">payload</target>");
        Ok(())
    }).unwrap();
}

#[test]
fn replay_rejects_reentrancy_without_resetting_the_outer_chain() {
    // A receiver may hold the selected handle. A nested invocation must fail
    // before begin_chain(), leaving the outer canonical stream unchanged.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(&document, &context, &VerificationRequest::default(), &account(), |session| {
        let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
        let reference = session.view().node_for_id("inside", &[]).unwrap();
        let mut output = Vec::new();
        selected.replay_reference(reference, ReplayMode::ReferenceOutput, &mut |chunk: &[u8]| {
            assert!(matches!(selected.replay_reference(reference, ReplayMode::ReferenceOutput, &mut |_: &[u8]| -> Result<(), ()> { panic!("nested receiver must not run"); }), Err(ReplayError::Processing(_))));
            output.extend_from_slice(chunk);
            Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(output, b"<target xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:unused\" Id=\"target\">payload</target>");
        Ok(())
    }).unwrap();
}

#[test]
fn repeated_replay_does_not_reset_current_shared_work() {
    // A successful replay spends the same account as verification/discovery.
    // Spending its remainder makes the next invocation fail before its sink.
    use structured_asn1::memory::MemoryError;
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    let work = account();
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let before = work.work_used();
            selected
                .replay_reference(reference, ReplayMode::ReferenceOutput, &mut |_: &[u8]| {
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(work.work_used() > before);
            work.charge_work(u64::try_from((1 << 28) - work.work_used()).unwrap())
                .unwrap();
            assert!(matches!(
                selected.replay_reference(
                    reference,
                    ReplayMode::ReferenceOutput,
                    &mut |_: &[u8]| -> Result<(), ()> {
                        panic!("exhausted work must refuse before receiver");
                    }
                ),
                Err(ReplayError::Processing(
                    xml_sec::xmldsig::DsigError::SharedExecution(MemoryError::WorkExceeded)
                ))
            ));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn original_catalogue_separates_ignored_processing_from_target_failures() {
    // Ignored Manifest processing is explicit; an unknown historical digest
    // under enabled processing is not incomplete instruction discovery.
    for (algorithm, process) in [
        ("urn:example:historical-digest", true),
        ("http://www.w3.org/2001/04/xmlenc#sha256", false),
    ] {
        let (xml, key) = signed_manifest("#target", algorithm, "");
        let document = XmlDocument::parse(xml).unwrap();
        let context = VerifyContext::new().key(&key).process_manifests(process);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let mut count = 0;
                let completeness = selected
                    .visit_authenticated_references(|_| {
                        count += 1;
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!(count, 2);
                assert_eq!(
                    completeness,
                    if process {
                        CatalogueCompleteness::Complete
                    } else {
                        CatalogueCompleteness::Unchecked(
                            session.view().node_for_id("manifest", &[]).unwrap(),
                        )
                    }
                );
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn replay_c14n_scratch_cannot_bypass_the_current_memory_account() {
    // A retained replay record's spare capacity does not make a new serializer
    // invocation free. Namespace/attribute scratch needs fresh admission before
    // allocation or receiver callbacks, even when input is already parsed.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    let work = account();
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            selected
                .replay_reference(reference, ReplayMode::ReferenceOutput, &mut |_: &[u8]| {
                    Ok::<_, ()>(())
                })
                .unwrap();
            let _held = work.reserve(work.limit() - work.used()).unwrap();
            let mut calls = 0;
            let result = selected.replay_reference(
                reference,
                ReplayMode::ReferenceOutput,
                &mut |_: &[u8]| {
                    calls += 1;
                    Ok::<_, ()>(())
                },
            );
            assert!(
                matches!(
                    result,
                    Err(ReplayError::Processing(DsigError::SharedExecution(_)))
                ),
                "expected scratch refusal, got {result:?}; receiver calls: {calls}"
            );
            assert_eq!(calls, 0, "scratch refusal must precede output");
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn replay_accounts_c14n11_xml_base_and_releases_temporary_capacity() {
    // XML Base fixup owns intermediate URI strings and a path-segment stack;
    // those must use the same account as namespace/attribute scratch.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replacen(
            "<root xmlns:ds=",
            "<root xml:base=\"https://example.test/a/b/\" xmlns:ds=",
            1,
        )
        .replacen("<target Id=", "<target xml:base=\"../c/\" Id=", 1)
        .replacen(
            "Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"",
            "Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"",
            1,
        );
    let document =
        XmlDocument::parse(SignContext::new(&signer).sign_template(&template).unwrap()).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    let work = account();
    with_verified_request(&document, &context, &VerificationRequest::default(), &work, |session| {
        let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
        let reference = session.view().node_for_id("inside", &[]).unwrap();
        let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
        let before = work.used();
        let mut peak = before;
        let mut output = Vec::new();
        selected.replay_reference(reference, ReplayMode::Timestamp(method), &mut |chunk: &[u8]| { peak = peak.max(work.used()); output.extend_from_slice(chunk); Ok::<_, ()>(()) }).unwrap();
        assert_eq!(output, b"<target xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:unused\" Id=\"target\" xml:base=\"https://example.test/a/c/\">payload</target>");
        assert!(peak > work.used(), "serializer scratch must be released after the invocation");
        Ok(())
    }).unwrap();
    assert_eq!(
        work.used(),
        0,
        "all retained session capacity releases with the session"
    );
}

#[test]
fn external_xml_replay_uses_the_original_binary_to_xml_adapter() {
    // Final C14N must parse detached XML through the normal transform adapter,
    // rather than stringify its bytes or select the Signature document.
    let uri = "https://example.test/xml";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/></ds:Transforms>"#;
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms);
    let resources = HashMap::from([(
        uri.to_owned(),
        b"<q:root xmlns:q='urn:payload' z='2' a='1'><!--keep--><q:child/></q:root>".to_vec(),
    )]);
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .process_manifests(true);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    with_verified_request(&document, &context, &request, &account(), |session| {
        let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
        let mut output = Vec::new();
        selected.replay_reference(session.view().node_for_id("inside", &[]).unwrap(), ReplayMode::ReferenceOutput, &mut |chunk: &[u8]| {output.extend_from_slice(chunk); Ok::<_, ()>(())}).unwrap();
        assert_eq!(output, b"<q:root xmlns:q=\"urn:payload\" a=\"1\" z=\"2\"><!--keep--><q:child></q:child></q:root>");
        Ok(())
    }).unwrap();
}

#[test]
fn external_xml_xpath_replay_keeps_namespace_axes_and_original_id_rules() {
    // Both XPath forms must consume the current parser's actual semantic DOM,
    // retaining independent attribute/namespace axes and its ID classification.
    let uri = "https://example.test/xpath-current-dom";
    let payload =
        b"<r xmlns:p='urn:p'><p:leaf Id='a'>left</p:leaf><p:leaf Id='b'>right</p:leaf></r>";
    for parameter in [
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(ancestor-or-self::node() | id('a')) = count(ancestor-or-self::node())</ds:XPath></ds:Transform>"#,
        r#"<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"><f:XPath xmlns:f="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">id('a')</f:XPath></ds:Transform>"#,
    ] {
        let transforms = format!(
            r#"<ds:Transforms>{parameter}<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>"#
        );
        let (xml, key) =
            signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", &transforms);
        let resources = HashMap::from([(uri.to_owned(), payload.to_vec())]);
        let request = VerificationRequest {
            external_resources: Some(&resources),
            ..Default::default()
        };
        for backend in backends() {
            let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
            let context = VerifyContext::new()
                .xml_backend(backend)
                .key(&key)
                .allowed_uri_types(UriTypeSet::ALL)
                .process_manifests(true);
            with_verified_request(&document, &context, &request, &account(), |session| {
                let current = account();
                session
                    .with_query(
                        session.evidence().signatures()[0].identity(),
                        &current,
                        |selected| {
                            let mut output = Vec::new();
                            assert_eq!(
                                selected
                                    .replay_reference(
                                        session.view().node_for_id("inside", &[]).unwrap(),
                                        ReplayMode::ReferenceOutput,
                                        &mut |chunk: &[u8]| {
                                            output.extend_from_slice(chunk);
                                            Ok::<_, ()>(())
                                        },
                                    )
                                    .unwrap(),
                                ReplayOutcome::Complete
                            );
                            assert_eq!(output, b"<p:leaf xmlns:p=\"urn:p\" Id=\"a\">left</p:leaf>");
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert_eq!(current.used(), 0);
                Ok(())
            })
            .unwrap();
        }
    }
}

#[test]
fn current_query_replays_opc_with_the_original_edition_after_producer_exhaustion() {
    // Real authenticated instructions retain their policy edition while both
    // relationship normalization and terminal C14N use only the current Work.
    use structured_asn1::{Encoding, Limits, Parser, memory::Work as _};
    use xml_sec::policy::{OpcRelationshipEdition, VerificationPolicy};
    let uri = "https://example.test/current-relationships";
    let transforms = r#"<ds:Transforms><ds:Transform Algorithm="http://schemas.openxmlformats.org/package/2006/RelationshipTransform"><r:RelationshipReference xmlns:r="http://schemas.openxmlformats.org/package/2006/digital-signature" SourceId="keep"/></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms>"#;
    let payload = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="drop" Type="urn:other" Target="discard"/><Relationship Id="keep" Type="urn:test" Target="part.xml"/></Relationships>"#;
    let expected = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="keep" Target="part.xml" TargetMode="Internal" Type="urn:test"></Relationship></Relationships>"#;
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms);
    let resources = HashMap::from([(uri.to_owned(), payload.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    for backend in backends() {
        for edition in [
            OpcRelationshipEdition::Ecma2012,
            OpcRelationshipEdition::Ecma2021,
        ] {
            let memory = account();
            let producer = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: 1 << 20,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = producer.read(&[], 0).unwrap();
            let work = reader.execution();
            let mut policy = VerificationPolicy::default();
            policy.transforms.opc_relationship_edition = edition;
            let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
            let context = VerifyContext::new()
                .policy(policy)
                .xml_backend(backend)
                .key(&key)
                .allowed_uri_types(UriTypeSet::ALL)
                .process_manifests(true);
            with_verified_request(&document, &context, &request, &work, |session| {
                for shift in (0..=20).rev() {
                    while work.charge_work(1 << shift).is_ok() {}
                }
                let retained = memory.used();
                let current = Parser::new(Encoding::Der, Limits::default(), memory.clone());
                let reader = current.read(&[], 0).unwrap();
                session
                    .with_query(
                        session.evidence().signatures()[0].identity(),
                        &reader.execution(),
                        |selected| {
                            let mut output = Vec::new();
                            assert_eq!(
                                selected
                                    .replay_reference(
                                        session.view().node_for_id("inside", &[]).unwrap(),
                                        ReplayMode::ReferenceOutput,
                                        &mut |chunk: &[u8]| {
                                            output.extend_from_slice(chunk);
                                            Ok::<_, ()>(())
                                        }
                                    )
                                    .unwrap(),
                                ReplayOutcome::Complete
                            );
                            assert_eq!(output, expected);
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert!(work.charge_work(1).is_err());
                assert_eq!(memory.used(), retained);
                Ok(())
            })
            .unwrap();
            assert_eq!(memory.used(), 0);
        }
    }
}

#[cfg(feature = "xslt")]
#[test]
fn current_query_replays_xslt_within_its_memory_account() {
    // The stylesheet comes from the authenticated original instruction, and its
    // compilation and execution workspace is reserved from the current query's
    // account: a small account refuses before the receiver sees any output.
    let uri = "https://example.test/xslt-input";
    let transforms = concat!(
        r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">"#,
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">"#,
        r#"<xsl:template match="/"><values><xsl:for-each select="//item"><xsl:sort select="."/>"#,
        r#"<v><xsl:value-of select="."/></v></xsl:for-each></values></xsl:template>"#,
        r#"</xsl:stylesheet></ds:Transform></ds:Transforms>"#
    );
    let (xml, key) = signed_manifest(uri, "http://www.w3.org/2001/04/xmlenc#sha256", transforms);
    let resources = HashMap::from([(
        uri.to_owned(),
        b"<doc><item>b</item><item>a</item></doc>".to_vec(),
    )]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    for backend in backends() {
        let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
        let context = VerifyContext::new()
            .xml_backend(backend)
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .process_manifests(true);
        with_verified_request(&document, &context, &request, &account(), |session| {
            for (current, expected) in [
                (account(), Ok(())),
                (
                    Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 24))),
                    Err(()),
                ),
            ] {
                let mut output = Vec::new();
                session
                    .with_query(
                        session.evidence().signatures()[0].identity(),
                        &current,
                        |selected| {
                            let result = selected.replay_reference(
                                session.view().node_for_id("inside", &[]).unwrap(),
                                ReplayMode::ReferenceOutput,
                                &mut |chunk: &[u8]| {
                                    output.extend_from_slice(chunk);
                                    Ok::<_, ()>(())
                                },
                            );
                            if expected.is_ok() {
                                assert_eq!(result.unwrap(), ReplayOutcome::Complete);
                                // The literal result element copies the `ds`
                                // namespace in scope at the stylesheet.
                                assert_eq!(
                                    output,
                                    concat!(
                                        "<?xml version=\"1.0\"?>\n",
                                        "<values xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
                                        "<v>a</v><v>b</v></values>\n"
                                    )
                                    .as_bytes()
                                );
                            } else {
                                assert!(
                                    matches!(
                                        result,
                                        Err(ReplayError::Processing(DsigError::SharedExecution(
                                            structured_asn1::memory::MemoryError::LimitExceeded
                                        )))
                                    ),
                                    "workspace must come from the current account, got {result:?}"
                                );
                                assert_eq!(output, b"");
                            }
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
                assert_eq!(current.used(), 0);
            }
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn stale_and_foreign_reference_identities_are_rejected_before_the_sink() {
    // A parse-local ordinal must never authorize the same ordinal from another
    // document or a previous generation of this document.
    let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
    let foreign = XmlDocument::parse(xml.clone())
        .unwrap()
        .with_view(|view| view.node_for_id("inside", &[]).unwrap());
    let mut document = XmlDocument::parse(xml).unwrap();
    let (stale, method) = document.with_view(|view| {
        (
            view.node_for_id("inside", &[]).unwrap(),
            view.node_for_id("timestamp-method", &[]).unwrap(),
        )
    });
    document.replace_content(method, "<unused/>").unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            for identity in [stale, foreign] {
                assert!(matches!(
                    selected.replay_reference(
                        identity,
                        ReplayMode::ReferenceOutput,
                        &mut |_: &[u8]| -> Result<(), ()> {
                            panic!("foreign or stale source must not run");
                        }
                    ),
                    Err(ReplayError::Processing(_))
                ));
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn timestamp_method_must_be_the_original_well_formed_method() {
    // A method handle is not an algorithm URI hint: its original QName and
    // parameter cardinality must be checked before any output is delivered.
    let method = r#"<ds:CanonicalizationMethod Id="timestamp-method" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#;
    for replacement in [
        method.replace("CanonicalizationMethod", "Object"),
        method.replace("/>", ">not simple whitespace</ds:CanonicalizationMethod>"),
        method.replace("/>", "><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ds\"/><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"u\"/></ds:CanonicalizationMethod>"),
    ] {
        let (xml, key) = signed_manifest("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "");
        let document = XmlDocument::parse(xml.replace(method, &replacement)).unwrap();
        let context = VerifyContext::new().key(&key).process_manifests(true);
        with_verified_request(&document, &context, &VerificationRequest::default(), &account(), |session| {
            let selected = session.select_signature(session.evidence().signatures()[0].identity())?;
            let reference = session.view().node_for_id("inside", &[]).unwrap();
            let method = session.view().node_for_id("timestamp-method", &[]).unwrap();
            assert!(matches!(selected.replay_reference(reference, ReplayMode::Timestamp(method), &mut |_: &[u8]| -> Result<(), ()> { panic!("invalid method must not reach receiver") }), Err(ReplayError::Processing(_))));
            Ok(())
        }).unwrap();
    }
}

#[test]
fn real_signed_nested_manifest_resolves_original_properties_and_visitor_refusal() {
    // A signed container authenticates a nested Manifest and its original
    // association properties; payload validity still does not authenticate an
    // unrelated Manifest elsewhere in the document.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = manifest_template("#target", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replace("URI=\"#manifest\"", "URI=\"#container\"")
        .replace("<ds:Object>", r##"<ds:Object Id="container"><nested><property Id="property" URI="#inside"/><unsupported Id="unsupported" URI="#"/><content Id="content">#in<!--split-->side</content>"##)
        .replace("</ds:Object>", "</nested></ds:Object>");
    let xml = SignContext::new(&signer).sign_template(&template).unwrap();
    for backend in backends() {
        let document = XmlDocument::parse_with_backend(xml.clone(), backend).unwrap();
        let context = VerifyContext::new()
            .xml_backend(backend)
            .key(&key)
            .process_manifests(true);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                let original = session.view().node_for_id("inside", &[]).unwrap();
                let parent = session.view().node_for_id("manifest", &[]).unwrap();
                assert!(matches!(
                    selected.resolve_reference(
                        session.view().node_for_id("unsupported", &[]).unwrap(),
                        LexicalSource::Attribute {
                            namespace: None,
                            local_name: "URI"
                        }
                    )?,
                    ReferenceResolution::Unsupported
                ));
                for (id, lexical) in [
                    (
                        "property",
                        LexicalSource::Attribute {
                            namespace: None,
                            local_name: "URI",
                        },
                    ),
                    ("content", LexicalSource::SimpleContent),
                ] {
                    let property = session.view().node_for_id(id, &[]).unwrap();
                    let ReferenceResolution::Reference(reference) =
                        selected.resolve_reference(property, lexical)?
                    else {
                        panic!("original signed property did not resolve");
                    };
                    assert_eq!(reference.identity, original);
                    assert_eq!(reference.parent, ReferenceParent::Manifest(parent));
                    assert!(matches!(
                        reference.result.unwrap().status,
                        DsigStatus::Invalid(_)
                    ));
                }
                let mut visited = 0;
                assert!(matches!(
                    selected.visit_authenticated_references(|_| {
                        visited += 1;
                        Err(73_u16)
                    }),
                    Err(CatalogueError::Visitor(73))
                ));
                assert_eq!(
                    visited, 1,
                    "visitor refusal must stop traversal immediately"
                );
                let mut output = Vec::new();
                assert_eq!(
                    selected
                        .replay_reference(
                            original,
                            ReplayMode::ReferenceOutput,
                            &mut |chunk: &[u8]| {
                                output.extend_from_slice(chunk);
                                Ok::<_, ()>(())
                            }
                        )
                        .unwrap(),
                    ReplayOutcome::Complete
                );
                assert!(output.ends_with(b">payload</target>"));
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn timestamp_preserves_comments_and_inclusive_prefix_list() {
    // Full XPointer retains comments at dereference; timestamp coercion then
    // uses the original WithComments algorithm and its PrefixList parameter.
    let secret = vec![0x61; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let key = HmacVerificationKey::new(secret).unwrap();
    let template = manifest_template("#xpointer(id('target'))", "http://www.w3.org/2001/04/xmlenc#sha256", "")
        .replacen("Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>", "Id=\"timestamp-method\" Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"u\"/></ds:CanonicalizationMethod>", 1);
    let xml = SignContext::new(&signer).sign_template(&template).unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let context = VerifyContext::new().key(&key).process_manifests(true);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut output = Vec::new();
            selected
                .replay_reference(
                    session.view().node_for_id("inside", &[]).unwrap(),
                    ReplayMode::Timestamp(
                        session.view().node_for_id("timestamp-method", &[]).unwrap(),
                    ),
                    &mut |chunk: &[u8]| {
                        output.extend_from_slice(chunk);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            assert_eq!(
                output,
                b"<target xmlns:u=\"urn:unused\" Id=\"target\">payload<!--comment--></target>"
            );
            Ok(())
        },
    )
    .unwrap();
}
