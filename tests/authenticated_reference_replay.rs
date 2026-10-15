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
    let signed = SignContext::new(&signer).sign_template(&xml).unwrap();
    let document = XmlDocument::parse(signed).unwrap();
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
            assert!(!output.is_empty());
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
