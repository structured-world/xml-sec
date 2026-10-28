//! Detached Reference payloads streamed or attested through a verified session.

#![cfg(feature = "xmldsig-sign")]

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{
    DetachedDigestAttestation, ManifestProcessing, PolicyViolation, SigningPolicy,
    VerificationPolicy,
};
use xml_sec::xmldsig::{
    DetachedChain, DetachedCompletion, DigestAlgorithm, DsigError, DsigStatus, ExternalPayload,
    FailureReason, HmacSigningKey, HmacVerificationKey, ReferenceBuilder, ReferenceResult,
    SignContext, SignatureAlgorithm, SignatureBuilder, Transform, UriTypeSet, VerificationRequest,
    VerifiedSession, VerifyContext, with_verified_request,
};

const SECRET: [u8; 32] = [0x5a; 32];

/// One signed detached Reference: its URI, transform chain, digest method and
/// the bytes it was signed over.
struct Detached<'a> {
    uri: &'a str,
    base64: bool,
    digest: DigestAlgorithm,
    payload: &'a [u8],
}

fn signing_policy() -> SigningPolicy {
    let mut policy = SigningPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy
}

fn verification_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy
}

/// Sign `<root>` with an in-document Reference to `#local` and the listed
/// detached References, supplying their bytes only to the signer.
fn signed(detached: &[Detached<'_>], local_tampered: bool) -> XmlDocument {
    let mut builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#local")
            .transform(Transform::C14n(C14nAlgorithm::new(
                C14nMode::Exclusive1_0,
                false,
            ))),
    );
    let mut resources = HashMap::new();
    for reference in detached {
        let mut item = ReferenceBuilder::new(reference.digest).uri(reference.uri);
        if reference.base64 {
            item = item.transform(Transform::Base64Decode);
        }
        builder = builder.add_reference(item);
        resources.insert(
            format!("https://example.test/data/{}", reference.uri),
            reference.payload.to_vec(),
        );
    }
    let xml = SignContext::new(&HmacSigningKey::new(SECRET.to_vec()).unwrap())
        .policy(signing_policy())
        .external_resources(&resources)
        .sign_with_builder(
            "<root xml:base=\"https://example.test/data/\"><local ID=\"local\">kept</local></root>",
            &builder,
        )
        .unwrap();
    let xml = if local_tampered {
        xml.replacen(">kept<", ">changed<", 1)
    } else {
        xml
    };
    XmlDocument::parse(xml).unwrap()
}

fn work() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

/// Run `continuation` on a verified session of `document` with no resident
/// external bytes, returning the final evidence's per-Reference results and
/// acceptance.
fn session<R>(
    document: &XmlDocument,
    policy: VerificationPolicy,
    continuation: impl for<'view, 'scope> FnOnce(
        &mut VerifiedSession<'view, 'scope, '_, Memory>,
    ) -> Result<R, DsigError>,
) -> (R, Vec<ReferenceResult>, bool) {
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    let context = VerifyContext::new().policy(policy).key(&key);
    let work = work();
    let (value, evidence) = with_verified_request(
        document,
        &context,
        &VerificationRequest::default(),
        &work,
        |mut session| {
            let value = continuation(&mut session)?;
            Ok((value, session.into_evidence()))
        },
    )
    .unwrap();
    let references = evidence.signatures()[0]
        .result()
        .as_ref()
        .unwrap()
        .signed_info_references
        .clone();
    let accepted = evidence.accepted(document).unwrap();
    (value, references, accepted)
}

fn stream(
    session: &mut VerifiedSession<'_, '_, '_, Memory>,
    references: &[xml_sec::NodeIdentity],
    payload: &[u8],
    chunk: usize,
    completion: DetachedCompletion,
) -> Result<(), DsigError> {
    let mut stream = session.detached_payload(references, completion)?;
    for part in payload.chunks(chunk.max(1)) {
        stream.update(part)?;
    }
    stream.finish()
}

fn pending_references(
    session: &VerifiedSession<'_, '_, '_, Memory>,
    completion: DetachedCompletion,
) -> Vec<xml_sec::NodeIdentity> {
    session
        .pending_detached(completion)
        .unwrap()
        .iter()
        .map(xml_sec::xmldsig::PendingDetached::reference)
        .collect()
}

#[test]
fn streamed_payload_completes_a_valid_detached_reference() {
    // Bytes the caller streams in chunks reach the same verdict as resident
    // bytes, record their provenance and fingerprint, and complete acceptance.
    let payload = b"detached payload bytes, hashed in chunks".repeat(64);
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: &payload,
        }],
        false,
    );
    for chunk in [1, 7, 4096, payload.len()] {
        let (pending, references, accepted) =
            session(&document, verification_policy(), |session| {
                let pending = session.pending_detached(DetachedCompletion::Complete)?;
                assert_eq!(pending.len(), 1);
                assert_eq!(pending[0].uri(), "https://example.test/data/payload.bin");
                assert_eq!(pending[0].digest_algorithm(), DigestAlgorithm::Sha256);
                assert_eq!(pending[0].chain(), DetachedChain::Octets);
                let reference = pending[0].reference();
                stream(
                    session,
                    &[reference],
                    &payload,
                    chunk,
                    DetachedCompletion::Complete,
                )?;
                Ok(session
                    .pending_detached(DetachedCompletion::Complete)?
                    .len())
            });
        assert_eq!(pending, 0, "a completed Reference is no longer pending");
        let detached = &references[1];
        assert_eq!(detached.status, DsigStatus::Valid, "chunk {chunk}");
        assert_eq!(detached.external_payload, Some(ExternalPayload::Streamed));
        let fingerprint: [u8; 32] = Sha256::digest(&payload).into();
        assert_eq!(detached.external_resource_fingerprint, Some(fingerprint));
        assert!(accepted, "every Reference now passes");
    }
}

#[test]
fn unstreamed_detached_reference_keeps_the_signature_unaccepted() {
    // Without bytes the Reference stays unavailable and the request is not
    // accepted; the signature itself remains verified.
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: b"bytes",
        }],
        false,
    );
    let ((), references, accepted) = session(&document, verification_policy(), |_| Ok(()));
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 1 })
    );
    assert!(!accepted);
}

#[test]
fn streamed_payload_that_differs_is_a_digest_mismatch() {
    // Streaming other bytes than the signer's is the same mismatch a resident
    // map would produce, not a processing failure.
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: b"signed bytes",
        }],
        false,
    );
    let ((), references, accepted) = session(&document, verification_policy(), |session| {
        let reference = pending_references(session, DetachedCompletion::Complete)[0];
        stream(
            session,
            &[reference],
            b"other bytes",
            3,
            DetachedCompletion::Complete,
        )
    });
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
    );
    assert_eq!(
        references[1].external_payload,
        Some(ExternalPayload::Streamed)
    );
    assert!(!accepted);
}

#[test]
fn one_pass_feeds_every_reference_paired_with_the_payload() {
    // Two References over the same payload with different digest methods are
    // completed by one stream; each gets its own digest and result.
    let payload = b"shared payload".repeat(300);
    let document = signed(
        &[
            Detached {
                uri: "a.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: &payload,
            },
            Detached {
                uri: "b.bin",
                base64: false,
                digest: DigestAlgorithm::Sha512,
                payload: &payload,
            },
        ],
        false,
    );
    let ((), references, accepted) = session(&document, verification_policy(), |session| {
        let pending = pending_references(session, DetachedCompletion::Complete);
        assert_eq!(pending.len(), 2);
        stream(
            session,
            &pending,
            &payload,
            997,
            DetachedCompletion::Complete,
        )
    });
    assert_eq!(references[1].status, DsigStatus::Valid);
    assert_eq!(references[2].status, DsigStatus::Valid);
    assert!(accepted);
}

#[test]
fn base64_chain_decodes_the_stream_with_the_resident_rules() {
    // A Base64-only chain is decoded on the fly: RFC 2045 §6.8 ignores bytes
    // outside the alphabet, padding is checked as in the resident transform,
    // and quanta split across chunks decode the same.
    // One byte past a multiple of three, so the encoding ends with "==".
    let mut decoded = b"payload behind a Base64 transform".repeat(200);
    decoded.push(b'!');
    let mut encoded = base64::engine::general_purpose::STANDARD
        .encode(&decoded)
        .into_bytes();
    // Line breaks every 76 characters, as MIME writes them.
    let mut wrapped = Vec::new();
    for line in encoded.chunks(76) {
        wrapped.extend_from_slice(line);
        wrapped.extend_from_slice(b"\r\n");
    }
    let document = signed(
        &[Detached {
            uri: "payload.b64",
            base64: true,
            digest: DigestAlgorithm::Sha256,
            payload: &wrapped,
        }],
        false,
    );
    for chunk in [1, 5, 4096, wrapped.len()] {
        let ((), references, accepted) = session(&document, verification_policy(), |session| {
            let pending = session.pending_detached(DetachedCompletion::Complete)?;
            assert_eq!(pending[0].chain(), DetachedChain::Base64);
            let reference = pending[0].reference();
            stream(
                session,
                &[reference],
                &wrapped,
                chunk,
                DetachedCompletion::Complete,
            )
        });
        assert_eq!(references[1].status, DsigStatus::Valid, "chunk {chunk}");
        let fingerprint: [u8; 32] = Sha256::digest(&wrapped).into();
        assert_eq!(
            references[1].external_resource_fingerprint,
            Some(fingerprint),
            "the fingerprint covers the bytes the caller supplied"
        );
        assert!(accepted);
    }

    // Data after padding and a truncated quantum are processing failures of
    // this Reference, exactly as the resident Base64 transform reports them.
    assert!(encoded.ends_with(b"=="));
    let truncated = encoded[..encoded.len() - 1].to_vec();
    encoded.extend_from_slice(b"QQ==");
    for malformed in [encoded.as_slice(), truncated.as_slice()] {
        let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
        let resident = HashMap::from([(
            "https://example.test/data/payload.b64".to_owned(),
            malformed.to_vec(),
        )]);
        let resident = VerifyContext::new()
            .policy(verification_policy())
            .key(&key)
            .external_resources(&resident)
            .verify_request(&document, &VerificationRequest::default())
            .unwrap();
        assert_eq!(
            resident.signatures()[0]
                .result()
                .as_ref()
                .unwrap()
                .signed_info_references[1]
                .status,
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 1 })
        );
        let ((), references, _) = session(&document, verification_policy(), |session| {
            let reference = pending_references(session, DetachedCompletion::Complete)[0];
            stream(
                session,
                &[reference],
                malformed,
                1000,
                DetachedCompletion::Complete,
            )
        });
        assert_eq!(
            references[1].status,
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 1 })
        );
    }
}

#[test]
fn chain_needing_xml_is_not_offered_for_streaming() {
    // A canonicalization transform needs the bytes parsed as XML, so the
    // Reference keeps the bounded resident path and is not pending here.
    let mut resources = HashMap::new();
    resources.insert(
        "https://example.test/data/doc.xml".to_owned(),
        b"<doc/>".to_vec(),
    );
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("doc.xml")
            .transform(Transform::C14n(C14nAlgorithm::new(
                C14nMode::Exclusive1_0,
                false,
            ))),
    );
    let xml = SignContext::new(&HmacSigningKey::new(SECRET.to_vec()).unwrap())
        .policy(signing_policy())
        .external_resources(&resources)
        .sign_with_builder("<root xml:base=\"https://example.test/data/\"/>", &builder)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let (pending, references, _) = session(&document, verification_policy(), |session| {
        Ok(session
            .pending_detached(DetachedCompletion::Complete)?
            .len())
    });
    assert_eq!(pending, 0);
    assert_eq!(
        references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 0 })
    );
}

#[test]
fn attested_digest_is_forbidden_unless_policy_accepts_it() {
    // A caller-attested digest is a policy decision, recorded as attested and
    // never as bytes this library hashed.
    let payload = b"payload the caller paired by digest";
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload,
        }],
        false,
    );
    let digest = Sha256::digest(payload).to_vec();
    let (forbidden, references, _) = session(&document, verification_policy(), |session| {
        let reference = pending_references(session, DetachedCompletion::Complete)[0];
        Ok(session.attest_detached(reference, &digest, DetachedCompletion::Complete))
    });
    assert!(matches!(
        forbidden,
        Err(DsigError::Policy(PolicyViolation::AttestedDigestForbidden))
    ));
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 1 })
    );

    let mut policy = verification_policy();
    policy.detached_digest_attestation = DetachedDigestAttestation::Accepted;
    for (attested, expected, accepted_expected) in [
        (digest.clone(), DsigStatus::Valid, true),
        (
            vec![0; 32],
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 }),
            false,
        ),
    ] {
        let (status, references, accepted) = session(&document, policy.clone(), |session| {
            let reference = pending_references(session, DetachedCompletion::Complete)[0];
            session.attest_detached(reference, &attested, DetachedCompletion::Complete)
        });
        assert_eq!(status, expected);
        assert_eq!(references[1].status, expected);
        assert_eq!(
            references[1].external_payload,
            Some(ExternalPayload::Attested)
        );
        assert_eq!(references[1].external_resource_fingerprint, None);
        assert_eq!(accepted, accepted_expected);
    }
}

#[test]
fn attested_digest_cannot_stand_for_a_transformed_reference() {
    // A digest over the paired bytes is not the input of a Base64 chain.
    let document = signed(
        &[Detached {
            uri: "payload.b64",
            base64: true,
            digest: DigestAlgorithm::Sha256,
            payload: b"cGF5bG9hZA==",
        }],
        false,
    );
    let mut policy = verification_policy();
    policy.detached_digest_attestation = DetachedDigestAttestation::Accepted;
    let (result, _, _) = session(&document, policy, |session| {
        let reference = pending_references(session, DetachedCompletion::Complete)[0];
        Ok(session.attest_detached(reference, &[0; 32], DetachedCompletion::Complete))
    });
    assert!(matches!(result, Err(DsigError::InvalidRequest { .. })));
}

#[test]
fn streamed_byte_limits_refuse_the_payload_and_keep_it_unavailable() {
    // Exceeding the per-Reference limit is a typed policy refusal; the payload
    // accepts no further chunk and finishes without a result.
    let payload = vec![0x42; 100];
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: &payload,
        }],
        false,
    );
    let mut policy = verification_policy();
    policy.resources.max_detached_payload_bytes = 99;
    let ((), references, _) = session(&document, policy, |session| {
        let reference = pending_references(session, DetachedCompletion::Complete)[0];
        let mut stream = session.detached_payload(&[reference], DetachedCompletion::Complete)?;
        stream.update(&payload[..60])?;
        assert!(matches!(
            stream.update(&payload[60..]),
            Err(DsigError::Policy(PolicyViolation::ResourceLimit {
                maximum: 99,
                actual: 100,
                ..
            }))
        ));
        assert!(
            stream.update(&[]).is_err(),
            "a refused payload stays refused"
        );
        assert!(stream.finish().is_err());
        Ok(())
    });
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 1 })
    );

    // The aggregate limit spans payloads of one session.
    let document = signed(
        &[
            Detached {
                uri: "a.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: &payload,
            },
            Detached {
                uri: "b.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: &payload,
            },
        ],
        false,
    );
    let mut policy = verification_policy();
    policy.resources.max_detached_payload_total_bytes = 150;
    let ((), references, _) = session(&document, policy, |session| {
        let pending = pending_references(session, DetachedCompletion::Complete);
        stream(
            session,
            &pending[..1],
            &payload,
            100,
            DetachedCompletion::Complete,
        )?;
        assert!(matches!(
            stream(
                session,
                &pending[1..],
                &payload,
                100,
                DetachedCompletion::Complete
            ),
            Err(DsigError::Policy(PolicyViolation::ResourceLimit {
                maximum: 150,
                actual: 200,
                ..
            }))
        ));
        Ok(())
    });
    assert_eq!(references[1].status, DsigStatus::Valid);
    assert_eq!(
        references[2].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 2 })
    );
}

#[test]
fn fail_fast_stops_after_the_first_failed_detached_reference() {
    // Fail-fast leaves the remaining pending References unprocessed after a
    // failure; the complete variant gives each its own result.
    let document = signed(
        &[
            Detached {
                uri: "a.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: b"first",
            },
            Detached {
                uri: "b.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: b"second",
            },
        ],
        false,
    );
    let (remaining, references, accepted) = session(&document, verification_policy(), |session| {
        let pending = pending_references(session, DetachedCompletion::FailFast);
        stream(
            session,
            &pending[..1],
            b"wrong",
            5,
            DetachedCompletion::FailFast,
        )?;
        Ok(pending_references(session, DetachedCompletion::FailFast).len())
    });
    assert_eq!(remaining, 0);
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
    );
    assert_eq!(references[2].status, DsigStatus::NotProcessed);
    assert!(!accepted);

    let ((), references, _) = session(&document, verification_policy(), |session| {
        let pending = pending_references(session, DetachedCompletion::Complete);
        stream(
            session,
            &pending[..1],
            b"wrong",
            5,
            DetachedCompletion::Complete,
        )?;
        stream(
            session,
            &pending[1..],
            b"second",
            5,
            DetachedCompletion::Complete,
        )
    });
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
    );
    assert_eq!(references[2].status, DsigStatus::Valid);
}

#[test]
fn fail_fast_requests_nothing_when_an_in_document_reference_failed() {
    // A Signature whose core validation already failed cannot pass, so the
    // fail-fast variant requests no payload; the complete one still does.
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: b"bytes",
        }],
        true,
    );
    let ((fail_fast, complete), references, _) =
        session(&document, verification_policy(), |session| {
            Ok((
                session
                    .pending_detached(DetachedCompletion::FailFast)?
                    .len(),
                session
                    .pending_detached(DetachedCompletion::Complete)?
                    .len(),
            ))
        });
    assert_eq!((fail_fast, complete), (0, 1));
    assert_eq!(
        references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}

#[test]
fn completed_detached_references_keep_the_first_failure_as_the_status() {
    // The overall status stays the first failing SignedInfo Reference in
    // document order after completion, here the in-document one.
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: b"bytes",
        }],
        true,
    );
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    let context = VerifyContext::new().policy(verification_policy()).key(&key);
    let work = work();
    let evidence = with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |mut session| {
            let reference = pending_references(&session, DetachedCompletion::Complete)[0];
            stream(
                &mut session,
                &[reference],
                b"bytes",
                2,
                DetachedCompletion::Complete,
            )?;
            Ok(session.into_evidence())
        },
    )
    .unwrap();
    let result = evidence.signatures()[0].result().as_ref().unwrap();
    assert_eq!(result.signed_info_references[1].status, DsigStatus::Valid);
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}

#[test]
fn invalid_payload_requests_are_rejected_before_any_byte() {
    // An empty, duplicated or non-pending Reference list is an invalid request.
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload: b"bytes",
        }],
        false,
    );
    let ((), _, _) = session(&document, verification_policy(), |session| {
        let reference = pending_references(session, DetachedCompletion::Complete)[0];
        let signature = session.evidence().signatures()[0].identity();
        for references in [&[][..], &[reference, reference][..], &[signature][..]] {
            assert!(matches!(
                session.detached_payload(references, DetachedCompletion::Complete),
                Err(DsigError::InvalidRequest { .. })
            ));
        }
        Ok(())
    });
}

#[test]
fn completing_core_validation_processes_the_authenticated_manifest() {
    // While a SignedInfo Reference is unavailable, core validation has failed
    // and Manifests are unparsed. Completing it processes them as verification
    // would (XMLDSig 1.1 §3.2), instead of leaving an empty Manifest list.
    let payload = b"detached part";
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(payload));
    let template = format!(
        r##"<root xml:base="https://example.test/data/"><item Id="item">manifest target</item><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="part.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference><ds:Reference URI="#manifest"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="manifest"><ds:Reference URI="#item"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##
    );
    let mut signing = signing_policy();
    signing.manifest_processing = ManifestProcessing::Process;
    let resources = HashMap::from([(
        "https://example.test/data/part.bin".to_owned(),
        payload.to_vec(),
    )]);
    let xml = SignContext::new(&HmacSigningKey::new(SECRET.to_vec()).unwrap())
        .policy(signing)
        .external_resources(&resources)
        .sign_template(&template)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = verification_policy();
    policy.manifest_processing = ManifestProcessing::Process;
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    let context = VerifyContext::new().policy(policy).key(&key);
    let work = work();
    let evidence = with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |mut session| {
            let before = session.evidence().signatures()[0]
                .result()
                .as_ref()
                .unwrap();
            assert!(before.manifest_references.is_empty());
            let reference = pending_references(&session, DetachedCompletion::Complete)[0];
            stream(
                &mut session,
                &[reference],
                payload,
                4,
                DetachedCompletion::Complete,
            )?;
            Ok(session.into_evidence())
        },
    )
    .unwrap();
    let result = evidence.signatures()[0].result().as_ref().unwrap();
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(result.manifest_references.len(), 1);
    assert_eq!(result.manifest_references[0].status, DsigStatus::Valid);
    assert!(evidence.all_valid());
    assert!(evidence.accepted(&document).unwrap());
}

#[test]
fn attested_digest_is_not_reported_as_computed_hash_use() {
    // Hash-use inspection reports what the operation actually hashed. An
    // attested digest was never computed here, unlike a streamed payload.
    use xml_sec::xmldsig::HashUseState;
    let payload = b"payload the caller paired by digest";
    let document = signed(
        &[Detached {
            uri: "payload.bin",
            base64: false,
            digest: DigestAlgorithm::Sha256,
            payload,
        }],
        false,
    );
    let mut policy = verification_policy();
    policy.detached_digest_attestation = DetachedDigestAttestation::Accepted;
    let digest = Sha256::digest(payload).to_vec();
    for attest in [true, false] {
        let (state, _, _) = session(&document, policy.clone(), |session| {
            let reference = pending_references(session, DetachedCompletion::Complete)[0];
            if attest {
                session.attest_detached(reference, &digest, DetachedCompletion::Complete)?;
            } else {
                stream(
                    session,
                    &[reference],
                    payload,
                    8,
                    DetachedCompletion::Complete,
                )?;
            }
            let signature = session.evidence().signatures()[0].identity();
            let selected = session.select_signature(signature)?;
            let mut state = None;
            selected
                .visit_hash_uses(|usage| {
                    if usage.instruction == reference {
                        state = Some(usage.state);
                    }
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok(state)
        });
        let expected = if attest {
            HashUseState::Unprocessed
        } else {
            HashUseState::Complete
        };
        assert_eq!(state, Some(expected), "attested: {attest}");
    }
}

#[test]
fn fail_fast_stops_inside_one_grouped_payload() {
    // One payload paired with several References: under fail-fast the first
    // failure in the caller's order leaves the following References
    // unprocessed even when the same bytes would match them.
    let document = signed(
        &[
            Detached {
                uri: "a.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: b"first",
            },
            Detached {
                uri: "b.bin",
                base64: false,
                digest: DigestAlgorithm::Sha256,
                payload: b"second",
            },
        ],
        false,
    );
    let ((), references, accepted) = session(&document, verification_policy(), |session| {
        let pending = pending_references(session, DetachedCompletion::FailFast);
        stream(
            session,
            &pending,
            b"second",
            3,
            DetachedCompletion::FailFast,
        )
    });
    assert_eq!(
        references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
    );
    assert_eq!(references[2].status, DsigStatus::NotProcessed);
    assert!(!accepted);
}

#[test]
fn listing_does_not_reparse_chains_that_cannot_stream() {
    // A detached Reference with an XPath transform needs its bytes as XML, so
    // it is never offered for streaming; listing must not parse its transforms
    // again and spend the operation's XPath allowance on every call.
    let payload = b"<doc/>";
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"<doc/>"));
    let template = format!(
        r#"<root xml:base="https://example.test/data/"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="doc.xml"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"#
    );
    let resources = HashMap::from([(
        "https://example.test/data/doc.xml".to_owned(),
        payload.to_vec(),
    )]);
    let xml = SignContext::new(&HmacSigningKey::new(SECRET.to_vec()).unwrap())
        .policy(signing_policy())
        .external_resources(&resources)
        .sign_template(&template)
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = verification_policy();
    policy.resources.max_xpath_expressions = 1;
    let (listed, references, _) = session(&document, policy, |session| {
        let mut listed = Vec::new();
        for _ in 0..3 {
            listed.push(
                session
                    .pending_detached(DetachedCompletion::Complete)?
                    .len(),
            );
        }
        Ok(listed)
    });
    assert_eq!(listed, [0, 0, 0]);
    assert_eq!(
        references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 0 })
    );
}
