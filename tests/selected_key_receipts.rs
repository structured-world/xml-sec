#![cfg(feature = "xmldsig")]

use std::{cell::Cell, sync::Arc};
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};
use structured_pkix::{key::PublicKeyInfo, path::WorkingKey};
use xml_sec::{
    XmlDocument,
    c14n::{C14nAlgorithm, C14nMode},
    provider::KeyAssociation,
    xmldsig::*,
};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

fn public_key(pem: &str) -> VerificationKey {
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: pem::parse(pem).unwrap().into_contents(),
        certificate_der: None,
        name: None,
    }
}

fn with_expected<R>(bytes: &[u8], visitor: impl FnOnce(WorkingKey<'_>) -> R) -> R {
    let parser = Parser::new(Encoding::Der, Limits::default(), account());
    let mut reader = parser.read(bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&reader, &element, "test expected SPKI").unwrap();
    assert!(reader.is_empty());
    visitor(WorkingKey::standing(key))
}

fn signed() -> XmlDocument {
    let signer =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    XmlDocument::parse(
        SignContext::new(&signer)
            .sign_with_builder("<root/>", &builder)
            .unwrap(),
    )
    .unwrap()
}

fn signed_named(id: &str) -> String {
    let signer =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .signature_id(format!("signature-{id}"))
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(format!("#payload-{id}")));
    SignContext::new(&signer)
        .sign_with_builder(
            &format!("<root><payload Id=\"payload-{id}\">value</payload></root>"),
            &builder,
        )
        .unwrap()
}

#[test]
fn receipts_do_not_cross_signatures_or_repeated_operations() {
    // Same keys, document and provider do not authorize reuse in another
    // Signature or a second operation over that exact document generation.
    let mut document = XmlDocument::parse(format!(
        "<both>{}{}</both>",
        signed_named("one"),
        signed_named("two")
    ))
    .unwrap();
    let stale = document.with_view(|view| view.node_for_id("signature-one", &[]).unwrap());
    let payload = document.with_view(|view| view.node_for_id("payload-one", &[]).unwrap());
    document.replace_content(payload, "value").unwrap();
    let foreign_document = XmlDocument::parse(signed_named("one")).unwrap();
    let foreign =
        foreign_document.with_view(|view| view.node_for_id("signature-one", &[]).unwrap());
    let key = public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let context = VerifyContext::new().key(&key);
    with_expected(&key.public_key_bytes, |expected| {
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                assert!(session.select_signature(stale).is_err());
                assert!(session.select_signature(foreign).is_err());
                let first = session
                    .select_signature(session.view().node_for_id("signature-one", &[]).unwrap())?;
                let second = session
                    .select_signature(session.view().node_for_id("signature-two", &[]).unwrap())?;
                first
                    .with_key_receipt(|receipt| {
                        let mut called = false;
                        assert!(matches!(
                            second.associate_key(&receipt, expected, |_| {
                                called = true;
                                Ok::<_, ()>(())
                            }),
                            Err(CatalogueError::Processing(DsigError::InvalidRequest { .. }))
                        ));
                        assert!(!called);
                        with_verified_request(
                            &document,
                            &context,
                            &VerificationRequest::default(),
                            &account(),
                            |other| {
                                let other = other.select_signature(
                                    other.view().node_for_id("signature-one", &[]).unwrap(),
                                )?;
                                assert!(matches!(
                                    other.associate_key(&receipt, expected, |_| {
                                        called = true;
                                        Ok::<_, ()>(())
                                    }),
                                    Err(CatalogueError::Processing(
                                        DsigError::InvalidRequest { .. }
                                    ))
                                ));
                                assert!(!called);
                                Ok(())
                            },
                        )
                        .unwrap();
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
    });
}

#[test]
fn receipt_storage_refusal_cannot_be_swallowed_by_candidate_recovery() {
    // Resource failure while retaining a real successful leaf is terminal;
    // even a custom composite swallowing errors cannot produce usable evidence.
    struct Exhaust<'a> {
        key: VerificationKey,
        work: &'a Memory,
        held: std::cell::RefCell<Option<structured_asn1::memory::OwnedVec<u8>>>,
    }
    impl VerifyingKey for Exhaust<'_> {
        fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
            self.key.association_spki(algorithm)
        }
        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, DsigError> {
            let verified = self.key.verify(algorithm, data, signature)?;
            let mut held = self.work.vector();
            held.try_reserve_exact(self.work.limit() - self.work.used())?;
            *self.held.borrow_mut() = Some(held);
            Ok(verified)
        }
    }
    struct Swallow<'a>(&'a dyn VerifyingKey);
    impl VerifyingKey for Swallow<'_> {
        fn verify_candidate_keys(
            &self,
            visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
        ) -> Result<Option<bool>, DsigError> {
            let _ = visitor(self.0);
            Ok(Some(true))
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            panic!("composite leaf")
        }
    }
    let work = account();
    let key = Exhaust {
        key: public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem")),
        work: &work,
        held: std::cell::RefCell::new(None),
    };
    let composite = Swallow(&key);
    let document = signed();
    let context = VerifyContext::new().key(&composite);
    let mut selected = false;
    let result: Result<(), DsigError> = with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let signature = session.evidence().signatures().first().unwrap();
            assert!(matches!(
                signature.result(),
                Err(DsigError::SharedExecution(
                    structured_asn1::memory::MemoryError::LimitExceeded
                ))
            ));
            let rejection = session.select_signature(signature.identity());
            selected = rejection.is_ok();
            match rejection {
                Err(
                    error @ DsigError::SharedExecution(
                        structured_asn1::memory::MemoryError::LimitExceeded,
                    ),
                ) => Err(error),
                _ => panic!("the original receipt storage failure must survive selection"),
            }
        },
    );
    assert!(!selected);
    assert!(result.is_err(), "exhausted retention remains terminal");
    drop(key.held.borrow_mut().take());
    assert_eq!(work.used(), 0, "retained charges follow their allocations");
}

struct ObservedKey {
    key: VerificationKey,
    calls: Cell<usize>,
    disclose: bool,
}

#[test]
fn recursive_composites_stop_before_a_leaf_or_stack_overflow() {
    // Caller-supplied composite nesting must not turn the observed provider
    // traversal into unbounded recursion, even with a generous work account.
    struct Recursive;
    impl VerifyingKey for Recursive {
        fn verify_candidate_keys(
            &self,
            visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
        ) -> Result<Option<bool>, DsigError> {
            visitor(self).map(Some)
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            panic!("a recursive composite is not a leaf")
        }
    }
    let document = signed();
    let context = VerifyContext::new().key(&Recursive);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let identity = session.evidence().signatures()[0].identity();
            assert!(matches!(
                session.select_signature(identity),
                Err(DsigError::SharedExecution(
                    structured_asn1::memory::MemoryError::WorkExceeded
                ))
            ));
            Ok(())
        },
    )
    .unwrap();
}

#[cfg(feature = "aws-lc-fips")]
#[test]
fn native_receipt_does_not_requery_a_previously_selected_leaf() {
    // A changing candidate source first supplies a wrong leaf, then a valid
    // child. A second lookup must not verify that child and receipt the old leaf.
    struct Changing<'a> {
        wrong: &'a VerificationKey,
        right: &'a VerificationKey,
        queries: Cell<usize>,
    }
    impl VerifyingKey for Changing<'_> {
        fn verify_candidate_keys(
            &self,
            visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
        ) -> Result<Option<bool>, DsigError> {
            let previous = self.queries.get();
            self.queries.set(previous + 1);
            if previous == 0 {
                Ok(None)
            } else {
                visitor(self.right).map(Some)
            }
        }
        fn verification_spki(
            &self,
            algorithm: SignatureAlgorithm,
        ) -> Result<Option<&[u8]>, DsigError> {
            self.wrong.verification_spki(algorithm)
        }
        fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
            self.wrong.association_spki(algorithm)
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            panic!("selected AWS must not use a software fallback")
        }
    }
    let wrong = public_key(include_str!("fixtures/keys/rsa/rsa-expired-pubkey.pem"));
    let right = public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let key = Changing {
        wrong: &wrong,
        right: &right,
        queries: Cell::new(0),
    };
    let document = signed();
    let context = VerifyContext::new()
        .key(&key)
        .provider(&xml_sec::provider::AwsLcFipsProvider);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let identity = session.evidence().signatures()[0].identity();
            assert!(
                session.select_signature(identity).is_err(),
                "the original wrong leaf cannot authenticate this Signature"
            );
            assert_eq!(
                key.queries.get(),
                1,
                "candidate selection is a single observation"
            );
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn equivalent_ec_encodings_use_only_the_selected_providers_semantics() {
    // RFC 5480 §2.2 allows compressed points. RustCrypto can prove their
    // equality; the official AWS safe API cannot, so must not software-fallback.
    use der::{Decode as _, Encode as _};
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let bytes = pem::parse(include_str!("fixtures/keys/ec/ec-prime256v1-pubkey.pem"))
        .unwrap()
        .into_contents();
    let public = pkcs8::SubjectPublicKeyInfoRef::from_der(&bytes).unwrap();
    let point =
        p256::PublicKey::from_sec1_bytes(public.subject_public_key.as_bytes().unwrap()).unwrap();
    let point = point.to_sec1_point(true);
    let compressed = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: public.algorithm,
        subject_public_key: der::asn1::BitStringRef::from_bytes(point.as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap();
    let signer =
        EcdsaP256SigningKey::from_pkcs8_pem(include_str!("fixtures/keys/ec/ec-prime256v1-key.pem"))
            .unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::EcdsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let document = XmlDocument::parse(
        SignContext::new(&signer)
            .sign_with_builder("<root/>", &builder)
            .unwrap(),
    )
    .unwrap();
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::EcdsaSha256,
        public_key_bytes: bytes,
        certificate_der: None,
        name: None,
    };
    let check = |provider: &dyn xml_sec::provider::CryptoProvider, outcome| {
        let context = VerifyContext::new().key(&key).provider(provider);
        with_expected(&compressed, |expected| {
            with_verified_request(
                &document,
                &context,
                &VerificationRequest::default(),
                &account(),
                |session| {
                    let selected =
                        session.select_signature(session.evidence().signatures()[0].identity())?;
                    selected
                        .with_key_receipt(|receipt| {
                            selected
                                .associate_key(&receipt, expected, |actual| {
                                    assert_eq!(actual, outcome);
                                    Ok::<_, ()>(())
                                })
                                .unwrap();
                            Ok::<_, ()>(())
                        })
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
    };
    check(&xml_sec::provider::RustCryptoProvider, KeyAssociation::Same);
    #[cfg(feature = "aws-lc-fips")]
    check(
        &xml_sec::provider::AwsLcFipsProvider,
        KeyAssociation::Unproven,
    );
}

#[test]
fn pss_method_compatibility_does_not_erase_effective_key_restrictions() {
    // RFC 4055 §3.3: absent restrictions are not the same key contract as
    // explicit minima, even when the actual salt-32 method fits both keys.
    use der::{Decode as _, Encode as _};
    fn public(base: &[u8], salt: Option<u8>) -> Vec<u8> {
        let base = pkcs8::SubjectPublicKeyInfoRef::from_der(base).unwrap();
        let digest = pkcs8::AlgorithmIdentifierRef {
            oid: der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: Some(der::asn1::AnyRef::NULL),
        }
        .to_der()
        .unwrap();
        let mgf = pkcs8::AlgorithmIdentifierRef {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8"),
            parameters: Some(der::asn1::AnyRef::from_der(&digest).unwrap()),
        }
        .to_der()
        .unwrap();
        let mut content = Vec::new();
        for (number, bytes) in [(0, digest), (1, mgf)] {
            content.extend(
                der::asn1::Any::new(
                    der::Tag::ContextSpecific {
                        constructed: true,
                        number: der::TagNumber(number),
                    },
                    bytes,
                )
                .unwrap()
                .to_der()
                .unwrap(),
            );
        }
        if let Some(salt) = salt
            && salt != 20
        {
            content.extend(
                der::asn1::Any::new(
                    der::Tag::ContextSpecific {
                        constructed: true,
                        number: der::TagNumber(2),
                    },
                    [2, 1, salt],
                )
                .unwrap()
                .to_der()
                .unwrap(),
            );
        }
        let params = der::asn1::Any::new(der::Tag::Sequence, content)
            .unwrap()
            .to_der()
            .unwrap();
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
                parameters: salt.map(|_| der::asn1::AnyRef::from_der(&params).unwrap()),
            },
            subject_public_key: base.subject_public_key,
        }
        .to_der()
        .unwrap()
    }
    let key = public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let unrestricted = public(&key.public_key_bytes, None);
    let minimum20 = public(&key.public_key_bytes, Some(20));
    let minimum32 = public(&key.public_key_bytes, Some(32));
    let signer =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaPssSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let document = XmlDocument::parse(
        SignContext::new(&signer)
            .sign_with_builder("<root/>", &builder)
            .unwrap(),
    )
    .unwrap();
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaPssSha256,
        public_key_bytes: minimum20.clone(),
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
            selected
                .with_key_receipt(|receipt| {
                    for (bytes, outcome) in [
                        (&minimum20, KeyAssociation::Same),
                        (&minimum32, KeyAssociation::Unproven),
                        (&unrestricted, KeyAssociation::Unproven),
                    ] {
                        with_expected(bytes, |expected| {
                            selected
                                .associate_key(&receipt, expected, |actual| {
                                    assert_eq!(actual, outcome);
                                    Ok::<_, ()>(())
                                })
                                .unwrap();
                        });
                    }
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok(())
        },
    )
    .unwrap();
}

impl VerifyingKey for ObservedKey {
    fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
        if self.disclose {
            self.key.association_spki(algorithm)
        } else {
            None
        }
    }
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

struct Candidates<'a>([&'a dyn VerifyingKey; 2]);

impl VerifyingKey for Candidates<'_> {
    fn verify_candidate_keys(
        &self,
        visitor: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
    ) -> Result<Option<bool>, DsigError> {
        for key in self.0 {
            if visitor(key)? {
                return Ok(Some(true));
            }
        }
        Ok(Some(false))
    }
    fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
        panic!("a composite is not a successful leaf")
    }
}

#[test]
fn receipt_is_the_real_successful_candidate_and_does_not_verify_again() {
    // The first candidate is a valid but wrong RSA key. Association must name
    // the second actual successful key, and repeated projection does no crypto.
    let wrong = ObservedKey {
        key: public_key(include_str!("fixtures/keys/rsa/rsa-expired-pubkey.pem")),
        calls: Cell::new(0),
        disclose: true,
    };
    let right = ObservedKey {
        key: public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem")),
        calls: Cell::new(0),
        disclose: true,
    };
    let candidates = Candidates([&wrong, &right]);
    let document = signed();
    let context = VerifyContext::new().key(&candidates);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            for _ in 0..2 {
                selected
                    .with_key_receipt(|receipt| {
                        assert!(receipt.has_public_evidence());
                        assert_eq!(
                            receipt.signature(),
                            session.evidence().signatures()[0].identity()
                        );
                        for (key, expected) in [
                            (&wrong.key, KeyAssociation::Mismatch),
                            (&right.key, KeyAssociation::Same),
                        ] {
                            with_expected(&key.public_key_bytes, |key| {
                                selected
                                    .associate_key(&receipt, key, |actual| {
                                        assert_eq!(actual, expected);
                                        Ok::<_, ()>(())
                                    })
                                    .unwrap();
                            });
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap();
            }
            assert_eq!(wrong.calls.get(), 1);
            assert_eq!(right.calls.get(), 1);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn opaque_keys_are_unproven_only_when_public_receipt_evidence_is_absent() {
    // No native verification SPKI is exported by this handle. A separate
    // public-only association receipt can nevertheless prove its real key.
    for disclose in [false, true] {
        let key = ObservedKey {
            key: public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem")),
            calls: Cell::new(0),
            disclose,
        };
        let document = signed();
        let context = VerifyContext::new().key(&key);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                selected
                    .with_key_receipt(|receipt| {
                        assert_eq!(receipt.has_public_evidence(), disclose);
                        with_expected(&key.key.public_key_bytes, |expected| {
                            selected
                                .associate_key(&receipt, expected, |result| {
                                    assert_eq!(
                                        result,
                                        if disclose {
                                            KeyAssociation::Same
                                        } else {
                                            KeyAssociation::Unproven
                                        }
                                    );
                                    Ok::<_, ()>(())
                                })
                                .unwrap();
                        });
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!(key.calls.get(), 1);
                Ok(())
            },
        )
        .unwrap();
    }
}

#[test]
fn current_work_and_typed_visitor_refusal_are_preserved() {
    // Both aggregate Memory and a narrower borrowed Execution pay comparison.
    exhausted_receipt(&account());
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1 << 20,
            ..Default::default()
        },
        account(),
    );
    let reader = parser.read(&[], 0).unwrap();
    exhausted_receipt(&reader.execution());
}

fn exhausted_receipt(work: &impl Work) {
    let key = public_key(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let document = signed();
    let context = VerifyContext::new().key(&key);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let refusal = selected.with_key_receipt(|_| Err::<(), _>("caller refused"));
            assert!(matches!(
                refusal,
                Err(CatalogueError::Visitor("caller refused"))
            ));
            selected
                .with_key_receipt(|receipt| {
                    for shift in (0..=28).rev() {
                        while work.charge_work(1 << shift).is_ok() {}
                    }
                    with_expected(&key.public_key_bytes, |expected| {
                        let mut called = false;
                        let result = selected.associate_key(&receipt, expected, |_| {
                            called = true;
                            Ok::<_, ()>(())
                        });
                        assert!(matches!(
                            result,
                            Err(CatalogueError::Processing(DsigError::SharedExecution(_)))
                        ));
                        assert!(!called);
                    });
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok(())
        },
    )
    .unwrap();
}
