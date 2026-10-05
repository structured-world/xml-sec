//! End-to-end external-key checks using only an isolated SoftHSM test store.
#![cfg(feature = "pkcs11")]

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use std::sync::Arc;
use xml_sec::provider::pkcs11::{Pkcs11Provider, cryptoki};
use xml_sec::provider::{
    ContentDecryptionKey, CryptoProvider, ExternalProviderError, KeyAgreementParameters,
    ProviderError, RustCryptoProvider,
};
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
use xml_sec::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm};

#[test]
fn isolated_token_operations_and_failures() {
    // Refuse initialization unless the maintained harness supplies a disposable store.
    // This prevents accidentally resetting a real token on a developer machine.
    let store = std::env::var("XML_SEC_PKCS11_TEST_STORE").expect("run scripts/test-pkcs11.sh");
    let config = std::env::var("SOFTHSM2_CONF").expect("isolated configuration");
    assert_eq!(
        std::path::Path::new(&config).parent(),
        Some(std::path::Path::new(&store))
    );
    let module =
        Pkcs11::new(std::env::var("XML_SEC_PKCS11_TEST_MODULE").expect("explicit test module"))
            .unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    // Keep the explicit module loaded until process shutdown. SoftHSM's OpenSSL
    // backend registers thread-local destructors that must run before dlclose.
    // Dropping the last module on the libtest worker unloads those callbacks.
    static MODULE: std::sync::OnceLock<Pkcs11> = std::sync::OnceLock::new();
    let module = MODULE.get_or_init(|| module);
    let slot = module.get_slots_with_token().unwrap()[0];
    let so = AuthPin::new("test-so-1234".into());
    let pin = AuthPin::new("test-user-1234".into());
    module
        .init_token(slot, &so, "xml-sec isolated test")
        .unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().token_initialized())
        .unwrap();
    {
        let session = module.open_rw_session(slot).unwrap();
        session.login(UserType::So, Some(&so)).unwrap();
        session.init_pin(&pin).unwrap();
    }
    let provider = Pkcs11Provider::new(module, slot).unwrap();
    // PKCS#11 Base 2.40 §5.6: the provider must not require token-write access.
    // A live R/O session prevents SO login, proving the mode without exposing
    // the provider's private session or modifying a real token's protection flags.
    {
        let admin = module.open_rw_session(slot).unwrap();
        assert!(matches!(
            admin.login(UserType::So, Some(&so)),
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::SessionReadOnlyExists,
                _
            ))
        ));
    }
    // Wrong credentials stay typed and never include token, PIN or module details.
    let error = provider
        .login(&AuthPin::new("wrong-pin".into()))
        .unwrap_err();
    assert!(matches!(
        error,
        ProviderError::External(ExternalProviderError::Credentials)
    ));
    assert!(!error.to_string().contains("wrong-pin"));
    provider.login(&pin).unwrap();
    let session = module.open_rw_session(slot).unwrap();
    session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Id(vec![1]),
                Attribute::PublicExponent(vec![1, 0, 1]),
                Attribute::ModulusBits(2048.into()),
                Attribute::Verify(true),
                Attribute::Encrypt(true),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Id(vec![1]),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Decrypt(true),
                Attribute::Unwrap(true),
            ],
        )
        .unwrap();
    let private = Arc::new(provider.rsa_private_key(&[1]).unwrap());
    let public = provider.rsa_public_key(&[1]).unwrap();
    let message = b"opaque key operation";
    let signature = provider
        .sign(private.as_ref(), SignatureAlgorithm::RsaSha256, message)
        .unwrap();
    // XMLDSig reference hashing, C14N and signature verification use one provider.
    let builder = xml_sec::xmldsig::SignatureBuilder::new(
        xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        xml_sec::xmldsig::ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(xml_sec::xmldsig::Transform::Enveloped),
    );
    let signed = xml_sec::xmldsig::SignContext::new(private.as_ref())
        .provider(&provider)
        .sign_with_builder("<root><payload>signed</payload></root>", &builder)
        .unwrap();
    // An opaque handle does not bypass the operation's RSA strength policy.
    let mut strict = xml_sec::policy::VerificationPolicy::default();
    strict.key_trust.rsa_keys.minimum_modulus_bits = 3072;
    assert!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(&public)
            .provider(&provider)
            .policy(strict)
            .verify(&signed)
            .is_err()
    );
    assert!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(&public)
            .provider(&provider)
            .verify(&signed)
            .unwrap()
            .status
            == xml_sec::xmldsig::DsigStatus::Valid
    );
    assert!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(&public)
            .provider(&provider)
            .verify(&signed.replace("signed", "changed"))
            .unwrap()
            .status
            != xml_sec::xmldsig::DsigStatus::Valid
    );
    assert!(
        provider
            .verify(&public, SignatureAlgorithm::RsaSha256, message, &signature)
            .unwrap()
    );
    assert!(
        !provider
            .verify(
                &public,
                SignatureAlgorithm::RsaSha256,
                b"tampered",
                &signature
            )
            .unwrap()
    );
    assert_eq!(
        provider.digest(DigestAlgorithm::Sha256, message).unwrap(),
        RustCryptoProvider
            .digest(DigestAlgorithm::Sha256, message)
            .unwrap()
    );
    // A same-name provider on another session must not execute this handle.
    let other = Pkcs11Provider::new(module, slot).unwrap();
    assert!(
        other
            .sign(private.as_ref(), SignatureAlgorithm::RsaSha256, message)
            .is_err()
    );
    assert!(
        other
            .verify(&public, SignatureAlgorithm::RsaSha256, message, &signature)
            .is_err()
    );
    assert!(
        RustCryptoProvider
            .verify(&public, SignatureAlgorithm::RsaSha256, message, &signature)
            .is_err()
    );
    // Clones share the execution domain and serialize whole C_Sign operations.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let provider = &provider;
            let private = &private;
            scope.spawn(move || {
                for _ in 0..4 {
                    assert_eq!(
                        provider
                            .sign(private.as_ref(), SignatureAlgorithm::RsaSha256, message)
                            .unwrap()
                            .len(),
                        256
                    );
                }
            });
        }
    });
    let kek = [0x31; 16];
    let cek = [0x72; 16];
    let native_aes = session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Id(vec![2]),
            Attribute::Value(kek.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Unwrap(true),
            Attribute::Decrypt(true),
        ])
        .unwrap();
    let opaque = provider.aes_key(&[2]).unwrap();
    let ciphertext = RustCryptoProvider
        .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &kek, message)
        .unwrap();
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, &opaque, &ciphertext)
            .unwrap(),
        message
    );
    assert!(
        opaque
            .decrypt_with_provider(&other, DataEncryptionAlgorithm::Aes128Gcm, &ciphertext)
            .is_err()
    );
    // Corrupt GCM must release no plaintext. Compare the exact native failure:
    // SoftHSM 2.6 SymDecrypt returns GENERAL_ERROR from decryptFinal, while 2.7
    // distinguishes ENCRYPTED_DATA_INVALID. Do not fabricate authentication
    // evidence from an opaque operational error or weaken this to is_err().
    // https://github.com/softhsm/SoftHSMv2/blob/2.6.1/src/lib/SoftHSM.cpp#L3071-L3076
    let mut corrupted = ciphertext.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut nonce: [u8; 12] = corrupted[..12].try_into().unwrap();
    let params = cryptoki::mechanism::aead::GcmParams::new(&mut nonce, &[], 128.into()).unwrap();
    let native_error = session
        .decrypt(&Mechanism::AesGcm(params), native_aes, &corrupted[12..])
        .unwrap_err();
    let expected = match native_error {
        cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::EncryptedDataInvalid,
            cryptoki::context::Function::Decrypt,
        ) => ProviderError::AuthenticationFailed,
        cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::GeneralError,
            cryptoki::context::Function::Decrypt,
        ) => ProviderError::External(ExternalProviderError::Operation),
        error => panic!("unexpected native GCM failure: {error:?}"),
    };
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, &opaque, &corrupted)
            .unwrap_err(),
        expected
    );
    // An authentication/operation failure must not poison the next invocation.
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, &opaque, &ciphertext)
            .unwrap(),
        message
    );
    let cbc = RustCryptoProvider
        .encrypt_data(DataEncryptionAlgorithm::Aes128Cbc, &kek, message)
        .unwrap();
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Cbc, &opaque, &cbc)
            .unwrap(),
        message
    );
    assert!(
        provider
            .decrypt_content_key(
                DataEncryptionAlgorithm::Aes128Cbc,
                &opaque,
                &cbc[..cbc.len() - 1]
            )
            .is_err()
    );
    let wrapped = RustCryptoProvider
        .wrap_key(KeyWrapAlgorithm::AesKw128, &kek, &cek)
        .unwrap();
    let content = provider
        .unwrap_content_key(
            &opaque,
            KeyWrapAlgorithm::AesKw128,
            DataEncryptionAlgorithm::Aes128Gcm,
            &wrapped,
        )
        .unwrap();
    assert_eq!(content.key_len(), 16);
    assert!(matches!(
        content.into_key(),
        Err(ProviderError::KeyNotExportable)
    ));
    // AES-256 must use the same opaque boundary, not an AES-128-only shortcut.
    let wide_kek = [0x53; 32];
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Id(vec![8]),
            Attribute::Value(wide_kek.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
            Attribute::Unwrap(true),
        ])
        .unwrap();
    let wide = provider.aes_key(&[8]).unwrap();
    for algorithm in [
        DataEncryptionAlgorithm::Aes256Cbc,
        DataEncryptionAlgorithm::Aes256Gcm,
    ] {
        let cipher = RustCryptoProvider
            .encrypt_data(algorithm, &wide_kek, message)
            .unwrap();
        assert_eq!(
            provider
                .decrypt_content_key(algorithm, &wide, &cipher)
                .unwrap(),
            message
        );
    }
    let wrapped = RustCryptoProvider
        .wrap_key(KeyWrapAlgorithm::AesKw256, &wide_kek, &wide_kek)
        .unwrap();
    assert_eq!(
        provider
            .unwrap_content_key(
                &wide,
                KeyWrapAlgorithm::AesKw256,
                DataEncryptionAlgorithm::Aes256Gcm,
                &wrapped
            )
            .unwrap()
            .key_len(),
        32
    );
    // Token usage, not merely existence of the algorithm, gates signing.
    session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Id(vec![3]),
                Attribute::PublicExponent(vec![1, 0, 1]),
                Attribute::ModulusBits(2048.into()),
            ],
            &[
                Attribute::Token(true),
                Attribute::Id(vec![3]),
                Attribute::Sign(false),
            ],
        )
        .unwrap();
    let denied = provider.rsa_private_key(&[3]).unwrap();
    assert!(
        provider
            .sign(&denied, SignatureAlgorithm::RsaSha256, message)
            .is_err()
    );
    assert!(provider.rsa_private_key(&[99]).is_err());
    // Exercise the public XML pipelines, not only the primitive provider calls.
    let resolver =
        xml_sec::xmlenc::OpaqueContentKeyResolver::new(Arc::new(provider.aes_key(&[2]).unwrap()));
    let encrypted = xml_sec::xmlenc::EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(kek.to_vec())
        .encrypt_binary(message)
        .unwrap();
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(message.to_vec())
    );
    let recipient = xml_sec::xmlenc::EncryptionRecipient::aes_key_wrap(
        kek.to_vec(),
        KeyWrapAlgorithm::AesKw128,
    );
    let encrypted = xml_sec::xmlenc::EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(recipient)
        .encrypt_binary(message)
        .unwrap();
    let resolver =
        xml_sec::xmlenc::OpaqueKekDecryptor::new(Arc::new(provider.aes_key(&[2]).unwrap()));
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(message.to_vec())
    );
    // Encrypting with a token public key is an explicit selection, with no software fallback.
    // SoftHSM exposes OAEP but rejects SHA-256 parameters; never retry with SHA-1.
    assert!(matches!(
        provider.transport_key(
            &public,
            &xml_sec::xmlenc::RsaOaepParameters::default(),
            &cek
        ),
        Err(ProviderError::Unsupported { .. })
    ));
    let parameters = xml_sec::xmlenc::RsaOaepParameters::legacy();
    let wrapped = provider.transport_key(&public, &parameters, &cek).unwrap();
    // OAEP's fixed ciphertext width must not hide a mismatched recovered CEK.
    let wrong_width = provider
        .transport_key(&public, &parameters, &[1; 24])
        .unwrap();
    assert!(matches!(
        provider.recover_content_key(
            private.as_ref(),
            &parameters,
            DataEncryptionAlgorithm::Aes128Gcm,
            &wrong_width
        ),
        Err(ProviderError::InvalidKeySize {
            expected: 16,
            actual: 24
        })
    ));
    let recovered = provider
        .recover_content_key(
            private.as_ref(),
            &parameters,
            DataEncryptionAlgorithm::Aes128Gcm,
            &wrapped,
        )
        .unwrap();
    assert_eq!(recovered.key_len(), 16);
    assert!(matches!(
        recovered.into_key(),
        Err(ProviderError::KeyNotExportable)
    ));
    use rsa::pkcs8::DecodePublicKey;
    let xml_sec::xmldsig::SigningPublicKeyInfo::Rsa { spki_der, .. } =
        xml_sec::xmldsig::SigningKey::public_key_info(private.as_ref()).unwrap()
    else {
        panic!("RSA metadata");
    };
    let recipient = xml_sec::xmlenc::EncryptionRecipient::rsa_oaep(
        rsa::RsaPublicKey::from_public_key_der(&spki_der).unwrap(),
    )
    .oaep_parameters(parameters);
    let encrypted = xml_sec::xmlenc::EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(recipient)
        .encrypt_binary(message)
        .unwrap();
    let resolver = xml_sec::xmlenc::PrivateKeyDecryptor::provider_key(private.clone());
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(message.to_vec())
    );
    // Both sides derive the same secret without reading either private scalar.
    use rsa::pkcs8::der::{Decode, asn1::OctetStringRef};
    for (curve, width, first_id) in [
        (&[6, 8, 42, 134, 72, 206, 61, 3, 1, 7][..], 32, 4),
        (&[6, 5, 43, 129, 4, 0, 34][..], 48, 6),
        (&[6, 5, 43, 129, 4, 0, 35][..], 66, 10),
    ] {
        let mut peers = Vec::new();
        for id in [first_id, first_id + 1] {
            let (public, _) = session
                .generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &[
                        Attribute::Token(true),
                        Attribute::Id(vec![id]),
                        Attribute::EcParams(curve.to_vec()),
                    ],
                    &[
                        Attribute::Token(true),
                        Attribute::Id(vec![id]),
                        Attribute::Derive(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                    ],
                )
                .unwrap();
            let attributes = session
                .get_attributes(public, &[cryptoki::object::AttributeType::EcPoint])
                .unwrap();
            let encoded = attributes
                .into_iter()
                .find_map(|value| match value {
                    Attribute::EcPoint(value) => Some(value),
                    _ => None,
                })
                .unwrap();
            // P-521 uses a long-form DER length, unlike the smaller curves.
            let point = <&OctetStringRef>::from_der(&encoded).unwrap().as_bytes();
            assert_eq!(point.len(), 1 + 2 * width);
            assert_eq!(point[0], 4);
            peers.push(point.to_vec());
        }
        let a = provider.agreement_key(&[first_id]).unwrap();
        let b = provider.agreement_key(&[first_id + 1]).unwrap();
        let parameters_a = KeyAgreementParameters {
            algorithm: "http://www.w3.org/2009/xmlenc11#ECDH-ES",
            peer_public_key: &peers[1],
        };
        let parameters_b = KeyAgreementParameters {
            algorithm: parameters_a.algorithm,
            peer_public_key: &peers[0],
        };
        let secret = zeroize::Zeroizing::new(provider.agree_key(&a, &parameters_a).unwrap());
        assert_eq!(secret.len(), width);
        assert_eq!(*secret, provider.agree_key(&b, &parameters_b).unwrap());
        assert!(other.agree_key(&a, &parameters_a).is_err());
        // The valid mechanism must still reject invalid point framing before derivation.
        let malformed_peer = KeyAgreementParameters {
            algorithm: parameters_a.algorithm,
            peer_public_key: &[],
        };
        assert!(provider.agree_key(&a, &malformed_peer).is_err());
    }
    // A malformed peer never reaches token derivation.
    let parameters = KeyAgreementParameters {
        algorithm: "unsupported",
        peer_public_key: &[],
    };
    assert!(
        !provider.supports(xml_sec::provider::ProviderCapability::KeyAgreement(
            &parameters
        ))
    );
    // Stale object handles are token errors, not authentication failures or retries.
    let stale = provider.aes_key(&[2]).unwrap();
    let object = session.find_objects(&[Attribute::Id(vec![2])]).unwrap()[0];
    session.destroy_object(object).unwrap();
    assert!(matches!(
        provider.decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, &stale, &ciphertext),
        Err(ProviderError::External(ExternalProviderError::Object))
    ));
    // A binary ID is a selector, not a unique-key guarantee. Never choose the
    // first matching object when a token contains duplicate persistent IDs.
    for _ in 0..2 {
        session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(true),
                Attribute::Id(vec![9]),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Value(vec![0; 16]),
            ])
            .unwrap();
    }
    assert!(matches!(
        provider.aes_key(&[9]),
        Err(ProviderError::External(ExternalProviderError::Object))
    ));
    assert!(matches!(
        provider.aes_key(&[]),
        Err(ProviderError::External(ExternalProviderError::Object))
    ));
    // Raw CEKs use the same width validation and token content primitive.
    assert_eq!(
        provider
            .decrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &kek, &ciphertext)
            .unwrap(),
        message
    );
    assert!(matches!(
        provider.decrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &[0; 24], &ciphertext),
        Err(ProviderError::InvalidKeySize {
            expected: 16,
            actual: 24
        })
    ));
}
