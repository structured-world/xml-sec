#![cfg(feature = "aws-lc-fips")]

use xml_sec::provider::{
    AwsLcFipsProvider, CryptoProvider, ProviderCapability, RustCryptoProvider,
};
use xml_sec::xmldsig::DigestAlgorithm;

#[test]
fn rsa_verifier_size_limit_is_unsupported_not_signature_mismatch() {
    // A caller may allow 1024-bit RSA; native capability limits must still be
    // distinguished from a cryptographically incorrect signature in both APIs.
    use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    use xml_sec::provider::{ProviderError, X509SignatureAlgorithm};
    use xml_sec::xmldsig::{
        DsigError, RsaSigningKey, SignatureAlgorithm, SignatureVerificationError, SigningKey as _,
        VerificationKey,
    };
    let mut rng = ChaCha8Rng::seed_from_u64(17);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let spki = private.to_public_key().to_public_key_der().unwrap();
    let signer = RsaSigningKey::from_pkcs8_der(private.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let algorithm = SignatureAlgorithm::RsaSha256;
    let data = b"valid signature under a caller-permitted small key";
    let signature = signer.sign(algorithm, data).unwrap();
    let key = VerificationKey {
        algorithm,
        public_key_bytes: spki.as_bytes().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert!(
        RustCryptoProvider
            .verify(&key, algorithm, data, &signature)
            .unwrap()
    );
    assert!(matches!(
        AwsLcFipsProvider.verify(&key, algorithm, data, &signature),
        Err(DsigError::Crypto(
            SignatureVerificationError::UnsupportedAlgorithm { .. }
        ))
    ));
    assert!(matches!(
        AwsLcFipsProvider.verify_x509_signature(
            X509SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256),
            data,
            &signature,
            spki.as_bytes(),
        ),
        Err(ProviderError::Unsupported { .. })
    ));
    let mut signing_policy = xml_sec::policy::SigningPolicy::default();
    signing_policy.rsa_keys.minimum_modulus_bits = 1024;
    let signed = xml_sec::xmldsig::SignContext::new(&signer)
        .policy(signing_policy)
        .sign_template(include_str!("fixtures/saml/response_signing_template.xml"))
        .unwrap();
    let mut verification_policy = xml_sec::policy::VerificationPolicy::default();
    verification_policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    assert_eq!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(&key)
            .policy(verification_policy.clone())
            .verify(&signed)
            .unwrap()
            .status,
        xml_sec::xmldsig::DsigStatus::Valid
    );
    assert!(matches!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(&key)
            .policy(verification_policy)
            .provider(&AwsLcFipsProvider)
            .verify(&signed),
        Err(DsigError::Crypto(
            SignatureVerificationError::UnsupportedAlgorithm { .. }
        ))
    ));
}

#[test]
fn native_primitives_match_published_known_answers() {
    assert!(!AwsLcFipsProvider.module_version().is_empty());
    assert!(AwsLcFipsProvider.fips_module_version().is_some());
    // SHA-256("abc") anchors differential testing to a fixed known answer.
    assert_eq!(
        AwsLcFipsProvider
            .digest(DigestAlgorithm::Sha256, b"abc")
            .unwrap(),
        hex_literal::hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    #[cfg(feature = "xmlenc")]
    {
        // RFC 3394 §4.1: wrapping 128 key bits under a 128-bit KEK.
        let kek = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let plain = hex_literal::hex!("00112233445566778899aabbccddeeff");
        assert_eq!(
            AwsLcFipsProvider
                .wrap_key(xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128, &kek, &plain)
                .unwrap(),
            hex_literal::hex!("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
        );
    }
}

#[test]
fn native_certificate_verification_uses_der_and_detects_tampering() {
    // Certificates use DER ECDSA, not XMLDSig's raw r||s wire representation.
    use x509_parser::prelude::FromDer as _;
    use xml_sec::provider::X509SignatureAlgorithm as A;
    for (pem, algorithm) in [
        (
            include_str!("fixtures/keys/rsa/rsa-2048-key.pem"),
            A::RsaPkcs1v15(DigestAlgorithm::Sha256),
        ),
        (
            include_str!("fixtures/keys/ec/ec-prime256v1-key.pem"),
            A::Ecdsa(DigestAlgorithm::Sha256),
        ),
    ] {
        let key = rcgen::KeyPair::from_pem(pem).unwrap();
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.der()).unwrap();
        let data = parsed.tbs_certificate.as_ref();
        let sig = parsed.signature_value.data.as_ref();
        let spki = parsed.public_key().raw;
        assert!(
            AwsLcFipsProvider
                .verify_x509_signature(algorithm, data, sig, spki)
                .unwrap()
        );
        assert!(
            RustCryptoProvider
                .verify_x509_signature(algorithm, data, sig, spki)
                .unwrap()
        );
        let mut corrupt = sig.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            !AwsLcFipsProvider
                .verify_x509_signature(algorithm, data, &corrupt, spki)
                .unwrap()
        );
    }
}

#[test]
fn inventory_imports_native_handles_without_bypassing_authorization() {
    // Provider selection must preserve usage, method and strength policy gates.
    use xml_sec::key_manager::{KeyInventory, KeyUsages};
    use xml_sec::policy::{ResourcePolicy, SigningPolicy};
    use xml_sec::xmldsig::SignatureAlgorithm as A;
    let pem = pem::parse(include_bytes!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let mut inventory = KeyInventory::default();
    inventory
        .add_private_der(
            "signer".into(),
            pem.contents(),
            None,
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        )
        .unwrap();
    let key = inventory
        .signing_key_with_provider(
            "signer",
            A::RsaSha256,
            &SigningPolicy::default(),
            &AwsLcFipsProvider,
        )
        .unwrap();
    assert_eq!(key.provider_name(), Some("aws-lc-fips"));
    assert!(
        inventory
            .signing_key_with_provider(
                "absent",
                A::RsaSha256,
                &SigningPolicy::default(),
                &AwsLcFipsProvider
            )
            .is_err()
    );
    assert!(
        inventory
            .signing_key_with_provider(
                "signer",
                A::DsaSha256,
                &SigningPolicy::default(),
                &AwsLcFipsProvider
            )
            .is_err()
    );
    let denied = SigningPolicy {
        signature_algorithms: Some(std::collections::HashSet::new()),
        ..SigningPolicy::default()
    };
    assert!(
        inventory
            .signing_key_with_provider("signer", A::RsaSha256, &denied, &AwsLcFipsProvider)
            .is_err()
    );
    #[cfg(feature = "xmlenc")]
    assert!(
        inventory
            .decryption_resolver_with_provider(
                "signer",
                &xml_sec::policy::DecryptionPolicy::default(),
                &AwsLcFipsProvider
            )
            .is_err()
    );
}

#[test]
fn aws_digests_match_rustcrypto() {
    // Independent engines must produce the same XMLDSig digest octets.
    let aws = AwsLcFipsProvider;
    for algorithm in [
        DigestAlgorithm::Sha1,
        DigestAlgorithm::Sha224,
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
        DigestAlgorithm::Sha3_256,
        DigestAlgorithm::Sha3_384,
        DigestAlgorithm::Sha3_512,
    ] {
        assert!(aws.supports(ProviderCapability::Digest(algorithm)));
        assert_eq!(
            aws.digest(algorithm, b"abc").unwrap(),
            RustCryptoProvider.digest(algorithm, b"abc").unwrap()
        );
    }
}

#[test]
fn xml_signatures_interoperate_through_selected_provider() {
    // Exercise the complete reference/mutation/signature pipeline in both directions;
    // a changed assertion must fail the digest gate rather than still verify.
    use xml_sec::provider::AwsLcSigningKey;
    use xml_sec::xmldsig::{
        DsigStatus, RsaSigningKey, SignContext, SignatureAlgorithm, SigningKey, VerificationKey,
        VerifyContext,
    };
    let key_pem = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
    let pem = pem::parse(key_pem).unwrap();
    let algorithm = SignatureAlgorithm::RsaSha256;
    let native = AwsLcSigningKey::from_pkcs8_der(algorithm, pem.contents()).unwrap();
    let rust = RsaSigningKey::from_pkcs8_pem(key_pem).unwrap();
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: native
            .public_key_info()
            .unwrap()
            .spki_der()
            .unwrap()
            .to_vec(),
        certificate_der: None,
        name: None,
    };
    let template = include_str!("fixtures/saml/response_signing_template.xml");
    for (key, signer) in [
        (
            &native as &dyn SigningKey,
            &AwsLcFipsProvider as &dyn CryptoProvider,
        ),
        (
            &rust as &dyn SigningKey,
            &RustCryptoProvider as &dyn CryptoProvider,
        ),
    ] {
        let signed = SignContext::new(key)
            .provider(signer)
            .sign_template(template)
            .unwrap();
        for provider in [
            &AwsLcFipsProvider as &dyn CryptoProvider,
            &RustCryptoProvider as &dyn CryptoProvider,
        ] {
            let result = VerifyContext::new()
                .provider(provider)
                .key(&verifier)
                .verify(&signed)
                .unwrap();
            assert_eq!(result.status, DsigStatus::Valid);
            let tampered = signed.replacen("administrator", "attacker", 1);
            assert_ne!(signed, tampered);
            let result = VerifyContext::new()
                .provider(provider)
                .key(&verifier)
                .verify(&tampered)
                .unwrap();
            assert_ne!(result.status, DsigStatus::Valid);
        }
    }
}

#[test]
fn unsupported_digest_never_falls_back() {
    // An absent AWS mechanism cannot silently run in the other engine.
    let algorithm = DigestAlgorithm::Sha3_224;
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::Digest(algorithm)));
    assert!(AwsLcFipsProvider.digest(algorithm, b"abc").is_err());
}

#[test]
fn native_ecdsa_keys_interoperate_and_reject_method_mismatch() {
    // Native import and fixed-width XMLDSig signatures must work for all three curves.
    use pkcs8::EncodePrivateKey as _;
    use xml_sec::provider::AwsLcSigningKey;
    use xml_sec::xmldsig::{SignatureAlgorithm as A, SigningKey, VerificationKey};
    let keys = [
        (
            A::EcdsaSha256,
            p256::SecretKey::from_slice(&[1; 32])
                .unwrap()
                .to_pkcs8_der()
                .unwrap(),
        ),
        (
            A::EcdsaSha384,
            p384::SecretKey::from_slice(&[1; 48])
                .unwrap()
                .to_pkcs8_der()
                .unwrap(),
        ),
        (
            A::EcdsaSha512,
            p521::SecretKey::from_slice(&[1; 66])
                .unwrap()
                .to_pkcs8_der()
                .unwrap(),
        ),
    ];
    for (algorithm, der) in keys {
        let key = AwsLcSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
        let verifier = VerificationKey {
            algorithm,
            public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
            certificate_der: None,
            name: None,
        };
        let signature = AwsLcFipsProvider
            .sign(&key, algorithm, b"curve test")
            .unwrap();
        assert!(
            AwsLcFipsProvider
                .verify(&verifier, algorithm, b"curve test", &signature)
                .unwrap()
        );
        assert!(
            RustCryptoProvider
                .verify(&verifier, algorithm, b"curve test", &signature)
                .unwrap()
        );
        assert!(
            !AwsLcFipsProvider
                .verify(&verifier, algorithm, b"wrong", &signature)
                .unwrap()
        );
        assert!(
            AwsLcFipsProvider
                .sign(&key, A::RsaSha256, b"curve test")
                .is_err()
        );
        assert!(
            AwsLcFipsProvider
                .verify(&verifier, A::RsaSha256, b"curve test", &signature)
                .is_err()
        );
    }
    assert!(AwsLcSigningKey::from_pkcs8_der(A::EcdsaSha256, b"invalid DER").is_err());
}

#[test]
fn native_rsa_signing_and_backend_binding() {
    // Native private handles cannot silently execute through RustCrypto.
    use xml_sec::provider::AwsLcSigningKey;
    use xml_sec::xmldsig::{SignatureAlgorithm, SigningKey};
    let pem = pem::parse(include_bytes!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let algorithm = SignatureAlgorithm::RsaSha256;
    let key = AwsLcSigningKey::from_pkcs8_der(algorithm, pem.contents()).unwrap();
    let signature = AwsLcFipsProvider.sign(&key, algorithm, b"message").unwrap();
    assert!(!signature.is_empty());
    assert!(
        RustCryptoProvider
            .sign(&key, algorithm, b"message")
            .is_err()
    );
    let info = key.public_key_info().unwrap();
    let verifier = xml_sec::xmldsig::VerificationKey {
        algorithm,
        public_key_bytes: info.spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert!(
        AwsLcFipsProvider
            .verify(&verifier, algorithm, b"message", &signature)
            .unwrap()
    );
    assert!(
        RustCryptoProvider
            .verify(&verifier, algorithm, b"message", &signature)
            .unwrap()
    );
    assert!(
        !AwsLcFipsProvider
            .verify(&verifier, algorithm, b"tampered", &signature)
            .unwrap()
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn rsa_recipient_xml_pipeline_interoperates_with_native_recovery() {
    // Exercise session-key generation, RSA transport, KeyInfo parsing and native recovery.
    use rsa::pkcs8::DecodePrivateKey as _;
    use std::sync::Arc;
    use xml_sec::provider::AwsLcRsaPrivateKey;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptionRecipient, PrivateKeyDecryptor,
    };
    let pem = pem::parse(include_bytes!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let rust = rsa::RsaPrivateKey::from_pkcs8_der(pem.contents()).unwrap();
    let public = rust.to_public_key();
    let native = PrivateKeyDecryptor::provider_key(Arc::new(
        AwsLcRsaPrivateKey::from_pkcs8_der(pem.contents()).unwrap(),
    ));
    let rust = PrivateKeyDecryptor::new(rust);
    for encryptor in [
        Arc::new(AwsLcFipsProvider) as Arc<dyn CryptoProvider>,
        Arc::new(RustCryptoProvider) as Arc<dyn CryptoProvider>,
    ] {
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
            .provider(encryptor)
            .add_recipient(EncryptionRecipient::rsa_oaep(public.clone()))
            .encrypt_binary(b"transported payload")
            .unwrap();
        for (resolver, provider) in [
            (
                &native as &dyn DecryptionKeyResolver,
                &AwsLcFipsProvider as &dyn CryptoProvider,
            ),
            (
                &rust as &dyn DecryptionKeyResolver,
                &RustCryptoProvider as &dyn CryptoProvider,
            ),
        ] {
            assert_eq!(
                DecryptContext::new(resolver)
                    .provider(provider)
                    .decrypt(&encrypted.encrypted_data_xml)
                    .unwrap(),
                DecryptedContent::Bytes(b"transported payload".to_vec())
            );
        }
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn xml_encryption_uses_the_selected_provider_end_to_end() {
    // XML serialization and parsing must preserve native ciphertext framing in both directions.
    use std::sync::Arc;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm as A, DecryptContext, DecryptedContent, EncryptedDataBuilder,
        SymmetricKeyDecryptor,
    };
    for algorithm in [A::Aes128Cbc, A::Aes256Gcm] {
        let key = vec![9; algorithm.key_len()];
        let resolver = SymmetricKeyDecryptor::new(key.clone());
        for provider in [
            Arc::new(AwsLcFipsProvider) as Arc<dyn CryptoProvider>,
            Arc::new(RustCryptoProvider) as Arc<dyn CryptoProvider>,
        ] {
            let encrypted = EncryptedDataBuilder::new(algorithm)
                .provider(provider)
                .direct_key(key.clone())
                .encrypt_binary(b"binary\0payload")
                .unwrap();
            for decryptor in [
                &AwsLcFipsProvider as &dyn CryptoProvider,
                &RustCryptoProvider as &dyn CryptoProvider,
            ] {
                let result = DecryptContext::new(&resolver)
                    .provider(decryptor)
                    .decrypt(&encrypted.encrypted_data_xml)
                    .unwrap();
                assert_eq!(result, DecryptedContent::Bytes(b"binary\0payload".to_vec()));
            }
            let wrong_key = SymmetricKeyDecryptor::new(vec![0; algorithm.key_len()]);
            if algorithm == A::Aes256Gcm {
                assert!(
                    DecryptContext::new(&wrong_key)
                        .provider(&AwsLcFipsProvider)
                        .decrypt(&encrypted.encrypted_data_xml)
                        .is_err()
                );
            }
        }
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn encryption_engines_interoperate_and_reject_tampering() {
    // Shared XML framing must interoperate in both directions, including empty content.
    use xml_sec::xmlenc::DataEncryptionAlgorithm as A;
    for algorithm in [A::Aes128Cbc, A::Aes256Cbc, A::Aes128Gcm, A::Aes256Gcm] {
        let key = vec![7; algorithm.key_len()];
        for data in [&b""[..], &b"message"[..], &[42; 32][..]] {
            let aws = AwsLcFipsProvider
                .encrypt_data(algorithm, &key, data)
                .unwrap();
            assert_eq!(
                RustCryptoProvider
                    .decrypt_data(algorithm, &key, &aws)
                    .unwrap(),
                data
            );
            let rust = RustCryptoProvider
                .encrypt_data(algorithm, &key, data)
                .unwrap();
            assert_eq!(
                AwsLcFipsProvider
                    .decrypt_data(algorithm, &key, &rust)
                    .unwrap(),
                data
            );
            assert!(
                AwsLcFipsProvider
                    .decrypt_data(algorithm, &key[..key.len() - 1], &rust)
                    .is_err()
            );
            assert!(
                AwsLcFipsProvider
                    .decrypt_data(algorithm, &key, &rust[..1])
                    .is_err()
            );
            if matches!(algorithm, A::Aes128Gcm | A::Aes256Gcm) {
                let mut tampered = aws;
                let last = tampered.len() - 1;
                tampered[last] ^= 1;
                assert!(
                    AwsLcFipsProvider
                        .decrypt_data(algorithm, &key, &tampered)
                        .is_err()
                );
            }
        }
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn key_wrap_engines_match_and_reject_invalid_input() {
    // RFC 3394 is deterministic; identical bytes prove framing and integrity interoperability.
    use xml_sec::xmlenc::KeyWrapAlgorithm as A;
    for algorithm in [A::AesKw128, A::AesKw256] {
        let kek = vec![8; algorithm.key_len()];
        let key = [3; 32];
        let wrapped = AwsLcFipsProvider.wrap_key(algorithm, &kek, &key).unwrap();
        assert_eq!(
            wrapped,
            RustCryptoProvider.wrap_key(algorithm, &kek, &key).unwrap()
        );
        assert_eq!(
            AwsLcFipsProvider
                .unwrap_key(algorithm, &kek, &wrapped)
                .unwrap(),
            key
        );
        let mut tampered = wrapped;
        tampered[0] ^= 1;
        assert!(
            AwsLcFipsProvider
                .unwrap_key(algorithm, &kek, &tampered)
                .is_err()
        );
        assert!(
            AwsLcFipsProvider
                .wrap_key(algorithm, &kek, &[0; 8])
                .is_err()
        );
        assert!(
            AwsLcFipsProvider
                .unwrap_key(algorithm, &kek, &[0; 16])
                .is_err()
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn native_oaep_interoperates_and_rejects_wrong_label() {
    // Labels and MGF parameters must not be ignored or silently handled by another engine.
    use rsa::pkcs8::DecodePrivateKey as _;
    use xml_sec::provider::{AwsLcRsaPrivateKey, RustCryptoRsaPrivateKey, RustCryptoRsaPublicKey};
    use xml_sec::xmlenc::{OaepDigestAlgorithm as D, RsaOaepParameters};
    let pem = pem::parse(include_bytes!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let key = rsa::RsaPrivateKey::from_pkcs8_der(pem.contents()).unwrap();
    let public = RustCryptoRsaPublicKey::new(key.to_public_key());
    let rust = RustCryptoRsaPrivateKey::new(key);
    let aws = AwsLcRsaPrivateKey::from_pkcs8_der(pem.contents()).unwrap();
    for digest in [D::Sha1, D::Sha256, D::Sha384, D::Sha512] {
        let params = RsaOaepParameters::xmlenc11(digest, digest).label(b"label".to_vec());
        let ciphertext = AwsLcFipsProvider
            .transport_key(&public, &params, b"secret")
            .unwrap();
        assert_eq!(
            RustCryptoProvider
                .recover_key(&rust, &params, &ciphertext)
                .unwrap(),
            b"secret"
        );
        let ciphertext = RustCryptoProvider
            .transport_key(&public, &params, b"secret")
            .unwrap();
        assert_eq!(
            AwsLcFipsProvider
                .recover_key(&aws, &params, &ciphertext)
                .unwrap(),
            b"secret"
        );
        assert!(
            AwsLcFipsProvider
                .recover_key(&aws, &params.clone().label(b"wrong".to_vec()), &ciphertext)
                .is_err()
        );
        assert!(
            RustCryptoProvider
                .recover_key(&aws, &params, &ciphertext)
                .is_err()
        );
        assert!(
            AwsLcFipsProvider
                .recover_key(&rust, &params, &ciphertext)
                .is_err()
        );
    }
    let params = RsaOaepParameters::xmlenc11(D::Sha256, D::Sha1);
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::KeyTransport(&params)));
    assert!(
        AwsLcFipsProvider
            .transport_key(&public, &params, b"secret")
            .is_err()
    );
}
