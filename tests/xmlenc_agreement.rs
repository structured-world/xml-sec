#![cfg(feature = "xmlenc")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
use xml_sec::provider::{CryptoProvider, EcdhCurve, RUST_CRYPTO_PROVIDER, RustCryptoEcdhKey};
use xml_sec::xmlenc::{
    AgreementDecryptor, AgreementMethod, DataEncryptionAlgorithm, DecryptContext, DecryptedContent,
    EncryptedDataBuilder, KeyEstablishmentBudget, SymmetricKeyDecryptor, parse_encrypted_data,
    parse_key_derivation_method,
};

fn method() -> xml_sec::xmlenc::KeyDerivationMethod {
    parse_key_derivation_method(
        r#"<x:KeyDerivationMethod xmlns:x="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF"><x:ConcatKDFParams AlgorithmID="00636970686572" PartyUInfo="00616c696365" PartyVInfo="00626f62"><d:DigestMethod xmlns:d="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></x:ConcatKDFParams></x:KeyDerivationMethod>"#,
        &DecryptionPolicy::default(),
    ).unwrap()
}

fn expected() -> AgreementMethod {
    AgreementMethod {
        algorithm: KeyAgreementAlgorithm::EcdhEs,
        method: Some(method()),
        nonce: Vec::new(),
        legacy_digest: None,
        originator: None,
        recipient: None,
    }
}

#[test]
fn x448_public_encryption_and_decryption_obey_typed_permission() {
    use std::collections::HashSet;
    use xml_sec::provider::RustCryptoX448Key;
    // The actual XML pipeline must preserve X448 identity, enforce permission
    // on both operations, and authenticate the result with AES-GCM.
    let sender = RustCryptoX448Key::from_bytes([3; 56]);
    let recipient = RustCryptoX448Key::from_bytes([5; 56]);
    let sender_public = sender.public_key();
    let mut encryption = xml_sec::policy::EncryptionPolicy::default();
    encryption.key_establishment.agreement_algorithms =
        Some(HashSet::from([KeyAgreementAlgorithm::X448]));
    let wire = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .agreement_key(
            method(),
            Box::new(sender),
            KeyAgreementAlgorithm::X448,
            recipient.public_key().to_vec(),
        )
        .policy(encryption)
        .encrypt_binary(b"X448 public pipeline")
        .unwrap();
    let descriptor = AgreementMethod {
        algorithm: KeyAgreementAlgorithm::X448,
        ..expected()
    };
    assert_eq!(
        parse_encrypted_data(&wire.encrypted_data_xml)
            .unwrap()
            .agreement_methods,
        vec![descriptor.clone()]
    );
    let resolver = AgreementDecryptor::content(
        &descriptor,
        &recipient,
        &sender_public,
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert!(matches!(
        DecryptContext::new(&resolver).decrypt(&wire.encrypted_data_xml),
        Err(xml_sec::xmlenc::XmlEncError::Policy(_))
    ));
    let mut decryption = DecryptionPolicy::default();
    decryption.key_establishment.agreement_algorithms =
        Some(HashSet::from([KeyAgreementAlgorithm::X448]));
    assert_eq!(
        DecryptContext::new(&resolver)
            .policy(decryption)
            .decrypt(&wire.encrypted_data_xml)
            .unwrap(),
        DecryptedContent::Bytes(b"X448 public pipeline".to_vec())
    );
}

#[test]
fn ecdh_sender_is_single_use_across_builder_clones() {
    // A new ciphertext is a new message, even through a cloned builder;
    // XMLEnc ECDH-ES must not reuse its originator private key.
    let sender = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[3; 32]).unwrap();
    let recipient = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[5; 32]).unwrap();
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).agreement_key(
        method(),
        Box::new(sender),
        KeyAgreementAlgorithm::EcdhEs,
        recipient.public_key(),
    );
    let clone = builder.clone();
    assert!(builder.encrypt_binary(b"first message").is_ok());
    assert!(builder.encrypt_binary(b"second message").is_err());
    assert!(clone.encrypt_binary(b"cloned message").is_err());
}

#[test]
fn ecdh_preflight_rejection_does_not_consume_the_sender() {
    // Policy/resource rejection precedes any key execution; a corrected
    // request may still use the pair, but successful dispatch consumes it.
    let sender = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[3; 32]).unwrap();
    let recipient = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[5; 32]).unwrap();
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).agreement_key(
        method(),
        Box::new(sender),
        KeyAgreementAlgorithm::EcdhEs,
        recipient.public_key(),
    );
    let mut policy = xml_sec::policy::EncryptionPolicy::default();
    policy.key_establishment.agreement_algorithms = Some(Default::default());
    assert!(
        builder
            .clone()
            .policy(policy)
            .encrypt_binary(b"denied")
            .is_err()
    );
    let mut policy = xml_sec::policy::EncryptionPolicy::default();
    policy.key_establishment.max_owned_bytes = 0;
    assert!(
        builder
            .clone()
            .policy(policy)
            .encrypt_binary(b"exhausted")
            .is_err()
    );
    assert!(builder.encrypt_binary(b"permitted").is_ok());
}

#[test]
fn ecdh_failed_dispatch_consumes_the_sender() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use xml_sec::provider::{KeyAgreementKey, KeyAgreementParameters, ProviderError};
    struct FailingKey(Arc<AtomicUsize>);
    impl KeyAgreementKey for FailingKey {
        fn agree(&self, _: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(ProviderError::AuthenticationFailed)
        }
    }
    // A failure after dispatch is not permission to repeat the same scalar
    // multiplication. Concurrent clones must attempt the primitive only once.
    let calls = Arc::new(AtomicUsize::new(0));
    let recipient = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[5; 32]).unwrap();
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).agreement_key(
        method(),
        Box::new(FailingKey(calls.clone())),
        KeyAgreementAlgorithm::EcdhEs,
        recipient.public_key(),
    );
    let clone = builder.clone();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| builder.encrypt_binary(b"first"));
        let second = scope.spawn(|| clone.encrypt_binary(b"second"));
        assert!(first.join().unwrap().is_err());
        assert!(second.join().unwrap().is_err());
    });
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn dh_agreement_roles_require_complete_parameter_groups() {
    // XMLEnc 1.1 §5.6.1 permits application-supplied domain parameters,
    // but never a partial P/Q/Generator or seed/pgenCounter sequence.
    for parameters in [
        "",
        "<x:P>Fw==</x:P><x:Q>Cw==</x:Q><x:Generator>Ag==</x:Generator>",
    ] {
        let wire = format!(
            "<x:EncryptedData xmlns:x='http://www.w3.org/2001/04/xmlenc#' xmlns:d='http://www.w3.org/2000/09/xmldsig#'><x:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/><d:KeyInfo><x:AgreementMethod Algorithm='http://www.w3.org/2009/xmlenc11#dh-es'><x:OriginatorKeyInfo><d:KeyValue><x:DHKeyValue>{parameters}<x:Public>CA==</x:Public></x:DHKeyValue></d:KeyValue></x:OriginatorKeyInfo></x:AgreementMethod></d:KeyInfo><x:CipherData><x:CipherValue>AQ==</x:CipherValue></x:CipherData></x:EncryptedData>"
        );
        let parsed = parse_encrypted_data(&wire).unwrap();
        let role = parsed.agreement_methods[0].originator.as_ref().unwrap();
        let xml_sec::xmldsig::parse::KeyInfoSource::KeyValue(
            xml_sec::xmldsig::parse::KeyValueInfo::Dh {
                p,
                q,
                generator,
                public,
                seed,
                pgen_counter,
            },
        ) = &role.sources[0]
        else {
            panic!("DH role was not preserved: {role:?}")
        };
        assert_eq!(public, &[8]);
        if parameters.is_empty() {
            assert_eq!((p, q, generator), (&None, &None, &None));
        } else {
            assert_eq!(p.as_deref(), Some([23].as_slice()));
            assert_eq!(q.as_deref(), Some([11].as_slice()));
            assert_eq!(generator.as_deref(), Some([2].as_slice()));
        }
        assert_eq!((seed, pgen_counter), (&None, &None));
        for bad in [
            "<x:P>Fw==</x:P>",
            "<x:Q>Cw==</x:Q>",
            "<x:Generator>Ag==</x:Generator>",
        ] {
            assert!(
                parse_encrypted_data(&wire.replace(
                    &format!("{parameters}<x:Public>"),
                    &format!("{bad}<x:Public>")
                ))
                .is_err()
            );
        }
        if !parameters.is_empty() {
            for suffix in [
                "<x:seed>AQ==</x:seed>",
                "<x:pgenCounter>AQ==</x:pgenCounter>",
            ] {
                assert!(
                    parse_encrypted_data(
                        &wire.replace("</x:Public>", &format!("</x:Public>{suffix}"))
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn agreement_role_metadata_obeys_encryption_policy_before_retention() {
    // Role KeyName is encryption metadata too; the shared XMLDSig parser's
    // larger safety ceiling must not override this operation's tighter policy.
    let (wire, _, _) = encrypted();
    let wire = wire.replace("</xenc:AgreementMethod>", &format!("<xenc:OriginatorKeyInfo><ds:KeyName>{}</ds:KeyName></xenc:OriginatorKeyInfo></xenc:AgreementMethod>", "k".repeat(81)));
    let mut policy = DecryptionPolicy::default();
    policy.resources.max_encryption_metadata_bytes = 80;
    assert!(matches!(
        DecryptContext::new(&SymmetricKeyDecryptor::new(vec![0; 16]))
            .policy(policy)
            .decrypt(&wire),
        Err(xml_sec::xmlenc::XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "encryption metadata bytes",
                ..
            }
        ))
    ));
}

#[test]
fn agreement_roles_share_the_candidate_allowance_with_their_descriptor() {
    // A descriptor plus its embedded public key costs two candidates, not two
    // independent allowances. Failure precedes decoding the malformed key.
    let (wire, _, _) = encrypted();
    let wire = wire.replace("</xenc:AgreementMethod>", "<xenc:OriginatorKeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>invalid</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></xenc:OriginatorKeyInfo></xenc:AgreementMethod>");
    let mut policy = DecryptionPolicy::default();
    policy.resources.max_key_candidates = 1;
    assert!(matches!(
        DecryptContext::new(&SymmetricKeyDecryptor::new(vec![0; 16]))
            .policy(policy)
            .decrypt(&wire),
        Err(xml_sec::xmlenc::XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                maximum: 1,
                actual: 2,
                ..
            }
        ))
    ));
}

fn encrypted() -> (String, RustCryptoEcdhKey, Vec<u8>) {
    let sender = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[3; 32]).unwrap();
    let recipient = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[5; 32]).unwrap();
    let descriptor = expected();
    let policy = DecryptionPolicy::default();
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    let key = descriptor
        .derive_key(
            DataEncryptionAlgorithm::Aes128Gcm.uri(),
            16,
            &sender,
            &recipient.public_key(),
            &RUST_CRYPTO_PROVIDER,
            &mut budget,
        )
        .unwrap();
    let wire = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key.to_vec())
        .encrypt_binary(b"agreement XML pipeline")
        .unwrap();
    let agreement = format!(
        "<ds:KeyInfo><xenc:AgreementMethod Algorithm=\"{}\">mixed text{}<!-- permitted trivia --></xenc:AgreementMethod></ds:KeyInfo>",
        descriptor.algorithm.uri(),
        descriptor
            .method
            .as_ref()
            .unwrap()
            .to_xml(&policy.resources)
            .unwrap(),
    );
    (
        wire.encrypted_data_xml.replace(
            "<xenc:CipherData>",
            &format!("{agreement}<xenc:CipherData>"),
        ),
        recipient,
        sender.public_key(),
    )
}

#[test]
fn xml_agreement_gates_content_key_and_preserves_mixed_content() {
    // Optional parties can be application-bound; transported agreement still
    // prevents a raw key resolver from bypassing the required derivation.
    let (wire, recipient, peer) = encrypted();
    let descriptor = expected();
    let parsed = parse_encrypted_data(&wire).unwrap();
    assert_eq!(parsed.agreement_methods, vec![descriptor.clone()]);
    let resolver = AgreementDecryptor::content(
        &descriptor,
        &recipient,
        &peer,
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert_eq!(
        DecryptContext::new(&resolver).decrypt(&wire).unwrap(),
        DecryptedContent::Bytes(b"agreement XML pipeline".to_vec())
    );
    assert!(
        DecryptContext::new(&SymmetricKeyDecryptor::new(vec![0; 16]))
            .decrypt(&wire)
            .is_err()
    );
}

#[test]
fn xml_agreement_rejects_party_substitution_and_shared_budget_exhaustion() {
    // Even structurally valid changed KDF party information is not a trusted
    // expectation; candidate and provider work share one operation budget.
    let (wire, recipient, peer) = encrypted();
    let descriptor = expected();
    let resolver = AgreementDecryptor::content(
        &descriptor,
        &recipient,
        &peer,
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert!(
        DecryptContext::new(&resolver)
            .decrypt(&wire.replace("00626F62", "00657665"))
            .is_err()
    );
    let mut policy = DecryptionPolicy::default();
    policy.resources.max_key_candidates = 1;
    assert!(
        DecryptContext::new(&resolver)
            .policy(policy)
            .decrypt(&wire)
            .is_err()
    );
}

#[test]
fn xml_agreement_rejects_unordered_or_duplicate_wire_parameters() {
    // AgreementMethod's optional schema fields still have an exact sequence.
    let (wire, _, _) = encrypted();
    for extra in [
        "<xenc:KA-Nonce>AA==</xenc:KA-Nonce>",
        "<xenc:RecipientKeyInfo/><xenc:OriginatorKeyInfo/>",
        "<xenc:RecipientKeyInfo/><xenc:RecipientKeyInfo/>",
    ] {
        let invalid = wire.replace(
            "</xenc:AgreementMethod>",
            &format!("{extra}</xenc:AgreementMethod>"),
        );
        assert!(parse_encrypted_data(&invalid).is_err());
    }
}

#[test]
fn xml_recipient_agreement_derives_a_kek_before_unwrapping_content() {
    // Same-width content and wrapping keys are not interchangeable purposes.
    // The XML descriptor must gate agreement, KDF, and final unwrap together.
    let sender = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[3; 32]).unwrap();
    let recipient = RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &[5; 32]).unwrap();
    let descriptor = expected();
    let policy = DecryptionPolicy::default();
    let wrap = xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128;
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    let kek = descriptor
        .derive_key(
            wrap.uri(),
            wrap.key_len(),
            &sender,
            &recipient.public_key(),
            &RUST_CRYPTO_PROVIDER,
            &mut budget,
        )
        .unwrap();
    let content = [3; 16];
    let wrapped = RUST_CRYPTO_PROVIDER.wrap_key(wrap, &kek, &content).unwrap();
    let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content)
        .encrypt_binary(b"agreement recipient")
        .unwrap();
    let key_info = format!(
        "<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm='{}'/><ds:KeyInfo><xenc:AgreementMethod Algorithm='{}'>{}</xenc:AgreementMethod></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>",
        wrap.uri(),
        descriptor.algorithm.uri(),
        descriptor
            .method
            .as_ref()
            .unwrap()
            .to_xml(&policy.resources)
            .unwrap(),
        STANDARD.encode(wrapped)
    );
    let wire = generated.encrypted_data_xml.replacen(
        "<xenc:CipherData>",
        &format!("{key_info}<xenc:CipherData>"),
        1,
    );
    let peer = sender.public_key();
    let resolver = AgreementDecryptor::wrapping(&descriptor, &recipient, &peer, wrap);
    assert_eq!(
        DecryptContext::new(&resolver).decrypt(&wire).unwrap(),
        DecryptedContent::Bytes(b"agreement recipient".to_vec())
    );
    assert!(
        DecryptContext::new(&xml_sec::xmlenc::KekDecryptor::new(kek.to_vec()))
            .decrypt(&wire)
            .is_err()
    );
    let mut limited = policy;
    limited.resources.max_key_candidates = 2;
    assert!(matches!(
        DecryptContext::new(&resolver)
            .policy(limited)
            .decrypt(&wire),
        Err(xml_sec::xmlenc::XmlEncError::Policy(_))
    ));
}
