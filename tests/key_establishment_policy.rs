#![cfg(feature = "xmlenc")]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use xml_sec::policy::{KeyAgreementAlgorithm, KeyDerivationAlgorithm, KeyEstablishmentPolicy};
use xml_sec::provider::{
    CryptoProvider, KdfContext, KdfParameters, ProviderCapability, ProviderError,
    RUST_CRYPTO_PROVIDER,
};
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
use xml_sec::xmlenc::{DerivedKeyInput, KeyEstablishmentBudget, XmlEncError};

struct RecordingProvider {
    calls: AtomicUsize,
    fail: AtomicBool,
    wrong_width: AtomicBool,
    unavailable: AtomicBool,
}

impl RecordingProvider {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            wrong_width: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
        }
    }
}

impl CryptoProvider for RecordingProvider {
    fn encrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.encrypt_data(algorithm, key, bytes)
    }
    fn decrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.decrypt_data(algorithm, key, bytes)
    }
    fn wrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.wrap_key(algorithm, key, bytes)
    }
    fn unwrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, key, bytes)
    }
    fn transport_key(
        &self,
        key: &dyn xml_sec::provider::KeyTransportKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.transport_key(key, parameters, bytes)
    }
    fn recover_key(
        &self,
        key: &dyn xml_sec::provider::KeyRecoveryKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.recover_key(key, parameters, bytes)
    }
    fn name(&self) -> &'static str {
        "recording-kdf"
    }
    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        !self.unavailable.load(Ordering::Relaxed) && RUST_CRYPTO_PROVIDER.supports(capability)
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), ProviderError> {
        RUST_CRYPTO_PROVIDER.fill_random(bytes)
    }
    fn digest(&self, algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>, ProviderError> {
        RUST_CRYPTO_PROVIDER.digest(algorithm, bytes)
    }
    fn sign(
        &self,
        key: &dyn xml_sec::xmldsig::SigningKey,
        algorithm: SignatureAlgorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
        RUST_CRYPTO_PROVIDER.sign(key, algorithm, bytes)
    }
    fn verify(
        &self,
        key: &dyn xml_sec::xmldsig::VerifyingKey,
        algorithm: SignatureAlgorithm,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, xml_sec::xmldsig::DsigError> {
        RUST_CRYPTO_PROVIDER.verify(key, algorithm, bytes, signature)
    }
    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(ProviderError::AuthenticationFailed);
        }
        let mut key = RUST_CRYPTO_PROVIDER.derive_key(parameters, secret)?;
        if self.wrong_width.load(Ordering::Relaxed) {
            key.pop();
        }
        Ok(key)
    }
}

fn parameters() -> KdfParameters<'static> {
    KdfParameters {
        algorithm: KeyDerivationAlgorithm::Pbkdf2.uri(),
        digest: Some(SignatureAlgorithm::HmacSha256.uri()),
        salt: b"salt",
        info: KdfContext::Octets(&[]),
        iterations: 2,
        output_len: 16,
    }
}

#[test]
fn unavailable_selected_provider_never_falls_back_to_software() {
    // Supported software primitives must not satisfy a request denied by the
    // selected engine, even when an opaque key could compute the agreement.
    struct ForbiddenKey;
    impl xml_sec::provider::KeyAgreementKey for ForbiddenKey {
        fn agree(
            &self,
            _: &xml_sec::provider::KeyAgreementParameters<'_>,
        ) -> Result<Vec<u8>, ProviderError> {
            panic!("agreement ran despite unavailable provider capability")
        }
    }
    let provider = RecordingProvider::new();
    provider.unavailable.store(true, Ordering::Relaxed);
    let policy = KeyEstablishmentPolicy::default();
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        budget
            .derive_key(&provider, &parameters(), b"secret")
            .is_err()
    );
    assert!(
        budget
            .agree_and_derive(
                &provider,
                &ForbiddenKey,
                &xml_sec::provider::KeyAgreementParameters {
                    algorithm: KeyAgreementAlgorithm::EcdhEs.uri(),
                    peer_public_key: &[4; 65]
                },
                &parameters()
            )
            .is_err()
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

fn xml_method(policy: &xml_sec::policy::DecryptionPolicy) -> xml_sec::xmlenc::KeyDerivationMethod {
    xml_sec::xmlenc::parse_key_derivation_method(
        "<KeyDerivationMethod xmlns='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2009/xmlenc11#pbkdf2'><PBKDF2-params><Salt><Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount><KeyLength>16</KeyLength><PRF Algorithm='http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'/></PBKDF2-params></KeyDerivationMethod>",
        policy,
    ).unwrap()
}

#[test]
fn public_ecdh_encryption_roundtrips_each_named_curve() {
    // ECDH field widths differ from the AES width. Every supported named curve
    // must preserve its fixed-width ZZ and derive the same consuming key on
    // opposite sides, rather than accidentally using the public point as IKM.
    use xml_sec::provider::{EcdhCurve, KeyAgreementParameters, RustCryptoEcdhKey};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    for (curve, width) in [
        (EcdhCurve::P256, 32),
        (EcdhCurve::P384, 48),
        (EcdhCurve::P521, 66),
    ] {
        let mut scalar = vec![0; width];
        scalar[width - 1] = 7;
        let sender = Box::new(RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap());
        scalar[width - 1] = 9;
        let recipient = RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap();
        let sender_public = sender.public_key();
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .agreement_key(
                method.clone(),
                sender,
                KeyAgreementAlgorithm::EcdhEs,
                recipient.public_key(),
            )
            .encrypt_binary(b"ECDH payload")
            .unwrap();
        let resolver = DerivedKeyDecryptor::content(
            &method,
            DerivedKeyInput::Agreement {
                key: &recipient,
                parameters: KeyAgreementParameters {
                    algorithm: KeyAgreementAlgorithm::EcdhEs.uri(),
                    peer_public_key: &sender_public,
                },
            },
            DataEncryptionAlgorithm::Aes128Gcm,
        );
        assert_eq!(
            DecryptContext::new(&resolver)
                .decrypt(&encrypted.encrypted_data_xml)
                .unwrap(),
            xml_sec::xmlenc::DecryptedContent::Bytes(b"ECDH payload".to_vec()),
            "{curve:?}"
        );
    }
}

#[test]
fn public_encryption_and_decryption_agree_without_exporting_secret() {
    // The sender and recipient use opposite opaque private handles. Agreement
    // stays inside each operation; denied mechanisms never reach the KDF.
    use std::sync::Arc;
    use xml_sec::provider::{KeyAgreementParameters, RustCryptoX25519Key};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let sender = Box::new(RustCryptoX25519Key::from_bytes([7; 32]));
    let recipient = RustCryptoX25519Key::from_bytes([9; 32]);
    let sender_public = sender.public_key();
    let recipient_public = recipient.public_key();
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let provider = Arc::new(RecordingProvider::new());
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .agreement_key(
            method.clone(),
            sender,
            KeyAgreementAlgorithm::X25519,
            recipient_public.to_vec(),
        )
        .provider(provider.clone());
    let mut denied = xml_sec::policy::EncryptionPolicy::default();
    denied.key_establishment.agreement_algorithms = Some(HashSet::new());
    assert!(matches!(
        builder
            .clone()
            .policy(denied)
            .encrypt_binary(b"agreement payload"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    let mut bounded = xml_sec::policy::EncryptionPolicy::default();
    bounded.key_establishment.max_owned_bytes = 47;
    assert!(matches!(
        builder
            .clone()
            .policy(bounded)
            .encrypt_binary(b"agreement payload"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    let encrypted = builder.encrypt_binary(b"agreement payload").unwrap();
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Agreement {
            key: &recipient,
            parameters: KeyAgreementParameters {
                algorithm: KeyAgreementAlgorithm::X25519.uri(),
                peer_public_key: &sender_public,
            },
        },
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert_eq!(
        DecryptContext::new(&resolver)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"agreement payload".to_vec())
    );
    // Invalid or non-contributory peers must never become KDF input, even
    // though the compiled provider advertises the agreement capability.
    for peer in [vec![0; 31], vec![0; 32]] {
        let invalid_peer = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .agreement_key(
                method.clone(),
                Box::new(RustCryptoX25519Key::from_bytes([7; 32])),
                KeyAgreementAlgorithm::X25519,
                peer,
            )
            .provider(provider.clone());
        assert!(invalid_peer.encrypt_binary(b"payload").is_err());
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn encryption_defers_derivation_to_final_operation_policy() {
    // Builder configuration and cloning must not execute KDF work. The final
    // operation policy gates both permission and allocation before dispatch.
    use std::sync::Arc;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let provider = Arc::new(RecordingProvider::new());
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method.clone(), b"secret".to_vec())
        .provider(provider.clone());
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    let mut denied = xml_sec::policy::EncryptionPolicy::default();
    denied.key_establishment.derivation_algorithms = Some(HashSet::new());
    assert!(matches!(
        builder.clone().policy(denied).encrypt_binary(b"payload"),
        Err(XmlEncError::Policy(_))
    ));
    let mut bounded = xml_sec::policy::EncryptionPolicy::default();
    bounded.key_establishment.max_owned_bytes = 15;
    assert!(matches!(
        builder.clone().policy(bounded).encrypt_binary(b"payload"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert!(!format!("{builder:?}").contains("secret"));
    let encrypted = builder.encrypt_binary(b"payload").unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    assert_eq!(parsed.derived_keys.len(), 1);
    assert_eq!(parsed.derived_keys[0].method.as_ref(), Some(&method));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert_eq!(
        DecryptContext::new(&resolver)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"payload".to_vec())
    );
    let wrong_width = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .derived_key(method, b"secret".to_vec())
        .provider(provider.clone());
    assert!(wrong_width.encrypt_binary(b"payload").is_err());
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn xml_derivation_cannot_be_bypassed_by_a_raw_key_resolver() {
    // Even possession of the final symmetric key must not cause the generic
    // resolver to silently ignore the XML key-establishment processing model.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, EncryptedDataBuilder, SymmetricKeyDecryptor,
    };
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let key = RUST_CRYPTO_PROVIDER
        .derive_key(&method.parameters(16).unwrap(), b"secret")
        .unwrap();
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method, b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    let resolver = SymmetricKeyDecryptor::new(key);
    assert!(matches!(
        DecryptContext::new(&resolver).decrypt(&encrypted.encrypted_data_xml),
        Err(XmlEncError::KeyNotFound)
    ));
}

#[test]
fn derived_key_owned_document_mutations_preserve_identity_and_atomicity() {
    // Actual encryption/decryption mutation must use the transported method,
    // advance generation only on success, and preserve the surrounding XML.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, DocumentEncryptionOptions,
        EncryptedDataBuilder,
    };
    let source = "<root><payload Id=\"plain\">content</payload><other/></root>";
    let mut document = xml_sec::XmlDocument::parse(source).unwrap();
    let identity = document.identity();
    let generation = document.generation();
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method.clone(), b"secret".to_vec())
        .encrypt_owned_document(
            &mut document,
            DocumentEncryptionOptions {
                element_id: Some("plain"),
            },
        )
        .unwrap();
    assert_eq!(document.identity(), identity);
    assert_eq!(document.generation(), generation + 1);
    assert!(document.as_xml().contains("DerivedKey"));
    let encrypted_xml = document.as_xml().to_owned();
    let incorrect = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"wrong"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert!(matches!(
        DecryptContext::new(&incorrect).decrypt_owned_document(&mut document, None),
        Err(XmlEncError::AeadAuthenticationFailed)
    ));
    assert_eq!(document.as_xml(), encrypted_xml);
    assert_eq!(document.identity(), identity);
    assert_eq!(document.generation(), generation + 1);
    let correct = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    DecryptContext::new(&correct)
        .decrypt_owned_document(&mut document, None)
        .unwrap();
    assert_eq!(document.as_xml(), source);
    assert_eq!(document.identity(), identity);
    assert_eq!(document.generation(), generation + 2);
}

#[test]
fn xml_derivation_matches_context_before_provider_work() {
    // Transported salt and association names are not permission to substitute
    // the application's master key or its expected derivation context.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method.clone(), b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    let provider = RecordingProvider::new();
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    let altered = encrypted.encrypted_data_xml.replace("c2FsdA==", "dGFtcGVy");
    assert_ne!(altered, encrypted.encrypted_data_xml);
    assert!(matches!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&altered),
        Err(XmlEncError::KeyNotFound)
    ));
    let named = encrypted.encrypted_data_xml.replace(
        "</xenc11:DerivedKey>",
        "<xenc11:MasterKeyName> master </xenc11:MasterKeyName></xenc11:DerivedKey>",
    );
    assert!(matches!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&named),
        Err(XmlEncError::KeyNotFound)
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    let resolver = resolver.master_key_name(" master ");
    assert_eq!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&named)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"payload".to_vec())
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn xml_derivation_omission_requires_explicit_request_method() {
    // XMLEnc 1.1 §3.5.2 permits absent KDF parameters only when the recipient
    // already knows them; no provider/default algorithm is inferred from XML.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let method_xml = method.to_xml(&policy.resources).unwrap();
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method.clone(), b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    let omitted = encrypted.encrypted_data_xml.replace(&method_xml, "");
    assert_ne!(omitted, encrypted.encrypted_data_xml);
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert_eq!(
        DecryptContext::new(&resolver).decrypt(&omitted).unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"payload".to_vec())
    );
}

#[test]
fn typed_derivation_uses_current_metadata_policy() {
    // A descriptor parsed under an earlier generous policy is revalidated
    // before resolution when supplied through the public typed entry point.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method.clone(), b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    let mut parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    parsed.derived_keys[0].master_key_name = Some("x".repeat(100));
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.resources.max_encryption_metadata_bytes = 99;
    let provider = RecordingProvider::new();
    assert!(matches!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .policy(policy)
            .decrypt_data(&parsed),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn typed_wrapped_key_references_use_current_operation_limit() {
    // Parsed public values may be modified by callers. Reference associations
    // must be bounded again before key derivation/recovery at consumption.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
        KeyWrapAlgorithm, ReferenceList,
    };
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let kek = RUST_CRYPTO_PROVIDER
        .derive_key(&method.parameters(16).unwrap(), b"secret")
        .unwrap();
    let output = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .recipient_aes_kw(kek, KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"payload")
        .unwrap();
    let mut encrypted = xml_sec::xmlenc::parse_encrypted_data(&output.encrypted_data_xml).unwrap();
    encrypted.encrypted_keys[0].reference_list = Some(ReferenceList {
        data_references: vec!["#a".into()],
        key_references: vec!["#b".into()],
    });
    let resolver = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        KeyWrapAlgorithm::AesKw128,
    );
    let provider = RecordingProvider::new();
    let mut policy = policy;
    policy.resources.max_references = 1;
    assert!(matches!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .policy(policy)
            .decrypt_data(&encrypted),
        Err(XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                maximum: 1,
                actual: 2,
                ..
            }
        ))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn reference_list_validates_container_before_reading_uri() {
    // XMLEnc 1.1 §3.6 has element-only ReferenceList content and a choice
    // between DataReference and KeyReference. Ignore comments, not invalid text
    // or foreign direct elements, before attempting URI association.
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, EncryptedDataBuilder};
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let output = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method, b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    for content in [
        "text<xenc:DataReference URI='#data'/>",
        "\u{a0}<xenc:DataReference URI='#data'/>",
        "<foreign xmlns='urn:foreign'/>",
    ] {
        let xml = output.encrypted_data_xml.replace(
            "</xenc11:DerivedKey>",
            &format!("<xenc:ReferenceList>{content}</xenc:ReferenceList></xenc11:DerivedKey>"),
        );
        assert!(
            matches!(
                xml_sec::xmlenc::parse_encrypted_data(&xml),
                Err(XmlEncError::InvalidStructure(_))
            ),
            "accepted {content}"
        );
    }
}

#[test]
fn reference_list_required_uri_may_be_empty() {
    // XMLEnc 1.1 §3.6 requires URI presence, not a nonempty anyURI. An empty
    // same-document URI remains a resolution question rather than bad syntax.
    let xml = "<xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' xmlns:xenc11='http://www.w3.org/2009/xmlenc11#' xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/><ds:KeyInfo><xenc11:DerivedKey><xenc:ReferenceList><xenc:DataReference URI=''/></xenc:ReferenceList></xenc11:DerivedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
    let encrypted = xml_sec::xmlenc::parse_encrypted_data(xml).unwrap();
    assert_eq!(
        encrypted.derived_keys[0]
            .reference_list
            .as_ref()
            .unwrap()
            .data_references,
        [""]
    );
}

#[test]
fn xml_derivation_rejects_unordered_and_mixed_parameters() {
    // Optional descriptor fields are still an ordered sequence, and metadata
    // containers must not accept hidden text or multiple occurrences.
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, EncryptedDataBuilder};
    let method = xml_method(&xml_sec::policy::DecryptionPolicy::default());
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .derived_key(method, b"secret".to_vec())
        .encrypt_binary(b"payload")
        .unwrap();
    for extra in [
        "unexpected",
        "\u{a0}",
        "<xenc11:MasterKeyName>a</xenc11:MasterKeyName><xenc11:DerivedKeyName>b</xenc11:DerivedKeyName>",
        "<xenc11:MasterKeyName>a</xenc11:MasterKeyName><xenc11:MasterKeyName>b</xenc11:MasterKeyName>",
    ] {
        let xml = encrypted.encrypted_data_xml.replace(
            "</xenc11:DerivedKey>",
            &format!("{extra}</xenc11:DerivedKey>"),
        );
        assert!(xml_sec::xmlenc::parse_encrypted_data(&xml).is_err());
    }
}

#[test]
fn public_decrypt_uses_operation_policy_for_derived_content_keys() {
    // The public decrypt path must invoke KDF inside its key-resolution graph
    // gate and enforce operation policy, not the policy used to parse parameters.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
    };
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let key = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters(), b"secret")
        .unwrap();
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_binary(b"derived content")
        .unwrap();
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    let provider = RecordingProvider::new();
    let wrong_purpose = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        DataEncryptionAlgorithm::Aes128Cbc,
    );
    assert!(
        DecryptContext::new(&wrong_purpose)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .is_err()
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"derived content".to_vec())
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    let mut denied = policy;
    denied.key_establishment.derivation_algorithms = Some(HashSet::new());
    assert!(matches!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .policy(denied)
            .decrypt(&encrypted.encrypted_data_xml),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn derived_wrapping_key_recovers_a_different_width_content_key() {
    // Key separation is explicit: a 128-bit derived KEK must not be tried as
    // a 256-bit direct content key before the embedded AES-KW recipient.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
        KeyWrapAlgorithm,
    };
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let kek = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters(), b"secret")
        .unwrap();
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .recipient_aes_kw(kek, KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"derived wrapping key")
        .unwrap();
    let resolver = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        KeyWrapAlgorithm::AesKw128,
    );
    let provider = RecordingProvider::new();
    let wrong_purpose = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        KeyWrapAlgorithm::AesKw256,
    );
    assert!(
        DecryptContext::new(&wrong_purpose)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .is_err()
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"derived wrapping key".to_vec())
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    let wrong = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Secret(b"wrong password"),
        KeyWrapAlgorithm::AesKw128,
    );
    assert!(
        DecryptContext::new(&wrong)
            .decrypt(&encrypted.encrypted_data_xml)
            .is_err()
    );
}

#[test]
fn exhausted_unwrap_allowance_prevents_earlier_derivation() {
    // A derived KEK is useless if this attempt cannot also unwrap. Reject the
    // whole required candidate fan-out before spending password-derivation work.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptionKeyResolver, DerivedKeyDecryptor, EncryptedDataBuilder,
        KeyCandidateBudget, KeyWrapAlgorithm,
    };
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .recipient_aes_kw(vec![1; 16], KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"payload")
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let resolver = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Secret(b"secret"),
        KeyWrapAlgorithm::AesKw128,
    );
    let provider = RecordingProvider::new();
    let mut budget = KeyCandidateBudget::with_limit(1);
    assert!(matches!(
        resolver.resolve_content_keys_with_policy(
            &provider,
            DataEncryptionAlgorithm::Aes256Gcm,
            Some(&parsed.encrypted_keys[0]),
            &policy,
            &mut budget
        ),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(budget.remaining(), 1);
}

#[test]
fn sha3_concat_padding_crossing_is_reserved_before_provider_work() {
    // FIPS 202 sections 5.1/6.1: at the rate boundary, a partial
    // octet plus SHA-3 domain/padding can require a second permutation.
    // The policy must reject before invoking a provider, at all four rates.
    for (digest, rate) in [
        (DigestAlgorithm::Sha3_224, 144),
        (DigestAlgorithm::Sha3_256, 136),
        (DigestAlgorithm::Sha3_384, 104),
        (DigestAlgorithm::Sha3_512, 72),
    ] {
        let secret = vec![0xa5; rate - 5];
        let mut params = KdfParameters {
            algorithm: KeyDerivationAlgorithm::ConcatKdf.uri(),
            digest: Some(digest.uri()),
            salt: &[],
            info: KdfContext::Bits {
                bytes: &[0xfe],
                bit_len: 7,
            },
            iterations: 0,
            output_len: 16,
        };
        let provider = RecordingProvider::new();
        let mut policy = KeyEstablishmentPolicy {
            digest_algorithms: Some(HashSet::from([digest])),
            max_hash_blocks: 1,
            ..KeyEstablishmentPolicy::default()
        };
        let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
        assert!(matches!(
            budget.derive_key(&provider, &params, &secret),
            Err(XmlEncError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "key establishment hash blocks",
                    maximum: 1,
                    actual: 2
                }
            ))
        ));
        assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
        policy.max_hash_blocks = 2;
        let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
        assert_eq!(
            budget
                .derive_key(&provider, &params, &secret)
                .unwrap()
                .len(),
            16
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        params.info = KdfContext::Octets(&[]);
        policy.max_hash_blocks = 1;
        let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
        assert_eq!(
            budget
                .derive_key(&provider, &params, &secret)
                .unwrap()
                .len(),
            16
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn nested_resolver_calls_share_derivation_allowance() {
    // A resolver may recurse or retry, but forwarding the candidate budget
    // retains failed KDF reservations instead of silently starting a new budget.
    let provider = RecordingProvider::new();
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.key_establishment.max_hash_blocks = 6;
    let mut budget = xml_sec::xmlenc::KeyCandidateBudget::with_limit(10);
    provider.fail.store(true, Ordering::Relaxed);
    assert!(
        budget
            .derive_key(&provider, &policy, &parameters(), b"secret")
            .is_err()
    );
    provider.fail.store(false, Ordering::Relaxed);
    assert!(matches!(
        budget.derive_key(&provider, &policy, &parameters(), b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn agreement_is_gated_by_kdf_permission_and_both_output_reservations() {
    // Permission and allocation gates must precede scalar multiplication, not
    // merely reject the KDF after a shared secret has already been produced.
    use xml_sec::provider::{KeyAgreementKey, KeyAgreementParameters, RustCryptoX25519Key};
    struct RecordingKey {
        key: RustCryptoX25519Key,
        calls: AtomicUsize,
    }
    impl KeyAgreementKey for RecordingKey {
        fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.key.agree(parameters)
        }
    }
    let key = RecordingKey {
        key: RustCryptoX25519Key::from_bytes([7; 32]),
        calls: AtomicUsize::new(0),
    };
    let peer = RustCryptoX25519Key::from_bytes([9; 32]).public_key();
    let agreement = KeyAgreementParameters {
        algorithm: KeyAgreementAlgorithm::X25519.uri(),
        peer_public_key: &peer,
    };
    let provider = RecordingProvider::new();
    let mut budget = xml_sec::xmlenc::KeyCandidateBudget::with_limit(20);
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.key_establishment.derivation_algorithms = Some(HashSet::new());
    assert!(matches!(
        budget.agree_and_derive(&provider, &policy, &key, &agreement, &parameters()),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    policy.key_establishment.derivation_algorithms = None;
    policy.key_establishment.max_owned_bytes = 47; // ZZ(32) + consuming key(16).
    assert!(matches!(
        budget.agree_and_derive(&provider, &policy, &key, &agreement, &parameters()),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    policy.key_establishment.max_owned_bytes = 48;
    let derived = budget
        .agree_and_derive(&provider, &policy, &key, &agreement, &parameters())
        .unwrap();
    assert_eq!(derived.len(), 16);
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        budget.agree_and_derive(&provider, &policy, &key, &agreement, &parameters()),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn public_decrypt_executes_agreement_and_kdf_inside_resolution() {
    // A caller-owned X25519 handle establishes the KEK within the operation;
    // neither the shared secret nor the derived KEK escapes or needs copying.
    use xml_sec::provider::{KeyAgreementParameters, RustCryptoX25519Key};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DerivedKeyDecryptor, EncryptedDataBuilder,
        KeyWrapAlgorithm,
    };
    let private = RustCryptoX25519Key::from_bytes([7; 32]);
    let peer = RustCryptoX25519Key::from_bytes([9; 32]).public_key();
    let agreement = KeyAgreementParameters {
        algorithm: KeyAgreementAlgorithm::X25519.uri(),
        peer_public_key: &peer,
    };
    let secret = zeroize::Zeroizing::new(
        RUST_CRYPTO_PROVIDER
            .agree_key(&private, &agreement)
            .unwrap(),
    );
    let kek = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters(), &secret)
        .unwrap();
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .recipient_aes_kw(kek, KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"agreement content")
        .unwrap();
    let policy = xml_sec::policy::DecryptionPolicy::default();
    let method = xml_method(&policy);
    let resolver = DerivedKeyDecryptor::wrapping(
        &method,
        DerivedKeyInput::Agreement {
            key: &private,
            parameters: agreement,
        },
        KeyWrapAlgorithm::AesKw128,
    );
    assert_eq!(
        DecryptContext::new(&resolver)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"agreement content".to_vec())
    );
}

#[test]
fn kdf_permission_gates_provider_work() {
    // Provider capability cannot override either the KDF or digest permission.
    let provider = RecordingProvider::new();
    let policy = KeyEstablishmentPolicy {
        derivation_algorithms: Some(HashSet::new()),
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(matches!(
        budget.derive_key(&provider, &parameters(), b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert_eq!(budget.hash_blocks(), 0);
    let policy = KeyEstablishmentPolicy {
        digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha512])),
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(matches!(
        budget.derive_key(&provider, &parameters(), b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn x448_permission_and_secret_width_gate_agreement() {
    use xml_sec::provider::{
        KeyAgreementKey, KeyAgreementParameters, ProviderError, RustCryptoX448Key,
    };
    // An unapproved algorithm or a 55-byte secret reservation must never reach
    // the private-key callback. X448 needs ZZ(56) plus the consuming key(16).
    struct CountedX448 {
        key: RustCryptoX448Key,
        calls: AtomicUsize,
    }
    impl KeyAgreementKey for CountedX448 {
        fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.key.agree(parameters)
        }
    }
    let private = CountedX448 {
        key: RustCryptoX448Key::from_bytes([7; 56]),
        calls: AtomicUsize::new(0),
    };
    let peer = RustCryptoX448Key::from_bytes([9; 56]).public_key();
    let agreement = KeyAgreementParameters {
        algorithm: KeyAgreementAlgorithm::X448.uri(),
        peer_public_key: &peer,
    };
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    let mut budget = xml_sec::xmlenc::KeyCandidateBudget::with_limit(20);
    assert!(matches!(
        budget.agree_and_derive(
            &RUST_CRYPTO_PROVIDER,
            &policy,
            &private,
            &agreement,
            &parameters()
        ),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(private.calls.load(Ordering::Relaxed), 0);
    policy.key_establishment.agreement_algorithms =
        Some(HashSet::from([KeyAgreementAlgorithm::X448]));
    policy.key_establishment.max_owned_bytes = 71;
    assert!(matches!(
        budget.agree_and_derive(
            &RUST_CRYPTO_PROVIDER,
            &policy,
            &private,
            &agreement,
            &parameters()
        ),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(private.calls.load(Ordering::Relaxed), 0);
    policy.key_establishment.max_owned_bytes = 72;
    let key = budget
        .agree_and_derive(
            &RUST_CRYPTO_PROVIDER,
            &policy,
            &private,
            &agreement,
            &parameters(),
        )
        .unwrap();
    assert_eq!(key.len(), 16);
    assert_eq!(private.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn kdf_reservations_are_atomic_and_cumulative_across_retries() {
    // One PBKDF2 block at c=2 costs 2 prepared HMAC blocks + 2 U1 + 2 U2.
    // A failed call consumes that reservation; a retry cannot reset allowance.
    let provider = RecordingProvider::new();
    let policy = KeyEstablishmentPolicy {
        max_hash_blocks: 12,
        max_owned_bytes: 32,
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert_eq!(
        budget
            .derive_key(&provider, &parameters(), b"secret")
            .unwrap()
            .len(),
        16
    );
    assert_eq!(budget.hash_blocks(), 6);
    provider.fail.store(true, Ordering::Relaxed);
    assert!(
        budget
            .derive_key(&provider, &parameters(), b"secret")
            .is_err()
    );
    assert_eq!(budget.hash_blocks(), 12);
    assert_eq!(budget.owned_bytes(), 32);
    assert!(matches!(
        budget.derive_key(&provider, &parameters(), b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 2);

    let policy = KeyEstablishmentPolicy {
        max_hash_blocks: 6,
        max_owned_bytes: 15,
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(matches!(
        budget.derive_key(&provider, &parameters(), b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(budget.hash_blocks(), 0);
    assert_eq!(budget.owned_bytes(), 0);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn oversized_iteration_count_and_context_fail_before_dispatch() {
    // XML u64 iteration counts must not truncate or initiate CPU work before
    // the operation-wide limit. Typed callers also undergo syntax validation.
    let provider = RecordingProvider::new();
    let policy = KeyEstablishmentPolicy::default();
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    let mut params = parameters();
    params.iterations = u64::MAX;
    assert!(matches!(
        budget.derive_key(&provider, &params, b"secret"),
        Err(XmlEncError::Policy(_))
    ));
    params.iterations = 2;
    params.info = KdfContext::Bits {
        bytes: &[0],
        bit_len: 1,
    };
    assert!(matches!(
        budget.derive_key(&provider, &params, b"secret"),
        Err(XmlEncError::Provider(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn dh_modulus_limit_counts_bits_not_padded_octets() {
    // A provider handle reporting a 513-bit modulus requires 65 output bytes.
    // Accounting the padded storage as a 520-bit modulus rejects valid widths.
    // This test isolates preflight; DH mathematics has independent KAT coverage.
    use xml_sec::provider::{KeyAgreementKey, KeyAgreementParameters};
    struct BoundaryKey;
    impl KeyAgreementKey for BoundaryKey {
        fn dh_domain_bits(&self) -> Option<(usize, usize)> {
            Some((513, 160))
        }
        fn agree(&self, _: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
            Ok(vec![7; 65])
        }
    }
    let policy = KeyEstablishmentPolicy {
        agreement_algorithms: Some([KeyAgreementAlgorithm::DhEs].into()),
        minimum_dh_modulus_bits: 513,
        minimum_dh_subgroup_bits: 160,
        max_dh_modulus_bits: 513,
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    let output = budget
        .agree_and_derive(
            &RUST_CRYPTO_PROVIDER,
            &BoundaryKey,
            &KeyAgreementParameters {
                algorithm: KeyAgreementAlgorithm::DhEs.uri(),
                peer_public_key: &[7; 65],
            },
            &parameters(),
        )
        .unwrap();
    assert_eq!(output.len(), 16);
}

#[test]
fn provider_output_width_and_legacy_permissions_are_checked() {
    // A provider cannot return a different cipher key width; legacy SHA-1
    // permission is local to KDF and must be explicit, even for legacy DH.
    let provider = RecordingProvider::new();
    provider.wrong_width.store(true, Ordering::Relaxed);
    let policy = KeyEstablishmentPolicy::default();
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(matches!(
        budget.derive_key(&provider, &parameters(), b"secret"),
        Err(XmlEncError::Provider(ProviderError::InvalidKeySize { .. }))
    ));
    assert!(
        policy
            .check_agreement(KeyAgreementAlgorithm::LegacyDh)
            .is_err()
    );
    assert!(
        policy
            .check_derivation(KeyDerivationAlgorithm::LegacyDh, DigestAlgorithm::Sha1)
            .is_err()
    );
    let policy = KeyEstablishmentPolicy {
        derivation_algorithms: Some(HashSet::from([KeyDerivationAlgorithm::LegacyDh])),
        digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha1])),
        ..Default::default()
    };
    assert!(
        policy
            .check_derivation(KeyDerivationAlgorithm::LegacyDh, DigestAlgorithm::Sha1)
            .is_ok()
    );
    assert!(
        policy
            .check_derivation(KeyDerivationAlgorithm::Hkdf, DigestAlgorithm::Sha1)
            .is_err()
    );
}

#[test]
fn parsed_xml_uses_one_policy_and_budget() {
    // Public XML parameters must reach the same pre-execution gate as typed
    // parameters, including width binding and cumulative repeated derivations.
    let parse_policy = xml_sec::policy::DecryptionPolicy::default();
    let xml = format!(
        "<KeyDerivationMethod xmlns='http://www.w3.org/2009/xmlenc11#' Algorithm='{}'><PBKDF2-params><Salt><Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount><KeyLength>16</KeyLength><PRF Algorithm='{}'/></PBKDF2-params></KeyDerivationMethod>",
        parameters().algorithm,
        parameters().digest.unwrap()
    );
    let method = xml_sec::xmlenc::parse_key_derivation_method(&xml, &parse_policy).unwrap();
    let provider = RecordingProvider::new();
    let policy = KeyEstablishmentPolicy {
        max_owned_bytes: 16,
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        method
            .derive_key(32, &provider, b"secret", &mut budget)
            .is_err()
    );
    let key = method
        .derive_key(16, &provider, b"secret", &mut budget)
        .unwrap();
    assert_eq!(
        &*key,
        &RUST_CRYPTO_PROVIDER
            .derive_key(&parameters(), b"secret")
            .unwrap()
    );
    assert!(matches!(
        method.derive_key(16, &provider, b"secret", &mut budget),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn dh_subgroup_minimum_must_leave_room_for_the_modulus() {
    // p = j*q + 1, j >= 2: equality is an impossible policy, while the
    // modulus minimum itself may equal the permitted modulus maximum.
    for subgroup in [2047, 2048, 2049] {
        let policy = KeyEstablishmentPolicy {
            max_dh_modulus_bits: 2048,
            minimum_dh_modulus_bits: 2048,
            minimum_dh_subgroup_bits: subgroup,
            ..Default::default()
        };
        assert_eq!(policy.validate().is_ok(), subgroup < 2048);
    }
}
