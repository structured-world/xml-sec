//! End-to-end external-key checks using only an isolated `SoftHSM` test store.
#![cfg(feature = "pkcs11")]

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::provider::pkcs11::{Pkcs11AesKey, Pkcs11Provider, Pkcs11RsaKey, cryptoki};
use xml_sec::provider::{
    ContentDecryptionKey, CryptoProvider, ExternalProviderError, KeyAgreementParameters,
    ProviderCapability, ProviderError, RustCryptoProvider,
};
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm, VerifyingKey as _};
use xml_sec::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm};

#[path = "support/provider_candidate_limits.rs"]
mod candidate_limits;

// Keep the explicit module loaded until process shutdown. SoftHSM's OpenSSL
// backend registers thread-local destructors that must run before dlclose.
// Dropping the last module on the libtest worker unloads those callbacks.
static MODULE: std::sync::OnceLock<Pkcs11> = std::sync::OnceLock::new();

const MESSAGE: &[u8; 20] = b"opaque key operation";
const CEK: [u8; 16] = [0x72; 16];

/// Initializes the disposable token supplied by the harness and returns its
/// slot with the security-officer and user PINs.
fn isolated_token() -> (&'static Pkcs11, Slot, AuthPin, AuthPin) {
    // Refuse initialization unless the maintained harness supplies a disposable store.
    // This prevents accidentally resetting a real token on a developer machine.
    let store = std::env::var("XML_SEC_PKCS11_TEST_STORE")
        .expect("run `cargo run -p xml-sec-tools -- pkcs11-tests`");
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
    (module, slot, so, pin)
}

/// PKCS#11 Base 2.40 §5.6: the provider must not require token-write access.
/// A live R/O session prevents SO login, proving the mode without exposing
/// the provider's private session or modifying a real token's protection flags.
fn assert_provider_session_read_only(module: &Pkcs11, slot: Slot, so: &AuthPin) {
    let admin = module.open_rw_session(slot).unwrap();
    assert!(matches!(
        admin.login(UserType::So, Some(so)),
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::SessionReadOnlyExists,
            _
        ))
    ));
}

fn assert_login_and_digests(provider: &Pkcs11Provider, pin: &AuthPin) {
    // Wrong credentials stay typed and never include token, PIN or module details.
    let error = provider
        .login(&AuthPin::new("wrong-pin".into()))
        .unwrap_err();
    assert!(matches!(
        error,
        ProviderError::External(ExternalProviderError::Credentials)
    ));
    assert!(!error.to_string().contains("wrong-pin"));
    provider.login(pin).unwrap();
    // Multi-part digests equal the software digest at every split, and an
    // abandoned digest leaves the serialized session ready for the next one.
    let data = (0..=255_u8).cycle().take(4_099).collect::<Vec<_>>();
    let mut digested = 0;
    for algorithm in DigestAlgorithm::ALL {
        if !provider.supports(ProviderCapability::Digest(algorithm)) {
            continue;
        }
        digested += 1;
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let expected = RustCryptoProvider
            .digest(algorithm, &data, &memory)
            .unwrap();
        let mut state = provider.begin_digest(algorithm, &memory).unwrap();
        for part in data.chunks(7) {
            state.update(part).unwrap();
        }
        let mut output = [0; xml_sec::xmldsig::MAX_DIGEST_OUTPUT];
        let written = state.finalize(&mut output).unwrap();
        assert_eq!(&output[..written], &*expected, "{algorithm:?}");
        drop(state);
        let mut abandoned = provider.begin_digest(algorithm, &memory).unwrap();
        abandoned.update(&data).unwrap();
        drop(abandoned);
        assert_eq!(
            &*provider.digest(algorithm, &data, &memory).unwrap(),
            &*expected,
            "{algorithm:?}"
        );
        // The token's state is charged like a software one, and refused alike.
        assert_eq!(memory.used(), 0);
        let empty = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert_eq!(
            provider.begin_digest(algorithm, &empty).err(),
            Some(ProviderError::Resource(MemoryError::LimitExceeded))
        );
    }
    assert!(digested > 0, "the test token advertises no digest");
}

/// Generates the sensitive, non-extractable RSA-2048 pair with ID 1.
fn generate_rsa_pair(session: &Session) {
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
}

/// Creates a sensitive, non-extractable token AES key with the given usages.
fn create_aes_key(session: &Session, id: u8, value: &[u8], usages: &[Attribute]) -> ObjectHandle {
    let mut template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Id(vec![id]),
        Attribute::Value(value.to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    template.extend_from_slice(usages);
    session.create_object(&template).unwrap()
}

fn assert_token_pss(provider: &Pkcs11Provider, private: &Pkcs11RsaKey, public: &Pkcs11RsaKey) {
    // PSS parameters reach the token unchanged, rather than a software fallback.
    for salt_len in [0, 32] {
        let algorithm = SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len,
        });
        let signature = provider.sign(private, algorithm, MESSAGE).unwrap();
        assert!(
            provider
                .verify(public, algorithm, MESSAGE, &signature)
                .unwrap()
        );
        assert!(
            !provider
                .verify(public, algorithm, b"changed", &signature)
                .unwrap()
        );
        let wrong = SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len: if salt_len == 0 { 32 } else { 0 },
        });
        assert!(!provider.verify(public, wrong, MESSAGE, &signature).unwrap());
    }
    // SoftHSM rejects a different MGF hash: propagate the token failure and
    // never silently sign with matching hashes or a software-held key.
    let unsupported_tuple = SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters {
        digest: DigestAlgorithm::Sha256,
        mgf_digest: DigestAlgorithm::Sha384,
        salt_len: 32,
    });
    assert!(provider.sign(private, unsupported_tuple, MESSAGE).is_err());
}

/// Signs an enveloped document with the token key and checks it verifies
/// only within the operation's RSA strength policy.
fn token_signed_document(
    provider: &Pkcs11Provider,
    private: &Pkcs11RsaKey,
    public: &Pkcs11RsaKey,
) -> String {
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
    let signed = xml_sec::xmldsig::SignContext::new(private)
        .provider(provider)
        .sign_with_builder("<root><payload>signed</payload></root>", &builder)
        .unwrap();
    // An opaque handle does not bypass the operation's RSA strength policy.
    let mut strict = xml_sec::policy::VerificationPolicy::default();
    strict.key_trust.rsa_keys.minimum_modulus_bits = 3072;
    assert!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(public)
            .provider(provider)
            .policy(strict)
            .verify(&signed)
            .is_err()
    );
    assert_eq!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(public)
            .provider(provider)
            .verify(&signed)
            .unwrap()
            .status,
        xml_sec::xmldsig::DsigStatus::Valid
    );
    signed
}

/// The token never exports private material or a native-verification SPKI.
/// Its cached public attributes still prove the actual successful key.
fn assert_token_key_receipt(provider: &Pkcs11Provider, public: &Pkcs11RsaKey, signed: &str) {
    use structured_asn1::{
        Encoding, Limits, Parser,
        memory::{Memory, MemoryAccount},
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)));
    assert!(
        public
            .verification_spki(SignatureAlgorithm::RsaSha256)
            .unwrap()
            .is_none()
    );
    let bytes = public
        .association_spki(SignatureAlgorithm::RsaSha256)
        .unwrap();
    let parser = Parser::new(Encoding::Der, Limits::default(), work.clone());
    let mut reader = parser.read(bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let expected = structured_pkix::path::WorkingKey::standing(
        structured_pkix::key::PublicKeyInfo::read_element(&reader, &element, "token expected key")
            .unwrap(),
    );
    let document = xml_sec::XmlDocument::parse(signed.to_owned()).unwrap();
    let context = xml_sec::xmldsig::VerifyContext::new()
        .key(public)
        .provider(provider);
    xml_sec::xmldsig::with_verified_request(
        &document,
        &context,
        &xml_sec::xmldsig::VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            selected
                .with_key_receipt(|receipt| {
                    assert!(receipt.has_public_evidence());
                    selected
                        .associate_key(&receipt, expected, |outcome| {
                            assert_eq!(outcome, xml_sec::provider::KeyAssociation::Same);
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
}

/// Token signatures verify only through the session that owns the handle.
fn assert_token_signatures(
    provider: &Pkcs11Provider,
    other: &Pkcs11Provider,
    private: &Pkcs11RsaKey,
    public: &Pkcs11RsaKey,
    signed: &str,
) {
    let signature = provider
        .sign(private, SignatureAlgorithm::RsaSha256, MESSAGE)
        .unwrap();
    assert_ne!(
        xml_sec::xmldsig::VerifyContext::new()
            .key(public)
            .provider(provider)
            .verify(&signed.replace("signed", "changed"))
            .unwrap()
            .status,
        xml_sec::xmldsig::DsigStatus::Valid
    );
    assert!(
        provider
            .verify(public, SignatureAlgorithm::RsaSha256, MESSAGE, &signature)
            .unwrap()
    );
    assert!(
        !provider
            .verify(
                public,
                SignatureAlgorithm::RsaSha256,
                b"tampered",
                &signature
            )
            .unwrap()
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
    assert_eq!(
        &*provider
            .digest(DigestAlgorithm::Sha256, MESSAGE, &memory)
            .unwrap(),
        &*RustCryptoProvider
            .digest(DigestAlgorithm::Sha256, MESSAGE, &memory)
            .unwrap()
    );
    // A same-name provider on another session must not execute this handle.
    assert!(
        other
            .sign(private, SignatureAlgorithm::RsaSha256, MESSAGE)
            .is_err()
    );
    assert!(
        other
            .verify(public, SignatureAlgorithm::RsaSha256, MESSAGE, &signature)
            .is_err()
    );
    assert!(
        RustCryptoProvider
            .verify(public, SignatureAlgorithm::RsaSha256, MESSAGE, &signature)
            .is_err()
    );
    // Clones share the execution domain and serialize whole C_Sign operations.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(move || {
                for _ in 0..4 {
                    assert_eq!(
                        provider
                            .sign(private, SignatureAlgorithm::RsaSha256, MESSAGE)
                            .unwrap()
                            .len(),
                        256
                    );
                }
            });
        }
    });
}

fn assert_opaque_gcm(
    provider: &Pkcs11Provider,
    other: &Pkcs11Provider,
    session: &Session,
    native_aes: ObjectHandle,
    opaque: &Pkcs11AesKey,
    ciphertext: &[u8],
) {
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, opaque, ciphertext)
            .unwrap(),
        MESSAGE
    );
    assert!(
        opaque
            .decrypt_with_provider(other, DataEncryptionAlgorithm::Aes128Gcm, ciphertext)
            .is_err()
    );
    // Corrupt GCM must release no plaintext. Compare the exact native failure:
    // SoftHSM 2.6 SymDecrypt returns GENERAL_ERROR from decryptFinal, while 2.7
    // distinguishes ENCRYPTED_DATA_INVALID. Do not fabricate authentication
    // evidence from an opaque operational error or weaken this to is_err().
    // https://github.com/softhsm/SoftHSMv2/blob/2.6.1/src/lib/SoftHSM.cpp#L3071-L3076
    let mut corrupted = ciphertext.to_vec();
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
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, opaque, &corrupted)
            .unwrap_err(),
        expected
    );
    // An authentication/operation failure must not poison the next invocation.
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, opaque, ciphertext)
            .unwrap(),
        MESSAGE
    );
}

fn assert_opaque_cbc_and_unwrap(provider: &Pkcs11Provider, opaque: &Pkcs11AesKey, kek: &[u8]) {
    let cbc = RustCryptoProvider
        .encrypt_data(DataEncryptionAlgorithm::Aes128Cbc, kek, MESSAGE)
        .unwrap();
    assert_eq!(
        provider
            .decrypt_content_key(DataEncryptionAlgorithm::Aes128Cbc, opaque, &cbc)
            .unwrap(),
        MESSAGE
    );
    assert!(
        provider
            .decrypt_content_key(
                DataEncryptionAlgorithm::Aes128Cbc,
                opaque,
                &cbc[..cbc.len() - 1]
            )
            .is_err()
    );
    // Sharing the AES key family does not make CBC key encryption an
    // AES_KEY_WRAP mechanism. Refuse it before inspecting ciphertext or
    // dispatching to the token, rather than misreporting integrity failure.
    for cipher in [
        DataEncryptionAlgorithm::Aes128Cbc,
        DataEncryptionAlgorithm::Aes256Cbc,
    ] {
        let algorithm = KeyWrapAlgorithm::Cbc(cipher);
        assert!(!provider.supports(ProviderCapability::KeyUnwrap(algorithm)));
        assert!(matches!(
            provider
                .unwrap_content_key(opaque, algorithm, DataEncryptionAlgorithm::Aes128Gcm, &[],),
            Err(ProviderError::Unsupported { .. })
        ));
    }
    let wrapped = RustCryptoProvider
        .wrap_key(KeyWrapAlgorithm::AesKw128, kek, &CEK)
        .unwrap();
    let content = provider
        .unwrap_content_key(
            opaque,
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
}

/// AES-256 must use the same opaque boundary, not an AES-128-only shortcut.
fn assert_wide_aes(provider: &Pkcs11Provider, session: &Session) {
    let wide_kek = [0x53; 32];
    create_aes_key(
        session,
        8,
        &wide_kek,
        &[Attribute::Decrypt(true), Attribute::Unwrap(true)],
    );
    let wide = provider.aes_key(&[8]).unwrap();
    for algorithm in [
        DataEncryptionAlgorithm::Aes256Cbc,
        DataEncryptionAlgorithm::Aes256Gcm,
    ] {
        let cipher = RustCryptoProvider
            .encrypt_data(algorithm, &wide_kek, MESSAGE)
            .unwrap();
        assert_eq!(
            provider
                .decrypt_content_key(algorithm, &wide, &cipher)
                .unwrap(),
            MESSAGE
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
}

/// Token usage, not merely existence of the algorithm, gates signing.
fn assert_sign_usage_gate(provider: &Pkcs11Provider, session: &Session) {
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
            .sign(&denied, SignatureAlgorithm::RsaSha256, MESSAGE)
            .is_err()
    );
    assert!(provider.rsa_private_key(&[99]).is_err());
}

/// Exercise the public XML pipelines, not only the primitive provider calls.
fn assert_xmlenc_pipelines(provider: &Pkcs11Provider, kek: &[u8]) {
    let resolver =
        xml_sec::xmlenc::OpaqueContentKeyResolver::new(Arc::new(provider.aes_key(&[2]).unwrap()));
    let encrypted = xml_sec::xmlenc::EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(kek.to_vec())
        .encrypt_binary(MESSAGE)
        .unwrap();
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(MESSAGE.to_vec())
    );
    let recipient = xml_sec::xmlenc::EncryptionRecipient::aes_key_wrap(
        kek.to_vec(),
        KeyWrapAlgorithm::AesKw128,
    );
    let encrypted = xml_sec::xmlenc::EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(recipient)
        .encrypt_binary(MESSAGE)
        .unwrap();
    let resolver =
        xml_sec::xmlenc::OpaqueKekDecryptor::new(Arc::new(provider.aes_key(&[2]).unwrap()));
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(MESSAGE.to_vec())
    );
}

fn assert_token_oaep(
    provider: &Pkcs11Provider,
    private: &Arc<Pkcs11RsaKey>,
    public: &Pkcs11RsaKey,
) {
    use xml_sec::rsa_encoding::RsaPublicKeyEncoding as _;
    // Encrypting with a token public key is an explicit selection, with no software fallback.
    // SoftHSM exposes OAEP but rejects SHA-256 parameters; never retry with SHA-1.
    assert!(matches!(
        provider.transport_key(public, &xml_sec::xmlenc::RsaOaepParameters::default(), &CEK),
        Err(ProviderError::Unsupported { .. })
    ));
    let parameters = xml_sec::xmlenc::RsaOaepParameters::legacy();
    let wrapped = provider.transport_key(public, &parameters, &CEK).unwrap();
    // OAEP's fixed ciphertext width must not hide a mismatched recovered CEK.
    let wrong_width = provider
        .transport_key(public, &parameters, &[1; 24])
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
        .encrypt_binary(MESSAGE)
        .unwrap();
    let resolver = xml_sec::xmlenc::PrivateKeyDecryptor::provider_key(private.clone());
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .provider(provider)
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(MESSAGE.to_vec())
    );
}

/// Generates a derive-only EC pair on `curve` and returns its uncompressed point.
fn token_ec_point(session: &Session, curve: &[u8], id: u8, width: usize) -> Vec<u8> {
    use pkcs8::der::{Decode, asn1::OctetStringRef};
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
    point.to_vec()
}

fn assert_token_ecdh(provider: &Pkcs11Provider, other: &Pkcs11Provider, session: &Session) {
    // Both sides derive the same secret without reading either private scalar.
    for (curve, width, first_id) in [
        (&[6, 8, 42, 134, 72, 206, 61, 3, 1, 7][..], 32, 4),
        (&[6, 5, 43, 129, 4, 0, 34][..], 48, 6),
        (&[6, 5, 43, 129, 4, 0, 35][..], 66, 10),
    ] {
        let peers = [
            token_ec_point(session, curve, first_id, width),
            token_ec_point(session, curve, first_id + 1, width),
        ];
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
}

fn assert_object_selection(
    provider: &Pkcs11Provider,
    session: &Session,
    kek: &[u8],
    ciphertext: &[u8],
) {
    // Stale object handles are token errors, not authentication failures or retries.
    let stale = provider.aes_key(&[2]).unwrap();
    let object = session.find_objects(&[Attribute::Id(vec![2])]).unwrap()[0];
    session.destroy_object(object).unwrap();
    assert!(matches!(
        provider.decrypt_content_key(DataEncryptionAlgorithm::Aes128Gcm, &stale, ciphertext),
        Err(ProviderError::External(ExternalProviderError::Object))
    ));
    // A binary ID is a selector, not a unique-key guarantee. Never choose the
    // first matching object when a token contains duplicate persistent IDs.
    for _ in 0..2 {
        create_aes_key(session, 9, &[0; 16], &[]);
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
            .decrypt_data(DataEncryptionAlgorithm::Aes128Gcm, kek, ciphertext)
            .unwrap(),
        MESSAGE
    );
    assert!(matches!(
        provider.decrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &[0; 24], ciphertext),
        Err(ProviderError::InvalidKeySize {
            expected: 16,
            actual: 24
        })
    ));
}

#[test]
fn isolated_token_operations_and_failures() {
    // One disposable token carries every phase in order: later phases rely on
    // the object IDs created earlier and the final one destroys the AES key.
    let (module, slot, so, pin) = isolated_token();
    let provider = Pkcs11Provider::new(module, slot).unwrap();
    candidate_limits::assert_provider_candidate_limits(&provider);
    assert_provider_session_read_only(module, slot, &so);
    assert_login_and_digests(&provider, &pin);
    let session = module.open_rw_session(slot).unwrap();
    generate_rsa_pair(&session);
    let private = Arc::new(provider.rsa_private_key(&[1]).unwrap());
    let public = provider.rsa_public_key(&[1]).unwrap();
    assert_token_pss(&provider, &private, &public);
    let signed = token_signed_document(&provider, &private, &public);
    assert_token_key_receipt(&provider, &public, &signed);
    let other = Pkcs11Provider::new(module, slot).unwrap();
    assert_token_signatures(&provider, &other, &private, &public, &signed);
    let kek = [0x31; 16];
    let native_aes = create_aes_key(
        &session,
        2,
        &kek,
        &[Attribute::Unwrap(true), Attribute::Decrypt(true)],
    );
    let opaque = provider.aes_key(&[2]).unwrap();
    let ciphertext = RustCryptoProvider
        .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &kek, MESSAGE)
        .unwrap();
    assert_opaque_gcm(
        &provider,
        &other,
        &session,
        native_aes,
        &opaque,
        &ciphertext,
    );
    assert_opaque_cbc_and_unwrap(&provider, &opaque, &kek);
    assert_wide_aes(&provider, &session);
    assert_sign_usage_gate(&provider, &session);
    assert_xmlenc_pipelines(&provider, &kek);
    assert_token_oaep(&provider, &private, &public);
    assert_token_ecdh(&provider, &other, &session);
    assert_object_selection(&provider, &session, &kek, &ciphertext);
}
