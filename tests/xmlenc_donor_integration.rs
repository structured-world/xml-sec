//! XMLEnc decrypt interoperability against pinned xmlsec1 donor vectors.

#![cfg(feature = "xmlenc")]

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{AeadInOut, KeyInit},
};
use aes_kw::KwAes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rsa::RsaPrivateKey;
use xml_sec as roxmltree;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize, canonicalize_xml};
use xml_sec::rsa_encoding::RsaPrivateKeyEncoding as _;
use xml_sec::xmlenc::{
    DecryptContext, DecryptedContent, KekDecryptor, PrivateKeyDecryptor, SymmetricKeyDecryptor,
    XmlEncError, decrypt, decrypt_data, decrypt_document, parse_encrypted_data,
};
use xml_sec::{Document, ParsingOptions};

const VECTOR_DIR: &str = "tests/fixtures/xmlenc/aleksey-xmlenc-01";
const NIST_DIR: &str = "tests/fixtures/xmlenc/nist-aesgcm";
const INTEROP_DIR: &str = "tests/fixtures/xmlenc/xmlenc11-interop-2012";
const MERLIN_DIR: &str = "tests/fixtures/xmlenc/merlin-xmlenc-five";
const PHAOS_DIR: &str = "tests/fixtures/xmlenc/01-phaos-xmlenc-3";
const KEY_INVENTORY: &str = "tests/fixtures/keys/keys.xml";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorpusOutcome {
    Decrypted,
    Rejected,
    DocumentedDeparture,
}

thread_local! {
    // Only the complete-corpus acceptance runner enables collection. Isolated
    // nextest cases remain independent and do not communicate via shared state.
    static COMPLETED_VECTORS: std::cell::RefCell<Option<std::collections::BTreeMap<String, CorpusOutcome>>> = const { std::cell::RefCell::new(None) };
}

fn completed_vector(directory: &str, name: &str, outcome: CorpusOutcome) {
    COMPLETED_VECTORS.with(|completed| {
        if let Some(completed) = completed.borrow_mut().as_mut() {
            let path = format!("{directory}/{name}.xml");
            assert!(Path::new(&path).is_file(), "stale executed vector: {path}");
            assert!(
                completed.insert(path.clone(), outcome).is_none(),
                "duplicate vector classification: {path}"
            );
        }
    });
}

fn assert_surplus_cek_plaintext(xml: &str, name: &str, recovered: &[u8]) {
    use xml_sec::provider::{CryptoProvider as _, RUST_CRYPTO_PROVIDER};
    // The public path already rejected the surplus CEK. This independent
    // primitive comparison documents the donor's truncation without adding
    // that fallback to public decryption or calling it positive API parity.
    let parsed = parse_encrypted_data(xml).unwrap();
    let algorithm = xml_sec::xmlenc::DataEncryptionAlgorithm::Aes128Gcm;
    assert_eq!(parsed.encryption_method.algorithm, algorithm.uri());
    let xml_sec::xmlenc::CipherData::Value { value } = parsed.cipher_data else {
        panic!("{name}: expected inline ciphertext")
    };
    let actual = RUST_CRYPTO_PROVIDER
        .decrypt_data(
            algorithm,
            &recovered[..16],
            &STANDARD.decode(value).unwrap(),
        )
        .unwrap();
    let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    assert_eq!(
        canonicalize_xml(&actual, &c14n).unwrap(),
        canonicalize_xml(&expected, &c14n).unwrap(),
        "{name}: donor plaintext under surplus-key truncation"
    );
}

#[test]
fn camellia_donor_algorithms_are_recognized() {
    // Complete corpus acceptance requires all three content and wrapping
    // widths; recognizing just the 128-bit happy path loses donor coverage.
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm};
    for bits in [128, 192, 256] {
        let content = format!("http://www.w3.org/2001/04/xmldsig-more#camellia{bits}-cbc");
        let wrapping = format!("http://www.w3.org/2001/04/xmldsig-more#kw-camellia{bits}");
        assert_eq!(
            DataEncryptionAlgorithm::from_uri(&content)
                .unwrap()
                .key_len(),
            bits / 8
        );
        assert_eq!(
            KeyWrapAlgorithm::from_uri(&wrapping).unwrap().key_len(),
            bits / 8
        );
    }
}

#[test]
fn chacha_donor_parameters_survive_parsing() {
    // The nonce belongs to EncryptionMethod, not the ciphertext prefix.
    // Parsing must retain parameters before a key resolver can be invoked.
    use xml_sec::xmlenc::DataEncryptionAlgorithm;
    for name in ["chacha20", "chacha20poly1305"] {
        let uri = format!("http://www.w3.org/2021/04/xmldsig-more#{name}");
        assert_eq!(
            DataEncryptionAlgorithm::from_uri(&uri).unwrap().key_len(),
            32
        );
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/enc-{name}-keyname.xml")).unwrap();
        parse_encrypted_data(&xml).unwrap();
    }
}

#[test]
fn decrypts_every_chacha_donor_vector_and_authenticates_aad() {
    use xml_sec::key_manager::SymmetricKeyKind;
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{ChaChaParameters, DataEncryptionAlgorithm as D};
    // Independently produced ciphertext verifies nonce placement, little-endian
    // counter handling, AAD encoding and appended tag framing together.
    let policy = DecryptionPolicy {
        data_algorithms: Some([D::ChaCha20, D::ChaCha20Poly1305].into()),
        ..DecryptionPolicy::default()
    };
    for (name, key_name) in [
        ("enc-chacha20-keyname", "test-chacha20"),
        ("enc-chacha20-keyname-missing-nonce", "test-chacha20"),
        ("enc-chacha20poly1305-keyname", "test-chacha20poly1305"),
        (
            "enc-chacha20poly1305-keyname-missing-nonce",
            "test-chacha20poly1305",
        ),
        ("enc-chacha20poly1305-aad-keyname", "test-chacha20poly1305"),
    ] {
        let key = std::fs::read(format!("{VECTOR_DIR}/{key_name}.bin")).unwrap();
        let resolver = SymmetricKeyDecryptor::with_kind(key, SymmetricKeyKind::ChaCha20);
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let context = DecryptContext::new(&resolver).policy(policy.clone());
        // These two donor files are deliberate decryption failures, not the
        // encryption result of the similarly named template. The pinned
        // oracle also refuses them; a decryptor must not invent a nonce.
        if name.ends_with("missing-nonce") {
            assert!(matches!(
                context.decrypt(&xml),
                Err(XmlEncError::MissingRequired("ChaCha Nonce"))
            ));
            completed_vector(VECTOR_DIR, name, CorpusOutcome::Rejected);
            continue;
        }
        assert_eq!(
            context.decrypt(&xml).unwrap(),
            DecryptedContent::Bytes(std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap()),
            "{name}"
        );
        let mut parsed = parse_encrypted_data(&xml).unwrap();
        parsed.encryption_method.chacha.as_mut().unwrap().nonce = None;
        assert!(matches!(
            context.decrypt_data(&parsed),
            Err(XmlEncError::MissingRequired("ChaCha Nonce"))
        ));
        if name.contains("aad") {
            parsed.encryption_method.chacha = Some(ChaChaParameters {
                aad: Some("tampered AAD".into()),
                ..parse_encrypted_data(&xml)
                    .unwrap()
                    .encryption_method
                    .chacha
                    .unwrap()
            });
            assert!(matches!(
                context.decrypt_data(&parsed),
                Err(XmlEncError::AeadAuthenticationFailed)
            ));
        }
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[test]
fn decrypts_all_direct_camellia_donor_widths() {
    // Donor ciphertext, not a self-roundtrip, verifies padding, IV framing,
    // key-family selection and the complete binary plaintext.
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::DataEncryptionAlgorithm as D;
    use xml_sec::xmlenc::KeyWrapAlgorithm as W;
    use xml_sec::{
        XmlBackend,
        key_manager::{KeyInventory, SymmetricKeyKind},
    };
    let policy = DecryptionPolicy {
        data_algorithms: Some([D::Camellia128Cbc, D::Camellia192Cbc, D::Camellia256Cbc].into()),
        key_wrap_algorithms: Some(
            [
                W::CamelliaKw128,
                W::CamelliaKw192,
                W::CamelliaKw256,
                W::Cbc(D::Camellia256Cbc),
            ]
            .into(),
        ),
        ..DecryptionPolicy::default()
    };
    let key_xml = std::fs::read_to_string(KEY_INVENTORY).unwrap();
    let key_document = Document::parse(&key_xml).unwrap();
    // Import the relevant family without activating unrelated DES/DSA
    // capabilities required by other entries in the shared donor store.
    let mut scoped_keys = String::from("<Keys xmlns='http://www.aleksey.com/xmlsec/2002'>");
    for entry in key_document
        .root_element()
        .children()
        .filter(|node| node.is_element())
    {
        if entry.descendants().any(|node| {
            node.has_tag_name(("http://www.aleksey.com/xmlsec/2002", "CamelliaKeyValue"))
        }) {
            scoped_keys.push_str(&key_xml[entry.range()]);
        }
    }
    scoped_keys.push_str("</Keys>");
    let inventory =
        KeyInventory::from_xml_bytes(scoped_keys.as_bytes(), &policy, XmlBackend::default())
            .unwrap();
    for bits in [128, 192, 256] {
        let name = format!("enc-camellia{bits}cbc-keyname");
        let key = inventory
            .symmetric_keys()
            .iter()
            .find(|key| key.name == format!("test-camellia{bits}"))
            .unwrap();
        assert_eq!(key.kind, SymmetricKeyKind::Camellia);
        let resolver = SymmetricKeyDecryptor::with_kind(key.bytes.to_vec(), key.kind);
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        assert!(matches!(
            DecryptContext::new(&resolver).decrypt(&xml),
            Err(XmlEncError::Policy(_))
        ));
        assert_eq!(
            DecryptContext::new(&resolver)
                .policy(policy.clone())
                .decrypt(&xml)
                .unwrap(),
            DecryptedContent::Bytes(std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap())
        );
        let wrong_family = SymmetricKeyDecryptor::new(key.bytes.to_vec());
        assert!(matches!(
            DecryptContext::new(&wrong_family)
                .policy(policy.clone())
                .decrypt(&xml),
            Err(XmlEncError::KeyNotFound)
        ));
        completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
        // The wrapped vectors use Camellia-128 content with each of the
        // three KEK widths. Inspect the parsed URI rather than inferring a
        // key width from the content algorithm or the filename.
        let name = format!("enc-camellia128cbc-kw-camellia{bits}-keyname");
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let resolver = KekDecryptor::with_kind(key.bytes.to_vec(), key.kind);
        assert_eq!(
            DecryptContext::new(&resolver)
                .policy(policy.clone())
                .decrypt(&xml)
                .unwrap(),
            DecryptedContent::Bytes(std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap())
        );
        completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
    }
}

#[test]
fn camellia_key_wrap_preserves_integrity_for_all_widths() {
    // RFC 9231 §2.6.3 substitutes the block primitive, not the integrity
    // contract. Altering either the register or wrapped body must fail closed.
    use xml_sec::provider::{CryptoProvider, ProviderError, RUST_CRYPTO_PROVIDER};
    use xml_sec::xmlenc::KeyWrapAlgorithm as W;
    for algorithm in [W::CamelliaKw128, W::CamelliaKw192, W::CamelliaKw256] {
        let kek = vec![0x42; algorithm.key_len()];
        let key = [0x37; 32];
        let wrapped = RUST_CRYPTO_PROVIDER
            .wrap_key(algorithm, &kek, &key)
            .unwrap();
        assert_eq!(wrapped.len(), 40);
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(algorithm, &kek, &wrapped)
                .unwrap(),
            key
        );
        for offset in [0, 8, 39] {
            let mut altered = wrapped.clone();
            altered[offset] ^= 1;
            assert!(matches!(
                RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, &kek, &altered),
                Err(ProviderError::AuthenticationFailed)
            ));
        }
    }
}

#[test]
fn cbc_encrypted_keys_enforce_framing_without_claiming_integrity() {
    use xml_sec::provider::{
        CryptoProvider, ProviderError, ProviderInputError, RUST_CRYPTO_PROVIDER,
    };
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, KeyWrapAlgorithm as W};

    // XMLEnc 1.1 sections 3.4 and 5.2 use ordinary CBC EncryptedType
    // framing for these EncryptedKeys, not RFC 3394 integrity wrapping.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-EncryptedKey
    // Check every enabled block primitive and KEK width. A modified IV
    // changes key bytes without invalidating padding: do not advertise
    // authenticated wrapping or require false tamper rejection from CBC.
    for (cipher, block) in [
        (D::Aes128Cbc, 16),
        (D::Aes256Cbc, 16),
        (D::Camellia128Cbc, 16),
        (D::Camellia192Cbc, 16),
        (D::Camellia256Cbc, 16),
        #[cfg(feature = "legacy-algorithms")]
        (D::Aes192Cbc, 16),
        #[cfg(feature = "legacy-algorithms")]
        (D::TripleDesCbc, 8),
    ] {
        let algorithm = W::Cbc(cipher);
        let kek = vec![0x42; algorithm.key_len()];
        let key = [0x37; 32];
        let wrapped = RUST_CRYPTO_PROVIDER
            .wrap_key(algorithm, &kek, &key)
            .unwrap();
        assert_eq!(wrapped.len(), key.len() + 2 * block, "{cipher:?}");
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(algorithm, &kek, &wrapped)
                .unwrap(),
            key
        );
        for length in [0, algorithm.key_len() - 1, algorithm.key_len() + 1] {
            assert_eq!(
                RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, &vec![0; length], &wrapped),
                Err(ProviderError::InvalidKeySize {
                    expected: algorithm.key_len(),
                    actual: length
                }),
                "{cipher:?}: KEK width",
            );
        }
        for length in [0, block, wrapped.len() - 1] {
            assert_eq!(
                RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, &kek, &wrapped[..length]),
                Err(ProviderError::InvalidInput(
                    ProviderInputError::AesCbcFraming
                )),
                "{cipher:?}: ciphertext framing",
            );
        }
        let mut invalid_padding = wrapped.clone();
        // A block-aligned key has a full padding block. Alter its previous
        // ciphertext block so the final padding-length octet becomes zero.
        let previous_last = invalid_padding.len() - block - 1;
        invalid_padding[previous_last] ^= block as u8;
        assert_eq!(
            RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, &kek, &invalid_padding),
            Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcCiphertext
            )),
            "{cipher:?}: invalid padding",
        );
        let mut altered_iv = wrapped;
        altered_iv[0] ^= 1;
        let mut altered_key = key;
        altered_key[0] ^= 1;
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(algorithm, &kek, &altered_iv)
                .unwrap(),
            altered_key,
            "{cipher:?}: unauthenticated IV",
        );
    }
}

#[test]
fn sha224_oaep_digest_and_mgf_are_recognized() {
    // XML Encryption 1.1 §5.5.2 includes MGF1-SHA224; its digest and
    // independently selected mask hash must survive parsing and serialization.
    use xml_sec::xmlenc::OaepDigestAlgorithm;
    let digest =
        OaepDigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#sha224").unwrap();
    assert_eq!(
        OaepDigestAlgorithm::from_mgf_uri("http://www.w3.org/2009/xmlenc11#mgf1sha224"),
        Some(digest)
    );
    assert_eq!(
        digest.mgf_uri(),
        Some("http://www.w3.org/2009/xmlenc11#mgf1sha224")
    );
}

#[test]
fn decrypts_ecdh_concat_hashes_with_the_pinned_recipient_keys() {
    use pkcs8::DecodePrivateKey as _;
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::provider::{CryptoProvider, EcdhCurve, RUST_CRYPTO_PROVIDER, RustCryptoEcdhKey};
    use xml_sec::xmldsig::{
        DigestAlgorithm,
        parse::{KeyInfo, KeyInfoSource},
    };
    use xml_sec::xmlenc::{
        AgreementDecryptor, AgreementMethod, CipherData, KeyEstablishmentBudget, KeyWrapAlgorithm,
        parse_key_derivation_method,
    };
    // The runner selects the second recipient key, not the first originator
    // key. All nine hash families must derive the donor's actual wrapping key.
    let import = |party: &str| {
        let name = if party == "second" {
            "ec-prime256v1-second-key"
        } else {
            "ec-prime256v1-key"
        };
        let encrypted =
            std::fs::read(format!("tests/fixtures/xmlenc/keys/ec/{name}.p8-der")).unwrap();
        let plain = pkcs8::EncryptedPrivateKeyInfoRef::try_from(encrypted.as_slice())
            .unwrap()
            .decrypt("secret123")
            .unwrap();
        let key = p256::SecretKey::from_pkcs8_der(plain.as_bytes()).unwrap();
        RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &key.to_bytes()).unwrap()
    };
    let recipient = import("second");
    let originator = import("first");
    let peer = originator.public_key();
    let policy = DecryptionPolicy::default();
    for (name, digest) in [
        ("sha1", DigestAlgorithm::Sha1),
        ("sha224", DigestAlgorithm::Sha224),
        ("sha256", DigestAlgorithm::Sha256),
        ("sha384", DigestAlgorithm::Sha384),
        ("sha512", DigestAlgorithm::Sha512),
        ("sha3_224", DigestAlgorithm::Sha3_224),
        ("sha3_256", DigestAlgorithm::Sha3_256),
        ("sha3_384", DigestAlgorithm::Sha3_384),
        ("sha3_512", DigestAlgorithm::Sha3_512),
    ] {
        let mut policy = policy.clone();
        policy.key_establishment.digest_algorithms =
            Some(std::collections::HashSet::from([digest]));
        let name = format!("enc_ecdh_p256_concatkdf_{name}_kw_aes256_aes128gcm");
        let descriptor = format!(
            "<x:KeyDerivationMethod xmlns:x='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2009/xmlenc11#ConcatKDF'><x:ConcatKDFParams AlgorithmID='00123456' PartyUInfo='00123456' PartyVInfo='00123456'><d:DigestMethod xmlns:d='http://www.w3.org/2000/09/xmldsig#' Algorithm='{}'/></x:ConcatKDFParams></x:KeyDerivationMethod>",
            digest.uri()
        );
        let role = |name: &str| {
            let mut info = KeyInfo::default();
            info.sources.push(KeyInfoSource::KeyName(name.into()));
            Some(info)
        };
        let method = AgreementMethod {
            algorithm: xml_sec::policy::KeyAgreementAlgorithm::EcdhEs,
            method: Some(parse_key_derivation_method(&descriptor, &policy).unwrap()),
            nonce: Vec::new(),
            legacy_digest: None,
            originator: role("originator-key-name"),
            recipient: role("recipient-key-name"),
        };
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let resolver =
            AgreementDecryptor::wrapping(&method, &recipient, &peer, KeyWrapAlgorithm::AesKw256);
        // Like the pinned X448 Concat recipes, these vectors wrap a 32-byte
        // session key for an AES-128 content URI. Preserve the exact-width
        // product invariant rather than silently truncating surplus bytes.
        assert!(
            matches!(
                DecryptContext::new(&resolver)
                    .policy(policy.clone())
                    .decrypt_document(&xml, None),
                Err(XmlEncError::InvalidWrappedKeyLength {
                    expected: 24,
                    actual: 40
                })
            ),
            "{name}"
        );
        let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
        let kek = method
            .derive_key(
                KeyWrapAlgorithm::AesKw256.uri(),
                32,
                &recipient,
                &peer,
                &RUST_CRYPTO_PROVIDER,
                &mut budget,
            )
            .unwrap();
        let parsed = parse_encrypted_data(&xml).unwrap();
        let CipherData::Value { value } = &parsed.encrypted_keys[0].cipher_data else {
            panic!("expected donor CipherValue")
        };
        let recovered = zeroize::Zeroizing::new(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(
                    KeyWrapAlgorithm::AesKw256,
                    &kek,
                    &STANDARD.decode(value).unwrap(),
                )
                .unwrap(),
        );
        assert_eq!(recovered.len(), 32, "{name}");
        assert_surplus_cek_plaintext(&xml, &name, &recovered);
        completed_vector(VECTOR_DIR, &name, CorpusOutcome::DocumentedDeparture);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_ecdh_p384_and_p521_donor_plaintexts() {
    use pkcs8::DecodePrivateKey as _;
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::provider::{EcdhCurve, RustCryptoEcdhKey};
    use xml_sec::xmlenc::{AgreementDecryptor, KeyWrapAlgorithm};

    // These donor recipes use matching CEK/content widths. Require the whole
    // public pipeline to return exact plaintext, not merely a successful KDF.
    for (curve, stem, name, wrap) in [
        (
            EcdhCurve::P384,
            "ec-prime384v1",
            "enc_ecdh_p384_concatkdf_sha384_kw_aes192_aes192gcm",
            KeyWrapAlgorithm::AesKw192,
        ),
        (
            EcdhCurve::P521,
            "ec-prime521v1",
            "enc_ecdh_p521_concatkdf_sha512_kw_aes256_aes256gcm",
            KeyWrapAlgorithm::AesKw256,
        ),
    ] {
        let import = |suffix: &str| {
            let encrypted = std::fs::read(format!(
                "tests/fixtures/xmlenc/keys/ec/{stem}{suffix}-key.p8-der"
            ))
            .expect("pinned EC private key");
            let plain = pkcs8::EncryptedPrivateKeyInfoRef::try_from(encrypted.as_slice())
                .expect("encrypted PKCS8")
                .decrypt("secret123")
                .expect("fixture password");
            let scalar = match curve {
                EcdhCurve::P384 => p384::SecretKey::from_pkcs8_der(plain.as_bytes())
                    .expect("P384 private key")
                    .to_bytes()
                    .to_vec(),
                EcdhCurve::P521 => p521::SecretKey::from_pkcs8_der(plain.as_bytes())
                    .expect("P521 private key")
                    .to_bytes()
                    .to_vec(),
                _ => unreachable!("only the two declared curves"),
            };
            let scalar = zeroize::Zeroizing::new(scalar);
            RustCryptoEcdhKey::from_scalar(curve, &scalar).expect("EC agreement key")
        };
        let recipient = import("-second");
        let originator = import("");
        let peer = originator.public_key();
        let xml =
            std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).expect("donor ciphertext");
        let expected =
            std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.data")).expect("donor plaintext");
        // Type=Element encrypts the root element, not the XML declaration or
        // trailing document newline. Compare its complete original source span.
        let expected_doc = Document::parse(&expected).expect("donor plaintext document");
        let expected_element = &expected[expected_doc.root_element().range()];
        let policy = DecryptionPolicy {
            data_algorithms: Some(
                [
                    xml_sec::xmlenc::DataEncryptionAlgorithm::Aes192Gcm,
                    xml_sec::xmlenc::DataEncryptionAlgorithm::Aes256Gcm,
                ]
                .into(),
            ),
            key_wrap_algorithms: Some(
                [KeyWrapAlgorithm::AesKw192, KeyWrapAlgorithm::AesKw256].into(),
            ),
            ..DecryptionPolicy::default()
        };
        let document = Document::parse(&xml).expect("donor document");
        let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(
            document.root_element(),
            &policy,
        )
        .expect("donor agreement metadata");
        let method = &parsed.encrypted_keys[0].sources.agreement_methods[0];
        let resolver = AgreementDecryptor::wrapping(method, &recipient, &peer, wrap);
        assert_eq!(
            DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt(&xml)
                .expect("complete donor ECDH decrypt"),
            DecryptedContent::Xml(expected_element.into()),
            "{name}"
        );
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[test]
fn decrypts_ecdh_hkdf_and_pbkdf2_donor_plaintexts() {
    use pkcs8::DecodePrivateKey as _;
    use xml_sec::provider::{
        CryptoProvider as _, EcdhCurve, RUST_CRYPTO_PROVIDER, RustCryptoEcdhKey,
    };
    use xml_sec::xmlenc::{AgreementDecryptor, KeyWrapAlgorithm};
    // Independently produced ECDH KDF vectors exercise the complete pipeline;
    // the public path never inherits the donor's surplus-key truncation.
    let import = |suffix: &str| {
        let encrypted = std::fs::read(format!(
            "tests/fixtures/xmlenc/keys/ec/ec-prime256v1{suffix}-key.p8-der"
        ))
        .expect("pinned P256 key");
        let plain = pkcs8::EncryptedPrivateKeyInfoRef::try_from(encrypted.as_slice())
            .expect("encrypted PKCS8")
            .decrypt("secret123")
            .expect("fixture password");
        let key = p256::SecretKey::from_pkcs8_der(plain.as_bytes()).expect("P256 private key");
        RustCryptoEcdhKey::from_scalar(EcdhCurve::P256, &key.to_bytes()).expect("agreement key")
    };
    let recipient = import("-second");
    let originator = import("");
    let peer = originator.public_key();
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.key_establishment.digest_algorithms = Some(
        [
            xml_sec::xmldsig::DigestAlgorithm::Sha1,
            xml_sec::xmldsig::DigestAlgorithm::Sha224,
            xml_sec::xmldsig::DigestAlgorithm::Sha256,
            xml_sec::xmldsig::DigestAlgorithm::Sha384,
            xml_sec::xmldsig::DigestAlgorithm::Sha512,
        ]
        .into(),
    );
    for name in [
        "enc_ecdh_p256_hkdf_sha256_kw_aes256_aes128gcm",
        "enc_ecdh_p256_hkdf_sha384_kw_aes256_aes128gcm",
        "enc_ecdh_p256_hkdf_sha512_kw_aes256_aes128gcm",
        "enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm",
        "enc_ecdh_p256_pbkdf2_1000_hmac_sha224_kw_aes256_aes128gcm",
        "enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm",
        "enc_ecdh_p256_pbkdf2_1000_hmac_sha384_kw_aes256_aes128gcm",
        "enc_ecdh_p256_pbkdf2_1000_hmac_sha512_kw_aes256_aes128gcm",
    ] {
        let xml =
            std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).expect("donor ciphertext");
        let expected =
            std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.data")).expect("donor plaintext");
        let document = Document::parse(&expected).expect("donor plaintext XML");
        let expected_element = &expected[document.root_element().range()];
        let parsed = parse_encrypted_data(&xml).expect("donor agreement metadata");
        let method = &parsed.encrypted_keys[0].sources.agreement_methods[0];
        let resolver =
            AgreementDecryptor::wrapping(method, &recipient, &peer, KeyWrapAlgorithm::AesKw256);
        let result = DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt(&xml);
        if name.contains("pbkdf2") {
            // The pinned testEnc.sh requests a 256-bit session key for an
            // AES-128-GCM template. Do not copy its implicit truncation into
            // the public API; prove the KDF/unwrap independently below.
            assert!(
                matches!(
                    result,
                    Err(XmlEncError::InvalidWrappedKeyLength {
                        expected: 24,
                        actual: 40
                    })
                ),
                "{name}: {result:?}"
            );
            let mut budget =
                xml_sec::xmlenc::KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
            let kek = method
                .derive_key(
                    KeyWrapAlgorithm::AesKw256.uri(),
                    32,
                    &recipient,
                    &peer,
                    &RUST_CRYPTO_PROVIDER,
                    &mut budget,
                )
                .unwrap();
            let xml_sec::xmlenc::CipherData::Value { value } =
                &parsed.encrypted_keys[0].cipher_data
            else {
                panic!("donor CipherValue")
            };
            let wrapped = STANDARD.decode(value).unwrap();
            let recovered = zeroize::Zeroizing::new(
                RUST_CRYPTO_PROVIDER
                    .unwrap_key(KeyWrapAlgorithm::AesKw256, &kek, &wrapped)
                    .unwrap(),
            );
            assert_eq!(recovered.len(), 32);
            let xml_sec::xmlenc::CipherData::Value { value } = &parsed.cipher_data else {
                panic!("donor content CipherValue")
            };
            let ciphertext = STANDARD.decode(value).unwrap();
            // This primitive-only comparison documents exactly what the donor
            // truncated; it never makes the invalid public input acceptable.
            assert_eq!(
                RUST_CRYPTO_PROVIDER
                    .decrypt_data(
                        xml_sec::xmlenc::DataEncryptionAlgorithm::Aes128Gcm,
                        &recovered[..16],
                        &ciphertext
                    )
                    .unwrap(),
                expected_element.as_bytes(),
                "{name}"
            );
            completed_vector(VECTOR_DIR, name, CorpusOutcome::DocumentedDeparture);
            continue;
        }
        assert_eq!(
            result.expect("complete ECDH KDF decrypt"),
            DecryptedContent::Xml(expected_element.into()),
            "{name}"
        );
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[test]
fn decrypts_direct_pbkdf2_and_hkdf_donor_plaintexts() {
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, DerivedKeyDecryptor, DerivedKeyInput};
    // Independent encrypted descriptors exercise transported PRF, salt,
    // iteration count and MasterKeyName before authenticated content delivery.
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.key_establishment.digest_algorithms = Some(
        [
            xml_sec::xmldsig::DigestAlgorithm::Sha1,
            xml_sec::xmldsig::DigestAlgorithm::Sha224,
            xml_sec::xmldsig::DigestAlgorithm::Sha256,
            xml_sec::xmldsig::DigestAlgorithm::Sha384,
            xml_sec::xmldsig::DigestAlgorithm::Sha512,
        ]
        .into(),
    );
    for kdf in ["pbkdf2", "hkdf"] {
        let secret =
            zeroize::Zeroizing::new(std::fs::read(format!("{VECTOR_DIR}/{kdf}-ikm.bin")).unwrap());
        for hash in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
            let name = format!("enc_{kdf}_hmac_{hash}_aes256gcm");
            let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
            let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
            let parsed = parse_encrypted_data(&xml).unwrap();
            let descriptor = &parsed.derived_keys[0];
            let method = descriptor.method.as_ref().expect("explicit donor KDF");
            let master_name = format!("{kdf}-ikm");
            let resolver = DerivedKeyDecryptor::content(
                method,
                DerivedKeyInput::Secret(&secret),
                D::Aes256Gcm,
            )
            .master_key_name(&master_name);
            let context = DecryptContext::new(&resolver).policy(policy.clone());
            assert_eq!(
                context
                    .decrypt(&xml)
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                DecryptedContent::Bytes(expected),
                "{name}"
            );
            let wrong_secret = b"not the donor credential";
            let wrong = DerivedKeyDecryptor::content(
                method,
                DerivedKeyInput::Secret(wrong_secret),
                D::Aes256Gcm,
            )
            .master_key_name(&master_name);
            assert!(
                matches!(
                    DecryptContext::new(&wrong)
                        .policy(policy.clone())
                        .decrypt(&xml),
                    Err(XmlEncError::AeadAuthenticationFailed)
                ),
                "{name}"
            );
            completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
        }
    }
}

#[test]
fn decrypts_hkdf_with_only_the_prf_parameter() {
    // Omitted salt/info/output length must use the specified HKDF defaults,
    // not require the fully populated descriptors used by the other vectors.
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, DerivedKeyDecryptor, DerivedKeyInput};
    let name = "enc_hkdf_prf_only_aes256gcm";
    let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
    let secret =
        zeroize::Zeroizing::new(std::fs::read(format!("{VECTOR_DIR}/hkdf-ikm.bin")).unwrap());
    let parsed = parse_encrypted_data(&xml).unwrap();
    let method = parsed.derived_keys[0].method.as_ref().unwrap();
    let resolver = DerivedKeyDecryptor::content(
        method,
        DerivedKeyInput::Secret(&secret),
        DataEncryptionAlgorithm::Aes256Gcm,
    )
    .master_key_name("hkdf-ikm");
    assert_eq!(
        DecryptContext::new(&resolver).decrypt(&xml).unwrap(),
        DecryptedContent::Bytes(std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap()),
    );
    completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
}

#[test]
fn decrypts_dh_es_concatkdf_with_pinned_domain_and_parties() {
    use der::{Decode as _, Reader as _, asn1::UintRef};
    use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
    use xml_sec::provider::{RUST_CRYPTO_PROVIDER, RustCryptoDhKey};
    use xml_sec::xmlenc::{AgreementDecryptor, KeyEstablishmentBudget, KeyWrapAlgorithm};

    // RFC 5114 domain parameters and both party keys are fixed independent
    // credentials; untrusted AgreementMethod never selects the private key.
    let directory = "tests/fixtures/xmlenc/keys/dhx";
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(format!("{directory}/dhx-rfc5114-3-second-key.p8-der")).unwrap(),
    );
    let plain = pkcs8::EncryptedPrivateKeyInfoRef::try_from(bytes.as_slice())
        .unwrap()
        .decrypt("secret123")
        .unwrap();
    let info = pkcs8::PrivateKeyInfoRef::try_from(plain.as_bytes()).unwrap();
    let (p, g, q) = info
        .algorithm
        .parameters
        .unwrap()
        .sequence(|reader| -> der::Result<_> {
            let p: UintRef<'_> = reader.decode()?;
            let g: UintRef<'_> = reader.decode()?;
            let q: UintRef<'_> = reader.decode()?;
            Ok((p, g, q))
        })
        .unwrap();
    let private = UintRef::from_der(info.private_key.as_bytes()).unwrap();
    let public_bytes =
        std::fs::read(format!("{directory}/dhx-rfc5114-3-first-pubkey.der")).unwrap();
    let public_info = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(&public_bytes).unwrap();
    assert_eq!(info.algorithm, public_info.algorithm);
    let peer = UintRef::from_der(public_info.subject_public_key.as_bytes().unwrap()).unwrap();
    let mut policy = DecryptionPolicy::default();
    policy.key_establishment.agreement_algorithms = Some([KeyAgreementAlgorithm::DhEs].into());
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    let key = RustCryptoDhKey::from_components(
        &RUST_CRYPTO_PROVIDER,
        &mut budget,
        p.as_bytes(),
        q.as_bytes(),
        g.as_bytes(),
        private.as_bytes(),
    )
    .unwrap();
    let name = "enc_dh_concatkdf_sha256_kw_aes128_aes128gcm";
    let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
    let parsed = parse_encrypted_data(&xml).unwrap();
    let method = &parsed.encrypted_keys[0].sources.agreement_methods[0];
    let resolver =
        AgreementDecryptor::wrapping(method, &key, peer.as_bytes(), KeyWrapAlgorithm::AesKw128);
    let actual = DecryptContext::new(&resolver)
        .policy(policy)
        .decrypt_document(&xml, None)
        .unwrap();
    let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    assert_eq!(
        canonicalize_xml(actual.as_bytes(), &c14n).unwrap(),
        canonicalize_xml(&expected, &c14n).unwrap()
    );
    completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
}

#[test]
fn classifies_all_pinned_xdh_concat_and_hkdf_vectors() {
    use der::Decode as _;
    use std::collections::HashSet;
    use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
    use xml_sec::provider::{
        CryptoProvider, KeyAgreementKey, RUST_CRYPTO_PROVIDER, RustCryptoX448Key,
        RustCryptoX25519Key,
    };
    use xml_sec::xmldsig::parse::{KeyInfo, KeyInfoSource};
    use xml_sec::xmlenc::{
        AgreementDecryptor, AgreementMethod, KeyWrapAlgorithm, parse_key_derivation_method,
    };
    // Donor-produced ciphertext proves X448, both KDF families, AES-KW and
    // Element replacement interoperate; generated self-roundtrips cannot.
    for (curve, algorithm) in [
        ("x25519", KeyAgreementAlgorithm::X25519),
        ("x448", KeyAgreementAlgorithm::X448),
    ] {
        let decode = |bytes: &[u8]| -> (Box<dyn KeyAgreementKey>, Vec<u8>) {
            if algorithm == KeyAgreementAlgorithm::X448 {
                let key = RustCryptoX448Key::from_pkcs8_der(bytes).unwrap();
                let public = key.public_key().to_vec();
                (Box::new(key), public)
            } else {
                // RFC 8410 sections 3 and 7: absent parameters and an inner
                // CurvePrivateKey OCTET STRING, not raw PKCS#8 wrapper bytes.
                // https://www.rfc-editor.org/rfc/rfc8410.html#section-7
                let info = pkcs8::PrivateKeyInfoRef::try_from(bytes).unwrap();
                assert_eq!(
                    info.algorithm.oid,
                    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110")
                );
                assert!(info.algorithm.parameters.is_none());
                let inner =
                    <&der::asn1::OctetStringRef>::from_der(info.private_key.as_bytes()).unwrap();
                let key = RustCryptoX25519Key::from_bytes(inner.as_bytes().try_into().unwrap());
                let public = key.public_key().to_vec();
                (Box::new(key), public)
            }
        };
        let import = |party: &str| {
            let encrypted = std::fs::read(format!(
                "tests/fixtures/xmlenc/keys/xdh/xdh-{curve}-{party}-key.p8-der"
            ))
            .unwrap();
            let plain = pkcs8::EncryptedPrivateKeyInfoRef::try_from(encrypted.as_slice())
                .unwrap()
                .decrypt("secret123")
                .unwrap();
            let key = decode(plain.as_bytes());
            let unprotected = std::fs::read(format!(
                "tests/fixtures/xmlenc/keys/xdh/xdh-{curve}-{party}-key.der"
            ))
            .unwrap();
            assert_eq!(key.1, decode(&unprotected).1);
            key
        };
        let (_originator, peer) = import("first");
        let (recipient, _recipient_public) = import("second");
        let mut policy = DecryptionPolicy::default();
        policy.key_establishment.agreement_algorithms = Some(HashSet::from([algorithm]));
        for (family, hash) in [
            ("concatkdf", "sha256"),
            ("concatkdf", "sha384"),
            ("hkdf", "sha256"),
            ("hkdf", "sha384"),
            ("hkdf", "sha512"),
        ] {
            let name = format!("enc_xdh_{curve}_{family}_{hash}_kw_aes256_aes128gcm");
            // Expectations come from the donor test recipe, not from the message.
            let method_xml = if family == "concatkdf" {
                let hash_uri = if hash == "sha256" {
                    "http://www.w3.org/2001/04/xmlenc#sha256"
                } else {
                    "http://www.w3.org/2001/04/xmldsig-more#sha384"
                };
                format!(
                    "<x:KeyDerivationMethod xmlns:x='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2009/xmlenc11#ConcatKDF'><x:ConcatKDFParams AlgorithmID='00123456' PartyUInfo='00123456' PartyVInfo='00123456'><d:DigestMethod xmlns:d='http://www.w3.org/2000/09/xmldsig#' Algorithm='{hash_uri}'/></x:ConcatKDFParams></x:KeyDerivationMethod>"
                )
            } else {
                format!(
                    "<x:KeyDerivationMethod xmlns:x='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2021/04/xmldsig-more#hkdf'><h:HKDFParams xmlns:h='http://www.w3.org/2021/04/xmldsig-more#'><h:PRF Algorithm='http://www.w3.org/2001/04/xmldsig-more#hmac-{hash}'/><h:Salt>AAECAwQFBgcICQoL</h:Salt><h:KeyLength>32</h:KeyLength></h:HKDFParams></x:KeyDerivationMethod>"
                )
            };
            let role = |name: &str| {
                let mut info = KeyInfo::default();
                info.sources.push(KeyInfoSource::KeyName(name.into()));
                Some(info)
            };
            let expected = AgreementMethod {
                algorithm,
                method: Some(parse_key_derivation_method(&method_xml, &policy).unwrap()),
                nonce: Vec::new(),
                legacy_digest: None,
                originator: role("originator-key-name"),
                recipient: role("recipient-key-name"),
            };
            let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
            let resolver = AgreementDecryptor::wrapping(
                &expected,
                recipient.as_ref(),
                &peer,
                KeyWrapAlgorithm::AesKw256,
            );
            let result = DecryptContext::new(&resolver)
                .policy(policy.clone())
                .decrypt_document(&xml, None);
            if family == "concatkdf" {
                // The pinned runner supplies --session-key aes-256 to an AES-128
                // template. The resulting wrapped CEK has 32 bytes, not 16.
                // XMLEnc 1.1 section 5.2.4 selects AES-128 by URI. Our exact-key
                // contract intentionally rejects the donor's implicit truncation;
                // rejection of surplus key material is a product invariant.
                // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-AES-GCM
                assert!(
                    matches!(
                        result,
                        Err(XmlEncError::InvalidWrappedKeyLength {
                            expected: 24,
                            actual: 40
                        })
                    ),
                    "{name}: {result:?}"
                );
                let parsed = parse_encrypted_data(&xml).unwrap();
                let mut budget =
                    xml_sec::xmlenc::KeyEstablishmentBudget::new(&policy.key_establishment)
                        .unwrap();
                let kek = expected
                    .derive_key(
                        KeyWrapAlgorithm::AesKw256.uri(),
                        32,
                        recipient.as_ref(),
                        &peer,
                        &RUST_CRYPTO_PROVIDER,
                        &mut budget,
                    )
                    .unwrap();
                let xml_sec::xmlenc::CipherData::Value { value } =
                    &parsed.encrypted_keys[0].cipher_data
                else {
                    panic!("donor requires CipherValue")
                };
                let wrapped = STANDARD.decode(value).unwrap();
                let recovered = zeroize::Zeroizing::new(
                    RUST_CRYPTO_PROVIDER
                        .unwrap_key(KeyWrapAlgorithm::AesKw256, &kek, &wrapped)
                        .unwrap(),
                );
                assert_eq!(recovered.len(), 32, "{name}: actual CEK width");
                assert_surplus_cek_plaintext(&xml, &name, &recovered);
                completed_vector(VECTOR_DIR, &name, CorpusOutcome::DocumentedDeparture);
                continue;
            }
            let actual = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            let plaintext = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_xml(actual.as_bytes(), &algorithm).unwrap(),
                canonicalize_xml(&plaintext, &algorithm).unwrap(),
                "{name}"
            );
            completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
        }
    }
}

#[test]
fn decrypts_xmlsec1_direct_aes_keyname_vectors() {
    // Covers both content modes with donor-produced CBC/GCM framing and direct keys.
    let keys = read_aes_keys(Path::new(KEY_INVENTORY));
    for (name, key_name) in [
        ("enc-aes128cbc-keyname", "test-aes128"),
        ("enc-aes128gcm-keyname", "test-aes128"),
        ("enc-aes256cbc-keyname", "test-aes256"),
        ("enc-aes256gcm-keyname", "test-aes256"),
    ] {
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml"))
            .expect("tracked donor XML must be readable");
        let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data"))
            .expect("tracked donor plaintext must be readable");
        let key = keys.get(key_name).expect("named donor AES key must exist");
        let decrypted = decrypt(&xml, &SymmetricKeyDecryptor::new(key.clone()))
            .expect("xmlsec1 donor ciphertext must decrypt");
        assert_eq!(decrypted, DecryptedContent::Bytes(expected), "{name}");
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_aleksey_legacy_direct_and_reference_shapes() {
    use xml_sec::key_manager::SymmetricKeyKind;
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, KeyWrapAlgorithm as W};
    // Original binary and XML outputs cover the root-element replacement
    // boundary as well as nested Element/Content and indirect ciphertext.
    let aes = read_aes_keys(Path::new(KEY_INVENTORY));
    let des = std::fs::read(format!("{VECTOR_DIR}/test-des.bin")).unwrap();
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::TripleDesCbc, D::Aes192Cbc, D::Aes192Gcm].into()),
        key_wrap_algorithms: Some([W::AesKw192, W::Cbc(D::Aes192Cbc)].into()),
        ..Default::default()
    };
    policy.xml.allow_internal_dtd = true;
    for (name, xml_output, aes_key, wrapped) in [
        ("enc-aes192cbc-keyname", false, true, false),
        ("enc-aes192gcm-keyname", false, true, false),
        ("enc-aes192cbc-keyname-ref", false, true, false),
        ("enc-des3cbc-keyname", false, false, false),
        ("enc-des3cbc-keyname2", false, false, false),
        ("enc-des3cbc-keyname-content", true, false, false),
        ("enc-des3cbc-keyname-element", true, false, false),
        ("enc-des3cbc-keyname-element-root", true, false, false),
        ("enc-des3cbc-aes192-keyname", false, true, true),
    ] {
        let (key, kind) = if aes_key {
            (&aes["test-aes192"], SymmetricKeyKind::Aes)
        } else {
            (&des, SymmetricKeyKind::Des)
        };
        let resolver: Box<dyn xml_sec::xmlenc::DecryptionKeyResolver> = if wrapped {
            Box::new(KekDecryptor::borrowed_with_kind(key, kind))
        } else {
            Box::new(SymmetricKeyDecryptor::with_kind(key.clone(), kind))
        };
        let encrypted = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
        let context = DecryptContext::new(resolver.as_ref()).policy(policy.clone());
        if xml_output {
            let actual = context
                .decrypt_document(&encrypted, None)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_dtd_document(&actual, &algorithm),
                canonicalize_dtd_document(std::str::from_utf8(&expected).unwrap(), &algorithm),
                "{name}"
            );
        } else if name == "enc-aes192cbc-keyname-ref" {
            // Binary ciphertext lives in a container document; the public
            // reference resolver supplies the source context, while typed
            // decryption returns bytes rather than trying XML replacement.
            let document = Document::parse_with_options(
                &encrypted,
                ParsingOptions {
                    allow_dtd: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let node = document
                .descendants()
                .find(|node| {
                    node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"))
                })
                .unwrap();
            let mut parsed =
                xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy).unwrap();
            let reference = node
                .descendants()
                .find(|node| {
                    node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherReference"))
                })
                .unwrap();
            let ciphertext = xml_sec::xmlenc::CipherReferenceContext::new(
                &policy,
                None,
                xml_sec::XmlBackend::default(),
                &[],
            )
            .unwrap()
            .resolve(reference)
            .unwrap();
            parsed.cipher_data = xml_sec::xmlenc::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            };
            assert_eq!(
                context.decrypt_data(&parsed).unwrap(),
                DecryptedContent::Bytes(expected),
                "{name}"
            );
        } else {
            assert_eq!(
                context
                    .decrypt(&encrypted)
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                DecryptedContent::Bytes(expected),
                "{name}"
            );
        }
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[test]
fn decrypts_aleksey_rsa_oaep_document_vectors() {
    // enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512 proves that libxmlsec1 accepts
    // an explicit XMLEnc 1.1 MGF child under the legacy OAEP URI. Generated
    // round trips cannot prove this parser/provider interoperability contract.
    let pem = std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-4096-key.pem")
        .expect("tracked Aleksey RSA key must be readable");
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&pem).expect("tracked Aleksey RSA key must be PKCS#8 PEM");
    for name in [
        "enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha1",
        "enc-aes256-kt-rsa_oaep_sha1-params",
        "enc-aes256-kt-rsa_oaep_sha1_mgf1_sha1",
        "enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha256",
        "enc-aes256-kt-rsa_oaep_sha224",
        "enc-aes256-kt-rsa_oaep_sha224_mgf1_sha224",
        "enc-aes256-kt-rsa_oaep_sha224_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha256_mgf1_sha256",
        "enc-aes256-kt-rsa_oaep_sha256_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha384",
        "enc-aes256-kt-rsa_oaep_sha384_mgf1_sha384",
        "enc-aes256-kt-rsa_oaep_sha384_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha512",
        "enc-aes256-kt-rsa_oaep_sha512_mgf1_sha1",
        "enc-aes256-kt-rsa_oaep_sha512_mgf1_sha224",
        "enc-aes256-kt-rsa_oaep_sha512_mgf1_sha256",
        "enc-aes256-kt-rsa_oaep_sha512_mgf1_sha384",
        "enc-aes256-kt-rsa_oaep_sha512_mgf1_sha512",
        "enc-aes256-kt-rsa_oaep_sha3_224",
        "enc-aes256-kt-rsa_oaep_sha3_256",
        "enc-aes256-kt-rsa_oaep_sha3_384",
        "enc-aes256-kt-rsa_oaep_sha3_512",
    ] {
        let encrypted = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml"))
            .expect("tracked Aleksey ciphertext must be readable");
        let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data"))
            .expect("tracked Aleksey plaintext must be readable");
        let decrypted = xml_sec::xmlenc::decrypt_document(
            &encrypted,
            Some("ED"),
            &PrivateKeyDecryptor::new(private_key.clone()),
        )
        .unwrap_or_else(|error| panic!("{name} must decrypt: {error}"));
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let actual_c14n = canonicalize_xml(decrypted.as_bytes(), &algorithm)
            .expect("decrypted Aleksey document must canonicalize");
        let expected_c14n = canonicalize_xml(&expected, &algorithm)
            .expect("Aleksey plaintext document must canonicalize");
        assert_eq!(actual_c14n, expected_c14n, "{name}");
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_each_recipient_in_the_two_transport_key_vector() {
    // Each recipient must recover the same document independently. Testing
    // only the first key misses candidate fallback to the second recipient.
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::KeyTransportAlgorithm;
    let name = "enc-two-enc-keys";
    let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
    let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
    let mut policy = DecryptionPolicy {
        key_transport_algorithms: Some([KeyTransportAlgorithm::RsaPkcs1v15].into()),
        ..DecryptionPolicy::default()
    };
    policy.xml.allow_internal_dtd = true;
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    for bits in [2048, 4096] {
        let pem =
            std::fs::read_to_string(format!("tests/fixtures/keys/rsa/rsa-{bits}-key.pem")).unwrap();
        let resolver = PrivateKeyDecryptor::new(RsaPrivateKey::from_pkcs8_pem(&pem).unwrap());
        let actual = DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt_document(&xml, None)
            .unwrap_or_else(|error| panic!("recipient {bits}: {error}"));
        assert_eq!(
            canonicalize_dtd_document(&actual, &c14n),
            canonicalize_dtd_document(std::str::from_utf8(&expected).unwrap(), &c14n),
            "recipient {bits}",
        );
    }
    completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_iso_latin1_element_and_content_donor_documents() {
    // Both the source document and the replaced document cross the public
    // byte-decoding boundary; UTF-8-only fixture loading hides this contract.
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::KeyTransportAlgorithm;
    let pem = std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-4096-key.pem").unwrap();
    let resolver = PrivateKeyDecryptor::new(RsaPrivateKey::from_pkcs8_pem(&pem).unwrap());
    let policy = DecryptionPolicy {
        key_transport_algorithms: Some([KeyTransportAlgorithm::RsaPkcs1v15].into()),
        ..DecryptionPolicy::default()
    };
    let context = DecryptContext::new(&resolver).policy(policy);
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    for name in ["enc-element-isolatin1", "enc-content-isolatin1"] {
        let encrypted = std::fs::read(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap();
        let mut document = xml_sec::XmlDocument::parse_bytes(&encrypted).unwrap();
        context
            .decrypt_owned_document(&mut document, None)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let expected_document = xml_sec::XmlDocument::parse_bytes(&expected).unwrap();
        assert_eq!(
            canonicalize_xml(document.as_xml().as_bytes(), &c14n).unwrap(),
            canonicalize_xml(expected_document.as_xml().as_bytes(), &c14n).unwrap(),
            "{name}",
        );
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_rsa15_documents_with_certificate_selector_metadata() {
    // The donor decrypt invocation supplies this private key explicitly.
    // X509 metadata is not an authorization source: these cases demonstrate
    // decryption with a caller-selected key, not certificate trust validation.
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::KeyTransportAlgorithm;
    let pem = std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-4096-key.pem").unwrap();
    let resolver = PrivateKeyDecryptor::new(RsaPrivateKey::from_pkcs8_pem(&pem).unwrap());
    let mut policy = DecryptionPolicy {
        data_algorithms: Some(
            [
                xml_sec::xmlenc::DataEncryptionAlgorithm::Aes256Cbc,
                xml_sec::xmlenc::DataEncryptionAlgorithm::TripleDesCbc,
            ]
            .into(),
        ),
        key_transport_algorithms: Some([KeyTransportAlgorithm::RsaPkcs1v15].into()),
        ..DecryptionPolicy::default()
    };
    policy.xml.allow_internal_dtd = true;
    let context = DecryptContext::new(&resolver).policy(policy);
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    for name in [
        "enc_rsa_1_5_x509_subject_name",
        "enc_rsa_1_5_x509_issuer_name_serial",
        "enc_rsa_1_5_x509_ski",
        "enc_rsa_1_5_x509_digest_sha1",
        "enc_rsa_1_5_x509_digest_sha224",
        "enc_rsa_1_5_x509_digest_sha256",
        "enc_rsa_1_5_x509_digest_sha384",
        "enc_rsa_1_5_x509_digest_sha512",
        "enc_rsa_1_5_x509_digest_sha3_224",
        "enc_rsa_1_5_x509_digest_sha3_256",
        "enc_rsa_1_5_x509_digest_sha3_384",
        "enc_rsa_1_5_x509_digest_sha3_512",
        "enc-two-recipients",
        "large_input",
    ] {
        let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.data")).unwrap();
        let actual = context
            .decrypt_document(&xml, None)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            canonicalize_dtd_document(&actual, &c14n),
            canonicalize_dtd_document(&expected, &c14n),
            "{name}",
        );
        completed_vector(VECTOR_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn legacy_oaep_donor_hashes_require_permission_then_decrypt() {
    // Compiling MD5/RIPEMD-160 is not permission. Validate both rejection at
    // the policy boundary and actual donor interoperability when allowed.
    use xml_sec::policy::{DecryptionPolicy, PolicyViolation};
    use xml_sec::xmlenc::OaepDigestAlgorithm as H;
    let private_key = RsaPrivateKey::from_pkcs8_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-4096-key.pem").unwrap(),
    )
    .unwrap();
    let resolver = PrivateKeyDecryptor::new(private_key);
    let policy = DecryptionPolicy {
        oaep_digests: Some([H::Md5, H::Ripemd160, H::Sha1, H::Sha512].into()),
        ..DecryptionPolicy::default()
    };
    for (hash, algorithm) in [("md5", H::Md5), ("ripemd160", H::Ripemd160)] {
        assert_eq!(algorithm.mgf_uri(), None);
        for suffix in ["", "_mgf1_sha512"] {
            let name = format!("enc-aes256-kt-rsa_oaep_{hash}{suffix}");
            let xml = std::fs::read_to_string(format!("{VECTOR_DIR}/{name}.xml")).unwrap();
            assert!(
                matches!(DecryptContext::new(&resolver).decrypt_document(&xml, Some("ED")),
                Err(XmlEncError::Policy(PolicyViolation::Algorithm { algorithm: rejected, .. })) if rejected == algorithm.uri())
            );
            let plaintext = DecryptContext::new(&resolver)
                .policy(policy.clone())
                .decrypt_document(&xml, Some("ED"))
                .unwrap();
            let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_xml(plaintext.as_bytes(), &c14n).unwrap(),
                canonicalize_xml(
                    &std::fs::read(format!("{VECTOR_DIR}/{name}.data")).unwrap(),
                    &c14n
                )
                .unwrap(),
                "{name}"
            );
            completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
        }
    }
}

fn read_merlin_aes_keys() -> HashMap<String, Vec<u8>> {
    let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/keys.xml"))
        .expect("tracked Merlin key inventory must be readable");
    let document = roxmltree::Document::parse(&xml).expect("Merlin key inventory must be XML");
    document
        .descendants()
        .filter(|node| node.tag_name().name() == "KeyInfo")
        .filter_map(|key_info| {
            let name = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "KeyName")?
                .text()?;
            let value = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "AESKeyValue")?
                .text()?;
            let key = STANDARD
                .decode(value.split_ascii_whitespace().collect::<String>())
                .expect("Merlin AES key must be base64");
            Some((name.to_owned(), key))
        })
        .collect()
}

#[test]
fn decrypts_merlin_standalone_aes128_cbc_vector() {
    // The original Merlin vector validates CBC framing, XML whitespace in
    // CipherValue, direct KeyName retention, and binary plaintext delivery.
    let keys = read_merlin_aes_keys();
    let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/encrypt-data-aes128-cbc.xml"))
        .expect("tracked Merlin ciphertext must be readable");
    let expected = std::fs::read(format!("{MERLIN_DIR}/encrypt-data-aes128-cbc.data"))
        .expect("tracked Merlin plaintext must be readable");
    let parsed = parse_encrypted_data(&xml).expect("Merlin EncryptedData must parse");
    assert_eq!(parsed.key_name.as_deref(), Some("job"));
    let key = keys.get("job").expect("Merlin job key must exist");
    assert_eq!(
        decrypt_data(&parsed, &SymmetricKeyDecryptor::new(key.clone()))
            .expect("Merlin AES-128-CBC vector must decrypt"),
        DecryptedContent::Bytes(expected)
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn rejects_original_merlin_corrupted_wrapped_key_before_document_mutation() {
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::provider::{CryptoProvider, ProviderError, RUST_CRYPTO_PROVIDER};
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, KeyWrapAlgorithm as W};

    // The original bad vector changes a valid-width RFC 3394 ciphertext,
    // not its algorithm or KEK. Section 2.2.3 requires integrity rejection:
    // https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.3
    // Check the primitive and full document API, without generating a new
    // corrupted vector or enabling unrelated legacy mechanisms.
    let xml = std::fs::read_to_string(format!(
        "{MERLIN_DIR}/bad-encrypt-content-aes128-cbc-kw-aes192.xml"
    ))
    .unwrap();
    let document = Document::parse(&xml).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData")))
        .unwrap();
    let policy = DecryptionPolicy {
        data_algorithms: Some([D::Aes128Cbc].into()),
        key_wrap_algorithms: Some([W::AesKw192].into()),
        ..Default::default()
    };
    let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy).unwrap();
    let kek = read_merlin_aes_keys().remove("jeb").unwrap();
    let xml_sec::xmlenc::CipherData::Value { value } = &parsed.encrypted_keys[0].cipher_data else {
        panic!("original bad vector must carry an inline wrapped key");
    };
    let wrapped = STANDARD.decode(value).unwrap();
    assert_eq!(wrapped.len(), 24);
    assert_eq!(
        RUST_CRYPTO_PROVIDER.unwrap_key(W::AesKw192, &kek, &wrapped),
        Err(ProviderError::AuthenticationFailed),
    );
    let resolver = KekDecryptor::new(kek);
    let context = DecryptContext::new(&resolver).policy(policy);
    assert!(matches!(
        context.decrypt_document(&xml, None),
        Err(XmlEncError::KeyWrapIntegrity)
    ));
    let mut owned = xml_sec::XmlDocument::parse(&xml).unwrap();
    let before = owned.as_xml().to_owned();
    let generation = owned.generation();
    assert!(matches!(
        context.decrypt_owned_document(&mut owned, None),
        Err(XmlEncError::KeyWrapIntegrity),
    ));
    assert_eq!(
        owned.as_xml(),
        before,
        "integrity failure must not mutate XML"
    );
    assert_eq!(owned.generation(), generation);
    completed_vector(
        MERLIN_DIR,
        "bad-encrypt-content-aes128-cbc-kw-aes192",
        CorpusOutcome::Rejected,
    );
}

#[test]
fn replaces_merlin_aes256_cbc_encrypted_content() {
    // This full-document oracle covers Content replacement under an inherited
    // namespace and accepts informational EncryptionProperties after CipherData.
    let keys = read_merlin_aes_keys();
    let encrypted =
        std::fs::read_to_string(format!("{MERLIN_DIR}/encrypt-content-aes256-cbc-prop.xml"))
            .expect("tracked Merlin encrypted document must be readable");
    let expected = std::fs::read(format!("{MERLIN_DIR}/encrypt-content-aes256-cbc-prop.data"))
        .expect("tracked Merlin plaintext document must be readable");
    let key = keys.get("jed").expect("Merlin jed key must exist");
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let decrypted = DecryptContext::new(&SymmetricKeyDecryptor::new(key.clone()))
        .policy(policy)
        .decrypt_document(&encrypted, Some("encrypt-data-0"))
        .expect("Merlin encrypted Content must be replaced");
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let actual_c14n = canonicalize_dtd_document(&decrypted, &algorithm);
    let expected = std::str::from_utf8(&expected).expect("Merlin plaintext must be UTF-8");
    let expected_c14n = canonicalize_dtd_document(expected, &algorithm);
    assert_eq!(actual_c14n, expected_c14n);
}

#[test]
fn decrypts_merlin_signature_documents_without_mutating_other_targets() {
    // These files also contain a historical signature transform. This test
    // exercises their XMLEnc payload through the public decryption API; it
    // does not pretend that decrypt_document verifies the XMLDSig transform.
    // Explicit target selection must leave both SignedInfo and the second,
    // already-encrypted payload in the Except example byte-for-byte intact.
    let plaintext = std::fs::read_to_string(format!("{MERLIN_DIR}/plaintext.xml")).unwrap();
    let plain_document = Document::parse(&plaintext).unwrap();
    let payment = plain_document
        .descendants()
        .find(|node| node.has_tag_name(("urn:example:po", "PaymentInfo")))
        .unwrap();
    let payment_source = &plaintext[payment.range()];
    // The encrypted fragment spans BillingAddress through CreditCard; the
    // pretty-print indentation before/after those elements stays outside the
    // original EncryptedData. Preserve every interior whitespace character.
    let expected_content = &payment_source[payment_source.find("<BillingAddress>").unwrap()
        ..payment_source.rfind("</CreditCard>").unwrap() + "</CreditCard>".len()];
    let key = read_merlin_aes_keys().remove("jed").unwrap();
    let resolver = SymmetricKeyDecryptor::new(key);
    let context = DecryptContext::new(&resolver);
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    for name in ["decryption-transform", "decryption-transform-except"] {
        let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let target = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("encrypt-data-0"))
            .unwrap();
        let cipher = parse_encrypted_data(&xml[target.range()]).unwrap();
        let DecryptedContent::Xml(content) = context.decrypt_data(&cipher).unwrap() else {
            panic!("{name}: Content plaintext must be XML");
        };
        let wrapper =
            |content: &str| format!("<PaymentInfo xmlns='urn:example:po'>{content}</PaymentInfo>");
        assert_eq!(
            canonicalize_xml(wrapper(&content).as_bytes(), &algorithm).unwrap(),
            canonicalize_xml(wrapper(expected_content).as_bytes(), &algorithm).unwrap(),
            "{name}"
        );
        let expected = format!(
            "{}{}{}",
            &xml[..target.range().start],
            expected_content,
            &xml[target.range().end..]
        );
        let actual = context
            .decrypt_document(&xml, Some("encrypt-data-0"))
            .unwrap();
        assert_eq!(
            canonicalize_xml(actual.as_bytes(), &algorithm).unwrap(),
            canonicalize_xml(expected.as_bytes(), &algorithm).unwrap(),
            "{name}"
        );
        let signature = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
            .unwrap();
        assert!(
            actual.contains(&xml[signature.range()]),
            "{name}: signature changed"
        );
        if let Some(excluded) = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("encrypt-data-1"))
        {
            assert!(
                actual.contains(&xml[excluded.range()]),
                "{name}: unselected ciphertext changed"
            );
        }
        let mut owned = xml_sec::XmlDocument::parse(&xml).unwrap();
        context
            .decrypt_owned_document(&mut owned, Some("encrypt-data-0"))
            .unwrap();
        assert_eq!(owned.as_xml(), actual, "{name}: owned replacement differs");
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
}

fn canonicalize_dtd_document(xml: &str, algorithm: &C14nAlgorithm) -> Vec<u8> {
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: true,
            ..ParsingOptions::default()
        },
    )
    .expect("Merlin document with internal DTD must parse");
    let mut output = Vec::new();
    canonicalize(&document, None, algorithm, &mut output)
        .expect("Merlin document must canonicalize");
    output
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_merlin_direct_and_wrapped_document_shapes() {
    use xml_sec::key_manager::{KeyInventory, SymmetricKeyKind};
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, KeyWrapAlgorithm as W};

    // Independent donor plaintext verifies binary, Element and Content paths,
    // including retrieval of a sibling EncryptedKey and its preservation.
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::TripleDesCbc, D::Aes128Cbc, D::Aes192Cbc, D::Aes256Cbc].into()),
        key_wrap_algorithms: Some([W::TripleDes, W::AesKw128, W::AesKw192, W::AesKw256].into()),
        ..DecryptionPolicy::default()
    };
    policy.xml.allow_internal_dtd = true;
    let inventory = KeyInventory::from_xml_bytes(
        &std::fs::read(format!("{MERLIN_DIR}/keys.xml")).unwrap(),
        &policy,
        xml_sec::XmlBackend::default(),
    )
    .unwrap();
    for (name, key_name, wrapped, binary) in [
        ("encrypt-data-aes128-cbc", "job", false, true),
        ("encrypt-content-tripledes-cbc", "bob", false, false),
        ("encrypt-content-aes256-cbc-prop", "jed", false, false),
        ("encrypt-data-aes256-cbc-kw-tripledes", "bob", true, true),
        ("encrypt-content-aes128-cbc-kw-aes192", "jeb", true, false),
        ("encrypt-data-aes192-cbc-kw-aes256", "jed", true, true),
        (
            "encrypt-element-tripledes-cbc-kw-aes128",
            "job",
            true,
            false,
        ),
        (
            "encrypt-element-aes256-cbc-retrieved-kw-aes256",
            "jed",
            true,
            false,
        ),
    ] {
        let key = inventory
            .symmetric_keys()
            .iter()
            .find(|key| key.name == key_name)
            .unwrap();
        assert_eq!(
            key.kind,
            if key_name == "bob" {
                SymmetricKeyKind::Des
            } else {
                SymmetricKeyKind::Aes
            }
        );
        let resolver: Box<dyn xml_sec::xmlenc::DecryptionKeyResolver> = if wrapped {
            Box::new(KekDecryptor::with_kind(key.bytes.to_vec(), key.kind))
        } else {
            Box::new(SymmetricKeyDecryptor::with_kind(
                key.bytes.to_vec(),
                key.kind,
            ))
        };
        let encrypted = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read(format!("{MERLIN_DIR}/{name}.data")).unwrap();
        let context = DecryptContext::new(resolver.as_ref()).policy(policy.clone());
        if binary {
            assert_eq!(
                context
                    .decrypt(&encrypted)
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                DecryptedContent::Bytes(expected),
                "{name}"
            );
        } else {
            let actual = context
                .decrypt_document(&encrypted, None)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_dtd_document(&actual, &algorithm),
                canonicalize_dtd_document(std::str::from_utf8(&expected).unwrap(), &algorithm),
                "{name}"
            );
        }
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_merlin_rsa_transport_shapes() {
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{DataEncryptionAlgorithm as D, KeyTransportAlgorithm as T};

    // Original 1024-bit test credentials require an explicit historical
    // policy; document certificates never relax the product's RSA minimum.
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::TripleDesCbc, D::Aes128Cbc].into()),
        key_transport_algorithms: Some([T::RsaPkcs1v15, T::RsaOaepMgf1p].into()),
        ..DecryptionPolicy::default()
    };
    policy.rsa_keys.minimum_modulus_bits = 1024;
    policy.xml.allow_internal_dtd = true;
    let key = RsaPrivateKey::from_pkcs1_pem(
        &std::fs::read_to_string(format!("{MERLIN_DIR}/rsapriv.pem")).unwrap(),
    )
    .unwrap();
    let resolver = PrivateKeyDecryptor::new(key);
    let context = DecryptContext::new(&resolver).policy(policy);
    for name in [
        "encrypt-data-tripledes-cbc-rsa-oaep-mgf1p",
        "encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256",
        "encrypt-element-aes128-cbc-rsa-1_5",
    ] {
        let encrypted = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read(format!("{MERLIN_DIR}/{name}.data")).unwrap();
        if name.starts_with("encrypt-data-") {
            assert_eq!(
                context
                    .decrypt(&encrypted)
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                DecryptedContent::Bytes(expected),
                "{name}"
            );
        } else {
            let actual = context
                .decrypt_document(&encrypted, None)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_dtd_document(&actual, &algorithm),
                canonicalize_dtd_document(std::str::from_utf8(&expected).unwrap(), &algorithm),
                "{name}"
            );
        }
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_merlin_same_document_cipher_reference() {
    // XPath selects the repository text before Base64 decoding. Compare the
    // entire replacement document, including the untouched repository node.
    let keys = read_merlin_aes_keys();
    let resolver = SymmetricKeyDecryptor::new(keys["jeb"].clone());
    let mut policy = xml_sec::policy::DecryptionPolicy {
        data_algorithms: Some([xml_sec::xmlenc::DataEncryptionAlgorithm::Aes192Cbc].into()),
        ..Default::default()
    };
    policy.xml.allow_internal_dtd = true;
    let name = "encrypt-element-aes192-cbc-ref";
    let encrypted = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
    let expected = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.data")).unwrap();
    let actual = DecryptContext::new(&resolver)
        .policy(policy)
        .decrypt_document(&encrypted, None)
        .unwrap();
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    assert_eq!(
        canonicalize_dtd_document(&actual, &algorithm),
        canonicalize_dtd_document(&expected, &algorithm)
    );
    completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
}

#[test]
fn decrypts_merlin_carried_key_name_without_altering_other_recipients() {
    // The first recipient is not ours. Failed unwrap must leave the second
    // associated recipient eligible without removing either metadata entry.
    let keys = read_merlin_aes_keys();
    let resolver =
        KekDecryptor::borrowed_with_kind(&keys["jed"], xml_sec::key_manager::SymmetricKeyKind::Aes);
    let encrypted = std::fs::read_to_string(format!(
        "{MERLIN_DIR}/encrypt-element-aes256-cbc-carried-kw-aes256.xml"
    ))
    .unwrap();
    let plain = std::fs::read_to_string(format!("{MERLIN_DIR}/plaintext.xml")).unwrap();
    let actual = DecryptContext::new(&resolver)
        .decrypt_document(&encrypted, None)
        .unwrap();
    let plain_document = Document::parse(&plain).unwrap();
    let payment = plain_document
        .descendants()
        .find(|node| node.has_tag_name(("urn:example:po", "PaymentInfo")))
        .unwrap();
    let encrypted_document = Document::parse(&encrypted).unwrap();
    let target = encrypted_document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData")))
        .unwrap();
    let range = target.range();
    let expected = format!(
        "{}{}{}",
        &encrypted[..range.start],
        &plain[payment.range()],
        &encrypted[range.end..]
    );
    assert_eq!(
        canonicalize_fixture_document(actual.as_bytes()),
        canonicalize_fixture_document(expected.as_bytes())
    );
    completed_vector(
        MERLIN_DIR,
        "encrypt-element-aes256-cbc-carried-kw-aes256",
        CorpusOutcome::Decrypted,
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn identifies_truncated_merlin_credentials_without_claiming_dh_parity() {
    use der::Decode as _;
    // Both original DH files are the same truncated credential in the pinned
    // donor. This is a credential failure, not proof of cipher compatibility.
    let first = std::fs::read(format!("{MERLIN_DIR}/dh0.p8")).unwrap();
    let second = std::fs::read(format!("{MERLIN_DIR}/dh1.p8")).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 409);
    assert!(
        matches!(pkcs8::PrivateKeyInfoRef::try_from(first.as_slice()), Err(pkcs8::Error::Asn1(error)) if matches!(error.kind(), der::ErrorKind::Incomplete { .. }))
    );
    let pfx = std::fs::read(format!("{MERLIN_DIR}/ids.p12")).unwrap();
    assert_eq!(pfx.len(), 499);
    assert!(
        matches!(pkcs12::pfx::Pfx::from_der(&pfx), Err(error) if matches!(error.kind(), der::ErrorKind::Incomplete { .. }))
    );
}

#[cfg(all(feature = "xmldsig", feature = "legacy-algorithms"))]
#[test]
fn verifies_merlin_signatures_after_authenticated_symmetric_key_unwrap() {
    use xml_sec::policy::VerificationPolicy;
    use xml_sec::provider::{CryptoProvider as _, RUST_CRYPTO_PROVIDER};
    use xml_sec::xmldsig::{
        DigestAlgorithm, DsigStatus, HmacVerificationKey, SignatureAlgorithm, UriTypeSet,
        VerifyContext,
    };
    use xml_sec::xmlenc::KeyWrapAlgorithm;
    // The application selects the KEK independently. Unwrapping a message's
    // key is not implicit signer authorization or certificate chain trust.
    let keys = read_merlin_aes_keys();
    let resources = HashMap::from([(
        "http://www.w3.org/TR/xml-stylesheet".to_owned(),
        std::fs::read("tests/fixtures/xmldsig/external-data/xml-stylesheet-2005").unwrap(),
    )]);
    for (name, wrapping, kek) in [
        (
            "encsig-sha256-hmac-sha256-kw-aes128",
            KeyWrapAlgorithm::AesKw128,
            keys["job"].as_slice(),
        ),
        (
            "encsig-sha384-hmac-sha384-kw-aes192",
            KeyWrapAlgorithm::AesKw192,
            keys["jeb"].as_slice(),
        ),
        (
            "encsig-sha512-hmac-sha512-kw-aes256",
            KeyWrapAlgorithm::AesKw256,
            keys["jed"].as_slice(),
        ),
        (
            "encsig-ripemd160-hmac-ripemd160-kw-tripledes",
            KeyWrapAlgorithm::TripleDes,
            b"abcdefghijklmnopqrstuvwx".as_slice(),
        ),
    ] {
        let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let value = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
            .unwrap();
        let wrapped = STANDARD
            .decode(
                value
                    .text()
                    .unwrap()
                    .split_ascii_whitespace()
                    .collect::<String>(),
            )
            .unwrap();
        let key = HmacVerificationKey::new(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(wrapping, kek, &wrapped)
                .unwrap(),
        )
        .unwrap();
        let mut policy = VerificationPolicy::default();
        policy.uris.references = UriTypeSet::ALL;
        policy.signature_algorithms = Some(
            [
                SignatureAlgorithm::HmacSha256,
                SignatureAlgorithm::HmacSha384,
                SignatureAlgorithm::HmacSha512,
                SignatureAlgorithm::HmacRipemd160,
            ]
            .into(),
        );
        policy.digest_algorithms = Some(
            [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
                DigestAlgorithm::Ripemd160,
            ]
            .into(),
        );
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(SignatureAlgorithm::HmacRipemd160);
        let result = VerifyContext::new()
            .key(&key)
            .policy(policy)
            .external_resources(&resources)
            .verify(&xml)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(result.status, DsigStatus::Valid, "{name}");
        assert_eq!(result.signed_info_references.len(), 1, "{name}");
        assert_eq!(
            result.signed_info_references[0].status,
            DsigStatus::Valid,
            "{name}"
        );
        let mut damaged = wrapped;
        damaged[0] ^= 1;
        assert!(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(wrapping, kek, &damaged)
                .is_err(),
            "{name}: tampered wrapping must not authenticate a key"
        );
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(all(feature = "xmldsig", feature = "legacy-algorithms"))]
#[test]
fn validates_merlin_rsa_transported_hmac_keys_without_exporting_recovered_keys() {
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::provider::{CryptoProvider as _, RUST_CRYPTO_PROVIDER};
    use xml_sec::xmldsig::{DsigStatus, HmacVerificationKey, UriTypeSet, VerifyContext};
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

    // Merlin publishes this MAC secret for debugging. A GCM challenge proves
    // the original transport recovers exactly that secret, while preserving
    // the production RSA-v1.5 implicit-rejection/non-exportable-key boundary.
    // RSA transport of an HMAC secret is not signer authentication; the
    // archive explicitly warns these signatures have no cryptographic merit.
    let secret = b"abcdefghijklmnopqrstuvwxyz012345";
    let private = zeroize::Zeroizing::new(
        std::fs::read("tests/fixtures/xmlenc/merlin-original-keys/rsa.p8").unwrap(),
    );
    let resolver = PrivateKeyDecryptor::new(RsaPrivateKey::from_pkcs8_der(&private).unwrap());
    let mut policy = DecryptionPolicy {
        key_transport_algorithms: Some(
            [
                KeyTransportAlgorithm::RsaPkcs1v15,
                KeyTransportAlgorithm::RsaOaepMgf1p,
            ]
            .into(),
        ),
        ..Default::default()
    };
    policy.rsa_keys.minimum_modulus_bits = 1024;
    let context = DecryptContext::new(&resolver).policy(policy);
    let verification_key = HmacVerificationKey::new(secret.to_vec()).unwrap();
    let resources = HashMap::from([(
        "http://www.w3.org/TR/xml-stylesheet".to_owned(),
        std::fs::read("tests/fixtures/xmldsig/external-data/xml-stylesheet-2005").unwrap(),
    )]);
    for name in [
        "encsig-hmac-sha256-rsa-1_5",
        "encsig-hmac-sha256-rsa-oaep-mgf1p",
    ] {
        let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let encrypted_key = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")))
            .unwrap();
        let challenge = b"exact transported MAC key";
        let cipher = RUST_CRYPTO_PROVIDER
            .encrypt_data(DataEncryptionAlgorithm::Aes256Gcm, secret, challenge)
            .unwrap();
        let envelope = format!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{}</KeyInfo><CipherData><CipherValue>{}</CipherValue></CipherData></EncryptedData>",
            &xml[encrypted_key.range()],
            STANDARD.encode(cipher),
        );
        assert_eq!(
            context.decrypt(&envelope).unwrap(),
            DecryptedContent::Bytes(challenge.to_vec()),
            "{name}"
        );
        let result = VerifyContext::new()
            .key(&verification_key)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .unwrap();
        assert_eq!(result.status, DsigStatus::Valid, "{name}");
        assert_eq!(result.signed_info_references.len(), 1, "{name}");
        assert_eq!(
            result.signed_info_references[0].status,
            DsigStatus::Valid,
            "{name}"
        );
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_merlin_dh_with_original_w3c_credentials() {
    use der::{Decode as _, Reader as _, asn1::UintRef};
    use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm, KeyDerivationAlgorithm};
    use xml_sec::provider::{RUST_CRYPTO_PROVIDER, RustCryptoDhKey};
    use xml_sec::xmldsig::DigestAlgorithm;
    use xml_sec::xmlenc::{
        AgreementDecryptor, DataEncryptionAlgorithm as D, KeyEstablishmentBudget,
        KeyWrapAlgorithm as W,
    };

    // Original archive credentials have a separate pinned provenance; the
    // later donor's truncated copies remain byte-for-byte unchanged.
    let bytes = zeroize::Zeroizing::new(
        std::fs::read("tests/fixtures/xmlenc/merlin-original-keys/dh1.p8").unwrap(),
    );
    assert_eq!(bytes.len(), 445);
    let info = pkcs8::PrivateKeyInfoRef::try_from(bytes.as_slice()).unwrap();
    let (p, g, q) = info
        .algorithm
        .parameters
        .unwrap()
        .sequence(|reader| -> der::Result<_> {
            let p: UintRef<'_> = reader.decode()?;
            let g: UintRef<'_> = reader.decode()?;
            let q: UintRef<'_> = reader.decode()?;
            let _j: UintRef<'_> = reader.decode()?;
            Ok((p, g, q))
        })
        .unwrap();
    let private = UintRef::from_der(info.private_key.as_bytes()).unwrap();
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::Aes192Cbc, D::Aes256Cbc].into()),
        key_wrap_algorithms: Some([W::AesKw256].into()),
        ..Default::default()
    };
    policy.key_establishment.agreement_algorithms = Some([KeyAgreementAlgorithm::LegacyDh].into());
    policy.key_establishment.derivation_algorithms =
        Some([KeyDerivationAlgorithm::LegacyDh].into());
    policy.key_establishment.digest_algorithms = Some(
        [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Ripemd160,
        ]
        .into(),
    );
    policy.key_establishment.minimum_dh_modulus_bits = 1024;
    policy.key_establishment.minimum_dh_subgroup_bits = 160;
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    let key = RustCryptoDhKey::from_components(
        &RUST_CRYPTO_PROVIDER,
        &mut budget,
        p.as_bytes(),
        q.as_bytes(),
        g.as_bytes(),
        private.as_bytes(),
    )
    .unwrap();
    let expected = std::fs::read(format!("{MERLIN_DIR}/plaintext.xml")).unwrap();
    for (name, wrapped) in [
        ("encrypt-content-aes192-cbc-dh-sha512", false),
        ("encrypt-element-aes256-cbc-kw-aes256-dh-ripemd160", true),
    ] {
        let encrypted = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
        let document = Document::parse(&encrypted).unwrap();
        let node = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData")))
            .unwrap();
        let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy).unwrap();
        let method = if wrapped {
            &parsed.encrypted_keys[0].sources.agreement_methods[0]
        } else {
            &parsed.agreement_methods[0]
        };
        // The published vector fixes the party binding for this test; this
        // is not a production strategy for trusting message-supplied parties.
        let public = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "Public")))
            .unwrap();
        let peer = STANDARD
            .decode(
                public
                    .text()
                    .unwrap()
                    .split_ascii_whitespace()
                    .collect::<String>(),
            )
            .unwrap();
        let resolver = if wrapped {
            AgreementDecryptor::wrapping(method, &key, &peer, W::AesKw256)
        } else {
            AgreementDecryptor::content(method, &key, &peer, D::Aes192Cbc)
        };
        let actual = DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt_document(&encrypted, None)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            canonicalize_fixture_document(actual.as_bytes()),
            canonicalize_fixture_document(&expected),
            "{name}"
        );
        completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
    }
    #[cfg(feature = "xmldsig")]
    {
        use xml_sec::provider::CryptoProvider as _;
        use xml_sec::xmldsig::{
            DsigStatus, HmacVerificationKey, SignatureAlgorithm, UriTypeSet, VerifyContext,
        };
        let resources = HashMap::from([(
            "http://www.w3.org/TR/xml-stylesheet".to_owned(),
            std::fs::read("tests/fixtures/xmldsig/external-data/xml-stylesheet-2005").unwrap(),
        )]);
        for (name, wrapped) in [
            ("encsig-hmac-sha256-kw-tripledes-dh", true),
            ("encsig-hmac-sha256-dh", false),
        ] {
            // Fixed archive party binding and KDF inputs are expected values,
            // not permissions or defaults inferred from an untrusted document.
            let xml = std::fs::read_to_string(format!("{MERLIN_DIR}/{name}.xml")).unwrap();
            let document = Document::parse(&xml).unwrap();
            let agreement = document
                .descendants()
                .find(|node| {
                    node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "AgreementMethod"))
                })
                .unwrap();
            assert_eq!(
                agreement.attribute("Algorithm"),
                Some(KeyAgreementAlgorithm::LegacyDh.uri())
            );
            let field = |local| {
                agreement
                    .descendants()
                    .find(|node| node.tag_name().name() == local)
                    .unwrap()
            };
            let decode = |local| {
                STANDARD
                    .decode(
                        field(local)
                            .text()
                            .unwrap()
                            .split_ascii_whitespace()
                            .collect::<String>(),
                    )
                    .unwrap()
            };
            assert_eq!(decode("KA-Nonce"), b"nonce");
            assert_eq!(
                field("DigestMethod").attribute("Algorithm"),
                Some(DigestAlgorithm::Sha256.uri())
            );
            assert_eq!(decode("P"), p.as_bytes());
            assert_eq!(decode("Q"), q.as_bytes());
            assert_eq!(decode("Generator"), g.as_bytes());
            let recipient_info = agreement
                .children()
                .find(|node| node.tag_name().name() == "RecipientKeyInfo")
                .unwrap();
            let cert_node = recipient_info
                .descendants()
                .find(|node| node.tag_name().name() == "X509Certificate")
                .unwrap();
            let cert_bytes = STANDARD
                .decode(
                    cert_node
                        .text()
                        .unwrap()
                        .split_ascii_whitespace()
                        .collect::<String>(),
                )
                .unwrap();
            let cert = x509_cert::Certificate::from_der(&cert_bytes).unwrap();
            let recipient_public = UintRef::from_der(
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .as_bytes()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                recipient_public.as_bytes(),
                key.public_key(),
                "{name}: recipient binding"
            );
            let peer = decode("Public");
            let method = xml_sec::xmlenc::AgreementMethod {
                algorithm: KeyAgreementAlgorithm::LegacyDh,
                method: None,
                nonce: b"nonce".to_vec(),
                legacy_digest: Some(DigestAlgorithm::Sha256.uri().into()),
                originator: None,
                recipient: None,
            };
            let mut signing_budget =
                KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
            let consuming = if wrapped {
                W::TripleDes.uri()
            } else {
                SignatureAlgorithm::HmacSha256.uri()
            };
            let derived = method
                .derive_key(
                    consuming,
                    if wrapped { 24 } else { 32 },
                    &key,
                    &peer,
                    &RUST_CRYPTO_PROVIDER,
                    &mut signing_budget,
                )
                .unwrap();
            let secret = if wrapped {
                let value = document
                    .descendants()
                    .find(|node| {
                        node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue"))
                    })
                    .unwrap();
                let cipher = STANDARD
                    .decode(
                        value
                            .text()
                            .unwrap()
                            .split_ascii_whitespace()
                            .collect::<String>(),
                    )
                    .unwrap();
                RUST_CRYPTO_PROVIDER
                    .unwrap_key(W::TripleDes, &derived, &cipher)
                    .unwrap()
            } else {
                derived.to_vec()
            };
            let verifier = HmacVerificationKey::new(secret).unwrap();
            if !wrapped {
                use xml_sec::xmldsig::{FailureReason, VerifyingKey as _};

                // The archive Readme selects a 256-bit HMAC key. Our caller
                // explicitly binds the consuming HMAC URI to the legacy KDF;
                // XMLEnc 1.1 section 5.6.2.2 specifies that KDF for encryption,
                // not an automatic AgreementMethod-to-SignatureMethod mapping.
                // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreementLegacyKDF
                // OpenSSL independently reproduced the DH shared secret and
                // the HMAC below; libxml2 reproduced canonical SignedInfo.
                // The original tag does not match this explicit binding. Keep
                // that rejection distinct from unsupported algorithms and from
                // the passing DH-to-wrapped-HMAC vector above.
                let si = document
                    .descendants()
                    .find(|node| {
                        node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo"))
                    })
                    .unwrap();
                let visible =
                    |node: xml_sec::Node<'_, '_>| node.ancestors().any(|ancestor| ancestor == si);
                let mut canonical = Vec::new();
                canonicalize(
                    &document,
                    Some(&visible),
                    &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
                    &mut canonical,
                )
                .unwrap();
                let expected = hex_literal::hex!(
                    "ec8acd98c413c7bb9ca0aa4adc8d1f0da59408d1515fb795f4b13d66a78c103a"
                );
                assert!(
                    verifier
                        .verify(SignatureAlgorithm::HmacSha256, &canonical, &expected)
                        .unwrap()
                );
                let value = document
                    .descendants()
                    .find(|node| {
                        node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureValue"))
                    })
                    .unwrap()
                    .text()
                    .unwrap();
                let original = STANDARD
                    .decode(value.split_ascii_whitespace().collect::<String>())
                    .unwrap();
                assert!(
                    !verifier
                        .verify(SignatureAlgorithm::HmacSha256, &canonical, &original)
                        .unwrap()
                );
                let original_result = VerifyContext::new()
                    .key(&verifier)
                    .allowed_uri_types(UriTypeSet::ALL)
                    .external_resources(&resources)
                    .verify(&xml)
                    .unwrap();
                assert_eq!(
                    original_result.status,
                    DsigStatus::Invalid(FailureReason::SignatureMismatch),
                    "{name}: unmodified archive tag",
                );
                // A positive counterpart replaces only SignatureValue in
                // memory, never the archived file or its signed reference.
                // This checks that full verification succeeds with the
                // independently computed tag under the same explicit binding.
                let counterpart = xml.replacen(value, &STANDARD.encode(expected), 1);
                let positive = VerifyContext::new()
                    .key(&verifier)
                    .allowed_uri_types(UriTypeSet::ALL)
                    .external_resources(&resources)
                    .verify(&counterpart)
                    .unwrap();
                assert_eq!(positive.status, DsigStatus::Valid, "{name}: counterpart");
                assert_eq!(positive.signed_info_references.len(), 1);
                assert_eq!(positive.signed_info_references[0].status, DsigStatus::Valid);
                completed_vector(MERLIN_DIR, name, CorpusOutcome::DocumentedDeparture);
                continue;
            }
            let result = VerifyContext::new()
                .key(&verifier)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
                .unwrap();
            assert_eq!(result.status, DsigStatus::Valid, "{name}");
            assert_eq!(result.signed_info_references.len(), 1, "{name}");
            assert_eq!(
                result.signed_info_references[0].status,
                DsigStatus::Valid,
                "{name}"
            );
            completed_vector(MERLIN_DIR, name, CorpusOutcome::Decrypted);
        }
    }
}

fn read_nist_keys(path: &Path) -> HashMap<String, Vec<u8>> {
    let xml = std::fs::read_to_string(path).expect("tracked NIST key inventory must be readable");
    let document = roxmltree::Document::parse(&xml).expect("NIST key inventory must be XML");
    document
        .descendants()
        .filter(|node| node.tag_name().name() == "KeyInfo")
        .map(|key_info| {
            let name = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "KeyName")
                .and_then(|node| node.text())
                .expect("NIST KeyInfo must contain KeyName");
            let value = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "AESKeyValue")
                .and_then(|node| node.text())
                .expect("NIST KeyInfo must contain AESKeyValue");
            let key = STANDARD
                .decode(value.trim())
                .expect("NIST AES key must be base64");
            (name.to_owned(), key)
        })
        .collect()
}

fn read_aes_keys(path: &Path) -> HashMap<String, Vec<u8>> {
    let xml = std::fs::read_to_string(path).expect("tracked key inventory must be readable");
    let document = roxmltree::Document::parse(&xml).expect("key inventory must be XML");
    document
        .descendants()
        .filter(|node| node.tag_name().name() == "KeyInfo")
        .filter_map(|key_info| {
            let name = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "KeyName")?
                .text()?;
            let value = key_info
                .descendants()
                .find(|node| node.tag_name().name() == "AESKeyValue")?
                .text()?;
            Some((
                name.to_owned(),
                STANDARD
                    .decode(value.split_ascii_whitespace().collect::<String>())
                    .expect("AES key must be base64"),
            ))
        })
        .collect()
}

fn xml_files(path: &Path) -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(path)
        .expect("NIST vector directory must be readable")
        .map(|entry| entry.expect("NIST directory entry must be readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "xml"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn vector_key_name(xml: &str) -> String {
    let document = roxmltree::Document::parse(xml).expect("NIST vector must be XML");
    document
        .descendants()
        .find(|node| node.tag_name().name() == "KeyName")
        .and_then(|node| node.text())
        .expect("NIST vector must name its AES key")
        .to_owned()
}

#[test]
fn classifies_complete_nist_aes_gcm_corpus() {
    // Every tracked NIST XML is classified so newly skipped vectors fail this test.
    let mut supported = 0;
    let mut rejected = 0;
    let mut unsupported = 0;

    for bits in [128, 192, 256] {
        let directory = Path::new(NIST_DIR).join(format!("aes{bits}"));
        let keys = read_nist_keys(&Path::new(NIST_DIR).join(format!("keys-aes{bits}-gcm.xml")));
        for xml_path in xml_files(&directory) {
            let xml = std::fs::read_to_string(&xml_path).expect("NIST vector must be readable");
            let key_name = vector_key_name(&xml);
            let key = keys.get(&key_name).expect("NIST vector key must exist");
            let data_path = xml_path.with_extension("data");
            let resolver = SymmetricKeyDecryptor::new(key.clone());
            #[cfg(feature = "legacy-algorithms")]
            let result = DecryptContext::new(&resolver)
                .policy(xml_sec::policy::DecryptionPolicy {
                    data_algorithms: Some(
                        [
                            xml_sec::xmlenc::DataEncryptionAlgorithm::Aes128Gcm,
                            xml_sec::xmlenc::DataEncryptionAlgorithm::Aes192Gcm,
                            xml_sec::xmlenc::DataEncryptionAlgorithm::Aes256Gcm,
                        ]
                        .into(),
                    ),
                    ..xml_sec::policy::DecryptionPolicy::default()
                })
                .decrypt(&xml);
            #[cfg(not(feature = "legacy-algorithms"))]
            let result = decrypt(&xml, &resolver);

            if bits == 192 && !cfg!(feature = "legacy-algorithms") {
                assert!(
                    matches!(result, Err(XmlEncError::UnsupportedAlgorithm(_))),
                    "{}",
                    xml_path.display()
                );
                unsupported += 1;
            } else if data_path.exists() {
                let encoded =
                    std::fs::read_to_string(&data_path).expect("NIST plaintext must be readable");
                let expected = STANDARD
                    .decode(encoded.trim())
                    .expect("NIST plaintext must be base64");
                assert_eq!(
                    result.expect("valid NIST vector must decrypt"),
                    DecryptedContent::Bytes(expected),
                    "{}",
                    xml_path.display()
                );
                supported += 1;
            } else {
                assert!(
                    matches!(result, Err(XmlEncError::AeadAuthenticationFailed)),
                    "{}",
                    xml_path.display()
                );
                rejected += 1;
            }
        }
    }

    assert!(supported > 0, "corpus must contain valid supported vectors");
    assert!(
        rejected > 0,
        "corpus must contain invalid supported vectors"
    );
    if cfg!(feature = "legacy-algorithms") {
        assert_eq!(
            unsupported, 0,
            "all AES-192 vectors must execute with permission"
        );
    } else {
        assert!(unsupported > 0, "corpus must account for AES-192 vectors");
    }
    assert_eq!(
        supported + rejected + unsupported,
        180,
        "all NIST XML vectors must be classified"
    );
}

#[test]
fn decrypts_xmlsec1_rsa_oaep_interop_vectors() {
    // These independent vectors cover legacy OAEP defaults, OAEP 1.1 digest/MGF
    // separation, and a non-empty OAEP label through the complete XML pipeline.
    for (name, key_name) in [
        (
            "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p",
            "RSA-2048_SHA256WithRSA.der",
        ),
        (
            "cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1",
            "RSA-3072_SHA256WithRSA.der",
        ),
        (
            "cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource",
            "RSA-4096_SHA256WithRSA.der",
        ),
    ] {
        let xml = std::fs::read_to_string(format!("{INTEROP_DIR}/{name}.xml"))
            .expect("tracked interop ciphertext must be readable");
        let expected = std::fs::read(format!("{INTEROP_DIR}/{name}.data"))
            .expect("tracked interop plaintext must be readable");
        let der = std::fs::read(format!("{INTEROP_DIR}/{key_name}"))
            .expect("tracked interop private key must be readable");
        let private_key = RsaPrivateKey::from_pkcs1_der(&der)
            .expect("xmlsec1 interop RSA key must be valid PKCS#1 DER");

        let decrypted = decrypt(&xml, &PrivateKeyDecryptor::new(private_key))
            .expect("xmlsec1 RSA-OAEP vector must decrypt");
        let DecryptedContent::Xml(plaintext) = decrypted else {
            panic!("donor Type=Element vector must return XML plaintext");
        };
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let actual_c14n = canonicalize_xml(plaintext.as_bytes(), &algorithm)
            .expect("decrypted donor plaintext must be canonicalizable XML");
        let expected_c14n = canonicalize_xml(&expected, &algorithm)
            .expect("donor plaintext must be canonicalizable XML");
        assert_eq!(actual_c14n, expected_c14n, "{name}");
    }
}

#[test]
fn decrypts_aes_kw_pipeline_and_rejects_wrapped_key_tampering() {
    // Exercises embedded EncryptedKey parsing and RFC 3394 integrity validation,
    // not merely the key unwrap primitive in isolation.
    let kek = [0x22_u8; 32];
    let session_key = [0x41_u8; 16];
    let plaintext = b"<Assertion ID=\"wrapped\">trusted</Assertion>";
    let mut wrapped_key = [0_u8; 24];
    KwAes256::new_from_slice(&kek)
        .expect("fixed KEK length")
        .wrap_key(&session_key, &mut wrapped_key)
        .expect("test key wrapping must succeed");
    let ciphertext = encrypt_gcm_wire(&session_key, plaintext);

    let xml = wrapped_key_xml(&wrapped_key, &ciphertext);
    let parsed = parse_encrypted_data(&xml).expect("complete AES-KW XML must parse");
    let decrypted = decrypt_data(&parsed, &KekDecryptor::new(kek))
        .expect("embedded AES-KW session key must decrypt content");
    assert_eq!(
        decrypted,
        DecryptedContent::Xml(String::from_utf8(plaintext.to_vec()).expect("test XML is UTF-8"))
    );

    let last = wrapped_key.len() - 1;
    wrapped_key[last] ^= 1;
    let tampered = wrapped_key_xml(&wrapped_key, &ciphertext);
    assert!(matches!(
        decrypt(&tampered, &KekDecryptor::new(kek)),
        Err(XmlEncError::KeyWrapIntegrity)
    ));
}

fn encrypt_gcm_wire(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let nonce = [0x19_u8; 12];
    let mut encrypted = plaintext.to_vec();
    Aes128Gcm::new_from_slice(key)
        .expect("fixed content key length")
        .encrypt_in_place(&nonce.into(), b"", &mut encrypted)
        .expect("test content encryption must succeed");
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&encrypted);
    wire
}

fn wrapped_key_xml(wrapped_key: &[u8], ciphertext: &[u8]) -> String {
    format!(
        r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey Recipient="integration-test"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#,
        STANDARD.encode(wrapped_key),
        STANDARD.encode(ciphertext)
    )
}

/// Loads the Phaos RSA transport key from the tracked donor corpus.
fn read_phaos_private_key() -> RsaPrivateKey {
    let der = std::fs::read(format!("{PHAOS_DIR}/rsa-priv-key.der"))
        .expect("tracked Phaos RSA key must be readable");
    RsaPrivateKey::from_pkcs1_der(&der).expect("Phaos RSA key must be PKCS#1 DER")
}

/// Canonicalizes donor XML so serialization differences do not mask semantics.
fn canonicalize_fixture_document(xml: &[u8]) -> Vec<u8> {
    canonicalize_xml(xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
        .expect("Phaos fixture must be canonicalizable XML")
}

/// Decrypts one Phaos vector and compares its canonical document to donor data.
fn assert_phaos_document(name: &str, resolver: &dyn xml_sec::xmlenc::DecryptionKeyResolver) {
    let encrypted = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml"))
        .expect("tracked Phaos ciphertext must be readable");
    let expected = std::fs::read(format!("{PHAOS_DIR}/{name}.data"))
        .expect("tracked Phaos plaintext must be readable");
    let decrypted = decrypt_document(&encrypted, Some("ED"), resolver)
        .unwrap_or_else(|error| panic!("{name} must decrypt: {error}"));
    assert_eq!(
        canonicalize_fixture_document(decrypted.as_bytes()),
        canonicalize_fixture_document(&expected),
        "{name}"
    );
    completed_vector(PHAOS_DIR, name, CorpusOutcome::Decrypted);
}

/// Exercises every Phaos vector supported by the crate's secure profile.
#[test]
fn decrypts_supported_phaos_rsa_oaep_and_aes_kw_vectors() {
    assert_eq!(execute_modern_phaos_vectors().len(), 5);
}

/// Returns exactly the cases whose complete plaintext was checked.
fn execute_modern_phaos_vectors() -> BTreeSet<String> {
    // These Phaos-produced documents independently exercise RSA-OAEP and both
    // RFC 3394 KEK sizes through Element and Content document replacement.
    let private_key = read_phaos_private_key();
    let mut executed = BTreeSet::new();
    for name in [
        "enc-element-aes128-kt-rsa_oaep_sha1",
        "enc-text-aes256-kt-rsa_oaep_sha1",
    ] {
        assert_phaos_document(name, &PrivateKeyDecryptor::new(private_key.clone()));
        assert!(executed.insert(name.to_owned()), "duplicate case: {name}");
    }

    let keys = read_aes_keys(Path::new(&format!("{PHAOS_DIR}/keys.xml")));
    for (name, key_name) in [
        ("enc-element-aes128-kw-aes128", "my-aes128-key"),
        ("enc-element-aes128-kw-aes256", "my-aes256-key"),
        ("enc-element-aes256-kw-aes256", "my-aes256-key"),
    ] {
        let kek = keys.get(key_name).expect("Phaos KEK must exist");
        assert_phaos_document(name, &KekDecryptor::new(kek.clone()));
        assert!(executed.insert(name.to_owned()), "duplicate case: {name}");
    }
    executed
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_all_phaos_legacy_transport_and_wrap_vectors() {
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm as D, KeyTransportAlgorithm as T, KeyWrapAlgorithm as W,
    };
    // Independent donor bytes cover all newly implemented content/transport/wrap
    // mechanisms, not ciphertext produced by the same implementation under test.
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::TripleDesCbc, D::Aes128Cbc, D::Aes192Cbc, D::Aes256Cbc].into()),
        key_transport_algorithms: Some([T::RsaPkcs1v15, T::RsaOaepMgf1p].into()),
        key_wrap_algorithms: Some([W::TripleDes, W::AesKw128, W::AesKw192, W::AesKw256].into()),
        ..DecryptionPolicy::default()
    };
    policy.rsa_keys.minimum_modulus_bits = 1024;
    let private = PrivateKeyDecryptor::new(read_phaos_private_key());
    let keys_xml = std::fs::read_to_string(format!("{PHAOS_DIR}/keys.xml")).unwrap();
    let keys_doc = Document::parse(&keys_xml).unwrap();
    let mut keys: HashMap<_, _> = read_aes_keys(Path::new(&format!("{PHAOS_DIR}/keys.xml")))
        .into_iter()
        .map(|(name, bytes)| (name, (xml_sec::key_manager::SymmetricKeyKind::Aes, bytes)))
        .collect();
    for entry in keys_doc
        .descendants()
        .filter(|node| node.tag_name().name() == "KeyInfo")
    {
        if let Some(value) = entry
            .descendants()
            .find(|node| node.tag_name().name() == "DESKeyValue")
        {
            let name = entry
                .descendants()
                .find(|node| node.tag_name().name() == "KeyName")
                .unwrap()
                .text()
                .unwrap();
            keys.insert(
                name.into(),
                (
                    xml_sec::key_manager::SymmetricKeyKind::Des,
                    STANDARD
                        .decode(
                            value
                                .text()
                                .unwrap()
                                .split_ascii_whitespace()
                                .collect::<String>(),
                        )
                        .unwrap(),
                ),
            );
        }
    }
    for (name, key_name) in [
        ("enc-element-3des-kt-rsa1_5", None),
        ("enc-element-3des-kt-rsa_oaep_sha1", None),
        ("enc-element-3des-kt-rsa_oaep_sha256", None),
        ("enc-element-3des-kt-rsa_oaep_sha512", None),
        ("enc-element-aes192-kt-rsa_oaep_sha1", None),
        ("enc-text-aes192-kt-rsa1_5", None),
        ("enc-content-aes256-kt-rsa1_5", None),
        ("enc-element-aes128-kt-rsa1_5", None),
        ("enc-content-3des-kw-aes192", Some("my-aes192-key")),
        ("enc-element-3des-kw-3des", Some("my-tripledes-key")),
        ("enc-text-3des-kw-aes256", Some("my-aes256-key")),
        ("enc-content-aes192-kw-aes256", Some("my-aes256-key")),
        ("enc-element-aes192-kw-aes192", Some("my-aes192-key")),
        ("enc-content-aes128-kw-3des", Some("my-3des-key")),
        ("enc-text-aes128-kw-aes192", Some("my-aes192-key")),
    ] {
        let encrypted = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml")).unwrap();
        let expected = std::fs::read(format!("{PHAOS_DIR}/{name}.data")).unwrap();
        let resolver: Box<dyn xml_sec::xmlenc::DecryptionKeyResolver> = match key_name {
            None => Box::new(private.clone()),
            Some(name) => {
                let (kind, bytes) = keys.get(name).unwrap();
                Box::new(KekDecryptor::with_kind(bytes.clone(), *kind))
            }
        };
        let actual = DecryptContext::new(resolver.as_ref())
            .policy(policy.clone())
            .decrypt_document(&encrypted, Some("ED"))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            canonicalize_fixture_document(actual.as_bytes()),
            canonicalize_fixture_document(&expected),
            "{name}"
        );
        completed_vector(PHAOS_DIR, name, CorpusOutcome::Decrypted);
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn decrypts_all_phaos_dh_vectors_from_original_text_key() {
    use der::Decode as _;
    use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
    use xml_sec::provider::{RUST_CRYPTO_PROVIDER, RustCryptoDhKey};
    use xml_sec::xmlenc::{
        AgreementDecryptor, DataEncryptionAlgorithm as D, KeyEstablishmentBudget,
    };

    // The donor's DER private key is truncated; its original key.txt carries
    // the complete p/q/g/x. Preserve both files unchanged and use the complete
    // published components, not a generated replacement or fixture exception.
    let text = std::fs::read_to_string(format!("{PHAOS_DIR}/key.txt")).expect("Phaos text keys");
    let dh_text = text
        .split_once("#Diffie-Hellman Private Key:")
        .expect("DH key section")
        .1;
    let component = |heading: &str| {
        dh_text
            .split_once(heading)
            .expect("DH component heading")
            .1
            .split('#')
            .next()
            .expect("DH component body")
            .split_whitespace()
            .map(|octet| u8::from_str_radix(octet, 16).expect("DH hexadecimal byte"))
            .collect::<Vec<_>>()
    };
    let (p, q, g, x) = (
        component("#Prime P"),
        component("#Prime Q"),
        component("#Generator G"),
        zeroize::Zeroizing::new(component("#Private Key Value")),
    );
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::TripleDesCbc, D::Aes128Cbc, D::Aes192Cbc, D::Aes256Cbc].into()),
        ..Default::default()
    };
    policy.key_establishment.agreement_algorithms = Some([KeyAgreementAlgorithm::LegacyDh].into());
    policy.key_establishment.derivation_algorithms =
        Some([xml_sec::policy::KeyDerivationAlgorithm::LegacyDh].into());
    policy.key_establishment.digest_algorithms =
        Some([xml_sec::xmldsig::DigestAlgorithm::Sha1].into());
    policy.key_establishment.minimum_dh_modulus_bits = 1024;
    policy.key_establishment.minimum_dh_subgroup_bits = 160;
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).expect("DH budget");
    let key = RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &x)
        .expect("published Phaos DH private key");
    let expected =
        std::fs::read(format!("{PHAOS_DIR}/payment.xml")).expect("original payment document");
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    for name in [
        "enc-element-3des-ka-dh",
        "enc-element-aes128-ka-dh",
        "enc-element-aes192-ka-dh",
        "enc-element-aes256-ka-dh",
    ] {
        let xml =
            std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml")).expect("DH ciphertext");
        let document = Document::parse(&xml).expect("DH document");
        let node = document
            .descendants()
            .find(|n| n.tag_name().name() == "EncryptedData")
            .expect("EncryptedData");
        let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy)
            .expect("DH agreement metadata");
        let certificate = node
            .descendants()
            .find(|n| n.tag_name().name() == "X509Certificate")
            .expect("originator certificate");
        let certificate = STANDARD
            .decode(
                certificate
                    .text()
                    .expect("certificate bytes")
                    .split_whitespace()
                    .collect::<String>(),
            )
            .expect("certificate base64");
        let certificate =
            x509_cert::Certificate::from_der(&certificate).expect("originator certificate DER");
        let peer_der = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .expect("byte-aligned DH public key");
        let peer = der::asn1::UintRef::from_der(peer_der).expect("DH public integer");
        let resolver = AgreementDecryptor::content(
            &parsed.agreement_methods[0],
            &key,
            peer.as_bytes(),
            D::from_uri(&parsed.encryption_method.algorithm).expect("donor content algorithm"),
        );
        let actual = DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt_document(&xml, Some("ED"))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            canonicalize_xml(actual.as_bytes(), &algorithm).expect("decrypted payment C14N"),
            canonicalize_xml(&expected, &algorithm).expect("original payment C14N"),
            "{name}"
        );
        completed_vector(PHAOS_DIR, name, CorpusOutcome::Decrypted);
    }
}

/// Asserts that a donor vector fails at its explicitly classified algorithm URI.
fn assert_unsupported(
    name: &str,
    expected_uri: &str,
    resolver: &dyn xml_sec::xmlenc::DecryptionKeyResolver,
) {
    let xml = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml"))
        .expect("tracked Phaos vector must be readable");
    let result = decrypt_document(&xml, Some("ED"), resolver);
    #[cfg(feature = "legacy-algorithms")]
    if xml_sec::xmlenc::DataEncryptionAlgorithm::from_uri(expected_uri).is_ok()
        || xml_sec::xmlenc::KeyWrapAlgorithm::from_uri(expected_uri).is_ok()
        || xml_sec::xmlenc::KeyTransportAlgorithm::from_uri(expected_uri).is_ok()
    {
        assert!(
            matches!(&result, Err(XmlEncError::Policy(xml_sec::policy::PolicyViolation::Algorithm { operation: "decryption", algorithm })) if algorithm == expected_uri),
            "{name} must deny unpermitted {expected_uri}, got {result:?}"
        );
        return;
    }
    assert!(
        matches!(&result, Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == expected_uri),
        "{name} must reject {expected_uri}, got {result:?}"
    );
}

/// Names ciphertext cases, excluding key and plaintext documents.
fn phaos_vector_names() -> BTreeSet<String> {
    std::fs::read_dir(PHAOS_DIR)
        .expect("Phaos fixture directory must be readable")
        .map(|entry| {
            entry
                .expect("Phaos directory entry must be readable")
                .path()
        })
        .filter(|path| {
            path.extension().is_some_and(|extension| extension == "xml")
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("enc-") || name.starts_with("bad-")
                })
        })
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_owned())
        .collect()
}

#[cfg(all(
    feature = "legacy-algorithms",
    feature = "experimental-pq",
    feature = "xmldsig"
))]
#[path = "common/xmlenc_ml_kem_corpus.rs"]
mod ml_kem_corpus;

#[cfg(all(
    feature = "legacy-algorithms",
    feature = "experimental-pq",
    feature = "xmldsig"
))]
#[path = "common/xmlenc_snapshot.rs"]
mod corpus_snapshot;

#[cfg(feature = "legacy-algorithms")]
#[test]
fn rejects_original_phaos_bad_wrapping_with_permitted_algorithms() {
    // A policy-denied algorithm is not a check of this negative ciphertext.
    // Use the original named DES credential. The bad document advertises AES
    // for a ciphertext whose length is not an AES block multiple; framing must
    // reject it before key recovery, rather than hiding it behind policy denial.
    let name = "bad-alg-enc-element-aes128-kw-3des";
    let xml = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml")).unwrap();
    let keys = std::fs::read_to_string(format!("{PHAOS_DIR}/keys.xml")).unwrap();
    let document = Document::parse(&keys).unwrap();
    let entry = document
        .root_element()
        .children()
        .find(|node| {
            node.descendants().any(|child| {
                child.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName"))
                    && child.text() == Some("my-tripledes-key")
            })
        })
        .unwrap();
    let value = entry
        .descendants()
        .find(|node| node.tag_name().name() == "DESKeyValue")
        .unwrap();
    let key = STANDARD
        .decode(
            value
                .text()
                .unwrap()
                .split_ascii_whitespace()
                .collect::<String>(),
        )
        .unwrap();
    let resolver = KekDecryptor::with_kind(key, xml_sec::key_manager::SymmetricKeyKind::Des);
    let policy = xml_sec::policy::DecryptionPolicy {
        key_wrap_algorithms: Some([xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes].into()),
        ..Default::default()
    };
    let result = DecryptContext::new(&resolver)
        .policy(policy)
        .decrypt_document(&xml, Some("ED"));
    assert!(
        matches!(
            result,
            Err(XmlEncError::InvalidCbcCiphertextLength {
                algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm::Aes128Cbc,
                block: 16,
                actual: 168,
            })
        ),
        "{name}: {result:?}"
    );
    completed_vector(PHAOS_DIR, name, CorpusOutcome::Rejected);
}

#[cfg(all(
    feature = "legacy-algorithms",
    feature = "experimental-pq",
    feature = "xmldsig"
))]
#[test]
fn complete_corpora_execute_every_vector_exactly_once() {
    // Classification comes from successful execution/assertions, never from
    // filenames mentioned in source, file counts or unsupported capabilities.
    corpus_snapshot::verify();
    struct Collection;
    impl Drop for Collection {
        fn drop(&mut self) {
            COMPLETED_VECTORS.with(|completed| *completed.borrow_mut() = None);
        }
    }
    COMPLETED_VECTORS.with(|completed| {
        assert!(completed.borrow().is_none());
        *completed.borrow_mut() = Some(Default::default());
    });
    let _collection = Collection;
    decrypts_every_chacha_donor_vector_and_authenticates_aad();
    decrypts_all_direct_camellia_donor_widths();
    decrypts_ecdh_concat_hashes_with_the_pinned_recipient_keys();
    decrypts_ecdh_p384_and_p521_donor_plaintexts();
    decrypts_ecdh_hkdf_and_pbkdf2_donor_plaintexts();
    decrypts_direct_pbkdf2_and_hkdf_donor_plaintexts();
    decrypts_hkdf_with_only_the_prf_parameter();
    decrypts_dh_es_concatkdf_with_pinned_domain_and_parties();
    classifies_all_pinned_xdh_concat_and_hkdf_vectors();
    decrypts_xmlsec1_direct_aes_keyname_vectors();
    decrypts_aleksey_legacy_direct_and_reference_shapes();
    decrypts_aleksey_rsa_oaep_document_vectors();
    decrypts_each_recipient_in_the_two_transport_key_vector();
    decrypts_iso_latin1_element_and_content_donor_documents();
    decrypts_rsa15_documents_with_certificate_selector_metadata();
    legacy_oaep_donor_hashes_require_permission_then_decrypt();
    for name in ml_kem_corpus::execute() {
        completed_vector(VECTOR_DIR, &name, CorpusOutcome::Decrypted);
    }
    decrypts_merlin_direct_and_wrapped_document_shapes();
    decrypts_merlin_rsa_transport_shapes();
    decrypts_merlin_same_document_cipher_reference();
    decrypts_merlin_carried_key_name_without_altering_other_recipients();
    decrypts_merlin_signature_documents_without_mutating_other_targets();
    rejects_original_merlin_corrupted_wrapped_key_before_document_mutation();
    verifies_merlin_signatures_after_authenticated_symmetric_key_unwrap();
    validates_merlin_rsa_transported_hmac_keys_without_exporting_recovered_keys();
    decrypts_merlin_dh_with_original_w3c_credentials();
    decrypts_supported_phaos_rsa_oaep_and_aes_kw_vectors();
    decrypts_all_phaos_legacy_transport_and_wrap_vectors();
    decrypts_all_phaos_dh_vectors_from_original_text_key();
    rejects_original_phaos_bad_wrapping_with_permitted_algorithms();

    let mut expected = BTreeSet::new();
    for (directory, auxiliary) in [
        (VECTOR_DIR, &[][..]),
        (MERLIN_DIR, &["keys.xml", "plaintext.xml"][..]),
        (PHAOS_DIR, &["keys.xml", "payment.xml"][..]),
    ] {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "xml") {
                continue;
            }
            let name = path.file_name().unwrap().to_str().unwrap();
            if !auxiliary.contains(&name) {
                assert!(expected.insert(path.to_str().unwrap().to_owned()));
            }
        }
        for name in auxiliary {
            assert!(
                Path::new(directory).join(name).is_file(),
                "stale auxiliary classification"
            );
        }
    }
    let completed = COMPLETED_VECTORS.with(|completed| completed.borrow_mut().take().unwrap());
    assert_eq!(completed.keys().cloned().collect::<BTreeSet<_>>(), expected);
    // Keep intentional deviations visible; no algorithm-denied or generic
    // Unsupported result may be recorded as successful donor compatibility.
    assert_eq!(
        completed
            .values()
            .filter(|outcome| **outcome == CorpusOutcome::DocumentedDeparture)
            .count(),
        19
    );
    assert_eq!(
        completed
            .values()
            .filter(|outcome| **outcome == CorpusOutcome::Rejected)
            .count(),
        4
    );
}

/// Proves that every encrypted Phaos vector has an explicit support classification.
#[test]
fn classifies_complete_phaos_decryption_corpus() {
    // Every Phaos ciphertext is classified. Legacy algorithms remain visible
    // interoperability boundaries rather than being silently skipped or enabled.
    const TRIPLEDES: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    const AES192: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    const KW_TRIPLEDES: &str = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
    const KW_AES192: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
    const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    const DH: &str = "http://www.w3.org/2001/04/xmlenc#dh";

    let direct = SymmetricKeyDecryptor::new([0_u8; 16]);
    let mut classified = execute_modern_phaos_vectors();
    for name in [
        "enc-content-3des-kw-aes192",
        "enc-element-3des-kt-rsa1_5",
        "enc-element-3des-kt-rsa_oaep_sha1",
        "enc-element-3des-kt-rsa_oaep_sha256",
        "enc-element-3des-kt-rsa_oaep_sha512",
        "enc-element-3des-kw-3des",
        "enc-text-3des-kw-aes256",
    ] {
        assert_unsupported(name, TRIPLEDES, &direct);
        assert!(classified.insert(name.to_owned()), "duplicate case: {name}");
    }
    for name in [
        "enc-content-aes192-kw-aes256",
        "enc-element-aes192-kt-rsa_oaep_sha1",
        "enc-element-aes192-kw-aes192",
        "enc-text-aes192-kt-rsa1_5",
    ] {
        assert_unsupported(name, AES192, &direct);
        assert!(classified.insert(name.to_owned()), "duplicate case: {name}");
    }

    let kek = KekDecryptor::new([0_u8; 32]);
    for name in [
        "bad-alg-enc-element-aes128-kw-3des",
        "enc-content-aes128-kw-3des",
    ] {
        assert_unsupported(name, KW_TRIPLEDES, &kek);
        assert!(classified.insert(name.to_owned()), "duplicate case: {name}");
    }
    assert_unsupported("enc-text-aes128-kw-aes192", KW_AES192, &kek);
    assert!(classified.insert("enc-text-aes128-kw-aes192".to_owned()));

    let private_key = PrivateKeyDecryptor::new(read_phaos_private_key());
    for name in [
        "enc-content-aes256-kt-rsa1_5",
        "enc-element-aes128-kt-rsa1_5",
    ] {
        assert_unsupported(name, RSA_1_5, &private_key);
        assert!(classified.insert(name.to_owned()), "duplicate case: {name}");
    }
    for name in [
        "enc-element-3des-ka-dh",
        "enc-element-aes128-ka-dh",
        "enc-element-aes192-ka-dh",
        "enc-element-aes256-ka-dh",
    ] {
        // Agreement is now parsed. A direct symmetric resolver must not claim
        // to perform DH, nor bypass the donor's transported party descriptors.
        let xml = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let node = document
            .descendants()
            .find(|node| node.tag_name().name() == "EncryptedData")
            .unwrap();
        let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(
            node,
            &xml_sec::policy::DecryptionPolicy::default(),
        )
        .unwrap();
        assert_eq!(parsed.agreement_methods[0].algorithm.uri(), DH);
        match name {
            "enc-element-3des-ka-dh" => assert_unsupported(name, TRIPLEDES, &direct),
            "enc-element-aes192-ka-dh" => assert_unsupported(name, AES192, &direct),
            _ => assert!(
                matches!(
                    decrypt_document(&xml, Some("ED"), &direct),
                    Err(XmlEncError::KeyNotFound)
                ),
                "{name}"
            ),
        }
        assert!(classified.insert(name.to_owned()), "duplicate case: {name}");
    }

    assert_eq!(classified.len(), 25);
    assert_eq!(classified, phaos_vector_names());
}

/// Verifies recipient-key mismatch and AES-KW integrity failure paths.
#[test]
fn rejects_phaos_wrong_rsa_key_and_tampered_wrapped_key() {
    // Independent negative paths prove OAEP does not accept another recipient's
    // key and RFC 3394 integrity is checked before donor content decryption.
    let rsa_xml = std::fs::read_to_string(format!(
        "{PHAOS_DIR}/enc-element-aes128-kt-rsa_oaep_sha1.xml"
    ))
    .expect("tracked Phaos RSA vector must be readable");
    let wrong_pem = std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
        .expect("tracked unrelated RSA key must be readable");
    let wrong_key = RsaPrivateKey::from_pkcs8_pem(&wrong_pem)
        .expect("tracked unrelated RSA key must be PKCS#8 PEM");
    let wrong_key_result =
        decrypt_document(&rsa_xml, Some("ED"), &PrivateKeyDecryptor::new(wrong_key));
    assert!(
        matches!(&wrong_key_result, Err(XmlEncError::Rsa(_))),
        "wrong RSA key must fail OAEP decryption, got {wrong_key_result:?}"
    );

    let mut wrapped_xml = std::fs::read(format!("{PHAOS_DIR}/enc-element-aes128-kw-aes128.xml"))
        .expect("tracked Phaos AES-KW vector must be readable");
    let marker = b"<CipherValue>";
    let start = wrapped_xml
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("Phaos EncryptedKey must contain CipherValue")
        + marker.len();
    let encoded = wrapped_xml[start..]
        .iter_mut()
        .find(|byte| !byte.is_ascii_whitespace())
        .expect("wrapped key must contain base64 data");
    *encoded = if *encoded == b'A' { b'B' } else { b'A' };
    let wrapped_xml = String::from_utf8(wrapped_xml).expect("Phaos XML must remain UTF-8");
    let keys = read_aes_keys(Path::new(&format!("{PHAOS_DIR}/keys.xml")));
    let kek = keys
        .get("my-aes128-key")
        .expect("Phaos AES-128 KEK must exist");
    assert!(matches!(
        decrypt_document(&wrapped_xml, Some("ED"), &KekDecryptor::new(kek.clone())),
        Err(XmlEncError::KeyWrapIntegrity)
    ));
}
