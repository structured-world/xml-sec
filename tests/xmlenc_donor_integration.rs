//! XMLEnc decrypt interoperability against pinned xmlsec1 donor vectors.

#![cfg(feature = "xmlenc")]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{AeadInOut, KeyInit},
};
use aes_kw::KwAes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, ParsingOptions};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize, canonicalize_xml};
use xml_sec::xmlenc::{
    DecryptedContent, DocumentDecryptionOptions, KekDecryptor, PrivateKeyDecryptor,
    SymmetricKeyDecryptor, XmlEncError, decrypt, decrypt_data, decrypt_document,
    decrypt_document_with_options, parse_encrypted_data,
};

const VECTOR_DIR: &str = "tests/fixtures/xmlenc/aleksey-xmlenc-01";
const NIST_DIR: &str = "tests/fixtures/xmlenc/nist-aesgcm";
const INTEROP_DIR: &str = "tests/fixtures/xmlenc/xmlenc11-interop-2012";
const MERLIN_DIR: &str = "tests/fixtures/xmlenc/merlin-xmlenc-five";
const PHAOS_DIR: &str = "tests/fixtures/xmlenc/01-phaos-xmlenc-3";
const KEY_INVENTORY: &str = "tests/fixtures/keys/keys.xml";

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
    }
}

#[test]
fn decrypts_aleksey_rsa_oaep_document_vectors() {
    // Full donor documents cover legacy OAEP defaults, an explicit OAEP label,
    // SHA-256 with fixed MGF1-SHA1, and XMLEnc 1.1 SHA-512/MGF1-SHA512.
    let pem = std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-4096-key.pem")
        .expect("tracked Aleksey RSA key must be readable");
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&pem).expect("tracked Aleksey RSA key must be PKCS#8 PEM");
    for name in [
        "enc-aes256-kt-rsa_oaep_sha1",
        "enc-aes256-kt-rsa_oaep_sha1-params",
        "enc-aes256-kt-rsa_oaep_sha256",
        "enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512",
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
    let decrypted = decrypt_document_with_options(
        &encrypted,
        DocumentDecryptionOptions {
            encrypted_data_id: Some("encrypt-data-0"),
            allow_dtd: true,
        },
        &SymmetricKeyDecryptor::new(key.clone()),
    )
    .expect("Merlin encrypted Content must be replaced");
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let actual_c14n = canonicalize_dtd_document(&decrypted, &algorithm);
    let expected = std::str::from_utf8(&expected).expect("Merlin plaintext must be UTF-8");
    let expected_c14n = canonicalize_dtd_document(expected, &algorithm);
    assert_eq!(actual_c14n, expected_c14n);
}

fn canonicalize_dtd_document(xml: &str, algorithm: &C14nAlgorithm) -> Vec<u8> {
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: true,
            entity_resolver: None,
            ..ParsingOptions::default()
        },
    )
    .expect("Merlin document with internal DTD must parse");
    let mut output = Vec::new();
    canonicalize(&document, None, algorithm, &mut output)
        .expect("Merlin document must canonicalize");
    output
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
            let result = decrypt(&xml, &SymmetricKeyDecryptor::new(key.clone()));

            if bits == 192 {
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
    assert!(unsupported > 0, "corpus must account for AES-192 vectors");
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

fn read_phaos_private_key() -> RsaPrivateKey {
    let der = std::fs::read(format!("{PHAOS_DIR}/rsa-priv-key.der"))
        .expect("tracked Phaos RSA key must be readable");
    RsaPrivateKey::from_pkcs1_der(&der).expect("Phaos RSA key must be PKCS#1 DER")
}

fn canonicalize_fixture_document(xml: &[u8]) -> Vec<u8> {
    canonicalize_xml(xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
        .expect("Phaos fixture must be canonicalizable XML")
}

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
}

#[test]
fn decrypts_supported_phaos_rsa_oaep_and_aes_kw_vectors() {
    // These Phaos-produced documents independently exercise RSA-OAEP and both
    // RFC 3394 KEK sizes through Element and Content document replacement.
    let private_key = read_phaos_private_key();
    for name in [
        "enc-element-aes128-kt-rsa_oaep_sha1",
        "enc-text-aes256-kt-rsa_oaep_sha1",
    ] {
        assert_phaos_document(name, &PrivateKeyDecryptor::new(private_key.clone()));
    }

    let keys = read_aes_keys(Path::new(&format!("{PHAOS_DIR}/keys.xml")));
    for (name, key_name) in [
        ("enc-element-aes128-kw-aes128", "my-aes128-key"),
        ("enc-element-aes128-kw-aes256", "my-aes256-key"),
        ("enc-element-aes256-kw-aes256", "my-aes256-key"),
    ] {
        let kek = keys.get(key_name).expect("Phaos KEK must exist");
        assert_phaos_document(name, &KekDecryptor::new(kek.clone()));
    }
}

fn assert_unsupported(
    name: &str,
    expected_uri: &str,
    resolver: &dyn xml_sec::xmlenc::DecryptionKeyResolver,
) {
    let xml = std::fs::read_to_string(format!("{PHAOS_DIR}/{name}.xml"))
        .expect("tracked Phaos vector must be readable");
    let result = decrypt_document(&xml, Some("ED"), resolver);
    assert!(
        matches!(&result, Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == expected_uri),
        "{name} must reject {expected_uri}, got {result:?}"
    );
}

fn phaos_vector_count() -> usize {
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
        .count()
}

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
    let mut classified = 5;
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
        classified += 1;
    }
    for name in [
        "enc-content-aes192-kw-aes256",
        "enc-element-aes192-kt-rsa_oaep_sha1",
        "enc-element-aes192-kw-aes192",
        "enc-text-aes192-kt-rsa1_5",
    ] {
        assert_unsupported(name, AES192, &direct);
        classified += 1;
    }

    let kek = KekDecryptor::new([0_u8; 32]);
    for name in [
        "bad-alg-enc-element-aes128-kw-3des",
        "enc-content-aes128-kw-3des",
    ] {
        assert_unsupported(name, KW_TRIPLEDES, &kek);
        classified += 1;
    }
    assert_unsupported("enc-text-aes128-kw-aes192", KW_AES192, &kek);
    classified += 1;

    let private_key = PrivateKeyDecryptor::new(read_phaos_private_key());
    for name in [
        "enc-content-aes256-kt-rsa1_5",
        "enc-element-aes128-kt-rsa1_5",
    ] {
        assert_unsupported(name, RSA_1_5, &private_key);
        classified += 1;
    }
    for name in [
        "enc-element-3des-ka-dh",
        "enc-element-aes128-ka-dh",
        "enc-element-aes192-ka-dh",
        "enc-element-aes256-ka-dh",
    ] {
        assert_unsupported(name, DH, &direct);
        classified += 1;
    }

    assert_eq!(classified, 25);
    assert_eq!(classified, phaos_vector_count());
}

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
