//! External decryption interoperability for XMLEnc produced by xml-sec.

#![cfg(feature = "xmlenc")]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

use rsa::RsaPublicKey;
use xml_sec::rsa_encoding::RsaPublicKeyEncoding as _;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, EncryptedDataBuilder, EncryptionRecipient, OaepDigestAlgorithm,
    RsaOaepParameters,
};
use xml_sec::{key_manager::KeyInventory, policy::ResourcePolicy};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn require_key_establishment_oracle() {
    // These acceptance tests intentionally require independent execution;
    // reporting success without an oracle would hide missing interoperability.
    assert!(
        xmlsec1::is_available(),
        "key-establishment interoperability requires xmlsec1 >= 1.3.13; run bash scripts/install-xmlsec1.sh and set XMLSEC1_BIN (see docs/crypto-providers.md)"
    );
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn path(label: &str, extension: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos();
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            path: std::env::temp_dir().join(format!(
                "xml-sec-{label}-{}-{timestamp}-{sequence}.{extension}",
                std::process::id()
            )),
        }
    }

    fn write(label: &str, extension: &str, contents: &[u8]) -> Self {
        let file = Self::path(label, extension);
        fs::write(&file.path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", file.path.display()));
        file
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn decrypt_with_xmlsec1(encrypted_xml: &str, key_option: &str, key_path: &Path) -> Vec<u8> {
    let input = TemporaryFile::write("xmlenc-input", "xml", encrypted_xml.as_bytes());
    let output = TemporaryFile::path("xmlenc-output", "data");
    let command_output = xmlsec1::command()
        .arg("decrypt")
        .arg("--lax-key-search")
        .arg(key_option)
        .arg(key_path)
        .arg("--output")
        .arg(&output.path)
        .arg(&input.path)
        .output()
        .expect("xmlsec1 must be installed for XMLEnc interoperability tests");
    assert!(
        command_output.status.success(),
        "xmlsec1 rejected xml-sec ciphertext:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&command_output.stdout),
        String::from_utf8_lossy(&command_output.stderr)
    );
    fs::read(&output.path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", output.path.display()))
}

#[test]
fn xmlsec1_version_gate_accepts_ci_version() {
    assert!(!xmlsec1::version_supports_interop(
        "xmlsec1 1.3.12 (openssl)"
    ));
    assert!(xmlsec1::version_supports_interop(
        "xmlsec1 1.3.13 (openssl)"
    ));
}

#[test]
fn cipher_reference_has_reciprocal_libxmlsec1_interoperability() {
    // CipherReference dereferences a source node and applies ds:base64, rather
    // than accidentally treating its XML text or serialized subtree as bytes.
    require_key_establishment_oracle();
    use xml_sec::xmlenc::{DecryptContext, DecryptedContent, SymmetricKeyDecryptor};
    fn referenced(wire: &str) -> String {
        let parsed = xml_sec::xmlenc::parse_encrypted_data(wire).expect("inline oracle data");
        let value = parsed
            .cipher_data
            .inline_value()
            .expect("inline ciphertext");
        let start = wire
            .find("<CipherValue>")
            .map(|index| (index, "</CipherValue>"))
            .or_else(|| {
                wire.find("<xenc:CipherValue>")
                    .map(|index| (index, "</xenc:CipherValue>"))
            })
            .expect("known CipherValue serialization");
        let end =
            start.0 + wire[start.0..].find(start.1).expect("closing CipherValue") + start.1.len();
        let mut result = wire.to_owned();
        result.replace_range(start.0..end, "<x:CipherReference xmlns:x='http://www.w3.org/2001/04/xmlenc#' URI='#cipher'><x:Transforms><d:Transform xmlns:d='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/2000/09/xmldsig#base64'/></x:Transforms></x:CipherReference>");
        let location = result
            .find("<CipherData>")
            .or_else(|| result.find("<xenc:CipherData>"))
            .expect("CipherData location");
        result.insert_str(location, &format!("<d:KeyInfo xmlns:d='http://www.w3.org/2000/09/xmldsig#'><f:Ciphertext xmlns:f='urn:xml-sec:interop' xml:id='cipher'>{value}</f:Ciphertext></d:KeyInfo>"));
        result
    }
    let secret = [0x59; 16];
    let key = TemporaryFile::write("cipher-reference-key", "bin", &secret);
    let plaintext = b"reciprocal source-anchored ciphertext reference";
    let produced = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(secret)
        .encrypt_binary(plaintext)
        .expect("Rust encryption");
    assert_eq!(
        decrypt_with_xmlsec1(
            &referenced(&produced.encrypted_data_xml),
            "--aeskey",
            &key.path
        ),
        plaintext
    );

    let template = TemporaryFile::write("cipher-reference-template", "xml", b"<EncryptedData xmlns='http://www.w3.org/2001/04/xmlenc#'><EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/><CipherData><CipherValue/></CipherData></EncryptedData>");
    let input = TemporaryFile::write("cipher-reference-plain", "bin", plaintext);
    let output = TemporaryFile::path("cipher-reference-donor", "xml");
    // The public test key is deliberately unnamed; select it explicitly by
    // mechanism rather than requiring a private store's KeyName convention.
    let status = xmlsec1::command()
        .args(["encrypt", "--lax-key-search", "--aeskey"])
        .arg(&key.path)
        .arg("--binary-data")
        .arg(&input.path)
        .arg("--output")
        .arg(&output.path)
        .arg(&template.path)
        .output()
        .expect("donor encryption");
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let wire = referenced(&fs::read_to_string(&output.path).expect("donor output"));
    assert_eq!(
        DecryptContext::new(&SymmetricKeyDecryptor::new(secret))
            .decrypt(&wire)
            .expect("Rust reference decryption"),
        DecryptedContent::Bytes(plaintext.to_vec())
    );
}

#[test]
fn kdf_xml_has_reciprocal_libxmlsec1_interoperability() {
    // Exercise actual transported descriptors, not prederived AES keys: each
    // supported SHA family/KDF runs in BOTH directions against libxmlsec1.
    require_key_establishment_oracle();
    use xml_sec::xmlenc::{DecryptContext, DecryptedContent, DerivedKeyDecryptor, DerivedKeyInput};
    const NS: &str = "http://www.w3.org/2009/xmlenc11#";
    const MORE: &str = "http://www.w3.org/2021/04/xmldsig-more#";
    let secret = b"xml-sec public interoperability test secret";
    let key = TemporaryFile::write("xmlenc-kdf-key", "bin", secret);
    let plaintext = b"independent XML key derivation interoperability";
    let data = TemporaryFile::write("xmlenc-kdf-plain", "data", plaintext);
    for sha in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
        let digest = match sha {
            "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
            "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "sha512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            "sha224" => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            _ => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        };
        let hmac = if sha == "sha1" {
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1".to_owned()
        } else {
            format!("http://www.w3.org/2001/04/xmldsig-more#hmac-{sha}")
        };
        let cases = [
            (
                "--pbkdf2-key",
                format!(
                    "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}pbkdf2'><PBKDF2-params><Salt><Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount><KeyLength>32</KeyLength><PRF Algorithm='{hmac}'/></PBKDF2-params></KeyDerivationMethod>"
                ),
            ),
            (
                "--hkdf-key",
                format!(
                    "<KeyDerivationMethod xmlns='{NS}' Algorithm='{MORE}hkdf'><HKDFParams xmlns='{MORE}'><PRF Algorithm='{hmac}'/><Salt>c2FsdA==</Salt><Info>aW5mbw==</Info><KeyLength>32</KeyLength></HKDFParams></KeyDerivationMethod>"
                ),
            ),
            // XMLEnc 1.1 §5.4.1 permits partial octets, but libxmlsec1's
            // xmlSecTransformConcatKdfParamsReadsBitsAttr supports only byte
            // alignment. Partial fields are independently covered in xmlenc_kdf.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
            (
                "--concatkdf-key",
                format!(
                    "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}ConcatKDF'><ConcatKDFParams AlgorithmID='0000' PartyUInfo='00D8' PartyVInfo='00D0'><DigestMethod xmlns='http://www.w3.org/2000/09/xmldsig#' Algorithm='{digest}'/></ConcatKDFParams></KeyDerivationMethod>"
                ),
            ),
        ];
        for (option, xml) in cases {
            let method =
                xml_sec::xmlenc::parse_key_derivation_method(&xml, &Default::default()).unwrap();
            let mut outbound = xml_sec::policy::EncryptionPolicy::default();
            outbound.key_establishment.digest_algorithms = Some(
                [
                    xml_sec::xmldsig::DigestAlgorithm::Sha1,
                    xml_sec::xmldsig::DigestAlgorithm::Sha224,
                    xml_sec::xmldsig::DigestAlgorithm::Sha256,
                    xml_sec::xmldsig::DigestAlgorithm::Sha384,
                    xml_sec::xmldsig::DigestAlgorithm::Sha512,
                ]
                .into_iter()
                .collect(),
            );
            let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
                .policy(outbound)
                .derived_key(method.clone(), secret.to_vec())
                .encrypt_binary(plaintext)
                .unwrap();
            assert_eq!(
                decrypt_with_xmlsec1(&encrypted.encrypted_data_xml, option, &key.path),
                plaintext,
                "{option}/{sha}"
            );
            let template = TemporaryFile::write(
                "xmlenc-kdf-template",
                "xml",
                encrypted.encrypted_data_xml.as_bytes(),
            );
            let output = TemporaryFile::path("xmlenc-kdf-oracle", "xml");
            let result = xmlsec1::command()
                .arg("encrypt")
                .arg("--lax-key-search")
                .arg(option)
                .arg(&key.path)
                .arg("--binary")
                .arg(&data.path)
                .arg("--output")
                .arg(&output.path)
                .arg(&template.path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{option}/{sha}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let resolver = DerivedKeyDecryptor::content(
                &method,
                DerivedKeyInput::Secret(secret),
                DataEncryptionAlgorithm::Aes256Gcm,
            );
            let mut inbound = xml_sec::policy::DecryptionPolicy::default();
            inbound.key_establishment.digest_algorithms = Some(
                [
                    xml_sec::xmldsig::DigestAlgorithm::Sha1,
                    xml_sec::xmldsig::DigestAlgorithm::Sha224,
                    xml_sec::xmldsig::DigestAlgorithm::Sha256,
                    xml_sec::xmldsig::DigestAlgorithm::Sha384,
                    xml_sec::xmldsig::DigestAlgorithm::Sha512,
                ]
                .into_iter()
                .collect(),
            );
            assert_eq!(
                DecryptContext::new(&resolver)
                    .policy(inbound)
                    .decrypt(&fs::read_to_string(&output.path).unwrap())
                    .unwrap(),
                DecryptedContent::Bytes(plaintext.to_vec()),
                "{option}/{sha}"
            );
        }
    }
}

#[test]
fn ecdh_xml_has_reciprocal_libxmlsec1_interoperability() {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use xml_sec::provider::{EcdhCurve, RustCryptoEcdhKey};
    use xml_sec::xmlenc::{AgreementDecryptor, DecryptContext, DecryptedContent};
    // Independently loaded private/public keys exercise the actual agreement,
    // XML KDF descriptor and content cipher in both directions, not raw AES.
    require_key_establishment_oracle();
    for (curve, width) in [
        (EcdhCurve::P256, 32),
        (EcdhCurve::P384, 48),
        (EcdhCurve::P521, 66),
    ] {
        let mut sender_scalar = vec![3; width];
        let mut recipient_scalar = vec![5; width];
        if curve == EcdhCurve::P521 {
            sender_scalar[0] = 0;
            recipient_scalar[0] = 0;
        }
        macro_rules! pem_pair {
            ($secret:ty, $scalar:expr) => {{
                let secret = <$secret>::from_slice($scalar).unwrap();
                (
                    secret.to_pkcs8_pem(LineEnding::LF).unwrap(),
                    secret
                        .public_key()
                        .to_public_key_pem(LineEnding::LF)
                        .unwrap(),
                )
            }};
        }
        let (sender_pem, sender_pub) = match curve {
            EcdhCurve::P256 => pem_pair!(p256::SecretKey, &sender_scalar),
            EcdhCurve::P384 => pem_pair!(p384::SecretKey, &sender_scalar),
            EcdhCurve::P521 => pem_pair!(p521::SecretKey, &sender_scalar),
        };
        let (recipient_pem, recipient_pub) = match curve {
            EcdhCurve::P256 => pem_pair!(p256::SecretKey, &recipient_scalar),
            EcdhCurve::P384 => pem_pair!(p384::SecretKey, &recipient_scalar),
            EcdhCurve::P521 => pem_pair!(p521::SecretKey, &recipient_scalar),
        };
        let sender_private = TemporaryFile::write("ecdh-sender", "pem", sender_pem.as_bytes());
        let sender_public =
            TemporaryFile::write("ecdh-sender-public", "pem", sender_pub.as_bytes());
        let recipient_private =
            TemporaryFile::write("ecdh-recipient", "pem", recipient_pem.as_bytes());
        let recipient_public =
            TemporaryFile::write("ecdh-recipient-public", "pem", recipient_pub.as_bytes());
        let sender_handle = RustCryptoEcdhKey::from_scalar(curve, &sender_scalar).unwrap();
        let sender_peer = sender_handle.public_key();
        let recipient_handle = RustCryptoEcdhKey::from_scalar(curve, &recipient_scalar).unwrap();
        let method = xml_sec::xmlenc::parse_key_derivation_method(
        "<KeyDerivationMethod xmlns='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2009/xmlenc11#ConcatKDF'><ConcatKDFParams AlgorithmID='00123456' PartyUInfo='00123456' PartyVInfo='00123456'><DigestMethod xmlns='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/></ConcatKDFParams></KeyDerivationMethod>",
        &Default::default()).unwrap();
        let plaintext = b"reciprocal ECDH XML interoperability";
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .agreement_key(
                method,
                Box::new(sender_handle),
                xml_sec::policy::KeyAgreementAlgorithm::EcdhEs,
                recipient_handle.public_key(),
            )
            .encrypt_binary(plaintext)
            .unwrap();
        let wire = encrypted.encrypted_data_xml.replace("</xenc:AgreementMethod>",
        "<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName></xenc:OriginatorKeyInfo><xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo></xenc:AgreementMethod>");
        let input = TemporaryFile::write("ecdh-input", "xml", wire.as_bytes());
        let output = TemporaryFile::path("ecdh-output", "data");
        let status = xmlsec1::command()
            .arg("decrypt")
            .arg("--privkey-pem:recipient")
            .arg(&recipient_private.path)
            .arg("--pubkey-pem:originator")
            .arg(&sender_public.path)
            .arg("--output")
            .arg(&output.path)
            .arg(&input.path)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert_eq!(fs::read(&output.path).unwrap(), plaintext);
        let parsed = xml_sec::xmlenc::parse_encrypted_data(&wire).unwrap();
        let descriptor = &parsed.agreement_methods[0];
        let template = wire.replace(parsed.cipher_data.inline_value().unwrap(), "");
        let template = TemporaryFile::write("ecdh-template", "xml", template.as_bytes());
        let data = TemporaryFile::write("ecdh-plain", "data", plaintext);
        let donor = TemporaryFile::path("ecdh-donor", "xml");
        let status = xmlsec1::command()
            .arg("encrypt")
            .arg("--privkey-pem:originator")
            .arg(&sender_private.path)
            .arg("--pubkey-pem:recipient")
            .arg(&recipient_public.path)
            .arg("--binary-data")
            .arg(&data.path)
            .arg("--output")
            .arg(&donor.path)
            .arg(&template.path)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let resolver = AgreementDecryptor::content(
            descriptor,
            &recipient_handle,
            &sender_peer,
            DataEncryptionAlgorithm::Aes128Gcm,
        );
        assert_eq!(
            DecryptContext::new(&resolver)
                .decrypt(&fs::read_to_string(&donor.path).unwrap())
                .unwrap(),
            DecryptedContent::Bytes(plaintext.to_vec())
        );
    }
}

#[test]
fn xmlsec1_decrypts_direct_aes_gcm_from_xml_sec() {
    // This validates nonce/tag framing and direct KeyName XML against an
    // independent implementation rather than our reciprocal decrypt path.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let key = [0x4a; 16];
    let plaintext = b"xmlsec1 direct AES-GCM interoperability";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .direct_key_name("interop-aes")
        .encrypt_binary(plaintext)
        .expect("direct AES-GCM encryption must succeed");
    let key_file = TemporaryFile::write("xmlenc-aes-key", "bin", &key);

    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--aeskey:interop-aes",
            &key_file.path
        ),
        plaintext
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn xmlsec1_decrypts_all_optional_content_and_transport_methods() {
    // Independent libxmlsec1 checks the 8-byte TDEA framing, AES-192 nonce/tag
    // layout, and parameterless RSA-1.5 transport, not just our own round trips.
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::xmlenc::KeyTransportAlgorithm;
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let plaintext = b"optional legacy mechanism interoperability";
    for algorithm in [
        DataEncryptionAlgorithm::TripleDesCbc,
        DataEncryptionAlgorithm::Aes192Cbc,
        DataEncryptionAlgorithm::Aes192Gcm,
    ] {
        let key = [0x31; 24];
        let encrypted = EncryptedDataBuilder::new(algorithm)
            .direct_key(key)
            .direct_key_name("interop")
            .policy(EncryptionPolicy {
                data_algorithms: Some([algorithm].into()),
                ..EncryptionPolicy::default()
            })
            .encrypt_binary(plaintext)
            .expect("explicitly permitted encryption");
        let file = TemporaryFile::write("legacy-key", "bin", &key);
        let option = if algorithm == DataEncryptionAlgorithm::TripleDesCbc {
            "--deskey:interop"
        } else {
            "--aeskey:interop"
        };
        assert_eq!(
            decrypt_with_xmlsec1(&encrypted.encrypted_data_xml, option, &file.path),
            plaintext
        );
    }
    for algorithm in [
        xml_sec::xmlenc::KeyWrapAlgorithm::AesKw192,
        xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes,
    ] {
        // Verify emitted CMS and AES-192 key-wrap bytes with the independent
        // resolver, complementing imported donor ciphertext decryption.
        let key = [0x31; 24];
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .add_recipient(
                EncryptionRecipient::aes_key_wrap(key, algorithm).key_name("interop-wrap"),
            )
            .policy(EncryptionPolicy {
                key_wrap_algorithms: Some([algorithm].into()),
                ..EncryptionPolicy::default()
            })
            .encrypt_binary(plaintext)
            .expect("permitted wrapping");
        let file = TemporaryFile::write("legacy-kek", "bin", &key);
        let option = if algorithm == xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes {
            "--deskey:interop-wrap"
        } else {
            "--aeskey:interop-wrap"
        };
        assert_eq!(
            decrypt_with_xmlsec1(&encrypted.encrypted_data_xml, option, &file.path),
            plaintext
        );
    }
    let public = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem").expect("public key"),
    )
    .expect("RSA SPKI");
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(EncryptionRecipient::rsa_pkcs1v15(public).key_name("interop-rsa"))
        .policy(EncryptionPolicy {
            key_transport_algorithms: Some([KeyTransportAlgorithm::RsaPkcs1v15].into()),
            ..EncryptionPolicy::default()
        })
        .encrypt_binary(plaintext)
        .expect("RSA-1.5 encryption");
    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--privkey-pem:interop-rsa",
            Path::new("tests/fixtures/keys/rsa/rsa-2048-key.pem")
        ),
        plaintext
    );
}

#[test]
fn xmlsec1_decrypts_rsa_oaep_wrapped_aes_cbc_from_xml_sec() {
    // This covers generated session-key transport, OAEP digest/MGF metadata,
    // nested EncryptedKey lookup, and XMLEnc CBC random-padding framing.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let public_key_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let private_key_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let public_key = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(public_key_path).expect("RSA public-key fixture must load"),
    )
    .expect("RSA public-key fixture must contain SPKI PEM");
    let plaintext = b"xmlsec1 RSA-OAEP and AES-CBC interoperability";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Cbc)
        .add_recipient(
            EncryptionRecipient::rsa_oaep(public_key)
                .oaep_parameters(
                    RsaOaepParameters::xmlenc11(
                        OaepDigestAlgorithm::Sha256,
                        OaepDigestAlgorithm::Sha256,
                    )
                    .label(b"xmlsec1-interop-label".to_vec()),
                )
                .key_name("interop-rsa"),
        )
        .encrypt_binary(plaintext)
        .expect("RSA-OAEP encryption must succeed");

    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--privkey-pem:interop-rsa",
            private_key_path
        ),
        plaintext
    );
}

#[test]
fn xmlsec1_decrypts_rsa_recipient_imported_by_key_inventory() {
    // A caller-owned inventory, rather than a directly decoded RSA fixture,
    // must preserve the independent libxmlsec1 transport wire contract.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let public_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let private_path = Path::new("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let public_pem = fs::read(public_path).expect("public-key fixture must load");
    let mut keys = KeyInventory::default();
    keys.add_public_pem(
        "inventory-rsa".into(),
        &public_pem,
        &ResourcePolicy::default(),
    )
    .expect("named public key must import");
    let public = keys
        .rsa_encryption_key(
            "inventory-rsa",
            &xml_sec::policy::EncryptionPolicy::default(),
        )
        .expect("imported RSA key must be usable for encryption");
    let plaintext = b"inventory-backed xmlsec1 interoperability";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(EncryptionRecipient::rsa_oaep(public).key_name("inventory-rsa"))
        .encrypt_binary(plaintext)
        .expect("inventory-backed encryption must succeed");
    assert_eq!(
        decrypt_with_xmlsec1(
            &encrypted.encrypted_data_xml,
            "--privkey-pem:inventory-rsa",
            private_path
        ),
        plaintext
    );
}
