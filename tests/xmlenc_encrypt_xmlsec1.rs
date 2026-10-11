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
use xml_sec::rsa_encoding::{RsaPrivateKeyEncoding as _, RsaPublicKeyEncoding as _};
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

#[cfg(all(feature = "xmldsig", feature = "c14n"))]
#[test]
fn merlin_templates_execute_reciprocally_with_xml_replacement() {
    // Execute the original templates, not generated lookalikes: metadata and
    // nested KeyInfo must survive the CLI's public template application path.
    // Each direction uses an independent crypto implementation and compares
    // the whole replacement document, not only the decrypted secret subtree.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
    use xml_sec::key_manager::SymmetricKeyKind;
    use xml_sec::policy::DecryptionPolicy;
    use xml_sec::xmlenc::{DecryptContext, KekDecryptor, SymmetricKeyDecryptor};

    require_key_establishment_oracle();
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xmlenc/merlin-xmlenc-five");
    let cases = [
        ("encrypt-data-aes128-cbc", "job", false),
        ("encrypt-content-aes256-cbc-prop", "jed", false),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-content-aes128-cbc-kw-aes192", "jeb", true),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-content-tripledes-cbc", "bob", false),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-data-aes192-cbc-kw-aes256", "jed", true),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-data-aes256-cbc-kw-tripledes", "bob", true),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-element-tripledes-cbc-kw-aes128", "job", true),
        #[cfg(feature = "legacy-algorithms")]
        (
            "encrypt-data-tripledes-cbc-rsa-oaep-mgf1p",
            "merlin-rsa-key",
            true,
        ),
        #[cfg(feature = "legacy-algorithms")]
        (
            "encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256",
            "merlin-rsa-key",
            true,
        ),
        #[cfg(feature = "legacy-algorithms")]
        ("encrypt-element-aes128-cbc-rsa-1_5", "merlin-rsa-key", true),
    ];
    let xml = "<PaymentInfo xmlns='urn:example:po'><BillingAddress>Donor template roundtrip</BillingAddress><CreditCard Type='test'/></PaymentInfo>";
    let binary = b"binary donor template roundtrip\0\xff";
    let xml_input = TemporaryFile::write("merlin-plaintext", "xml", xml.as_bytes());
    let binary_input = TemporaryFile::write("merlin-plaintext", "bin", binary);
    let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let policy = DecryptionPolicy {
        key_transport_algorithms: Some(
            [
                xml_sec::xmlenc::KeyTransportAlgorithm::RsaOaepMgf1p,
                #[cfg(feature = "legacy-algorithms")]
                xml_sec::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15,
            ]
            .into(),
        ),
        key_wrap_algorithms: Some(
            [
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128,
                #[cfg(feature = "legacy-algorithms")]
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw192,
                xml_sec::xmlenc::KeyWrapAlgorithm::AesKw256,
                #[cfg(feature = "legacy-algorithms")]
                xml_sec::xmlenc::KeyWrapAlgorithm::TripleDes,
            ]
            .into(),
        ),
        data_algorithms: Some(
            cases
                .iter()
                .map(|(name, _, _)| {
                    let template =
                        fs::read_to_string(directory.join(format!("{name}.tmpl"))).unwrap();
                    let document = xml_sec::Document::parse(&template).unwrap();
                    let method = document
                        .root_element()
                        .children()
                        .find(|node| {
                            node.is_element() && node.tag_name().name() == "EncryptionMethod"
                        })
                        .unwrap();
                    DataEncryptionAlgorithm::from_uri(method.attribute("Algorithm").unwrap())
                        .unwrap()
                })
                .collect(),
        ),
        ..DecryptionPolicy::default()
    };
    let mut completed = std::collections::BTreeSet::new();
    for (name, key_name, wrapped) in cases {
        let template = directory.join(format!("{name}.tmpl"));
        let source = fs::read_to_string(&template).unwrap();
        let document = xml_sec::Document::parse(&source).unwrap();
        let encrypted_type = document.root_element().attribute("Type");
        let is_binary = encrypted_type.is_none();
        let option = if is_binary {
            "--binary-data"
        } else {
            "--xml-data"
        };
        let input = if is_binary {
            &binary_input.path
        } else {
            &xml_input.path
        };
        let rsa = key_name == "merlin-rsa-key";
        let key = match key_name {
            "job" => b"abcdefghijklmnop".as_slice(),
            "jeb" | "bob" => b"abcdefghijklmnopqrstuvwx".as_slice(),
            "jed" => b"abcdefghijklmnopqrstuvwxyz012345".as_slice(),
            "merlin-rsa-key" => &[],
            _ => unreachable!("case table names a donor key"),
        };
        let kind = match key_name {
            #[cfg(feature = "legacy-algorithms")]
            "bob" => SymmetricKeyKind::Des,
            _ => SymmetricKeyKind::Aes,
        };
        let key_file = TemporaryFile::write("merlin-selected-key", "bin", key);
        let expected_xml = match encrypted_type {
            Some("http://www.w3.org/2001/04/xmlenc#Content") => "<holder xmlns='urn:example:po'><BillingAddress>Donor template roundtrip</BillingAddress><CreditCard Type='test'/></holder>".to_owned(),
            Some("http://www.w3.org/2001/04/xmlenc#Element") => format!("<holder xmlns='urn:example:po'>{xml}</holder>"),
            None => String::new(),
            other => panic!("unexpected donor Type: {other:?}"),
        };
        for native in [true, false] {
            let output = TemporaryFile::path("merlin-encrypted", "xml");
            let mut command = if native {
                std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
            } else {
                xmlsec1::command()
            };
            command.arg("encrypt");
            if rsa {
                // Keep the donor template unchanged but select our 2048-bit
                // credential: template interoperability must not relax the
                // CLI's RSA minimum for historical 1024-bit sample keys.
                command
                    .arg("--pubkey-pem:merlin-rsa-key")
                    .arg("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
            } else if native {
                // The complete original key store contains DES. A build
                // without that capability correctly rejects the store; pass
                // only the caller-selected, template-named credential here.
                let family = if key_name == "bob" { "des" } else { "aes" };
                command
                    .arg(format!("--{family}-key:{key_name}"))
                    .arg(&key_file.path);
            } else {
                command.arg("--keys-file").arg(directory.join("keys.xml"));
            }
            if !native && wrapped {
                let method = document
                    .root_element()
                    .children()
                    .find(|node| {
                        node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptionMethod"))
                    })
                    .unwrap();
                let algorithm =
                    DataEncryptionAlgorithm::from_uri(method.attribute("Algorithm").unwrap())
                        .unwrap();
                let family = if algorithm.uri().ends_with("tripledes-cbc") {
                    "des"
                } else {
                    "aes"
                };
                command
                    .arg("--session-key")
                    .arg(format!("{family}-{}", algorithm.key_len() * 8));
            }
            let result = command
                .arg(option)
                .arg(input)
                .arg("--output")
                .arg(&output.path)
                .arg(&template)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{name}, native={native}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let wire = fs::read_to_string(&output.path).unwrap();
            let wire_document = xml_sec::Document::parse(&wire).unwrap();
            let data_node = wire_document
                .descendants()
                .find(|node| {
                    node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"))
                })
                .unwrap_or_else(|| {
                    panic!("{name}, native={native}: missing EncryptedData in {wire}")
                });
            let parsed = xml_sec::xmlenc::parse_encrypted_data(&wire[data_node.range()]).unwrap();
            for attribute in ["Id", "MimeType", "Encoding"] {
                assert_eq!(
                    data_node.attribute(attribute),
                    document.root_element().attribute(attribute),
                    "{name}: {attribute}"
                );
            }
            if wrapped {
                assert_eq!(parsed.encrypted_keys.len(), 1, "{name}");
                assert_eq!(
                    parsed.encrypted_keys[0].key_name.as_deref(),
                    Some(key_name),
                    "{name}"
                );
            } else {
                assert!(parsed.encrypted_keys.is_empty(), "{name}");
                assert_eq!(parsed.key_name.as_deref(), Some(key_name), "{name}");
            }
            if native
                && let Some(properties) = document.descendants().find(|node| {
                    node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptionProperties"))
                })
            {
                assert!(
                    wire.contains(&source[properties.range()]),
                    "{name}: template properties changed"
                );
            }
            let expected_type = encrypted_type.map(|uri| match uri {
                "http://www.w3.org/2001/04/xmlenc#Content" => {
                    xml_sec::xmlenc::EncryptedDataType::Content
                }
                "http://www.w3.org/2001/04/xmlenc#Element" => {
                    xml_sec::xmlenc::EncryptedDataType::Element
                }
                _ => panic!("unexpected template Type"),
            });
            assert_eq!(parsed.encrypted_type, expected_type, "{name}");
            let wire = if is_binary {
                wire
            } else {
                format!(
                    // Content decryption uses the receiving parent's namespace
                    // context. Keep the donor --xml-data parent's default
                    // namespace when moving its encrypted child for comparison.
                    "<holder xmlns='urn:example:po'>{}</holder>",
                    &wire[data_node.range()]
                )
            };
            if native {
                let input = TemporaryFile::write("merlin-ciphertext", "xml", wire.as_bytes());
                let decrypted = TemporaryFile::path("merlin-decrypted", "bin");
                let mut command = xmlsec1::command();
                command.arg("decrypt");
                if rsa {
                    command
                        .arg("--privkey-pem:merlin-rsa-key")
                        .arg("tests/fixtures/keys/rsa/rsa-2048-key.pem");
                } else {
                    command.arg("--keys-file").arg(directory.join("keys.xml"));
                }
                let result = command
                    .arg("--output")
                    .arg(&decrypted.path)
                    .arg(&input.path)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{name}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let actual = fs::read(&decrypted.path).unwrap();
                if is_binary {
                    assert_eq!(actual, binary, "{name}");
                } else {
                    assert_eq!(
                        canonicalize_xml(&actual, &c14n).unwrap(),
                        canonicalize_xml(expected_xml.as_bytes(), &c14n).unwrap(),
                        "{name}"
                    );
                }
            } else {
                let direct = SymmetricKeyDecryptor::with_kind(key.to_vec(), kind);
                let kek = KekDecryptor::with_kind(key.to_vec(), kind);
                let private = if rsa {
                    Some(xml_sec::xmlenc::PrivateKeyDecryptor::new(
                        rsa::RsaPrivateKey::from_pkcs8_pem(
                            &fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
                                .unwrap(),
                        )
                        .unwrap(),
                    ))
                } else {
                    None
                };
                let resolver: &dyn xml_sec::xmlenc::DecryptionKeyResolver = if rsa {
                    private.as_ref().unwrap()
                } else if wrapped {
                    &kek
                } else {
                    &direct
                };
                let context = DecryptContext::new(resolver).policy(policy.clone());
                if is_binary {
                    assert_eq!(
                        context.decrypt(&wire).unwrap(),
                        xml_sec::xmlenc::DecryptedContent::Bytes(binary.to_vec()),
                        "{name}"
                    );
                } else {
                    let actual = context.decrypt_document(&wire, None).unwrap();
                    assert_eq!(
                        canonicalize_xml(actual.as_bytes(), &c14n).unwrap(),
                        canonicalize_xml(expected_xml.as_bytes(), &c14n).unwrap(),
                        "{name}"
                    );
                }
            }
        }
        assert!(
            completed.insert(format!("{name}.tmpl")),
            "duplicate template: {name}"
        );
    }
    #[cfg(feature = "legacy-algorithms")]
    {
        // Inventory is derived from the imported files, while completion is
        // recorded only after both encryption/decryption directions succeed.
        // A newly imported EncryptedData template cannot silently go unrun.
        let mut expected = std::collections::BTreeSet::new();
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "tmpl") {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let document = xml_sec::Document::parse(&source).unwrap();
            let name = path.file_name().unwrap().to_str().unwrap();
            if document
                .root_element()
                .has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"))
            {
                assert!(expected.insert(name.to_owned()));
            } else {
                // This is a signing template with an EncryptedKey, not an
                // EncryptedData template. Its emitted signature/key unwrap
                // is covered by the Merlin signature integration tests.
                assert_eq!(name, "encsig-ripemd160-hmac-ripemd160-kw-tripledes.tmpl");
                assert!(
                    document
                        .root_element()
                        .has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature",))
                );
            }
        }
        assert_eq!(
            completed, expected,
            "unexecuted or stale Merlin template cases"
        );
    }
}

#[test]
fn camellia_cbc_and_key_wrap_interoperate_at_every_key_width() {
    // An independent implementation must consume our CBC padding and RFC3394
    // output. Self-roundtrips alone can hide a shared framing defect.
    require_key_establishment_oracle();
    use DataEncryptionAlgorithm as D;
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::xmlenc::KeyWrapAlgorithm as W;
    let policy = EncryptionPolicy {
        data_algorithms: Some([D::Camellia128Cbc, D::Camellia192Cbc, D::Camellia256Cbc].into()),
        key_wrap_algorithms: Some([W::CamelliaKw128, W::CamelliaKw192, W::CamelliaKw256].into()),
        ..EncryptionPolicy::default()
    };
    for (content, wrapping) in [
        (D::Camellia128Cbc, W::CamelliaKw128),
        (D::Camellia192Cbc, W::CamelliaKw192),
        (D::Camellia256Cbc, W::CamelliaKw256),
    ] {
        let key = vec![0x43; content.key_len()];
        let file = TemporaryFile::write("camellia-key", "bin", &key);
        // libxmlsec1's CLI reports "both result doc and result buffer are
        // null" for an empty binary result. Verify that boundary through the
        // public API; the independent CLI covers nonempty padding boundaries.
        let empty = EncryptedDataBuilder::new(content)
            .direct_key(key.clone())
            .policy(policy.clone())
            .encrypt_binary(b"")
            .unwrap();
        let resolver = xml_sec::xmlenc::SymmetricKeyDecryptor::with_kind(
            key.clone(),
            xml_sec::key_manager::SymmetricKeyKind::Camellia,
        );
        let decryption = xml_sec::policy::DecryptionPolicy {
            data_algorithms: policy.data_algorithms.clone(),
            ..xml_sec::policy::DecryptionPolicy::default()
        };
        assert_eq!(
            xml_sec::xmlenc::DecryptContext::new(&resolver)
                .policy(decryption)
                .decrypt(&empty.encrypted_data_xml)
                .unwrap(),
            xml_sec::xmlenc::DecryptedContent::Bytes(Vec::new())
        );
        for plaintext in [b"short".as_slice(), &[0x52; 16], &[0x73; 33]] {
            let direct = EncryptedDataBuilder::new(content)
                .direct_key(key.clone())
                .policy(policy.clone())
                .encrypt_binary(plaintext)
                .unwrap();
            assert_eq!(
                decrypt_with_xmlsec1(&direct.encrypted_data_xml, "--camellia-key", &file.path),
                plaintext
            );
            let wrapped = EncryptedDataBuilder::new(content)
                .recipient_aes_kw(key.clone(), wrapping)
                .policy(policy.clone())
                .encrypt_binary(plaintext)
                .unwrap();
            assert_eq!(
                decrypt_with_xmlsec1(&wrapped.encrypted_data_xml, "--camellia-key", &file.path),
                plaintext
            );
        }
    }
}

#[test]
fn extended_oaep_hashes_have_reciprocal_oracle_coverage() {
    // XML DigestMethod and MGF1 are independent selections, including SHA3
    // content hashes with standardized SHA-1/SHA-512 masks.
    require_key_establishment_oracle();
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::xmlenc::KeyTransportAlgorithm;
    let path = Path::new("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(path).unwrap()).unwrap();
    let public = RsaPublicKey::from(&private);
    let hashes = [
        OaepDigestAlgorithm::Sha224,
        OaepDigestAlgorithm::Sha3_224,
        OaepDigestAlgorithm::Sha3_256,
        OaepDigestAlgorithm::Sha3_384,
        OaepDigestAlgorithm::Sha3_512,
        #[cfg(feature = "legacy-algorithms")]
        OaepDigestAlgorithm::Md5,
        #[cfg(feature = "legacy-algorithms")]
        OaepDigestAlgorithm::Ripemd160,
    ];
    let policy = EncryptionPolicy {
        oaep_digests: Some(
            hashes
                .iter()
                .copied()
                .chain([OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512])
                .collect(),
        ),
        ..EncryptionPolicy::default()
    };
    for digest in hashes {
        for mgf_digest in [OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512] {
            let parameters = RsaOaepParameters {
                algorithm: KeyTransportAlgorithm::RsaOaep11,
                digest,
                mgf_digest,
                label: b"independent OAEP label".to_vec(),
            };
            let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .add_recipient(
                    EncryptionRecipient::rsa_oaep(public.clone()).oaep_parameters(parameters),
                )
                .policy(policy.clone())
                .encrypt_binary(b"extended OAEP interoperability")
                .unwrap();
            assert_eq!(
                decrypt_with_xmlsec1(&encrypted.encrypted_data_xml, "--privkey-pem", path),
                b"extended OAEP interoperability"
            );
        }
    }
}

#[test]
fn chacha_wire_parameters_interoperate_with_the_oracle() {
    use xml_sec::xmlenc::{
        ChaChaParameters, DecryptContext, DecryptedContent, SymmetricKeyDecryptor,
    };
    use xml_sec::{
        key_manager::SymmetricKeyKind,
        policy::{DecryptionPolicy, EncryptionPolicy},
    };
    // Exercise both generated and explicit nonces, a nonzero counter, XML
    // escaping in AAD and boundary-length payloads. The oracle must read the
    // nonce from EncryptionMethod rather than an accidental ciphertext prefix.
    require_key_establishment_oracle();
    for algorithm in [
        DataEncryptionAlgorithm::ChaCha20,
        DataEncryptionAlgorithm::ChaCha20Poly1305,
    ] {
        for generated in [false, true] {
            let key = [0x6b; 32];
            let key_file = TemporaryFile::write("chacha-key", "bin", &key);
            let parameters = ChaChaParameters {
                nonce: if generated { None } else { Some([0x37; 12]) },
                counter: if algorithm == DataEncryptionAlgorithm::ChaCha20 {
                    Some(7_u32.to_le_bytes())
                } else {
                    None
                },
                aad: if algorithm == DataEncryptionAlgorithm::ChaCha20Poly1305 {
                    Some("AAD<&>\r\nПривет".into())
                } else {
                    None
                },
            };
            let encryption = EncryptionPolicy {
                data_algorithms: Some([algorithm].into()),
                ..EncryptionPolicy::default()
            };
            let decryption = DecryptionPolicy {
                data_algorithms: Some([algorithm].into()),
                ..DecryptionPolicy::default()
            };
            for length in [0, 1, 63, 64, 65, 129] {
                let payload = vec![0x79; length];
                let encrypted = EncryptedDataBuilder::new(algorithm)
                    .policy(encryption.clone())
                    .chacha_parameters(parameters.clone())
                    .direct_key(key)
                    .encrypt_binary(&payload)
                    .unwrap();
                let parsed =
                    xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
                assert!(
                    parsed
                        .encryption_method
                        .chacha
                        .as_ref()
                        .unwrap()
                        .nonce
                        .is_some()
                );
                let resolver = SymmetricKeyDecryptor::with_kind(key, SymmetricKeyKind::ChaCha20);
                assert_eq!(
                    DecryptContext::new(&resolver)
                        .policy(decryption.clone())
                        .decrypt(&encrypted.encrypted_data_xml)
                        .unwrap(),
                    DecryptedContent::Bytes(payload.clone())
                );
                // The xmlsec1 CLI has no result buffer for an empty plaintext;
                // nonempty cases run independently through its public decrypt.
                if !payload.is_empty() {
                    assert_eq!(
                        decrypt_with_xmlsec1(
                            &encrypted.encrypted_data_xml,
                            "--chacha20-key",
                            &key_file.path
                        ),
                        payload
                    );
                }
            }
        }
    }
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
    for sha in [
        "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384",
        "sha3-512",
    ] {
        let digest = match sha {
            "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
            "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "sha512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            "sha224" => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            "sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "sha3-224" => "http://www.w3.org/2007/05/xmldsig-more#sha3-224",
            "sha3-256" => "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
            "sha3-384" => "http://www.w3.org/2007/05/xmldsig-more#sha3-384",
            "sha3-512" => "http://www.w3.org/2007/05/xmldsig-more#sha3-512",
            _ => unreachable!("enumerated hash family"),
        };
        let hmac = if sha == "sha1" {
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1".to_owned()
        } else {
            format!("http://www.w3.org/2001/04/xmldsig-more#hmac-{sha}")
        };
        let mut cases = Vec::new();
        // The existing HMAC KDF contract selects SHA-1/SHA-2; SHA-3
        // is a direct digest for ConcatKDF, not an advertised HMAC PRF.
        if !sha.starts_with("sha3-") {
            cases.extend([
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
            ]);
        }
        // XMLEnc 1.1 §5.4.1 permits partial octets, but libxmlsec1's
        // xmlSecTransformConcatKdfParamsReadsBitsAttr supports only byte
        // alignment. Partial fields are independently covered in xmlenc_kdf.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
        cases.push((
                "--concatkdf-key",
                format!(
                    "<KeyDerivationMethod xmlns='{NS}' Algorithm='{NS}ConcatKDF'><ConcatKDFParams AlgorithmID='0000' PartyUInfo='00D8' PartyVInfo='00D0'><DigestMethod xmlns='http://www.w3.org/2000/09/xmldsig#' Algorithm='{digest}'/></ConcatKDFParams></KeyDerivationMethod>"
                ),
            ));
        for (option, xml) in cases {
            let method =
                xml_sec::xmlenc::parse_key_derivation_method(&xml, &Default::default()).unwrap();
            let mut outbound = xml_sec::policy::EncryptionPolicy::default();
            outbound.key_establishment.digest_algorithms =
                Some([xml_sec::xmldsig::DigestAlgorithm::from_uri(digest).unwrap()].into());
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
            inbound.key_establishment.digest_algorithms =
                Some([xml_sec::xmldsig::DigestAlgorithm::from_uri(digest).unwrap()].into());
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
