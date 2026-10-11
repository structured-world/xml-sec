//! Complete pinned XML Encryption 1.1 interoperability corpus.

use std::{collections::BTreeSet, fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::{Decode as _, Reader as _, asn1::UintRef};
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
use xml_sec::provider::{EcdhCurve, RUST_CRYPTO_PROVIDER, RustCryptoDhKey, RustCryptoEcdhKey};
use xml_sec::rsa_encoding::RsaPrivateKeyEncoding as _;
use xml_sec::xmlenc::{
    AgreementDecryptor, DataEncryptionAlgorithm as D, DecryptContext, DecryptedContent,
    DerivedKeyDecryptor, DerivedKeyInput, KeyEstablishmentBudget, KeyWrapAlgorithm as W,
    PrivateKeyDecryptor, SymmetricKeyDecryptor, XmlEncError, parse_encrypted_data_node_with_policy,
};
use xml_sec::{Document, XmlBackend};

#[path = "common/xmlenc_snapshot.rs"]
mod snapshot;

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

const DIRECTORY: &str = "tests/fixtures/xmlenc/xmlenc11-interop-2012";

#[derive(Clone, Copy)]
enum Credential {
    Aes,
    Rsa(u16),
    Derived(&'static str),
    Ec(EcdhCurve, &'static str),
    Dh,
}

struct Case {
    name: &'static str,
    credential: Credential,
    width: usize,
}

const CASES: &[Case] = &[
    Case {
        name: "xenc11-example-AES128-GCM",
        credential: Credential::Aes,
        width: 128,
    },
    Case {
        name: "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p",
        credential: Credential::Rsa(2048),
        width: 128,
    },
    Case {
        name: "cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256",
        credential: Credential::Rsa(3072),
        width: 192,
    },
    Case {
        name: "cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1",
        credential: Credential::Rsa(3072),
        width: 256,
    },
    Case {
        name: "cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource",
        credential: Credential::Rsa(4096),
        width: 256,
    },
    Case {
        name: "dkey-example-ConcatKDF-crypto",
        credential: Credential::Derived("dkey-concatkdf.bin"),
        width: 256,
    },
    Case {
        name: "dkey3-example-ConcatKDF-crypto",
        credential: Credential::Derived("dkey3-concatkdf.bin"),
        width: 256,
    },
    Case {
        name: "dkey-example-PBKDF2-crypto",
        credential: Credential::Derived("dkey-pbkdf2.bin"),
        width: 256,
    },
    Case {
        name: "dkey3-example-PBKDF2-crypto",
        credential: Credential::Derived("dkey3-pbkdf2.bin"),
        width: 256,
    },
    Case {
        name: "cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF",
        credential: Credential::Ec(EcdhCurve::P256, "ec-prime256v1"),
        width: 128,
    },
    Case {
        name: "cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF",
        credential: Credential::Ec(EcdhCurve::P384, "ec-prime384v1"),
        width: 192,
    },
    Case {
        name: "cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF",
        credential: Credential::Ec(EcdhCurve::P521, "ec-prime521v1"),
        width: 256,
    },
    Case {
        name: "cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF",
        credential: Credential::Dh,
        width: 128,
    },
];

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIRECTORY)
        .join(name)
}

fn policy() -> DecryptionPolicy {
    // Compatibility permission is explicit and local to this corpus. The
    // historical 1024-bit DH domain does not weaken the product defaults.
    let mut policy = DecryptionPolicy {
        data_algorithms: Some([D::Aes128Gcm, D::Aes192Gcm, D::Aes256Gcm, D::Aes256Cbc].into()),
        key_wrap_algorithms: Some([W::AesKw128, W::AesKw192, W::AesKw256].into()),
        ..Default::default()
    };
    policy.key_establishment.agreement_algorithms =
        Some([KeyAgreementAlgorithm::EcdhEs, KeyAgreementAlgorithm::DhEs].into());
    policy.key_establishment.minimum_dh_modulus_bits = 1024;
    policy.key_establishment.minimum_dh_subgroup_bits = 160;
    policy
}

fn ec_key(curve: EcdhCurve, bytes: &[u8]) -> RustCryptoEcdhKey {
    let scalar = zeroize::Zeroizing::new(match curve {
        EcdhCurve::P256 => p256::SecretKey::from_sec1_der(bytes)
            .unwrap()
            .to_bytes()
            .to_vec(),
        EcdhCurve::P384 => p384::SecretKey::from_sec1_der(bytes)
            .unwrap()
            .to_bytes()
            .to_vec(),
        EcdhCurve::P521 => p521::SecretKey::from_sec1_der(bytes)
            .unwrap()
            .to_bytes()
            .to_vec(),
    });
    RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap()
}

fn dh_key(bytes: &[u8], policy: &DecryptionPolicy) -> Result<RustCryptoDhKey, XmlEncError> {
    let info = pkcs8::PrivateKeyInfoRef::try_from(bytes).unwrap();
    let (p, g, q) = info
        .algorithm
        .parameters
        .unwrap()
        .sequence(|reader| -> der::Result<_> {
            Ok((
                reader.decode::<UintRef<'_>>()?,
                reader.decode::<UintRef<'_>>()?,
                reader.decode::<UintRef<'_>>()?,
            ))
        })
        .unwrap();
    let private = UintRef::from_der(info.private_key.as_bytes()).unwrap();
    let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
    RustCryptoDhKey::from_components(
        &RUST_CRYPTO_PROVIDER,
        &mut budget,
        p.as_bytes(),
        q.as_bytes(),
        g.as_bytes(),
        private.as_bytes(),
    )
}

fn peer(document: &Document<'_>, local_name: &str) -> Vec<u8> {
    // Only pinned test credentials establish trust here. Message-supplied key
    // material is never used to discover or replace the application's key.
    let node = document
        .descendants()
        .find(|node| node.tag_name().name() == local_name)
        .unwrap();
    STANDARD
        .decode(node.text().unwrap().split_whitespace().collect::<String>())
        .unwrap()
}

fn decrypt_case(
    case: &Case,
    xml: &str,
    backend: XmlBackend,
    regenerated: bool,
) -> Result<DecryptedContent, XmlEncError> {
    let policy = policy();
    let document = Document::parse_with_backend(xml, backend).unwrap();
    let parsed = parse_encrypted_data_node_with_policy(document.root_element(), &policy).unwrap();
    let context = |resolver| {
        DecryptContext::new(resolver)
            .policy(policy.clone())
            .xml_backend(backend)
            .decrypt(xml)
    };
    match case.credential {
        Credential::Aes => {
            let key = fs::read(path("xenc11-example-AES128-GCM.key")).unwrap();
            context(&SymmetricKeyDecryptor::new(key))
        }
        Credential::Rsa(bits) => {
            let bytes = zeroize::Zeroizing::new(
                fs::read(path(&format!("RSA-{bits}_SHA256WithRSA.der"))).unwrap(),
            );
            let key = rsa::RsaPrivateKey::from_pkcs1_der(&bytes).unwrap();
            context(&PrivateKeyDecryptor::new(key))
        }
        Credential::Derived(file) => {
            let secret = zeroize::Zeroizing::new(fs::read(path(file)).unwrap());
            let descriptor = &parsed.derived_keys[0];
            let mut resolver = DerivedKeyDecryptor::content(
                descriptor.method.as_ref().unwrap(),
                DerivedKeyInput::Secret(&secret),
                D::Aes256Cbc,
            );
            if let Some(name) = descriptor.master_key_name.as_deref() {
                resolver = resolver.master_key_name(name);
            }
            context(&resolver)
        }
        Credential::Ec(curve, stem) => {
            let key_path = if regenerated {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("tests/fixtures/xmlenc/keys/ec/{stem}-key.der"))
            } else {
                path(&format!(
                    "EC-P{}_SHA256WithECDSA-orig.der",
                    match curve {
                        EcdhCurve::P256 => 256,
                        EcdhCurve::P384 => 384,
                        EcdhCurve::P521 => 521,
                    }
                ))
            };
            let bytes = zeroize::Zeroizing::new(fs::read(key_path).unwrap());
            let key = ec_key(curve, &bytes);
            let peer = peer(&document, "PublicKey");
            let wrap = match case.width {
                128 => W::AesKw128,
                192 => W::AesKw192,
                256 => W::AesKw256,
                _ => unreachable!(),
            };
            context(&AgreementDecryptor::wrapping(
                &parsed.encrypted_keys[0].sources.agreement_methods[0],
                &key,
                &peer,
                wrap,
            ))
        }
        Credential::Dh => {
            let key_path = if regenerated {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-key.der")
            } else {
                path("DH-1024_SHA256WithDSA.der")
            };
            let bytes = zeroize::Zeroizing::new(fs::read(key_path).unwrap());
            let key = dh_key(&bytes, &policy)?;
            let peer = peer(&document, "Public");
            context(&AgreementDecryptor::wrapping(
                &parsed.encrypted_keys[0].sources.agreement_methods[0],
                &key,
                &peer,
                W::AesKw128,
            ))
        }
    }
}

fn assert_plaintext(case: &Case, actual: DecryptedContent) {
    let expected = fs::read(path(&format!("{}.data", case.name))).unwrap();
    match actual {
        DecryptedContent::Bytes(bytes) => assert_eq!(bytes, expected, "{}", case.name),
        DecryptedContent::Xml(xml) => {
            let mode = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            assert_eq!(
                canonicalize_xml(xml.as_bytes(), &mode).unwrap(),
                canonicalize_xml(&expected, &mode).unwrap(),
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn every_pinned_ciphertext_executes_on_every_backend() {
    // Enumeration must equal execution, including the untouched X509 variants;
    // an added fixture cannot silently become an untested file.
    snapshot::verify();
    let found: BTreeSet<_> = fs::read_dir(path(""))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".xml"))
        .collect();
    let mut expected = BTreeSet::new();
    for case in CASES {
        expected.insert(format!("{}.xml", case.name));
        if matches!(case.credential, Credential::Ec(..) | Credential::Dh) {
            expected.insert(format!("{}-orig.xml", case.name));
        }
    }
    assert_eq!(found, expected);
    assert_eq!(expected.len(), 17);
    for backend in XmlBackend::available() {
        for case in CASES {
            for original in [false, true] {
                if original && !matches!(case.credential, Credential::Ec(..) | Credential::Dh) {
                    continue;
                }
                let suffix = if original { "-orig" } else { "" };
                let xml = fs::read_to_string(path(&format!("{}{suffix}.xml", case.name))).unwrap();
                let result = decrypt_case(case, &xml, backend, false);
                if matches!(case.credential, Credential::Dh) {
                    // The pinned X9.42 credential has an even 1023-bit q,
                    // violating RFC 2631 §2.2's large-prime requirement. This
                    // is a rejected credential, not an unsupported algorithm.
                    // https://www.rfc-editor.org/rfc/rfc2631.html#section-2.2
                    assert!(matches!(
                        result,
                        Err(XmlEncError::Provider(
                            xml_sec::provider::ProviderError::InvalidInput(
                                xml_sec::provider::ProviderInputError::DhKey
                            )
                        ))
                    ));
                    continue;
                }
                let actual = result.unwrap_or_else(|error| {
                    panic!("{} ({backend:?}, original={original}): {error}", case.name)
                });
                assert_plaintext(case, actual);
            }
        }
    }
}

fn oracle_output(command: &mut std::process::Command, name: &str) {
    let result = command.output().expect("independent xmlsec1 oracle");
    assert!(
        result.status.success(),
        "{name}: oracle failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn every_original_template_encrypts_for_the_public_decrypt_api() {
    // Run every original template with the donor's actual credential recipe.
    // Never substitute a generated template or call Unsupported a success.
    assert!(
        xmlsec1::is_available(),
        "oracle required: {}",
        xmlsec1::skip_reason()
    );
    let found: BTreeSet<_> = fs::read_dir(path(""))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".tmpl"))
        .collect();
    assert_eq!(
        found,
        CASES
            .iter()
            .map(|case| format!("{}.tmpl", case.name))
            .collect()
    );
    let temporary = tempfile::tempdir().unwrap();
    for case in CASES {
        let output = temporary.path().join(format!("{}.xml", case.name));
        let mut command = xmlsec1::command();
        command.arg("encrypt").arg("--output").arg(&output);
        match case.credential {
            Credential::Aes => {
                command
                    .arg("--aeskey:TestKeyName_GCM")
                    .arg(path("xenc11-example-AES128-GCM.key"));
            }
            Credential::Rsa(bits) => {
                let name = if bits == 2048 {
                    "TestRsa2048Key"
                } else {
                    "TestRsa3072Key"
                };
                command
                    .arg(format!("--privkey-der:{name}"))
                    .arg(path(&format!("RSA-{bits}_SHA256WithRSA.der")));
            }
            Credential::Derived(file) => {
                let (option, name) = match file {
                    "dkey-concatkdf.bin" => ("concatkdf-key", "dkey"),
                    "dkey3-concatkdf.bin" => ("concatkdf-key", "dkey3"),
                    "dkey-pbkdf2.bin" => ("pbkdf2-key", "dkey-pbkdf2"),
                    "dkey3-pbkdf2.bin" => ("pbkdf2-key", "dkey3-pbkdf2"),
                    _ => unreachable!("closed fixture credential inventory"),
                };
                command.arg(format!("--{option}:{name}")).arg(path(file));
            }
            Credential::Ec(curve, stem) => {
                let bits = match curve {
                    EcdhCurve::P256 => 256,
                    EcdhCurve::P384 => 384,
                    EcdhCurve::P521 => 521,
                };
                command
                    .arg("--enabled-key-data")
                    .arg("agreement-method,enc-key,key-value,key-name,ec")
                    .arg(format!("--privkey-der:EC-P{bits}"))
                    .arg(path(&format!("EC-P{bits}_SHA256WithECDSA.der")))
                    .arg(format!("--pubkey-der:TestKeyName-{stem}"))
                    .arg(format!("tests/fixtures/xmlenc/keys/ec/{stem}-pubkey.der"));
            }
            Credential::Dh => {
                command
                    .arg("--enabled-key-data")
                    .arg("agreement-method,enc-key,key-value,key-name,dh")
                    .arg("--privkey-der:dhx-rfc5114-3-first")
                    .arg("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-first-key.der")
                    .arg("--pubkey-der:dhx-rfc5114-3-second")
                    .arg("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-pubkey.der");
            }
        }
        if matches!(
            case.credential,
            Credential::Rsa(..) | Credential::Ec(..) | Credential::Dh
        ) {
            command
                .arg("--session-key")
                .arg(format!("aes-{}", case.width));
        }
        let binary = matches!(case.credential, Credential::Aes | Credential::Derived(..));
        command
            .arg(if binary {
                "--binary-data"
            } else {
                "--xml-data"
            })
            .arg(path(&format!("{}.data", case.name)))
            .arg(path(&format!("{}.tmpl", case.name)));
        oracle_output(&mut command, case.name);
        let xml = fs::read_to_string(&output).unwrap();
        for backend in XmlBackend::available() {
            let actual = decrypt_case(case, &xml, backend, true)
                .unwrap_or_else(|error| panic!("{} ({backend:?}): {error}", case.name));
            assert_plaintext(case, actual);
            let encrypted = encrypt_case(case, &xml, backend);
            let input = temporary.path().join("rust-encrypted.xml");
            let plaintext = temporary.path().join("oracle-plaintext.data");
            fs::write(&input, encrypted).unwrap();
            let mut command = xmlsec1::command();
            command
                .arg("decrypt")
                .arg("--lax-key-search")
                .arg("--output")
                .arg(&plaintext);
            match case.credential {
                Credential::Aes => {
                    command
                        .arg("--aeskey")
                        .arg(path("xenc11-example-AES128-GCM.key"));
                }
                Credential::Rsa(bits) => {
                    let name = if bits == 2048 {
                        "TestRsa2048Key"
                    } else {
                        "TestRsa3072Key"
                    };
                    command
                        .arg(format!("--privkey-der:{name}"))
                        .arg(path(&format!("RSA-{bits}_SHA256WithRSA.der")));
                }
                Credential::Derived(file) => {
                    command
                        .arg(if file.contains("concatkdf") {
                            "--concatkdf-key"
                        } else {
                            "--pbkdf2-key"
                        })
                        .arg(path(file));
                }
                Credential::Ec(_, stem) => {
                    command
                        .arg("--enabled-key-data")
                        .arg("agreement-method,enc-key,key-value,key-name,ec")
                        .arg(format!("--privkey-der:TestKeyName-{stem}"))
                        .arg(format!("tests/fixtures/xmlenc/keys/ec/{stem}-key.der"));
                }
                Credential::Dh => {
                    command
                        .arg("--enabled-key-data")
                        .arg("agreement-method,enc-key,key-value,key-name,dh")
                        .arg("--privkey-der:dhx-rfc5114-3-second")
                        .arg("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-key.der");
                }
            }
            command.arg(&input);
            oracle_output(&mut command, case.name);
            let bytes = fs::read(&plaintext).unwrap();
            assert_plaintext(
                case,
                if binary {
                    DecryptedContent::Bytes(bytes)
                } else {
                    DecryptedContent::Xml(String::from_utf8(bytes).unwrap())
                },
            );
        }
    }
}

fn encrypt_case(case: &Case, populated_template: &str, backend: XmlBackend) -> String {
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::provider::CryptoProvider as _;
    use xml_sec::xmlenc::{
        EncryptedDataBuilder, EncryptionRecipient, KeyTransportAlgorithm, OaepDigestAlgorithm as H,
        RsaOaepParameters,
    };
    let policy = policy();
    let document = Document::parse_with_backend(populated_template, backend).unwrap();
    let parsed = parse_encrypted_data_node_with_policy(document.root_element(), &policy).unwrap();
    let algorithm = D::from_uri(&parsed.encryption_method.algorithm).unwrap();
    let encryption = EncryptionPolicy {
        data_algorithms: policy.data_algorithms.clone(),
        key_wrap_algorithms: policy.key_wrap_algorithms.clone(),
        key_establishment: policy.key_establishment.clone(),
        ..Default::default()
    };
    let mut builder = EncryptedDataBuilder::new(algorithm)
        .policy(encryption)
        .xml_backend(backend);
    let mut public_replacement = None;
    match case.credential {
        Credential::Aes => {
            builder = builder.direct_key(fs::read(path("xenc11-example-AES128-GCM.key")).unwrap());
        }
        Credential::Rsa(bits) => {
            let bytes = zeroize::Zeroizing::new(
                fs::read(path(&format!("RSA-{bits}_SHA256WithRSA.der"))).unwrap(),
            );
            let private = rsa::RsaPrivateKey::from_pkcs1_der(&bytes).unwrap();
            let method = &parsed.encrypted_keys[0].encryption_method;
            // XMLEnc 1.1 §5.5.2 specifies SHA-1 defaults independently for
            // DigestMethod and MGF; never turn absence into MGF=DigestMethod.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-RSA-OAEP
            let parameters = RsaOaepParameters {
                algorithm: KeyTransportAlgorithm::from_uri(&method.algorithm).unwrap(),
                digest: method
                    .oaep_digest
                    .as_deref()
                    .map_or(H::Sha1, |uri| H::from_uri(uri).unwrap()),
                mgf_digest: method
                    .mgf_algorithm
                    .as_deref()
                    .map_or(H::Sha1, |uri| H::from_mgf_uri(uri).unwrap()),
                label: method.oaep_params.clone().unwrap_or_default(),
            };
            builder = builder.add_recipient(
                EncryptionRecipient::rsa_oaep(rsa::RsaPublicKey::from(&private))
                    .oaep_parameters(parameters),
            );
        }
        Credential::Derived(file) => {
            builder = builder.derived_key(
                parsed.derived_keys[0].method.clone().unwrap(),
                fs::read(path(file)).unwrap(),
            );
        }
        Credential::Ec(curve, stem) => {
            // XMLEnc §5.6.4 requires a fresh ephemeral sender. Draw an
            // unbiased scalar through the provider, not a pinned private key.
            let width = match curve {
                EcdhCurve::P256 => 32,
                EcdhCurve::P384 => 48,
                EcdhCurve::P521 => 66,
            };
            let mut scalar = zeroize::Zeroizing::new(vec![0; width]);
            let sender = loop {
                RUST_CRYPTO_PROVIDER.fill_random(&mut scalar).unwrap();
                if curve == EcdhCurve::P521 {
                    scalar[0] &= 1;
                }
                if let Ok(key) = RustCryptoEcdhKey::from_scalar(curve, &scalar) {
                    break key;
                }
            };
            let bytes = zeroize::Zeroizing::new(
                fs::read(format!("tests/fixtures/xmlenc/keys/ec/{stem}-key.der")).unwrap(),
            );
            let recipient = ec_key(curve, &bytes);
            let method = &parsed.encrypted_keys[0].sources.agreement_methods[0];
            let wrap = W::from_uri(&parsed.encrypted_keys[0].encryption_method.algorithm).unwrap();
            let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
            let kek = method
                .derive_key(
                    wrap.uri(),
                    wrap.key_len(),
                    &sender,
                    &recipient.public_key(),
                    &RUST_CRYPTO_PROVIDER,
                    &mut budget,
                )
                .unwrap();
            builder = builder.recipient_aes_kw(kek.to_vec(), wrap);
            let node = document
                .descendants()
                .find(|node| node.tag_name().name() == "PublicKey")
                .unwrap();
            let text = node.children().find(|node| node.is_text()).unwrap();
            public_replacement = Some((text.range(), STANDARD.encode(sender.public_key())));
        }
        Credential::Dh => {
            // The original template names both RFC 5114 test parties. Their
            // private handles are explicit test request inputs, not discovered
            // from KeyInfo. Cryptography and work accounting remain public API.
            let first = zeroize::Zeroizing::new(
                fs::read("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-first-key.der").unwrap(),
            );
            let second = zeroize::Zeroizing::new(
                fs::read("tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-second-key.der").unwrap(),
            );
            let sender = dh_key(&first, &policy).unwrap();
            let recipient = dh_key(&second, &policy).unwrap();
            let method = &parsed.encrypted_keys[0].sources.agreement_methods[0];
            let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment).unwrap();
            let kek = method
                .derive_key(
                    W::AesKw128.uri(),
                    16,
                    &sender,
                    &recipient.public_key(),
                    &RUST_CRYPTO_PROVIDER,
                    &mut budget,
                )
                .unwrap();
            builder = builder.recipient_aes_kw(kek.to_vec(), W::AesKw128);
        }
    }
    let expected = fs::read(path(&format!("{}.data", case.name))).unwrap();
    let encrypted = if matches!(case.credential, Credential::Aes | Credential::Derived(..)) {
        builder.encrypt_binary(&expected)
    } else {
        let source = std::str::from_utf8(&expected).unwrap();
        let plaintext = Document::parse(source).unwrap();
        // Type=Element encrypts the root, not the document's XML declaration.
        builder.encrypt_xml(&source[plaintext.root_element().range()])
    }
    .unwrap()
    .encrypted_data_xml;
    if !matches!(
        case.credential,
        Credential::Rsa(..) | Credential::Ec(..) | Credential::Dh
    ) {
        return encrypted;
    }
    // XMLEnc §5.8.3 specifies xmlenc#sha384, whereas libxmlsec1 only registers
    // xmldsig-more#sha384. Keep the original template's accepted alias instead
    // of changing our normative serializer to satisfy this oracle departure.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-SHA384
    // Caller-managed KEK orchestration uses AgreementMethod::derive_key and
    // the builder's AES-KW API. Retain the populated original template's party
    // and KDF descriptors, replacing only cryptographic results. This does not
    // claim that the CLI exposes an agreement-template encryption option.
    let generated = Document::parse(&encrypted).unwrap();
    let values: Vec<_> = generated
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
        .map(|node| node.text().unwrap())
        .collect();
    let targets: Vec<_> = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
        .map(|node| node.children().find(|node| node.is_text()).unwrap().range())
        .collect();
    assert_eq!(targets.len(), values.len());
    let mut edits: Vec<_> = targets
        .into_iter()
        .zip(values.into_iter().map(str::to_owned))
        .collect();
    if let Some(edit) = public_replacement {
        edits.push(edit);
    }
    edits.sort_by_key(|(range, _)| range.start);
    let mut candidate = populated_template.to_owned();
    for (range, value) in edits.into_iter().rev() {
        candidate.replace_range(range, &value);
    }
    Document::parse(&candidate).unwrap();
    candidate
}

#[test]
fn corrupted_authenticated_content_and_wrapped_keys_are_rejected() {
    // Flip each independently protected value, not XML syntax. GCM must fail
    // authentication and wrapped-key damage must never release plaintext.
    for case in CASES {
        if matches!(case.credential, Credential::Derived(..) | Credential::Dh) {
            continue;
        }
        let xml = fs::read_to_string(path(&format!("{}.xml", case.name))).unwrap();
        let document = Document::parse(&xml).unwrap();
        for value in document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
        {
            let text = value.children().find(|node| node.is_text()).unwrap();
            let mut bytes = STANDARD
                .decode(text.text().unwrap().split_whitespace().collect::<String>())
                .unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            let mut corrupted = xml.clone();
            corrupted.replace_range(text.range(), &STANDARD.encode(bytes));
            for backend in XmlBackend::available() {
                let error = decrypt_case(case, &corrupted, backend, false).unwrap_err();
                assert!(
                    matches!(
                        error,
                        XmlEncError::AeadAuthenticationFailed
                            | XmlEncError::Rsa(_)
                            | XmlEncError::KeyWrapIntegrity
                            | XmlEncError::Provider(
                                xml_sec::provider::ProviderError::AuthenticationFailed
                            )
                    ),
                    "{} ({backend:?}): expected cryptographic rejection, got {error:?}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn historical_cbc_expectations_follow_xmlenc_padding() {
    // XMLEnc 1.1 §5.2.1 requires removing the final padding count. These four
    // old ciphertexts were published without applying padding first; preserve
    // both original and corrected expected files, rather than fixing fixtures.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Padding
    for case in CASES {
        if !matches!(case.credential, Credential::Derived(..)) {
            continue;
        }
        let original = fs::read(path(&format!("{}-orig.data", case.name))).unwrap();
        let corrected = fs::read(path(&format!("{}.data", case.name))).unwrap();
        // The pinned files end in 0x08 (the donor README says 0x07).
        // Removing eight bytes is normative, irrespective of the padding
        // bytes' values; XML Encryption does not require PKCS#7 repetition.
        assert_eq!(original.last(), Some(&8));
        assert_eq!(corrected, original[..original.len() - 8]);
    }
}

#[test]
fn malformed_kdf_parameters_fail_before_key_resolution() {
    // Zero PBKDF2 iterations violate XMLEnc §5.4.2's positiveInteger;
    // ConcatKDF's padding-count octet must be 0..7 (§5.4.1). A raw-key
    // resolver cannot handle DerivedKey: KeyNotFound would reveal that syntax
    // was allowed to reach resolution instead of being rejected up front.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-PBKDF2
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
    let resolver = SymmetricKeyDecryptor::new([0_u8; 32]);
    for case in CASES {
        let Credential::Derived(file) = case.credential else {
            continue;
        };
        let xml = fs::read_to_string(path(&format!("{}.xml", case.name))).unwrap();
        let malformed = if file.contains("concatkdf") {
            assert!(xml.contains("AlgorithmID=\"00"));
            xml.replacen("AlgorithmID=\"00", "AlgorithmID=\"08", 1)
        } else {
            let document = Document::parse(&xml).unwrap();
            let node = document
                .descendants()
                .find(|node| node.tag_name().name() == "IterationCount")
                .unwrap();
            let text = node.children().find(|node| node.is_text()).unwrap();
            let mut malformed = xml.clone();
            malformed.replace_range(text.range(), "0");
            malformed
        };
        for backend in XmlBackend::available() {
            let error = DecryptContext::new(&resolver)
                .policy(policy())
                .xml_backend(backend)
                .decrypt(&malformed)
                .unwrap_err();
            assert!(
                matches!(error, XmlEncError::InvalidStructure(_)),
                "{} ({backend:?}): {error}",
                case.name
            );
        }
    }
}
