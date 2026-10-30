use std::fs;

use aes::cipher::BlockModeEncrypt as _;
use base64::Engine as _;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};

use super::*;

#[test]
fn traditional_pem_rejects_invalid_protection_before_workspace() {
    // Malformed protection metadata must be refused before DER allocation.
    let encrypted =
        include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem");
    for malformed in [
        encrypted.replace("AES-256-CBC", "RC2-CBC"),
        encrypted.replace(
            "C98DDAE6A971742BF435D3FF6CD60028",
            "C98DDAE6A971742BF435D3FF6CD6002Z",
        ),
    ] {
        let allocations = std::cell::Cell::new(0);
        assert!(
            decode_traditional_pem(
                malformed.as_bytes(),
                "RSA PRIVATE KEY",
                Some(b"legacy-rsa-password"),
                Path::new("key"),
                |_, _| {
                    allocations.set(allocations.get() + 1);
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(allocations.get(), 0);
    }
}

#[test]
fn traditional_pem_workspace_limit_precedes_decoding() {
    // Exact source + decoded capacity is accepted; one byte less fails
    // before the streaming decoder allocates its output.
    let pem = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", vec![1, 2, 3]));
    let mut resources = ResourcePolicy {
        max_external_resource_total_bytes: pem.len() + 3,
        ..ResourcePolicy::default()
    };
    assert_eq!(
        decode_bounded_traditional_pem(pem.as_bytes(), None, Path::new("key"), &resources)
            .unwrap()
            .der
            .as_slice(),
        &[1, 2, 3]
    );
    resources.max_external_resource_total_bytes -= 1;
    assert!(matches!(
        decode_bounded_traditional_pem(pem.as_bytes(), None, Path::new("key"), &resources),
        Err(KeyMaterialError::Policy(_))
    ));
}

#[test]
fn damaged_protected_pem_is_terminal() {
    // A recognized protected envelope cannot become a skippable candidate
    // just because its encrypted payload is not valid base64.
    let encrypted =
        include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem");
    let (headers, _) = encrypted.split_once("\n\n").unwrap();
    let damaged = format!("{headers}\n\n!!!!\n-----END RSA PRIVATE KEY-----\n");
    assert!(matches!(
        decode_bounded_traditional_pem(
            damaged.as_bytes(),
            Some(b"legacy-rsa-password"),
            Path::new("key"),
            &ResourcePolicy::default()
        ),
        Err(KeyMaterialError::ProtectedContainer)
    ));
}

#[test]
fn rsa_containers_preflight_components_before_native_decode() {
    // Every CLI container must reject excessive borrowed components before
    // bigint allocation, including traditional PEM after decryption.
    let pem = include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let (_, der) = der::pem::decode_vec(pem.as_bytes()).expect("fixture PEM");
    let info = PrivateKeyInfoRef::try_from(der.as_slice()).expect("fixture PKCS#8");
    let oversized = vec![1_u8; 1025];
    for modulus in [true, false] {
        let mut key = pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).unwrap();
        if modulus {
            key.modulus = UintRef::new(&oversized).unwrap();
        } else {
            key.private_exponent = UintRef::new(&oversized).unwrap();
        }
        let pkcs1 = key.to_der().unwrap();
        let pkcs8 = PrivateKeyInfoRef::new(
            pkcs1::ALGORITHM_ID,
            der::asn1::OctetStringRef::new(&pkcs1).unwrap(),
        )
        .to_der()
        .unwrap();
        let plain_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.clone()));
        let traditional = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", pkcs1.clone()));
        let protected = encrypted_traditional_pem("RSA PRIVATE KEY", &pkcs1, b"secret");
        for (bytes, format, password) in [
            (pkcs1.as_slice(), PrivateKeyFormat::Der, None),
            (pkcs8.as_slice(), PrivateKeyFormat::Der, None),
            (pkcs8.as_slice(), PrivateKeyFormat::Pkcs8Der, None),
            (plain_pem.as_bytes(), PrivateKeyFormat::Pem, None),
            (plain_pem.as_bytes(), PrivateKeyFormat::Pkcs8Pem, None),
            (traditional.as_bytes(), PrivateKeyFormat::Pem, None),
            (
                protected.as_bytes(),
                PrivateKeyFormat::Pem,
                Some(b"secret".as_slice()),
            ),
        ] {
            let error = decode_rsa_private_with_password(
                Path::new("key"),
                bytes,
                format,
                password,
                &ResourcePolicy::default(),
            )
            .expect_err("oversized components must fail preflight");
            assert!(
                error.to_string().contains("safety limit"),
                "{format:?}: {error}"
            );
        }
    }
}

#[test]
fn rsa_pkcs8_pem_keeps_label_and_protected_failure_contracts() {
    // A borrowed preflight must not enable label fallback or downgrade
    // unauthenticated CBC plaintext to an ordinary candidate mismatch.
    let fixture = include_bytes!("../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let (_, der) = der::pem::decode_vec(fixture).unwrap();
    let mislabeled = pem::encode(&pem::Pem::new("CERTIFICATE", der));
    assert!(
        decode_rsa_private_with_password(
            Path::new("key.pem"),
            mislabeled.as_bytes(),
            PrivateKeyFormat::Pkcs8Pem,
            None,
            &ResourcePolicy::default(),
        )
        .is_err()
    );
    let protected = encrypted_traditional_pem("RSA PRIVATE KEY", b"not ASN.1", b"secret");
    assert!(matches!(
        decode_rsa_private_with_password(
            Path::new("key.pem"),
            protected.as_bytes(),
            PrivateKeyFormat::Pem,
            Some(b"secret"),
            &ResourcePolicy::default(),
        ),
        Err(KeyMaterialError::ProtectedContainer)
    ));
}

#[test]
fn protected_rsa_container_failure_is_not_a_lax_candidate_miss() {
    // A wrong or missing password must stop lax search before a later
    // unprotected candidate can silently replace the requested key.
    let rsa = RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("RSA fixture");
    let plain = rsa.to_pkcs8_der().expect("PKCS#8 fixture");
    let mut rng = ChaCha20Rng::seed_from_u64(0xA11C_E501);
    let encrypted = PrivateKeyInfoRef::try_from(plain.as_bytes())
        .expect("PKCS#8 reference")
        .encrypt_with_rng(&mut rng, b"correct")
        .expect("encrypted fixture");
    for password in [None, Some(b"wrong".as_slice())] {
        assert!(matches!(
            decode_rsa_private_with_password(
                Path::new("protected.der"),
                encrypted.as_bytes(),
                PrivateKeyFormat::Pkcs8Der,
                password,
                &ResourcePolicy::default(),
            ),
            Err(KeyMaterialError::ProtectedContainer)
        ));
    }
    let invalid_policy = ResourcePolicy {
        max_external_resource_bytes: usize::MAX,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        decode_rsa_private_with_password(
            Path::new("protected.der"),
            encrypted.as_bytes(),
            PrivateKeyFormat::Pkcs8Der,
            Some(b"correct"),
            &invalid_policy,
        ),
        Err(KeyMaterialError::Policy(_))
    ));
}

#[test]
fn encrypted_traditional_dsa_and_ec_reject_valid_padding_invalid_der() {
    // CBC padding can succeed without authenticating the plaintext. A
    // protected envelope containing invalid DER remains terminal for lax search.
    for tag in ["DSA PRIVATE KEY", "EC PRIVATE KEY"] {
        let text = encrypted_traditional_pem(tag, b"not ASN.1", b"secret");
        let result = if tag == "DSA PRIVATE KEY" {
            decode_dsa_signing_key(
                Path::new("key.pem"),
                text.as_bytes(),
                PrivateKeyFormat::Pem,
                Some(b"secret"),
            )
        } else {
            decode_ecdsa_signing_key(
                Path::new("key.pem"),
                text.as_bytes(),
                PrivateKeyFormat::Pem,
                Some(b"secret"),
            )
        };
        assert!(
            matches!(result, Err(KeyMaterialError::ProtectedContainer)),
            "{tag}"
        );
    }
}

#[test]
fn traditional_encrypted_rsa_pem_preserves_password_failure() {
    // A protected traditional PEM must not look like a missing key to lax selection.
    let pem = include_bytes!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem"
    );
    for password in [None, Some(b"wrong".as_slice())] {
        assert!(matches!(
            decode_rsa_private_with_password(
                Path::new("protected.pem"),
                pem,
                PrivateKeyFormat::Pem,
                password,
                &ResourcePolicy::default(),
            ),
            Err(KeyMaterialError::ProtectedContainer)
        ));
    }
}

fn load_signing_key(
    path: impl AsRef<Path>,
    format: PrivateKeyFormat,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    decode_signing_key(path, &bytes, format, SignatureAlgorithm::RsaSha256, None)
}

/// OpenSSL's traditional DSA structure for `key`, with a caller-chosen
/// version and public value so tests can make it inconsistent.
fn traditional_dsa_der(key: &NativeDsaSigningKey, version: u8, public: &[u8]) -> Vec<u8> {
    let verifying_key = key.verifying_key();
    let components = verifying_key.components();
    let p = components.p().to_be_bytes_trimmed_vartime();
    let q = components.q().to_be_bytes_trimmed_vartime();
    let g = components.g().to_be_bytes_trimmed_vartime();
    let secret = key.x().to_be_bytes_trimmed_vartime();
    TraditionalDsaPrivateKey {
        version,
        p: UintRef::new(p.as_ref()).unwrap(),
        q: UintRef::new(q.as_ref()).unwrap(),
        g: UintRef::new(g.as_ref()).unwrap(),
        y: UintRef::new(public).unwrap(),
        x: UintRef::new(secret.as_ref()).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn encrypted_traditional_pem(tag: &str, der: &[u8], password: &[u8]) -> String {
    use std::fmt::Write as _;
    let iv = [0x39; 16];
    let key = openssl_legacy_key(password, &iv[..8], 32);
    let mut ciphertext = vec![0_u8; der.len() + 16];
    ciphertext[..der.len()].copy_from_slice(der);
    let ciphertext_len = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
        .unwrap()
        .encrypt_padded::<Pkcs7>(&mut ciphertext, der.len())
        .unwrap()
        .len();
    ciphertext.truncate(ciphertext_len);
    let encoded = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let mut iv_hex = String::with_capacity(iv.len() * 2);
    for byte in iv {
        write!(iv_hex, "{byte:02X}").expect("writing to a String cannot fail");
    }
    format!(
        "-----BEGIN {tag}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{iv_hex}\n\n{body}\n-----END {tag}-----\n"
    )
}

#[test]
#[expect(
    deprecated,
    reason = "traditional OpenSSL DSA compatibility includes legacy 1024/160 containers"
)]
fn traditional_dsa_decoder_rejects_ambiguous_or_inconsistent_containers() {
    // The generic DER option accepts the OpenSSL DSA structure only when
    // its complete ASN.1 container and public/private components agree.
    let mut rng = ChaCha20Rng::seed_from_u64(0xD5A1_D5A1);
    let components =
        DsaComponents::try_generate_from_rng_with_key_size(&mut rng, dsa::KeySize::DSA_1024_160)
            .unwrap();
    let key =
        NativeDsaSigningKey::try_generate_from_rng_with_components(&mut rng, components).unwrap();
    let y = key.verifying_key().y().to_be_bytes_trimmed_vartime();
    let valid = traditional_dsa_der(&key, 0, y.as_ref());
    let path = Path::new("traditional-dsa.der");
    decode_signing_key(
        path,
        &valid,
        PrivateKeyFormat::Der,
        SignatureAlgorithm::DsaSha256,
        None,
    )
    .expect("valid traditional DSA DER must decode");

    let password = b"legacy-dsa-password";
    let encrypted = encrypted_traditional_pem("DSA PRIVATE KEY", &valid, password);
    let encrypted_path = Path::new("traditional-encrypted-dsa.pem");
    decode_signing_key(
        encrypted_path,
        encrypted.as_bytes(),
        PrivateKeyFormat::Pem,
        SignatureAlgorithm::DsaSha256,
        Some(password),
    )
    .expect("the correct password must decrypt traditional DSA PEM");
    for rejected_password in [None, Some(b"wrong-password".as_slice())] {
        assert!(
            decode_signing_key(
                encrypted_path,
                encrypted.as_bytes(),
                PrivateKeyFormat::Pem,
                SignatureAlgorithm::DsaSha256,
                rejected_password,
            )
            .is_err(),
            "missing or incorrect passwords must fail closed"
        );
    }
    let trailing = format!("{encrypted}not-pem-trailing-input");
    assert!(
        decode_signing_key(
            encrypted_path,
            trailing.as_bytes(),
            PrivateKeyFormat::Pem,
            SignatureAlgorithm::DsaSha256,
            Some(password),
        )
        .is_err(),
        "encrypted DSA PEM must occupy the complete input"
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    let mut mismatched_y = y.to_vec();
    *mismatched_y.last_mut().unwrap() ^= 1;
    for (bytes, format) in [
        (
            traditional_dsa_der(&key, 1, y.as_ref()),
            PrivateKeyFormat::Der,
        ),
        (trailing, PrivateKeyFormat::Der),
        (
            traditional_dsa_der(&key, 0, &mismatched_y),
            PrivateKeyFormat::Der,
        ),
        (valid, PrivateKeyFormat::Pkcs8Der),
    ] {
        assert!(
            decode_signing_key(path, &bytes, format, SignatureAlgorithm::DsaSha256, None,).is_err(),
            "malformed or misclassified traditional DSA must be rejected"
        );
    }
}

fn signing_template_with_key_info(key_info: &str, targets: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue/>{key_info}{targets}</ds:Signature>"#
    )
}

/// The operation document the commands parse once, under `policy`.
fn operation_document(
    xml: impl Into<String>,
    policy: &impl xml_sec::XmlDocumentPolicy,
) -> xml_sec::XmlDocument {
    parse_operation_document(xml.into(), policy, xml_sec::XmlBackend::default()).unwrap()
}

#[test]
fn signing_metadata_rejects_invalid_key_info_reference_graphs() {
    // Signing key selection must fail closed on the same malformed graph
    // shapes rejected by verification rather than silently discarding the
    // reference and selecting an unconstrained key.
    let cases = [
        (
            "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#missing\"/></ds:KeyInfo>",
            "",
            "KeyInfoReference target is missing or ambiguous",
        ),
        (
            "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
            "<ds:Object Id=\"target\"/>",
            "KeyInfoReference target must be KeyInfo",
        ),
        (
            "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
            "<ds:KeyInfo Id=\"target\"><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
            "KeyInfoReference cycle detected",
        ),
        (
            "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"keys.xml#target\"/></ds:KeyInfo>",
            "",
            "KeyInfoReference URI policy rejected the operation",
        ),
    ];
    for (key_info, targets, expected) in cases {
        let error = signing_signature_metadata(
            &operation_document(
                signing_template_with_key_info(key_info, targets),
                &SigningPolicy::default(),
            ),
            None,
            &[],
            &SigningPolicy::default(),
            xml_sec::XmlBackend::default(),
            xml_sec::provider::default_provider(),
        )
        .expect_err("invalid KeyInfoReference graph must be rejected");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn signing_metadata_bounds_key_info_reference_depth() {
    // Acyclic chains remain attacker-controlled, so traversal depth must
    // consume the operation policy limit before parsing the next target.
    let maximum = SigningPolicy::default()
        .resources
        .max_key_info_reference_depth;
    let targets = (0..=maximum)
        .map(|index| {
            if index == maximum {
                format!("<ds:KeyInfo Id=\"level-{index}\"><ds:KeyName>key</ds:KeyName></ds:KeyInfo>")
            } else {
                format!("<ds:KeyInfo Id=\"level-{index}\"><dsig11:KeyInfoReference URI=\"#level-{}\"/></ds:KeyInfo>", index + 1)
            }
        })
        .collect::<String>();
    let error = signing_signature_metadata(
        &operation_document(
            signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#level-0\"/></ds:KeyInfo>",
                &targets,
            ),
            &SigningPolicy::default(),
        ),
        None,
        &[],
        &SigningPolicy::default(),
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect_err("over-deep KeyInfoReference chain must be rejected");
    assert!(
        error
            .to_string()
            .contains(&format!("policy maximum {maximum}")),
        "{error}"
    );
}

#[test]
fn signing_metadata_bounds_key_info_reference_candidate_work() {
    // Referenced sources share one aggregate candidate budget with the
    // reference nodes themselves; each nested KeyInfo cannot reset it.
    let mut policy = SigningPolicy::default();
    policy.resources.max_key_candidates = 2;
    let error = signing_signature_metadata(
        &operation_document(
            signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:KeyInfo Id=\"target\"><ds:KeyName>one</ds:KeyName><ds:KeyName>two</ds:KeyName></ds:KeyInfo>",
            ),
            &policy,
        ),
        None,
        &[],
        &policy,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect_err("aggregate candidate work must respect operation policy");
    assert!(
        error
            .to_string()
            .contains("key candidates exceeds policy maximum 2"),
        "{error}"
    );
}

#[test]
fn signing_metadata_enforces_key_info_reference_uri_policy() {
    // The signing policy can disable KeyInfoReference independently of
    // ordinary signed-payload references; metadata selection must honor it
    // before dereferencing even a valid same-document target.
    let mut policy = SigningPolicy::default();
    policy.uris.key_info_references = xml_sec::xmldsig::UriTypeSet::new(false, false, false);
    let error = signing_signature_metadata(
        &operation_document(
            signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:KeyInfo Id=\"target\"><ds:KeyName>key</ds:KeyName></ds:KeyInfo>",
            ),
            &policy,
        ),
        None,
        &[],
        &policy,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect_err("disabled KeyInfoReference URI class must be rejected");
    assert!(
        error
            .to_string()
            .contains("KeyInfoReference URI policy rejected the operation"),
        "{error}"
    );
}

#[test]
fn normalizes_pkcs1_private_and_public_keys() {
    // PKCS#1 is a donor-supported RSA container. The CLI normalizes it to
    // the core's PKCS#8/SPKI contracts. Generating the source key keeps this
    // unit test runnable from the published crate without repository paths.
    let original = RsaPrivateKey::new(&mut ChaCha20Rng::from_seed([7; 32]), 1024).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("private.pem");
    let public = temp.path().join("public.der");
    fs::write(
        &private,
        original.to_pkcs1_pem(pkcs8::LineEnding::default()).unwrap(),
    )
    .unwrap();
    fs::write(
        &public,
        original.to_public_key().to_pkcs1_der().unwrap().as_bytes(),
    )
    .unwrap();

    load_signing_key(&private, PrivateKeyFormat::Pem).expect("PKCS#1 private key must normalize");
    let key = load_verification_key(
        &public,
        PublicKeyEncoding::Der,
        SignatureAlgorithm::RsaSha256,
    )
    .expect("PKCS#1 public key must normalize");
    RsaPublicKey::from_public_key_der(&key.public_key_bytes)
        .expect("verification key must use SPKI DER");
}

#[test]
fn decrypts_traditional_encrypted_rsa_pem() {
    // `--privkey-pem` follows libxmlsec1's container-agnostic PEM
    // contract, including the OpenSSL legacy encrypted PKCS#1 envelope.
    let encrypted = include_bytes!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem"
    );
    let path = Path::new("rsa-2048-key-traditional-encrypted.pem");

    decode_signing_key(
        path,
        encrypted,
        PrivateKeyFormat::Pem,
        SignatureAlgorithm::RsaSha256,
        Some(b"legacy-rsa-password"),
    )
    .expect("the correct password must decrypt traditional RSA PEM");

    for password in [None, Some(b"wrong-password".as_slice())] {
        assert!(
            decode_signing_key(
                path,
                encrypted,
                PrivateKeyFormat::Pem,
                SignatureAlgorithm::RsaSha256,
                password,
            )
            .is_err(),
            "missing or incorrect passwords must fail closed"
        );
    }
}

#[test]
fn decrypts_traditional_encrypted_sec1_pem_for_every_curve() {
    // Generic PEM keys use one password-aware OpenSSL envelope contract for
    // every supported EC curve; explicit PKCS#8 options remain container-strict.
    let password = b"legacy-ec-password";
    let cases = [
        (
            SignatureAlgorithm::EcdsaSha256,
            p256::SecretKey::from_slice(&[0x11; 32])
                .unwrap()
                .to_sec1_der()
                .unwrap()
                .to_vec(),
        ),
        (
            SignatureAlgorithm::EcdsaSha384,
            p384::SecretKey::from_slice(&[0x22; 48])
                .unwrap()
                .to_sec1_der()
                .unwrap()
                .to_vec(),
        ),
        (
            SignatureAlgorithm::EcdsaSha512,
            p521::SecretKey::from_slice(&[0x01; 66])
                .unwrap()
                .to_sec1_der()
                .unwrap()
                .to_vec(),
        ),
    ];

    for (algorithm, der) in cases {
        let encrypted = encrypted_traditional_pem("EC PRIVATE KEY", &der, password);
        let path = Path::new("traditional-encrypted-ec.pem");
        decode_signing_key(
            path,
            encrypted.as_bytes(),
            PrivateKeyFormat::Pem,
            algorithm,
            Some(password),
        )
        .expect("the correct password must decrypt traditional SEC1 PEM");

        for rejected_password in [None, Some(b"wrong-password".as_slice())] {
            assert!(
                decode_signing_key(
                    path,
                    encrypted.as_bytes(),
                    PrivateKeyFormat::Pem,
                    algorithm,
                    rejected_password,
                )
                .is_err(),
                "missing or incorrect passwords must fail closed"
            );
        }

        let trailing = format!("{encrypted}not-pem-trailing-input");
        assert!(
            decode_signing_key(
                path,
                trailing.as_bytes(),
                PrivateKeyFormat::Pem,
                algorithm,
                Some(password),
            )
            .is_err(),
            "encrypted SEC1 PEM must occupy the complete input"
        );
    }
}

#[test]
fn rejects_malformed_traditional_encrypted_rsa_pem() {
    // Legacy PEM metadata is a parser configuration boundary: an
    // unknown cipher, malformed IV, or extra input must never fall back to
    // interpreting encrypted bytes as a plaintext private key.
    let encrypted =
        include_str!("../../../../tests/fixtures/keys/rsa/rsa-2048-key-traditional-encrypted.pem");
    let path = Path::new("rsa-2048-key-traditional-encrypted.pem");
    let cases = [
        encrypted.replace("AES-256-CBC", "RC2-CBC"),
        encrypted.replace(
            "C98DDAE6A971742BF435D3FF6CD60028",
            "C98DDAE6A971742BF435D3FF6CD6002Z",
        ),
        format!("{encrypted}\nnot-pem-trailing-input"),
        format!("{encrypted}\n{encrypted}"),
    ];

    for malformed in cases {
        assert!(
            decode_signing_key(
                path,
                malformed.as_bytes(),
                PrivateKeyFormat::Pem,
                SignatureAlgorithm::RsaSha256,
                Some(b"legacy-rsa-password"),
            )
            .is_err(),
            "malformed legacy PEM envelopes must fail closed"
        );
    }
}

#[test]
fn asymmetric_loaders_enforce_the_selected_option_format() {
    // CLI option names are format contracts: accepting a different
    // container would hide configuration errors and diverge from xmlsec1.
    let original = RsaPrivateKey::new(&mut ChaCha20Rng::from_seed([8; 32]), 1024).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let private_pem = temp.path().join("private.pem");
    let private_der = temp.path().join("private.der");
    let public_pem = temp.path().join("public.pem");
    let public_der = temp.path().join("public.der");
    fs::write(
        &private_pem,
        original.to_pkcs1_pem(pkcs8::LineEnding::default()).unwrap(),
    )
    .unwrap();
    fs::write(&private_der, original.to_pkcs1_der().unwrap().as_bytes()).unwrap();
    fs::write(
        &public_pem,
        original
            .to_public_key()
            .to_pkcs1_pem(pkcs8::LineEnding::default())
            .unwrap(),
    )
    .unwrap();
    fs::write(
        &public_der,
        original.to_public_key().to_pkcs1_der().unwrap().as_bytes(),
    )
    .unwrap();

    assert!(load_signing_key(&private_pem, PrivateKeyFormat::Der).is_err());
    assert!(load_signing_key(&private_der, PrivateKeyFormat::Pem).is_err());
    assert!(load_signing_key(&private_pem, PrivateKeyFormat::Pkcs8Pem).is_err());
    assert!(load_signing_key(&private_der, PrivateKeyFormat::Pkcs8Der).is_err());
    assert!(
        load_verification_key(
            &public_pem,
            PublicKeyEncoding::Der,
            SignatureAlgorithm::RsaSha256,
        )
        .is_err()
    );
    assert!(
        load_verification_key(
            &public_der,
            PublicKeyEncoding::Pem,
            SignatureAlgorithm::RsaSha256,
        )
        .is_err()
    );
}

#[test]
fn malformed_pem_error_names_the_source_path() {
    // Diagnostics must identify the failing file rather than a PEM label.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("broken-key.pem");
    fs::write(
        &path,
        "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
    )
    .unwrap();
    let error = load_verification_key(&path, PublicKeyEncoding::Pem, SignatureAlgorithm::RsaSha256)
        .unwrap_err();
    assert!(error.to_string().contains(path.to_str().unwrap()));
    assert!(!error.to_string().contains("in PUBLIC KEY"));
}

#[test]
fn utf8_spki_der_is_not_misclassified_as_pem() {
    // Container detection follows successful decoding, not UTF-8 validity.
    // This minimal unknown-algorithm SPKI is entirely ASCII/control bytes.
    let spki = [
        0x30, 0x0a, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x01, 0x00,
    ];
    assert!(std::str::from_utf8(&spki).is_ok());
    assert!(valid_spki(&spki));
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("public.der");
    fs::write(&path, spki).unwrap();

    let key = load_verification_key(&path, PublicKeyEncoding::Der, SignatureAlgorithm::RsaSha256)
        .expect("valid UTF-8 DER must reach the DER decoder");
    assert_eq!(key.public_key_bytes, spki);
}

#[test]
fn certificate_loader_does_not_guess_an_encoding() {
    // The selected option, not UTF-8 validity, controls the decoder.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("certificate.pem");
    fs::write(&path, b"not a PEM container").unwrap();
    assert!(load_certificate_with_source_len(&path, CertificateEncoding::Pem).is_err());
    assert!(load_certificate_with_source_len(&path, CertificateEncoding::Der).is_err());
}

#[test]
fn symmetric_key_loader_rejects_input_above_the_supported_ceiling() {
    // Decryption does not know the exact AES width until it parses the
    // ciphertext, but the CLI must still reject data beyond every supported
    // AES key size instead of treating an arbitrary file as key material.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.key");
    fs::write(&path, [0_u8; 33]).unwrap();

    let error = load_symmetric(&path, None).unwrap_err();

    assert!(error.to_string().contains("maximum 32 bytes"));
}

#[test]
fn oversized_asymmetric_material_is_rejected_before_decoding() {
    // Key and certificate inputs are caller-controlled files. An invalid
    // oversized file must hit the read ceiling before a decoder sees it.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.pem");
    fs::write(&path, vec![b'x'; KEY_MATERIAL_BYTE_CEILING + 1]).unwrap();

    let Err(error) = load_signing_key(&path, PrivateKeyFormat::Pem) else {
        panic!("oversized key material must be rejected");
    };

    let message = error.to_string();
    assert!(message.contains(&path.display().to_string()));
    assert!(message.contains(&format!("maximum {KEY_MATERIAL_BYTE_CEILING} bytes")));
}

#[test]
fn selected_signature_controls_verification_key_algorithm() {
    // Key decoding must inspect the same selected Signature as verification;
    // an unrelated earlier signature may use a different key family.
    let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
    let signature = |id: &str, algorithm: &str| {
        format!(
            r#"<ds:Signature Id="{id}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="{algorithm}"/>
<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>
</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
        )
    };
    let xml = format!(
        "<root>{}{}</root>",
        signature("rsa", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        signature("ec", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
    );

    let metadata = verification_signature_metadata(
        &operation_document(xml, &VerificationPolicy::default()),
        Some("ec"),
        &[],
        &xml_sec::policy::VerificationPolicy::default(),
        VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .unwrap();
    assert_eq!(metadata.algorithm, SignatureAlgorithm::EcdsaSha256);
}

#[test]
fn direct_verification_metadata_ignores_malformed_document_keys() {
    // A pinned caller key makes document KeyInfo irrelevant. Malformed key
    // metadata must therefore remain for the core verifier to ignore.
    let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
    let xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><dsig11:DEREncodedKeyValue>not-base64!</dsig11:DEREncodedKeyValue></ds:KeyInfo></ds:Signature>"#
    );

    let metadata = verification_signature_metadata(
        &operation_document(xml.as_str(), &VerificationPolicy::default()),
        None,
        &[],
        &VerificationPolicy::default(),
        VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect("unused malformed document keys must not block a pinned key");

    assert_eq!(metadata.algorithm, SignatureAlgorithm::RsaSha256);
    assert_eq!(metadata.key_names, Vec::<String>::new());
    // Raw HMAC keys are pinned too: neither malformed key bytes nor an
    // unused unresolved reference may make their metadata inspection fail.
    let hmac_xml = xml.replace("#rsa-sha256", "#hmac-sha256");
    for input in [
        hmac_xml.clone(),
        hmac_xml.replace(
            "<dsig11:DEREncodedKeyValue>not-base64!</dsig11:DEREncodedKeyValue>",
            "<dsig11:KeyInfoReference URI=\"#missing\"/>",
        ),
    ] {
        let metadata = verification_signature_metadata(
            &operation_document(input, &VerificationPolicy::default()),
            None,
            &[],
            &VerificationPolicy::default(),
            VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
            xml_sec::provider::default_provider(),
        )
        .expect("pinned HMAC must ignore unused key hints");
        assert_eq!(metadata.algorithm, SignatureAlgorithm::HmacSha256);
        assert_eq!(metadata.key_names, Vec::<String>::new());
    }
}

#[test]
fn signature_metadata_preserves_every_key_name_for_resolution() {
    // KeyInfo is an ordered list of lookup sources; collapsing it to the
    // first KeyName makes later valid key-manager entries unreachable.
    let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
    let xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><ds:KeyName>old</ds:KeyName><ds:KeyName>wan<!--split-->ted</ds:KeyName></ds:KeyInfo></ds:Signature>"#
    );

    let metadata = verification_signature_metadata(
        &operation_document(xml, &VerificationPolicy::default()),
        None,
        &[],
        &xml_sec::policy::VerificationPolicy::default(),
        VerificationKeyNameResolution::ResolveDocumentKeyInfo,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .unwrap();

    assert_eq!(metadata.key_names, ["old", "wanted"]);
}

#[test]
fn verification_metadata_resolves_referenced_key_names() {
    // CLI candidate selection precedes core verification, so it must see
    // the same bounded KeyInfoReference graph as the verifier.
    let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
    let xml = format!(
        r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><dsig11:KeyInfoReference URI="#target"/></ds:KeyInfo></ds:Signature><ds:KeyInfo Id="target"><ds:KeyName>wanted</ds:KeyName></ds:KeyInfo></root>"##
    );

    let document = operation_document(xml, &VerificationPolicy::default());
    let metadata = verification_signature_metadata(
        &document,
        None,
        &[],
        &VerificationPolicy::default(),
        VerificationKeyNameResolution::ResolveDocumentKeyInfo,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect("same-document KeyInfoReference must resolve before candidate selection");

    assert_eq!(metadata.key_names, ["wanted"]);

    let mut disabled = VerificationPolicy::default();
    disabled
        .key_sources
        .remove(xml_sec::policy::KeySourceKind::KeyInfoReference);
    let error = verification_signature_metadata(
        &document,
        None,
        &[],
        &disabled,
        VerificationKeyNameResolution::ResolveDocumentKeyInfo,
        xml_sec::XmlBackend::default(),
        xml_sec::provider::default_provider(),
    )
    .expect_err("metadata selection must honor the verification key-source policy");
    assert!(error.to_string().contains("key sources are disabled"));
}

#[test]
fn signature_discovery_obeys_the_verification_node_ceiling() {
    // Metadata discovery runs before cryptographic verification and must
    // not allocate a DOM larger than the operation policy permits.
    let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
    let xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
    );
    let policy = xml_sec::policy::VerificationPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_nodes: 4,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..xml_sec::policy::VerificationPolicy::default()
    };

    // Discovery reads the operation document, so its parse carries the ceiling.
    let Err(error) = parse_operation_document(xml, &policy, xml_sec::XmlBackend::default()) else {
        panic!("a document over the node ceiling must not parse");
    };
    // The parser's own text, as the CLI reported it before discovery shared the
    // operation's document; no document-layer prefix is added.
    assert_eq!(
        error.to_string(),
        "invalid XML signature: nodes limit reached"
    );
}

#[test]
fn a_syntax_error_keeps_the_backend_diagnostic() {
    // The owned parse maps a syntax error to the backend's own text, which the
    // CLI reports without the document layer's "XML parsing error" prefix.
    let Err(error) = parse_operation_document(
        "<root>".to_owned(),
        &xml_sec::policy::VerificationPolicy::default(),
        xml_sec::XmlBackend::default(),
    ) else {
        panic!("an unclosed element must not parse");
    };
    let text = error.to_string();
    assert!(text.contains(" rejected XML: "), "{text}");
    assert!(!text.contains("XML parsing error"), "{text}");
}
