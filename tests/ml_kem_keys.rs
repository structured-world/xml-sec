#![cfg(feature = "experimental-pq")]

use der::Decode;
use xml_sec::provider::{
    CryptoProvider, KeyDecapsulationKey, KeyEncapsulationAlgorithm, MlKemPrivateKeyEncoding,
    RustCryptoMlKemPrivateKey, RustCryptoMlKemPublicKey, RustCryptoProvider,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/xmldsig/keys/ml-kem")
            .join(name),
    )
    .expect("imported ML-KEM fixture")
}

fn fixture_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

#[cfg(feature = "xmlenc")]
#[test]
fn cli_establishes_keys_for_sign_verify_encrypt_decrypt() {
    // Exercise the real executable and protected-key import, not only core APIs.
    let directory = tempfile::tempdir().unwrap();
    let run = |arguments: &[&std::ffi::OsStr]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    for size in [512, 768, 1024] {
        let public = fixture_path(&format!("xmldsig/keys/ml-kem/ml-kem-{size}-pubkey.pem"));
        let private = fixture_path(&format!("xmldsig/keys/ml-kem/ml-kem-{size}-key.p8-pem"));
        let template = fixture_path(&format!(
            "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-{size}.tmpl"
        ));
        let signed = directory.path().join(format!("signed-{size}.xml"));
        run(&[
            "sign".as_ref(),
            "--pubkey-pem".as_ref(),
            public.as_os_str(),
            "--output".as_ref(),
            signed.as_os_str(),
            template.as_os_str(),
        ]);
        run(&[
            "verify".as_ref(),
            "--insecure".as_ref(),
            "--pkcs8-pem".as_ref(),
            private.as_os_str(),
            "--pwd".as_ref(),
            "secret123".as_ref(),
            signed.as_os_str(),
        ]);
        if let Some(oracle) = std::env::var_os("XMLSEC1_BIN") {
            // An enabled independent oracle must verify the complete XML binding.
            let raw = fixture_path(&format!("xmldsig/keys/ml-kem/ml-kem-{size}-key.pem"));
            let output = std::process::Command::new(oracle)
                .args([
                    "--verify",
                    "--enabled-key-data",
                    "key-name,encapsulation-mechanism",
                    &format!("--privkey-pem:TestKeyName-ml-kem-{size}"),
                ])
                .arg(raw)
                .arg(&signed)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let denied = std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
            .args(["verify", "--pkcs8-pem"])
            .arg(&private)
            .args(["--pwd", "secret123"])
            .arg(&signed)
            .output()
            .unwrap();
        assert!(
            !denied.status.success(),
            "KEM must not establish sender trust"
        );
        let wrong = std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
            .args(["verify", "--insecure", "--pkcs8-pem"])
            .arg(&private)
            .args(["--pwd", "wrong"])
            .arg(&signed)
            .output()
            .unwrap();
        assert!(!wrong.status.success());
        let data = directory.path().join("plaintext");
        std::fs::write(&data, b"<test>ML-KEM CLI plaintext</test>").unwrap();
        let width = match size {
            512 => 128,
            768 => 192,
            _ => 256,
        };
        let encryption = fixture_path(&format!(
            "xmlenc/aleksey-xmlenc-01/enc-aes{width}gcm-em-ml-kem-{size}.tmpl"
        ));
        let encrypted = directory.path().join(format!("encrypted-{size}.xml"));
        let decrypted = directory.path().join(format!("decrypted-{size}"));
        run(&[
            "encrypt".as_ref(),
            "--pubkey-pem".as_ref(),
            public.as_os_str(),
            "--xml-data".as_ref(),
            data.as_os_str(),
            "--output".as_ref(),
            encrypted.as_os_str(),
            encryption.as_os_str(),
        ]);
        run(&[
            "decrypt".as_ref(),
            "--pkcs8-pem".as_ref(),
            private.as_os_str(),
            "--pwd".as_ref(),
            "secret123".as_ref(),
            "--output".as_ref(),
            decrypted.as_os_str(),
            encrypted.as_os_str(),
        ]);
        // These donor templates specify Type=Content, so the wrapper element
        // is not part of the encrypted/decrypted payload.
        assert_eq!(std::fs::read(decrypted).unwrap(), b"ML-KEM CLI plaintext");
        if let Some(oracle) = std::env::var_os("XMLSEC1_BIN") {
            // libxmlsec1 replaces Type=Content in the owning XML document,
            // unlike our byte-returning CLI. Supply its actual parent context:
            // top-level text alone cannot be serialized as an XML document.
            let oracle_input = directory.path().join(format!("oracle-{size}.xml"));
            let encrypted_xml = std::fs::read_to_string(&encrypted).unwrap();
            let element = &encrypted_xml[encrypted_xml.find("<EncryptedData").unwrap()
                ..encrypted_xml.find("</EncryptedData>").unwrap() + "</EncryptedData>".len()];
            std::fs::write(&oracle_input, format!("<test>{element}</test>")).unwrap();
            let raw = fixture_path(&format!("xmldsig/keys/ml-kem/ml-kem-{size}-key.pem"));
            let output = std::process::Command::new(oracle)
                .args([
                    "--decrypt",
                    "--enabled-key-data",
                    "key-name,encapsulation-mechanism",
                    &format!("--privkey-pem:TestKeyName-ml-kem-{size}"),
                ])
                .arg(raw)
                .arg(&oracle_input)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let c14n =
                xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_0, false);
            assert_eq!(
                xml_sec::c14n::canonicalize_xml(&output.stdout, &c14n).unwrap(),
                b"<test>ML-KEM CLI plaintext</test>"
            );
        }
    }
}

#[test]
fn all_donor_hmac_encapsulation_ciphertexts_verify() {
    // The public facade consumes complete independent donor signatures; test
    // code must not decapsulate and inject a raw HMAC key on its behalf.
    for size in [512, 768, 1024] {
        let xml = std::fs::read_to_string(fixture_path(&format!(
            "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-{size}.xml"
        )))
        .expect("signed donor XML");
        let key =
            RustCryptoMlKemPrivateKey::from_pkcs8_der(&fixture(&format!("ml-kem-{size}-key.der")))
                .unwrap();
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        policy
            .key_establishment
            .encapsulation_algorithms
            .insert(key.algorithm());
        policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
        let result = xml_sec::xmldsig::VerifyContext::new()
            .decapsulation_key(&key)
            .policy(policy)
            .verify(&xml)
            .expect("donor verification");
        assert_eq!(
            result.status,
            xml_sec::xmldsig::DsigStatus::Valid,
            "ML-KEM-{size}"
        );
    }
}

#[test]
fn inventory_accepts_recipient_material_not_signature_keys() {
    // ML-KEM material authorizes key establishment, never signature generation.
    let resources = xml_sec::policy::ResourcePolicy::default();
    for size in [512, 768, 1024] {
        let mut inventory = xml_sec::key_manager::KeyInventory::default();
        inventory
            .add_private_der(
                "recipient".into(),
                &fixture(&format!("ml-kem-{size}-key.der")),
                None,
                xml_sec::key_manager::KeyUsages::DECRYPT,
                &resources,
            )
            .unwrap();
        inventory
            .add_public_der_with_usages(
                "sender".into(),
                fixture(&format!("ml-kem-{size}-pubkey.der")),
                xml_sec::key_manager::KeyUsages::ENCRYPT,
                &resources,
            )
            .unwrap();
        assert!(
            inventory
                .signing_key(
                    "recipient",
                    xml_sec::xmldsig::SignatureAlgorithm::HmacSha256,
                    &xml_sec::policy::SigningPolicy::default()
                )
                .is_err()
        );
        #[cfg(feature = "xmlenc")]
        {
            let mut policy = xml_sec::policy::DecryptionPolicy::default();
            policy
                .key_establishment
                .encapsulation_algorithms
                .insert(match size {
                    512 => KeyEncapsulationAlgorithm::MlKem512,
                    768 => KeyEncapsulationAlgorithm::MlKem768,
                    _ => KeyEncapsulationAlgorithm::MlKem1024,
                });
            // Inventory selection must dispatch by key identity, not assume RSA.
            inventory.decryption_resolver("recipient", &policy).unwrap();
        }
    }
}

#[test]
fn hmac_templates_establish_fresh_keys_and_obey_policy() {
    // Complete signing/verification must populate CipherValue before reference
    // digests. Reusing a template creates fresh ciphertext, not a reused secret.
    for size in [512, 768, 1024] {
        let template = std::fs::read_to_string(fixture_path(&format!(
            "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-{size}.tmpl"
        )))
        .unwrap();
        let private =
            RustCryptoMlKemPrivateKey::from_pkcs8_der(&fixture(&format!("ml-kem-{size}-key.der")))
                .unwrap();
        let public = private.public_key();
        let denied =
            xml_sec::xmldsig::SignContext::new_encapsulation(&public).sign_template(&template);
        assert!(denied.is_err(), "experimental KEM is denied by default");
        let mut signing = xml_sec::policy::SigningPolicy::default();
        signing
            .key_establishment
            .encapsulation_algorithms
            .insert(private.algorithm());
        let context =
            xml_sec::xmldsig::SignContext::new_encapsulation(&public).policy(signing.clone());
        let first = context.sign_template(&template).unwrap();
        let second = context.sign_template(&template).unwrap();
        assert_ne!(first, second);
        let mut verification = xml_sec::policy::VerificationPolicy {
            key_establishment: signing.key_establishment.clone(),
            ..xml_sec::policy::VerificationPolicy::default()
        };
        verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
        for signed in [first, second] {
            let result = xml_sec::xmldsig::VerifyContext::new()
                .decapsulation_key(&private)
                .policy(verification.clone())
                .verify(&signed)
                .unwrap();
            assert_eq!(result.status, xml_sec::xmldsig::DsigStatus::Valid);
            assert_eq!(
                result.key_trust,
                xml_sec::xmldsig::KeyTrustEvidence::NotEstablished
            );
        }
        signing.key_establishment.max_encapsulation_operations = 0;
        assert!(
            xml_sec::xmldsig::SignContext::new_encapsulation(&public)
                .policy(signing)
                .sign_template(&template)
                .is_err()
        );
    }
}

#[test]
fn ordinary_hmac_cannot_ignore_an_encapsulation_template() {
    // A raw key must not turn an unexecuted KEM instruction into valid output.
    let template = std::fs::read_to_string(fixture_path(
        "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-512.tmpl",
    ))
    .unwrap();
    let key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).unwrap();
    assert!(
        xml_sec::xmldsig::SignContext::new(&key)
            .sign_template(&template)
            .is_err()
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn cli_rejects_inapplicable_key_options_before_key_io() {
    // A KEM template needs a recipient public key, not a signing private/raw
    // key. Report the option and command before touching the supplied path.
    let template =
        fixture_path("xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-512.tmpl");
    for option in ["hmac-key", "privkey-pem", "pkcs8-der"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
            .arg("sign")
            .arg(format!("--{option}"))
            .arg("missing-key-file")
            .arg(&template)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "Error: --{option} is inapplicable to sign with EncapsulationMechanism; supply a recipient public key\n"
            )
        );
    }
}

#[test]
fn multiple_signatures_share_the_encapsulation_allowance() {
    // A second Signature must not restart the operation-wide KEM allowance.
    let template = std::fs::read_to_string(fixture_path(
        "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-512.tmpl",
    ))
    .unwrap();
    let element = &template[template.find("<Signature").unwrap()..];
    let xml = format!(
        "<root>{element}{}</root>",
        element.replace("object", "second")
    );
    let private =
        RustCryptoMlKemPrivateKey::from_seed(KeyEncapsulationAlgorithm::MlKem512, &[9; 64])
            .unwrap();
    let public = private.public_key();
    let mut signing = xml_sec::policy::SigningPolicy::default();
    signing
        .key_establishment
        .encapsulation_algorithms
        .insert(private.algorithm());
    let first = xml_sec::xmldsig::SignContext::new_encapsulation(&public)
        .policy(signing.clone())
        .signature_template_selection(xml_sec::xmldsig::SignatureTemplateSelection::FirstDescendant)
        .sign_template(&xml)
        .unwrap();
    let signed = xml_sec::xmldsig::SignContext::new_encapsulation(&public)
        .policy(signing.clone())
        .sign_template(&first)
        .unwrap();
    let document = xml_sec::XmlDocument::parse(&signed).unwrap();
    let mut policy = xml_sec::policy::VerificationPolicy {
        key_establishment: signing.key_establishment,
        ..xml_sec::policy::VerificationPolicy::default()
    };
    policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    assert!(
        xml_sec::xmldsig::VerifyContext::new()
            .decapsulation_key(&private)
            .policy(policy.clone())
            .verify_all(&document)
            .unwrap()
            .all_valid()
    );
    policy.key_establishment.max_encapsulation_operations = 1;
    let evidence = xml_sec::xmldsig::VerifyContext::new()
        .decapsulation_key(&private)
        .policy(policy)
        .verify_all(&document)
        .unwrap();
    assert!(!evidence.all_valid());
    assert_eq!(evidence.signatures().len(), 2);
    assert_eq!(
        evidence.signatures()[0].result().as_ref().unwrap().status,
        xml_sec::xmldsig::DsigStatus::Valid
    );
    assert!(
        evidence.signatures()[1]
            .result()
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("key encapsulation operations")
    );
}

#[test]
fn hmac_builder_establishes_a_recipient_key() {
    // Builder and template entry points must use the same establishment path.
    let private =
        RustCryptoMlKemPrivateKey::from_seed(KeyEncapsulationAlgorithm::MlKem512, &[7; 64])
            .unwrap();
    let public = private.public_key();
    let mut policy = xml_sec::policy::SigningPolicy::default();
    policy
        .key_establishment
        .encapsulation_algorithms
        .insert(private.algorithm());
    let builder = xml_sec::xmldsig::SignatureBuilder::new(
        xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
        xml_sec::xmldsig::SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        xml_sec::xmldsig::ReferenceBuilder::new(xml_sec::xmldsig::DigestAlgorithm::Sha256)
            .uri("")
            .transform(xml_sec::xmldsig::Transform::Enveloped),
    );
    let signed = xml_sec::xmldsig::SignContext::new_encapsulation(&public)
        .policy(policy.clone())
        .sign_with_builder("<root>message</root>", &builder)
        .unwrap();
    let mut verification = xml_sec::policy::VerificationPolicy {
        key_establishment: policy.key_establishment,
        ..xml_sec::policy::VerificationPolicy::default()
    };
    verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    assert_eq!(
        xml_sec::xmldsig::VerifyContext::new()
            .decapsulation_key(&private)
            .policy(verification)
            .verify(&signed)
            .unwrap()
            .status,
        xml_sec::xmldsig::DsigStatus::Valid
    );
}

#[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
#[test]
fn all_donor_content_encapsulation_ciphertexts_decrypt() {
    // Independently produced CBC/GCM documents cover all KEM parameter sets
    // and every AES consumer width. Compare complete canonicalized documents.
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
    for (name, size, width) in [
        ("enc-aes256-em-ml-kem-512", 512, 32),
        ("enc-aes256-em-ml-kem-768", 768, 32),
        ("enc-aes256-em-ml-kem-1024", 1024, 32),
        ("enc-aes128gcm-em-ml-kem-512", 512, 16),
        ("enc-aes192gcm-em-ml-kem-768", 768, 24),
        ("enc-aes256gcm-em-ml-kem-1024", 1024, 32),
    ] {
        let path = format!("xmlenc/aleksey-xmlenc-01/{name}");
        let xml = std::fs::read_to_string(fixture_path(&format!("{path}.xml")))
            .expect("encrypted donor XML");
        let expected =
            std::fs::read(fixture_path(&format!("{path}.data"))).expect("donor plaintext");
        let private =
            RustCryptoMlKemPrivateKey::from_pkcs8_der(&fixture(&format!("ml-kem-{size}-key.der")))
                .unwrap();
        let key = xml_sec::xmlenc::EncapsulationDecryptor::new(&private);
        let mut policy = xml_sec::policy::DecryptionPolicy::default();
        policy
            .key_establishment
            .encapsulation_algorithms
            .insert(private.algorithm());
        let document = xml_sec::Document::parse(&xml).expect("donor XML");
        let method = document
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptionMethod"))
            })
            .expect("content method");
        let content_algorithm = xml_sec::xmlenc::DataEncryptionAlgorithm::from_uri(
            method.attribute("Algorithm").expect("content URI"),
        )
        .expect("content algorithm");
        assert_eq!(content_algorithm.key_len(), width);
        // The AES-192 vector requires explicit product-policy permission;
        // importing a donor document must not grant that permission implicitly.
        policy.data_algorithms = Some([content_algorithm].into_iter().collect());
        let decrypted = xml_sec::xmlenc::DecryptContext::new(&key)
            .policy(policy)
            .decrypt_document(&xml, Some("ED"))
            .expect("donor content decryption");
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        assert_eq!(
            canonicalize_xml(decrypted.as_bytes(), &algorithm).expect("actual C14N"),
            canonicalize_xml(&expected, &algorithm).expect("expected C14N"),
            "{name}"
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn encrypted_data_builder_round_trips_all_kem_parameter_sets() {
    // Public APIs must establish a CEK, emit a complete mechanism and recover
    // the original bytes, without test-side secret extraction or raw-key fallback.
    for size in [512, 768, 1024] {
        let private =
            RustCryptoMlKemPrivateKey::from_pkcs8_der(&fixture(&format!("ml-kem-{size}-key.der")))
                .unwrap();
        let mut policy = xml_sec::policy::EncryptionPolicy::default();
        policy
            .key_establishment
            .encapsulation_algorithms
            .insert(private.algorithm());
        let result = xml_sec::xmlenc::EncryptedDataBuilder::new(
            xml_sec::xmlenc::DataEncryptionAlgorithm::Aes256Gcm,
        )
        .encapsulation_key(std::sync::Arc::new(private.public_key()))
        .policy(policy.clone())
        .encrypt_binary(b"KEM content")
        .unwrap();
        let resolver = xml_sec::xmlenc::EncapsulationDecryptor::new(&private);
        let decrypt = xml_sec::policy::DecryptionPolicy {
            key_establishment: policy.key_establishment,
            ..xml_sec::policy::DecryptionPolicy::default()
        };
        let output = xml_sec::xmlenc::DecryptContext::new(&resolver)
            .policy(decrypt)
            .decrypt(&result.encrypted_data_xml)
            .unwrap();
        assert_eq!(
            output,
            xml_sec::xmlenc::DecryptedContent::Bytes(b"KEM content".to_vec())
        );
        let document = xml_sec::Document::parse(&result.encrypted_data_xml).unwrap();
        let value = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
            .unwrap();
        let original = value.text().unwrap();
        let replacement = format!(
            "{}{}",
            if original.starts_with('A') { "B" } else { "A" },
            &original[1..]
        );
        let tampered = result
            .encrypted_data_xml
            .replacen(original, &replacement, 1);
        let policy = xml_sec::policy::DecryptionPolicy {
            key_establishment: xml_sec::policy::KeyEstablishmentPolicy {
                encapsulation_algorithms: [private.algorithm()].into(),
                ..xml_sec::policy::KeyEstablishmentPolicy::default()
            },
            ..xml_sec::policy::DecryptionPolicy::default()
        };
        // Valid-width KEM rejection remains implicit, but GCM must not release
        // plaintext under the resulting rejection secret.
        assert!(
            xml_sec::xmlenc::DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt(&tampered)
                .is_err()
        );
    }
}

#[test]
fn all_donor_key_formats_preserve_the_exact_key_pair() {
    // Independent OpenSSL-generated fixtures prevent mutually incorrect local
    // import/export implementations from hiding behind a local round-trip.
    for (algorithm, name) in [
        (KeyEncapsulationAlgorithm::MlKem512, "ml-kem-512"),
        (KeyEncapsulationAlgorithm::MlKem768, "ml-kem-768"),
        (KeyEncapsulationAlgorithm::MlKem1024, "ml-kem-1024"),
    ] {
        let public = fixture(&format!("{name}-pubkey.der"));
        let public_key = RustCryptoMlKemPublicKey::from_spki_der(&public).expect("public DER");
        assert_eq!(
            public_key.to_spki_der().expect("SPKI export").as_bytes(),
            public
        );
        let public_pem = pem::parse(fixture(&format!("{name}-pubkey.pem"))).expect("public PEM");
        assert_eq!(public_pem.contents(), public);

        let private = zeroize::Zeroizing::new(fixture(&format!("{name}-key.der")));
        let private_pem = pem::parse(fixture(&format!("{name}-key.pem"))).expect("private PEM");
        assert_eq!(private_pem.contents(), private.as_slice());
        let encrypted = fixture(&format!("{name}-key.p8-der"));
        let encrypted_pem =
            pem::parse(fixture(&format!("{name}-key.p8-pem"))).expect("encrypted PEM");
        // PEM and DER containers were encrypted independently with different
        // salts/IVs. Compare the recovered key identities, not ciphertext bytes.
        let encrypted_pem_info =
            pkcs8::EncryptedPrivateKeyInfoRef::from_der(encrypted_pem.contents())
                .expect("encrypted PEM DER");
        assert!(encrypted_pem_info.decrypt("incorrect password").is_err());
        let decrypted_pem = encrypted_pem_info
            .decrypt("secret123")
            .expect("PEM fixture password");
        let encrypted_info =
            pkcs8::EncryptedPrivateKeyInfoRef::from_der(&encrypted).expect("encrypted DER");
        assert!(encrypted_info.decrypt("incorrect password").is_err());
        let decrypted = encrypted_info
            .decrypt("secret123")
            .expect("fixture password");
        let key = RustCryptoMlKemPrivateKey::from_pkcs8_der(&private).expect("private DER");
        let provider_public = RustCryptoProvider
            .import_encapsulation_key(algorithm, &public)
            .expect("provider public import");
        let provider_private = RustCryptoProvider
            .import_decapsulation_key(algorithm, &private)
            .expect("provider private import");
        let protected =
            RustCryptoMlKemPrivateKey::from_pkcs8_der(decrypted.as_bytes()).expect("decrypted DER");
        let protected_pem = RustCryptoMlKemPrivateKey::from_pkcs8_der(decrypted_pem.as_bytes())
            .expect("decrypted PEM");
        assert_eq!(key.algorithm(), algorithm);
        assert_eq!(protected.algorithm(), algorithm);
        assert_eq!(
            key.public_key()
                .to_spki_der()
                .expect("public export")
                .as_bytes(),
            public
        );
        assert_eq!(protected.public_key().to_bytes(), public_key.to_bytes());
        assert_eq!(protected_pem.public_key().to_bytes(), public_key.to_bytes());

        let encapsulated = RustCryptoProvider
            .encapsulate_key(&public_key)
            .expect("encapsulation");
        assert_eq!(
            *RustCryptoProvider
                .decapsulate_key(provider_private.as_ref(), &encapsulated.ciphertext)
                .expect("opaque decapsulation"),
            *encapsulated.shared_secret
        );
        let opaque_encapsulation = RustCryptoProvider
            .encapsulate_key(provider_public.as_ref())
            .expect("opaque encapsulation");
        assert_eq!(
            *RustCryptoProvider
                .decapsulate_key(&key, &opaque_encapsulation.ciphertext)
                .expect("opaque key identity"),
            *opaque_encapsulation.shared_secret
        );
        let different_set = if algorithm == KeyEncapsulationAlgorithm::MlKem512 {
            KeyEncapsulationAlgorithm::MlKem768
        } else {
            KeyEncapsulationAlgorithm::MlKem512
        };
        assert!(
            RustCryptoProvider
                .import_encapsulation_key(different_set, &public)
                .is_err()
        );
        assert!(
            RustCryptoProvider
                .import_decapsulation_key(different_set, &private)
                .is_err()
        );
        for private_key in [&key, &protected, &protected_pem] {
            assert_eq!(
                *RustCryptoProvider
                    .decapsulate_key(private_key, &encapsulated.ciphertext)
                    .expect("decapsulation"),
                *encapsulated.shared_secret
            );
            let expanded = private_key
                .to_pkcs8_der(MlKemPrivateKeyEncoding::Expanded)
                .expect("expanded export");
            let reimported = RustCryptoMlKemPrivateKey::from_pkcs8_der(expanded.as_bytes())
                .expect("expanded reimport");
            assert_eq!(
                *RustCryptoProvider
                    .decapsulate_key(&reimported, &encapsulated.ciphertext)
                    .expect("expanded decapsulation"),
                *encapsulated.shared_secret
            );
        }
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn nested_kem_wrap_recovery_shares_the_operation_budget() {
    // A KEM supplies an AES-KW KEK, not the content key. Nested execution
    // must preserve the same permission and zero-attempt rejection boundary.
    use base64::Engine as _;
    let private =
        RustCryptoMlKemPrivateKey::from_seed(KeyEncapsulationAlgorithm::MlKem768, &[7; 64])
            .unwrap();
    let result = RustCryptoProvider
        .encapsulate_key(&private.public_key())
        .unwrap();
    let content_key = [9; 32];
    let wrapped = RustCryptoProvider
        .wrap_key(
            xml_sec::xmlenc::KeyWrapAlgorithm::AesKw256,
            result.shared_secret.as_slice(),
            &content_key,
        )
        .unwrap();
    let ciphertext = RustCryptoProvider
        .encrypt_data(
            xml_sec::xmlenc::DataEncryptionAlgorithm::Aes256Gcm,
            &content_key,
            b"nested KEM plaintext",
        )
        .unwrap();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let xml = format!(
        "<x:EncryptedData xmlns:x=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:d=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:k=\"{}\"><x:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/><d:KeyInfo><x:EncryptedKey><x:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes256\"/><d:KeyInfo><k:EncapsulationMechanism Algorithm=\"{}\"><d:KeyInfo/><x:CipherData><x:CipherValue>{}</x:CipherValue></x:CipherData></k:EncapsulationMechanism></d:KeyInfo><x:CipherData><x:CipherValue>{}</x:CipherValue></x:CipherData></x:EncryptedKey></d:KeyInfo><x:CipherData><x:CipherValue>{}</x:CipherValue></x:CipherData></x:EncryptedData>",
        xml_sec::key_establishment::ENCAPSULATION_NS,
        private.algorithm().uri(),
        encode(&result.ciphertext),
        encode(&wrapped),
        encode(&ciphertext)
    );
    let resolver = xml_sec::xmlenc::EncapsulationDecryptor::new(&private);
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy
        .key_establishment
        .encapsulation_algorithms
        .insert(private.algorithm());
    assert_eq!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt(&xml)
            .unwrap(),
        xml_sec::xmlenc::DecryptedContent::Bytes(b"nested KEM plaintext".to_vec())
    );
    policy.key_establishment.max_encapsulation_operations = 0;
    assert!(
        xml_sec::xmlenc::DecryptContext::new(&resolver)
            .policy(policy)
            .decrypt(&xml)
            .is_err()
    );
    // The executable must select the recipient inside EncryptedKey as well,
    // rather than assuming every private recipient is RSA.
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("nested.xml");
    let key = directory.path().join("recipient.der");
    std::fs::write(&input, &xml).unwrap();
    std::fs::write(
        &key,
        private
            .to_pkcs8_der(MlKemPrivateKeyEncoding::Seed)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmlsec1"))
        .args(["decrypt", "--pkcs8-der"])
        .arg(key)
        .arg(input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"nested KEM plaintext");
}

#[test]
fn reciprocal_openssl_encapsulation_and_private_encodings() {
    // Fixed donor vectors above always run. Like the other live-oracle tests,
    // OPENSSL_BIN requests reciprocal execution and makes any oracle error fatal.
    let Some(binary) = std::env::var_os("OPENSSL_BIN") else {
        return;
    };
    let directory = tempfile::tempdir().expect("isolated oracle workspace");
    let private_path = directory.path().join("private.der");
    let public_path = directory.path().join("public.der");
    let ciphertext_path = directory.path().join("ciphertext");
    let secret_path = directory.path().join("secret");
    let run = |arguments: &[&std::ffi::OsStr]| {
        let output = std::process::Command::new(&binary)
            .args(arguments)
            .output()
            .expect("OpenSSL oracle");
        assert!(
            output.status.success(),
            "OpenSSL failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    for algorithm in [
        KeyEncapsulationAlgorithm::MlKem512,
        KeyEncapsulationAlgorithm::MlKem768,
        KeyEncapsulationAlgorithm::MlKem1024,
    ] {
        let key = RustCryptoMlKemPrivateKey::generate(&RustCryptoProvider, algorithm)
            .expect("ML-KEM key generation");
        let public = key.public_key();
        std::fs::write(
            &public_path,
            public.to_spki_der().expect("SPKI export").as_bytes(),
        )
        .expect("oracle public key");
        run(&[
            "pkeyutl".as_ref(),
            "-encap".as_ref(),
            "-pubin".as_ref(),
            "-inkey".as_ref(),
            public_path.as_os_str(),
            "-out".as_ref(),
            ciphertext_path.as_os_str(),
            "-secret".as_ref(),
            secret_path.as_os_str(),
        ]);
        let ciphertext = std::fs::read(&ciphertext_path).expect("OpenSSL ciphertext");
        let secret = zeroize::Zeroizing::new(std::fs::read(&secret_path).expect("OpenSSL secret"));
        assert_eq!(secret.len(), 32);
        assert_eq!(
            RustCryptoProvider
                .decapsulate_key(&key, &ciphertext)
                .expect("RustCrypto decapsulation")
                .as_slice(),
            secret.as_slice()
        );
        let encapsulated = RustCryptoProvider
            .encapsulate_key(&public)
            .expect("RustCrypto encapsulation");
        std::fs::write(&ciphertext_path, &encapsulated.ciphertext).expect("oracle ciphertext");
        for encoding in [
            MlKemPrivateKeyEncoding::Seed,
            MlKemPrivateKeyEncoding::Expanded,
            MlKemPrivateKeyEncoding::Combined,
        ] {
            // Every RFC 9935 representation must identify the same real key
            // when decoded by an independent implementation, not just our reader.
            std::fs::write(
                &private_path,
                key.to_pkcs8_der(encoding)
                    .expect("private export")
                    .as_bytes(),
            )
            .expect("oracle private key");
            run(&[
                "pkeyutl".as_ref(),
                "-decap".as_ref(),
                "-inkey".as_ref(),
                private_path.as_os_str(),
                "-in".as_ref(),
                ciphertext_path.as_os_str(),
                "-out".as_ref(),
                secret_path.as_os_str(),
            ]);
            let decoded = zeroize::Zeroizing::new(
                std::fs::read(&secret_path).expect("oracle decapsulation secret"),
            );
            assert_eq!(
                decoded.as_slice(),
                encapsulated.shared_secret.as_slice(),
                "{algorithm:?} {encoding:?}"
            );
        }
    }
}
