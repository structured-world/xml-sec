use std::{fs, path::Path, process::Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_xmlsec1")
}

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
}

#[test]
fn signs_verifies_and_rejects_tampering_through_process_api() {
    // Exercise the process boundary and prove a post-signature content change
    // is classified as invalid rather than accepted or reported as a CLI error.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let signed = temp.path().join("signed.xml");

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .args(["--output"])
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let verify = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let tampered = temp.path().join("tampered.xml");
    let xml = fs::read_to_string(&signed).unwrap();
    fs::write(&tampered, xml.replace("some text", "tampered text")).unwrap();
    let rejected = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&tampered)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid"));
}

#[test]
fn encrypts_decrypts_and_rejects_wrong_symmetric_key() {
    // A reciprocal binary round trip must preserve non-UTF-8 bytes, while an
    // authenticated GCM decrypt with the wrong key must fail.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    let wrong_key = temp.path().join("wrong-key.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let decrypted = temp.path().join("decrypted.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"process-level binary payload\0\xff").unwrap();
    // xmlsec1 treats --aeskey input as raw bytes even when all bytes happen to
    // be valid Base64 characters.
    fs::write(&key, b"0123456789abcdef").unwrap();
    fs::write(&wrong_key, b"fedcba9876543210").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aeskey:content"])
        .arg(&key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .args(["--output"])
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aeskey"])
        .arg(&key)
        .args(["--output"])
        .arg(&decrypted)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&plaintext).unwrap());

    let rejected = Command::new(binary())
        .args(["decrypt", "--aeskey"])
        .arg(&wrong_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
}

#[test]
fn encrypts_and_decrypts_with_an_rsa_oaep_recipient() {
    // The advertised RSA path must emit XML Encryption 1.1 OAEP and unwrap its
    // generated content key through a separate CLI invocation.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"RSA recipient payload").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .args(["--output"])
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .contains("http://www.w3.org/2009/xmlenc11#rsa-oaep")
    );

    let decrypt = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(&private_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, fs::read(&plaintext).unwrap());
}

#[test]
fn decrypts_encrypted_data_embedded_in_a_document() {
    // libxmlsec1 decrypt replaces EncryptedData in its containing document; a
    // standalone-only implementation would reject this process contract.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let key = temp.path().join("key.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let document = temp.path().join("document.xml");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, "<secret>document payload</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aeskey:content"])
        .arg(&key)
        .args(["--xml-data"])
        .arg(&plaintext)
        .args(["--output"])
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(encrypt.status.success());
    fs::write(
        &document,
        format!(
            "<root><before/>{}<after/></root>",
            fs::read_to_string(&encrypted).unwrap()
        ),
    )
    .unwrap();

    let decrypted = Command::new(binary())
        .args(["decrypt", "--aeskey"])
        .arg(&key)
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        decrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    let output = String::from_utf8(decrypted.stdout).unwrap();
    let parsed = roxmltree::Document::parse(&output).unwrap();
    assert_eq!(parsed.root_element().tag_name().name(), "root");
    assert_eq!(
        parsed
            .descendants()
            .find(|node| node.has_tag_name("secret"))
            .and_then(|node| node.text()),
        Some("document payload")
    );
}

#[test]
fn generated_key_store_uses_the_libxmlsec1_xml_shape() {
    // Validate namespaces and element layout, not just well-formedness, because
    // libxmlsec1's key manager depends on this exact interoperable structure.
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("keys.xml");
    let generated = Command::new(binary())
        .args(["keys", "--gen-key:integration<&", "aes-128"])
        .arg(&key_store)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let xml = fs::read_to_string(key_store).unwrap();
    let document = roxmltree::Document::parse(&xml).unwrap();
    let elements = document
        .descendants()
        .filter(|node| node.is_element())
        .map(|node| (node.tag_name().namespace(), node.tag_name().name()))
        .collect::<Vec<_>>();
    assert_eq!(
        elements,
        vec![
            (Some("http://www.aleksey.com/xmlsec/2002"), "Keys"),
            (Some("http://www.w3.org/2000/09/xmldsig#"), "KeyInfo"),
            (Some("http://www.w3.org/2000/09/xmldsig#"), "KeyName"),
            (Some("http://www.w3.org/2000/09/xmldsig#"), "KeyValue"),
            (Some("http://www.aleksey.com/xmlsec/2002"), "AESKeyValue"),
        ]
    );
    assert_eq!(
        document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")))
            .and_then(|node| node.text()),
        Some("integration<&")
    );
}

#[test]
fn generated_key_store_contains_every_requested_key() {
    // Repeated --gen-key options are independent requests and must never be
    // silently collapsed to the first parsed value.
    let generated = Command::new(binary())
        .args([
            "keys",
            "--gen-key:first",
            "aes-128",
            "--gen-key:second",
            "aes-256",
        ])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let xml = String::from_utf8(generated.stdout).unwrap();
    let document = roxmltree::Document::parse(&xml).unwrap();
    let names = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")))
        .filter_map(|node| node.text())
        .collect::<Vec<_>>();
    assert_eq!(names, ["first", "second"]);
}

#[test]
fn reports_capabilities_and_process_failures_deterministically() {
    // Cover parser, capability, malformed-input, and output-path failures at
    // the executable boundary where automation observes only status and stderr.
    let temp = tempfile::tempdir().unwrap();
    let malformed = temp.path().join("malformed.xml");
    fs::write(&malformed, "<Signature>").unwrap();

    assert!(
        Command::new(binary())
            .args(["check-transforms", "c14n", "rsa-sha256"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new(binary())
            .args(["check-transforms", "xslt"])
            .status()
            .unwrap()
            .success()
    );
    let invalid_xml = Command::new(binary())
        .args(["verify", "--pubkey-pem", "missing.pem"])
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!invalid_xml.status.success());
    assert!(String::from_utf8_lossy(&invalid_xml.stderr).contains("signature"));
    assert!(
        !Command::new(binary())
            .args(["verify", "--unknown-option", "missing.xml"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new(binary())
            .args([
                "keys",
                "--gen-key:test",
                "aes-128",
                "/missing/output/keys.xml"
            ])
            .status()
            .unwrap()
            .success()
    );
}
