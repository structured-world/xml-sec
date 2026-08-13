use std::{fs, path::Path, process::Command};

use rsa::{
    RsaPrivateKey,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _},
};

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
fn output_template_expands_the_extensionless_input_basename() {
    // libxmlsec1 automation uses one output template across many input files;
    // only the first placeholder is replaced and the input extension is removed.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let output_template = temp.path().join("signed-{inputfile}-{inputfile}.xml");
    let expected = temp
        .path()
        .join("signed-enveloping-sha256-rsa-sha256-{inputfile}.xml");

    let signed = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg("--output")
        .arg(output_template)
        .arg(template)
        .output()
        .unwrap();

    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(expected.is_file());
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
fn encryption_preserves_template_metadata_and_supports_id_selection() {
    // Encryption templates are output contracts. Only CipherValue is mutable;
    // caller-owned identifiers, KeyInfo, properties, and extension attributes remain.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    let encrypted = temp.path().join("encrypted.xml");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="payload" Type="http://www.w3.org/2001/04/xmlenc#Element" MimeType="application/xml">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>content</KeyName></KeyInfo>
<CipherData><CipherValue/></CipherData>
<EncryptionProperties><EncryptionProperty Id="audit"><meta xmlns="urn:test">kept</meta></EncryptionProperty></EncryptionProperties>
</EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"<secret>template metadata payload</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();
    let result = Command::new(binary())
        .args(["encrypt", "--aeskey:content"])
        .arg(&key)
        .args(["--xml-data"])
        .arg(&plaintext)
        .args(["--output"])
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = fs::read_to_string(&encrypted).unwrap();
    assert!(output.contains("Id=\"payload\""));
    assert!(output.contains("MimeType=\"application/xml\""));
    assert!(output.contains("<KeyName>content</KeyName>"));
    assert!(output.contains("<meta xmlns=\"urn:test\">kept</meta>"));

    let decrypted = Command::new(binary())
        .args(["decrypt", "--aeskey"])
        .arg(&key)
        .args(["--node-id", "payload"])
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(
        decrypted.stdout,
        b"<secret>template metadata payload</secret>"
    );
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
fn honors_legacy_rsa_oaep_parameters_from_the_template() {
    // Advertising rsa-oaep-mgf1p requires an actual process round trip, and
    // template parameters must drive key wrapping rather than only survive as XML.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("legacy-oaep.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<ds:KeyInfo><EncryptedKey Recipient="legacy">
<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></EncryptionMethod>
<CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo>
<CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"legacy OAEP payload").unwrap();
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
    let xml = fs::read_to_string(&encrypted).unwrap();
    assert!(xml.contains("rsa-oaep-mgf1p"));
    assert!(xml.contains("Recipient=\"legacy\""));

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
    assert_eq!(decrypt.stdout, b"legacy OAEP payload");
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
fn generated_key_store_allows_an_unnamed_key() {
    // The optional --gen-key parameter controls KeyName presence; omitting it
    // must still generate usable AES material rather than rejecting the command.
    let generated = Command::new(binary())
        .args(["keys", "--gen-key", "aes-128"])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let xml = String::from_utf8(generated.stdout).unwrap();
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert!(
        !document
            .descendants()
            .any(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")))
    );
    let value = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.aleksey.com/xmlsec/2002", "AESKeyValue")))
        .and_then(|node| node.text())
        .unwrap();
    assert_eq!(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
            .unwrap()
            .len(),
        16
    );
}

#[cfg(unix)]
#[test]
fn generated_key_store_is_private_on_create_and_overwrite() {
    use std::os::unix::fs::PermissionsExt as _;

    // Key stores contain raw symmetric keys; both a new file and an existing
    // permissive file must end with owner-only permissions.
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("keys.xml");
    fs::write(&key_store, b"old").unwrap();
    fs::set_permissions(&key_store, fs::Permissions::from_mode(0o666)).unwrap();
    let generated = Command::new(binary())
        .args(["keys", "--gen-key:private", "aes-128"])
        .arg(&key_store)
        .output()
        .unwrap();
    assert!(generated.status.success());
    assert_eq!(
        fs::metadata(&key_store).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn explicit_certificate_pins_the_verification_identity() {
    // An embedded certificate must not override an explicit certificate passed
    // by the caller, even when both certificates are structurally valid.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let wrong_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let signed = temp.path().join("signed.xml");
    let compound = format!("{},{}", private_key.display(), certificate.display());
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
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

    assert!(
        Command::new(binary())
            .args(["verify", "--pubkey-cert-pem"])
            .arg(&certificate)
            .arg(&signed)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new(binary())
            .args(["verify", "--pubkey-cert-pem"])
            .arg(&wrong_certificate)
            .arg(&signed)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn explicit_certificate_obeys_trust_anchor_policy() {
    // An explicit leaf pins identity but does not establish trust when callers
    // also supply anchors; --insecure is the explicit compatibility opt-out.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let wrong_anchor = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let signed = temp.path().join("signed.xml");
    let compound = format!("{},{}", private_key.display(), certificate.display());
    assert!(
        Command::new(binary())
            .args(["sign", "--privkey-pem"])
            .arg(compound)
            .arg("--output")
            .arg(&signed)
            .arg(&template)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new(binary())
            .args(["verify", "--pubkey-cert-pem"])
            .arg(&certificate)
            .arg("--trusted-pem")
            .arg(&certificate)
            .arg(&signed)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new(binary())
            .args(["verify", "--pubkey-cert-pem"])
            .arg(&certificate)
            .arg("--trusted-pem")
            .arg(&wrong_anchor)
            .arg(&signed)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary())
            .args(["verify", "--insecure", "--pubkey-cert-pem"])
            .arg(&certificate)
            .arg("--trusted-pem")
            .arg(&wrong_anchor)
            .arg(&signed)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn der_private_key_option_decodes_its_der_companion_certificate() {
    // The comma-separated companion uses the same encoding family as the key
    // option; treating DER certificate bytes as UTF-8 would reject valid input.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_pem =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem"))
            .unwrap();
    let private_der = temp.path().join("private.der");
    fs::write(
        &private_der,
        RsaPrivateKey::from_pkcs8_pem(&private_pem)
            .unwrap()
            .to_pkcs8_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let certificate_pem =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem"))
            .unwrap();
    let (_, certificate) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let certificate_der = temp.path().join("certificate.der");
    fs::write(&certificate_der, certificate.contents).unwrap();
    let compound = format!("{},{}", private_der.display(), certificate_der.display());

    let output = Command::new(binary())
        .args(["sign", "--privkey-p8-der"])
        .arg(compound)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("X509Certificate")
    );
}

#[test]
fn multiple_signing_keys_require_the_matching_template_name() {
    // Repeated key options are a key set, not first-one-wins. A template name
    // selects exactly one named key and an unknown name fails deterministically.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let wrong_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let selected = Command::new(binary())
        .args(["sign", "--privkey-pem:wrong"])
        .arg(&wrong_key)
        .args(["--privkey-pem:TestKeyName-rsa-2048"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );

    let missing = Command::new(binary())
        .args(["sign", "--privkey-pem:first"])
        .arg(&private_key)
        .args(["--privkey-pem:second"])
        .arg(&wrong_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("unknown KeyName"));
}

#[cfg(target_os = "linux")]
#[test]
fn signs_through_non_utf8_filesystem_paths() {
    use std::os::unix::ffi::OsStringExt as _;

    // Unix paths are byte strings; CLI parsing must not reject a valid file
    // solely because its name cannot be represented as UTF-8.
    let temp = tempfile::tempdir().unwrap();
    let template = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"template-\xff.xml".to_vec()));
    let key = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"key-\xfe.pem".to_vec()));
    fs::copy(
        project_root()
            .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl"),
        &template,
    )
    .unwrap();
    fs::copy(
        project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem"),
        &key,
    )
    .unwrap();
    let output = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generated_key_store_contains_every_requested_key() {
    // Repeated --gen-key options are independent requests and must never be
    // silently collapsed to the first parsed value.
    let generated = Command::new(binary())
        .args(["keys", "-g:first", "aes-128", "--gen-key:second", "aes-256"])
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
    let foreign_template = temp.path().join("foreign-template.xml");
    fs::write(
        &foreign_template,
        "<EncryptedData xmlns=\"urn:not-xmlenc\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><CipherData><CipherValue/></CipherData></EncryptedData>",
    )
    .unwrap();

    assert!(
        Command::new(binary())
            .args(["check-transforms", "c14n", "rsa-sha256"])
            .status()
            .unwrap()
            .success()
    );
    let conflicting_keys = Command::new(binary())
        .args([
            "verify",
            "--pubkey-pem",
            "first.pem",
            "--pubkey-pem",
            "second.pem",
        ])
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!conflicting_keys.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting_keys.stderr)
            .contains("exactly one explicit public key")
    );

    let foreign = Command::new(binary())
        .args(["encrypt", "--aeskey", "missing.key", "--binary-data"])
        .arg(&malformed)
        .arg(&foreign_template)
        .output()
        .unwrap();
    assert!(!foreign.status.success());
    assert!(String::from_utf8_lossy(&foreign.stderr).contains("no EncryptedData"));
    assert_eq!(
        Command::new(binary())
            .arg("check-transforms")
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    assert_eq!(
        Command::new(binary())
            .args(["check-transforms", "rsa-oaep-mgf1p"])
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    assert_eq!(
        Command::new(binary())
            .arg("unknown-command")
            .status()
            .unwrap()
            .code(),
        Some(1)
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

    let config = temp.path().join("crypto-config");
    fs::create_dir(&config).unwrap();
    fs::write(config.join("backend.conf"), "unsupported").unwrap();
    assert!(
        !Command::new(binary())
            .args(["check-transforms", "--crypto-config"])
            .arg(&config)
            .arg("c14n")
            .status()
            .unwrap()
            .success()
    );
}
