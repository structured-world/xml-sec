use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use rsa::{
    RsaPrivateKey,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _},
};
use xml_sec::{
    c14n::{C14nAlgorithm, C14nMode},
    xmldsig::{
        DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
        SignatureBuilder, Transform, XPathExpression, XPathHereSemantics,
    },
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

fn signature_template_without_key_info() -> &'static str {
    r##"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#object"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>
</SignedInfo>
<SignatureValue/>
<Object Id="object">payload</Object>
</Signature>"##
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
fn short_command_help_alias_reaches_process_dispatch() {
    // Parsing an alias is insufficient if command validation later rejects its
    // canonical option, so exercise the complete process route for donor `-h`.
    let output = Command::new(binary())
        .args(["verify", "-h"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Usage:"));
}

#[test]
fn verifies_libxmlsec_legacy_here_semantics_through_process_api() {
    // The expression selects different nodes under specification and libxmlsec
    // semantics, so process success proves the CLI policy reaches transforms.
    let temp = tempfile::tempdir().unwrap();
    let signed_path = temp.path().join("legacy-here.xml");
    let private_key =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .unwrap();
    let key = RsaSigningKey::from_pkcs8_pem(&private_key).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::XPath(XPathExpression::new(
                "count(. | here()) = 1",
            ))),
    );
    let signed = SignContext::new(&key)
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .sign_with_builder("<root><payload>legacy here</payload></root>", &builder)
        .unwrap();
    fs::write(&signed_path, signed).unwrap();

    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let verify = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(public_key)
        .arg(signed_path)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn named_public_key_obeys_signature_key_name_unless_lax() {
    // Named direct keys participate in the same strict KeyName contract as a
    // key manager; --lax-key-search is the explicit compatibility escape hatch.
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
    assert!(sign.status.success());

    let strict = Command::new(binary())
        .args(["verify", "--pubkey-pem:wrong"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("KeyName"));

    let lax = Command::new(binary())
        .args(["verify", "--lax-key-search", "--pubkey-pem:wrong"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );
}

#[test]
fn named_verification_certificate_obeys_signature_key_name_unless_lax() {
    // Explicit certificates are pinned verification identities, so naming one
    // must use the same strict lookup contract as naming a raw public key.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let certificate_der = temp.path().join("certificate.der");
    let certificate_pem = fs::read(&certificate).unwrap();
    let (_, certificate_contents) = x509_parser::pem::parse_x509_pem(&certificate_pem).unwrap();
    fs::write(&certificate_der, certificate_contents.contents).unwrap();
    let signed = temp.path().join("signed.xml");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(sign.status.success());

    for (option, path) in [
        ("pubkey-cert-pem", certificate.as_path()),
        ("pubkey-cert-der", certificate_der.as_path()),
    ] {
        let matching = Command::new(binary())
            .args(["verify", &format!("--{option}:TestKeyName-rsa-2048")])
            .arg(path)
            .arg(&signed)
            .output()
            .unwrap();
        assert!(
            matching.status.success(),
            "{}",
            String::from_utf8_lossy(&matching.stderr)
        );

        let strict = Command::new(binary())
            .args(["verify", &format!("--{option}:wrong")])
            .arg(path)
            .arg(&signed)
            .output()
            .unwrap();
        assert!(!strict.status.success());
        assert!(String::from_utf8_lossy(&strict.stderr).contains("KeyName"));

        let lax = Command::new(binary())
            .args(["verify", "--lax-key-search", &format!("--{option}:wrong")])
            .arg(path)
            .arg(&signed)
            .output()
            .unwrap();
        assert!(
            lax.status.success(),
            "{}",
            String::from_utf8_lossy(&lax.stderr)
        );
    }
}

#[test]
fn verification_reads_the_conventional_stdin_marker() {
    // A lone dash is input data, not an option name; this is the process-level
    // contract used by shell pipelines and the donor CLI.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let signed = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(signed.status.success());

    let mut verify = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    verify
        .stdin
        .take()
        .unwrap()
        .write_all(&signed.stdout)
        .unwrap();
    let output = verify.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn verification_node_id_selects_one_signature_subtree() {
    // libxmlsec1 resolves --node-id to a start node and finds the Signature
    // below it; unrelated signatures elsewhere in the document are ignored.
    let temp = tempfile::tempdir().unwrap();
    let original = fs::read_to_string(
        project_root()
            .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl"),
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let mut signatures = Vec::new();
    for id in ["first", "second"] {
        let template = temp.path().join(format!("{id}.xml"));
        fs::write(
            &template,
            original
                .replace("#object", &format!("#{id}-object"))
                .replace("Id=\"object\"", &format!("Id=\"{id}-object\"")),
        )
        .unwrap();
        let output = Command::new(binary())
            .args(["sign", "--privkey-pem"])
            .arg(&private_key)
            .arg(&template)
            .output()
            .unwrap();
        assert!(output.status.success());
        let signed = String::from_utf8(output.stdout).unwrap();
        let signed = signed
            .split_once("?>")
            .map_or(signed.as_str(), |(_, body)| body)
            .replace(
                "<Signature xmlns=",
                &format!("<Signature Id=\"{id}\" xmlns="),
            );
        signatures.push(signed);
    }
    signatures[1] = signatures[1].replace("some text", "tampered text");
    let document = temp.path().join("multiple.xml");
    fs::write(
        &document,
        format!("<Document>{}{}</Document>", signatures[0], signatures[1]),
    )
    .unwrap();

    let valid = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--node-id", "first"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );

    let invalid = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--node-id", "second"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("signature is invalid"));

    let missing = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--node-id", "missing"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("selected node"));

    let duplicate = temp.path().join("duplicate.xml");
    fs::write(
        &duplicate,
        fs::read_to_string(&document)
            .unwrap()
            .replace("Id=\"second\"", "Id=\"first\""),
    )
    .unwrap();
    let ambiguous = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--node-id", "first"])
        .arg(&duplicate)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous"));
}

#[test]
fn signing_node_id_selects_one_signature_subtree() {
    // The donor treats --node-id as an operation start node. Signing must fill
    // only the Signature below that node while preserving unrelated templates.
    let temp = tempfile::tempdir().unwrap();
    let original = fs::read_to_string(
        project_root()
            .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl"),
    )
    .unwrap();
    let body = original
        .split_once("?>")
        .map_or(original.as_str(), |(_, body)| body);
    let template = temp.path().join("multiple-templates.xml");
    let first = body
        .replace("#object", "#first-object")
        .replace("Id=\"object\"", "Id=\"first-object\"");
    let second = body
        .replace("#object", "#second-object")
        .replace("Id=\"object\"", "Id=\"second-object\"");
    fs::write(
        &template,
        format!(
            "<Document><Envelope Id=\"first\">{first}</Envelope><Envelope Id=\"second\">{second}</Envelope></Document>"
        ),
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");

    let output = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .args(["--node-id", "first"])
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed = String::from_utf8(output.stdout).unwrap();
    let document = roxmltree::Document::parse(&signed).unwrap();
    let values = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureValue")))
        .map(|node| node.text().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(!values[0].trim().is_empty());
    assert!(values[1].trim().is_empty());

    let missing = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .args(["--node-id", "missing"])
        .arg(&template)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing or ambiguous"));

    let duplicate = temp.path().join("duplicate-start.xml");
    fs::write(
        &duplicate,
        fs::read_to_string(&template)
            .unwrap()
            .replace("Id=\"second\"", "Id=\"first\""),
    )
    .unwrap();
    let ambiguous = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .args(["--node-id", "first"])
        .arg(&duplicate)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("missing or ambiguous"));
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
fn encryption_node_id_selects_one_template_subtree() {
    // --node-id selects the operation start node, not EncryptedData/@Id. Both
    // template inspection and replacement must stay within that subtree.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("multiple-templates.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    let encrypted_data = |id: &str| {
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="{id}"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#
        )
    };
    fs::write(
        &template,
        format!(
            "<Document><Envelope Id=\"first\">{}</Envelope><Envelope Id=\"second\">{}</Envelope></Document>",
            encrypted_data("first-template"),
            encrypted_data("second-template")
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"selected payload").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let output = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .args(["--node-id", "first"])
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let encrypted = String::from_utf8(output.stdout).unwrap();
    let document = roxmltree::Document::parse(&encrypted).unwrap();
    let values = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
        .map(|node| node.text().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(!values[0].trim().is_empty());
    assert!(values[1].trim().is_empty());

    let missing = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .args(["--node-id", "missing"])
        .arg(&template)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing or ambiguous"));

    let duplicate = temp.path().join("duplicate-start.xml");
    fs::write(
        &duplicate,
        fs::read_to_string(&template)
            .unwrap()
            .replace("Id=\"second\"", "Id=\"first\""),
    )
    .unwrap();
    let ambiguous = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .args(["--node-id", "first"])
        .arg(&duplicate)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("missing or ambiguous"));
}

#[test]
fn binary_encryption_rejects_xml_typed_templates() {
    // Binary payloads cannot truthfully carry the XML Element or Content type;
    // otherwise decryption routes arbitrary bytes through XML validation.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("typed-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, [0xff, 0x00, 0xfe]).unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let result = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--binary-data"])
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("binary-data"));
}

#[test]
fn encryption_rejects_simultaneous_binary_and_xml_payloads() {
    // Selecting one option by branch order can encrypt the wrong input while
    // reporting success, so payload mode must be an exclusive choice.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let binary_payload = temp.path().join("payload.bin");
    let xml = temp.path().join("payload.xml");
    let key = temp.path().join("content.key");
    let output = temp.path().join("encrypted.xml");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&binary_payload, b"binary payload").unwrap();
    fs::write(&xml, b"<payload>xml payload</payload>").unwrap();
    fs::write(&key, [0x31; 16]).unwrap();

    let result = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(key)
        .args(["--binary-data"])
        .arg(binary_payload)
        .args(["--xml-data"])
        .arg(xml)
        .args(["--output"])
        .arg(&output)
        .arg(template)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("exactly one"));
    assert!(!output.exists());
}

#[test]
fn direct_aes_key_name_must_match_the_template_unless_lax() {
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("named-template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>expected</KeyName></KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, "<secret/>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let strict = Command::new(binary())
        .args(["encrypt", "--aes-key:wrong"])
        .arg(&key)
        .args(["--xml-data"])
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("KeyName"));

    let lax = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--aes-key:wrong"])
        .arg(&key)
        .args(["--xml-data"])
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );
}

#[test]
fn named_aes_decryption_obeys_encrypted_data_key_name_unless_lax() {
    // Decryption key selection must enforce the same document identity contract
    // as encryption rather than discarding the CLI option's registry name.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("named-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>expected</KeyName></KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"named decrypt").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key:expected"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(encrypt.status.success());

    let strict = Command::new(binary())
        .args(["decrypt", "--aes-key:wrong"])
        .arg(&key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("KeyName"));

    let lax = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--aes-key:wrong"])
        .arg(&key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );
    assert_eq!(lax.stdout, b"named decrypt");
}

#[test]
fn standalone_binary_decryption_accepts_its_root_node_id() {
    // --node-id selects an operation start point; selecting the standalone root
    // must not route opaque bytes through XML document replacement validation.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="payload"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, [0xff, 0x00, 0xfe]).unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(encrypt.status.success());

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .args(["--node-id", "payload"])
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, [0xff, 0x00, 0xfe]);

    let missing = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .args(["--node-id", "missing"])
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

#[test]
fn embedded_decryption_node_id_selects_an_operation_subtree() {
    // The selected ID belongs to an ancestor operation node; EncryptedData is
    // intentionally anonymous, matching libxmlsec1's start-node contract.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let encrypted = temp.path().join("encrypted.xml");
    let document = temp.path().join("document.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"<secret>selected subtree</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();
    let encryption = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--xml-data"])
        .arg(&plaintext)
        .args(["--output"])
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(encryption.status.success());
    fs::write(
        &document,
        format!(
            "<Document><Envelope Id=\"selected\">{}</Envelope></Document>",
            fs::read_to_string(&encrypted).unwrap()
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .args(["--node-id", "selected"])
        .arg(&document)
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
            .contains("<Envelope Id=\"selected\"><secret>selected subtree</secret></Envelope>")
    );
}

#[test]
fn rsa_recipient_name_must_match_the_template_unless_lax() {
    // A named RSA key selects the nested EncryptedKey recipient identity, not
    // the direct content-encryption key metadata on EncryptedData.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("named-rsa-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
<ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:KeyName>recipient</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo>
<CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"named recipient").unwrap();

    let matching = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:recipient"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        matching.status.success(),
        "{}",
        String::from_utf8_lossy(&matching.stderr)
    );
    fs::write(&encrypted, &matching.stdout).unwrap();

    let strict = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:wrong"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("KeyName"));

    let lax = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--pubkey-pem:wrong"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );

    let strict_decrypt = Command::new(binary())
        .args(["decrypt", "--privkey-pem:wrong"])
        .arg(&private_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!strict_decrypt.status.success());
    assert!(String::from_utf8_lossy(&strict_decrypt.stderr).contains("KeyName"));

    let lax_decrypt = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--privkey-pem:wrong"])
        .arg(&private_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        lax_decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&lax_decrypt.stderr)
    );
    assert_eq!(lax_decrypt.stdout, b"named recipient");
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
fn encrypts_with_rsa_recipient_certificates() {
    // Donor certificate options extract the recipient public key from either
    // PEM or DER X.509 input and feed the same RSA-OAEP encryption path.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate_pem = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let certificate_der = temp.path().join("certificate.der");
    let pem = fs::read(&certificate_pem).unwrap();
    let (_, certificate) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
    fs::write(&certificate_der, certificate.contents).unwrap();
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"certificate recipient").unwrap();

    for (option, certificate) in [
        ("--pubkey-cert-pem", certificate_pem.as_path()),
        ("--pubkey-cert-der", certificate_der.as_path()),
    ] {
        let encrypted = temp.path().join(format!("{option}.xml"));
        let encryption = Command::new(binary())
            .args(["encrypt", option])
            .arg(certificate)
            .args(["--binary-data"])
            .arg(&plaintext)
            .args(["--output"])
            .arg(&encrypted)
            .arg(&template)
            .output()
            .unwrap();
        assert!(
            encryption.status.success(),
            "{option}: {}",
            String::from_utf8_lossy(&encryption.stderr)
        );

        let decryption = Command::new(binary())
            .args(["decrypt", "--privkey-pem"])
            .arg(&private_key)
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            decryption.status.success(),
            "{option}: {}",
            String::from_utf8_lossy(&decryption.stderr)
        );
        assert_eq!(decryption.stdout, b"certificate recipient");
    }
}

#[test]
fn rsa_decryption_accepts_private_key_certificate_companions() {
    // libxmlsec private-key options permit certificate companions after the
    // key path; decryption consumes the key while retaining that syntax.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"certificate companion").unwrap();
    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(encrypt.status.success());

    let compound = format!("{},{}", private_key.display(), certificate.display());
    let decrypt = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(compound)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"certificate companion");

    let malformed = temp.path().join("malformed.pem");
    fs::write(&malformed, "not a certificate").unwrap();
    let malformed_compound = format!("{},{}", private_key.display(), malformed.display());
    let rejected = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(malformed_compound)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("certificate"));

    let missing_compound = format!(
        "{},{}",
        private_key.display(),
        temp.path().join("missing.pem").display()
    );
    let missing = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(missing_compound)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing.pem"));
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
    let created = temp.path().join("created.xml");
    let create = Command::new(binary())
        .args(["keys", "--gen-key:private", "aes-128"])
        .arg(&created)
        .output()
        .unwrap();
    assert!(create.status.success());
    assert_eq!(
        fs::metadata(&created).unwrap().permissions().mode() & 0o777,
        0o600
    );

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
fn signing_embeds_every_certificate_from_the_private_key_option() {
    // libxmlsec1 treats every comma-separated path after the private key as a
    // certificate to embed, so recipients can reconstruct the supplied chain.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let leaf = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let issuer = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let signed = temp.path().join("signed.xml");
    let compound = format!(
        "{},{},{}",
        private_key.display(),
        leaf.display(),
        issuer.display()
    );

    let result = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
        .args(["--output"])
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let xml = fs::read_to_string(signed).unwrap();
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(
        document
            .descendants()
            .filter(
                |node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))
            )
            .count(),
        2
    );
}

#[test]
fn signing_rejects_a_malformed_secondary_certificate() {
    // Every certificate path is parsed before signing; a malformed trailing
    // chain member must not be silently omitted from the emitted KeyInfo.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let leaf = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let malformed = temp.path().join("malformed.pem");
    fs::write(&malformed, "not a certificate").unwrap();
    let compound = format!(
        "{},{},{}",
        private_key.display(),
        leaf.display(),
        malformed.display()
    );

    let result = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid PEM certificate"));
}

#[test]
fn signing_with_certificate_companions_does_not_require_key_info() {
    // Certificate companions are always validated, but optional output metadata
    // must only be written when the signature template provides its placeholder.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("without-key-info.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    fs::write(&template, signature_template_without_key_info()).unwrap();
    let compound = format!("{},{}", private_key.display(), certificate.display());

    let result = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let signed = String::from_utf8(result.stdout).unwrap();
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<KeyInfo"));

    let malformed = temp.path().join("malformed.pem");
    fs::write(&malformed, "not a certificate").unwrap();
    let malformed_compound = format!("{},{}", private_key.display(), malformed.display());
    let rejected = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(malformed_compound)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("certificate"));
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

#[test]
fn singleton_named_signing_key_obeys_template_key_name() {
    // Naming one key enables strict KeyName lookup even when the key set has a
    // single entry; lax lookup is the explicit donor-compatible escape hatch.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");

    let strict = Command::new(binary())
        .args(["sign", "--privkey-pem:unexpected"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("unknown KeyName"));

    let lax = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:unexpected"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );
}

#[test]
fn singleton_named_signing_key_reports_missing_template_key_name() {
    // A registry-named signing key without a template lookup name is a distinct
    // failure from ambiguity among multiple keys and must report that contract.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("without-key-info.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(&template, signature_template_without_key_info()).unwrap();

    let result = Command::new(binary())
        .args(["sign", "--privkey-pem:named"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("named private key requires a template KeyName"));
    assert!(!stderr.contains("multiple private keys"));
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
    let key_lengths = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.aleksey.com/xmlsec/2002", "AESKeyValue")))
        .map(|node| {
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                node.text().unwrap(),
            )
            .unwrap()
            .len()
        })
        .collect::<Vec<_>>();
    assert_eq!(key_lengths, [16, 32]);
}

#[test]
fn capability_queries_report_supported_and_unsupported_names() {
    assert!(
        Command::new(binary())
            .args(["check-transforms", "c14n", "rsa-sha256"])
            .status()
            .unwrap()
            .success()
    );
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
    assert!(
        !Command::new(binary())
            .args(["check-transforms", "xslt"])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn conflicting_verification_keys_fail_before_input_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let malformed = temp.path().join("malformed.xml");
    fs::write(&malformed, "<Signature>").unwrap();
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
}

#[test]
fn foreign_encryption_namespace_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let malformed = temp.path().join("malformed.xml");
    let foreign_template = temp.path().join("foreign-template.xml");
    fs::write(&malformed, "<Signature>").unwrap();
    fs::write(
        &foreign_template,
        "<EncryptedData xmlns=\"urn:not-xmlenc\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><CipherData><CipherValue/></CipherData></EncryptedData>",
    )
    .unwrap();
    let foreign = Command::new(binary())
        .args(["encrypt", "--aeskey", "missing.key", "--binary-data"])
        .arg(&malformed)
        .arg(&foreign_template)
        .output()
        .unwrap();
    assert!(!foreign.status.success());
    assert!(String::from_utf8_lossy(&foreign.stderr).contains("no EncryptedData"));
}

#[test]
fn parser_input_and_output_failures_are_nonzero() {
    let temp = tempfile::tempdir().unwrap();
    let malformed = temp.path().join("malformed.xml");
    fs::write(&malformed, "<Signature>").unwrap();
    assert_eq!(
        Command::new(binary())
            .arg("unknown-command")
            .status()
            .unwrap()
            .code(),
        Some(1)
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

#[test]
fn nonempty_crypto_config_is_rejected_with_the_expected_diagnostic() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("crypto-config");
    fs::create_dir(&config).unwrap();
    fs::write(config.join("backend.conf"), "unsupported").unwrap();
    let output = Command::new(binary())
        .args(["check-transforms", "--crypto-config"])
        .arg(&config)
        .arg("c14n")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported option for this command: --crypto-config")
    );
}
