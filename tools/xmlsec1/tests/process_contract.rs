use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use base64::Engine as _;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{
        DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
    },
    traits::PublicKeyParts as _,
};
use x509_parser::{extensions::ParsedExtension, prelude::FromDer as _};
use xml_sec::{
    c14n::{C14nAlgorithm, C14nMode},
    policy::{EncryptionPolicy, VerificationPolicy},
    provider::default_provider,
    xmldsig::{
        DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
        SignatureBuilder, Transform, XPathExpression, mutation::append_signature_to_root,
    },
    xmlenc::{
        DataEncryptionAlgorithm, EncryptedDataBuilder, EncryptionRecipient, KeyCandidateBudget,
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

fn ecdsa_signature_template() -> &'static str {
    r##"<root><payload ID="payload">payload</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
<Reference URI="#payload"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>
</SignedInfo>
<SignatureValue/>
</Signature></root>"##
}

fn visa3d_signature_template() -> &'static str {
    r##"<root><payload ID="visa'3d">payload</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#visa'3d"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>
</SignedInfo>
<SignatureValue/>
</Signature></root>"##
}

fn signature_template_with_key_info(key_info: &str) -> String {
    signature_template_without_key_info()
        .replacen(
            "<Signature ",
            "<Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" ",
            1,
        )
        .replace(
            "<SignatureValue/>",
            &format!("<SignatureValue/><KeyInfo>{key_info}</KeyInfo>"),
        )
}

fn rsa_key_value_with_leading_zeroes(
    public_key: &RsaPublicKey,
    modulus_zeroes: usize,
    exponent_zeroes: usize,
) -> String {
    let base64 = &base64::engine::general_purpose::STANDARD;
    let mut modulus = vec![0; modulus_zeroes];
    modulus.extend(public_key.n().to_be_bytes_trimmed_vartime());
    let mut exponent = vec![0; exponent_zeroes];
    exponent.extend(public_key.e().to_be_bytes_trimmed_vartime());
    format!(
        "<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>",
        base64.encode(modulus),
        base64.encode(exponent)
    )
}

fn der_encoded_key_value(public_key: &RsaPublicKey) -> String {
    let der = public_key
        .to_public_key_der()
        .expect("fixture public key must encode as SPKI");
    format!(
        "<dsig11:DEREncodedKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">{}</dsig11:DEREncodedKeyValue>",
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    )
}

fn x509_certificate_value(path: &Path) -> String {
    let (_, pem) = x509_parser::pem::parse_x509_pem(&fs::read(path).unwrap()).unwrap();
    format!(
        "<ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data>",
        base64::engine::general_purpose::STANDARD.encode(pem.contents)
    )
}

fn pem_der_base64(path: &Path) -> String {
    let (_, pem) = x509_parser::pem::parse_x509_pem(&fs::read(path).unwrap()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(pem.contents)
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
fn cli_asn1_signature_mode_requires_the_explicit_donor_flag() {
    // The compatibility option controls both emitted and accepted framing;
    // standards-default verification must not auto-detect DER.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("ecdsa-template.xml");
    let signed = temp.path().join("ecdsa-signed.xml");
    fs::write(&template, ecdsa_signature_template()).unwrap();
    let private_key = project_root().join("tests/fixtures/keys/ec/ec-prime256v1-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");

    let sign = Command::new(binary())
        .args(["sign", "--enable-asn1-signatures-hack", "--privkey-pem"])
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

    let signed_xml = fs::read_to_string(&signed).unwrap();
    let document = roxmltree::Document::parse(&signed_xml).unwrap();
    let encoded = document
        .descendants()
        .find(|node| node.has_tag_name("SignatureValue"))
        .and_then(|node| node.text())
        .unwrap();
    let signature = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert_eq!(signature.first(), Some(&0x30));
    assert_ne!(signature.len(), 64);

    let rejected = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid ECDSA signature encoding"));

    let accepted = Command::new(binary())
        .args(["verify", "--enable-asn1-signatures-hack", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
}

#[test]
fn cli_visa3d_mode_bypasses_xpointer_for_registered_ids() {
    // The apostrophe makes libxmlsec1's default xpointer(id('...')) wrapper
    // invalid. Visa3D mode performs direct registered-ID lookup instead.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("visa3d-template.xml");
    let signed = temp.path().join("visa3d-signed.xml");
    fs::write(&template, visa3d_signature_template()).unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

    let rejected = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        rejected_stderr.contains("unsupported URI: #visa'3d"),
        "unexpected standards-mode diagnostic: {rejected_stderr}"
    );

    let sign = Command::new(binary())
        .args(["sign", "--enable-visa3d-hack", "--privkey-pem"])
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

    let default_verify = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(!default_verify.status.success());

    let compatible_verify = Command::new(binary())
        .args(["verify", "--enable-visa3d-hack", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        compatible_verify.status.success(),
        "{}",
        String::from_utf8_lossy(&compatible_verify.stderr)
    );
}

#[test]
fn signing_rejects_preserved_key_info_for_another_key() {
    // A successful signature must not retain a cryptographic identity that
    // directs ordinary KeyInfo resolution to a different public key.
    let temp = tempfile::tempdir().unwrap();
    let source = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let template = temp.path().join("stale-key-info.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let stale_public = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"))
            .unwrap(),
    )
    .unwrap();
    let identities = [
        rsa_key_value_with_leading_zeroes(&stale_public, 0, 0).replace("ds:", ""),
        der_encoded_key_value(&stale_public),
        x509_certificate_value(
            &project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        )
        .replace("ds:", ""),
        "<KeyValue><ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</PublicKey></ECKeyValue></KeyValue>".into(),
    ];
    let source_xml = fs::read_to_string(source).unwrap();
    for (index, identity) in identities.iter().enumerate() {
        fs::write(&template, source_xml.replace("<X509Data/>", identity)).unwrap();
        let output = Command::new(binary())
            .args(["sign", "--privkey-pem:TestKeyName-rsa-2048"])
            .arg(&private_key)
            .arg(&template)
            .output()
            .unwrap();
        assert!(!output.status.success(), "identity {index} was accepted");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("does not match the selected signing key"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let matching_public = RsaPublicKey::from(
        &RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(&private_key).unwrap()).unwrap(),
    );
    fs::write(
        &template,
        source_xml.replace(
            "<X509Data/>",
            &rsa_key_value_with_leading_zeroes(&matching_public, 0, 0).replace("ds:", ""),
        ),
    )
    .unwrap();
    let matching = Command::new(binary())
        .args(["sign", "--privkey-pem:TestKeyName-rsa-2048"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        matching.status.success(),
        "{}",
        String::from_utf8_lossy(&matching.stderr)
    );
}

#[test]
fn direct_public_key_verification_rejects_invalid_trust_inputs() {
    // Explicit trust inputs are configuration, not optional resolver hints:
    // validate them even when a raw public key verifies the signature.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let malformed_trust = temp.path().join("malformed-trust.pem");
    let signed = temp.path().join("signed.xml");
    fs::write(&malformed_trust, b"not a certificate").unwrap();

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
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
        .arg("--trusted-pem")
        .arg(&malformed_trust)
        .arg(&signed)
        .output()
        .unwrap();

    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("certificate"));
}

#[test]
fn verification_without_a_selector_uses_the_first_signature() {
    // libxmlsec1 treats the document root as the operation start node and verifies
    // its first descendant Signature rather than imposing global cardinality.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("multiple-signatures.xml");
    let signed = temp.path().join("signed.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        format!(
            "<root>{}<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/></root>",
            signature_template_without_key_info()
        ),
    )
    .unwrap();

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
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
}

#[test]
fn binary_encryption_round_trips_a_custom_type_uri() {
    // Custom Type URIs classify opaque application data, so binary mode must
    // preserve the URI and reciprocal decryption must return the original bytes.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("custom-type.xml");
    let plaintext = temp.path().join("payload.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let key = temp.path().join("content.key");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="urn:example:opaque"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"opaque application bytes").unwrap();
    fs::write(&key, [0x57_u8; 16]).unwrap();

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
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .contains("Type=\"urn:example:opaque\"")
    );

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"opaque application bytes");
}

#[test]
fn lax_signing_preserves_order_across_private_key_option_kinds() {
    // The first compatible key is determined by CLI occurrence order, not by
    // the PEM/DER spelling used to supply it.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let first_pem =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem"))
            .unwrap();
    let first = RsaPrivateKey::from_pkcs8_pem(&first_pem).unwrap();
    let first_der = temp.path().join("first.der");
    fs::write(&first_der, first.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let second = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let first_public = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let signed = temp.path().join("signed.xml");

    let sign = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-der"])
        .arg(&first_der)
        .arg("--privkey-pem")
        .arg(&second)
        .arg("--output")
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
        .arg(&first_public)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn signing_writes_requested_diagnostics_separately_from_output() {
    // Diagnostic flags describe the completed signing context; the signed XML
    // remains exclusively in --output so shell callers can consume both streams.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");

    for (flag, expected) in [
        ("--print-debug", "Status: succeeded"),
        ("--print-xml-debug", "<SignatureContext"),
    ] {
        let signed = temp.path().join(format!("signed-{flag}.xml"));
        let output = Command::new(binary())
            .args(["sign", flag, "--privkey-pem"])
            .arg(&private_key)
            .arg("--output")
            .arg(&signed)
            .arg(&template)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::read_to_string(&signed)
                .unwrap()
                .contains("SignatureValue")
        );
        let diagnostics = String::from_utf8(output.stdout).unwrap();
        assert!(diagnostics.contains(expected), "{diagnostics}");
        if flag == "--print-xml-debug" {
            let document = roxmltree::Document::parse(&diagnostics)
                .expect("signing XML diagnostics must be well-formed");
            assert_eq!(
                document.root_element().attribute("status"),
                Some("SUCCEEDED")
            );
        }
    }
}

#[test]
fn debug_options_are_rejected_for_non_crypto_commands() {
    // Diagnostic contexts exist only for DSig and XMLEnc operations. Accepting
    // the flags on keys would silently discard a recognized caller request.
    let output = Command::new(binary())
        .args(["keys", "--print-debug", "--gen-key:test", "aes-128"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "option --print-debug is recognized but is not applicable to the keys command"
        ),
        "{stderr}"
    );
}

#[test]
fn signing_without_output_preserves_donor_stdout_order() {
    // libxmlsec1 multiplexes a stdout result and requested debug context when
    // --output is absent; preserve the result-first order for drop-in callers.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let output = Command::new(binary())
        .args(["sign", "--print-debug", "--privkey-pem"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let diagnostics = stdout
        .find("== Signature Context")
        .expect("debug context must follow the signed result");
    let signed_xml = stdout[..diagnostics].trim_end();
    let document = roxmltree::Document::parse(signed_xml)
        .expect("the result prefix before diagnostics must remain valid XML");
    assert_eq!(document.root_element().tag_name().name(), "Signature");
    assert!(stdout[diagnostics..].contains("Status: succeeded"));
}

#[test]
fn scoped_id_attribute_selects_and_signs_the_registered_element() {
    // An unqualified libxmlsec1 --id-attr element name is namespace-agnostic;
    // the custom attribute must drive selection and Reference resolution.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("scoped-id.xml");
    let signed = temp.path().join("scoped-id-signed.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r##"<root xmlns:app="urn:application"><app:Envelope Token="selected"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#selected"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature><payload>registered</payload></app:Envelope></root>"##,
    )
    .unwrap();

    let sign = Command::new(binary())
        .args([
            "sign",
            "--id-attr:Token",
            "Envelope",
            "--node-id",
            "selected",
        ])
        .args(["--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
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
        .args([
            "verify",
            "--id-attr:Token",
            "Envelope",
            "--node-id",
            "selected",
        ])
        .arg("--pubkey-pem")
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let wrong_element = Command::new(binary())
        .args(["sign", "--id-attr:Token", "Other", "--node-id", "selected"])
        .arg("--privkey-pem")
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!wrong_element.status.success());
    assert!(String::from_utf8_lossy(&wrong_element.stderr).contains("missing or ambiguous"));
}

#[test]
fn xml_debug_verification_output_matches_the_donor_xml_contract() {
    // The upstream runner parses --print-xml-debug output with xmllint, so the
    // diagnostic mode must not share the plain-text debug renderer.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
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

    let verify = Command::new(binary())
        .args(["verify", "--print-xml-debug", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let debug_xml = String::from_utf8(verify.stdout).unwrap();
    let document = roxmltree::Document::parse(&debug_xml).expect("debug output must be XML");
    let root = document.root_element();
    assert_eq!(root.tag_name().name(), "VerificationContext");
    assert_eq!(root.attribute("status"), Some("OK"));
    assert_eq!(root.attribute("failureReason"), Some("UNKNOWN"));

    let tampered = temp.path().join("tampered.xml");
    fs::write(
        &tampered,
        fs::read_to_string(&signed)
            .unwrap()
            .replace("some text", "tampered text"),
    )
    .unwrap();
    let invalid = Command::new(binary())
        .args(["verify", "--print-xml-debug", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&tampered)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let invalid_xml = String::from_utf8(invalid.stdout).unwrap();
    let invalid_document =
        roxmltree::Document::parse(&invalid_xml).expect("invalid debug output must still be XML");
    let invalid_root = invalid_document.root_element();
    assert_eq!(invalid_root.attribute("status"), Some("FAILED"));
    assert_eq!(invalid_root.attribute("failureReason"), Some("REFERENCE"));
}

#[test]
fn xml_debug_reports_authenticated_manifest_reference_failure_at_the_root() {
    // A Manifest digest failure invalidates the CLI operation even when the
    // outer SignedInfo and SignatureValue remain cryptographically valid.
    let temp = tempfile::tempdir().unwrap();
    let private_key_pem =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .unwrap();
    let private_key = RsaSigningKey::from_pkcs8_pem(&private_key_pem).unwrap();
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let digest_probe = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#manifest-payload")
                .transform(Transform::C14n(c14n.clone())),
        );
    let probe = SignContext::new(&private_key)
        .sign_with_builder(
            "<root><payload Id=\"manifest-payload\">original</payload></root>",
            &digest_probe,
        )
        .unwrap();
    let probe_document = roxmltree::Document::parse(&probe).unwrap();
    let manifest_digest = probe_document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "DigestValue")))
        .and_then(|node| node.text())
        .unwrap();
    let template = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#manifest")
                .transform(Transform::C14n(c14n)),
        )
        .build_template()
        .unwrap()
        .replace(
            "</Signature>",
            &format!(
                "<Object><Manifest Id=\"manifest\"><Reference URI=\"#manifest-payload\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>{manifest_digest}</DigestValue></Reference></Manifest></Object></Signature>"
            ),
        );
    let unsigned = append_signature_to_root(
        "<root><payload Id=\"manifest-payload\">original</payload></root>",
        &template,
    )
    .unwrap();
    let signed = SignContext::new(&private_key)
        .sign_template(&unsigned)
        .unwrap();
    let tampered = temp.path().join("manifest-tampered.xml");
    fs::write(&tampered, signed.replace(">original<", ">tampered<")).unwrap();

    let output = Command::new(binary())
        .args(["verify", "--print-xml-debug", "--pubkey-pem"])
        .arg(&public_key)
        .arg(&tampered)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let diagnostics = String::from_utf8(output.stdout).unwrap();
    let document = roxmltree::Document::parse(&diagnostics).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("status"), Some("FAILED"));
    assert_eq!(root.attribute("failureReason"), Some("REFERENCE"));
    let signed_info_statuses = root
        .children()
        .find(|node| node.has_tag_name("SignedInfoReferences"))
        .expect("SignedInfo diagnostics")
        .children()
        .filter(|node| node.has_tag_name("ReferenceVerificationContext"))
        .filter_map(|node| node.attribute("status"))
        .collect::<Vec<_>>();
    let manifest_statuses = root
        .children()
        .find(|node| node.has_tag_name("ManifestReferences"))
        .expect("Manifest diagnostics")
        .children()
        .filter(|node| node.has_tag_name("ReferenceVerificationContext"))
        .filter_map(|node| node.attribute("status"))
        .collect::<Vec<_>>();
    assert_eq!(signed_info_statuses, ["OK"]);
    assert_eq!(manifest_statuses, ["FAILED"]);
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
fn donor_help_command_targets_one_runtime_command() {
    // libxmlsec1 accepts help-<cmd>, not topic aliases such as help-dsig.
    let output = Command::new(binary()).arg("help-sign").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Usage: xmlsec1 sign"));

    let output = Command::new(binary()).arg("help-dsig").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown command"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Usage: xmlsec1 sign"));

    for command in ["---h", "---?"] {
        let output = Command::new(binary()).arg(command).output().unwrap();
        assert!(!output.status.success(), "unexpectedly accepted {command}");
    }
}

#[test]
fn signs_and_verifies_libxmlsec_legacy_here_semantics_through_process_api() {
    // The expression selects different nodes under specification and libxmlsec
    // semantics, so this round trip proves both CLI policies reach transforms.
    let temp = tempfile::tempdir().unwrap();
    let template_path = temp.path().join("legacy-here-template.xml");
    let signed_path = temp.path().join("legacy-here.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
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
    let template = append_signature_to_root(
        "<root><payload>legacy here</payload></root>",
        &builder.build_template().unwrap(),
    )
    .unwrap();
    fs::write(&template_path, template).unwrap();

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
        .arg(&signed_path)
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

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
fn lax_verification_searches_past_incompatible_key_types() {
    // Lax lookup relaxes KeyName matching, but it must still search by the
    // signature algorithm instead of treating the first registry entry as final.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-ecdsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/ec/ec-prime256v1-key.pem");
    let rsa_public_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let ec_public_key = project_root().join("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");
    let signed = temp.path().join("signed.xml");

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
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
        .args(["verify", "--lax-key-search", "--pubkey-pem:rsa"])
        .arg(&rsa_public_key)
        .arg("--pubkey-pem:ec")
        .arg(&ec_public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn lax_verification_does_not_recover_from_aggregate_material_exhaustion() {
    // Lax search may skip malformed key candidates, but it must not turn the
    // invocation-wide 32 MiB material ceiling into a per-candidate limit.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let signed = temp.path().join("signed.xml");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg("--output")
        .arg(&signed)
        .arg(template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let mut malformed = Vec::new();
    for (index, size) in [8, 8, 8, 1, 8].into_iter().enumerate() {
        let path = temp.path().join(format!("malformed-{index}.pem"));
        fs::File::create(&path)
            .unwrap()
            .set_len(size * 1024 * 1024)
            .unwrap();
        malformed.push(path);
    }
    let mut verify = Command::new(binary());
    verify.args(["verify", "--lax-key-search"]);
    for (index, path) in malformed.iter().enumerate() {
        verify.arg(format!("--pubkey-pem:malformed-{index}"));
        verify.arg(path);
    }
    let output = verify
        .arg("--pubkey-pem:valid")
        .arg(public_key)
        .arg(signed)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("configured external key/certificate material exceeds policy limit")
    );
}

#[test]
fn strict_verification_searches_each_distinct_template_key_name() {
    // Separate KeyNames identify separate key-manager entries. A unique match
    // for each name is a search order, not an ambiguity across the whole set.
    let temp = tempfile::tempdir().unwrap();
    let source_template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let template_path = temp.path().join("template.xml");
    let signed_path = temp.path().join("signed.xml");
    let template = fs::read_to_string(source_template).unwrap().replace(
        "<KeyName>TestKeyName-rsa-2048</KeyName>",
        "<KeyName>wrong</KeyName><KeyName>valid</KeyName>",
    );
    fs::write(&template_path, template).unwrap();

    let valid_private = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let wrong_public = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let valid_public = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(valid_private)
        .arg("--output")
        .arg(&signed_path)
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let verify = Command::new(binary())
        .args(["verify", "--pubkey-pem:wrong"])
        .arg(wrong_public)
        .arg("--pubkey-pem:valid")
        .arg(valid_public)
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
fn strict_verification_rejects_a_selected_key_load_failure() {
    // Every strict named option is explicit configuration and must load. Lax
    // search alone may skip an unreadable candidate and continue to a valid key.
    let temp = tempfile::tempdir().unwrap();
    let source_template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let template_path = temp.path().join("template.xml");
    let signed_path = temp.path().join("signed.xml");
    let missing_key = temp.path().join("missing-public-key.pem");
    let template = fs::read_to_string(source_template).unwrap().replace(
        "<KeyName>TestKeyName-rsa-2048</KeyName>",
        "<KeyName>missing</KeyName><KeyName>valid</KeyName>",
    );
    fs::write(&template_path, template).unwrap();

    let valid_private = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let valid_public = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(valid_private)
        .arg("--output")
        .arg(&signed_path)
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let verify = |lax: bool| {
        let mut command = Command::new(binary());
        command.arg("verify");
        if lax {
            command.arg("--lax-key-search");
        }
        command
            .arg("--pubkey-pem:missing")
            .arg(&missing_key)
            .arg("--pubkey-pem:valid")
            .arg(&valid_public)
            .arg(&signed_path)
            .output()
            .unwrap()
    };

    let strict = verify(false);
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("missing-public-key.pem"));

    let lax = verify(true);
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );

    let incompatible_certificate =
        project_root().join("tests/fixtures/keys/ec/ec-prime256v1-cert.pem");
    let verify_certificate = |lax: bool| {
        let mut command = Command::new(binary());
        command.arg("verify");
        if lax {
            command.arg("--lax-key-search");
        }
        command
            .arg("--pubkey-cert-pem:missing")
            .arg(&incompatible_certificate)
            .arg("--pubkey-pem:valid")
            .arg(&valid_public)
            .arg(&signed_path)
            .output()
            .unwrap()
    };

    let strict_certificate = verify_certificate(false);
    assert!(!strict_certificate.status.success());
    let lax_certificate = verify_certificate(true);
    assert!(
        lax_certificate.status.success(),
        "{}",
        String::from_utf8_lossy(&lax_certificate.stderr)
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
fn pinned_verification_certificate_ignores_crls_without_trust_anchors() {
    // CRL processing belongs to path validation. A caller-pinned certificate
    // without separate anchors remains a direct verification key even when a
    // generic compatibility invocation also supplies --verify-crls.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let signed = temp.path().join("signed.xml");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg("--output")
        .arg(&signed)
        .arg(template)
        .output()
        .unwrap();
    assert!(sign.status.success());

    let verify = Command::new(binary())
        .args(["verify", "--verify-crls", "--pubkey-cert-pem"])
        .arg(certificate)
        .arg(signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn asymmetric_option_names_enforce_their_declared_encoding() {
    // Automation must fail closed when a PEM file is wired to a DER option;
    // accepting it would make the public xmlsec1 option contract misleading.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");

    let rejected_sign = Command::new(binary())
        .args(["sign", "--privkey-der"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected_sign.status.success());

    let signed = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(signed.status.success());
    let temp = tempfile::tempdir().unwrap();
    let signed_path = temp.path().join("signed.xml");
    fs::write(&signed_path, signed.stdout).unwrap();

    for (option, path) in [
        ("pubkey-der", public_key.as_path()),
        ("pubkey-cert-der", certificate.as_path()),
    ] {
        let rejected = Command::new(binary())
            .args(["verify", &format!("--{option}")])
            .arg(path)
            .arg(&signed_path)
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "unexpectedly accepted --{option}"
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
fn verification_reports_output_as_inapplicable() {
    // Verification produces status and diagnostics, not a transformed document;
    // reject the shared donor option with a command-specific diagnostic.
    let output = Command::new(binary())
        .args(["verify", "--output", "unused.xml", "input.xml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Error: option --output is recognized but is not applicable to the verify command\n"
    );
}

#[test]
fn signing_processes_manifests_unless_explicitly_ignored() {
    // libxmlsec1 fills direct Object/Manifest references before SignedInfo;
    // --ignore-manifests is the explicit opt-out, not an accepted no-op.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("manifest-template.xml");
    fs::write(
        &template,
        r##"<root><payload Id="payload">manifest payload</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#manifest"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="manifest"><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>stale</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##,
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let sign = |ignore: bool| {
        let mut command = Command::new(binary());
        command.arg("sign");
        if ignore {
            command.arg("--ignore-manifests");
        }
        command
            .arg("--privkey-pem")
            .arg(&private_key)
            .arg(&template)
            .output()
            .unwrap()
    };

    let processed = sign(false);
    assert!(
        processed.status.success(),
        "{}",
        String::from_utf8_lossy(&processed.stderr)
    );
    assert!(!String::from_utf8_lossy(&processed.stdout).contains(">stale</ds:DigestValue>"));

    let ignored = sign(true);
    assert!(
        ignored.status.success(),
        "{}",
        String::from_utf8_lossy(&ignored.stderr)
    );
    assert!(String::from_utf8_lossy(&ignored.stdout).contains(">stale</ds:DigestValue>"));
}

#[test]
fn ignore_manifests_preserves_signed_info_dependency_checks() {
    // The CLI flag opts out of Manifest traversal, not the dependency safety
    // required to keep SignedInfo references valid after SignatureValue fill.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("signature-value-cycle.xml");
    fs::write(
        &template,
        r##"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##,
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");

    let output = Command::new(binary())
        .args(["sign", "--ignore-manifests", "--privkey-pem"])
        .arg(private_key)
        .arg(template)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SignatureValue") && stderr.contains("cycle"),
        "{stderr}"
    );
}

#[test]
fn signing_processes_nested_manifests_in_dependency_order() {
    // The process API must expose the same dependency-aware Manifest pipeline
    // as SignContext rather than emitting a signature with a stale outer digest.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("nested-manifest-template.xml");
    let signed = temp.path().join("nested-manifest-signed.xml");
    fs::write(
        &template,
        r##"<root><payload Id="payload">nested payload</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#outer"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="outer"><ds:Reference URI="#inner"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest><ds:Manifest Id="inner"><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##,
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");

    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg("--output")
        .arg(&signed)
        .arg(template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let verify = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(public_key)
        .arg(signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn signing_accepts_utf16_xml_and_rejects_malformed_code_units() {
    // XML 1.0 requires UTF-16 support at the byte-oriented process boundary.
    let temp = tempfile::tempdir().unwrap();
    let source = fs::read_to_string(
        project_root()
            .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl"),
    )
    .unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    for (name, bom, encode, declaration) in [
        (
            "le",
            [0xff, 0xfe],
            u16::to_le_bytes as fn(u16) -> [u8; 2],
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
        ),
        (
            "be",
            [0xfe, 0xff],
            u16::to_be_bytes as fn(u16) -> [u8; 2],
            "<?xml version='1.0' encoding='utf-16'?>",
        ),
    ] {
        let path = temp.path().join(format!("template-{name}.xml"));
        let mut bytes = bom.to_vec();
        let declaration_end = source.find("?>").expect("fixture XML declaration") + 2;
        let encoded_source = format!("{declaration}{}", &source[declaration_end..]);
        bytes.extend(encoded_source.encode_utf16().flat_map(encode));
        fs::write(&path, bytes).unwrap();
        let output = Command::new(binary())
            .args(["sign", "--privkey-pem"])
            .arg(&private_key)
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let signed = String::from_utf8(output.stdout).unwrap();
        let declaration_end = signed.find("?>").expect("signed XML declaration") + 2;
        let declaration = &signed[..declaration_end];
        assert!(declaration.contains("UTF-8"), "{name}: {declaration}");
        assert!(!declaration.contains("UTF-16"), "{name}: {declaration}");
        roxmltree::Document::parse(&signed).expect("transcoded output must remain byte-parseable");
    }

    let malformed = temp.path().join("malformed.xml");
    fs::write(&malformed, [0xff, 0xfe, 0x00]).unwrap();
    let output = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg(malformed)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("odd byte length"));
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
        format!(
            "<Document><Envelope Id=\"both\">{}{}</Envelope></Document>",
            signatures[0], signatures[1]
        ),
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

    let first_descendant = Command::new(binary())
        .args(["verify", "--pubkey-pem"])
        .arg(&public_key)
        .args(["--node-id", "both"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        first_descendant.status.success(),
        "{}",
        String::from_utf8_lossy(&first_descendant.stderr)
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
    // The donor performs a depth-first search from the --node-id start node.
    // Signing must fill only the first descendant Signature template.
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
            "<Document><Envelope Id=\"first\">{first}{second}</Envelope><Envelope Id=\"second\"/></Document>"
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
fn signing_without_node_selector_uses_first_signature_template() {
    // Default sign selection follows document order, matching verification and
    // libxmlsec1 rather than unexpectedly targeting the last Signature.
    let temp = tempfile::tempdir().unwrap();
    let body = signature_template_without_key_info();
    let first = body
        .replace("#object", "#first")
        .replace("Id=\"object\"", "Id=\"first\"");
    let second = body
        .replace("#object", "#second")
        .replace("Id=\"object\"", "Id=\"second\"");
    let template = temp.path().join("default-signature-selection.xml");
    fs::write(&template, format!("<Document>{first}{second}</Document>")).unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");

    let output = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
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
        .map(|node| node.text().unwrap_or_default().trim().to_owned())
        .collect::<Vec<_>>();
    assert!(!values[0].is_empty());
    assert!(values[1].is_empty());
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
fn repeated_output_options_fail_before_creating_files() {
    // Canonical and alias spellings identify one donor singleton; accepting
    // both would silently redirect output through last-value wins behavior.
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.xml");
    let second = temp.path().join("second.xml");
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let output = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg("--output")
        .arg(&first)
        .arg("-o")
        .arg(&second)
        .arg(&template)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be repeated"));
    assert!(!first.exists());
    assert!(!second.exists());
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
fn encryption_writes_requested_diagnostics_and_rejects_duplicate_methods() {
    // Encryption diagnostics are a separate stdout contract, and malformed
    // templates must fail before either diagnostics or ciphertext is emitted.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(&plaintext, b"diagnostic payload").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    for (flag, expected) in [
        ("--print-debug", "Status: succeeded"),
        ("--print-xml-debug", "<DataEncryptionContext"),
    ] {
        let template = temp.path().join(format!("template-{flag}.xml"));
        let encrypted = temp.path().join(format!("encrypted-{flag}.xml"));
        fs::write(
            &template,
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
        )
        .unwrap();
        let output = Command::new(binary())
            .args(["encrypt", flag, "--aeskey"])
            .arg(&key)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg("--output")
            .arg(&encrypted)
            .arg(&template)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::read_to_string(&encrypted)
                .unwrap()
                .contains("CipherValue")
        );
        let diagnostics = String::from_utf8(output.stdout).unwrap();
        assert!(diagnostics.contains(expected), "{diagnostics}");
        if flag == "--print-xml-debug" {
            let document = roxmltree::Document::parse(&diagnostics)
                .expect("encryption XML diagnostics must be well-formed");
            assert_eq!(
                document.root_element().attribute("status"),
                Some("replaced")
            );
        }
    }

    let malformed = temp.path().join("duplicate-method.xml");
    let rejected_output = temp.path().join("must-not-exist.xml");
    fs::write(
        &malformed,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    let rejected = Command::new(binary())
        .args(["encrypt", "--aeskey"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&rejected_output)
        .arg(&malformed)
        .output()
        .unwrap();

    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("more than one direct EncryptionMethod")
    );
    assert!(!rejected_output.exists());

    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    for (case, malformed_xml, key_args) in [
        (
            "duplicate-cipher-data",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            None,
        ),
        (
            "key-info-after-cipher-data",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData><ds:KeyInfo><ds:KeyName>late</ds:KeyName></ds:KeyInfo></EncryptedData>"#,
            None,
        ),
        (
            "recipient-without-value",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><CipherData/></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            Some(&public_key),
        ),
        (
            "recipient-cipher-reference",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><CipherData><CipherReference URI="urn:cipher"/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            Some(&public_key),
        ),
    ] {
        let malformed = temp.path().join(format!("{case}.xml"));
        let rejected_output = temp.path().join(format!("{case}-output.xml"));
        fs::write(&malformed, malformed_xml).unwrap();
        let mut command = Command::new(binary());
        command.arg("encrypt");
        if let Some(public_key) = key_args {
            command.arg("--pubkey-pem").arg(public_key);
        } else {
            command.arg("--aeskey").arg(&key);
        }
        let rejected = command
            .arg("--binary-data")
            .arg(&plaintext)
            .arg("--output")
            .arg(&rejected_output)
            .arg(&malformed)
            .output()
            .unwrap();

        assert!(!rejected.status.success(), "{case} unexpectedly succeeded");
        assert!(!rejected_output.exists(), "{case} emitted partial output");
    }
}

#[test]
fn xml_debug_decryption_writes_diagnostics_separately_from_plaintext() {
    // The unmodified donor runner redirects diagnostics from stdout while
    // --output receives the decrypted payload, then parses stdout as XML.
    let temp = tempfile::tempdir().unwrap();
    let fixtures = project_root().join("tools/xmlsec1/tests/fixtures/upstream");
    let vector = fixtures.join("xmlenc11-interop-2012/xenc11-example-AES128-GCM");
    let decrypted = temp.path().join("decrypted.data");

    let text_decrypted = temp.path().join("text-decrypted.data");
    let text_output = Command::new(binary())
        .args(["decrypt", "--print-debug", "--lax-key-search", "--aeskey"])
        .arg(vector.with_extension("key"))
        .arg("--output")
        .arg(&text_decrypted)
        .arg(vector.with_extension("xml"))
        .output()
        .unwrap();
    assert!(
        text_output.status.success(),
        "{}",
        String::from_utf8_lossy(&text_output.stderr)
    );
    assert_eq!(
        fs::read(&text_decrypted).unwrap(),
        fs::read(vector.with_extension("data")).unwrap()
    );
    let text_diagnostics = String::from_utf8(text_output.stdout).unwrap();
    assert!(text_diagnostics.contains("== Data Decryption Context"));
    assert!(text_diagnostics.contains("Status: succeeded"));

    let output = Command::new(binary())
        .args([
            "decrypt",
            "--print-xml-debug",
            "--lax-key-search",
            "--aeskey",
        ])
        .arg(vector.with_extension("key"))
        .arg("--output")
        .arg(&decrypted)
        .arg(vector.with_extension("xml"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&decrypted).unwrap(),
        fs::read(vector.with_extension("data")).unwrap()
    );
    let diagnostics = String::from_utf8(output.stdout).unwrap();
    let document = roxmltree::Document::parse(&diagnostics)
        .expect("--print-xml-debug stdout must be well-formed XML");
    let root = document.root_element();
    assert_eq!(root.tag_name().name(), "DataDecryptionContext");
    assert_eq!(root.attribute("status"), Some("not-replaced"));
    assert_eq!(root.attribute("failureReason"), Some("UNKNOWN"));
    assert!(root.descendants().any(|node| {
        node.has_tag_name("Transform")
            && node.attribute("href") == Some("http://www.w3.org/2009/xmlenc11#aes128-gcm")
    }));
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
    // --node-id selects the operation start node, not EncryptedData/@Id. The
    // first descendant is filled and later templates remain untouched.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("multiple-templates.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    let encrypted_data = |id: &str| {
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="{id}" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#
        )
    };
    fs::write(
        &template,
        format!(
            "<Document><Envelope Id=\"first\">{}{}</Envelope><Envelope Id=\"second\">{}</Envelope></Document>",
            encrypted_data("first-template"),
            encrypted_data("later-first-subtree-template"),
            encrypted_data("second-template")
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"<selected>payload</selected>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let output = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--xml-data"])
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
    assert!(values[2].trim().is_empty());

    let missing = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .args(["--xml-data"])
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
        .args(["--xml-data"])
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
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("binary-data"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn binary_encryption_rejects_embedded_opaque_templates() {
    // Embedded decryption replaces the selected node in its containing XML
    // document, so accepting opaque bytes here would create output that the
    // reciprocal CLI path cannot represent.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(&plaintext, [0xff, 0x00, 0xfe]).unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    for encrypted_type in [None, Some("urn:example:opaque")] {
        let type_attribute = encrypted_type
            .map(|value| format!(" Type=\"{value}\""))
            .unwrap_or_default();
        let template = temp.path().join(format!(
            "embedded-{}.xml",
            encrypted_type.map_or("untyped", |_| "custom")
        ));
        fs::write(
            &template,
            format!(
                r#"<Document><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"{type_attribute}><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData></Document>"#
            ),
        )
        .unwrap();

        let result = Command::new(binary())
            .args(["encrypt", "--aes-key"])
            .arg(&key)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg(&template)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{encrypted_type:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("embedded"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
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
fn untyped_xml_template_round_trips_when_embedded() {
    // --xml-data infers Element semantics. The rendered wire document must
    // retain that inference so embedded decryption performs XML replacement.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let encrypted = temp.path().join("encrypted.xml");
    let document = temp.path().join("document.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="quoted>delimiter"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"<secret>inferred XML</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encryption = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--xml-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encryption.status.success(),
        "{}",
        String::from_utf8_lossy(&encryption.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    assert!(
        encrypted_xml.contains("Id=\"quoted>delimiter\" Type="),
        "{encrypted_xml}"
    );
    fs::write(
        &document,
        format!(
            "<root><scope Id=\"selected\">{}</scope></root>",
            encrypted_xml
        ),
    )
    .unwrap();

    let decryption = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .args(["--node-id", "selected"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        decryption.status.success(),
        "{}",
        String::from_utf8_lossy(&decryption.stderr)
    );
    assert!(
        String::from_utf8(decryption.stdout)
            .unwrap()
            .contains("<scope Id=\"selected\"><secret>inferred XML</secret></scope>")
    );
}

#[test]
fn xml_data_encrypts_the_parsed_document_node() {
    // libxmlsec1 parses --xml-data and serializes either the document element
    // or its children. The declaration and document-boundary trivia are not
    // plaintext nodes in either encryption mode.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &plaintext,
        b"<?xml version=\"1.0\"?>\n<!--outside--><secret xmlns=\"urn:default\" xmlns:p=\"urn:prefixed\"><value>payload</value><p:item/></secret>\n",
    )
    .unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    for encrypted_type in ["Element", "Content"] {
        let template = temp.path().join(format!("template-{encrypted_type}.xml"));
        let encrypted = temp.path().join(format!("encrypted-{encrypted_type}.xml"));
        fs::write(
            &template,
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#{encrypted_type}"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            ),
        )
        .unwrap();

        let encryption = Command::new(binary())
            .args(["encrypt", "--aes-key"])
            .arg(&key)
            .arg("--xml-data")
            .arg(&plaintext)
            .arg("--output")
            .arg(&encrypted)
            .arg(&template)
            .output()
            .unwrap();
        assert!(
            encryption.status.success(),
            "{encrypted_type}: {}",
            String::from_utf8_lossy(&encryption.stderr)
        );

        let decryption = Command::new(binary())
            .args(["decrypt", "--aes-key"])
            .arg(&key)
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            decryption.status.success(),
            "{encrypted_type}: {}",
            String::from_utf8_lossy(&decryption.stderr)
        );
        let decrypted = String::from_utf8(decryption.stdout).unwrap();
        let wrapped = if encrypted_type == "Element" {
            decrypted
        } else {
            format!("<probe>{decrypted}</probe>")
        };
        let document = roxmltree::Document::parse(&wrapped)
            .expect("decrypted XML must preserve inherited namespace bindings");
        let value = document
            .descendants()
            .find(|node| node.tag_name().name() == "value")
            .expect("default-namespaced child must survive");
        let item = document
            .descendants()
            .find(|node| node.tag_name().name() == "item")
            .expect("prefixed child must survive");
        assert_eq!(value.tag_name().namespace(), Some("urn:default"));
        assert_eq!(item.tag_name().namespace(), Some("urn:prefixed"));
    }
}

#[test]
fn xml_data_content_preserves_cdata_as_text() {
    // CDATA is exposed as a text node, but its source range retains the complete
    // lexical construct. Content serialization must preserve both that form and
    // its text semantics rather than accidentally turning payload into markup.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let encrypted = temp.path().join("encrypted.xml");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Content"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(
        &plaintext,
        b"<wrapper><![CDATA[<secret/> & text]]></wrapper>",
    )
    .unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encryption = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--xml-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encryption.status.success(),
        "{}",
        String::from_utf8_lossy(&encryption.stderr)
    );

    let decryption = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decryption.status.success(),
        "{}",
        String::from_utf8_lossy(&decryption.stderr)
    );
    let decrypted = String::from_utf8(decryption.stdout).unwrap();
    assert_eq!(decrypted, "<![CDATA[<secret/> & text]]>");
    let wrapped = format!("<probe>{decrypted}</probe>");
    let document = roxmltree::Document::parse(&wrapped)
        .expect("decrypted Content plaintext must remain well-formed XML content");
    let root = document.root_element();
    assert_eq!(root.text(), Some("<secret/> & text"));
    assert!(!root.children().any(|node| node.is_element()));
}

#[test]
fn xml_data_applies_plaintext_limit_after_document_node_serialization() {
    // The source document and encrypted plaintext are distinct resources. A
    // large wrapper may fit the document ceiling while its tiny child content
    // remains far below the encryption plaintext ceiling.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let key = temp.path().join("key.bin");
    let policy = EncryptionPolicy::default();
    let padding = "x".repeat(policy.resources.max_encryption_plaintext_bytes);
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Content"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(
        &plaintext,
        format!("<wrapper padding=\"{padding}\"><child/></wrapper>"),
    )
    .unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let output = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--xml-data")
        .arg(&plaintext)
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
fn direct_aes_encryption_rejects_recipient_templates() {
    // A direct content key cannot refresh an EncryptedKey recipient. Emitting
    // the untouched wrapped key would create internally inconsistent XML.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("recipient-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><CipherData><CipherValue>c3RhbGU=</CipherValue></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"recipient mismatch").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let output = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("recipient"));
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
fn encryption_rejects_duplicate_content_key_names() {
    // The core XMLEnc parser permits at most one direct KeyName. Reject the
    // template before encryption rather than emitting ciphertext we cannot read.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("duplicate-key-name.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ds:KeyName>first</ds:KeyName><ds:KeyName>second</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"duplicate content key names").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("more than one direct KeyName"));
}

#[test]
fn encryption_rejects_duplicate_encrypted_data_key_info() {
    // A generated document must satisfy the same singleton KeyInfo structure
    // that the reciprocal parser enforces during decryption.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("duplicate-key-info.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo/><ds:KeyInfo/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"duplicate encrypted data key info").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("EncryptedData contains more than one direct KeyInfo")
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
fn named_aes_key_ring_selects_one_key_for_encryption_and_decryption() {
    // Repeatable AES options form a key ring. The document name must select
    // exactly one entry rather than making every multi-key invocation invalid.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("named-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let wrong_key = temp.path().join("wrong.bin");
    let matching_key = temp.path().join("matching.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>selected</KeyName></KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"selected AES key").unwrap();
    fs::write(&wrong_key, b"fedcba9876543210").unwrap();
    fs::write(&matching_key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key:wrong"])
        .arg(&wrong_key)
        .args(["--aes-key:selected"])
        .arg(&matching_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
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
        .args(["decrypt", "--aes-key:wrong"])
        .arg(&wrong_key)
        .args(["--aes-key:selected"])
        .arg(&matching_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"selected AES key");

    let ambiguous = Command::new(binary())
        .args(["decrypt", "--aes-key:selected"])
        .arg(&wrong_key)
        .args(["--aes-key:selected"])
        .arg(&matching_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("multiple AES key"));

    // Lax lookup intentionally ignores duplicate identity metadata and searches
    // by key kind, so the first compatible entry can complete the round trip.
    let lax_encrypted = temp.path().join("lax-encrypted.xml");
    let lax_encrypt = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--aes-key:selected"])
        .arg(&matching_key)
        .args(["--aes-key:selected"])
        .arg(&wrong_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&lax_encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        lax_encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&lax_encrypt.stderr)
    );
    let lax_decrypt = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--aes-key:selected"])
        .arg(&wrong_key)
        .args(["--aes-key:selected"])
        .arg(&matching_key)
        .arg(&lax_encrypted)
        .output()
        .unwrap();
    assert!(
        lax_decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&lax_decrypt.stderr)
    );
    assert_eq!(lax_decrypt.stdout, b"selected AES key");
}

#[test]
fn lax_aes_key_ring_is_bounded_before_filesystem_reads() {
    // Candidate work is an operation ceiling, so oversized rings must fail
    // before even the first attacker-selected path is opened.
    let temp = tempfile::tempdir().unwrap();
    let encrypted = temp.path().join("encrypted.xml");
    fs::write(
        &encrypted,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue>AAAAAAAAAAAAAAAAAAAAAA==</CipherValue></CipherData></EncryptedData>"#,
    )
    .unwrap();
    let maximum = KeyCandidateBudget::for_operation().remaining();
    let mut command = Command::new(binary());
    command.args(["decrypt", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--aes-key");
        command.arg(temp.path().join(format!("missing-{index}.key")));
    }
    let output = command.arg(&encrypted).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key candidates exceeds policy maximum"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("got {}", maximum + 1)), "{stderr}");
    assert!(!stderr.contains("missing-0.key"), "{stderr}");
}

#[test]
fn lax_verification_key_ring_is_bounded_before_filesystem_reads() {
    // The compiled verification candidate ceiling must reject oversized rings
    // before opening even the first attacker-selected public-key path.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let signed = temp.path().join("signed.xml");
    fs::write(&template, signature_template_without_key_info()).unwrap();
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(private_key)
        .arg("--output")
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let maximum = VerificationPolicy::default()
        .key_trust
        .max_x509_candidate_paths;
    let mut command = Command::new(binary());
    command.args(["verify", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--pubkey-pem");
        command.arg(temp.path().join(format!("missing-{index}.pem")));
    }
    let output = command.arg(&signed).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("verification key candidates"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "exceeds policy maximum {maximum}: got {}",
            maximum + 1
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("missing-0.pem"), "{stderr}");
}

#[test]
fn lax_rsa_key_ring_is_bounded_before_filesystem_reads() {
    // RSA decryption must apply the shared candidate-work ceiling before
    // decoding any private-key source, matching the direct AES path.
    let temp = tempfile::tempdir().unwrap();
    let encrypted = temp.path().join("encrypted.xml");
    fs::write(
        &encrypted,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue>AAAAAAAAAAAAAAAAAAAAAA==</CipherValue></CipherData></EncryptedData>"#,
    )
    .unwrap();
    let maximum = KeyCandidateBudget::for_operation().remaining();
    let mut command = Command::new(binary());
    command.args(["decrypt", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--privkey-pem");
        command.arg(temp.path().join(format!("missing-{index}.pem")));
    }
    let output = command.arg(&encrypted).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key candidates exceeds policy maximum"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("got {}", maximum + 1)), "{stderr}");
    assert!(!stderr.contains("missing-0.pem"), "{stderr}");
}

#[test]
fn lax_signing_key_ring_is_bounded_before_filesystem_reads() {
    // Candidate work is bounded independently from successful byte accounting:
    // unreadable or oversized sources must not permit unbounded read attempts.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    fs::write(&template, signature_template_without_key_info()).unwrap();
    let maximum = KeyCandidateBudget::for_operation().remaining();
    let mut command = Command::new(binary());
    command.args(["sign", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--privkey-pem");
        command.arg(temp.path().join(format!("missing-{index}.pem")));
    }
    let output = command.arg(&template).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key candidates exceeds policy maximum"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("got {}", maximum + 1)), "{stderr}");
    assert!(!stderr.contains("missing-0.pem"), "{stderr}");
}

#[test]
fn lax_rsa_encryption_key_ring_is_bounded_before_filesystem_reads() {
    // RSA recipient lookup has the same operation ceiling as direct AES and
    // RSA decryption, so oversized rings must fail before candidate decoding.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"bounded RSA encryption candidates").unwrap();
    let maximum = KeyCandidateBudget::for_operation().remaining();
    let mut command = Command::new(binary());
    command.args(["encrypt", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--pubkey-pem");
        command.arg(temp.path().join(format!("missing-{index}.pem")));
    }
    let output = command
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key candidates exceeds policy maximum"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("got {}", maximum + 1)), "{stderr}");
    assert!(!stderr.contains("missing-0.pem"), "{stderr}");
}

#[test]
fn lax_aes_encryption_key_ring_is_bounded_before_filesystem_reads() {
    // Encryption shares the operation-wide key candidate ceiling and must reject
    // an oversized ring before opening any attacker-selected path.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"bounded encryption candidates").unwrap();
    let maximum = KeyCandidateBudget::for_operation().remaining();
    let mut command = Command::new(binary());
    command.args(["encrypt", "--lax-key-search"]);
    for index in 0..=maximum {
        command.arg("--aes-key");
        command.arg(temp.path().join(format!("missing-{index}.key")));
    }
    let output = command
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key candidates exceeds policy maximum"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("got {}", maximum + 1)), "{stderr}");
    assert!(!stderr.contains("missing-0.key"), "{stderr}");
}

#[test]
fn named_direct_aes_key_populates_an_empty_key_info() {
    // An empty placeholder reserves KeyInfo's schema position. The generated
    // KeyName must survive so strict multi-key decryption can select the key.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("empty-key-info.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let wrong = temp.path().join("wrong.bin");
    let selected = temp.path().join("selected.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"empty KeyInfo identity").unwrap();
    fs::write(&wrong, b"fedcba9876543210").unwrap();
    fs::write(&selected, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key:selected"])
        .arg(&selected)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    let encrypted_document = roxmltree::Document::parse(&encrypted_xml).unwrap();
    assert_eq!(
        encrypted_document
            .descendants()
            .find(|node| { node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")) })
            .and_then(|node| node.text()),
        Some("selected")
    );

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aes-key:wrong"])
        .arg(&wrong)
        .args(["--aes-key:selected"])
        .arg(&selected)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"empty KeyInfo identity");
}

#[test]
fn named_direct_aes_key_extends_extension_only_key_info() {
    // Foreign KeyInfo extensions are preserved, but they cannot suppress the
    // generated KeyName needed for strict recipient selection during decrypt.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("extension-key-info.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let wrong = temp.path().join("wrong.bin");
    let selected = temp.path().join("selected.bin");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:recipient"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ext:Metadata>keep</ext:Metadata></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"extension KeyInfo identity").unwrap();
    fs::write(&wrong, b"fedcba9876543210").unwrap();
    fs::write(&selected, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key:selected"])
        .arg(&selected)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    assert!(encrypted_xml.contains("<ext:Metadata>keep</ext:Metadata>"));
    assert!(encrypted_xml.contains(">selected</"));

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aes-key:wrong"])
        .arg(&wrong)
        .args(["--aes-key:selected"])
        .arg(&selected)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"extension KeyInfo identity");
}

#[test]
fn encryption_rejects_invalid_content_encryption_method_structure() {
    // Encrypt must apply the same EncryptionMethod invariants as decrypt;
    // otherwise it can emit ciphertext that its reciprocal parser rejects.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let key = temp.path().join("key.bin");
    fs::write(&plaintext, b"method validation").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    for (case, children, expected) in [
        (
            "mismatched-key-size",
            "<KeySize>192</KeySize>",
            "requires KeySize 128",
        ),
        (
            "duplicate-key-size",
            "<KeySize>128</KeySize><KeySize>128</KeySize>",
            "KeySize",
        ),
        (
            "oaep-on-aes",
            "<OAEPparams>YQ==</OAEPparams>",
            "only valid for RSA-OAEP",
        ),
    ] {
        let template = temp.path().join(format!("{case}.xml"));
        fs::write(
            &template,
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm">{children}</EncryptionMethod><CipherData><CipherValue/></CipherData></EncryptedData>"#
            ),
        )
        .unwrap();

        let output = Command::new(binary())
            .args(["encrypt", "--aes-key"])
            .arg(&key)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg(&template)
            .output()
            .unwrap();

        assert!(!output.status.success(), "{case} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
fn rsa_encryption_rejects_duplicate_recipient_key_names() {
    // Recipient identity is a singleton selection hint. Silently selecting the
    // first value would emit ciphertext that the reciprocal parser rejects.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("duplicate-recipient-name.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:KeyName>first</ds:KeyName><ds:KeyName>second</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"ambiguous recipient").unwrap();

    let output = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:first"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "ciphertext must not be emitted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("more than one direct KeyName"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rsa_encryption_rejects_duplicate_recipient_key_info() {
    // Each EncryptedKey has one optional KeyInfo identity. Selecting the first
    // duplicate would preserve malformed output that decryption rejects.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("duplicate-recipient-key-info.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo/><ds:KeyInfo/><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"duplicate recipient key info").unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("EncryptedKey contains more than one direct KeyInfo")
    );
}

#[test]
fn rsa_encryption_rejects_stale_recipient_key_value_metadata() {
    // A template KeyValue is a cryptographic identity, not a selection hint.
    // Preserving it while wrapping for another key would emit contradictory XML.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("rsa-key-value-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let matching_path = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let mismatching_path = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let matching =
        RsaPublicKey::from_public_key_pem(&fs::read_to_string(&matching_path).unwrap()).unwrap();
    fs::write(
        &template,
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo>{}</ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            rsa_key_value_with_leading_zeroes(&matching, 1, 2)
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"recipient identity").unwrap();

    let accepted = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&matching_path)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&mismatching_path)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("recipient key metadata"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn rsa_encryption_validates_der_encoded_recipient_metadata() {
    // DEREncodedKeyValue identifies the wrapping recipient just like
    // RSAKeyValue and X509Data: matching SPKI is accepted, stale SPKI is not.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("der-recipient-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let matching_path = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let mismatching_path = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let matching =
        RsaPublicKey::from_public_key_pem(&fs::read_to_string(&matching_path).unwrap()).unwrap();
    fs::write(
        &template,
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo>{}</ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            der_encoded_key_value(&matching)
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"DER recipient identity").unwrap();

    let accepted = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&matching_path)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&mismatching_path)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("recipient key metadata"));
}

#[test]
fn rsa_encryption_rejects_stale_recipient_certificate_metadata() {
    // X509Data identifies the same recipient as the wrapped content key. A
    // certificate for another key must fail before any contradictory output.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("x509-recipient-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let matching_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let mismatching_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    fs::write(
        &template,
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo>{}</ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            x509_certificate_value(&certificate)
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"certificate recipient identity").unwrap();

    let accepted = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&matching_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&mismatching_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("recipient key metadata"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn rsa_encryption_rejects_embedded_certificate_with_stale_selectors() {
    // An embedded certificate and its selectors form one identity assertion.
    // A matching wrapping key must not make contradictory selectors ignorable.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("x509-recipient-selector-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let matching_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let certificate_with_stale_selector = x509_certificate_value(&certificate).replace(
        "</ds:X509Data>",
        "<ds:X509SubjectName>CN=not-the-recipient</ds:X509SubjectName></ds:X509Data>",
    );
    fs::write(
        &template,
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo>{certificate_with_stale_selector}</ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"certificate selector identity").unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&matching_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("lookup identifiers do not match the embedded certificate chain"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn rsa_encryption_matches_selector_only_x509data_to_configured_certificate() {
    // Selector-only X509Data resolves against --pubkey-cert-pem certificate
    // metadata; a bare public key cannot satisfy that certificate identity.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("x509-selector-recipient.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let bare_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let (_, certificate_pem) =
        x509_parser::pem::parse_x509_pem(&fs::read(&certificate).unwrap()).unwrap();
    let (_, parsed_certificate) =
        x509_parser::certificate::X509Certificate::from_der(&certificate_pem.contents).unwrap();
    let ski = parsed_certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(value) => Some(value.0),
            _ => None,
        })
        .unwrap();
    let digest = default_provider()
        .digest(DigestAlgorithm::Sha256, &certificate_pem.contents)
        .unwrap();
    fs::write(&plaintext, b"selector recipient identity").unwrap();
    let selectors = [
        (
            "subject",
            "<ds:X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</ds:X509SubjectName>".to_owned(),
        ),
        (
            "issuer-serial",
            "<ds:X509IssuerSerial><ds:X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</ds:X509IssuerName><ds:X509SerialNumber>680572598617295163017172295025714171905498632019</ds:X509SerialNumber></ds:X509IssuerSerial>".to_owned(),
        ),
        (
            "ski",
            format!(
                "<ds:X509SKI>{}</ds:X509SKI>",
                base64::engine::general_purpose::STANDARD.encode(ski)
            ),
        ),
        (
            "digest",
            format!(
                "<dsig11:X509Digest Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">{}</dsig11:X509Digest>",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ),
        ),
    ];
    for (name, selector) in selectors {
        fs::write(
            &template,
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:X509Data>{selector}</ds:X509Data></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            ),
        )
        .unwrap();
        let accepted = Command::new(binary())
            .args(["encrypt", "--pubkey-cert-pem"])
            .arg(&certificate)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg(&template)
            .output()
            .unwrap();
        assert!(
            accepted.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&accepted.stderr)
        );
    }

    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</ds:X509SubjectName></ds:X509Data></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&bare_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("certificate"));
}

#[test]
fn named_rsa_key_ring_selects_one_recipient_for_encryption_and_decryption() {
    // Recipient KeyName selects one public/private key pair from repeatable
    // options on both sides of the process boundary.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("named-rsa-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let wrong_public = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let matching_public = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let wrong_private = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let matching_private = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:KeyName>selected</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"selected RSA recipient").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:wrong"])
        .arg(&wrong_public)
        .args(["--pubkey-pem:selected"])
        .arg(&matching_public)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
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
        .args(["decrypt", "--privkey-pem:wrong"])
        .arg(&wrong_private)
        .args(["--privkey-pem:selected"])
        .arg(&matching_private)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"selected RSA recipient");
}

#[test]
fn named_rsa_option_identifies_a_generated_recipient() {
    // With no EncryptedKey skeleton, the selected option name is the only
    // recipient identity available to the reciprocal strict key-ring lookup.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("generated-named-recipient.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"generated named recipient").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:recipient"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    let document = roxmltree::Document::parse(&encrypted_xml).unwrap();
    assert!(document.descendants().any(|node| {
        node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName"))
            && node.text() == Some("recipient")
    }));

    let decrypt = Command::new(binary())
        .args(["decrypt", "--privkey-pem:recipient"])
        .arg(&private_key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"generated named recipient");
}

#[test]
fn named_rsa_option_populates_existing_unnamed_recipients() {
    // Existing recipient skeletons keep their template metadata, but a missing
    // nested identity must receive the selected option name for strict decrypt.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(&plaintext, b"existing named recipient").unwrap();

    for (case, nested_key_info) in [("absent", ""), ("empty", "<ds:KeyInfo/>")] {
        let template = temp.path().join(format!("{case}-recipient-template.xml"));
        let encrypted = temp.path().join(format!("{case}-recipient.xml"));
        fs::write(
            &template,
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>{nested_key_info}<CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#
            ),
        )
        .unwrap();

        let encrypt = Command::new(binary())
            .args(["encrypt", "--pubkey-pem:recipient"])
            .arg(&public_key)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg("--output")
            .arg(&encrypted)
            .arg(&template)
            .output()
            .unwrap();
        assert!(
            encrypt.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&encrypt.stderr)
        );
        let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
        let document = roxmltree::Document::parse(&encrypted_xml).unwrap();
        let encrypted_key = document
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")))
            .unwrap();
        assert!(encrypted_key.descendants().any(|node| {
            node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName"))
                && node.text() == Some("recipient")
        }));

        let decrypt = Command::new(binary())
            .args(["decrypt", "--privkey-pem:recipient"])
            .arg(&private_key)
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            decrypt.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&decrypt.stderr)
        );
        assert_eq!(decrypt.stdout, b"existing named recipient");
    }
}

#[test]
fn lax_rsa_decryption_skips_malformed_private_key_candidates() {
    // Lax lookup is an ordered compatibility search. A malformed entry must not
    // prevent a later or earlier usable key from unwrapping the recipient.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("lax-private-key-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let malformed = temp.path().join("malformed.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"skip malformed private key").unwrap();
    fs::write(&malformed, b"not a private key").unwrap();
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

    for candidates in [[&malformed, &private_key], [&private_key, &malformed]] {
        let decrypt = Command::new(binary())
            .args(["decrypt", "--lax-key-search", "--privkey-pem:first"])
            .arg(candidates[0])
            .args(["--privkey-pem:second"])
            .arg(candidates[1])
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            decrypt.status.success(),
            "{}",
            String::from_utf8_lossy(&decrypt.stderr)
        );
        assert_eq!(decrypt.stdout, b"skip malformed private key");
    }

    let rejected = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--privkey-pem:first"])
        .arg(&malformed)
        .args(["--privkey-pem:second"])
        .arg(&malformed)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("private key"));
}

#[test]
fn lax_rsa_decryption_stops_after_aggregate_material_exhaustion() {
    // Candidate-local decode failures remain skippable, but once cumulative
    // source bytes cross the invocation ceiling a later small valid key must
    // not revive the search using the unchanged pre-failure budget total.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("budget-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let malformed_8m = temp.path().join("malformed-8m.pem");
    let malformed_1m = temp.path().join("malformed-1m.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"aggregate budget must be terminal").unwrap();
    fs::File::create(&malformed_8m)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    fs::File::create(&malformed_1m)
        .unwrap()
        .set_len(1024 * 1024)
        .unwrap();

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

    let decrypt = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--privkey-pem:first"])
        .arg(&malformed_8m)
        .args(["--privkey-pem:second"])
        .arg(&malformed_8m)
        .args(["--privkey-pem:third"])
        .arg(&malformed_8m)
        .args(["--privkey-pem:fourth"])
        .arg(&malformed_1m)
        .args(["--privkey-pem:fifth"])
        .arg(&malformed_8m)
        .args(["--privkey-pem:valid"])
        .arg(&private_key)
        .arg(&encrypted)
        .output()
        .unwrap();

    assert!(!decrypt.status.success());
    assert!(
        String::from_utf8_lossy(&decrypt.stderr)
            .contains("configured external key/certificate material exceeds policy limit")
    );
}

#[test]
fn lax_rsa_search_skips_candidates_that_conflict_with_recipient_metadata() {
    // Lax name matching does not make preserved KeyValue metadata advisory: a
    // syntactically valid but mismatching key must be skipped in favor of the
    // later candidate whose public components satisfy the template identity.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("lax-recipient-metadata.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let wrong = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let matching = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let matching_key =
        RsaPublicKey::from_public_key_pem(&fs::read_to_string(&matching).unwrap()).unwrap();
    fs::write(
        &template,
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo>{}</ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
            rsa_key_value_with_leading_zeroes(&matching_key, 0, 0)
        ),
    )
    .unwrap();
    fs::write(&plaintext, b"metadata-selected recipient").unwrap();

    let accepted = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--pubkey-pem:first"])
        .arg(&wrong)
        .args(["--pubkey-pem:second"])
        .arg(&matching)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
}

#[test]
fn lax_rsa_encryption_skips_keys_rejected_by_policy() {
    // Lax lookup searches for a usable RSA recipient. A parseable weak key must
    // not prevent a later policy-compliant key from reaching encryption.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("lax-recipient-policy.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let weak_public_key = temp.path().join("rsa-1024-pubkey.pem");
    let weak_key = RsaPrivateKey::new(&mut ChaCha8Rng::from_seed([0x72; 32]), 1024).unwrap();
    fs::write(
        &weak_public_key,
        weak_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap(),
    )
    .unwrap();
    let compliant_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"policy-selected recipient").unwrap();

    let accepted = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--pubkey-pem:weak"])
        .arg(&weak_public_key)
        .args(["--pubkey-pem:compliant"])
        .arg(&compliant_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&weak_public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("requires RSA keys between 2048 and 8192 bits: got 1024")
    );
}

#[test]
fn rsa_encryption_populates_an_existing_key_info_container() {
    // A template may reserve KeyInfo for non-cryptographic metadata without
    // pre-creating EncryptedKey. Encryption must add the generated recipient
    // while preserving those sibling sources.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("key-info-container-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ds:KeyName>content-key</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"existing KeyInfo container").unwrap();

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
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    let document = roxmltree::Document::parse(&encrypted_xml).unwrap();
    assert!(document.descendants().any(|node| {
        node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName"))
            && node.text() == Some("content-key")
    }));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")))
            .count(),
        1
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
    assert_eq!(decrypt.stdout, b"existing KeyInfo container");
}

#[test]
fn rsa_encryption_preserves_extension_cipher_values() {
    // CipherValue is meaningful only along an EncryptedKey recipient path.
    // Extension-owned values must remain caller metadata, not placeholders.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("extension-cipher-value.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:test"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ext:Metadata><CipherValue>ZXh0ZW5zaW9u</CipherValue></ext:Metadata></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"extension metadata").unwrap();

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
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    let document = roxmltree::Document::parse(&encrypted_xml).unwrap();
    assert_eq!(
        document
            .descendants()
            .find(|node| node.has_tag_name(("urn:test", "Metadata")))
            .and_then(|node| {
                node.children().find(|child| {
                    child.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue"))
                })
            })
            .and_then(|node| node.text()),
        Some("ZXh0ZW5zaW9u")
    );
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")))
            .count(),
        1
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
    assert_eq!(decrypt.stdout, b"extension metadata");
}

#[test]
fn rsa_encryption_builds_every_named_recipient() {
    // Repeatable public keys map one-for-one to template recipients. Every
    // generated wrapped key must remain decryptable, while missing or duplicate
    // matches fail before emitting a partial recipient set.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("multi-recipient-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_a = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let public_b = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_a = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let private_b = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo><ds:KeyName>a</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></EncryptionMethod><ds:KeyInfo><ds:KeyName>b</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"multiple RSA recipients").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:a"])
        .arg(&public_a)
        .args(["--pubkey-pem:b"])
        .arg(&public_b)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    let document = roxmltree::Document::parse(&encrypted_xml).unwrap();
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey")))
            .count(),
        2
    );

    for (name, private_key) in [("a", &private_a), ("b", &private_b)] {
        let decrypt = Command::new(binary())
            .arg("decrypt")
            .arg(format!("--privkey-pem:{name}"))
            .arg(private_key)
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            decrypt.status.success(),
            "{}",
            String::from_utf8_lossy(&decrypt.stderr)
        );
        assert_eq!(decrypt.stdout, b"multiple RSA recipients");
    }

    let decrypt_with_key_ring = Command::new(binary())
        .args(["decrypt", "--privkey-pem:a"])
        .arg(&private_a)
        .arg("--privkey-pem:b")
        .arg(&private_b)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt_with_key_ring.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt_with_key_ring.stderr)
    );
    assert_eq!(decrypt_with_key_ring.stdout, b"multiple RSA recipients");

    let missing = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:a"])
        .arg(&public_a)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("unknown KeyName"));

    let duplicate = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:a"])
        .arg(&public_a)
        .args(["--pubkey-pem:a"])
        .arg(&public_b)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("multiple RSA recipient key"));

    let lax_encrypted = temp.path().join("lax-encrypted.xml");
    let lax_encrypt = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--pubkey-pem:ignored-a"])
        .arg(&public_a)
        .arg("--pubkey-pem:ignored-b")
        .arg(&public_b)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&lax_encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        lax_encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&lax_encrypt.stderr)
    );
    for (name, private_key) in [("a", &private_a), ("b", &private_b)] {
        let decrypt = Command::new(binary())
            .arg("decrypt")
            .arg(format!("--privkey-pem:{name}"))
            .arg(private_key)
            .arg(&lax_encrypted)
            .output()
            .unwrap();
        assert!(
            decrypt.status.success(),
            "lax recipient {name}: {}",
            String::from_utf8_lossy(&decrypt.stderr)
        );
        assert_eq!(decrypt.stdout, b"multiple RSA recipients");
    }

    let insufficient_output = temp.path().join("insufficient-lax.xml");
    let insufficient = Command::new(binary())
        .args(["encrypt", "--lax-key-search", "--pubkey-pem:ignored"])
        .arg(&public_a)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&insufficient_output)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!insufficient.status.success());
    assert!(!insufficient_output.exists());
}

#[test]
fn mixed_named_and_unnamed_rsa_recipients_keep_distinct_key_identities() {
    // A mixed template must retain the unnamed slot through both encryption and
    // decryption selection instead of collapsing all recipients to KeyName.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("mixed-recipient-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_a = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let public_b = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_a = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let private_b = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:KeyName>a</ds:KeyName></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"mixed recipient identities").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--pubkey-pem:a"])
        .arg(&public_a)
        .arg("--pubkey-pem")
        .arg(&public_b)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg("--output")
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
        .args(["decrypt", "--privkey-pem:a"])
        .arg(&private_b)
        .arg("--privkey-pem")
        .arg(&private_b)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert_eq!(decrypt.stdout, b"mixed recipient identities");

    let ambiguous = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(&private_b)
        .arg("--privkey-pem")
        .arg(&private_b)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("recipient identity"));

    let wrong_identity = Command::new(binary())
        .args(["decrypt", "--privkey-pem:a"])
        .arg(&private_b)
        .arg("--privkey-pem")
        .arg(&private_a)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        !wrong_identity.status.success(),
        "an unnamed key must not act as a wildcard for named recipient a"
    );
}

#[test]
fn encryption_node_id_accepts_namespaced_id_attributes() {
    // CLI node selection shares local-name ID semantics with reference
    // resolution, including profile-standard qualified wsu:Id attributes.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("namespaced-node-id-template.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let aes_key = temp.path().join("aes.key");
    fs::write(
        &template,
        r#"<root xmlns:wsu="urn:wsu"><scope wsu:Id="target"><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData></scope></root>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"<selected>namespaced node ID</selected>").unwrap();
    fs::write(&aes_key, [7_u8; 16]).unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--node-id", "target", "--aes-key"])
        .arg(&aes_key)
        .arg("--xml-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    assert!(String::from_utf8_lossy(&encrypt.stdout).contains("wsu:Id=\"target\""));
}

#[test]
fn global_id_attribute_selects_encrypt_and_decrypt_subtrees() {
    // --add-id-attr applies one local attribute name to every element, and the
    // registration must survive both CLI-side template parsing and core decrypt.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("custom-id-template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let encrypted = temp.path().join("encrypted.xml");
    let key = temp.path().join("aes.key");
    fs::write(
        &template,
        r#"<root><scope Token="target"><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData></scope></root>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"<secret>registered</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--add-id-attr", "Token", "--node-id", "target"])
        .arg("--aes-key")
        .arg(&key)
        .arg("--xml-data")
        .arg(&plaintext)
        .arg("--output")
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
        .args(["decrypt", "--add-id-attr", "Token", "--node-id", "target"])
        .arg("--aes-key")
        .arg(&key)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    let output = String::from_utf8(decrypt.stdout).unwrap();
    assert!(output.contains("<scope Token=\"target\"><secret>registered</secret></scope>"));
}

#[test]
fn named_decryption_key_selects_a_later_recipient() {
    // A document KeyName selects among all EncryptedKey recipients. Checking
    // only the first recipient would reject a valid key before core decryption
    // can reach the matching wrapped content key.
    let temp = tempfile::tempdir().unwrap();
    let encrypted = temp.path().join("encrypted.xml");
    let matching_private = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let matching_public = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"))
            .unwrap(),
    )
    .unwrap();
    let other_public = RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"))
            .unwrap(),
    )
    .unwrap();
    let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .add_recipient(EncryptionRecipient::rsa_oaep(other_public).key_name("other"))
        .add_recipient(EncryptionRecipient::rsa_oaep(matching_public).key_name("matching"))
        .encrypt_binary(b"later recipient")
        .unwrap();
    fs::write(&encrypted, generated.encrypted_data_xml).unwrap();

    let output = Command::new(binary())
        .args(["decrypt", "--privkey-pem:matching"])
        .arg(&matching_private)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"later recipient");
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

    let unrelated_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let mismatched_compound = format!(
        "{},{}",
        private_key.display(),
        unrelated_certificate.display()
    );
    let mismatched = Command::new(binary())
        .args(["decrypt", "--privkey-pem"])
        .arg(&mismatched_compound)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(!mismatched.status.success());
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("does not match"));

    let valid_compound = format!("{},{}", private_key.display(), certificate.display());
    let lax = Command::new(binary())
        .args(["decrypt", "--lax-key-search", "--privkey-pem:first"])
        .arg(mismatched_compound)
        .args(["--privkey-pem:second"])
        .arg(valid_compound)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        lax.status.success(),
        "{}",
        String::from_utf8_lossy(&lax.stderr)
    );
    assert_eq!(lax.stdout, b"certificate companion");

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
fn encryption_rejects_incomplete_or_ambiguous_recipient_methods() {
    // Template metadata must describe exactly one self-consistent wrapping
    // method; first-match parsing can otherwise emit output our parser rejects.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(&plaintext, b"recipient metadata").unwrap();
    let method = |children: &str| {
        format!(
            r#"<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">{children}</EncryptionMethod>"#
        )
    };
    let digest = r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#;
    let mgf = r#"<xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>"#;
    let label = "<OAEPparams>YQ==</OAEPparams>";

    for (case, recipient_method, expected) in [
        ("missing", String::new(), "EncryptionMethod"),
        (
            "duplicate-method",
            format!("{}{}", method(""), method("")),
            "EncryptionMethod",
        ),
        (
            "duplicate-digest",
            method(&format!("{digest}{digest}")),
            "DigestMethod",
        ),
        ("duplicate-mgf", method(&format!("{mgf}{mgf}")), "MGF"),
        (
            "duplicate-label",
            method(&format!("{label}{label}")),
            "OAEPparams",
        ),
    ] {
        let template = temp.path().join(format!("{case}.xml"));
        fs::write(
            &template,
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey>{recipient_method}<CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#
            ),
        )
        .unwrap();
        let output = Command::new(binary())
            .args(["encrypt", "--pubkey-pem"])
            .arg(&public_key)
            .arg("--binary-data")
            .arg(&plaintext)
            .arg(&template)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn encryption_rejects_templates_the_decryption_parser_cannot_consume() {
    // Encryption preserves template metadata, so it must reject every structure
    // that the reciprocal parser would reject instead of emitting dead output.
    let temp = tempfile::tempdir().unwrap();
    let plaintext = temp.path().join("plaintext.bin");
    let aes_key = temp.path().join("aes-key.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(&plaintext, b"template validation").unwrap();
    fs::write(&aes_key, b"0123456789abcdef").unwrap();

    let oversized_id = "x".repeat(4 * 1024 + 1);
    let cases = [
        (
            "recipient-child-order",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><ds:KeyInfo><ds:KeyName>recipient</ds:KeyName></ds:KeyInfo><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#.to_owned(),
            true,
        ),
        (
            "unsupported-recipient-method-child",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:test"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ext:Parameters/></EncryptionMethod><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#.to_owned(),
            true,
        ),
        (
            "empty-content-key-name",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ds:KeyName/></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#.to_owned(),
            false,
        ),
        (
            "empty-recipient-key-name",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/><ds:KeyInfo><ds:KeyName/></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#.to_owned(),
            true,
        ),
        (
            "oversized-encrypted-data-id",
            format!(
                r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="{oversized_id}"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#
            ),
            false,
        ),
        (
            "agreement-only-key-info",
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><AgreementMethod Algorithm="urn:test:agreement"/></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#.to_owned(),
            false,
        ),
    ];

    for (case, xml, uses_rsa_recipient) in cases {
        let template = temp.path().join(format!("{case}.xml"));
        let output_path = temp.path().join(format!("{case}-output.xml"));
        fs::write(&template, xml).unwrap();
        let mut command = Command::new(binary());
        command.arg("encrypt");
        if uses_rsa_recipient {
            command.arg("--pubkey-pem").arg(&public_key);
        } else {
            command.arg("--aes-key").arg(&aes_key);
        }
        let output = command
            .arg("--binary-data")
            .arg(&plaintext)
            .arg("--output")
            .arg(&output_path)
            .arg(&template)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case} unexpectedly succeeded");
        assert!(!output_path.exists(), "{case} emitted partial output");
    }
}

#[test]
fn rsa_oaep_label_split_by_comment_round_trips() {
    // XML simple content spans every direct text node. Keeping only the first
    // side of a comment makes encryption and decryption use different labels.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("split-label.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    fs::write(&plaintext, b"comment-split OAEP label").unwrap();
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><OAEPparams>YWJj<!--split-->ZA==</OAEPparams></EncryptionMethod><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();

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
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
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
    assert_eq!(decrypt.stdout, b"comment-split OAEP label");
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
fn rsa_oaep_accepts_the_xmldsig_more_sha384_digest_uri() {
    // libxmlsec1 emits the XMLDSig-more spelling for SHA-384. Encryption and
    // decryption must share one alias mapping for this interoperable template.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("sha384-alias.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha384"/></EncryptionMethod><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"SHA-384 OAEP alias").unwrap();

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
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
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
    assert_eq!(decrypt.stdout, b"SHA-384 OAEP alias");
}

#[test]
fn legacy_rsa_oaep_rejects_xmlenc11_mgf_parameters() {
    // XML Encryption 1.0 fixes MGF1 to SHA-1. Preserving an XML Encryption 1.1
    // MGF child would make the emitted structure contradict the wrapping mode.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("legacy-oaep-with-mgf.xml");
    let plaintext = temp.path().join("plaintext.bin");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></EncryptionMethod><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, b"invalid legacy OAEP metadata").unwrap();

    let rejected = Command::new(binary())
        .args(["encrypt", "--pubkey-pem"])
        .arg(&public_key)
        .arg("--binary-data")
        .arg(&plaintext)
        .arg(&template)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("MGF"));
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
fn embedded_decryption_replaces_only_the_first_encrypted_data() {
    // libxmlsec1 starts at the selected operation node and decrypts its first
    // EncryptedData descendant rather than rejecting later encrypted siblings.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("template.xml");
    let plaintext = temp.path().join("plaintext.xml");
    let key = temp.path().join("key.bin");
    let encrypted = temp.path().join("encrypted.xml");
    let document = temp.path().join("document.xml");
    fs::write(
        &template,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue/></CipherData></EncryptedData>"#,
    )
    .unwrap();
    fs::write(&plaintext, "<secret>first payload</secret>").unwrap();
    fs::write(&key, b"0123456789abcdef").unwrap();

    let encrypt = Command::new(binary())
        .args(["encrypt", "--aes-key"])
        .arg(&key)
        .arg("--xml-data")
        .arg(&plaintext)
        .arg("--output")
        .arg(&encrypted)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        encrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    let encrypted_xml = fs::read_to_string(&encrypted).unwrap();
    fs::write(
        &document,
        format!("<root><first>{encrypted_xml}</first><second>{encrypted_xml}</second></root>"),
    )
    .unwrap();

    let decrypt = Command::new(binary())
        .args(["decrypt", "--aes-key"])
        .arg(&key)
        .arg(&document)
        .output()
        .unwrap();

    assert!(
        decrypt.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    let output = String::from_utf8(decrypt.stdout).unwrap();
    let parsed = roxmltree::Document::parse(&output).unwrap();
    let first = parsed
        .descendants()
        .find(|node| node.has_tag_name("first"))
        .unwrap();
    let second = parsed
        .descendants()
        .find(|node| node.has_tag_name("second"))
        .unwrap();
    assert!(first.descendants().any(|node| node.has_tag_name("secret")));
    assert!(
        second.descendants().any(|node| {
            node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptedData"))
        })
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
fn generated_key_store_rejects_non_xml_key_names_before_writing() {
    // Escaping handles markup but cannot make XML 1.0-forbidden characters
    // serializable; a failed command must not leave a malformed secret file.
    let temp = tempfile::tempdir().unwrap();
    let key_store = temp.path().join("invalid.xml");
    let output = Command::new(binary())
        .arg("keys")
        .arg("--gen-key:invalid\u{1}name")
        .arg("aes-128")
        .arg(&key_store)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("XML"));
    assert!(!key_store.exists());
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
    assert_eq!(
        Command::new(binary())
            .arg("check-key-data")
            .status()
            .unwrap()
            .code(),
        Some(0)
    );
    assert_eq!(
        Command::new(binary())
            .args(["check-key-data", "unknown-key-data"])
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
}

#[test]
fn embedded_certificate_requires_trust_unless_insecure() {
    // Document-controlled X509Data is an identity claim, not a trust anchor.
    // Only an explicit insecure opt-out may verify it without caller trust.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let signed = temp.path().join("signed.xml");
    let compound = format!("{},{}", private_key.display(), certificate.display());
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
        .arg("--output")
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let untrusted = Command::new(binary())
        .arg("verify")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(!untrusted.status.success());
    assert!(String::from_utf8_lossy(&untrusted.stderr).contains("trusted"));

    let insecure = Command::new(binary())
        .args(["verify", "--insecure"])
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        insecure.status.success(),
        "{}",
        String::from_utf8_lossy(&insecure.stderr)
    );

    let insecure_with_crls = Command::new(binary())
        .args(["verify", "--insecure", "--verify-crls"])
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        insecure_with_crls.status.success(),
        "{}",
        String::from_utf8_lossy(&insecure_with_crls.stderr)
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
fn certificate_embedding_preserves_existing_key_info_sources() {
    // Populating X509Data must not erase the KeyName that selected the signing
    // key or create a second X509Data beside the template placeholder.
    let temp = tempfile::tempdir().unwrap();
    let source = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let template = temp.path().join("key-info-template.xml");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let public_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let signed = temp.path().join("signed.xml");
    let template_xml = fs::read_to_string(source).unwrap().replace(
        "<X509Data/>",
        "<X509Data Id=\"caller\"><X509CRL>Y3Js</X509CRL></X509Data>",
    );
    fs::write(&template, template_xml).unwrap();
    let compound = format!("{},{}", private_key.display(), certificate.display());

    let result = Command::new(binary())
        .args(["sign", "--privkey-pem:TestKeyName-rsa-2048"])
        .arg(compound)
        .arg("--output")
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let xml = fs::read_to_string(&signed).unwrap();
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")))
            .filter_map(|node| node.text())
            .collect::<Vec<_>>(),
        ["TestKeyName-rsa-2048"]
    );
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Data")))
            .count(),
        1
    );
    assert_eq!(
        document
            .descendants()
            .filter(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))
            })
            .count(),
        1
    );
    let x509_data = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Data")))
        .unwrap();
    assert_eq!(x509_data.attribute("Id"), Some("caller"));
    assert_eq!(
        x509_data
            .children()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509CRL")))
            .and_then(|node| node.text()),
        Some("Y3Js")
    );

    let verify = Command::new(binary())
        .args(["verify", "--pubkey-pem:TestKeyName-rsa-2048"])
        .arg(&public_key)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
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
    assert!(String::from_utf8_lossy(&result.stderr).contains("certificate"));
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
fn explicit_certificate_verification_honors_embedded_crls() {
    // The explicit certificate pins identity, while document X509CRL entries
    // still provide revocation evidence when the caller enables CRL checking.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let intermediate = project_root().join("tests/fixtures/keys/ca2cert.pem");
    let anchor = project_root().join("tests/fixtures/keys/cacert.pem");
    let crl = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem");
    let signed = temp.path().join("signed.xml");
    let with_crl = temp.path().join("signed-with-crl.xml");
    let compound = format!("{},{}", private_key.display(), certificate.display());
    let sign = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(compound)
        .arg("--output")
        .arg(&signed)
        .arg(&template)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let signed_xml = fs::read_to_string(&signed).unwrap();
    let signed_xml = signed_xml.replacen(
        "</X509Data>",
        &format!("<X509CRL>{}</X509CRL></X509Data>", pem_der_base64(&crl)),
        1,
    );
    fs::write(&with_crl, signed_xml).unwrap();

    let unchecked = Command::new(binary())
        .args(["verify", "--pubkey-cert-pem"])
        .arg(&certificate)
        .arg("--trusted-pem")
        .arg(&anchor)
        .arg("--untrusted-pem")
        .arg(&intermediate)
        .arg(&with_crl)
        .output()
        .unwrap();
    assert!(
        unchecked.status.success(),
        "{}",
        String::from_utf8_lossy(&unchecked.stderr)
    );

    let checked = Command::new(binary())
        .args(["verify", "--verify-crls", "--pubkey-cert-pem"])
        .arg(&certificate)
        .arg("--trusted-pem")
        .arg(&anchor)
        .arg("--untrusted-pem")
        .arg(&intermediate)
        .arg(&with_crl)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(
        String::from_utf8_lossy(&checked.stderr).contains("CRL"),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
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

    // Lax lookup is type-based rather than identity-only and therefore remains
    // effective when the explicit key set contains more than one RSA key.
    let lax = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:first"])
        .arg(&private_key)
        .args(["--privkey-pem:second"])
        .arg(&wrong_key)
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
fn lax_signing_skips_keys_rejected_by_the_signing_policy() {
    // Lax lookup is an ordered search for a usable key, not permission to select
    // a weak key and fail before trying a later policy-compliant candidate.
    let temp = tempfile::tempdir().unwrap();
    let weak_key_path = temp.path().join("rsa-1024.pem");
    let weak_key = RsaPrivateKey::new(&mut ChaCha8Rng::from_seed([0x71; 32]), 1024).unwrap();
    fs::write(
        &weak_key_path,
        weak_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let compliant_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");

    let signed = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:weak"])
        .arg(&weak_key_path)
        .args(["--privkey-pem:compliant"])
        .arg(&compliant_key)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
}

#[test]
fn lax_signing_skips_a_key_with_a_mismatched_certificate_companion() {
    // A comma-separated key and certificate chain is one candidate. Lax search
    // must reject the complete candidate before considering the next option.
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let matching_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let unrelated_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let mismatched = format!(
        "{},{}",
        private_key.display(),
        unrelated_certificate.display()
    );
    let matching = format!(
        "{},{}",
        private_key.display(),
        matching_certificate.display()
    );

    let signed = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:first"])
        .arg(mismatched)
        .args(["--privkey-pem:second"])
        .arg(matching)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
}

#[test]
fn lax_signing_skips_a_key_that_conflicts_with_preserved_rsa_key_value() {
    // Preserved public identity is part of candidate suitability. Lax search
    // must continue after a valid private key whose public components differ.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("key-value-template.xml");
    let wrong = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let matching = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let matching_key =
        RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(&matching).unwrap()).unwrap();
    fs::write(
        &template,
        signature_template_with_key_info(&rsa_key_value_with_leading_zeroes(
            &matching_key.to_public_key(),
            0,
            0,
        )),
    )
    .unwrap();

    let signed = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:wrong"])
        .arg(&wrong)
        .args(["--privkey-pem:matching"])
        .arg(&matching)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
}

#[test]
fn lax_signing_skips_a_key_that_conflicts_with_preserved_x509_identity() {
    // Each key/certificate option can be internally consistent yet contradict
    // the template's X509Data; lax search must validate that identity per try.
    let temp = tempfile::tempdir().unwrap();
    let template = temp.path().join("x509-template.xml");
    let wrong_key = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let wrong_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let matching_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let matching_certificate = project_root().join("tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    fs::write(
        &template,
        signature_template_with_key_info(&x509_certificate_value(&matching_certificate)),
    )
    .unwrap();
    let wrong = format!("{},{}", wrong_key.display(), wrong_certificate.display());
    let matching = format!(
        "{},{}",
        matching_key.display(),
        matching_certificate.display()
    );

    let signed = Command::new(binary())
        .args(["sign", "--lax-key-search", "--privkey-pem:wrong"])
        .arg(wrong)
        .args(["--privkey-pem:matching"])
        .arg(matching)
        .arg(&template)
        .output()
        .unwrap();

    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
}

#[test]
fn verification_selects_a_later_named_key_from_every_template_key_name() {
    // Repeated public-key inputs model a key manager, and every direct
    // KeyName is an ordered lookup source rather than only the first one.
    let temp = tempfile::tempdir().unwrap();
    let template = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl");
    let private_key = project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem");
    let matching_public = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let wrong_public = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let signed = Command::new(binary())
        .args(["sign", "--privkey-pem"])
        .arg(&private_key)
        .arg(&template)
        .output()
        .unwrap();
    assert!(signed.status.success());
    let signed_path = temp.path().join("multiple-key-names.xml");
    let signed_xml = String::from_utf8(signed.stdout).unwrap().replace(
        "<KeyName>TestKeyName-rsa-2048</KeyName>",
        "<KeyName>stale</KeyName><KeyName>selected</KeyName>",
    );
    fs::write(&signed_path, signed_xml).unwrap();

    let verified = Command::new(binary())
        .args(["verify", "--pubkey-pem:wrong"])
        .arg(&wrong_public)
        .args(["--pubkey-pem:selected"])
        .arg(&matching_public)
        .arg(&signed_path)
        .output()
        .unwrap();

    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
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
fn duplicate_named_verification_keys_are_rejected_as_ambiguous() {
    // Repeatable keys are a lookup set, but one KeyName must never select two
    // entries because silently choosing by option order would be unstable.
    let signed = project_root()
        .join("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml");
    let first = project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let second = project_root().join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let conflicting_keys = Command::new(binary())
        .args(["verify", "--pubkey-pem:TestKeyName-rsa-2048"])
        .arg(&first)
        .arg("--pubkey-pem:TestKeyName-rsa-2048")
        .arg(&second)
        .arg(&signed)
        .output()
        .unwrap();
    assert!(!conflicting_keys.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting_keys.stderr)
            .contains("multiple verification key inputs match template KeyNames")
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
fn positional_sentinel_after_input_is_not_silently_discarded() {
    // Once a filename has ended option parsing, a later `--` is a second
    // filename and must fail the one-input process contract before file access.
    let output = Command::new(binary())
        .args(["verify", "signed.xml", "--"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("expects exactly one input file"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
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
