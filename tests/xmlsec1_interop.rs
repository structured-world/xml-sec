//! XMLDSig signing interoperability checks against the external xmlsec1 CLI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, EcdsaP256SigningKey, EcdsaP384SigningKey,
    FailureReason, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
    SignatureBuilder, SigningKey, Transform, VerifyContext,
};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryXmlFile {
    path: PathBuf,
}

impl TemporaryXmlFile {
    fn write(label: &str, contents: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos();
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "xml-sec-{label}-{}-{timestamp}-{sequence}.xml",
            std::process::id(),
        ));
        fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
        Self { path }
    }
}

impl Drop for TemporaryXmlFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn signing_builder(algorithm: SignatureAlgorithm, digest: DigestAlgorithm) -> SignatureBuilder {
    SignatureBuilder::new(exclusive_c14n(), algorithm).add_reference(
        ReferenceBuilder::new(digest)
            .uri("#payload")
            .transform(Transform::Enveloped)
            .transform(Transform::C14n(exclusive_c14n())),
    )
}

fn xmlsec1_version_supports_interop(version: &str) -> bool {
    version
        .split_whitespace()
        .find_map(|token| {
            let mut components = token.split('.');
            Some((
                components.next()?.parse::<u16>().ok()?,
                components.next()?.parse::<u16>().ok()?,
            ))
        })
        .is_some_and(|(major, minor)| major > 1 || (major == 1 && minor >= 3))
}

fn xmlsec1_is_available() -> bool {
    let Ok(output) = Command::new("xmlsec1").arg("--version").output() else {
        return false;
    };

    output.status.success()
        && std::str::from_utf8(&output.stdout).is_ok_and(xmlsec1_version_supports_interop)
}

#[test]
fn xmlsec1_version_gate_requires_add_id_attr_support() {
    assert!(xmlsec1_version_supports_interop("xmlsec1 1.3.0 (openssl)"));
    assert!(xmlsec1_version_supports_interop("xmlsec1 1.3.12 (openssl)"));
    assert!(xmlsec1_version_supports_interop("xmlsec1 2.0.0 (openssl)"));
    assert!(!xmlsec1_version_supports_interop(
        "xmlsec1 1.2.37 (openssl)"
    ));
    assert!(!xmlsec1_version_supports_interop("xmlsec1 unknown"));
}

fn signed_payload_xml(key: &dyn SigningKey, builder: &SignatureBuilder) -> String {
    SignContext::new(key)
        .sign_with_builder(
            "<root ID=\"payload\"><payload>external verifier contract</payload></root>",
            builder,
        )
        .expect("xml-sec must sign the XMLDSig payload")
}

#[test]
fn interop_fixture_references_the_enveloped_root() {
    // This CLI-independent check ensures the reciprocal tests cover excluding
    // the appended Signature from the signed root node set.
    let template = signing_builder(SignatureAlgorithm::RsaSha256, DigestAlgorithm::Sha256)
        .build_template()
        .expect("interop template must build");
    let xml = xml_sec::xmldsig::mutation::append_signature_to_root(
        "<root ID=\"payload\"><payload>external verifier contract</payload></root>",
        &template,
    )
    .expect("interop fixture must append a signature");

    assert!(xml.contains("URI=\"#payload\""));
    assert!(xml.contains("<root ID=\"payload\""));
    assert!(xml.contains("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\""));
}

fn verify_with_xmlsec1(signed_xml: &str, public_key: &Path) -> std::process::Output {
    let input = TemporaryXmlFile::write("xmlsec1-interop", signed_xml);
    Command::new("xmlsec1")
        .arg("--verify")
        .arg("--lax-key-search")
        .arg("--add-id-attr")
        .arg("ID")
        .arg("--pubkey-pem")
        .arg(public_key)
        .arg(&input.path)
        .output()
        .expect("xmlsec1 must be installed to run XMLDSig interoperability tests")
}

fn sign_with_xmlsec1(
    template: &Path,
    key_name: &str,
    private_key: &Path,
    certificate: &Path,
) -> String {
    let output_file = TemporaryXmlFile::write("xmlsec1-signed", "");
    let key_and_certificate = format!("{},{}", private_key.display(), certificate.display());
    let output = Command::new("xmlsec1")
        .arg("--sign")
        .arg("--add-id-attr")
        .arg("Id")
        .arg(format!("--privkey-pem:{key_name}"))
        .arg(key_and_certificate)
        .arg("--output")
        .arg(&output_file.path)
        .arg(template)
        .output()
        .expect("xmlsec1 must be installed to create XMLDSig interop fixtures");
    assert!(
        output.status.success(),
        "xmlsec1 failed to sign its template:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::read_to_string(&output_file.path).unwrap_or_else(|error| {
        panic!(
            "failed to read xmlsec1 output {}: {error}",
            output_file.path.display()
        )
    })
}

fn assert_xmlsec1_accepts(signed_xml: &str, public_key: &str) {
    let output = verify_with_xmlsec1(signed_xml, Path::new(public_key));
    assert!(
        output.status.success(),
        "xmlsec1 rejected a signature created by xml-sec:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn xmlsec1_verifies_rsa_sha256_signature_from_xml_sec() {
    // A separate implementation must accept the generated enveloped signature,
    // including its reference digest, exclusive C14N, and RSA SignatureValue.
    if !xmlsec1_is_available() {
        eprintln!("skipping xmlsec1 interoperability test: xmlsec1 is not installed");
        return;
    }

    let key = RsaSigningKey::from_pkcs8_pem(
        &fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
            .expect("RSA private-key fixture must load"),
    )
    .expect("RSA private-key fixture must parse");

    let signed = signed_payload_xml(
        &key,
        &signing_builder(SignatureAlgorithm::RsaSha256, DigestAlgorithm::Sha256),
    );

    assert_xmlsec1_accepts(&signed, "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
}

#[test]
fn xmlsec1_verifies_ecdsa_signatures_from_xml_sec() {
    // P-256 and P-384 prove that xml-sec emits XMLDSig raw r||s values that
    // xmlsec1 accepts for both supported ECDSA curve widths.
    if !xmlsec1_is_available() {
        eprintln!("skipping xmlsec1 interoperability test: xmlsec1 is not installed");
        return;
    }

    let p256_key = EcdsaP256SigningKey::from_pkcs8_pem(
        &fs::read_to_string("tests/fixtures/keys/ec/ec-prime256v1-key.pem")
            .expect("P-256 private-key fixture must load"),
    )
    .expect("P-256 private-key fixture must parse");
    let p384_key = EcdsaP384SigningKey::from_pkcs8_pem(
        &fs::read_to_string("tests/fixtures/keys/ec/ec-prime384v1-key.pem")
            .expect("P-384 private-key fixture must load"),
    )
    .expect("P-384 private-key fixture must parse");

    let p256_signed = signed_payload_xml(
        &p256_key,
        &signing_builder(SignatureAlgorithm::EcdsaP256Sha256, DigestAlgorithm::Sha256),
    );
    assert_xmlsec1_accepts(
        &p256_signed,
        "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
    );

    let p384_signed = signed_payload_xml(
        &p384_key,
        &signing_builder(SignatureAlgorithm::EcdsaP384Sha384, DigestAlgorithm::Sha384),
    );
    assert_xmlsec1_accepts(
        &p384_signed,
        "tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem",
    );
}

#[test]
fn xmlsec1_rejects_tampered_signature_from_xml_sec() {
    // The external verifier must reject a changed signed payload, proving the
    // test is exercising validation rather than merely command invocation.
    if !xmlsec1_is_available() {
        eprintln!("skipping xmlsec1 interoperability test: xmlsec1 is not installed");
        return;
    }

    let key = RsaSigningKey::from_pkcs8_pem(
        &fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
            .expect("RSA private-key fixture must load"),
    )
    .expect("RSA private-key fixture must parse");
    let signed = signed_payload_xml(
        &key,
        &signing_builder(SignatureAlgorithm::RsaSha256, DigestAlgorithm::Sha256),
    );
    let tampered = signed.replacen("external verifier contract", "tampered payload", 1);

    let output = verify_with_xmlsec1(
        &tampered,
        Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
    );
    assert!(
        !output.status.success(),
        "xmlsec1 accepted a tampered XMLDSig document:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn xml_sec_verifies_xmlsec1_signatures_with_embedded_certificates() {
    // xmlsec1 must create signatures that our full pipeline accepts through
    // the embedded X509Data resolver, not through a separately injected key.
    if !xmlsec1_is_available() {
        eprintln!("skipping xmlsec1 interoperability test: xmlsec1 is not installed");
        return;
    }

    let resolver = DefaultKeyResolver::default();
    for (template, key_name, private_key, certificate) in [
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl",
            "TestKeyName-rsa-2048",
            "tests/fixtures/keys/rsa/rsa-2048-key.pem",
            "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
        ),
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-ecdsa-sha256.tmpl",
            "TestKeyName-ec-prime256v1",
            "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
            "tests/fixtures/keys/ec/ec-prime256v1-cert.pem",
        ),
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-ecdsa-sha384.tmpl",
            "TestKeyName-ec-prime384v1",
            "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
            "tests/fixtures/keys/ec/ec-prime384v1-cert.pem",
        ),
    ] {
        let signed = sign_with_xmlsec1(
            Path::new(template),
            key_name,
            Path::new(private_key),
            Path::new(certificate),
        );
        let result = VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&signed)
            .unwrap_or_else(|error| panic!("xml-sec failed to process xmlsec1 output: {error}"));

        assert_eq!(result.status, DsigStatus::Valid, "{template}");
    }
}

#[test]
fn xml_sec_rejects_tampered_xmlsec1_signature_before_crypto_verification() {
    // Mutating the signed Object must fail reference validation before the
    // verifier reaches SignatureValue cryptography, matching XMLDSig fail-fast.
    if !xmlsec1_is_available() {
        eprintln!("skipping xmlsec1 interoperability test: xmlsec1 is not installed");
        return;
    }

    let signed = sign_with_xmlsec1(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl"),
        "TestKeyName-rsa-2048",
        Path::new("tests/fixtures/keys/rsa/rsa-2048-key.pem"),
        Path::new("tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
    );
    let tampered = signed.replacen("some text", "modified text", 1);
    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&tampered)
        .expect("tampered XMLDSig must be a completed invalid verification");

    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}
