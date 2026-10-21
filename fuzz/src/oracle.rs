//! Explicit test-only native oracle. Nothing here enters a product runtime path.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, HmacSigningKey, HmacVerificationKey, KeyInfoWriteError,
    KeyInfoWriter, ReferenceBuilder, SignContext, SignatureAlgorithm, SignatureBuilder, SigningKey,
    Transform, VerifyContext,
};

struct NamedHmac;
impl KeyInfoWriter for NamedHmac {
    fn write_key_info(&self, _: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        Ok("<KeyName>fuzz-hmac</KeyName>".into())
    }
}

fn run(command: &mut Command, diagnostics: &Path) {
    let stderr = std::fs::File::create(diagnostics).expect("oracle diagnostics file");
    let mut process = command
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("explicit XMLSEC1_BIN must execute");
    let start = Instant::now();
    loop {
        if let Some(status) = process.try_wait().expect("oracle status") {
            assert!(
                status.success(),
                "oracle failed: {status}: {}",
                std::fs::read_to_string(diagnostics).expect("oracle diagnostics")
            );
            return;
        }
        if start.elapsed() >= Duration::from_secs(10) {
            process.kill().expect("kill timed-out oracle");
            process.wait().expect("reap timed-out oracle");
            panic!("oracle timed out after 10 seconds");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn xmlsec_oracle(data: &[u8]) {
    let executable =
        std::env::var_os("XMLSEC1_BIN").expect("set the explicitly provisioned XMLSEC1_BIN");
    let data = &data[..data.len().min(1024)];
    let selector = data.first().copied().unwrap_or(0);
    let mode = match selector % 3 {
        0 => C14nMode::Inclusive1_0,
        1 => C14nMode::Inclusive1_1,
        _ => C14nMode::Exclusive1_0,
    };
    let canonical = C14nAlgorithm::new(mode, selector & 4 != 0);
    let builder = SignatureBuilder::new(canonical.clone(), SignatureAlgorithm::HmacSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#target")
                .transform(Transform::C14n(canonical)),
        );
    let text = super::payload(data);
    let xml = format!(
        "<root xmlns:p='urn:fuzz'><p:payload ID='target' a='1'><!--comment-->{text}</p:payload></root>"
    );
    let signer = HmacSigningKey::new(vec![0x42; 32]).expect("fixed oracle test key");
    let verifier = HmacVerificationKey::new(vec![0x42; 32]).expect("fixed oracle test key");
    let directory = tempfile::tempdir().expect("isolated oracle workspace");
    let key = directory.path().join("hmac.bin");
    let native = directory.path().join("native.xml");
    let template = directory.path().join("template.xml");
    let foreign = directory.path().join("foreign.xml");
    let diagnostics = directory.path().join("stderr.txt");
    std::fs::write(&key, [0x42; 32]).expect("test key");
    let signed = SignContext::new(&signer)
        .key_info_writer(&NamedHmac)
        .sign_with_builder(&xml, &builder)
        .expect("native signature");
    std::fs::write(&native, &signed).expect("oracle input");
    let mut verify = Command::new(&executable);
    verify
        .arg("--verify")
        .arg("--hmackey:fuzz-hmac")
        .arg(&key)
        .args([
            "--enabled-reference-uris",
            "empty,same-doc",
            "--id-attr:ID",
            "urn:fuzz:payload",
        ])
        .arg(&native);
    run(&mut verify, &diagnostics);

    // libxmlsec1 1.3.13 defaults to strict KeyInfo selection. Name the
    // explicitly loaded fixture key rather than enabling lax key search.
    let signature = builder
        .build_template()
        .expect("signature template")
        .replace(
            "<KeyInfo/>",
            "<KeyInfo><KeyName>fuzz-hmac</KeyName></KeyInfo>",
        );
    assert!(signature.contains("<KeyName>fuzz-hmac</KeyName>"));
    let template_xml = format!(
        "<root xmlns:p='urn:fuzz'><p:payload ID='target' a='1'><!--comment-->{text}</p:payload>{signature}</root>"
    );
    std::fs::write(&template, template_xml).expect("oracle signing template");
    let mut sign = Command::new(&executable);
    sign.arg("--sign")
        .arg("--hmackey:fuzz-hmac")
        .arg(&key)
        .arg("--output")
        .arg(&foreign)
        .args([
            "--enabled-reference-uris",
            "empty,same-doc",
            "--id-attr:ID",
            "urn:fuzz:payload",
        ])
        .arg(&template);
    run(&mut sign, &diagnostics);
    let signed = std::fs::read_to_string(&foreign).expect("oracle signed output");
    for backend in super::BACKENDS {
        assert_eq!(
            VerifyContext::new()
                .key(&verifier)
                .xml_backend(backend)
                .verify(&signed)
                .expect("oracle signature must verify")
                .status,
            DsigStatus::Valid
        );
    }
}
