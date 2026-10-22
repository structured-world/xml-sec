//! Authorize an expected signed element using an explicitly pinned RSA public key.
//!
//! Run with `cargo run --example verify -- signed.xml public-key.pem expected-id`.
//! The key is trusted application input, not a key selected by the document.
//! This example handles local files; applications must bound their own input I/O.

use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::{SignatureAlgorithm, VerificationKey, VerificationRequest};
use xml_sec::{XmlSecurity, api::Operation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: verify <signed.xml> <public-key.pem> <expected-id>");
        std::process::exit(2);
    }
    let provider = RustCryptoProvider;
    let policies = PolicyCompiler::new(PolicyProfile::Modern, &provider, None)?.compile(
        &PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        },
    )?;
    let security = XmlSecurity::new(&policies, &provider)?;
    let public = pem::parse(std::fs::read(&args[1])?)?;
    if public.tag() != "PUBLIC KEY" {
        return Err("expected a SubjectPublicKeyInfo PUBLIC KEY PEM".into());
    }
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: public.into_contents(),
        certificate_der: None,
        name: None,
    };
    let document =
        security.parse_document(std::fs::read_to_string(&args[0])?, Operation::Verify)?;
    let id = args[2].to_str().ok_or("expected ID must be UTF-8")?;
    let target = document
        .with_view(|view| view.node_for_id(id, &[]))
        .ok_or("expected target ID is absent or ambiguous")?;
    let evidence = security.verifier()?.key(&key).verify(
        &document,
        &VerificationRequest {
            expected_targets: &[target],
            ..Default::default()
        },
    )?;
    if !evidence.accepted(&document)? {
        return Err("expected target was not authenticated".into());
    }
    println!("authenticated target: {id}");
    Ok(())
}
