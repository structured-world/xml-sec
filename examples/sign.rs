//! Sign an XML document with an enveloped RSA-SHA256 XMLDSig signature.
//!
//! Run with `cargo run --example sign --all-features`. The example uses test
//! credentials solely to demonstrate the API; applications must load their own
//! PKCS#8 private key and matching X.509 certificate from secure storage.

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
    SignatureBuilder, Transform, X509CertificateKeyInfoWriter,
};

const PRIVATE_KEY_PEM: &str = include_str!("../tests/fixtures/keys/rsa/rsa-2048-key.pem");
const CERTIFICATE_PEM: &str = include_str!("../tests/fixtures/keys/rsa/rsa-2048-cert.pem");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let unsigned = r#"<Invoice ID="invoice-2026-07"><Amount>42.00</Amount></Invoice>"#;
    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let signature_template = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#invoice-2026-07")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(c14n)),
        )
        .build_template()?;

    let signing_key = RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY_PEM)?;
    let key_info = X509CertificateKeyInfoWriter::from_pem(CERTIFICATE_PEM)?;
    let signed = SignContext::new(&signing_key)
        .key_info_writer(&key_info)
        .sign_template(&xml_sec::xmldsig::mutation::append_signature_to_root(
            unsigned,
            &signature_template,
        )?)?;

    println!("{signed}");
    Ok(())
}
