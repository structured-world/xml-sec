//! Encrypt an XML element for an RSA-OAEP recipient.
//!
//! Run with `cargo run --example encrypt --all-features`. The example uses a
//! test public key solely to demonstrate the API; applications must resolve
//! recipient keys from authenticated configuration or certificate metadata.

use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use xml_sec::xmlenc::{DataEncryptionAlgorithm, EncryptedDataBuilder, EncryptionRecipient};

const PUBLIC_KEY_PEM: &str = include_str!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY_PEM)?;
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .id("encrypted-assertion")
        .add_recipient(
            EncryptionRecipient::rsa_oaep(public_key)
                .recipient("service-provider")
                .key_name("service-provider-rsa"),
        )
        .encrypt_xml(
            r#"<Assertion ID="assertion-1"><Subject>alice@example.com</Subject></Assertion>"#,
        )?;

    println!("{}", encrypted.encrypted_data_xml);
    Ok(())
}
