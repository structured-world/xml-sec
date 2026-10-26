//! An `XMLDSig` build without `xmldsig-sign`: verification works from public
//! material, while signing, private-key import and randomness are not compiled.
#![cfg(all(
    feature = "xmldsig",
    not(feature = "xmldsig-sign"),
    any(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")
))]

use base64::Engine as _;
use dsa::pkcs8::DecodePublicKey as _;
use xml_sec::XmlBackend;
use xml_sec::key_manager::KeyInventory;
use xml_sec::policy::VerificationPolicy;
use xml_sec::provider::{ProviderCapability, ProviderError, ProviderOperation, default_provider};
use xml_sec::xmldsig::{
    DsigStatus, SignatureAlgorithm, SigningKeyError, verify_signature_with_pem_key,
};

#[test]
fn signatures_verify_from_public_material() {
    // The verification pipeline is complete without any signing component.
    let result = verify_signature_with_pem_key(
        include_str!("fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml"),
        include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        false,
    )
    .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn the_bundled_provider_compiles_no_entropy_source() {
    // Randomness serves signing and encryption only; this build has neither,
    // so the bundled provider reports it unsupported instead of drawing it.
    let provider = default_provider();
    assert!(!provider.supports(ProviderCapability::Random));
    let mut output = [0x5a_u8; 16];
    let error = provider
        .fill_random(&mut output)
        .expect_err("no entropy source is compiled");
    assert!(matches!(
        error,
        ProviderError::Unsupported {
            operation: ProviderOperation::Random,
            algorithm: None,
        }
    ));
    assert_eq!(
        output, [0x5a_u8; 16],
        "output is not consumed after an error"
    );
}

#[test]
fn the_bundled_provider_imports_no_signing_key() {
    // A well-formed PKCS#8 key is still refused: private-key import is not compiled.
    let der = pem::parse(include_str!("fixtures/keys/rsa/rsa-2048-key.pem"))
        .expect("fixture PEM")
        .into_contents();
    let error = default_provider()
        .import_signing_key(SignatureAlgorithm::RsaSha256, &der)
        .err()
        .expect("signing-key import is not compiled");
    assert!(matches!(
        error,
        SigningKeyError::Provider(ProviderError::Unsupported {
            operation: ProviderOperation::Sign,
            ..
        })
    ));
}

/// Unsigned big-endian bytes without leading zeroes (`XMLDSig` `CryptoBinary`).
fn crypto_binary(value: &crypto_bigint::BoxedUint) -> String {
    let bytes = value.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    base64::engine::general_purpose::STANDARD.encode(&bytes[start..])
}

#[test]
fn key_stores_keep_the_public_dsa_tuple_without_its_private_value() {
    // libxmlsec key stores carry DSA X beside the public tuple. Verification
    // needs only the tuple, so a store with an X that does not even match Y
    // imports here; a signing build would derive and reject that private key.
    let key = dsa::VerifyingKey::from_public_key_pem(include_str!(
        "fixtures/xmldsig/keys/dsa/dsa-2048-pubkey.pem"
    ))
    .expect("DSA fixture");
    let components = key.components();
    let xml = format!(
        "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>dsa</KeyName><KeyValue><DSAKeyValue><P>{}</P><Q>{}</Q><G>{}</G><X xmlns=\"http://www.aleksey.com/xmlsec/2002\">AQ==</X><Y>{}</Y></DSAKeyValue></KeyValue></KeyInfo></Keys>",
        crypto_binary(components.p()),
        crypto_binary(components.q()),
        crypto_binary(components.g()),
        crypto_binary(key.y()),
    );
    let inventory = KeyInventory::from_xml_bytes(
        xml.as_bytes(),
        &VerificationPolicy::default(),
        XmlBackend::default(),
    )
    .expect("the public tuple imports");
    assert_eq!(inventory.entry_count(), 1);
    let names: Vec<_> = inventory
        .public_keys()
        .iter()
        .map(|key| key.name.as_str())
        .collect();
    assert_eq!(names, ["dsa"]);
}
