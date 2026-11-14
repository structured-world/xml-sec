use super::sign_signature_value;
use crate::policy::{EcdsaSignatureValueEncoding, SigningPolicy};
use crate::xmldsig::{EcdsaP256SigningKey, SignatureAlgorithm, SignatureContext};

#[test]
fn an_ecdsa_value_follows_the_policy_encoding() {
    // A caller signing outside a document gets the representation the
    // policy selects, as document signing writes it: fixed-width r || s by
    // default, an ASN.1 DER SEQUENCE when the policy asks for it.
    let key = EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
    ))
    .expect("P-256 fixture must parse");
    let sign = |encoding| {
        let policy = SigningPolicy {
            ecdsa_signature_value_encoding: encoding,
            ..SigningPolicy::default()
        };
        sign_signature_value(
            &policy,
            crate::provider::default_provider(),
            &key,
            SignatureAlgorithm::EcdsaSha256,
            &SignatureContext::default(),
            b"signed bytes",
        )
        .expect("a permitted method signs")
    };
    assert_eq!(sign(EcdsaSignatureValueEncoding::XmlDsig).len(), 64);
    let der = sign(EcdsaSignatureValueEncoding::XmlSecAsn1Der);
    assert_eq!(der.first(), Some(&0x30), "a DER SEQUENCE");
    assert_ne!(der.len(), 64);
}

#[test]
fn a_method_the_policy_excludes_is_refused() {
    let key = EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
    ))
    .expect("P-256 fixture must parse");
    let policy = SigningPolicy {
        signature_algorithms: Some([SignatureAlgorithm::RsaSha256].into()),
        ..SigningPolicy::default()
    };
    assert!(
        sign_signature_value(
            &policy,
            crate::provider::default_provider(),
            &key,
            SignatureAlgorithm::EcdsaSha256,
            &SignatureContext::default(),
            b"signed bytes",
        )
        .is_err()
    );
}
