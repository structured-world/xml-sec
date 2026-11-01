//! Interoperability checks that read the donor checkout, which is not packaged.

use std::fs;
use std::path::Path;

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

use xml_sec::policy::{EcdsaSignatureValueEncoding, VerificationPolicy};
use xml_sec::xmldsig::{DsigStatus, SignatureAlgorithm, VerificationKey, VerifyContext};

#[test]
fn asn1_ecdsa_compatibility_matches_pinned_xmlsec1() {
    // The upstream vector is intentionally invalid under XMLDSig framing and
    // valid only when both implementations select libxmlsec1's ASN.1 mode.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let fixture = Path::new(
        "donors/xmlsec/tests/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256-with-asn1.xml",
    );
    let public_key = Path::new("donors/xmlsec/tests/keys/ec/ec-prime256v1-pubkey.pem");
    let donor_key_option = "--pubkey-pem:TestKeyName-ec-prime256v1";

    let donor_default = xmlsec1::command()
        .args(["--verify", donor_key_option])
        .arg(public_key)
        .arg(fixture)
        .output()
        .expect("pinned xmlsec1 must run");
    assert!(!donor_default.status.success());
    let donor_compatible = xmlsec1::command()
        .args([
            "--verify",
            "--enable-asn1-signatures-hack",
            donor_key_option,
        ])
        .arg(public_key)
        .arg(fixture)
        .output()
        .expect("pinned xmlsec1 must run");
    assert!(
        donor_compatible.status.success(),
        "{}",
        String::from_utf8_lossy(&donor_compatible.stderr)
    );

    let xml = fs::read_to_string(fixture).expect("upstream ASN.1 fixture must load");
    let (_, pem) = x509_parser::pem::parse_x509_pem(&fs::read(public_key).unwrap())
        .expect("upstream EC public key must parse");
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::EcdsaSha256,
        public_key_bytes: pem.contents,
        certificate_der: None,
        name: Some("TestKeyName-ec-prime256v1".into()),
    };
    assert!(VerifyContext::new().key(&key).verify(&xml).is_err());
    let policy = VerificationPolicy {
        ecdsa_signature_value_encoding: EcdsaSignatureValueEncoding::XmlSecAsn1Der,
        ..VerificationPolicy::default()
    };
    let native = VerifyContext::new()
        .key(&key)
        .policy(policy)
        .verify(&xml)
        .expect("native ASN.1 compatibility verification must run");
    assert_eq!(native.status, DsigStatus::Valid);
}
