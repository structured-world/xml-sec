use std::{
    fs,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::Document;
use xml_sec::xmldsig::{
    KeyInfoSource, X509ChainError, X509ChainOptions, X509DataInfo, parse_key_info,
    verify_x509_certificate_chain,
};

const VERIFICATION_TIME: u64 = 1_773_964_800; // 2026-03-20T00:00:00Z

fn pem_der(path: impl AsRef<Path>) -> Vec<u8> {
    let pem = fs::read_to_string(path).expect("fixture PEM should be readable");
    let mut inside_pem = false;
    let payload = pem
        .lines()
        .filter(|line| {
            if line.starts_with("-----BEGIN ") {
                inside_pem = true;
                return false;
            }
            if line.starts_with("-----END ") {
                inside_pem = false;
                return false;
            }
            inside_pem
        })
        .collect::<String>();
    STANDARD
        .decode(payload)
        .expect("fixture PEM should contain base64 DER")
}

fn fixture(path: &str) -> Vec<u8> {
    pem_der(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keys")
            .join(path),
    )
}

fn parsed_chain(leaf_path: &str, crl: Option<Vec<u8>>) -> X509DataInfo {
    let leaf = STANDARD.encode(fixture(leaf_path));
    let intermediate = STANDARD.encode(fixture("ca2cert.pem"));
    let root = STANDARD.encode(fixture("cacert.pem"));
    let crl = crl
        .map(|der| format!("<X509CRL>{}</X509CRL>", STANDARD.encode(der)))
        .unwrap_or_default();
    let xml = format!(
        r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>
            <X509Certificate>{root}</X509Certificate>
            <X509Certificate>{leaf}</X509Certificate>
            <X509Certificate>{intermediate}</X509Certificate>
            {crl}
        </X509Data></KeyInfo>"#
    );
    let document = Document::parse(&xml).expect("fixture XML should parse");
    let key_info = parse_key_info(document.root_element()).expect("fixture KeyInfo should parse");
    match key_info
        .sources
        .into_iter()
        .next()
        .expect("X509Data source should exist")
    {
        KeyInfoSource::X509Data(info) => info,
        other => panic!("expected X509Data, got {other:?}"),
    }
}

fn options<'a>(trusted_certs: &'a [Vec<u8>], check_crls: bool) -> X509ChainOptions<'a> {
    X509ChainOptions {
        trusted_certs,
        verification_time: UNIX_EPOCH + Duration::from_secs(VERIFICATION_TIME),
        max_chain_depth: 3,
        check_crls,
    }
}

#[test]
fn validates_unordered_chain_against_explicit_anchor() {
    let info = parsed_chain("rsa/rsa-2048-cert.pem", None);
    let anchors = [fixture("cacert.pem")];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn rejects_chain_without_matching_trust_anchor() {
    let info = parsed_chain("rsa/rsa-2048-cert.pem", None);

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&[], false)),
        Err(X509ChainError::UntrustedRoot)
    );
}

#[test]
fn rejects_expired_leaf_at_selected_verification_time() {
    let info = parsed_chain("rsa/rsa-expired-cert.pem", None);
    let anchors = [fixture("cacert.pem")];
    let mut expired_time = options(&anchors, false);
    expired_time.verification_time = UNIX_EPOCH + Duration::from_secs(1_774_828_800);

    assert_eq!(
        verify_x509_certificate_chain(&info, &expired_time),
        Err(X509ChainError::CertificateNotValid(0))
    );
}

#[test]
fn rejects_path_longer_than_configured_depth() {
    let info = parsed_chain("rsa/rsa-2048-cert.pem", None);
    let anchors = [fixture("cacert.pem")];
    let mut limited = options(&anchors, false);
    limited.max_chain_depth = 2;

    assert_eq!(
        verify_x509_certificate_chain(&info, &limited),
        Err(X509ChainError::DepthExceeded(2))
    );
}

#[test]
fn rejects_certificate_with_tampered_signature() {
    let mut info = parsed_chain("rsa/rsa-2048-cert.pem", None);
    let leaf_index = info.certificate_chain[0];
    let last_byte = info.certificates[leaf_index]
        .last_mut()
        .expect("fixture certificate should not be empty");
    *last_byte ^= 1;
    let anchors = [fixture("cacert.pem")];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::InvalidSignature(0))
    );
}

#[test]
fn rejects_certificate_revoked_by_authenticated_crl() {
    let crl = fixture("rsa/rsa-2048-cert-revoked-crl.pem");
    let info = parsed_chain("rsa/rsa-2048-cert.pem", Some(crl));
    let anchors = [fixture("cacert.pem")];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, true)),
        Err(X509ChainError::Revoked(0))
    );
}

#[test]
fn ignores_supplied_crl_when_revocation_checking_is_disabled() {
    let crl = fixture("rsa/rsa-2048-cert-revoked-crl.pem");
    let info = parsed_chain("rsa/rsa-2048-cert.pem", Some(crl));
    let anchors = [fixture("cacert.pem")];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn rejects_malformed_crl_when_revocation_checking_is_enabled() {
    let info = parsed_chain("rsa/rsa-2048-cert.pem", Some(vec![1, 2, 3]));
    let anchors = [fixture("cacert.pem")];

    assert!(matches!(
        verify_x509_certificate_chain(&info, &options(&anchors, true)),
        Err(X509ChainError::InvalidDer { kind: "CRL", .. })
    ));
}
