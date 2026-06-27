use std::{
    fs,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber, date_time_ymd,
};
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

fn generated_chain(
    root_constraints: BasicConstraints,
    intermediate_is_ca: IsCa,
    intermediate_key_usages: Vec<KeyUsagePurpose>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut root_params = CertificateParams::new(Vec::new()).unwrap();
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "root");
    root_params.is_ca = IsCa::Ca(root_constraints);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root =
        rcgen::CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

    let mut intermediate_params = CertificateParams::new(Vec::new()).unwrap();
    intermediate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "intermediate");
    intermediate_params.is_ca = intermediate_is_ca;
    intermediate_params.key_usages = intermediate_key_usages;
    let intermediate =
        rcgen::CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root)
            .unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &intermediate)
        .unwrap();

    (
        leaf.der().to_vec(),
        intermediate.der().to_vec(),
        root.der().to_vec(),
    )
}

fn generated_info(certificates: Vec<Vec<u8>>) -> X509DataInfo {
    let mut info = X509DataInfo::default();
    info.certificate_chain = (0..certificates.len()).collect();
    info.certificates = certificates;
    info
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
fn validates_chain_completed_by_external_anchor() {
    let (leaf, intermediate, root) = generated_chain(
        BasicConstraints::Unconstrained,
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
    );
    let info = generated_info(vec![leaf, intermediate]);
    let anchors = [root];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn rejects_malformed_configured_anchor_even_when_another_anchor_matches() {
    let info = parsed_chain("rsa/rsa-2048-cert.pem", None);
    let anchors = [vec![1, 2, 3], fixture("cacert.pem")];

    assert!(matches!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::InvalidDer {
            kind: "certificate",
            ..
        })
    ));
}

#[test]
fn selects_signature_verifying_anchor_when_subjects_match() {
    let mut first_params = CertificateParams::new(Vec::new()).unwrap();
    first_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    first_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    first_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let first =
        rcgen::CertifiedIssuer::self_signed(first_params, KeyPair::generate().unwrap()).unwrap();

    let mut second_params = CertificateParams::new(Vec::new()).unwrap();
    second_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    second_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    second_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let second =
        rcgen::CertifiedIssuer::self_signed(second_params, KeyPair::generate().unwrap()).unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &second)
        .unwrap();
    let info = generated_info(vec![leaf.der().to_vec()]);
    let anchors = [first.der().to_vec(), second.der().to_vec()];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn selects_fully_valid_anchor_when_signing_keys_match() {
    let anchor_key = KeyPair::generate().unwrap();
    let anchor_key_der = anchor_key.serialize_der();

    let mut expired_params = CertificateParams::new(Vec::new()).unwrap();
    expired_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    expired_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    expired_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    expired_params.not_before = date_time_ymd(2020, 1, 1);
    expired_params.not_after = date_time_ymd(2021, 1, 1);
    let expired = rcgen::CertifiedIssuer::self_signed(
        expired_params,
        KeyPair::try_from(anchor_key_der.as_slice()).unwrap(),
    )
    .unwrap();

    let mut valid_params = CertificateParams::new(Vec::new()).unwrap();
    valid_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    valid_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    valid_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let valid = rcgen::CertifiedIssuer::self_signed(valid_params, anchor_key).unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &valid)
        .unwrap();
    let info = generated_info(vec![leaf.der().to_vec()]);
    let anchors = [expired.der().to_vec(), valid.der().to_vec()];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn replaces_embedded_rollover_root_with_trusted_anchor() {
    let root_key = KeyPair::generate().unwrap();
    let root_key_der = root_key.serialize_der();

    let mut expired_params = CertificateParams::new(Vec::new()).unwrap();
    expired_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    expired_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    expired_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    expired_params.not_before = date_time_ymd(2020, 1, 1);
    expired_params.not_after = date_time_ymd(2021, 1, 1);
    let expired = rcgen::CertifiedIssuer::self_signed(expired_params, root_key).unwrap();

    let mut renewed_params = CertificateParams::new(Vec::new()).unwrap();
    renewed_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "shared root");
    renewed_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    renewed_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let renewed = rcgen::CertifiedIssuer::self_signed(
        renewed_params,
        KeyPair::try_from(root_key_der.as_slice()).unwrap(),
    )
    .unwrap();

    let mut intermediate_params = CertificateParams::new(Vec::new()).unwrap();
    intermediate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let intermediate = rcgen::CertifiedIssuer::signed_by(
        intermediate_params,
        KeyPair::generate().unwrap(),
        &expired,
    )
    .unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &intermediate)
        .unwrap();
    let info = generated_info(vec![
        leaf.der().to_vec(),
        intermediate.der().to_vec(),
        expired.der().to_vec(),
    ]);
    let anchors = [renewed.der().to_vec()];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Ok(())
    );
}

#[test]
fn rejects_leaf_without_signature_key_usage() {
    let mut root_params = CertificateParams::new(Vec::new()).unwrap();
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root =
        rcgen::CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &root)
        .unwrap();
    let info = generated_info(vec![leaf.der().to_vec()]);
    let anchors = [root.der().to_vec()];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::InvalidKeyUsage {
            position: 0,
            required: "digitalSignature or nonRepudiation",
        })
    );
}

#[test]
fn rejects_non_ca_issuer() {
    let (leaf, intermediate, root) = generated_chain(
        BasicConstraints::Unconstrained,
        IsCa::NoCa,
        vec![KeyUsagePurpose::KeyCertSign],
    );
    let info = generated_info(vec![leaf, intermediate, root.clone()]);
    let anchors = [root];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::IssuerNotCa(1))
    );
}

#[test]
fn rejects_ca_without_key_cert_sign_usage() {
    let (leaf, intermediate, root) = generated_chain(
        BasicConstraints::Unconstrained,
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::DigitalSignature],
    );
    let info = generated_info(vec![leaf, intermediate, root.clone()]);
    let anchors = [root];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::InvalidKeyUsage {
            position: 1,
            required: "keyCertSign",
        })
    );
}

#[test]
fn rejects_path_length_constraint_violation() {
    let (leaf, intermediate, root) = generated_chain(
        BasicConstraints::Constrained(0),
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
    );
    let info = generated_info(vec![leaf, intermediate, root.clone()]);
    let anchors = [root];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, false)),
        Err(X509ChainError::PathLengthExceeded {
            position: 2,
            limit: 0
        })
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

#[test]
fn rejects_crl_signed_by_certificate_without_crl_sign_usage() {
    let mut root_params = CertificateParams::new(Vec::new()).unwrap();
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root =
        rcgen::CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

    let issuer_key = KeyPair::generate().unwrap();
    let mut cert_params = CertificateParams::new(Vec::new()).unwrap();
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "issuer");
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let issuer_cert = cert_params.signed_by(&issuer_key, &root).unwrap();

    let mut signing_params = CertificateParams::new(Vec::new()).unwrap();
    signing_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "issuer");
    signing_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    signing_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer = Issuer::new(signing_params, issuer_key);

    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf");
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().unwrap(), &issuer)
        .unwrap();
    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 3, 15),
        next_update: date_time_ymd(2026, 4, 15),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap();
    let mut info = generated_info(vec![
        leaf.der().to_vec(),
        issuer_cert.der().to_vec(),
        root.der().to_vec(),
    ]);
    info.crls.push(crl.der().to_vec());
    let anchors = [root.der().to_vec()];

    assert_eq!(
        verify_x509_certificate_chain(&info, &options(&anchors, true)),
        Err(X509ChainError::InvalidKeyUsage {
            position: 1,
            required: "cRLSign",
        })
    );
}
