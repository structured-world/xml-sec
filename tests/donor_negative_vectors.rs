//! Negative `XMLDSig` vectors from the Phaos interoperability corpus.
//!
//! Each check targets the first stable rejection boundary in the public API.
//! The historical fixtures combine invalid signatures with advisory X.509
//! metadata, so tests that exercise `SignedInfo` validation supply a caller key
//! and deliberately bypass document `KeyInfo` resolution.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x509_parser::prelude::{FromDer, X509Certificate};
use xml_sec::XmlDomDocument as Document;
use xml_sec::policy::PolicyViolation;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, KeyInfoSource, KeyResolverConfig, ParseError,
    SignatureAlgorithm, SignatureVerificationError, VerificationKey, VerifyContext, X509ChainError,
    X509ChainOptions, X509DataInfo, parse_key_info, verify_signature_with_pem_key,
    verify_x509_certificate_chain,
};

const PHAOS_DIR: &str = "tests/fixtures/xmldsig/phaos-xmldsig-three";
const STRONG_RSA_PUBLIC_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");
const PHAOS_RSA_CERTIFICATE: &[u8] =
    include_bytes!("fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-cert.der");
const PHAOS_RSA_CA_CERTIFICATE: &[u8] =
    include_bytes!("fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-ca-cert.der");

/// A whole-hour instant after the Unix epoch.
fn hours_after_epoch(hours: i64) -> xml_sec::policy::Instant {
    xml_sec::policy::Instant::new(hours * 3600, 0).unwrap()
}

fn read_vector(name: &str) -> String {
    let path = Path::new(PHAOS_DIR).join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn phaos_x509_data() -> X509DataInfo {
    let xml = format!(
        concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>",
            "<X509Certificate>{}</X509Certificate>",
            "<X509Certificate>{}</X509Certificate>",
            "</X509Data></KeyInfo>"
        ),
        STANDARD.encode(PHAOS_RSA_CERTIFICATE),
        STANDARD.encode(PHAOS_RSA_CA_CERTIFICATE),
    );
    let document = Document::parse(&xml).expect("Phaos certificate wrapper must parse");
    let key_info = parse_key_info(document.root_element()).expect("Phaos chain must parse");
    match key_info
        .sources
        .into_iter()
        .next()
        .expect("Phaos chain must produce X509Data")
    {
        KeyInfoSource::X509Data(info) => info,
        other => panic!("expected X509Data, got {other:?}"),
    }
}

fn phaos_verification_key() -> VerificationKey {
    let (rest, certificate) = X509Certificate::from_der(PHAOS_RSA_CERTIFICATE)
        .expect("Phaos RSA certificate must be valid DER");
    assert!(rest.is_empty(), "Phaos certificate must consume all DER");
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha1,
        public_key_bytes: certificate.public_key().raw.to_vec(),
        certificate_der: Some(PHAOS_RSA_CERTIFICATE.to_vec()),
        name: None,
    }
}

#[test]
fn phaos_bad_digest_vector_is_refused_at_the_key_before_any_reference() {
    // The key is checked before SignedInfo or any Reference (W3C XML Signature
    // Best Practices BP1): the donor's 1024-bit RSA key fails the default size
    // policy, so the altered DigestValue is never reached.
    let xml = read_vector("signature-rsa-enveloped-bad-digest-val.xml");
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::RsaSha1);
    let key = phaos_verification_key();
    let error = VerifyContext::new()
        .policy(policy)
        .key(&key)
        .verify(&xml)
        .expect_err("an undersized key is refused before reference work");

    assert!(
        matches!(
            error,
            DsigError::Crypto(SignatureVerificationError::KeyPolicy(
                PolicyViolation::KeySize {
                    actual_bits: 1024,
                    ..
                }
            ))
        ),
        "unexpected refusal: {error:?}"
    );
}

#[test]
fn phaos_bad_signature_artifact_fails_on_its_unsupported_md5_reference() {
    // Despite its filename, the donor adds a second Reference using MD5 and
    // omits DigestValue. Without legacy capability the URI fails first;
    // with it, the missing mandatory DigestValue fails structural parsing.
    let xml = read_vector("signature-rsa-enveloped-bad-sig.xml");
    let error = verify_signature_with_pem_key(&xml, STRONG_RSA_PUBLIC_KEY, false)
        .expect_err("unsupported donor Reference must fail processing");

    #[cfg(not(feature = "legacy-algorithms"))]
    assert!(matches!(
        error,
        DsigError::ParseSignedInfo(ParseError::UnsupportedAlgorithm { ref uri })
            if uri == "http://www.w3.org/2001/04/xmldsig-more#md5"
    ));
    #[cfg(feature = "legacy-algorithms")]
    assert!(matches!(
        error,
        DsigError::ParseSignedInfo(ParseError::MissingElement {
            element: "DigestValue"
        })
    ));
}

#[test]
fn phaos_valid_baseline_rejects_legacy_rsa_key_policy() {
    // References in the historical positive vector are valid, but RSA-SHA1 is
    // rejected by the default verification policy before backend key handling.
    let xml = read_vector("signature-rsa-enveloped.xml");
    let key = phaos_verification_key();
    let error = VerifyContext::new()
        .key(&key)
        .verify(&xml)
        .expect_err("legacy Phaos RSA key must remain rejected");

    assert!(matches!(
        error,
        DsigError::Policy(PolicyViolation::Algorithm {
            operation: "verification",
            ..
        })
    ));
}

#[test]
fn pre_resolved_rsa_key_obeys_the_operation_strength_policy() {
    // Direct keys and resolver-produced keys must enforce the same immutable
    // operation policy; changing the key source must never weaken trust.
    let xml = read_vector("signature-rsa-enveloped.xml");
    let key = phaos_verification_key();
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::RsaSha1);
    policy.key_trust.rsa_keys.minimum_modulus_bits = 2048;

    let error = VerifyContext::new()
        .policy(policy)
        .key(&key)
        .verify(&xml)
        .expect_err("the 1024-bit direct key must not bypass the 2048-bit policy");

    assert!(matches!(
        error,
        DsigError::Crypto(SignatureVerificationError::KeyPolicy(
            PolicyViolation::KeySize {
                operation: "verification",
                key_type: "RSA",
                minimum_bits: 2048,
                maximum_bits: 8192,
                actual_bits: 1024,
            }
        ))
    ));
}

#[test]
fn fuzz_seed_reaches_valid_signature_verification() {
    // The bounded CI fuzz run starts from a complete document so mutations can
    // reach transforms, digesting, X.509 resolution, and signature verification.
    let xml = std::fs::read_to_string("fuzz/corpus/xmldsig_verify/signature.xml")
        .expect("fuzz seed must be readable");
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::RsaSha1);
    policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: vec![PHAOS_RSA_CERTIFICATE.to_vec()],
        ..KeyResolverConfig::default()
    });

    policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;

    let result = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify(&xml)
        .expect("complete fuzz seed must traverse the verification pipeline");

    assert_eq!(result.status, DsigStatus::Valid);
    assert!(
        result
            .signed_info_references
            .iter()
            .all(|reference| reference.status == DsigStatus::Valid)
    );
}

#[test]
fn phaos_certificate_chain_is_expired_at_a_modern_verification_time() {
    // The Phaos leaf and CA expired in 2012. A deterministic 2026 verification
    // time must reject the leaf before its key can establish trust.
    let info = phaos_x509_data();
    let trusted = vec![PHAOS_RSA_CA_CERTIFICATE.to_vec()];
    let options = X509ChainOptions {
        trusted_certs: &trusted,
        verification_time: hours_after_epoch(490_896),
        utc_facts: None,
        max_chain_depth: 2,
        check_crls: false,
        allowed_extended_key_usages: None,
        rsa_keys: xml_sec::policy::RsaKeyPolicy::default(),
        dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
        certificate_signature_algorithms: None,
    };

    assert_eq!(
        verify_x509_certificate_chain(&info, &options),
        Err(X509ChainError::CertificateNotValid(0))
    );
}

#[test]
fn x509_path_enforces_configured_issuer_rsa_minimum() {
    // Cryptographic providers authenticate signatures; deployment key strength
    // belongs to the compiled path policy and must reject this historical CA.
    // Isolate strength from Phaos's non-DER KeyUsage, which the shared decoder
    // correctly rejects before the issuer signature callback can run.
    let issuer_key = rcgen::KeyPair::from_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem"))
        .expect("RSA issuer key fixture");
    let mut issuer_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "RSA strength authority");
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let issuer = rcgen::CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "RSA strength signer");
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let leaf = leaf_params
        .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
        .unwrap();
    let trusted = vec![issuer.der().to_vec()];
    let mut info = X509DataInfo::default();
    info.certificates = vec![leaf.der().to_vec(), issuer.der().to_vec()];
    info.certificate_chain = vec![0, 1];
    let mut options = X509ChainOptions {
        utc_facts: None,
        trusted_certs: &trusted,
        verification_time: xml_sec::policy::instant_from_system_time(std::time::SystemTime::now())
            .unwrap(),
        max_chain_depth: 2,
        check_crls: false,
        allowed_extended_key_usages: None,
        rsa_keys: xml_sec::policy::RsaKeyPolicy::default(),
        dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
        certificate_signature_algorithms: None,
    };

    verify_x509_certificate_chain(&info, &options).expect("canonical chain meets default minimum");
    options.rsa_keys.minimum_modulus_bits = 3072;

    assert!(matches!(
        verify_x509_certificate_chain(&info, &options),
        Err(X509ChainError::KeyPolicy {
            position: 1,
            source: PolicyViolation::KeySize {
                key_type: "RSA",
                minimum_bits: 3072,
                actual_bits: 2048,
                ..
            }
        })
    ));
}

#[test]
fn phaos_non_der_key_usage_cannot_establish_certificate_trust() {
    // X.690 (2021) 11.2.2 removes every trailing zero from a named bit list;
    // Phaos's 03 03 07 D8 00 is not DER. Cryptographic XML corpus success
    // must never be interpreted as acceptance of this certificate path.
    // https://www.itu.int/rec/T-REC-X.690-202102-I/en
    let info = phaos_x509_data();
    let trusted = vec![PHAOS_RSA_CA_CERTIFICATE.to_vec()];
    let options = X509ChainOptions {
        trusted_certs: &trusted,
        verification_time: hours_after_epoch(306_828),
        utc_facts: None,
        max_chain_depth: 2,
        check_crls: false,
        allowed_extended_key_usages: None,
        rsa_keys: xml_sec::policy::RsaKeyPolicy {
            minimum_modulus_bits: 1024,
        },
        dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
        certificate_signature_algorithms: None,
    };
    assert_eq!(
        verify_x509_certificate_chain(&info, &options),
        Err(X509ChainError::UnsupportedCriticalExtension {
            position: 0,
            oid: "2.5.29.15".into()
        })
    );
}
