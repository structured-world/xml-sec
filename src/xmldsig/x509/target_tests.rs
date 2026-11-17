//! `verify_x509_certificate`: a target validated through untrusted
//! intermediates to a caller anchor returns the target's own key, and every
//! way the path can fail is the typed reason, not a key.

use std::time::{Duration, SystemTime};

use super::*;
use crate::policy::{DsaKeyPolicy, ResourcePolicy, RsaKeyPolicy};

fn instant(time: SystemTime) -> Instant {
    crate::policy::instant_from_system_time(time).expect("representable test time")
}

fn options(anchors: &[Vec<u8>], at: SystemTime) -> X509ChainOptions<'_> {
    X509ChainOptions {
        trusted_certs: anchors,
        utc_facts: None,
        verification_time: instant(at),
        max_chain_depth: 10,
        check_crls: false,
        allowed_extended_key_usages: None,
        rsa_keys: RsaKeyPolicy::default(),
        dsa_keys: DsaKeyPolicy::default(),
        certificate_signature_algorithms: None,
    }
}

fn params(name: &str, ca: bool) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    if ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    }
    params
}

/// A root, an intermediate it issued and a leaf the intermediate issued,
/// with the leaf's public key.
struct Chain {
    root: Vec<u8>,
    intermediate: Vec<u8>,
    leaf: Vec<u8>,
    leaf_spki: Vec<u8>,
}

fn chain() -> Chain {
    let root = rcgen::CertifiedIssuer::self_signed(
        params("target root", true),
        rcgen::KeyPair::generate().expect("root key"),
    )
    .expect("root");
    let intermediate = rcgen::CertifiedIssuer::signed_by(
        params("target intermediate", true),
        rcgen::KeyPair::generate().expect("intermediate key"),
        &root,
    )
    .expect("intermediate");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = params("target leaf", false)
        .signed_by(&leaf_key, &intermediate)
        .expect("leaf");
    Chain {
        root: root.der().to_vec(),
        intermediate: intermediate.der().to_vec(),
        leaf: leaf.der().to_vec(),
        leaf_spki: rcgen::PublicKeyData::subject_public_key_info(&leaf_key),
    }
}

#[test]
fn the_target_key_comes_back_through_an_untrusted_intermediate() {
    // An unrelated certificate and the target listed again among the
    // intermediates change nothing: the path is built from the target.
    let chain = chain();
    let unrelated = rcgen::CertifiedIssuer::self_signed(
        params("unrelated", true),
        rcgen::KeyPair::generate().expect("unrelated key"),
    )
    .expect("unrelated")
    .der()
    .to_vec();
    let anchors = vec![chain.root.clone()];
    let verified = verify_x509_certificate(
        &chain.leaf,
        &[unrelated, chain.leaf.clone(), chain.intermediate.clone()],
        &[],
        &options(&anchors, SystemTime::now()),
        &ResourcePolicy::default(),
        crate::provider::default_provider(),
    )
    .expect("a path to the anchor");
    assert_eq!(verified.subject_public_key_info, chain.leaf_spki);
}

#[test]
fn without_a_path_to_an_anchor_there_is_no_key() {
    let chain = chain();
    let anchors = vec![chain.root.clone()];
    // The intermediate is missing, so the leaf's issuer is unknown.
    let missing = verify_x509_certificate(
        &chain.leaf,
        &[],
        &[],
        &options(&anchors, SystemTime::now()),
        &ResourcePolicy::default(),
        crate::provider::default_provider(),
    );
    assert_eq!(missing, Err(X509ChainError::UntrustedRoot));
    // No anchor at all: the complete path still ends untrusted.
    let untrusted = verify_x509_certificate(
        &chain.leaf,
        &[chain.intermediate.clone(), chain.root.clone()],
        &[],
        &options(&[], SystemTime::now()),
        &ResourcePolicy::default(),
        crate::provider::default_provider(),
    );
    assert_eq!(untrusted, Err(X509ChainError::UntrustedRoot));
}

#[test]
fn a_target_outside_its_validity_has_no_key() {
    let chain = chain();
    let anchors = vec![chain.root.clone()];
    // rcgen's certificates are valid from 1975 on.
    let before = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);
    let expired = verify_x509_certificate(
        &chain.leaf,
        &[chain.intermediate.clone()],
        &[],
        &options(&anchors, before),
        &ResourcePolicy::default(),
        crate::provider::default_provider(),
    );
    assert_eq!(expired, Err(X509ChainError::CertificateNotValid(0)));
}

#[test]
fn a_malformed_target_is_refused_as_certificate_processing() {
    let chain = chain();
    let anchors = vec![chain.root.clone()];
    let refused = verify_x509_certificate(
        b"not a certificate",
        &[chain.intermediate],
        &[],
        &options(&anchors, SystemTime::now()),
        &ResourcePolicy::default(),
        crate::provider::default_provider(),
    );
    assert!(
        matches!(
            refused,
            Err(X509ChainError::Processing(_) | X509ChainError::InvalidDer { .. })
        ),
        "{refused:?}"
    );
}

#[test]
fn evidence_beyond_the_aggregate_byte_limit_is_refused_before_parsing() {
    let chain = chain();
    let anchors = vec![chain.root.clone()];
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: chain.leaf.len() + chain.intermediate.len(),
        ..ResourcePolicy::default()
    };
    // The anchor is evidence too, and it no longer fits.
    let refused = verify_x509_certificate(
        &chain.leaf,
        &[chain.intermediate.clone()],
        &[],
        &options(&anchors, SystemTime::now()),
        &resources,
        crate::provider::default_provider(),
    );
    assert_eq!(
        refused,
        Err(X509ChainError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                maximum: resources.max_external_resource_total_bytes,
            }
        ))
    );
}
