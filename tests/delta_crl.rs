#![cfg(feature = "xmldsig")]
//! RFC 5280 5.2.4 and 6.3.3 complete-plus-delta evaluation through the public
//! chain API. Every list is really signed by the path's issuing key.

use der::{Decode as _, Encode as _, asn1::BitString};
use rcgen::SigningKey as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    date_time_ymd,
};
use time::OffsetDateTime;
use x509_cert::ext::pkix::crl::dp::{IssuingDistributionPoint, Reasons};
use xml_sec::policy::Instant;
use xml_sec::xmldsig::{
    X509ChainError, X509ChainOptions, X509DataInfo, verify_x509_certificate_chain,
};

const VERIFICATION_TIME: i64 = 1_773_964_800; // 2026-03-20T00:00:00Z
const LEAF_SERIAL: u64 = 0x51;
const INTERMEDIATE_SERIAL: u64 = 0x52;
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";

type Issuer = CertifiedIssuer<'static, KeyPair>;

fn current() -> (OffsetDateTime, OffsetDateTime) {
    (date_time_ymd(2026, 3, 15), date_time_ymd(2026, 4, 15))
}

fn expired() -> (OffsetDateTime, OffsetDateTime) {
    (date_time_ymd(2026, 2, 1), date_time_ymd(2026, 3, 1))
}

fn root_named(name: &str) -> Issuer {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

/// Leaf directly under `issuer`, with a serial the lists below can name.
fn leaf_of(issuer: &Issuer) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.serial_number = Some(SerialNumber::from(LEAF_SERIAL));
    params.use_authority_key_identifier_extension = true;
    params
        .signed_by(&KeyPair::generate().unwrap(), issuer)
        .unwrap()
        .der()
        .to_vec()
}

fn entry(serial: u64, reason: Option<RevocationReason>) -> RevokedCertParams {
    RevokedCertParams {
        serial_number: SerialNumber::from(serial),
        revocation_time: date_time_ymd(2026, 3, 10),
        reason_code: reason,
        invalidity_date: None,
    }
}

/// One list as rcgen writes it: crlNumber and authorityKeyIdentifier included.
fn list(
    issuer: &Issuer,
    number: u64,
    (this_update, next_update): (OffsetDateTime, OffsetDateTime),
    revoked_certs: Vec<RevokedCertParams>,
) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .der()
    .to_vec()
}

/// Add extensions to a signed list and sign the result again.
fn extended(
    issuer: &Issuer,
    list: &[u8],
    extensions: impl IntoIterator<Item = x509_cert::ext::Extension>,
) -> Vec<u8> {
    let mut encoded: x509_cert::crl::CertificateList =
        x509_cert::crl::CertificateList::from_der(list).unwrap();
    encoded
        .tbs_cert_list
        .crl_extensions
        .as_mut()
        .unwrap()
        .extend(extensions);
    let signature = issuer
        .key()
        .sign(&encoded.tbs_cert_list.to_der().unwrap())
        .unwrap();
    encoded.signature = BitString::from_bytes(&signature).unwrap();
    encoded.to_der().unwrap()
}

fn extension(oid: &str, critical: bool, value: Vec<u8>) -> x509_cert::ext::Extension {
    x509_cert::ext::Extension {
        extn_id: der::asn1::ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: der::asn1::OctetString::new(value).unwrap(),
    }
}

/// The `BaseCRLNumber` value of `deltaCRLIndicator`, as a DER INTEGER.
fn base_number(base: u8) -> Vec<u8> {
    assert!(base < 0x80, "one positive content octet");
    vec![0x02, 0x01, base]
}

fn indicator(base: u8) -> x509_cert::ext::Extension {
    extension(DELTA_CRL_INDICATOR, true, base_number(base))
}

fn delta(
    issuer: &Issuer,
    number: u64,
    base: u8,
    window: (OffsetDateTime, OffsetDateTime),
    revoked: Vec<RevokedCertParams>,
) -> Vec<u8> {
    extended(
        issuer,
        &list(issuer, number, window, revoked),
        [indicator(base)],
    )
}

fn scope(point: &IssuingDistributionPoint) -> x509_cert::ext::Extension {
    extension(
        ISSUING_DISTRIBUTION_POINT,
        true,
        point.to_der().unwrap().clone(),
    )
}

fn reasons_scope(reason: Reasons) -> x509_cert::ext::Extension {
    scope(&IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: false,
        only_contains_ca_certs: false,
        only_some_reasons: Some(reason.into()),
        indirect_crl: false,
        only_contains_attribute_certs: false,
    })
}

fn user_scope(ca_only: bool) -> x509_cert::ext::Extension {
    scope(&IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: !ca_only,
        only_contains_ca_certs: ca_only,
        only_some_reasons: None,
        indirect_crl: false,
        only_contains_attribute_certs: false,
    })
}

fn chain(certificates: Vec<Vec<u8>>, crls: Vec<Vec<u8>>) -> X509DataInfo {
    let mut info = X509DataInfo::default();
    info.certificate_chain = (0..certificates.len()).collect();
    info.certificates = certificates;
    info.crls = crls;
    info
}

fn verify(info: &X509DataInfo, root: &Issuer) -> Result<(), X509ChainError> {
    verify_with_utc(info, root, true)
}

fn verify_with_utc(info: &X509DataInfo, root: &Issuer, utc: bool) -> Result<(), X509ChainError> {
    let anchors = [root.der().to_vec()];
    verify_x509_certificate_chain(
        info,
        &X509ChainOptions {
            // Explicit synthetic UTC coverage belongs to this test request.
            utc_facts: utc.then(|| {
                structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
                    .expect("test UTC facts")
            }),
            trusted_certs: &anchors,
            verification_time: Instant::new(VERIFICATION_TIME, 0).unwrap(),
            max_chain_depth: 3,
            check_crls: true,
            allowed_extended_key_usages: None,
            rsa_keys: xml_sec::policy::RsaKeyPolicy::default(),
            dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
            certificate_signature_algorithms: None,
        },
    )
}

fn leaf_chain(root: &Issuer, crls: Vec<Vec<u8>>) -> X509DataInfo {
    chain(vec![leaf_of(root), root.der().to_vec()], crls)
}

#[test]
fn delta_with_its_complete_list_accepts_an_unlisted_certificate() {
    // The pair must establish absence, not fail as an unpaired delta.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = delta(&root, 4, 3, current(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Ok(())
    );
}

#[test]
fn revocation_listed_only_in_the_delta_rejects_the_certificate() {
    // The update, not the older complete list, carries this revocation.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = delta(&root, 4, 3, current(), vec![entry(LEAF_SERIAL, None)]);
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::Revoked(0))
    );
}

#[test]
fn revocation_in_the_complete_list_survives_a_delta_that_omits_it() {
    // A delta lists changes only; silence does not lift the base entry.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), vec![entry(LEAF_SERIAL, None)]);
    let update = delta(&root, 4, 3, current(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::Revoked(0))
    );
}

#[test]
fn remove_from_crl_in_the_delta_lifts_a_hold_in_the_complete_list() {
    // RFC 5280 5.3.1: removeFromCRL appears only in delta CRLs.
    let root = root_named("delta root");
    let hold = Some(RevocationReason::CertificateHold);
    let base = list(&root, 3, current(), vec![entry(LEAF_SERIAL, hold)]);
    let removal = Some(RevocationReason::RemoveFromCrl);
    let update = delta(&root, 4, 3, current(), vec![entry(LEAF_SERIAL, removal)]);
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Ok(())
    );
}

#[test]
fn current_delta_keeps_an_expired_complete_list_usable() {
    // RFC 5280 5.2.4: the delta's update window governs the combined list.
    let root = root_named("delta root");
    let base = list(&root, 3, expired(), Vec::new());
    let update = delta(&root, 4, 3, current(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Ok(())
    );
}

#[test]
fn expired_delta_is_refused_even_over_a_current_complete_list() {
    // The delta may carry a revocation the base lacks, so it cannot be skipped.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = delta(&root, 4, 3, expired(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::InvalidCrl(1))
    );
}

#[test]
fn delta_without_a_complete_list_is_refused() {
    let root = root_named("delta root");
    let update = delta(&root, 4, 3, current(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![update]), &root),
        Err(X509ChainError::InvalidCrl(0))
    );
}

#[test]
fn delta_that_cannot_bind_its_complete_list_is_refused() {
    // RFC 5280 5.2.4: baseCRLNumber <= complete number < delta number.
    let root = root_named("delta root");
    let cases = [
        ("complete list older than the delta's base", 3, 5, 6),
        ("delta not newer than the complete list", 4, 3, 4),
    ];
    for (case, complete, base, number) in cases {
        let info = leaf_chain(
            &root,
            vec![
                list(&root, complete, current(), Vec::new()),
                delta(&root, number, base, current(), Vec::new()),
            ],
        );
        assert_eq!(
            verify(&info, &root),
            Err(X509ChainError::InvalidCrl(1)),
            "{case}"
        );
    }
}

#[test]
fn delta_indicator_must_be_critical_to_bind() {
    // RFC 5280 5.2.4 requires criticality; a noncritical marker binds nothing.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = extended(
        &root,
        &list(&root, 4, current(), Vec::new()),
        [extension(DELTA_CRL_INDICATOR, false, base_number(3))],
    );
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::InvalidCrl(1))
    );
}

#[test]
fn delta_of_another_scope_does_not_update_the_complete_list() {
    // RFC 5280 6.3.3(c): the pair needs the same distribution scope.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = extended(
        &root,
        &list(&root, 4, current(), Vec::new()),
        [indicator(3), user_scope(false)],
    );
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::InvalidCrl(1))
    );
}

#[test]
fn unbound_delta_outside_the_target_scope_is_ignored() {
    // A list covering only CA certificates says nothing about this leaf.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = extended(
        &root,
        &list(&root, 4, current(), Vec::new()),
        [indicator(3), user_scope(true)],
    );
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Ok(())
    );
}

#[test]
fn delta_signed_by_a_rolled_over_key_is_ignored_for_the_selected_issuer() {
    // Equal names are not key identities: its authority key identifier selects
    // another issuer, so this list is no evidence about the selected path.
    let root = root_named("delta root");
    let previous = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = delta(&previous, 4, 3, current(), vec![entry(LEAF_SERIAL, None)]);
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Ok(())
    );
}

#[test]
fn newest_delta_supersedes_an_older_one_in_either_order() {
    // Deltas accumulate from their base, so the older hold is already resolved
    // by the newer removal. Supply order must not change the answer.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let hold = Some(RevocationReason::CertificateHold);
    let removal = Some(RevocationReason::RemoveFromCrl);
    let older = delta(&root, 4, 3, expired(), vec![entry(LEAF_SERIAL, hold)]);
    let newer = delta(&root, 5, 3, current(), vec![entry(LEAF_SERIAL, removal)]);
    for crls in [
        vec![base.clone(), older.clone(), newer.clone()],
        vec![newer, older, base],
    ] {
        assert_eq!(verify(&leaf_chain(&root, crls), &root), Ok(()));
    }
}

#[test]
fn newest_delta_decides_by_number_beyond_one_octet() {
    // CRL numbers are integers: 0x0100 is newer than 0xFF though its first
    // content octet is smaller.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let older = delta(&root, 0xFF, 3, current(), vec![entry(LEAF_SERIAL, None)]);
    let newer = delta(&root, 0x0100, 3, current(), Vec::new());
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, newer, older]), &root),
        Ok(())
    );
}

#[test]
fn pair_coverage_is_limited_to_the_reasons_of_its_scope() {
    // RFC 5280 6.3.3(d): a bound pair qualifies only the base's reasons.
    let root = root_named("delta root");
    let reason = reasons_scope(Reasons::KeyCompromise);
    let base = extended(
        &root,
        &list(&root, 3, current(), Vec::new()),
        [reason.clone()],
    );
    let update = extended(
        &root,
        &list(&root, 4, current(), Vec::new()),
        [indicator(3), reason],
    );
    assert_eq!(
        verify(&leaf_chain(&root, vec![base, update]), &root),
        Err(X509ChainError::IncompleteCrlCoverage(0))
    );
}

#[test]
fn delta_evaluation_requires_caller_utc_facts() {
    // Without UTC history no absence can be established for an applicable pair.
    let root = root_named("delta root");
    let base = list(&root, 3, current(), Vec::new());
    let update = delta(&root, 4, 3, current(), Vec::new());
    assert_eq!(
        verify_with_utc(&leaf_chain(&root, vec![base, update]), &root, false),
        Err(X509ChainError::MissingUtcFacts)
    );
}

#[test]
fn exhausted_work_during_delta_evaluation_stays_a_resource_refusal() {
    // Spent budget must not read as a bad list or as an established status.
    let root = root_named("delta root");
    let info = leaf_chain(
        &root,
        vec![
            list(&root, 3, current(), Vec::new()),
            delta(&root, 4, 3, current(), Vec::new()),
            delta(&root, 5, 3, current(), Vec::new()),
        ],
    );
    let anchors = [root.der().to_vec()];
    let options = X509ChainOptions {
        utc_facts: Some(
            structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
                .expect("test UTC facts"),
        ),
        trusted_certs: &anchors,
        verification_time: Instant::new(VERIFICATION_TIME, 0).unwrap(),
        max_chain_depth: 3,
        check_crls: true,
        allowed_extended_key_usages: None,
        rsa_keys: xml_sec::policy::RsaKeyPolicy::default(),
        dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
        certificate_signature_algorithms: None,
    };
    let mut completed = false;
    for max_x509_work in (1..200_000).step_by(64) {
        let resources = xml_sec::policy::ResourcePolicy {
            max_x509_work,
            ..Default::default()
        };
        match xml_sec::xmldsig::verify_x509_certificate_chain_with_resources(
            &info,
            &options,
            &resources,
            xml_sec::provider::default_provider(),
        ) {
            Ok(()) => {
                completed = true;
                break;
            }
            Err(X509ChainError::Policy(_)) => (),
            Err(X509ChainError::Processing(error)) if error.is_resource() => (),
            Err(other) => panic!("work {max_x509_work}: {other:?}"),
        }
    }
    assert!(completed, "the sweep must reach a sufficient budget");
}

/// Independent issuer: `scripts/generate-delta-crl-fixtures.sh`, whose OpenSSL
/// verifier accepted the silent pair and refused the revoking one.
fn openssl_pair(delta: &[u8]) -> Result<(), X509ChainError> {
    let root = include_bytes!("fixtures/x509/delta-crl/ca.der").to_vec();
    let info = chain(
        vec![
            include_bytes!("fixtures/x509/delta-crl/leaf.der").to_vec(),
            root.clone(),
        ],
        vec![
            include_bytes!("fixtures/x509/delta-crl/complete.crl").to_vec(),
            delta.to_vec(),
        ],
    );
    let anchors = [root];
    verify_x509_certificate_chain(
        &info,
        &X509ChainOptions {
            utc_facts: Some(
                structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
                    .expect("test UTC facts"),
            ),
            trusted_certs: &anchors,
            // 2040-01-01T00:00:00Z, after the fixtures' revocation date.
            verification_time: Instant::new(2_208_988_800, 0).unwrap(),
            max_chain_depth: 3,
            check_crls: true,
            allowed_extended_key_usages: None,
            rsa_keys: xml_sec::policy::RsaKeyPolicy::default(),
            dsa_keys: xml_sec::policy::DsaKeyPolicy::default(),
            certificate_signature_algorithms: None,
        },
    )
}

#[test]
fn openssl_issued_silent_delta_is_accepted_as_openssl_accepts_it() {
    assert_eq!(
        openssl_pair(include_bytes!("fixtures/x509/delta-crl/silent.crl")),
        Ok(())
    );
}

#[test]
fn openssl_issued_revoking_delta_is_refused_as_openssl_refuses_it() {
    assert_eq!(
        openssl_pair(include_bytes!("fixtures/x509/delta-crl/revoking.crl")),
        Err(X509ChainError::Revoked(0))
    );
}

#[test]
fn delta_applies_at_its_own_path_position() {
    // The root's delta revokes the intermediate, not the leaf below it.
    let root = root_named("delta root");
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "delta intermediate");
    params.serial_number = Some(SerialNumber::from(INTERMEDIATE_SERIAL));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    let intermediate: Issuer =
        CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &root).unwrap();
    let info = chain(
        vec![
            leaf_of(&intermediate),
            intermediate.der().to_vec(),
            root.der().to_vec(),
        ],
        vec![
            list(&root, 3, current(), Vec::new()),
            delta(
                &root,
                4,
                3,
                current(),
                vec![entry(INTERMEDIATE_SERIAL, None)],
            ),
        ],
    );
    assert_eq!(verify(&info, &root), Err(X509ChainError::Revoked(1)));
}
