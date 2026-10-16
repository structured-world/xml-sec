#![cfg(feature = "xmldsig")]

use der::{Decode as _, Encode as _};
use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::{key::PublicKeyInfo, path::WorkingKey};
use xml_sec::provider::{CryptoProvider, KeyAssociation, RustCryptoProvider};

#[path = "support/provider_candidate_limits.rs"]
mod candidate_limits;

fn associate(actual: &[u8], expected: &[u8]) -> KeyAssociation {
    let parser = Parser::new(
        Encoding::Der,
        Limits::default(),
        Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 28))),
    );
    let mut reader = parser.read(expected, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let expected = PublicKeyInfo::read_element(&reader, &element, "expected SPKI").unwrap();
    RustCryptoProvider
        .associate_verification_key(actual, WorkingKey::standing(expected), &|_| Ok(()))
        .unwrap()
}

#[test]
fn ordinary_rustcrypto_candidate_traversal_is_bounded() {
    // Ordinary verification and receipt capture must enforce the same ceiling.
    candidate_limits::assert_provider_candidate_limits(&RustCryptoProvider);
}

#[cfg(feature = "aws-lc-fips")]
#[test]
fn ordinary_aws_candidate_traversal_is_bounded() {
    // The native ordinary API must not recursively bypass receipt-path bounds.
    candidate_limits::assert_provider_candidate_limits(&xml_sec::provider::AwsLcFipsProvider);
}

#[test]
fn rsa_components_are_compared_across_rsa_and_pss_identifiers() {
    // Different n/e prove mismatch in either OID direction. Equal components
    // with different effective restrictions do not establish the same key.
    let first = pem::parse(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem"))
        .unwrap()
        .into_contents();
    let second = pem::parse(include_str!("fixtures/keys/rsa/rsa-expired-pubkey.pem"))
        .unwrap()
        .into_contents();
    let pss = |bytes: &[u8]| {
        let original = pkcs8::SubjectPublicKeyInfoRef::from_der(bytes).unwrap();
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
                parameters: None,
            },
            subject_public_key: original.subject_public_key,
        }
        .to_der()
        .unwrap()
    };
    let first_pss = pss(&first);
    let second_pss = pss(&second);
    let original = pkcs8::SubjectPublicKeyInfoRef::from_der(&first).unwrap();
    let rsa =
        pkcs1::RsaPublicKeyRef::from_der(original.subject_public_key.as_bytes().unwrap()).unwrap();
    let exponent = pkcs1::RsaPublicKeyRef {
        public_exponent: der::asn1::UintRef::new(&[3]).unwrap(),
        ..rsa
    }
    .to_der()
    .unwrap();
    let different_exponent = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: original.algorithm,
        subject_public_key: der::asn1::BitStringRef::from_bytes(&exponent).unwrap(),
    }
    .to_der()
    .unwrap();
    let different_exponent_pss = pss(&different_exponent);
    for (left, right, expected) in [
        (&first, &second_pss, KeyAssociation::Mismatch),
        (&first_pss, &second, KeyAssociation::Mismatch),
        (&first, &first_pss, KeyAssociation::Unproven),
        (&first_pss, &first, KeyAssociation::Unproven),
        (&first, &different_exponent_pss, KeyAssociation::Mismatch),
        (&first_pss, &different_exponent, KeyAssociation::Mismatch),
    ] {
        assert_eq!(associate(left, right), expected);
    }
    // PSS absence is unrestricted; a written NULL is not that representation,
    // even though generic WorkingKey parameter projection reports None.
    let pss_info = pkcs8::SubjectPublicKeyInfoRef::from_der(&first_pss).unwrap();
    let pss_null = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            parameters: Some(der::asn1::AnyRef::NULL),
            ..pss_info.algorithm
        },
        subject_public_key: pss_info.subject_public_key,
    }
    .to_der()
    .unwrap();
    assert_eq!(associate(&first_pss, &pss_null), KeyAssociation::Unproven);
}

#[cfg(feature = "experimental-pq")]
#[test]
fn fixed_format_pq_keys_distinguish_mismatch_and_malformed() {
    // Every bit pattern of the parameter-set-sized ML-DSA/SLH-DSA public
    // encoding is admissible; wrong widths or written parameters are not.
    use xml_sec::xmldsig::PqAlgorithm;
    let spki = |algorithm: PqAlgorithm, bits: &[u8], null: bool| {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: der::asn1::ObjectIdentifier::new_unwrap(algorithm.oid()),
                parameters: null.then_some(der::asn1::AnyRef::NULL),
            },
            subject_public_key: der::asn1::BitStringRef::from_bytes(bits).unwrap(),
        }
        .to_der()
        .unwrap()
    };
    for algorithm in PqAlgorithm::ALL {
        let size = match algorithm {
            PqAlgorithm::MlDsa44 => 1312,
            PqAlgorithm::MlDsa65 => 1952,
            PqAlgorithm::MlDsa87 => 2592,
            PqAlgorithm::SlhDsaSha2_128f | PqAlgorithm::SlhDsaSha2_128s => 32,
            PqAlgorithm::SlhDsaSha2_192f | PqAlgorithm::SlhDsaSha2_192s => 48,
            PqAlgorithm::SlhDsaSha2_256f | PqAlgorithm::SlhDsaSha2_256s => 64,
        };
        let first = spki(algorithm, &vec![0x42; size], false);
        let different = spki(algorithm, &vec![0x43; size], false);
        assert_eq!(
            associate(&first, &first),
            KeyAssociation::Same,
            "{algorithm:?}"
        );
        assert_eq!(
            associate(&first, &different),
            KeyAssociation::Mismatch,
            "{algorithm:?}"
        );
        for malformed in [
            spki(algorithm, &[], false),
            spki(algorithm, &vec![0x42; size - 1], false),
            spki(algorithm, &vec![0x42; size + 1], false),
            spki(algorithm, &vec![0x42; size], true),
        ] {
            assert_eq!(
                associate(&first, &malformed),
                KeyAssociation::Unproven,
                "{algorithm:?}"
            );
            assert_eq!(
                associate(&malformed, &first),
                KeyAssociation::Unproven,
                "{algorithm:?}"
            );
            assert_eq!(
                associate(&malformed, &malformed),
                KeyAssociation::Unproven,
                "{algorithm:?}"
            );
        }
    }
}

#[test]
fn edwards_original_null_parameters_are_not_hidden_by_effective_projection() {
    // WorkingKey intentionally projects NULL as no effective parameters;
    // RFC 8410 still forbids writing it in either original Edwards SPKI.
    for (oid, bits) in [
        (
            ed25519_dalek::pkcs8::ALGORITHM_OID,
            ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        (
            ed448_goldilocks::ALGORITHM_OID,
            ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..])
                .unwrap()
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
    ] {
        let make = |parameters| {
            pkcs8::SubjectPublicKeyInfoRef {
                algorithm: pkcs8::AlgorithmIdentifierRef { oid, parameters },
                subject_public_key: der::asn1::BitStringRef::from_bytes(&bits).unwrap(),
            }
            .to_der()
            .unwrap()
        };
        let valid = make(None);
        let null = make(Some(der::asn1::AnyRef::NULL));
        assert_eq!(associate(&valid, &null), KeyAssociation::Unproven);
        assert_eq!(associate(&null, &valid), KeyAssociation::Unproven);
        assert_eq!(associate(&null, &null), KeyAssociation::Unproven);
    }
}
