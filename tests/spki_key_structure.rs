//! Structural RSA and EC SubjectPublicKeyInfo checks at key resolution and
//! key import: the accepted shapes resolve, and every refused shape keeps the
//! error kind callers already distinguish.

#![cfg(feature = "xmldsig")]

use xml_sec::key_manager::KeyInventory;
use xml_sec::policy::{ResourcePolicy, VerificationPolicy, VerificationTrustMode};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, KeyInfo, KeyInfoSource, KeyResolutionError, KeyResolver as _,
    SignatureAlgorithm,
};

const EC_P256: &[u8] = include_bytes!("fixtures/xmlenc/keys/ec/ec-prime256v1-pubkey.der");
const RSA_2048: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");

/// One DER TLV with a definite length (X.690 8.1.3).
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = contents.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let octets = length.to_be_bytes();
        let skip = octets.iter().take_while(|octet| **octet == 0).count();
        out.push(0x80 | (octets.len() - skip) as u8);
        out.extend_from_slice(&octets[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// The first DER element of `bytes`: its tag, contents and the bytes after it.
fn split(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let (length, header) = match bytes[1] {
        short if short < 0x80 => (short as usize, 2),
        long => {
            let count = (long & 0x7f) as usize;
            let length = bytes[2..2 + count]
                .iter()
                .fold(0_usize, |length, octet| (length << 8) | *octet as usize);
            (length, 2 + count)
        }
    };
    (
        bytes[0],
        &bytes[header..header + length],
        &bytes[header + length..],
    )
}

fn rsa_spki() -> Vec<u8> {
    pem::parse(RSA_2048)
        .expect("fixture PEM")
        .contents()
        .to_vec()
}

/// The EC fixture with its curve parameters replaced by `parameters`.
fn ec_with_parameters(parameters: &[u8]) -> Vec<u8> {
    let (_, spki, _) = split(EC_P256);
    let (_, algorithm, key) = split(spki);
    let (_, _, curve) = split(algorithm);
    let algorithm_oid = &algorithm[..algorithm.len() - curve.len()];
    let algorithm = tlv(0x30, &[algorithm_oid, parameters].concat());
    tlv(0x30, &[algorithm.as_slice(), key].concat())
}

/// The RSA fixture with one more INTEGER inside `RSAPublicKey`.
fn rsa_with_trailing_component() -> Vec<u8> {
    let spki = rsa_spki();
    let (_, contents, _) = split(&spki);
    let (_, _, key) = split(contents);
    let algorithm = &contents[..contents.len() - key.len()];
    let (_, bits, _) = split(key);
    let (_, components, _) = split(&bits[1..]);
    let public_key = tlv(0x30, &[components, &[0x02, 0x01, 0x01]].concat());
    let key = tlv(0x03, &[&[0x00][..], &public_key].concat());
    tlv(0x30, &[algorithm, key.as_slice()].concat())
}

fn resolve(spki: &[u8], method: SignatureAlgorithm) -> Result<bool, DsigError> {
    let mut info = KeyInfo::default();
    info.sources
        .push(KeyInfoSource::DerEncodedKeyValue(spki.to_vec()));
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    DefaultKeyResolver::default()
        .resolve_with_policy(Some(&info), method, &policy)
        .map(|key| key.is_some())
}

fn imports(spki: &[u8]) -> bool {
    KeyInventory::default()
        .add_public_der("key".into(), spki.to_vec(), &ResourcePolicy::default())
        .is_ok()
}

#[test]
fn named_curve_and_rsa_keys_resolve_and_import() {
    // Controls for the refusals below: the unmodified fixtures are accepted
    // by both entry points, so each refusal is caused by its one change.
    assert!(resolve(EC_P256, SignatureAlgorithm::EcdsaSha256).expect("named P-256 key"));
    assert!(imports(EC_P256));
    let rsa = rsa_spki();
    assert!(resolve(&rsa, SignatureAlgorithm::RsaSha256).expect("RSA key"));
    assert!(imports(&rsa));
}

#[test]
fn ec_keys_without_a_named_curve_are_algorithm_mismatches() {
    // RFC 5480 2.1.1: implicitCurve (NULL) and specifiedCurve MUST NOT be
    // used. Both name no supported curve, as before for any non-OID value.
    for parameters in [&[0x05, 0x00][..], &[0x30, 0x03, 0x02, 0x01, 0x01]] {
        let spki = ec_with_parameters(parameters);
        assert!(matches!(
            resolve(&spki, SignatureAlgorithm::EcdsaSha256),
            Err(DsigError::KeyResolution(
                KeyResolutionError::AlgorithmMismatch
            ))
        ));
        assert!(!imports(&spki));
    }
}

#[test]
fn trailing_bytes_after_spki_are_invalid_keys() {
    // RFC 5280 4.1.2.7: DEREncodedKeyValue holds exactly one SPKI.
    for (spki, method) in [
        (EC_P256.to_vec(), SignatureAlgorithm::EcdsaSha256),
        (rsa_spki(), SignatureAlgorithm::RsaSha256),
    ] {
        let spki = [spki.as_slice(), &[0x00]].concat();
        assert!(matches!(
            resolve(&spki, method),
            Err(DsigError::KeyResolution(
                KeyResolutionError::InvalidPublicKey
            ))
        ));
        assert!(!imports(&spki));
    }
}

#[test]
fn rsa_public_key_with_extra_component_is_invalid() {
    // RFC 8017 A.1.1: RSAPublicKey is exactly modulus and publicExponent.
    let spki = rsa_with_trailing_component();
    assert!(matches!(
        resolve(&spki, SignatureAlgorithm::RsaSha256),
        Err(DsigError::KeyResolution(
            KeyResolutionError::InvalidPublicKey
        ))
    ));
    assert!(!imports(&spki));
}
