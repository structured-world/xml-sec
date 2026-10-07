#![cfg(feature = "xmldsig")]

use der::{Decode, Encode};
use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use xml_sec::rsa_encoding::{RsaPrivateKeyEncoding, RsaPublicKeyEncoding};

const PRIVATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const PUBLIC: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");

#[test]
fn rsa_encoding_round_trips_both_containers() {
    // Encoding adaptation must retain exact keys without a second RSA engine.
    let private = RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let public = RsaPublicKey::from_public_key_pem(PUBLIC).unwrap();
    assert_eq!(private.to_public_key(), public);
    let pkcs1 = private.to_pkcs1_der().unwrap();
    let pkcs8 = private.to_pkcs8_der().unwrap();
    assert_eq!(pkcs8.as_bytes(), pem::parse(PRIVATE).unwrap().contents());
    assert_eq!(
        RsaPrivateKey::from_pkcs1_der(pkcs1.as_bytes()).unwrap(),
        private
    );
    assert_eq!(
        RsaPrivateKey::from_pkcs8_der(pkcs8.as_bytes()).unwrap(),
        private
    );
    let pkcs1 = public.to_pkcs1_der().unwrap();
    let spki = public.to_public_key_der().unwrap();
    assert_eq!(spki.as_bytes(), pem::parse(PUBLIC).unwrap().contents());
    assert_eq!(
        RsaPublicKey::from_pkcs1_der(pkcs1.as_bytes()).unwrap(),
        public
    );
    assert_eq!(
        RsaPublicKey::from_public_key_der(spki.as_bytes()).unwrap(),
        public
    );
    assert_eq!(
        RsaPrivateKey::from_pkcs1_pem(&private.to_pkcs1_pem(Default::default()).unwrap()).unwrap(),
        private
    );
    assert_eq!(
        RsaPublicKey::from_pkcs1_pem(&public.to_pkcs1_pem(Default::default()).unwrap()).unwrap(),
        public
    );
    assert_eq!(
        RsaPrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem(Default::default()).unwrap()).unwrap(),
        private
    );
    assert_eq!(
        RsaPublicKey::from_public_key_pem(&public.to_public_key_pem(Default::default()).unwrap())
            .unwrap(),
        public
    );
}

#[test]
fn rsa_encoding_rejects_container_confusion_and_trailing_data() {
    // Strict container labels and DER consumption must survive the adapter.
    assert!(RsaPrivateKey::from_pkcs1_pem(PRIVATE).is_err());
    assert!(RsaPublicKey::from_pkcs1_pem(PUBLIC).is_err());
    let private = RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let mut bytes = private.to_pkcs1_der().unwrap().as_bytes().to_vec();
    bytes.push(0);
    assert!(RsaPrivateKey::from_pkcs1_der(&bytes).is_err());
    assert!(RsaPrivateKey::from_pkcs8_der(&bytes).is_err());
    let mut bytes = private
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes.push(0);
    assert!(RsaPublicKey::from_public_key_der(&bytes).is_err());
}

#[test]
fn rsa_encoding_validates_algorithm_parameters() {
    // RFC 3279 §2.3.1 requires rsaEncryption parameters to be ASN.1 NULL.
    let key = RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let encoded = key.to_pkcs8_der().unwrap();
    let mut info = pkcs8::PrivateKeyInfoRef::from_der(encoded.as_bytes()).unwrap();
    info.algorithm.parameters = None;
    assert!(RsaPrivateKey::from_pkcs8_der(&info.to_der().unwrap()).is_err());
    info.algorithm.oid = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    assert!(RsaPrivateKey::from_pkcs8_der(&info.to_der().unwrap()).is_err());
    let encoded = key.to_public_key().to_public_key_der().unwrap();
    let mut info = pkcs8::SubjectPublicKeyInfoRef::from_der(encoded.as_bytes()).unwrap();
    info.algorithm.parameters = None;
    assert!(RsaPublicKey::from_public_key_der(&info.to_der().unwrap()).is_err());
    assert!(key.n().bits_vartime() >= 2048);
}

#[test]
fn rsa_encoding_protected_container_requires_correct_password() {
    // Protected import must decrypt first and never reinterpret an error as a
    // different container; successful import retains the exact private key.
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
    let key = RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let der = key.to_pkcs8_der().unwrap();
    let encrypted = pkcs8::PrivateKeyInfoRef::from_der(der.as_bytes())
        .unwrap()
        .encrypt_with_rng(&mut ChaCha20Rng::seed_from_u64(25), b"correct")
        .unwrap();
    let pem = encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF)
        .unwrap();
    assert_eq!(
        RsaPrivateKey::from_pkcs8_encrypted_der(encrypted.as_bytes(), b"correct").unwrap(),
        key
    );
    assert_eq!(
        RsaPrivateKey::from_pkcs8_encrypted_pem(&pem, b"correct").unwrap(),
        key
    );
    assert!(RsaPrivateKey::from_pkcs8_encrypted_der(encrypted.as_bytes(), b"wrong").is_err());
    assert!(RsaPrivateKey::from_pkcs8_encrypted_pem(&pem, b"wrong").is_err());
    assert!(RsaPrivateKey::from_pkcs8_encrypted_pem(PRIVATE, b"correct").is_err());
}

#[test]
fn rsa_encoding_rejects_invalid_key_components() {
    // Codec parsing is not validation: the existing RSA engine must reject
    // invalid exponents and inconsistent private components after DER decode.
    let key = RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let bytes = key.to_pkcs1_der().unwrap();
    let mut encoded = pkcs1::RsaPrivateKeyRef::from_der(bytes.as_bytes()).unwrap();
    encoded.prime1 = pkcs1::UintRef::new(&[1]).unwrap();
    assert!(RsaPrivateKey::from_pkcs1_der(&encoded.to_der().unwrap()).is_err());
    let oversized = vec![1; encoded.modulus.as_bytes().len() + 1];
    encoded.prime1 = pkcs1::UintRef::new(&oversized).unwrap();
    assert!(RsaPrivateKey::from_pkcs1_der(&encoded.to_der().unwrap()).is_err());
    let bytes = key.to_public_key().to_pkcs1_der().unwrap();
    let mut encoded = pkcs1::RsaPublicKeyRef::from_der(bytes.as_bytes()).unwrap();
    encoded.public_exponent = pkcs1::UintRef::new(&[2]).unwrap();
    assert!(RsaPublicKey::from_pkcs1_der(&encoded.to_der().unwrap()).is_err());
}
