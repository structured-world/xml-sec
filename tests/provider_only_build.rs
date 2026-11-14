//! An `XMLDSig` build without the built-in `rustcrypto` backends: every digest
//! and signature check runs in the `CryptoProvider` the caller selects, and
//! the core hands that provider the exact public key the document names.
#![cfg(all(
    feature = "xmldsig",
    not(feature = "rustcrypto"),
    any(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")
))]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use num_bigint::BigUint;
use sha2::Digest as _;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::PublicKeyInfo;
use structured_pkix::key::{dsa, ec, rsa};
use structured_pkix::path::EffectiveKey;
use xml_sec::policy::{VerificationPolicy, VerificationTrustMode};
use xml_sec::provider::{
    CryptoProvider, DigestState, KdfParameters, ProviderCapability, ProviderError,
    ProviderOperation, charged_digest_state, default_provider,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, MAX_DIGEST_OUTPUT,
    SignatureAlgorithm, SigningKey, SigningKeyError, VerificationKey, VerifyContext, VerifyingKey,
};

const RSA_PUBLIC_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");
const DSA_PUBLIC_KEY: &str = include_str!("fixtures/xmldsig/keys/dsa/dsa-2048-pubkey.pem");
const EC_PUBLIC_KEY: &str = include_str!("fixtures/keys/ec/ec-prime256v1-pubkey.pem");

/// A downstream provider: SHA-256 and RSA PKCS#1 v1.5 with SHA-256 of its
/// own, reading only the SPKI the key hands it. It records every SPKI it was
/// asked to verify with.
#[derive(Default)]
struct DownstreamProvider {
    keys: Mutex<Vec<Vec<u8>>>,
}

struct Sha256State(sha2::Sha256);

impl DigestState for Sha256State {
    fn update(&mut self, data: &[u8]) -> Result<(), ProviderError> {
        self.0.update(data);
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8; MAX_DIGEST_OUTPUT]) -> Result<usize, ProviderError> {
        let digest = self.0.finalize_reset();
        output[..digest.len()].copy_from_slice(&digest);
        Ok(digest.len())
    }
}

fn unsupported(operation: ProviderOperation, algorithm: Option<&str>) -> ProviderError {
    ProviderError::Unsupported {
        operation,
        algorithm: algorithm.map(str::to_owned),
    }
}

impl CryptoProvider for DownstreamProvider {
    fn name(&self) -> &'static str {
        "downstream"
    }

    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        // Every method the documents below name, so each reaches `verify`;
        // only RSA-SHA256 is then computed.
        matches!(
            capability,
            ProviderCapability::Digest(DigestAlgorithm::Sha256)
                | ProviderCapability::Verify(
                    SignatureAlgorithm::RsaSha256
                        | SignatureAlgorithm::DsaSha256
                        | SignatureAlgorithm::EcdsaSha256
                )
        )
    }

    fn fill_random(&self, _: &mut [u8]) -> Result<(), ProviderError> {
        Err(unsupported(ProviderOperation::Random, None))
    }

    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(
            ProviderOperation::Kdf,
            Some(parameters.algorithm),
        ))
    }

    fn begin_digest(
        &self,
        algorithm: DigestAlgorithm,
        memory: &Memory,
    ) -> Result<Box<dyn DigestState + '_>, ProviderError> {
        if algorithm != DigestAlgorithm::Sha256 {
            return Err(unsupported(
                ProviderOperation::Digest,
                Some(algorithm.uri()),
            ));
        }
        charged_digest_state(Sha256State(sha2::Sha256::new()), memory)
    }

    fn sign(
        &self,
        _: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        _: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        Err(SigningKeyError::UnsupportedAlgorithm {
            uri: algorithm.uri().into(),
        })
    }

    fn verify(
        &self,
        key: &dyn VerifyingKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        let spki = key
            .verification_spki(algorithm)?
            .ok_or_else(|| unsupported(ProviderOperation::Verify, Some(algorithm.uri())))?;
        self.keys.lock().expect("unpoisoned").push(spki.to_vec());
        Ok(
            algorithm == SignatureAlgorithm::RsaSha256
                && rsa_pkcs1v15_sha256(spki, data, signature),
        )
    }
}

/// RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017 sections 8.2.2
/// and 9.2), on big integers of the provider's own.
fn rsa_pkcs1v15_sha256(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // DigestInfo prefix of SHA-256 (RFC 8017 section 9.2, note 1).
    const PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let (modulus, exponent) = with_key(spki, |info, memory| {
        let key = rsa::read(info, memory).expect("an RSA key");
        (
            key.modulus().as_bytes().to_vec(),
            key.exponent().as_bytes().to_vec(),
        )
    });
    let width = modulus.len();
    if signature.len() != width || width < PREFIX.len() + 32 + 11 {
        return false;
    }
    let representative = BigUint::from_bytes_be(signature).modpow(
        &BigUint::from_bytes_be(&exponent),
        &BigUint::from_bytes_be(&modulus),
    );
    let mut expected = vec![0xff_u8; width];
    expected[0] = 0;
    expected[1] = 1;
    let digest_start = width - 32;
    expected[digest_start - PREFIX.len() - 1] = 0;
    expected[digest_start - PREFIX.len()..digest_start].copy_from_slice(&PREFIX);
    expected[digest_start..].copy_from_slice(&sha2::Sha256::digest(message));
    // The big-endian representative drops the leading zero octet.
    representative.to_bytes_be() == expected[1..]
}

/// Run `read` on the SPKI `der` through the shared PKIX reader.
fn with_key<T>(der: &[u8], read: impl FnOnce(PublicKeyInfo<'_>, &Memory) -> T) -> T {
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(der, 0).expect("DER");
    let element = reader.next_element().expect("an element").expect("one");
    let info = PublicKeyInfo::read_element(&reader, &element, "key").expect("an SPKI");
    read(info, &memory)
}

fn spki(pem_text: &str) -> Vec<u8> {
    pem::parse(pem_text).expect("fixture PEM").into_contents()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The XML Signature 1.1 interop P-256 document with `method`, a
/// `SignatureValue` of `width` zero octets and `key_value` as its `KeyValue`.
/// The reference digest stays valid, so verification reaches the provider.
fn document(method: &str, width: usize, key_value: &str) -> String {
    include_str!("fixtures/xmldsig/xmldsig11-interop-2012/signature-enveloping-p256_sha256.xml")
        .replace(
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            method,
        )
        .replace(
            "eYx4ImirtPG/eJLWgJHoMS30voH+tozerMftKbYz27vtYNgsHfAvV4M+oEkNgoibq5qnwsO2Z8nn+ndKxhVqFg==",
            &b64(&vec![0; width]),
        )
        .replace(
            concat!(
                r#"<ECKeyValue xmlns="http://www.w3.org/2009/xmldsig11#"><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>"#,
                "<PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</PublicKey></ECKeyValue>"
            ),
            key_value,
        )
}

fn key_value_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy
}

/// The status of `xml` verified with its `KeyValue` through `provider`.
fn verify_key_value(xml: &str, provider: &DownstreamProvider) -> DsigStatus {
    let resolver = DefaultKeyResolver::default();
    VerifyContext::new()
        .policy(key_value_policy())
        .key_resolver(&resolver)
        .provider(provider)
        .verify(xml)
        .expect("verification runs")
        .status
}

fn rsa_key() -> VerificationKey {
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: spki(RSA_PUBLIC_KEY),
        certificate_der: None,
        name: None,
    }
}

const RSA_SIGNED: &str =
    include_str!("fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml");

/// `xml` with its whole `SignatureValue` replaced by `value`.
fn with_signature_value(xml: &str, value: &[u8]) -> String {
    let start = xml.find("<SignatureValue>").expect("a value") + "<SignatureValue>".len();
    let end = xml.find("</SignatureValue>").expect("closed");
    format!("{}{}{}", &xml[..start], b64(value), &xml[end..])
}

#[test]
fn a_signature_verifies_through_the_callers_provider() {
    // Digests and the RSA check both run in the provider; the core supplies
    // the key's own SPKI.
    let provider = DownstreamProvider::default();
    let key = rsa_key();
    let result = VerifyContext::new()
        .key(&key)
        .provider(&provider)
        .verify(RSA_SIGNED)
        .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        *provider.keys.lock().expect("unpoisoned"),
        [spki(RSA_PUBLIC_KEY)]
    );
}

#[test]
fn a_tampered_signature_fails_in_the_callers_provider() {
    // The provider's own mismatch, not a refusal by the core.
    let provider = DownstreamProvider::default();
    let key = rsa_key();
    // 256 octets frame as an RSA-2048 value, so only the provider can refuse it.
    let tampered = with_signature_value(RSA_SIGNED, &[1; 256]);
    let result = VerifyContext::new()
        .key(&key)
        .provider(&provider)
        .verify(&tampered)
        .expect("verification runs");
    assert!(
        matches!(result.status, DsigStatus::Invalid(_)),
        "{result:?}"
    );
    assert_eq!(
        *provider.keys.lock().expect("unpoisoned"),
        [spki(RSA_PUBLIC_KEY)],
        "the provider computed the mismatch"
    );
}

#[test]
fn without_a_provider_nothing_is_computed() {
    // No backend is compiled in: the default provider reports every digest
    // and signature unsupported, and verification refuses with that error.
    let provider = default_provider();
    assert!(!provider.supports(ProviderCapability::Digest(DigestAlgorithm::Sha256)));
    assert!(!provider.supports(ProviderCapability::Verify(SignatureAlgorithm::RsaSha256)));
    let key = rsa_key();
    let error = VerifyContext::new()
        .key(&key)
        .verify(RSA_SIGNED)
        .expect_err("no provider computes the digests");
    assert!(error.to_string().contains("provider"), "{error}");
}

#[test]
fn an_rsa_key_value_reaches_the_provider_as_its_canonical_spki() {
    // RSAKeyValue (XMLDSig 1.1 section 4.5.2.2) becomes the rsaEncryption
    // SPKI of RFC 3279 section 2.3.1, byte for byte the fixture's DER.
    let (modulus, exponent) = with_key(&spki(RSA_PUBLIC_KEY), |info, memory| {
        let key = rsa::read(info, memory).expect("an RSA key");
        (
            key.modulus().as_bytes().to_vec(),
            key.exponent().as_bytes().to_vec(),
        )
    });
    let xml = document(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        modulus.len(),
        &format!(
            "<dsig:RSAKeyValue><dsig:Modulus>{}</dsig:Modulus><dsig:Exponent>{}</dsig:Exponent></dsig:RSAKeyValue>",
            b64(&modulus),
            b64(&exponent)
        ),
    );
    let provider = DownstreamProvider::default();
    assert!(matches!(
        verify_key_value(&xml, &provider),
        DsigStatus::Invalid(_)
    ));
    assert_eq!(
        *provider.keys.lock().expect("unpoisoned"),
        [spki(RSA_PUBLIC_KEY)]
    );
}

#[test]
fn a_dsa_key_value_reaches_the_provider_as_its_canonical_spki() {
    // DSAKeyValue (XMLDSig 1.1 section 4.5.2.1) becomes the id-dsa SPKI with
    // Dss-Parms of RFC 3279 section 2.3.2, byte for byte the fixture's DER;
    // its 256-bit q fixes the 64-octet DSA-SHA256 value.
    let (p, q, g, y) = with_key(&spki(DSA_PUBLIC_KEY), |info, memory| {
        let key = dsa::read(EffectiveKey::standing(info), memory).expect("a DSA key");
        let parameters = key.parameters().expect("written parameters");
        (
            parameters.p().as_bytes().to_vec(),
            parameters.q().as_bytes().to_vec(),
            parameters.g().as_bytes().to_vec(),
            key.y().as_bytes().to_vec(),
        )
    });
    assert_eq!(q.len(), 32);
    let xml = document(
        "http://www.w3.org/2009/xmldsig11#dsa-sha256",
        64,
        &format!(
            "<dsig:DSAKeyValue><dsig:P>{}</dsig:P><dsig:Q>{}</dsig:Q><dsig:G>{}</dsig:G><dsig:Y>{}</dsig:Y></dsig:DSAKeyValue>",
            b64(&p),
            b64(&q),
            b64(&g),
            b64(&y)
        ),
    );
    let provider = DownstreamProvider::default();
    assert!(matches!(
        verify_key_value(&xml, &provider),
        DsigStatus::Invalid(_)
    ));
    assert_eq!(
        *provider.keys.lock().expect("unpoisoned"),
        [spki(DSA_PUBLIC_KEY)]
    );
}

#[test]
fn an_ec_key_value_reaches_the_provider_as_its_canonical_spki() {
    // ECKeyValue with a named curve (XMLDSig 1.1 section 4.5.2.3) becomes the
    // id-ecPublicKey SPKI of RFC 5480 section 2, byte for byte the fixture's.
    let point = with_key(&spki(EC_PUBLIC_KEY), |info, memory| {
        ec::read(EffectiveKey::standing(info), memory)
            .expect("an EC key")
            .as_bytes()
            .to_vec()
    });
    let xml = document(
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        64,
        &format!(
            r#"<ECKeyValue xmlns="http://www.w3.org/2009/xmldsig11#"><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><PublicKey>{}</PublicKey></ECKeyValue>"#,
            b64(&point)
        ),
    );
    let provider = DownstreamProvider::default();
    assert!(matches!(
        verify_key_value(&xml, &provider),
        DsigStatus::Invalid(_)
    ));
    assert_eq!(
        *provider.keys.lock().expect("unpoisoned"),
        [spki(EC_PUBLIC_KEY)]
    );
}

#[test]
fn an_rsa_key_value_outside_rfc_8017_or_the_work_ceiling_is_refused_for_any_provider() {
    // RFC 8017 section 3.1 makes n odd and e odd with 3 <= e < n; an exponent
    // past the core's ceiling would hand any provider unbounded work. None of
    // these keys resolves, so no provider is ever asked to use one.
    use xml_sec::xmldsig::{
        KeyInfo, KeyInfoSource, KeyResolutionError, KeyResolver as _, KeyValueInfo,
    };
    let modulus = with_key(&spki(RSA_PUBLIC_KEY), |info, memory| {
        rsa::read(info, memory)
            .expect("an RSA key")
            .modulus()
            .as_bytes()
            .to_vec()
    });
    let mut even = modulus.clone();
    *even.last_mut().expect("a modulus") &= 0xfe;
    let resolver = DefaultKeyResolver::default();
    for (modulus, exponent, admitted) in [
        (&modulus, vec![1, 0, 1], true),
        (&modulus, vec![2, 0, 0, 0, 1], false),
        (&modulus, vec![1, 0, 0], false),
        (&modulus, vec![1], false),
        (&even, vec![1, 0, 1], false),
    ] {
        let mut info = KeyInfo::default();
        info.sources
            .push(KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus: modulus.clone(),
                exponent: exponent.clone(),
            }));
        let result = resolver.resolve_with_policy(
            Some(&info),
            SignatureAlgorithm::RsaSha256,
            &key_value_policy(),
        );
        if admitted {
            assert!(result.expect("resolves").is_some());
        } else {
            assert!(
                matches!(
                    result,
                    Err(DsigError::KeyResolution(
                        KeyResolutionError::InvalidPublicKey
                    ))
                ),
                "{exponent:?}"
            );
        }
    }
}

#[test]
fn a_signature_value_of_the_wrong_width_never_reaches_the_provider() {
    // The core frames SignatureValue against the key it read itself: a
    // 2048-bit modulus takes exactly 256 octets (RFC 8017 section 8.2.2).
    let provider = DownstreamProvider::default();
    let key = rsa_key();
    let short = with_signature_value(RSA_SIGNED, &[1; 255]);
    let result = VerifyContext::new()
        .key(&key)
        .provider(&provider)
        .verify(&short)
        .expect("verification runs");
    assert!(
        matches!(result.status, DsigStatus::Invalid(_)),
        "{result:?}"
    );
    assert!(provider.keys.lock().expect("unpoisoned").is_empty());
}
