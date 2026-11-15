use super::sign_signature_value;
use crate::policy::{EcdsaSignatureValueEncoding, SigningPolicy};
use crate::xmldsig::{EcdsaP256SigningKey, SignatureAlgorithm, SignatureContext};

#[test]
fn an_ecdsa_value_follows_the_policy_encoding() {
    // A caller signing outside a document gets the representation the
    // policy selects, as document signing writes it: fixed-width r || s by
    // default, an ASN.1 DER SEQUENCE when the policy asks for it.
    let key = EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
    ))
    .expect("P-256 fixture must parse");
    let sign = |encoding| {
        let policy = SigningPolicy {
            ecdsa_signature_value_encoding: encoding,
            ..SigningPolicy::default()
        };
        sign_signature_value(
            &policy,
            crate::provider::default_provider(),
            &key,
            SignatureAlgorithm::EcdsaSha256,
            &SignatureContext::default(),
            b"signed bytes",
        )
        .expect("a permitted method signs")
    };
    assert_eq!(sign(EcdsaSignatureValueEncoding::XmlDsig).len(), 64);
    let der = sign(EcdsaSignatureValueEncoding::XmlSecAsn1Der);
    assert_eq!(der.first(), Some(&0x30), "a DER SEQUENCE");
    assert_ne!(der.len(), 64);
}

#[test]
fn a_policy_that_admits_no_key_candidate_signs_nothing() {
    // The supplied key is one key candidate, as in document signing: a
    // policy whose candidate allowance is zero refuses it before the key is
    // asked anything.
    let key = EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
    ))
    .expect("P-256 fixture must parse");
    let mut policy = SigningPolicy::default();
    policy.resources.max_key_candidates = 0;
    assert!(matches!(
        sign_signature_value(
            &policy,
            crate::provider::default_provider(),
            &key,
            SignatureAlgorithm::EcdsaSha256,
            &SignatureContext::default(),
            b"signed bytes",
        ),
        Err(crate::xmldsig::SigningError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                ..
            }
        ))
    ));
}

/// The default provider, apart from a signing result one octet too long.
struct OverlongSignature;

impl crate::provider::CryptoProvider for OverlongSignature {
    fn name(&self) -> &'static str {
        "overlong-signature"
    }

    fn supports(&self, capability: crate::provider::ProviderCapability<'_>) -> bool {
        crate::provider::default_provider().supports(capability)
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
        crate::provider::default_provider().fill_random(output)
    }

    fn derive_key(
        &self,
        parameters: &crate::provider::KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().derive_key(parameters, secret)
    }

    fn begin_digest(
        &self,
        algorithm: crate::xmldsig::DigestAlgorithm,
        memory: &structured_asn1::memory::Memory,
    ) -> Result<
        alloc::boxed::Box<dyn crate::provider::DigestState + '_>,
        crate::provider::ProviderError,
    > {
        crate::provider::default_provider().begin_digest(algorithm, memory)
    }

    fn sign(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::xmldsig::SigningKeyError> {
        let mut value = crate::provider::default_provider().sign(key, algorithm, data)?;
        value.push(0);
        Ok(value)
    }

    fn verify(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError> {
        crate::provider::default_provider().verify(key, algorithm, data, signature)
    }

    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().encrypt_data(algorithm, key, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().decrypt_data(algorithm, key, ciphertext)
    }

    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: crate::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().wrap_key(algorithm, kek, key)
    }

    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: crate::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().unwrap_key(algorithm, kek, wrapped)
    }

    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn crate::provider::KeyTransportKey,
        parameters: &crate::xmlenc::RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().transport_key(key, parameters, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn crate::provider::KeyRecoveryKey,
        parameters: &crate::xmlenc::RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, crate::provider::ProviderError> {
        crate::provider::default_provider().recover_key(key, parameters, ciphertext)
    }
}

#[test]
fn an_hmac_value_of_the_wrong_length_is_refused() {
    // The full HMAC output is asked for, so a provider result of any other
    // length is the wrong-length error, never cut down to fit.
    let key = crate::xmldsig::HmacSigningKey::new(alloc::vec![0x42; 32]).expect("an HMAC key");
    assert!(
        sign_signature_value(
            &SigningPolicy::default(),
            &OverlongSignature,
            &key,
            SignatureAlgorithm::HmacSha256,
            &SignatureContext::default(),
            b"signed bytes",
        )
        .is_err()
    );
}

#[test]
fn a_method_the_policy_excludes_is_refused() {
    let key = EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
    ))
    .expect("P-256 fixture must parse");
    let policy = SigningPolicy {
        signature_algorithms: Some([SignatureAlgorithm::RsaSha256].into()),
        ..SigningPolicy::default()
    };
    assert!(
        sign_signature_value(
            &policy,
            crate::provider::default_provider(),
            &key,
            SignatureAlgorithm::EcdsaSha256,
            &SignatureContext::default(),
            b"signed bytes",
        )
        .is_err()
    );
}
