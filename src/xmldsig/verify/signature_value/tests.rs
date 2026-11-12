use super::*;
use crate::policy::{Instant, KeyTrustPolicy, PolicyValidity, PolicyViolation, VerificationPolicy};
use crate::provider::default_provider;
use crate::xmldsig::HmacVerificationKey;

const SECRET: [u8; 32] = [0x42; 32];
const DATA: &[u8] = b"signed bytes";

fn key() -> HmacVerificationKey {
    HmacVerificationKey::new(SECRET.to_vec()).expect("a 256-bit HMAC key")
}

#[test]
fn an_expired_policy_is_refused_before_verification() {
    // A policy whose authorization interval has ended admits nothing, as
    // document verification refuses it. The caller's verification time is
    // set because a build without a host clock checks the interval at it;
    // the value is never examined, the refusal comes first.
    let policy = VerificationPolicy {
        validity: Some(PolicyValidity {
            authorization_id: "expired".into(),
            authority: "caller".into(),
            reason: "an interval in the past".into(),
            not_before: Instant::new(0, 0).expect("the epoch"),
            expires_at: Instant::new(1, 0).expect("one second after the epoch"),
        }),
        key_trust: KeyTrustPolicy {
            verification_time: Some(Instant::new(2, 0).expect("two seconds after the epoch")),
            ..KeyTrustPolicy::default()
        },
        ..VerificationPolicy::default()
    };
    let result = verify_signature_value(
        &policy,
        default_provider(),
        &key(),
        SignatureAlgorithm::HmacSha256,
        DATA,
        &[0; 32],
    );
    assert!(
        matches!(
            result,
            Err(DsigError::Policy(PolicyViolation::AuthorizationExpired))
        ),
        "{result:?}"
    );
}

/// The selected provider executes the method; needs the built-in provider
/// both to compute the value and to offer the method being refused.
#[cfg(feature = "rustcrypto")]
mod selected_provider {
    use alloc::{boxed::Box, vec::Vec};

    use super::*;
    use crate::provider::{
        CryptoProvider, KdfParameters, ProviderCapability, ProviderError, ProviderOperation,
    };
    use crate::xmldsig::{IncrementalHmac, SigningKey, SigningKeyError};

    fn mac() -> Vec<u8> {
        let mut mac = IncrementalHmac::begin(SignatureAlgorithm::HmacSha256, &SECRET)
            .expect("a 256-bit HMAC key");
        mac.update(DATA);
        mac.finish()
    }

    /// Offers every capability of the default provider and refuses to verify.
    struct RefusingVerification;

    impl CryptoProvider for RefusingVerification {
        fn name(&self) -> &'static str {
            "refusing-verification"
        }

        fn supports(&self, capability: ProviderCapability<'_>) -> bool {
            default_provider().supports(capability)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
            default_provider().fill_random(output)
        }

        fn derive_key(
            &self,
            parameters: &KdfParameters<'_>,
            secret: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().derive_key(parameters, secret)
        }

        fn begin_digest(
            &self,
            algorithm: crate::xmldsig::DigestAlgorithm,
            memory: &structured_asn1::memory::Memory,
        ) -> Result<Box<dyn crate::provider::DigestState + '_>, ProviderError> {
            default_provider().begin_digest(algorithm, memory)
        }

        fn sign(
            &self,
            key: &dyn SigningKey,
            algorithm: SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            default_provider().sign(key, algorithm, data)
        }

        fn verify(
            &self,
            _key: &dyn VerifyingKey,
            algorithm: SignatureAlgorithm,
            _data: &[u8],
            _signature: &[u8],
        ) -> Result<bool, DsigError> {
            Err(ProviderError::Unsupported {
                operation: ProviderOperation::Verify,
                algorithm: Some(algorithm.uri().into()),
            }
            .into())
        }

        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().encrypt_data(algorithm, key, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().decrypt_data(algorithm, key, ciphertext)
        }

        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().wrap_key(algorithm, kek, key)
        }

        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().unwrap_key(algorithm, kek, wrapped)
        }

        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            key: &dyn crate::provider::KeyTransportKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &dyn crate::provider::KeyRecoveryKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            default_provider().recover_key(key, parameters, ciphertext)
        }
    }

    #[test]
    fn the_supplied_key_is_charged_as_an_inspected_candidate() {
        // The caller's key is one inspected candidate, as document
        // verification charges its root key: a budget of none refuses it,
        // and one admits it.
        let algorithm = SignatureAlgorithm::HmacSha256;
        let value = mac();
        let mut policy = VerificationPolicy::default();
        policy.resources.max_key_candidates = 0;
        let refused =
            verify_signature_value(&policy, default_provider(), &key(), algorithm, DATA, &value);
        assert!(matches!(refused, Err(DsigError::Policy(_))), "{refused:?}");
        policy.resources.max_key_candidates = 1;
        let admitted =
            verify_signature_value(&policy, default_provider(), &key(), algorithm, DATA, &value);
        assert!(matches!(admitted, Ok(true)), "{admitted:?}");
    }

    #[test]
    fn verification_runs_through_the_selected_provider() {
        // The provider that offers the method also executes it: its refusal
        // is the result, never a verification by the key behind its back.
        let policy = VerificationPolicy::default();
        let algorithm = SignatureAlgorithm::HmacSha256;
        let value = mac();
        let built_in =
            verify_signature_value(&policy, default_provider(), &key(), algorithm, DATA, &value);
        assert!(matches!(built_in, Ok(true)), "{built_in:?}");
        let refused = verify_signature_value(
            &policy,
            &RefusingVerification,
            &key(),
            algorithm,
            DATA,
            &value,
        );
        assert!(
            matches!(
                refused,
                Err(DsigError::Provider(ProviderError::Unsupported {
                    operation: ProviderOperation::Verify,
                    ..
                }))
            ),
            "{refused:?}"
        );
    }
}
