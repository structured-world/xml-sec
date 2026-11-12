//! Signature-value verification under a verification policy, outside a
//! document operation.

use core::cell::RefCell;

use super::{DsigError, SignatureAlgorithm, VerificationScope, VerifyingKey};

/// Verify `signature_value` over `signed_data` with `key` as signature
/// verification does under `policy`: the method must be permitted, the key
/// must meet the policy's strength and the value its wire framing, and the
/// provider must offer the method. For a caller that has the signed bytes
/// itself, such as a transform chain.
///
/// # Errors
/// Returns a policy refusal, an unsupported method or the key's
/// verification-processing failure; a completed cryptographic mismatch and a
/// value of the wrong framing are `Ok(false)`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rustcrypto")]
/// # {
/// use xml_sec::policy::VerificationPolicy;
/// use xml_sec::xmldsig::verify::verify_signature_value;
/// use xml_sec::xmldsig::{HmacVerificationKey, IncrementalHmac, SignatureAlgorithm};
///
/// let secret = [0x42; 32];
/// let mut mac = IncrementalHmac::begin(SignatureAlgorithm::HmacSha256, &secret)?;
/// mac.update(b"signed bytes");
/// let value = mac.finish();
/// let key = HmacVerificationKey::new(secret.to_vec())?;
/// let policy = VerificationPolicy::default();
/// let provider = xml_sec::provider::default_provider();
/// let algorithm = SignatureAlgorithm::HmacSha256;
/// assert!(verify_signature_value(&policy, provider, &key, algorithm, b"signed bytes", &value)?);
/// assert!(!verify_signature_value(&policy, provider, &key, algorithm, b"other bytes", &value)?);
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn verify_signature_value(
    policy: &crate::policy::VerificationPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    key: &dyn VerifyingKey,
    algorithm: SignatureAlgorithm,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, DsigError> {
    // The complete snapshot first, its authorization interval included, as
    // document verification admits a policy.
    policy.validate()?;
    policy.check_signature_algorithm(algorithm)?;
    let candidates = RefCell::new(crate::xmldsig::InspectedKeyCandidateBudget::new(policy));
    // The supplied key is one inspected candidate, as document verification
    // charges the key it inspects.
    candidates.borrow_mut().charge()?;
    let certificates = candidates.borrow().certificates().share();
    let scope = VerificationScope::new(policy, &certificates);
    key.validate_policy(&scope)?;
    if !key.validate_signature_value_with_policy(&scope, algorithm, signature_value)? {
        return Ok(false);
    }
    provider.require_capability(crate::provider::ProviderCapability::Verify(algorithm))?;
    // The provider executes the method over the policy-scoped key, as the
    // signature verification of a document does.
    let candidate_refusal = RefCell::new(None);
    let verifier = super::PolicyVerifyingKey {
        key,
        scope,
        candidates: &candidates,
        candidate_refusal: &candidate_refusal,
    };
    let context = crate::xmldsig::SignatureContext::new(&[])?;
    let input = crate::provider::SignatureVerificationInput::new(
        algorithm,
        &context,
        signed_data,
        signature_value,
    );
    // A provider that reads the key material itself does so under this
    // call's certificate account, as in document verification.
    #[cfg(feature = "aws-lc-fips")]
    let input = input.with_certificates(&certificates);
    let result = provider.verify_with_key_receipt(&verifier, input, &mut |_| Ok(()));
    if let Some(error) = candidate_refusal.into_inner() {
        return Err(error.into());
    }
    result
}

#[cfg(test)]
mod tests;
