//! Signature-value creation under a signing policy, outside a document
//! operation.

use super::{
    SignatureAlgorithm, SigningError, SigningKey, SigningKeyError, encode_signature_output,
    expected_signature_output_len, validate_signature_output,
};

/// The `SignatureValue` octets of `signed_data` signed by `key` with
/// `algorithm` under `policy`, as document signing produces them: the method
/// must be permitted and offered by the provider, the output must have the
/// length the key and method determine, and an ECDSA value is written in the
/// policy's [`ecdsa_signature_value_encoding`]. For a caller that has the
/// signed bytes itself, such as a transform chain. The key counts as one of
/// the policy's key candidates. `context` is the context
/// string of a method that takes one (Ed25519ctx, Ed448, ML-DSA); empty for
/// the others. The counterpart of
/// [`verify_signature_value`](crate::xmldsig::verify::verify_signature_value).
///
/// [`ecdsa_signature_value_encoding`]: crate::policy::SigningPolicy::ecdsa_signature_value_encoding
///
/// # Errors
/// Returns a policy refusal, an unsupported method, the key's signing
/// failure or an output of the wrong length.
///
/// # Examples
///
/// ```
/// use xml_sec::policy::SigningPolicy;
/// use xml_sec::xmldsig::sign::sign_signature_value;
/// use xml_sec::xmldsig::{HmacSigningKey, SignatureAlgorithm, SignatureContext};
///
/// let key = HmacSigningKey::new(vec![0x42; 32])?;
/// let value = sign_signature_value(
///     &SigningPolicy::default(),
///     xml_sec::provider::default_provider(),
///     &key,
///     SignatureAlgorithm::HmacSha256,
///     &SignatureContext::default(),
///     b"signed bytes",
/// )?;
/// assert_eq!(value.len(), 32);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn sign_signature_value(
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    key: &dyn SigningKey,
    algorithm: SignatureAlgorithm,
    context: &crate::xmldsig::SignatureContext,
    signed_data: &[u8],
) -> Result<Vec<u8>, SigningError> {
    policy.validate()?;
    // The supplied key is one key candidate, as in document signing.
    policy.resources.validate_key_candidates(1)?;
    policy.check_signature_algorithm(algorithm)?;
    let expected = expected_signature_output_len(key, algorithm, policy, None)?;
    provider
        .require_capability(crate::provider::ProviderCapability::Sign(algorithm))
        .map_err(SigningKeyError::from)?;
    // The full output is asked for, an HMAC's included, so the value is
    // checked as the provider returned it.
    let value = provider.sign_with_context(key, algorithm, context, signed_data)?;
    validate_signature_output(expected, &value)?;
    encode_signature_output(algorithm, value, policy.ecdsa_signature_value_encoding)
}

#[cfg(test)]
mod tests;
