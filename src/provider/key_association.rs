//! Selected-provider evidence, separate from key authorization and trust.

use crate::xmldsig::{DsigError, SignatureAlgorithm, SignatureContext, VerifyingKey};
use structured_asn1::memory::MemoryError;
use structured_pkix::path::WorkingKey;

/// Public-key association established by the originally selected provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAssociation {
    /// The expected effective public key is the successful verification key.
    Same,
    /// Public-key semantics establish a different key.
    Mismatch,
    /// Available public evidence cannot establish either conclusion.
    Unproven,
}

/// Borrowed input to one original signature verification, never a second pass.
#[derive(Clone, Copy)]
pub struct SignatureVerificationInput<'a> {
    /// Originally parsed method and effective parameters.
    pub algorithm: SignatureAlgorithm,
    /// Originally parsed domain separation.
    pub context: &'a SignatureContext,
    /// Original canonical SignedInfo bytes.
    pub data: &'a [u8],
    /// Original decoded SignatureValue.
    pub signature: &'a [u8],
}

/// Provider observations; only a successful leaf can supply key evidence.
pub enum KeyVerificationEvent<'a> {
    /// Admit another candidate dispatch; a previous terminal refusal stays terminal.
    BeforeCandidate {
        /// Nested composite depth, bounded by the hard candidate ceiling.
        depth: usize,
    },
    /// This exact leaf returned a successful cryptographic verification.
    Verified(&'a dyn VerifyingKey),
}

pub(super) fn observed_leaf<F, O>(
    key: &dyn VerifyingKey,
    observer: &mut O,
    verify_leaf: &F,
) -> Result<bool, DsigError>
where
    F: Fn(&dyn VerifyingKey) -> Result<bool, DsigError>,
    O: FnMut(KeyVerificationEvent<'_>) -> Result<(), DsigError> + ?Sized,
{
    observed_at_depth(key, observer, verify_leaf, 0)
}

fn observed_at_depth<F, O>(
    key: &dyn VerifyingKey,
    observer: &mut O,
    verify_leaf: &F,
    depth: usize,
) -> Result<bool, DsigError>
where
    F: Fn(&dyn VerifyingKey) -> Result<bool, DsigError>,
    O: FnMut(KeyVerificationEvent<'_>) -> Result<(), DsigError> + ?Sized,
{
    observer(KeyVerificationEvent::BeforeCandidate { depth })?;
    if depth == crate::hard_limits::KEY_CANDIDATE_CEILING {
        return Err(MemoryError::WorkExceeded.into());
    }
    if let Some(result) = key.verify_candidate_keys(&mut |candidate| {
        observed_at_depth(candidate, observer, verify_leaf, depth + 1)
    })? {
        return Ok(result);
    }
    let verified = verify_leaf(key)?;
    if verified {
        observer(KeyVerificationEvent::Verified(key))?;
    }
    Ok(verified)
}

#[cfg(any(feature = "aws-lc-fips", feature = "pkcs11"))]
pub(super) fn compare(
    actual: &[u8],
    expected: WorkingKey<'_>,
    charge: &dyn Fn(u64) -> Result<(), MemoryError>,
) -> Result<KeyAssociation, DsigError> {
    compare_with_points(actual, expected, charge, false)
}

pub(super) fn compare_rustcrypto(
    actual: &[u8],
    expected: WorkingKey<'_>,
    charge: &dyn Fn(u64) -> Result<(), MemoryError>,
) -> Result<KeyAssociation, DsigError> {
    compare_with_points(actual, expected, charge, true)
}

fn compare_with_points(
    actual: &[u8],
    expected: WorkingKey<'_>,
    charge: &dyn Fn(u64) -> Result<(), MemoryError>,
    rustcrypto_points: bool,
) -> Result<KeyAssociation, DsigError> {
    use der::Decode as _;
    // Borrowed DER decoding and comparisons are linear in the supplied source;
    // admit their complete byte scans before entering either codec.
    let size = actual
        .len()
        .checked_add(expected.key().as_bytes().len())
        .and_then(|size| size.checked_add(expected.parameters().map_or(0, <[u8]>::len)))
        .and_then(|size| size.checked_mul(8))
        .and_then(|size| size.checked_add(256))
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(MemoryError::WorkExceeded)?;
    charge(size)?;
    let Ok(actual) = pkcs8::SubjectPublicKeyInfoRef::from_der(actual) else {
        return Ok(KeyAssociation::Unproven);
    };
    let Some(bits) = actual.subject_public_key.as_bytes() else {
        return Ok(KeyAssociation::Unproven);
    };
    let Some(expected_bits) = expected.key().key_octets() else {
        return Ok(KeyAssociation::Unproven);
    };
    let algorithm = expected.key().algorithm();
    if actual.algorithm.oid.as_bytes() != algorithm.algorithm().as_bytes() {
        return Ok(KeyAssociation::Unproven);
    }
    let parameters = match expected.parameters() {
        Some(bytes) => match der::asn1::AnyRef::from_der(bytes) {
            Ok(value) => Some(value),
            Err(_) => return Ok(KeyAssociation::Unproven),
        },
        None => None,
    };
    if actual.algorithm.oid == pkcs1::ALGORITHM_OID {
        // RFC 3279 §2.3.1: RSA key identity consists of n and e. Omitted
        // versus NULL parameters are tolerated by the existing RSA codec.
        // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1
        if actual
            .algorithm
            .parameters
            .is_some_and(|value| !value.is_null())
            || parameters.is_some_and(|value| !value.is_null())
        {
            return Ok(KeyAssociation::Unproven);
        }
        return Ok(rsa_components(bits, expected_bits));
    }
    let dsa = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
    if actual.algorithm.oid == dsa {
        // RFC 3279 §2.3.2: y alone is not a DSA key; the effective p/q/g
        // may come from the checked path rather than the subject's SPKI.
        // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
        let (Some(actual_params), Some(expected_params)) =
            (actual.algorithm.parameters, parameters)
        else {
            return Ok(KeyAssociation::Unproven);
        };
        let (Ok(actual_params), Ok(expected_params), Ok(actual_y), Ok(expected_y)) = (
            actual_params.decode_as::<crate::xmldsig::signature::BorrowedDsaPublicParameters<'_>>(),
            expected_params
                .decode_as::<crate::xmldsig::signature::BorrowedDsaPublicParameters<'_>>(),
            der::asn1::UintRef::from_der(bits),
            der::asn1::UintRef::from_der(expected_bits),
        ) else {
            return Ok(KeyAssociation::Unproven);
        };
        return Ok(
            if actual_y == expected_y
                && actual_params.p == expected_params.p
                && actual_params.q == expected_params.q
                && actual_params.g == expected_params.g
            {
                KeyAssociation::Same
            } else {
                KeyAssociation::Mismatch
            },
        );
    }
    if actual.algorithm.parameters != parameters {
        // RFC 5280 §6.1.3 preserves effective working parameters. Method
        // compatibility alone does not prove equal PSS restrictions or groups.
        // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3
        return Ok(KeyAssociation::Unproven);
    }
    // Exact original algorithm, effective parameters and public octets prove
    // association without re-encoding, fingerprints or another signature check.
    if bits == expected_bits {
        return Ok(KeyAssociation::Same);
    }
    if actual.algorithm.oid == der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10") {
        return Ok(rsa_components(bits, expected_bits));
    }
    if rustcrypto_points && actual.algorithm.oid == p256::elliptic_curve::ALGORITHM_OID {
        let Some(curve) =
            parameters.and_then(|value| value.decode_as::<der::asn1::ObjectIdentifier>().ok())
        else {
            return Ok(KeyAssociation::Unproven);
        };
        // RFC 5480 §2.2 permits compressed/uncompressed points. Only the
        // selected RustCrypto provider uses its own point decoder here.
        // https://www.rfc-editor.org/rfc/rfc5480#section-2.2
        macro_rules! compare_points {
            ($curve:ty, $bits:expr) => {{
                // Two fixed-width point decodings/comparison have a fixed
                // field-arithmetic admission, independent of XML length.
                charge($bits * $bits * 16)?;
                match (
                    <$curve>::from_sec1_bytes(bits),
                    <$curve>::from_sec1_bytes(expected_bits),
                ) {
                    (Ok(left), Ok(right)) => {
                        if left == right {
                            KeyAssociation::Same
                        } else {
                            KeyAssociation::Mismatch
                        }
                    }
                    _ => KeyAssociation::Unproven,
                }
            }};
        }
        return Ok(
            if curve == der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7") {
                compare_points!(p256::PublicKey, 256)
            } else if curve == der::asn1::ObjectIdentifier::new_unwrap("1.3.132.0.34") {
                compare_points!(p384::PublicKey, 384)
            } else if curve == der::asn1::ObjectIdentifier::new_unwrap("1.3.132.0.35") {
                compare_points!(p521::PublicKey, 521)
            } else {
                KeyAssociation::Unproven
            },
        );
    }
    Ok(KeyAssociation::Unproven)
}

fn rsa_components(actual: &[u8], expected: &[u8]) -> KeyAssociation {
    use der::Decode as _;
    let (Ok(actual), Ok(expected)) = (
        pkcs1::RsaPublicKeyRef::from_der(actual),
        pkcs1::RsaPublicKeyRef::from_der(expected),
    ) else {
        return KeyAssociation::Unproven;
    };
    if actual.modulus == expected.modulus && actual.public_exponent == expected.public_exponent {
        KeyAssociation::Same
    } else {
        KeyAssociation::Mismatch
    }
}
