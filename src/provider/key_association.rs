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
    let mut admitted = 0;
    let mut observer_refused = false;
    let result = observed_at_depth(
        key,
        &mut |event| {
            if observer_refused {
                return Err(MemoryError::WorkExceeded.into());
            }
            let result = observer(event);
            if matches!(
                result,
                Err(DsigError::SharedExecution(MemoryError::WorkExceeded))
            ) {
                observer_refused = true;
            }
            result
        },
        verify_leaf,
        0,
        &mut admitted,
    );
    // A composite may recover from a visitor error, but cannot recover capacity
    // after a terminal hard refusal and report an unchecked later success.
    if observer_refused || admitted > crate::hard_limits::KEY_CANDIDATE_CEILING {
        return Err(MemoryError::WorkExceeded.into());
    }
    result
}

fn observed_at_depth<F, O>(
    key: &dyn VerifyingKey,
    observer: &mut O,
    verify_leaf: &F,
    depth: usize,
    admitted: &mut usize,
) -> Result<bool, DsigError>
where
    F: Fn(&dyn VerifyingKey) -> Result<bool, DsigError>,
    O: FnMut(KeyVerificationEvent<'_>) -> Result<(), DsigError> + ?Sized,
{
    if depth == crate::hard_limits::KEY_CANDIDATE_CEILING
        || *admitted >= crate::hard_limits::KEY_CANDIDATE_CEILING
    {
        *admitted = crate::hard_limits::KEY_CANDIDATE_CEILING + 1;
        return Err(MemoryError::WorkExceeded.into());
    }
    *admitted += 1;
    observer(KeyVerificationEvent::BeforeCandidate { depth })?;
    if let Some(result) = key.verify_candidate_keys(&mut |candidate| {
        observed_at_depth(candidate, observer, verify_leaf, depth + 1, admitted)
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
    use der::{Decode as _, Tagged as _};
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
    let rsa_pss = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    // RFC 4055 §3.1: PSS parameters are absent or RSASSA-PSS-params, never
    // NULL. PSS does not inherit parameters; retain the original field rather
    // than the generic WorkingKey projection which treats NULL as absent.
    // https://www.rfc-editor.org/rfc/rfc4055#section-3.1
    let effective_parameters = if algorithm.algorithm().as_bytes() == rsa_pss.as_bytes() {
        algorithm.parameters()
    } else {
        expected.parameters()
    };
    let parameters = match effective_parameters {
        Some(bytes) => match der::asn1::AnyRef::from_der(bytes) {
            Ok(value) => Some(value),
            Err(_) => return Ok(KeyAssociation::Unproven),
        },
        None => None,
    };
    let expected_oid = algorithm.algorithm().as_bytes();
    let actual_rsa =
        actual.algorithm.oid == pkcs1::ALGORITHM_OID || actual.algorithm.oid == rsa_pss;
    let expected_rsa =
        expected_oid == pkcs1::ALGORITHM_OID.as_bytes() || expected_oid == rsa_pss.as_bytes();
    if actual_rsa && expected_rsa {
        // RFC 3279 §2.3.1: RSA key identity consists of n and e. Omitted
        // versus NULL parameters are tolerated by the existing RSA codec.
        // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1
        if (actual.algorithm.oid == pkcs1::ALGORITHM_OID
            && actual
                .algorithm
                .parameters
                .is_some_and(|value| !value.is_null()))
            || (expected_oid == pkcs1::ALGORITHM_OID.as_bytes()
                && parameters.is_some_and(|value| !value.is_null()))
            || (actual.algorithm.oid == rsa_pss
                && actual
                    .algorithm
                    .parameters
                    .is_some_and(|value| value.tag() != der::Tag::Sequence))
            || (expected_oid == rsa_pss.as_bytes()
                && parameters.is_some_and(|value| value.tag() != der::Tag::Sequence))
        {
            return Ok(KeyAssociation::Unproven);
        }
        let components = rsa_components(bits, expected_bits);
        // RFC 4055 §3.3 constrains PSS use independently of n/e. Comparing
        // components across rsaEncryption/PSS can prove a different key, but
        // equal components do not prove equal effective algorithm restrictions.
        // This Same/Mismatch/Unproven classification is product reporting.
        // https://www.rfc-editor.org/rfc/rfc4055#section-3.3
        return Ok(
            if components == KeyAssociation::Same
                && (actual.algorithm.oid.as_bytes() != expected_oid
                    || (actual.algorithm.oid == rsa_pss
                        && actual.algorithm.parameters != parameters))
            {
                KeyAssociation::Unproven
            } else {
                components
            },
        );
    }
    if actual.algorithm.oid.as_bytes() != expected_oid {
        return Ok(KeyAssociation::Unproven);
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
    #[cfg(feature = "experimental-pq")]
    if rustcrypto_points
        && let Some(algorithm) = crate::xmldsig::PqAlgorithm::from_oid(actual.algorithm.oid)
    {
        // RFC 9881 §§2,4 / RFC 9909 §§3,5 require absent parameters and
        // fixed-width raw public encodings. Validate both before byte equality;
        // identical malformed encodings do not establish key association.
        // https://www.rfc-editor.org/rfc/rfc9881.html#section-4
        // https://www.rfc-editor.org/rfc/rfc9909.html#section-5
        return Ok(
            if actual.algorithm.parameters.is_some()
                || expected.key().algorithm().parameters().is_some()
                || parameters.is_some()
                || !valid_pq_public_encoding(algorithm, bits)
                || !valid_pq_public_encoding(algorithm, expected_bits)
            {
                KeyAssociation::Unproven
            } else if bits == expected_bits {
                KeyAssociation::Same
            } else {
                KeyAssociation::Mismatch
            },
        );
    }
    if rustcrypto_points
        && (actual.algorithm.oid == ed25519_dalek::pkcs8::ALGORITHM_OID
            || actual.algorithm.oid == ed448_goldilocks::ALGORITHM_OID)
    {
        // RFC 8410 §§3–4 requires absent parameters and encoded public-key
        // octets; RFC 8032 §§5.1.3/5.2.3 defines their point encoding. Decode
        // only inside the selected RustCrypto provider, never as native fallback.
        // https://www.rfc-editor.org/rfc/rfc8410#section-4
        // https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3
        // WorkingKey's generic effective projection treats NULL as absent;
        // the original encoding is still governed by RFC 8410 §3.
        // https://www.rfc-editor.org/rfc/rfc8410#section-3
        if actual.algorithm.parameters.is_some()
            || expected.key().algorithm().parameters().is_some()
            || parameters.is_some()
        {
            return Ok(KeyAssociation::Unproven);
        }
        macro_rules! compare_edwards {
            ($key:ty, $length:expr, $width:expr, $point:ident, $encoded:expr) => {{
                let (Ok(left), Ok(right)) = (
                    <&[u8; $length]>::try_from(bits),
                    <&[u8; $length]>::try_from(expected_bits),
                ) else {
                    return Ok(KeyAssociation::Unproven);
                };
                charge($width * $width * 8)?;
                let Ok(left) = <$key>::from_bytes(left) else {
                    return Ok(KeyAssociation::Unproven);
                };
                let $point = left.to_edwards();
                let left = $encoded;
                // Point decoders may accept noncanonical encodings. Such wire
                // aliases are not validated RFC 8032 public-key encodings.
                if left.as_slice() != bits {
                    KeyAssociation::Unproven
                } else if bits == expected_bits {
                    // Reuse the first decoded point for identical input.
                    KeyAssociation::Same
                } else {
                    charge($width * $width * 8)?;
                    let Ok(right) = <$key>::from_bytes(right) else {
                        return Ok(KeyAssociation::Unproven);
                    };
                    let $point = right.to_edwards();
                    let right = $encoded;
                    if right.as_slice() != expected_bits {
                        KeyAssociation::Unproven
                    } else {
                        KeyAssociation::Mismatch
                    }
                }
            }};
        }
        return Ok(
            if actual.algorithm.oid == ed25519_dalek::pkcs8::ALGORITHM_OID {
                compare_edwards!(
                    ed25519_dalek::VerifyingKey,
                    32,
                    256,
                    point,
                    point.compress().to_bytes()
                )
            } else {
                compare_edwards!(
                    ed448_goldilocks::VerifyingKey,
                    57,
                    448,
                    point,
                    point.to_affine().compress().0
                )
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

#[cfg(feature = "experimental-pq")]
fn valid_pq_public_encoding(algorithm: crate::xmldsig::PqAlgorithm, bytes: &[u8]) -> bool {
    use crate::rustcrypto_ml_dsa as ml_dsa;
    use crate::xmldsig::PqAlgorithm;
    // FIPS 204 §7.2 Algorithms 22–23: pkDecode is a bijection over the
    // fixed-size rho/t1 encoding (every packed 10-bit coefficient is valid).
    // Admission uses the selected backend's borrowed encoded-key type, not
    // matrix expansion, key cloning or a second signature verification.
    // https://doi.org/10.6028/NIST.FIPS.204
    fn ml<P: ml_dsa::MlDsaParams>(bytes: &[u8]) -> bool {
        <&ml_dsa::EncodedVerifyingKey<P>>::try_from(bytes).is_ok()
    }
    // FIPS 205 §9.1 / RFC 9909 §5: every seed||root of width 2*n is a
    // public encoding; backend-associated width validation needs no copy.
    // https://www.rfc-editor.org/rfc/rfc9909.html#section-5
    fn slh<P: slh_dsa::ParameterSet>(bytes: &[u8]) -> bool {
        <&hybrid_array::Array<u8, P::VkLen>>::try_from(bytes).is_ok()
    }
    match algorithm {
        PqAlgorithm::MlDsa44 => ml::<ml_dsa::MlDsa44>(bytes),
        PqAlgorithm::MlDsa65 => ml::<ml_dsa::MlDsa65>(bytes),
        PqAlgorithm::MlDsa87 => ml::<ml_dsa::MlDsa87>(bytes),
        PqAlgorithm::SlhDsaSha2_128f => slh::<slh_dsa::Sha2_128f>(bytes),
        PqAlgorithm::SlhDsaSha2_128s => slh::<slh_dsa::Sha2_128s>(bytes),
        PqAlgorithm::SlhDsaSha2_192f => slh::<slh_dsa::Sha2_192f>(bytes),
        PqAlgorithm::SlhDsaSha2_192s => slh::<slh_dsa::Sha2_192s>(bytes),
        PqAlgorithm::SlhDsaSha2_256f => slh::<slh_dsa::Sha2_256f>(bytes),
        PqAlgorithm::SlhDsaSha2_256s => slh::<slh_dsa::Sha2_256s>(bytes),
    }
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
