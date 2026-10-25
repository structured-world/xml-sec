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
#[non_exhaustive]
pub struct SignatureVerificationInput<'a> {
    /// Originally parsed method and effective parameters.
    pub algorithm: SignatureAlgorithm,
    /// Originally parsed domain separation.
    pub context: &'a SignatureContext,
    /// Original canonical `SignedInfo` bytes.
    pub data: &'a [u8],
    /// Original decoded `SignatureValue`.
    pub signature: &'a [u8],
    /// The verification operation's key-material account, when the input
    /// comes from one; a standalone provider call reads under its own. Only
    /// the native provider reads SPKI itself; the software provider reads it
    /// through the operation-scoped key hooks.
    #[cfg(feature = "aws-lc-fips")]
    certificates: Option<&'a crate::xmldsig::pkix::CertificateSession>,
}

impl<'a> SignatureVerificationInput<'a> {
    /// Input for a standalone verification outside a [`VerifyContext`] operation.
    ///
    /// [`VerifyContext`]: crate::xmldsig::VerifyContext
    #[must_use]
    pub fn new(
        algorithm: SignatureAlgorithm,
        context: &'a SignatureContext,
        data: &'a [u8],
        signature: &'a [u8],
    ) -> Self {
        Self {
            algorithm,
            context,
            data,
            signature,
            #[cfg(feature = "aws-lc-fips")]
            certificates: None,
        }
    }

    #[cfg(feature = "aws-lc-fips")]
    pub(crate) fn with_certificates(
        self,
        certificates: &'a crate::xmldsig::pkix::CertificateSession,
    ) -> Self {
        Self {
            certificates: Some(certificates),
            ..self
        }
    }

    /// Reads `use_session` under the operation's account, or a standalone
    /// hard-ceiling account when this input belongs to no operation.
    #[cfg(feature = "aws-lc-fips")]
    pub(crate) fn with_session<T>(
        &self,
        use_session: impl FnOnce(&crate::xmldsig::pkix::CertificateSession) -> T,
    ) -> T {
        match self.certificates {
            Some(session) => use_session(session),
            None => use_session(&crate::xmldsig::pkix::CertificateSession::standalone()),
        }
    }
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
    // Borrowed decoding and comparisons are linear in the supplied source;
    // admit their complete byte scans before reading either key.
    let size = actual
        .len()
        .checked_add(expected.key().as_bytes().len())
        .and_then(|size| size.checked_add(expected.parameters().map_or(0, <[u8]>::len)))
        .and_then(|size| size.checked_mul(8))
        .and_then(|size| size.checked_add(256))
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(MemoryError::WorkExceeded)?;
    charge(size)?;
    // The shared PKIX reader owns the actual SPKI syntax, as it does the expected key's.
    // The operation was charged for this whole scan above through `charge`;
    // the reader's own account only bounds the borrowed decode.
    let session = crate::xmldsig::pkix::CertificateSession::standalone();
    session
        .with_public_key_info(actual, |actual, execution| {
            Ok(associate(
                actual,
                expected,
                execution,
                charge,
                rustcrypto_points,
            ))
        })
        .unwrap_or(Ok(KeyAssociation::Unproven))
}

fn associate(
    actual: structured_pkix::PublicKeyInfo<'_>,
    expected: WorkingKey<'_>,
    execution: &structured_asn1::memory::Execution<'_>,
    charge: &dyn Fn(u64) -> Result<(), MemoryError>,
    rustcrypto_points: bool,
) -> Result<KeyAssociation, DsigError> {
    use structured_pkix::oid::{EC_PUBLIC_KEY, ED448, ED25519, RSA_ENCRYPTION, RSASSA_PSS};
    let (Some(bits), Some(expected_bits)) = (actual.key_octets(), expected.key().key_octets())
    else {
        return Ok(KeyAssociation::Unproven);
    };
    let actual_algorithm = actual.algorithm();
    let algorithm = expected.key().algorithm();
    let actual_oid = actual_algorithm.algorithm();
    let expected_oid = algorithm.algorithm();
    // RFC 4055 §3.1: PSS parameters are absent or RSASSA-PSS-params, never
    // NULL. PSS does not inherit parameters; retain the original field rather
    // than the generic WorkingKey projection which treats NULL as absent.
    // https://www.rfc-editor.org/rfc/rfc4055#section-3.1
    let parameters = if expected_oid == RSASSA_PSS {
        algorithm.parameters()
    } else {
        expected.parameters()
    };
    let is_rsa = |oid| oid == RSA_ENCRYPTION || oid == RSASSA_PSS;
    if is_rsa(actual_oid) && is_rsa(expected_oid) {
        return Ok(compare_rsa_material(
            actual, expected, parameters, execution,
        ));
    }
    if actual_oid != expected_oid {
        return Ok(KeyAssociation::Unproven);
    }
    if actual_oid.as_bytes() == dsa::OID.as_bytes() {
        return Ok(compare_dsa_material(actual, expected, execution));
    }
    #[cfg(feature = "experimental-pq")]
    if rustcrypto_points
        && let Some(algorithm) = crate::xmldsig::PqAlgorithm::from_oid(actual_oid.as_bytes())
    {
        // RFC 9881 §§2,4 / RFC 9909 §§3,5 require absent parameters and
        // fixed-width raw public encodings. Validate both before byte equality;
        // identical malformed encodings do not establish key association.
        // https://www.rfc-editor.org/rfc/rfc9881.html#section-4
        // https://www.rfc-editor.org/rfc/rfc9909.html#section-5
        return Ok(
            if actual_algorithm.parameters().is_some()
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
    if rustcrypto_points && (actual_oid == ED25519 || actual_oid == ED448) {
        // RFC 8410 §§3–4 requires absent parameters and encoded public-key
        // octets; RFC 8032 §§5.1.3/5.2.3 defines their point encoding. Decode
        // only inside the selected RustCrypto provider, never as native fallback.
        // https://www.rfc-editor.org/rfc/rfc8410#section-4
        // https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3
        // WorkingKey's generic effective projection treats NULL as absent;
        // the original encoding is still governed by RFC 8410 §3.
        // https://www.rfc-editor.org/rfc/rfc8410#section-3
        if actual_algorithm.parameters().is_some()
            || expected.key().algorithm().parameters().is_some()
            || parameters.is_some()
        {
            return Ok(KeyAssociation::Unproven);
        }
        return compare_edwards_points(actual_oid == ED25519, bits, expected_bits, charge);
    }
    if actual_algorithm.parameters() != parameters {
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
    if rustcrypto_points && actual_oid == EC_PUBLIC_KEY {
        // RFC 5480 §2.1.1.1 namedCurve parameters, as whole DER OBJECT IDENTIFIERs.
        const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
        let Some(curve) = parameters else {
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
        return Ok(if curve == P256 {
            compare_points!(p256::PublicKey, 256)
        } else if curve == P384 {
            compare_points!(p384::PublicKey, 384)
        } else if curve == P521 {
            compare_points!(p521::PublicKey, 521)
        } else {
            KeyAssociation::Unproven
        });
    }
    Ok(KeyAssociation::Unproven)
}

#[inline]
fn compare_rsa_material(
    actual: structured_pkix::PublicKeyInfo<'_>,
    expected: WorkingKey<'_>,
    parameters: Option<&[u8]>,
    execution: &structured_asn1::memory::Execution<'_>,
) -> KeyAssociation {
    use structured_pkix::oid::{RSA_ENCRYPTION, RSASSA_PSS};
    const NULL: &[u8] = &[0x05, 0x00];
    // RFC 3279 §2.3.1: RSA key identity consists of n and e. Omitted
    // versus NULL parameters are tolerated by the existing RSA codec.
    // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1
    let actual_algorithm = actual.algorithm();
    let actual_oid = actual_algorithm.algorithm();
    let actual_parameters = actual_algorithm.parameters();
    let expected_oid = expected.key().algorithm().algorithm();
    // A whole constructed SEQUENCE parameter starts with its DER tag octet.
    let sequence = |value: &[u8]| value.first() == Some(&0x30);
    if (actual_oid == RSA_ENCRYPTION && !actual_algorithm.has_no_parameters())
        || (expected_oid == RSA_ENCRYPTION && parameters.is_some_and(|value| value != NULL))
        || (actual_oid == RSASSA_PSS && actual_parameters.is_some_and(|value| !sequence(value)))
        || (expected_oid == RSASSA_PSS && parameters.is_some_and(|value| !sequence(value)))
    {
        return KeyAssociation::Unproven;
    }
    let (Ok(left), Ok(right)) = (
        structured_pkix::key::rsa::read(actual, execution),
        structured_pkix::key::rsa::read(expected.key(), execution),
    ) else {
        return KeyAssociation::Unproven;
    };
    let components = if left.modulus().as_bytes() == right.modulus().as_bytes()
        && left.exponent().as_bytes() == right.exponent().as_bytes()
    {
        KeyAssociation::Same
    } else {
        KeyAssociation::Mismatch
    };
    // RFC 4055 §3.3 constrains PSS use independently of n/e. Comparing
    // components across rsaEncryption/PSS can prove a different key, but
    // equal components do not prove equal effective algorithm restrictions.
    // This Same/Mismatch/Unproven classification is product reporting.
    // https://www.rfc-editor.org/rfc/rfc4055#section-3.3
    if components == KeyAssociation::Same
        && (actual_oid != expected_oid
            || (actual_oid == RSASSA_PSS && actual_parameters != parameters))
    {
        KeyAssociation::Unproven
    } else {
        components
    }
}

#[inline]
fn compare_dsa_material(
    actual: structured_pkix::PublicKeyInfo<'_>,
    expected: WorkingKey<'_>,
    execution: &structured_asn1::memory::Execution<'_>,
) -> KeyAssociation {
    use structured_pkix::key::dsa;
    // RFC 3279 §2.3.2: y alone is not a DSA key; the effective p/q/g
    // may come from the checked path rather than the subject's SPKI.
    // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
    let (Ok(actual), Ok(expected)) = (
        dsa::read(WorkingKey::standing(actual), execution),
        dsa::read(expected, execution),
    ) else {
        return KeyAssociation::Unproven;
    };
    let (Some(actual_params), Some(expected_params)) = (actual.parameters(), expected.parameters())
    else {
        return KeyAssociation::Unproven;
    };
    if actual.y().as_bytes() == expected.y().as_bytes()
        && actual_params.p().as_bytes() == expected_params.p().as_bytes()
        && actual_params.q().as_bytes() == expected_params.q().as_bytes()
        && actual_params.g().as_bytes() == expected_params.g().as_bytes()
    {
        KeyAssociation::Same
    } else {
        KeyAssociation::Mismatch
    }
}

#[inline]
fn compare_edwards_points(
    ed25519: bool,
    bits: &[u8],
    expected_bits: &[u8],
    charge: &dyn Fn(u64) -> Result<(), MemoryError>,
) -> Result<KeyAssociation, DsigError> {
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
    Ok(if ed25519 {
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
    })
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
