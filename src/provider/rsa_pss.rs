//! Local parameterized adaptation of sad-rsa 0.10.2 PSS and MGF1.
//!
//! Derived from src/pss.rs and src/algorithms/{pss,mgf}.rs, MIT OR Apache-2.0.
//! RSA arithmetic, blinding and fault checks remain in sad-rsa. Only the
//! padding module is adapted here, as with the fixed-width recovery patch.

use crate::rsa_encoding::RsaPublicKeyEncoding as _;
use crate::rustcrypto_sha3 as sha3;
use crypto_bigint::BoxedUint;
use der::{Decode as _, Reader as _, Tagged as _};
use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{CryptoProvider, ProviderRng};
use crate::xmldsig::{DigestAlgorithm, RsaPssParameters, SigningKeyError};

/// Hash borrowed parts directly into stack storage; MGF1 creates no per-block Vec.
fn hash(algorithm: DigestAlgorithm, parts: &[&[u8]], output: &mut [u8; 64]) {
    macro_rules! compute {
        ($digest:ty) => {{
            let mut digest = <$digest>::new();
            for part in parts {
                digest.update(part);
            }
            let result = digest.finalize();
            output[..result.len()].copy_from_slice(&result);
        }};
    }
    match algorithm {
        DigestAlgorithm::Sha1 => compute!(sha1::Sha1),
        DigestAlgorithm::Sha224 => compute!(sha2::Sha224),
        DigestAlgorithm::Sha256 => compute!(sha2::Sha256),
        DigestAlgorithm::Sha384 => compute!(sha2::Sha384),
        DigestAlgorithm::Sha512 => compute!(sha2::Sha512),
        DigestAlgorithm::Sha3_224 => compute!(sha3::Sha3_224),
        DigestAlgorithm::Sha3_256 => compute!(sha3::Sha3_256),
        DigestAlgorithm::Sha3_384 => compute!(sha3::Sha3_384),
        DigestAlgorithm::Sha3_512 => compute!(sha3::Sha3_512),
        #[cfg(feature = "legacy-algorithms")]
        DigestAlgorithm::Md5 => compute!(md5::Md5),
        #[cfg(feature = "legacy-algorithms")]
        DigestAlgorithm::Ripemd160 => compute!(ripemd::Ripemd160),
    }
}

fn mask(out: &mut [u8], algorithm: DigestAlgorithm, seed: &[u8]) {
    // RFC 8017 appendix B.2.1: Hash(seed || I2OSP(counter, 4)).
    // https://www.rfc-editor.org/rfc/rfc8017.html#appendix-B.2.1
    // RSA's absolute modulus ceiling bounds the counter far below 2^32.
    let mut block = [0u8; 64];
    for (counter, chunk) in out.chunks_mut(algorithm.output_len()).enumerate() {
        hash(
            algorithm,
            &[seed, &(counter as u32).to_be_bytes()],
            &mut block,
        );
        for (byte, mask) in chunk.iter_mut().zip(&block) {
            *byte ^= mask;
        }
    }
}

fn valid_key(parameters: RsaPssParameters, key: &impl PublicKeyParts) -> bool {
    let bits = key.n().bits() as usize;
    bits <= crate::hard_limits::RSA_MODULUS_BIT_CEILING && parameters.fits_modulus_bits(bits)
}

pub(crate) fn public_key(spki: &[u8], parameters: RsaPssParameters) -> Option<RsaPublicKey> {
    // RFC 4055 section 3.3: a PSS SPKI restricts hashes/trailer and sets a
    // minimum salt length; absent parameters permit any supported PSS tuple.
    // https://www.rfc-editor.org/rfc/rfc4055.html#section-3.3
    RsaPublicKey::from_pkcs1_der(encoded_public_key(spki, parameters)?).ok()
}

/// Borrow the RSA bit string after checking its algorithm restrictions. Native
/// providers share this preflight without allocating software RSA bigints.
pub(crate) fn encoded_public_key(spki: &[u8], parameters: RsaPssParameters) -> Option<&[u8]> {
    use x509_parser::prelude::FromDer as _;
    let public = pkcs8::SubjectPublicKeyInfoRef::from_der(spki).ok()?;
    let (_, parsed) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki).ok()?;
    match parsed.algorithm.algorithm.as_bytes() {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => {
            if public
                .algorithm
                .parameters
                .is_some_and(|value| !value.is_null())
            {
                return None;
            }
        }
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] => {
            if public
                .algorithm
                .parameters
                .is_some_and(|value| !valid_parameter_encoding(value))
            {
                return None;
            }
            if parsed.algorithm.parameters.as_ref().is_some_and(|value| {
                !super::rustcrypto_x509::rsa_pss_key_parameters_allow(
                    value,
                    super::X509SignatureAlgorithm::RsaPss {
                        digest: parameters.digest,
                        mgf_digest: parameters.mgf_digest,
                        salt_len: parameters.salt_len,
                    },
                )
            }) {
                return None;
            }
        }
        _ => return None,
    }
    public.subject_public_key.as_bytes()
}

fn valid_parameter_encoding(parameters: der::asn1::AnyRef<'_>) -> bool {
    // RFC 8017 appendix A.2.3 defines an ordered, explicitly tagged sequence.
    // x509-parser's value decoder does not check its unconsumed suffix, so
    // validate the complete borrowed DER before interpreting key restrictions.
    // https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.2.3
    parameters
        .sequence(|reader| -> der::Result<()> {
            let mut previous = None;
            while !reader.is_finished() {
                let field: der::asn1::AnyRef<'_> = reader.decode()?;
                let der::Tag::ContextSpecific {
                    constructed: true,
                    number,
                } = field.tag()
                else {
                    return Err(field.tag().value_error().into());
                };
                if number.0 > 3 || previous.is_some_and(|last| number.0 <= last) {
                    return Err(field.tag().value_error().into());
                }
                previous = Some(number.0);
                match number.0 {
                    0 | 1 => {
                        let algorithm = pkcs8::AlgorithmIdentifierRef::from_der(field.value())?;
                        let hash = if number.0 == 1 {
                            algorithm
                                .parameters
                                .ok_or(field.tag().value_error())?
                                .decode_as::<pkcs8::AlgorithmIdentifierRef<'_>>()?
                        } else {
                            algorithm
                        };
                        if hash.parameters.is_some_and(|value| !value.is_null()) {
                            return Err(field.tag().value_error().into());
                        }
                    }
                    _ => {
                        u32::from_der(field.value())?;
                    }
                }
            }
            Ok(())
        })
        .is_ok()
}

pub(crate) fn sign(
    provider: &dyn CryptoProvider,
    key: &RsaPrivateKey,
    parameters: RsaPssParameters,
    message: &[u8],
) -> Result<Vec<u8>, SigningKeyError> {
    if !valid_key(parameters, key) {
        return Err(SigningKeyError::SigningFailed);
    }
    let bits = key.n().bits() as usize - 1;
    let em_len = bits.div_ceil(8);
    let h_len = parameters.digest.output_len();
    let mut m_hash = [0u8; 64];
    hash(parameters.digest, &[message], &mut m_hash);
    let mut encoded = Zeroizing::new(vec![0u8; em_len]);
    let (db, tail) = encoded.split_at_mut(em_len - h_len - 1);
    let h = &mut tail[..h_len];
    let separator = db.len() - parameters.salt_len - 1;
    db[separator] = 1;
    provider.fill_random(&mut db[separator + 1..])?;
    let mut h_hash = [0u8; 64];
    hash(
        parameters.digest,
        &[&[0; 8], &m_hash[..h_len], &db[separator + 1..]],
        &mut h_hash,
    );
    h.copy_from_slice(&h_hash[..h_len]);
    mask(db, parameters.mgf_digest, h);
    db[0] &= 0xff >> (em_len * 8 - bits);
    encoded[em_len - 1] = 0xbc;
    let value = BoxedUint::from_be_slice(&encoded, key.n_bits_precision())
        .map_err(|_| SigningKeyError::SigningFailed)?;
    let value = rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut ProviderRng(provider)), &value)
        .map_err(|_| SigningKeyError::SigningFailed)?;
    let bytes = value.to_be_bytes();
    Ok(bytes[bytes.len() - key.size()..].to_vec())
}

pub(crate) fn verify(
    key: &RsaPublicKey,
    parameters: RsaPssParameters,
    message: &[u8],
    signature: &[u8],
) -> bool {
    if signature.len() != key.size() || !valid_key(parameters, key) {
        return false;
    }
    let Ok(value) = BoxedUint::from_be_slice(signature, key.n_bits_precision()) else {
        return false;
    };
    // RSAVP1 rejects representatives outside [0, n); raw modular arithmetic
    // alone would accept the alternate encoding s+n of a valid signature.
    // RFC 8017 section 5.2.2: https://www.rfc-editor.org/rfc/rfc8017.html#section-5.2.2
    if value >= *key.n().as_ref() {
        return false;
    }
    let Ok(value) = rsa::hazmat::rsa_encrypt(key, &value) else {
        return false;
    };
    let mut encoded = value.to_be_bytes();
    let bits = key.n().bits() as usize - 1;
    let em_len = bits.div_ceil(8);
    let leading = encoded.len() - em_len;
    // RFC 8017 section 8.1.2 step 2 requires an emLen-octet representative.
    // Do not silently truncate a nonzero octet for moduli congruent to 1 mod 8.
    // https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1.2
    if encoded[..leading].iter().any(|byte| *byte != 0) {
        return false;
    }
    let encoded = &mut encoded[leading..];
    if encoded[em_len - 1] != 0xbc {
        return false;
    }
    let h_len = parameters.digest.output_len();
    let (db, tail) = encoded.split_at_mut(em_len - h_len - 1);
    let h = &tail[..h_len];
    let high_bits = em_len * 8 - bits;
    if db[0] & !(0xff >> high_bits) != 0 {
        return false;
    }
    mask(db, parameters.mgf_digest, h);
    db[0] &= 0xff >> high_bits;
    let separator = db.len() - parameters.salt_len - 1;
    let mut valid = db[separator].ct_eq(&1);
    for byte in &db[..separator] {
        valid &= byte.ct_eq(&0);
    }
    let mut m_hash = [0u8; 64];
    hash(parameters.digest, &[message], &mut m_hash);
    let mut expected = [0u8; 64];
    hash(
        parameters.digest,
        &[&[0; 8], &m_hash[..h_len], &db[separator + 1..]],
        &mut expected,
    );
    bool::from(valid & expected[..h_len].ct_eq(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};

    #[test]
    fn signs_non_byte_aligned_modulus_with_dependency_verification() {
        // Exercise our signing encoder at modBits == 1 mod 8 without relying
        // on sad-rsa's unrelated odd-width private DER exporter.
        let private = RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(2049), 2049)
            .expect("deterministic odd-width RSA key");
        let signature = sign(
            &super::super::RustCryptoProvider,
            &private,
            RsaPssParameters::DEFAULT,
            b"odd modulus",
        )
        .expect("odd-width PSS signing");
        let public = RsaPublicKey::from(&private);
        assert_eq!(signature.len(), 257);
        public
            .verify(
                rsa::Pss::<sha2::Sha256>::new(),
                &sha2::Sha256::digest(b"odd modulus"),
                &signature,
            )
            .expect("independent PSS verifier accepts odd-width signature");
    }
}
