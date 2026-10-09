//! Operation-wide KDF preflight. No derived work precedes this gate.

use crate::policy::{
    KeyAgreementAlgorithm, KeyDerivationAlgorithm, KeyEstablishmentPolicy, PolicyViolation,
};
use crate::provider::{
    CryptoProvider, KdfContext, KdfParameters, KeyAgreementKey, KeyAgreementParameters,
    ProviderCapability, ProviderError, ProviderInputError, ProviderOperation,
};
use crate::xmldsig::{DigestAlgorithm, SignatureAlgorithm};

use super::XmlEncError;
pub(super) use crate::key_establishment::KeyEstablishmentUsage;
use crate::key_establishment::reserve;

/// Cumulative KDF allowance borrowed from one immutable operation policy.
///
/// Share this instance across every recipient, derived key and retry. Reservations
/// are monotonic, including failed provider calls. Input slices remain borrowed;
/// only the provider's returned key buffer is owned and zeroized by this API.
pub struct KeyEstablishmentBudget<'a> {
    policy: &'a KeyEstablishmentPolicy,
    usage: KeyEstablishmentUsage,
}

impl<'a> KeyEstablishmentBudget<'a> {
    /// Validate the snapshot before compiling or executing key-establishment work.
    pub fn new(policy: &'a KeyEstablishmentPolicy) -> Result<Self, PolicyViolation> {
        policy.validate()?;
        Ok(Self {
            policy,
            usage: KeyEstablishmentUsage::default(),
        })
    }

    /// Derive through the selected provider only after syntax, permission,
    /// capability and aggregate allocation/CPU reservations have succeeded.
    pub fn derive_key(
        &mut self,
        provider: &dyn CryptoProvider,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        self.usage
            .derive_key(self.policy, provider, parameters, secret)
    }

    /// Agree and derive using the same monotonic operation allowance. Permission
    /// and both workspace/output reservations precede either provider callback.
    pub fn agree_and_derive(
        &mut self,
        provider: &dyn CryptoProvider,
        key: &dyn KeyAgreementKey,
        agreement: &KeyAgreementParameters<'_>,
        parameters: &KdfParameters<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        self.usage
            .agree_and_derive(self.policy, provider, key, agreement, parameters)
    }

    /// Cumulative compression work reserved, including failed attempts.
    pub const fn hash_blocks(&self) -> usize {
        self.usage.hash_blocks
    }

    /// Cumulative output allocations reserved, including failed attempts.
    pub const fn owned_bytes(&self) -> usize {
        self.usage.owned_bytes
    }

    /// Cumulative finite-field validation and exponentiation work reserved.
    pub const fn modular_work(&self) -> usize {
        self.usage.modular_work
    }

    pub(crate) fn reserve_dh_import(
        &mut self,
        p_bits: usize,
        q_bits: usize,
        p_twos: usize,
        q_twos: usize,
    ) -> Result<(), XmlEncError> {
        self.policy.validate()?;
        if self
            .policy
            .check_agreement(KeyAgreementAlgorithm::DhEs)
            .is_err()
        {
            self.policy
                .check_agreement(KeyAgreementAlgorithm::LegacyDh)?;
        }
        self.policy.check_dh_domain(p_bits, q_bits)?;
        reserve(
            crate::policy::resource_name::DH_MODULUS_BITS,
            0,
            p_bits as u128,
            self.policy.max_dh_modulus_bits,
        )?;
        // crypto-primes 0.7 MillerRabin holds its parameters across 64 rounds.
        // Each round allocates a 16-entry power table plus conversion buffers,
        // then at most v2(n-1) squares. Include boxed headers and public-domain
        // import/division/Montgomery setup rather than charging payload alone.
        let bytes = |bits: usize, twos: usize| {
            let slot = bits.div_ceil(64) as u128 * 8 + 64;
            slot * (512 + 64 * (64 + twos as u128))
        };
        self.usage.commit_dh_reservation(
            self.policy,
            modular_cost(p_bits, p_bits, 64)
                + modular_cost(q_bits, q_bits, 64)
                + modular_cost(p_bits, p_bits, 2),
            bytes(p_bits, p_twos) + bytes(q_bits, q_twos),
        )
    }
}

fn modular_cost(bits: usize, exponent_bits: usize, count: usize) -> u128 {
    let limbs = bits.div_ceil(usize::BITS as usize) as u128;
    // Bound native-word product passes for the fixed-window exponentiation,
    // Miller-Rabin's trailing squares and reduction, including window setup.
    // Counting native words also preserves the bound on 32-bit targets.
    (limbs * limbs).div_ceil(64) * (exponent_bits as u128 + 64) * 8 * count as u128
}

impl KeyEstablishmentUsage {
    pub(super) fn agree_and_derive(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        provider: &dyn CryptoProvider,
        key: &dyn KeyAgreementKey,
        agreement: &KeyAgreementParameters<'_>,
        parameters: &KdfParameters<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        policy.validate()?;
        let mechanism = KeyAgreementAlgorithm::from_uri(agreement.algorithm)
            .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(agreement.algorithm.into()))?;
        policy.check_agreement(mechanism)?;
        let width = match (mechanism, agreement.peer_public_key) {
            (KeyAgreementAlgorithm::X25519, bytes) if bytes.len() == 32 => 32,
            (KeyAgreementAlgorithm::EcdhEs, [4, tail @ ..])
                if matches!(tail.len(), 64 | 96 | 132) =>
            {
                tail.len() / 2
            }
            (KeyAgreementAlgorithm::EcdhEs, [2 | 3, tail @ ..])
                if matches!(tail.len(), 32 | 48 | 66) =>
            {
                tail.len()
            }
            (KeyAgreementAlgorithm::DhEs | KeyAgreementAlgorithm::LegacyDh, bytes) => {
                let (p_bits, q_bits) = key
                    .dh_domain_bits()
                    .ok_or_else(|| invalid(ProviderInputError::DhKey))?;
                policy.check_dh_domain(p_bits, q_bits)?;
                let width = p_bits.div_ceil(8);
                if bytes.is_empty() || bytes.len() > width || width == 0 {
                    return Err(invalid(ProviderInputError::DhKey));
                }
                width
            }
            _ => return Err(invalid(ProviderInputError::EcdhKey)),
        };
        // XMLEnc 1.1 §5.6.4 fixes ZZ to the field-element octet width. Reserve
        // both ZZ and the consuming key before either provider callback; a
        // denied KDF must not initiate otherwise permitted scalar multiplication.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ECDH-ES
        let (algorithm, digest, blocks) = preflight(parameters, width)?;
        // The legacy agreement URI fixes its implicit KDF. DH-ES permits an
        // explicit KDF, but replacing legacy derivation silently changes the
        // wire algorithm, even if both mechanisms are separately permitted.
        // XMLEnc 1.1 §§5.6.2.1–5.6.2.2:
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreementLegacyKDF
        if mechanism == KeyAgreementAlgorithm::LegacyDh
            && algorithm != KeyDerivationAlgorithm::LegacyDh
        {
            return Err(invalid(ProviderInputError::LegacyDhKdfParameters));
        }
        policy.check_derivation(algorithm, digest)?;
        provider.require_capability(ProviderCapability::KeyAgreement(agreement))?;
        provider.require_capability(ProviderCapability::Kdf(parameters))?;
        let dh = matches!(
            mechanism,
            KeyAgreementAlgorithm::DhEs | KeyAgreementAlgorithm::LegacyDh
        );
        let modular = if dh {
            modular_cost(width * 8, width * 8, 2)
        } else {
            0
        };
        let workspace = if dh { (width as u128 + 64) * 256 } else { 0 };
        self.commit_all(
            policy,
            blocks,
            modular,
            width as u128 + parameters.output_len as u128 + workspace,
        )?;
        let secret = zeroize::Zeroizing::new(provider.agree_key(key, agreement)?);
        check_width(&secret, width)?;
        let output = zeroize::Zeroizing::new(provider.derive_key(parameters, &secret)?);
        check_width(&output, parameters.output_len)?;
        Ok(output)
    }

    pub(super) fn derive_key(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        provider: &dyn CryptoProvider,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        policy.validate()?;
        let (algorithm, digest, blocks) = preflight(parameters, secret.len())?;
        policy.check_derivation(algorithm, digest)?;
        provider.require_capability(ProviderCapability::Kdf(parameters))?;
        self.commit_reservation(policy, blocks, parameters.output_len as u128)?;
        let output = zeroize::Zeroizing::new(provider.derive_key(parameters, secret)?);
        check_width(&output, parameters.output_len)?;
        Ok(output)
    }

    fn commit_reservation(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        blocks: u128,
        allocations: u128,
    ) -> Result<(), XmlEncError> {
        Ok(self.commit_all(policy, blocks, 0, allocations)?)
    }

    fn commit_dh_reservation(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        modular: u128,
        allocations: u128,
    ) -> Result<(), XmlEncError> {
        Ok(self.commit_all(policy, 0, modular, allocations)?)
    }
}

fn check_width(bytes: &[u8], expected: usize) -> Result<(), XmlEncError> {
    if bytes.len() != expected {
        return Err(ProviderError::InvalidKeySize {
            expected,
            actual: bytes.len(),
        }
        .into());
    }
    Ok(())
}

fn invalid(kind: ProviderInputError) -> XmlEncError {
    ProviderError::InvalidInput(kind).into()
}

fn unsupported(uri: &str) -> XmlEncError {
    ProviderError::Unsupported {
        operation: ProviderOperation::Kdf,
        algorithm: Some(uri.into()),
    }
    .into()
}

// SHA compression-block costs include padding and HMAC's inner/outer hashes,
// not merely the user-supplied PBKDF2 iteration count. The bound follows the
// provider's streaming framing without allocating concatenated input strings.
// RFC 8018 §5.2, RFC 5869 §§2.2–2.3, XMLEnc 1.1 §§5.4.1 and 5.6.2.2:
// https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2
// https://www.rfc-editor.org/rfc/rfc5869.html#section-2
// https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
fn preflight(
    parameters: &KdfParameters<'_>,
    secret_len: usize,
) -> Result<(KeyDerivationAlgorithm, DigestAlgorithm, u128), XmlEncError> {
    let algorithm = KeyDerivationAlgorithm::from_uri(parameters.algorithm)
        .ok_or_else(|| unsupported(parameters.algorithm))?;
    let uri = parameters
        .digest
        .ok_or_else(|| unsupported(parameters.algorithm))?;
    let digest = match algorithm {
        KeyDerivationAlgorithm::Hkdf | KeyDerivationAlgorithm::Pbkdf2 => {
            match SignatureAlgorithm::from_uri(uri) {
                Some(SignatureAlgorithm::HmacSha1) => DigestAlgorithm::Sha1,
                Some(SignatureAlgorithm::HmacSha224) => DigestAlgorithm::Sha224,
                Some(SignatureAlgorithm::HmacSha256) => DigestAlgorithm::Sha256,
                Some(SignatureAlgorithm::HmacSha384) => DigestAlgorithm::Sha384,
                Some(SignatureAlgorithm::HmacSha512) => DigestAlgorithm::Sha512,
                _ => return Err(unsupported(uri)),
            }
        }
        _ => match DigestAlgorithm::from_uri(uri) {
            Some(
                value @ (DigestAlgorithm::Sha1
                | DigestAlgorithm::Sha224
                | DigestAlgorithm::Sha256
                | DigestAlgorithm::Sha384
                | DigestAlgorithm::Sha512),
            ) => value,
            _ => return Err(unsupported(uri)),
        },
    };
    let width = digest.output_len();
    let block = if width <= 32 { 64u128 } else { 128 };
    let padding = if width <= 32 { 9u128 } else { 17 };
    let hash = |bytes: u128| (bytes + padding).div_ceil(block);
    let hmac_key = |bytes: usize| {
        if bytes as u128 > block {
            hash(bytes as u128) + 2
        } else {
            2
        }
    };
    let output_blocks = parameters.output_len.div_ceil(width) as u128;
    let work = match algorithm {
        KeyDerivationAlgorithm::Pbkdf2 => {
            if parameters.iterations == 0
                || parameters.output_len == 0
                || octets(parameters.info).is_none_or(|info| !info.is_empty())
                || output_blocks > u32::MAX as u128
            {
                return Err(invalid(ProviderInputError::Pbkdf2Parameters));
            }
            // The PRF and salt prefix are prepared once, then cloned. Account
            // their actual compression work once, not once per output block.
            let salt = parameters.salt.len() as u128;
            hmac_key(secret_len)
                + salt / block
                + output_blocks
                    * (hash(salt % block + 4) + 1 + 2 * (parameters.iterations as u128 - 1))
        }
        KeyDerivationAlgorithm::Hkdf => {
            let info = octets(parameters.info)
                .ok_or_else(|| invalid(ProviderInputError::HkdfParameters))?;
            if parameters.iterations != 0 || output_blocks > 255 {
                return Err(invalid(ProviderInputError::HkdfParameters));
            }
            // Conservatively include a previous full digest in every T_i,
            // including T_1, which actually uses an empty previous value.
            hmac_key(parameters.salt.len())
                + hash(secret_len as u128)
                + 1
                + 2
                + output_blocks * (hash(width as u128 + info.len() as u128 + 1) + 1)
        }
        KeyDerivationAlgorithm::ConcatKdf => {
            if parameters.iterations != 0
                || !parameters.salt.is_empty()
                || parameters.output_len == 0
                || output_blocks > u32::MAX as u128
            {
                return Err(invalid(ProviderInputError::ConcatKdfParameters));
            }
            let (bytes, bits) = match parameters.info {
                KdfContext::Octets(bytes) => (bytes, bytes.len() as u128 * 8),
                KdfContext::Bits { bytes, bit_len } => (bytes, bit_len as u128),
                _ => return Err(invalid(ProviderInputError::ConcatKdfParameters)),
            };
            let used = (bits % 8) as usize;
            if bits.div_ceil(8) != bytes.len() as u128
                || (used != 0 && bytes[bytes.len() - 1] & (0xff >> used) != 0)
            {
                return Err(invalid(ProviderInputError::ConcatKdfParameters));
            }
            output_blocks * hash(4 + secret_len as u128 + bits.div_ceil(8))
        }
        KeyDerivationAlgorithm::LegacyDh => {
            let KdfContext::LegacyDh {
                encryption_algorithm,
                nonce,
            } = parameters.info
            else {
                return Err(invalid(ProviderInputError::LegacyDhKdfParameters));
            };
            if parameters.iterations != 0
                || !parameters.salt.is_empty()
                || parameters.output_len == 0
                || output_blocks > 255
                || parameters.output_len.checked_mul(8).is_none()
            {
                return Err(invalid(ProviderInputError::LegacyDhKdfParameters));
            }
            output_blocks
                * hash(
                    secret_len as u128
                        + 2
                        + encryption_algorithm.len() as u128
                        + nonce.len() as u128
                        + 40,
                )
        }
    };
    Ok((algorithm, digest, work))
}

fn octets(context: KdfContext<'_>) -> Option<&[u8]> {
    match context {
        KdfContext::Octets(bytes) => Some(bytes),
        KdfContext::Bits { bytes, bit_len }
            if bit_len.is_multiple_of(8) && bit_len / 8 == bytes.len() =>
        {
            Some(bytes)
        }
        _ => None,
    }
}
