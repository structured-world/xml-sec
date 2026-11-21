//! Validated finite-field DH. Public-domain checks are variable-time; private
//! exponentiation uses the full, fixed modulus precision.

use crypto_bigint::{
    BoxedUint, NonZero, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use crypto_primes::hazmat::MillerRabin;
use zeroize::Zeroizing;

use crate::provider::{
    CryptoProvider, KeyAgreementKey, KeyAgreementParameters, ProviderError, ProviderInputError,
    ProviderOperation,
};
use crate::xmlenc::{KeyEstablishmentBudget, XmlEncError};

use super::{DH_ES_URI, DH_URI};

/// Finite-field DH handle with validated prime-order domain parameters.
/// Private scalars and shared secrets are never exposed by Debug.
pub struct RustCryptoDhKey {
    params: BoxedMontyParams,
    order: BoxedUint,
    generator: BoxedUint,
    private: Zeroizing<BoxedUint>,
    width: usize,
    domain_bits: (usize, usize),
}

impl core::fmt::Debug for RustCryptoDhKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RustCryptoDhKey").finish_non_exhaustive()
    }
}

impl RustCryptoDhKey {
    /// Import unsigned big-endian p/q/g and private x. Validation is charged to
    /// the supplied operation before allocating big integers or testing primes.
    /// The provider supplies independent random Miller-Rabin bases; failures are
    /// propagated, never replaced with deterministic or biased bases.
    ///
    /// # Errors
    /// Returns an error for invalid domain or private-key parameters, policy or
    /// resource refusal, or provider randomness failure during primality validation.
    pub fn from_components(
        provider: &dyn CryptoProvider,
        budget: &mut KeyEstablishmentBudget<'_>,
        p: &[u8],
        q: &[u8],
        generator: &[u8],
        private: &[u8],
    ) -> Result<Self, XmlEncError> {
        let ceiling = crate::hard_limits::DH_MODULUS_BIT_CEILING / 8;
        if p.len() > ceiling
            || q.len() > p.len()
            || generator.len() > p.len()
            || private.len() > p.len()
        {
            return Err(invalid().into());
        }
        let p = significant(p);
        let q = significant(q);
        let generator = significant(generator);
        let p_bits = bits(p);
        let q_bits = bits(q);
        // XMLEnc 1.1 §5.6.2 defines p/g minima. Prime-order q and the private
        // interval follow RFC 2631 §2.2; these checks do not claim validation of
        // generation seeds or a FIPS-approved parameter-generation procedure.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreement
        // https://www.rfc-editor.org/rfc/rfc2631.html#section-2.2
        if p_bits < 512
            || q_bits < 160
            || q_bits >= p_bits
            || bits(generator) < 160
            || p.last().is_none_or(|v| v & 1 == 0)
            || q.last().is_none_or(|v| v & 1 == 0)
        {
            return Err(invalid().into());
        }
        budget.reserve_dh_import(p_bits, q_bits, twos_minus_one(p), twos_minus_one(q))?;
        let precision = u32::try_from(p_bits.div_ceil(64)).map_err(|_| invalid())? * 64;
        let p_value = decode(p, precision)?;
        let q_precision = u32::try_from(q_bits.div_ceil(64)).map_err(|_| invalid())? * 64;
        let q_small = decode(q, q_precision)?;
        let order = decode(q, precision)?;
        let one = BoxedUint::one_with_precision(precision);
        let two = decode(&[2], precision)?;
        let p_minus_one = p_value.wrapping_sub(&one);
        let divisor = NonZero::new(order.clone()).ok_or_else(invalid)?;
        if order >= p_minus_one
            || p_minus_one.rem_vartime(&divisor) != BoxedUint::zero_with_precision(precision)
        {
            return Err(invalid().into());
        }
        let generator = decode(generator, precision)?;
        let private = Zeroizing::new(decode(private, precision)?);
        if generator <= one
            || generator >= p_minus_one
            || *private < two
            || *private > order.wrapping_sub(&two)
        {
            return Err(invalid().into());
        }
        probable_prime(|bytes| provider.fill_random(bytes), &p_value)?;
        probable_prime(|bytes| provider.fill_random(bytes), &q_small)?;
        let params = BoxedMontyParams::new_vartime(Odd::new(p_value).ok_or_else(invalid)?);
        if BoxedMontyForm::new(generator.clone(), &params)
            .pow_bounded_exp(&order, u32::try_from(q_bits).map_err(|_| invalid())?)
            .retrieve()
            != one
        {
            return Err(invalid().into());
        }
        Ok(Self {
            params,
            order,
            generator,
            private,
            width: p.len(),
            domain_bits: (p_bits, q_bits),
        })
    }

    /// Import an X9.42 DH (`dhpublicnumber`, RFC 3279 section 2.3.3) PKCS#8
    /// private key, validated as [`Self::from_components`] validates it.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::policy::{DecryptionPolicy, KeyAgreementAlgorithm};
    /// use xml_sec::provider::{RUST_CRYPTO_PROVIDER, RustCryptoDhKey};
    /// use xml_sec::xmlenc::KeyEstablishmentBudget;
    ///
    /// let der = include_bytes!("../../../tests/fixtures/xmlenc/keys/dhx/dhx-rfc5114-3-first-key.der");
    /// let mut policy = DecryptionPolicy::default();
    /// policy.key_establishment.agreement_algorithms = Some([KeyAgreementAlgorithm::DhEs].into());
    /// let mut budget = KeyEstablishmentBudget::new(&policy.key_establishment)?;
    /// let key = RustCryptoDhKey::from_pkcs8_der(&RUST_CRYPTO_PROVIDER, &mut budget, der)?;
    /// assert_eq!(key.public_key().len(), 256);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error for a key of another algorithm or malformed encoding,
    /// and as [`Self::from_components`] does.
    pub fn from_pkcs8_der(
        provider: &dyn CryptoProvider,
        budget: &mut KeyEstablishmentBudget<'_>,
        der: &[u8],
    ) -> Result<Self, XmlEncError> {
        let key = pkcs8_components(der)?;
        Self::from_components(provider, budget, key.p, key.q, key.generator, key.private)
    }

    /// Export the public value with the same fixed octet width as p.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        let value = Zeroizing::new(
            BoxedMontyForm::new(self.generator.clone(), &self.params).pow(&self.private),
        );
        let integer = Zeroizing::new(value.retrieve());
        let bytes = Zeroizing::new(integer.to_be_bytes());
        bytes[bytes.len() - self.width..].to_vec()
    }
}

impl KeyAgreementKey for RustCryptoDhKey {
    fn dh_domain_bits(&self) -> Option<(usize, usize)> {
        Some(self.domain_bits)
    }

    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
        if !matches!(parameters.algorithm, DH_URI | DH_ES_URI) {
            return Err(ProviderError::Unsupported {
                operation: ProviderOperation::KeyAgreement,
                algorithm: Some(parameters.algorithm.into()),
            });
        }
        if parameters.peer_public_key.is_empty() || parameters.peer_public_key.len() > self.width {
            return Err(invalid());
        }
        let precision = self.generator.bits_precision();
        let peer = decode(parameters.peer_public_key, precision)?;
        let one = BoxedUint::one_with_precision(precision);
        let two = decode(&[2], precision)?;
        // RFC 2631 §2.1.5 allows this subgroup validation; our policy requires
        // it before using an untrusted peer with a private exponent. The p-1
        // endpoint cannot survive this check for the odd prime-order subgroup.
        // https://www.rfc-editor.org/rfc/rfc2631.html#section-2.1.5
        if peer < two || peer >= self.params.modulus().as_ref().wrapping_sub(&one) {
            return Err(invalid());
        }
        let peer = BoxedMontyForm::new(peer, &self.params);
        if peer
            .pow_bounded_exp(&self.order, self.order.bit_width_vartime())
            .retrieve()
            != one
        {
            return Err(invalid());
        }
        // RFC 2631 §2.1.2 and XMLEnc 1.1 §5.6.2 require leading zero octets in
        // ZZ. Never trim the integer or reveal private exponent bit length.
        // https://www.rfc-editor.org/rfc/rfc2631.html#section-2.1.2
        let secret = Zeroizing::new(peer.pow(&self.private));
        let integer = Zeroizing::new(secret.retrieve());
        let bytes = Zeroizing::new(integer.to_be_bytes());
        Ok(bytes[bytes.len() - self.width..].to_vec())
    }
}

fn invalid() -> ProviderError {
    ProviderError::InvalidInput(ProviderInputError::DhKey)
}

/// The unsigned big-endian components of an X9.42 DH private key.
struct Components<'a> {
    p: &'a [u8],
    q: &'a [u8],
    generator: &'a [u8],
    private: &'a [u8],
}

/// The components of an X9.42 DH PKCS#8 private key (RFC 3279 section
/// 2.3.3: `DomainParameters` as the algorithm parameters, the INTEGER x as
/// the private key).
fn pkcs8_components(der: &[u8]) -> Result<Components<'_>, ProviderError> {
    use der::{Decode as _, asn1::UintRef};
    let info = pkcs8::PrivateKeyInfoRef::try_from(der).map_err(|_| invalid())?;
    if info.algorithm.oid != crate::xmldsig::keys::DH_PUBLIC_NUMBER {
        return Err(invalid());
    }
    let [p, generator, q] =
        crate::xmldsig::keys::x942_domain(info.algorithm.parameters).ok_or_else(invalid)?;
    let private = UintRef::from_der(info.private_key.as_bytes()).map_err(|_| invalid())?;
    Ok(Components {
        p,
        q,
        generator,
        private: private.as_bytes(),
    })
}

/// The public value g^x mod p of an X9.42 DH PKCS#8 private key, at p's
/// octet width, after the structural checks a key import makes: odd p within
/// the safety ceiling, 1 < g < p-1 and 2 <= x <= q-2. Validating the group
/// (primality, subgroup order) and its strength is the agreement's, under the
/// operation's policy.
pub(crate) fn pkcs8_public_value(der: &[u8]) -> Result<Vec<u8>, ProviderError> {
    let Components {
        p,
        q,
        generator,
        private,
    } = pkcs8_components(der)?;
    let ceiling = crate::hard_limits::DH_MODULUS_BIT_CEILING / 8;
    let p = significant(p);
    if p.is_empty()
        || p.len() > ceiling
        || q.len() > p.len()
        || generator.len() > p.len()
        || private.len() > p.len()
        || p.last().is_none_or(|v| v & 1 == 0)
    {
        return Err(invalid());
    }
    let precision = u32::try_from(bits(p).div_ceil(64)).map_err(|_| invalid())? * 64;
    let modulus = decode(p, precision)?;
    let order = decode(q, precision)?;
    let generator = decode(generator, precision)?;
    let private = Zeroizing::new(decode(private, precision)?);
    let one = BoxedUint::one_with_precision(precision);
    let two = decode(&[2], precision)?;
    if generator <= one
        || generator >= modulus.wrapping_sub(&one)
        || *private < two
        || order < two
        || *private > order.wrapping_sub(&two)
    {
        return Err(invalid());
    }
    let params = BoxedMontyParams::new_vartime(Odd::new(modulus).ok_or_else(invalid)?);
    let value = Zeroizing::new(BoxedMontyForm::new(generator, &params).pow(&private));
    let integer = Zeroizing::new(value.retrieve());
    let bytes = Zeroizing::new(integer.to_be_bytes());
    Ok(bytes[bytes.len() - p.len()..].to_vec())
}

fn significant(bytes: &[u8]) -> &[u8] {
    let offset = bytes.iter().position(|&v| v != 0).unwrap_or(bytes.len());
    &bytes[offset..]
}

fn bits(bytes: &[u8]) -> usize {
    match bytes.first() {
        Some(first) => bytes.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

fn twos_minus_one(bytes: &[u8]) -> usize {
    let last = bytes[bytes.len() - 1] - 1;
    if last != 0 {
        return last.trailing_zeros() as usize;
    }
    let mut count = 8;
    for byte in bytes[..bytes.len() - 1].iter().rev() {
        if *byte != 0 {
            return count + byte.trailing_zeros() as usize;
        }
        count += 8;
    }
    count
}

fn decode(bytes: &[u8], precision: u32) -> Result<BoxedUint, ProviderError> {
    BoxedUint::from_be_slice(bytes, precision).map_err(|_| invalid())
}

fn probable_prime(
    mut fill_random: impl FnMut(&mut [u8]) -> Result<(), ProviderError>,
    candidate: &BoxedUint,
) -> Result<(), ProviderError> {
    let test = MillerRabin::new(Odd::new(candidate.clone()).ok_or_else(invalid)?);
    let precision = candidate.bits_precision();
    let two = decode(&[2], precision)?;
    let maximum = candidate.wrapping_sub(&two);
    let maximum_bytes = maximum.to_be_bytes();
    let mut bytes = vec![0; (candidate.bit_width_vartime() as usize).div_ceil(8)];
    let maximum_bytes = &maximum_bytes[maximum_bytes.len() - bytes.len()..];
    let excess = bytes.len() * 8 - candidate.bit_width_vartime() as usize;
    // Bounded rejection sampling avoids both RNG-error suppression and modulo
    // bias. 64 independent uniform bases bound composite acceptance by 2^-128;
    // this is a probable-prime check, not a primality certificate.
    for _ in 0..64 {
        let mut selected = None;
        for _ in 0..128 {
            fill_random(&mut bytes)?;
            bytes[0] &= 0xff >> excess;
            let value = significant(&bytes);
            if (value.len() > 1 || value.first().is_some_and(|v| *v >= 2))
                && bytes.as_slice() <= maximum_bytes
            {
                selected = Some(decode(&bytes, precision)?);
                break;
            }
        }
        let base =
            selected.ok_or_else(|| ProviderError::Random("DH base sampling exhausted".into()))?;
        if test.test(&base).is_composite() {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primality_randomness_errors_are_terminal() {
        // Propagate the first RNG failure, never fall back to fixed bases.
        let candidate = decode(&[251], 64).expect("prime fixture fits one limb");
        let mut calls = 0;
        let result = probable_prime(
            |_| {
                calls += 1;
                Err(ProviderError::AuthenticationFailed)
            },
            &candidate,
        );
        assert!(matches!(result, Err(ProviderError::AuthenticationFailed)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn unusable_randomness_has_a_finite_rejection_bound() {
        // A stuck RNG terminates; modulo reduction would bias accepted bases.
        let candidate = decode(&[251], 64).expect("prime fixture fits one limb");
        let mut calls = 0;
        let result = probable_prime(
            |bytes| {
                calls += 1;
                bytes.fill(0);
                Ok(())
            },
            &candidate,
        );
        assert!(matches!(result, Err(ProviderError::Random(_))));
        assert_eq!(calls, 128);
    }

    #[test]
    fn primality_rejects_composites_and_samples_all_rounds_for_primes() {
        // 251 is prime; 253 = 11*23, witnessed by base two. This deterministic
        // test source is not used as a cryptographic RNG in production.
        for (candidate, expected, count) in [(251, true, 64), (253, false, 1)] {
            let mut calls = 0;
            let result = probable_prime(
                |bytes| {
                    calls += 1;
                    bytes.fill(2);
                    Ok(())
                },
                &decode(&[candidate], 64).expect("primality fixtures fit one limb"),
            );
            assert_eq!(result.is_ok(), expected);
            assert_eq!(calls, count);
        }
    }
}
