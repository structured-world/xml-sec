//! Fixed-width session-key adaptation of `rsa` PKCS#1 v1.5 recovery.
//!
//! Source: `RustCrypto` `rsa`, src/pkcs1v15.rs and
//! `src/algorithms/pkcs1v15.rs` (MIT OR Apache-2.0), first adapted from the
//! sadco-io/sad-rsa 0.10.2 fork of it.
//! RSA arithmetic, blinding and fault checking remain in that dependency.
//! Unlike its general-message API, this adapter retains padding validity for
//! the enclosing content operation and never exposes a variable-length result.

use crypto_bigint::{BoxedUint, CtAssign, CtLt};
use rsa::{PrivateKey as RsaPrivateKey, traits::PublicKeyParts};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use super::{CryptoProvider, ProviderError, ProviderInputError, ProviderRng, RecoveredContentKey};

pub(super) fn recover(
    provider: &dyn CryptoProvider,
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    key_len: usize,
) -> Result<RecoveredContentKey, ProviderError> {
    let width = key.size();
    if !matches!(key_len, 16 | 24 | 32) || width < key_len + 11 {
        return Err(ProviderError::InvalidInput(
            ProviderInputError::PrimitiveInitialization("XMLEnc content-key width"),
        ));
    }
    if ciphertext.len() != width {
        return Err(ProviderError::InvalidInput(
            ProviderInputError::PrimitiveInitialization("RSA ciphertext width"),
        ));
    }
    let mut output = Zeroizing::new(vec![0; key_len]);
    provider.fill_random(&mut output)?;
    let mut representative = BoxedUint::from_be_slice(ciphertext, key.n_bits_precision())
        .map_err(|error| super::rustcrypto::map_rsa_error(&error.into()))?;
    let in_range = representative.ct_lt(key.n());
    // Normalize an out-of-range public representative, but retain its invalidity.
    // Every width-correct input still performs blinded RSA and content work.
    representative.ct_assign(
        &BoxedUint::zero_with_precision(key.n_bits_precision()),
        !in_range,
    );
    let decoded = Zeroizing::new(
        rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut ProviderRng(provider)), &representative)
            .map_err(|error| super::rustcrypto::map_rsa_error(&error))?,
    );
    let encoded = Zeroizing::new(decoded.to_be_bytes());
    let encoded = &encoded[encoded.len() - width..];
    // RFC 8017 §7.2.2 Step 3: 00 || 02 || at least eight nonzero PS bytes
    // || 00 || M. Expected CEK width makes the delimiter position public,
    // avoiding the donor's variable-length alignment/materialization entirely.
    // https://www.rfc-editor.org/rfc/rfc8017#section-7.2.2
    let delimiter = width - key_len - 1;
    let mut valid = encoded[0].ct_eq(&0)
        & encoded[1].ct_eq(&2)
        & encoded[delimiter].ct_eq(&0)
        & Choice::from(in_range.to_u8());
    for byte in &encoded[2..delimiter] {
        valid &= !byte.ct_eq(&0);
    }
    for (output, recovered) in output.iter_mut().zip(&encoded[delimiter + 1..]) {
        *output = u8::conditional_select(output, recovered, valid);
    }
    Ok(RecoveredContentKey::recovery(output, valid))
}

#[cfg(test)]
mod tests;
