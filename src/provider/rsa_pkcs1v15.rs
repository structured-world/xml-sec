//! Fixed-width session-key adaptation of sad-rsa 0.10.2 PKCS#1 v1.5 recovery.
//!
//! Source: sadco-io/sad-rsa, src/pkcs1v15.rs and
//! src/algorithms/pkcs1v15.rs::decrypt_inner (MIT OR Apache-2.0).
//! RSA arithmetic, blinding and fault checking remain in that dependency.
//! Unlike its general-message API, this adapter retains padding validity for
//! the enclosing content operation and never exposes a variable-length result.

use crypto_bigint::{BoxedUint, CtAssign, CtLt};
use rsa::{RsaPrivateKey, traits::PublicKeyParts};
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
        .map_err(|error| super::rustcrypto::map_rsa_error(error.into()))?;
    let in_range = representative.ct_lt(key.n());
    // Normalize an out-of-range public representative, but retain its invalidity.
    // Every width-correct input still performs blinded RSA and content work.
    representative.ct_assign(
        &BoxedUint::zero_with_precision(key.n_bits_precision()),
        !in_range,
    );
    let decoded = Zeroizing::new(
        rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut ProviderRng(provider)), &representative)
            .map_err(super::rustcrypto::map_rsa_error)?,
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
mod tests {
    use super::*;
    use crate::rsa_encoding::RsaPrivateKeyEncoding as _;

    fn private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("valid RSA fixture")
    }

    fn encrypt_encoded(key: &RsaPrivateKey, encoded: &[u8]) -> Vec<u8> {
        let value =
            BoxedUint::from_be_slice(encoded, key.n_bits_precision()).expect("modulus-width block");
        let ciphertext = rsa::hazmat::rsa_encrypt(&key.to_public_key(), &value)
            .expect("encoded representative below modulus")
            .to_be_bytes();
        ciphertext[ciphertext.len() - key.size()..].to_vec()
    }

    #[test]
    fn fixed_width_recovery_checks_every_padding_boundary() {
        // A fixed delimiter must enforce the complete RFC 8017 encoding, not
        // merely return the expected number of bytes after implicit rejection.
        let key = private_key();
        let provider = super::super::RustCryptoProvider;
        for key_len in [16, 24, 32] {
            let delimiter = key.size() - key_len - 1;
            let mut encoded = vec![0x31; key.size()];
            encoded[0] = 0;
            encoded[1] = 2;
            encoded[delimiter] = 0;
            let candidate = recover(&provider, &key, &encrypt_encoded(&key, &encoded), key_len)
                .expect("valid recovery");
            assert!(candidate.valid());
            assert_eq!(candidate.bytes(), &encoded[delimiter + 1..]);
            for (position, replacement) in
                [(0, 1), (1, 1), (2, 0), (delimiter - 1, 0), (delimiter, 1)]
            {
                let previous = encoded[position];
                encoded[position] = replacement;
                let candidate = recover(&provider, &key, &encrypt_encoded(&key, &encoded), key_len)
                    .expect("fixed-width invalid candidate");
                assert!(!candidate.valid(), "position {position}");
                assert_eq!(candidate.bytes().len(), key_len);
                encoded[position] = previous;
            }
        }
    }

    #[test]
    fn out_of_range_representative_retains_invalidity() {
        // A width-correct representative >= n must still produce a fixed-width
        // candidate so the content operation executes before rejecting it.
        let key = private_key();
        let bytes = key.n().to_be_bytes();
        let bytes = &bytes[bytes.len() - key.size()..];
        let candidate = recover(&super::super::RustCryptoProvider, &key, bytes, 16)
            .expect("normalized invalid candidate");
        assert!(!candidate.valid());
        assert_eq!(candidate.bytes().len(), 16);
        assert!(recover(&super::super::RustCryptoProvider, &key, &bytes[1..], 16).is_err());
        assert!(recover(&super::super::RustCryptoProvider, &key, bytes, 15).is_err());
    }
}
