use super::*;
use crate::rsa_encoding::RsaPrivateKeyEncoding as _;

fn private_key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
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
        for (position, replacement) in [(0, 1), (1, 1), (2, 0), (delimiter - 1, 0), (delimiter, 1)]
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

#[test]
fn a_key_leaving_the_operation_hides_a_rejected_recovery() {
    // A key handed out where validity cannot follow it must look the same
    // whether the padding held: the recovered key, or a random substitute
    // of its width, never an error that would be a padding oracle.
    let key = private_key();
    let provider = super::super::RustCryptoProvider;
    let delimiter = key.size() - 16 - 1;
    let mut encoded = vec![0x31; key.size()];
    encoded[0] = 0;
    encoded[1] = 2;
    encoded[delimiter] = 0;
    let valid = recover(&provider, &key, &encrypt_encoded(&key, &encoded), 16)
        .expect("valid recovery")
        .into_key_or_substitute()
        .expect("a recovered key");
    assert_eq!(valid.as_slice(), &encoded[delimiter + 1..]);
    encoded[1] = 1;
    let rejected = recover(&provider, &key, &encrypt_encoded(&key, &encoded), 16)
        .expect("fixed-width invalid candidate")
        .into_key_or_substitute()
        .expect("a substitute, not an error");
    assert_eq!(rejected.len(), 16);
    assert_ne!(rejected.as_slice(), &encoded[delimiter + 1..]);
    // A mechanism whose failure is already public still reports it.
    let confirmed = super::super::RecoveredContentKey {
        bytes: Zeroizing::new(vec![0; 16]),
        valid: Choice::from(0),
        implicit_rejection: false,
        opaque: None,
    };
    assert!(matches!(
        confirmed.into_key_or_substitute(),
        Err(ProviderError::AuthenticationFailed)
    ));
}
