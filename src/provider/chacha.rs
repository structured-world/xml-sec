//! Primitive dispatch for the draft XML-security ChaCha profiles.
use super::{ProviderError, ProviderInputError};
use crate::xmlenc::{ChaChaParametersRef, DataEncryptionAlgorithm};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};

fn invalid(message: &'static str) -> ProviderError {
    ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(message))
}

fn validate<'a>(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    parameters: ChaChaParametersRef<'a>,
) -> Result<&'a [u8; 12], ProviderError> {
    parameters
        .validate(algorithm)
        .map_err(|_| invalid("ChaCha parameters"))?;
    if key.len() != 32 {
        return Err(ProviderError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }
    parameters
        .nonce
        .ok_or_else(|| invalid("missing ChaCha nonce"))
}

fn stream(
    key: &[u8],
    nonce: &[u8; 12],
    counter: [u8; 4],
    bytes: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let mut cipher =
        chacha20::ChaCha20::new_from_slices(key, nonce).map_err(|_| invalid("ChaCha key/nonce"))?;
    // RFC 8439 §2.3 uses a 32-bit little-endian counter; libxmlsec1's
    // experimental XML profile carries its four encoded bytes unchanged.
    // https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3
    let position = u64::from(u32::from_le_bytes(counter)) * 64;
    cipher
        .try_seek(position)
        .map_err(|_| invalid("ChaCha counter"))?;
    // Check the primitive's counter boundary before copying attacker-sized
    // input. StreamCipher::try_apply_keystream repeats this check on use.
    cipher
        .check_remaining(bytes.len())
        .map_err(|_| invalid("ChaCha counter exhausted"))?;
    let mut output = zeroize::Zeroizing::new(bytes.to_vec());
    cipher
        .try_apply_keystream(&mut output)
        .map_err(|_| invalid("ChaCha counter exhausted"))?;
    Ok(core::mem::take(&mut *output))
}

pub(super) fn encrypt(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    plaintext: &[u8],
    parameters: ChaChaParametersRef<'_>,
) -> Result<Vec<u8>, ProviderError> {
    let nonce = validate(algorithm, key, parameters)?;
    if algorithm == DataEncryptionAlgorithm::ChaCha20 {
        return stream(
            key,
            nonce,
            parameters.counter.expect("validated counter"),
            plaintext,
        );
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid("ChaCha20-Poly1305 key"))?;
    let length = plaintext
        .len()
        .checked_add(16)
        .ok_or_else(|| invalid("ChaCha20-Poly1305 length"))?;
    let mut output = zeroize::Zeroizing::new(Vec::with_capacity(length));
    output.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(
            nonce.into(),
            parameters.aad.unwrap_or("").as_bytes(),
            output.as_mut_slice().into(),
        )
        .map_err(|_| ProviderError::AuthenticationFailed)?;
    output.extend_from_slice(&tag);
    Ok(core::mem::take(&mut *output))
}

pub(super) fn decrypt(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    ciphertext: &[u8],
    parameters: ChaChaParametersRef<'_>,
) -> Result<Vec<u8>, ProviderError> {
    let nonce = validate(algorithm, key, parameters)?;
    if algorithm == DataEncryptionAlgorithm::ChaCha20 {
        return stream(
            key,
            nonce,
            parameters.counter.expect("validated counter"),
            ciphertext,
        );
    }
    if ciphertext.len() < 16 {
        return Err(invalid("ChaCha20-Poly1305 framing"));
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid("ChaCha20-Poly1305 key"))?;
    let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let tag = chacha20poly1305::Tag::try_from(tag).map_err(|_| invalid("ChaCha20-Poly1305 tag"))?;
    let mut output = zeroize::Zeroizing::new(body.to_vec());
    cipher
        .decrypt_inout_detached(
            nonce.into(),
            parameters.aad.unwrap_or("").as_bytes(),
            output.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| ProviderError::AuthenticationFailed)?;
    Ok(core::mem::take(&mut *output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "complete hexadecimal octets");
        pairs
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("ASCII vector");
                u8::from_str_radix(text, 16).expect("hexadecimal vector")
            })
            .collect()
    }

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn rfc8439_stream_vector_checks_counter_byte_order() {
        // RFC 8439 §2.4.2 independently checks our nonce/counter adapter.
        // https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4.2
        let key: Vec<u8> = (0..32).collect();
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let parameters = ChaChaParametersRef {
            nonce: Some(&nonce),
            counter: Some(1_u32.to_le_bytes()),
            aad: None,
        };
        let expected = bytes(concat!(
            "6e2e359a2568f98041ba0728dd0d6981",
            "e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b357",
            "1639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e",
            "52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42",
            "874d"
        ));
        assert_eq!(
            encrypt(
                DataEncryptionAlgorithm::ChaCha20,
                &key,
                PLAINTEXT,
                parameters
            )
            .expect("RFC encryption"),
            expected
        );
        assert_eq!(
            decrypt(
                DataEncryptionAlgorithm::ChaCha20,
                &key,
                &expected,
                parameters
            )
            .expect("RFC decryption"),
            PLAINTEXT
        );
    }

    #[test]
    fn rfc8439_aead_vector_checks_tag_and_ciphertext() {
        // RFC 8439 §2.8.2 has binary AAD outside the XML string-AAD contract.
        // Verify the primitive's complete vector, then the adapter's identical
        // ciphertext with empty AAD (AAD changes the tag, not the ciphertext).
        // https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
        let key: Vec<u8> = (0x80..=0x9f).collect();
        let nonce = [7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = bytes("50515253c0c1c2c3c4c5c6c7");
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("RFC key");
        let mut output = PLAINTEXT.to_vec();
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), &aad, output.as_mut_slice().into())
            .expect("RFC AEAD");
        assert_eq!(
            output,
            bytes(concat!(
                "d31a8d34648e60db7b86afbc53ef7ec2",
                "a4aded51296e08fea9e2b5a736ee62d6",
                "3dbea45e8ca9671282fafb69da92728b",
                "1a71de0a9e060b2905d6a5b67ecd3b36",
                "92ddbd7f2d778b8c9803aee328091b58",
                "fab324e4fad675945585808b4831d7bc",
                "3ff4def08e4b7a9de576d26586cec64b",
                "6116"
            ))
        );
        assert_eq!(tag.as_slice(), bytes("1ae10b594f09e26a7e902ecbd0600691"));
        let parameters = ChaChaParametersRef {
            nonce: Some(&nonce),
            counter: None,
            aad: None,
        };
        let mut sealed = encrypt(
            DataEncryptionAlgorithm::ChaCha20Poly1305,
            &key,
            PLAINTEXT,
            parameters,
        )
        .expect("XML AEAD adapter");
        assert_eq!(&sealed[..PLAINTEXT.len()], output);
        assert_eq!(
            decrypt(
                DataEncryptionAlgorithm::ChaCha20Poly1305,
                &key,
                &sealed,
                parameters,
            )
            .expect("XML AEAD decryption"),
            PLAINTEXT
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(matches!(
            decrypt(
                DataEncryptionAlgorithm::ChaCha20Poly1305,
                &key,
                &sealed,
                parameters,
            ),
            Err(ProviderError::AuthenticationFailed)
        ));
    }

    #[test]
    fn exhausted_counter_is_rejected_without_output() {
        // Counter exhaustion must never wrap and reuse keystream (RFC 8439 §2.4).
        // https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4
        let parameters = ChaChaParametersRef {
            nonce: Some(&[0; 12]),
            counter: Some(u32::MAX.to_le_bytes()),
            aad: None,
        };
        for operation in [encrypt, decrypt] {
            assert!(matches!(
                operation(
                    DataEncryptionAlgorithm::ChaCha20,
                    &[0; 32],
                    &[0; 65],
                    parameters
                ),
                Err(ProviderError::InvalidInput(
                    ProviderInputError::PrimitiveInitialization(_)
                ))
            ));
        }
    }
}
