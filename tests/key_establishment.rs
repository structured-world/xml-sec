#![cfg(feature = "xmlenc")]

use xml_sec::provider::{
    CryptoProvider, KdfContext, KdfParameters, KeyAgreementParameters, RUST_CRYPTO_PROVIDER,
    RustCryptoX25519Key,
};

#[test]
fn ecdh_all_nist_curves_preserve_fixed_width_and_validate_peers() {
    use xml_sec::provider::{EcdhCurve, RustCryptoEcdhKey};
    // With scalar one, ECDH returns the peer's affine x coordinate. Exercise
    // all curve widths and reject the SEC1 identity instead of deriving from it.
    for (curve, width) in [
        (EcdhCurve::P256, 32),
        (EcdhCurve::P384, 48),
        (EcdhCurve::P521, 66),
    ] {
        let mut scalar = vec![0; width];
        scalar[width - 1] = 1;
        let key = RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap();
        let public = key.public_key();
        let mut parameters = KeyAgreementParameters {
            algorithm: "http://www.w3.org/2009/xmlenc11#ECDH-ES",
            peer_public_key: &public,
        };
        assert_eq!(
            RUST_CRYPTO_PROVIDER.agree_key(&key, &parameters).unwrap(),
            public[1..1 + width]
        );
        parameters.peer_public_key = &[0];
        assert!(RUST_CRYPTO_PROVIDER.agree_key(&key, &parameters).is_err());
        assert!(RustCryptoEcdhKey::from_scalar(curve, &vec![0; width]).is_err());
    }
}

fn hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "odd test hex width");
    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid test hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn legacy_dh_kdf_matches_xmlenc_normative_example() {
    // XMLEnc 1.1 section 5.6.2.2 example 41 hashes ZZ followed by ASCII
    // "01", the consuming algorithm URI, nonce and decimal key bits.
    // The printed digest is corrected by accepted informative erratum E01:
    // https://www.w3.org/2008/xmlsec/errata/xmlenc-core-11-errata.html
    let parameters = KdfParameters {
        algorithm: "http://www.w3.org/2001/04/xmlenc#dh",
        digest: Some("http://www.w3.org/2000/09/xmldsig#sha1"),
        salt: &[],
        info: KdfContext::LegacyDh {
            encryption_algorithm: "Example:Block/Alg",
            nonce: b"foo",
        },
        iterations: 0,
        output_len: 10,
    };
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, &hex("deadbeef"))
            .unwrap(),
        hex("59d9ba5e06072c119409")
    );
    let mut invalid = parameters;
    invalid.output_len = 255 * 20 + 1;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&invalid, b"secret")
            .is_err()
    );
    invalid = parameters;
    invalid.info = KdfContext::Octets(b"Example:Block/Algfoo80");
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&invalid, b"secret")
            .is_err()
    );
}

#[test]
fn legacy_dh_counter_reaches_ff_without_wrapping_or_decimal_encoding() {
    use sha1::Digest as _;
    // The protocol counter is exactly two uppercase hexadecimal characters.
    // Compare every block through FF, including the numeric/alphabetic boundary.
    let output_len = 255 * 20;
    let parameters = KdfParameters {
        algorithm: "http://www.w3.org/2001/04/xmlenc#dh",
        digest: Some("http://www.w3.org/2000/09/xmldsig#sha1"),
        salt: &[],
        info: KdfContext::LegacyDh {
            encryption_algorithm: "urn:consuming-cipher",
            nonce: b"nonce",
        },
        iterations: 0,
        output_len,
    };
    let actual = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters, b"secret")
        .unwrap();
    for (index, block) in actual.as_chunks::<20>().0.iter().enumerate() {
        let mut hash = sha1::Sha1::new();
        hash.update(b"secret");
        hash.update(format!("{:02X}", index + 1).as_bytes());
        hash.update(b"urn:consuming-cipher");
        hash.update(b"nonce");
        hash.update((output_len * 8).to_string().as_bytes());
        assert_eq!(block.as_slice(), hash.finalize().as_slice());
    }
}

#[test]
fn hkdf_matches_rfc5869_case_one() {
    // RFC 5869 Appendix A.1: extract-and-expand must preserve salt and info.
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let parameters = KdfParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
        digest: Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
        salt: &salt,
        info: KdfContext::Octets(&info),
        iterations: 0,
        output_len: 42,
    };
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, &[0x0b; 22])
            .unwrap(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn pbkdf2_matches_rfc6070_and_rejects_invalid_parameters() {
    // RFC 6070 sections 2 and 3: iteration changes and embedded NULs must
    // change the PRF input, not be treated as text terminators or defaults.
    let mut parameters = KdfParameters {
        algorithm: "http://www.w3.org/2009/xmlenc11#pbkdf2",
        digest: Some("http://www.w3.org/2000/09/xmldsig#hmac-sha1"),
        salt: b"salt",
        info: KdfContext::Octets(&[]),
        iterations: 1,
        output_len: 20,
    };
    for (iterations, expected) in [
        (1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        (2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        (4096, "4b007901b765489abead49d926f721d065a429c1"),
    ] {
        parameters.iterations = iterations;
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"password")
                .unwrap(),
            hex(expected)
        );
    }
    parameters.salt = b"sa\0lt";
    parameters.output_len = 16;
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"pass\0word")
            .unwrap(),
        hex("56fa6aa75548099dcc37d7f03425e0c3")
    );
    parameters.iterations = 0;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"password")
            .is_err()
    );
    parameters.iterations = 1;
    parameters.output_len = 0;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"password")
            .is_err()
    );
    parameters.output_len = 16;
    parameters.info = KdfContext::Octets(b"not a PBKDF2 parameter");
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"password")
            .is_err()
    );
    parameters.info = KdfContext::Octets(&[]);
    parameters.digest = None;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"password")
            .is_err()
    );
}

#[test]
fn pbkdf2_all_prfs_match_rustcrypto_across_output_blocks() {
    use xml_sec::xmldsig::SignatureAlgorithm;
    // Compare exact bytes for all advertised PRFs with the independent existing
    // RustCrypto entry point, including a partial final block and a long key.
    macro_rules! check {
        ($digest:ty, $prf:expr, $width:expr) => {{
            let parameters = KdfParameters {
                algorithm: "http://www.w3.org/2009/xmlenc11#pbkdf2",
                digest: Some($prf.uri()),
                salt: b"salt",
                info: KdfContext::Octets(&[]),
                iterations: 3,
                output_len: 2 * $width + 1,
            };
            let password = [0xa5; 200];
            let mut expected = vec![0; parameters.output_len];
            pbkdf2::pbkdf2_hmac::<$digest>(&password, parameters.salt, 3, &mut expected);
            assert_eq!(
                RUST_CRYPTO_PROVIDER
                    .derive_key(&parameters, &password)
                    .unwrap(),
                expected
            );
        }};
    }
    check!(sha1::Sha1, SignatureAlgorithm::HmacSha1, 20);
    check!(sha2::Sha224, SignatureAlgorithm::HmacSha224, 28);
    check!(sha2::Sha256, SignatureAlgorithm::HmacSha256, 32);
    check!(sha2::Sha384, SignatureAlgorithm::HmacSha384, 48);
    check!(sha2::Sha512, SignatureAlgorithm::HmacSha512, 64);
}

#[test]
fn concat_kdf_hashes_counter_secret_and_context_without_hmac_or_salt() {
    use sha2::Digest;
    // XMLEnc 1.1 section 5.4.1: counter starts at one; each block hashes
    // counter || Z || OtherInfo. Cover a partial output block and hash padding
    // boundaries with an independent byte-oriented Digest implementation.
    for length in [0, 1, 19, 20, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129] {
        let info = vec![0x5a; length];
        let parameters = KdfParameters {
            algorithm: "http://www.w3.org/2009/xmlenc11#ConcatKDF",
            digest: Some("http://www.w3.org/2001/04/xmlenc#sha256"),
            salt: &[],
            info: KdfContext::Octets(&info),
            iterations: 0,
            output_len: 37,
        };
        let mut expected = Vec::new();
        for counter in [1_u32, 2] {
            let mut digest = sha2::Sha256::new();
            digest.update(counter.to_be_bytes());
            digest.update(b"secret");
            digest.update(&info);
            expected.extend_from_slice(&digest.finalize());
        }
        expected.truncate(37);
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .unwrap(),
            expected
        );
    }
}

#[test]
fn concat_kdf_rejects_malformed_bit_strings_and_unrelated_parameters() {
    // Packed bit strings must not carry undeclared trailing data or nonzero
    // padding. Octet-only KDFs must not silently round a valid partial string.
    let mut parameters = KdfParameters {
        algorithm: "http://www.w3.org/2009/xmlenc11#ConcatKDF",
        digest: Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        salt: &[],
        info: KdfContext::Bits {
            bytes: &[0x80],
            bit_len: 1,
        },
        iterations: 0,
        output_len: 16,
    };
    let partial = RUST_CRYPTO_PROVIDER
        .derive_key(&parameters, b"secret")
        .unwrap();
    parameters.info = KdfContext::Octets(&[0x80]);
    assert_ne!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"secret")
            .unwrap(),
        partial
    );
    for context in [
        KdfContext::Bits {
            bytes: &[0x81],
            bit_len: 1,
        },
        KdfContext::Bits {
            bytes: &[0x80],
            bit_len: 9,
        },
        KdfContext::Bits {
            bytes: &[0x80],
            bit_len: 0,
        },
        KdfContext::Bits {
            bytes: &[],
            bit_len: usize::MAX,
        },
    ] {
        parameters.info = context;
        assert!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .is_err()
        );
    }
    parameters.info = KdfContext::Bits {
        bytes: &[0x80],
        bit_len: 1,
    };
    parameters.algorithm = "http://www.w3.org/2021/04/xmldsig-more#hkdf";
    parameters.digest = Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"secret")
            .is_err()
    );
    parameters.algorithm = "http://www.w3.org/2009/xmlenc11#pbkdf2";
    parameters.iterations = 1;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"secret")
            .is_err()
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn legacy_concat_hashes_match_independent_digest_at_block_boundaries() {
    use sha2::Digest;
    // Legacy digest permission is separate from primitive support. Compare
    // complete multi-block output against the byte-oriented RustCrypto API;
    // boundary lengths catch applying big-endian SHA framing to MD5/RIPEMD.
    macro_rules! check {
        ($digest:ty, $uri:expr) => {
            for length in [0, 1, 45, 46, 47, 53, 54, 55, 56, 63, 64, 129] {
                let info = vec![0xa5; length];
                let parameters = KdfParameters {
                    algorithm: "http://www.w3.org/2009/xmlenc11#ConcatKDF",
                    digest: Some($uri),
                    salt: &[],
                    info: KdfContext::Octets(&info),
                    iterations: 0,
                    output_len: 37,
                };
                let mut expected = Vec::new();
                for counter in [1_u32, 2, 3] {
                    let mut digest = <$digest>::new();
                    digest.update(counter.to_be_bytes());
                    digest.update(b"secret");
                    digest.update(&info);
                    expected.extend_from_slice(&digest.finalize());
                }
                expected.truncate(37);
                assert_eq!(
                    RUST_CRYPTO_PROVIDER
                        .derive_key(&parameters, b"secret")
                        .unwrap(),
                    expected
                );
            }
        };
    }
    check!(md5::Md5, "http://www.w3.org/2001/04/xmldsig-more#md5");
    check!(
        ripemd::Ripemd160,
        "http://www.w3.org/2001/04/xmlenc#ripemd160"
    );
}

#[test]
fn agreement_primitives_compose_with_xmlenc_key_wrap_and_authenticated_content() {
    use xml_sec::provider::{EcdhCurve, KeyAgreementKey, RustCryptoEcdhKey};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptedContent, EncryptedDataBuilder, EncryptionRecipient,
        KekDecryptor, KeyWrapAlgorithm, decrypt,
    };
    // Check the public primitive-to-XML boundary: both parties independently
    // derive the KEK; it must unwrap the emitted EncryptedKey and authenticate
    // its GCM content. This does NOT claim XML AgreementMethod resolution.
    let check = |sender: &dyn KeyAgreementKey,
                 sender_public: &[u8],
                 recipient: &dyn KeyAgreementKey,
                 recipient_public: &[u8],
                 agreement: &str| {
        let sender_secret = zeroize::Zeroizing::new(
            RUST_CRYPTO_PROVIDER
                .agree_key(
                    sender,
                    &KeyAgreementParameters {
                        algorithm: agreement,
                        peer_public_key: recipient_public,
                    },
                )
                .unwrap(),
        );
        let recipient_secret = zeroize::Zeroizing::new(
            RUST_CRYPTO_PROVIDER
                .agree_key(
                    recipient,
                    &KeyAgreementParameters {
                        algorithm: agreement,
                        peer_public_key: sender_public,
                    },
                )
                .unwrap(),
        );
        assert_eq!(*sender_secret, *recipient_secret);
        for (content, wrap) in [
            (
                DataEncryptionAlgorithm::Aes128Gcm,
                KeyWrapAlgorithm::AesKw128,
            ),
            (
                DataEncryptionAlgorithm::Aes256Gcm,
                KeyWrapAlgorithm::AesKw256,
            ),
        ] {
            for (kdf, digest, context) in [
                (
                    "http://www.w3.org/2021/04/xmldsig-more#hkdf",
                    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                    KdfContext::Octets(b"recipient context"),
                ),
                (
                    "http://www.w3.org/2009/xmlenc11#ConcatKDF",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    KdfContext::Bits {
                        bytes: &[0xa8],
                        bit_len: 5,
                    },
                ),
            ] {
                let parameters = KdfParameters {
                    algorithm: kdf,
                    digest: Some(digest),
                    salt: &[],
                    info: context,
                    iterations: 0,
                    output_len: wrap.key_len(),
                };
                let sender_kek = RUST_CRYPTO_PROVIDER
                    .derive_key(&parameters, &sender_secret)
                    .unwrap();
                let recipient_kek = RUST_CRYPTO_PROVIDER
                    .derive_key(&parameters, &recipient_secret)
                    .unwrap();
                let encrypted = EncryptedDataBuilder::new(content)
                    .add_recipient(EncryptionRecipient::aes_key_wrap(sender_kek, wrap))
                    .encrypt_binary(b"agreement-derived recipient key")
                    .unwrap();
                assert_eq!(
                    decrypt(
                        &encrypted.encrypted_data_xml,
                        &KekDecryptor::new(recipient_kek.clone())
                    )
                    .unwrap(),
                    DecryptedContent::Bytes(b"agreement-derived recipient key".to_vec())
                );
                let mut wrong = zeroize::Zeroizing::new(recipient_kek);
                wrong[0] ^= 1;
                assert!(
                    decrypt(
                        &encrypted.encrypted_data_xml,
                        &KekDecryptor::new(wrong.to_vec())
                    )
                    .is_err()
                );
            }
        }
    };
    for (curve, width) in [
        (EcdhCurve::P256, 32),
        (EcdhCurve::P384, 48),
        (EcdhCurve::P521, 66),
    ] {
        let mut scalar = zeroize::Zeroizing::new(vec![0; width]);
        scalar[width - 1] = 3;
        let sender = RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap();
        scalar[width - 1] = 5;
        let recipient = RustCryptoEcdhKey::from_scalar(curve, &scalar).unwrap();
        check(
            &sender,
            &sender.public_key(),
            &recipient,
            &recipient.public_key(),
            "http://www.w3.org/2009/xmlenc11#ECDH-ES",
        );
    }
    let sender = RustCryptoX25519Key::from_bytes([3; 32]);
    let recipient = RustCryptoX25519Key::from_bytes([5; 32]);
    check(
        &sender,
        &sender.public_key(),
        &recipient,
        &recipient.public_key(),
        "http://www.w3.org/2021/04/xmldsig-more#x25519",
    );
}

#[test]
fn hkdf_empty_salt_and_info_match_rfc5869_case_three() {
    // RFC 5869 Appendix A.3: omission means the specified empty/default inputs,
    // never an application-selected fallback digest or context.
    let parameters = KdfParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
        digest: Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
        salt: &[],
        info: KdfContext::Octets(&[]),
        iterations: 0,
        output_len: 42,
    };
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, &[0x0b; 22])
            .unwrap(),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn hkdf_sha1_matches_rfc5869_case_four() {
    // RFC 5869 Appendix A.4 checks a different PRF and hash block size.
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let parameters = KdfParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
        digest: Some("http://www.w3.org/2000/09/xmldsig#hmac-sha1"),
        salt: &salt,
        info: KdfContext::Octets(&info),
        iterations: 0,
        output_len: 42,
    };
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, &[0x0b; 11])
            .unwrap(),
        hex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
    );
}

#[test]
fn hkdf_all_prfs_enforce_exact_expand_boundary() {
    use xml_sec::xmldsig::SignatureAlgorithm;
    // Every advertised PRF accepts exactly 255 blocks, rejects one extra byte,
    // and preserves a caller-requested zero-length output.
    for (prf, width) in [
        (SignatureAlgorithm::HmacSha1, 20),
        (SignatureAlgorithm::HmacSha224, 28),
        (SignatureAlgorithm::HmacSha256, 32),
        (SignatureAlgorithm::HmacSha384, 48),
        (SignatureAlgorithm::HmacSha512, 64),
    ] {
        let mut parameters = KdfParameters {
            algorithm: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
            digest: Some(prf.uri()),
            salt: &[],
            info: KdfContext::Octets(&[]),
            iterations: 0,
            output_len: 255 * width,
        };
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .unwrap()
                .len(),
            parameters.output_len
        );
        parameters.output_len += 1;
        assert!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .is_err()
        );
        parameters.output_len = 0;
        assert!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .unwrap()
                .is_empty()
        );
        parameters.digest = Some(SignatureAlgorithm::RsaSha256.uri());
        assert!(
            RUST_CRYPTO_PROVIDER
                .derive_key(&parameters, b"secret")
                .is_err()
        );
    }
}

#[test]
fn x25519_masks_peer_high_bit_per_rfc7748() {
    // RFC 7748 section 5 requires masking bit 255, not rejecting a peer whose
    // encoding has it set. This boundary must match the underlying primitive.
    let alice = RustCryptoX25519Key::from_bytes([7; 32]);
    let bob = RustCryptoX25519Key::from_bytes([9; 32]);
    let mut public = bob.public_key();
    let parameters = KeyAgreementParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#x25519",
        peer_public_key: &public,
    };
    let expected = RUST_CRYPTO_PROVIDER.agree_key(&alice, &parameters).unwrap();
    public[31] |= 0x80;
    let parameters = KeyAgreementParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#x25519",
        peer_public_key: &public,
    };
    assert_eq!(
        RUST_CRYPTO_PROVIDER.agree_key(&alice, &parameters).unwrap(),
        expected
    );
}

#[test]
fn hkdf_rejects_excessive_output_and_iteration_parameter() {
    // RFC 5869 section 2.3 bounds expand output before allocating its buffer.
    let mut parameters = KdfParameters {
        algorithm: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
        digest: Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
        salt: &[],
        info: KdfContext::Octets(&[]),
        iterations: 0,
        output_len: 255 * 32 + 1,
    };
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"secret")
            .is_err()
    );
    parameters.output_len = 32;
    parameters.iterations = 1;
    assert!(
        RUST_CRYPTO_PROVIDER
            .derive_key(&parameters, b"secret")
            .is_err()
    );
}

#[test]
fn x25519_matches_rfc7748_alice_bob() {
    // RFC 7748 section 6.1: both parties must derive exactly the same secret.
    let alice = RustCryptoX25519Key::from_bytes(
        hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap(),
    );
    let bob = RustCryptoX25519Key::from_bytes(
        hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        alice.public_key().as_slice(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    for (key, peer) in [(&alice, bob.public_key()), (&bob, alice.public_key())] {
        let parameters = KeyAgreementParameters {
            algorithm: "http://www.w3.org/2021/04/xmldsig-more#x25519",
            peer_public_key: &peer,
        };
        assert_eq!(
            RUST_CRYPTO_PROVIDER.agree_key(key, &parameters).unwrap(),
            expected
        );
    }
}

#[test]
fn x25519_rejects_noncontributory_and_wrong_width_peers() {
    // Reject low-order/all-zero shared secrets and malformed wire widths.
    let key = RustCryptoX25519Key::from_bytes([7; 32]);
    for peer in [&[0; 32][..], &[0; 31][..], &[0; 33][..]] {
        let parameters = KeyAgreementParameters {
            algorithm: "http://www.w3.org/2021/04/xmldsig-more#x25519",
            peer_public_key: peer,
        };
        assert!(RUST_CRYPTO_PROVIDER.agree_key(&key, &parameters).is_err());
    }
}

#[test]
fn x448_matches_rfc7748_alice_bob() {
    use xml_sec::provider::RustCryptoX448Key;
    // RFC 7748 section 6.2 checks both public encodings and the shared secret.
    let alice = RustCryptoX448Key::from_bytes(
        hex(concat!(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d",
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        ))
        .try_into()
        .unwrap(),
    );
    let bob = RustCryptoX448Key::from_bytes(
        hex(concat!(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d",
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        ))
        .try_into()
        .unwrap(),
    );
    assert_eq!(
        alice.public_key().as_slice(),
        hex(concat!(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c",
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        ))
    );
    assert_eq!(
        bob.public_key().as_slice(),
        hex(concat!(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430",
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        ))
    );
    let expected = hex(concat!(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b",
        "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    ));
    for (key, peer) in [(&alice, bob.public_key()), (&bob, alice.public_key())] {
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .agree_key(
                    key,
                    &KeyAgreementParameters {
                        algorithm: "http://www.w3.org/2021/04/xmldsig-more#x448",
                        peer_public_key: &peer,
                    }
                )
                .unwrap(),
            expected
        );
    }
}

#[test]
fn x448_reduces_noncanonical_peers_and_rejects_zero_secrets() {
    use xml_sec::provider::{ProviderError, RustCryptoX448Key};
    // RFC 7748 section 5: p + 5 and 5 encode the same field element.
    let key = RustCryptoX448Key::from_bytes([7; 56]);
    let mut base = [0; 56];
    base[0] = 5;
    let mut equivalent = [0; 56];
    equivalent[0] = 4;
    equivalent[28..].fill(0xff);
    let agree = |peer: &[u8]| {
        RUST_CRYPTO_PROVIDER.agree_key(
            &key,
            &KeyAgreementParameters {
                algorithm: "http://www.w3.org/2021/04/xmldsig-more#x448",
                peer_public_key: peer,
            },
        )
    };
    assert_eq!(agree(&base).unwrap(), agree(&equivalent).unwrap());
    // Contributory agreement is a product requirement, permitted by section 6.2.
    let mut p = [0xff; 56];
    p[28] = 0xfe;
    let mut one = [0; 56];
    one[0] = 1;
    for peer in [[0; 56], one, p] {
        assert!(matches!(
            agree(&peer),
            Err(ProviderError::AuthenticationFailed)
        ));
    }
    for peer in [&[0; 55][..], &[0; 57][..]] {
        assert!(matches!(
            agree(peer),
            Err(ProviderError::InvalidKeySize { expected: 56, .. })
        ));
    }
}

#[test]
fn x448_pkcs8_import_checks_oid_wrapping_and_public_identity() {
    use der::{
        Encode,
        asn1::{BitStringRef, OctetStringRef},
    };
    use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfoRef};
    use xml_sec::provider::RustCryptoX448Key;
    // RFC 8410 sections 3 and 7 require absent parameters and a nested
    // CurvePrivateKey OCTET STRING. A supplied public key must match the scalar.
    let scalar = [7; 56];
    let raw_key = RustCryptoX448Key::from_bytes(scalar);
    let nested = OctetStringRef::new(&scalar).unwrap().to_der().unwrap();
    let mut info = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.101.111"),
            parameters: None,
        },
        OctetStringRef::new(&nested).unwrap(),
    );
    assert_eq!(
        RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap())
            .unwrap()
            .public_key(),
        raw_key.public_key()
    );
    let public = raw_key.public_key();
    info.public_key = Some(BitStringRef::from_bytes(&public).unwrap());
    assert_eq!(
        RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap())
            .unwrap()
            .public_key(),
        public
    );
    let mut wrong_public = public;
    wrong_public[0] ^= 1;
    info.public_key = Some(BitStringRef::from_bytes(&wrong_public).unwrap());
    assert!(RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap()).is_err());
    info.public_key = None;
    info.algorithm.parameters = Some(der::asn1::AnyRef::NULL);
    assert!(RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap()).is_err());
    info.algorithm.parameters = None;
    info.algorithm.oid = ObjectIdentifier::new_unwrap("1.3.101.110");
    assert!(RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap()).is_err());
    info.algorithm.oid = ObjectIdentifier::new_unwrap("1.3.101.111");
    info.private_key = OctetStringRef::new(&scalar).unwrap();
    assert!(RustCryptoX448Key::from_pkcs8_der(&info.to_der().unwrap()).is_err());
}
