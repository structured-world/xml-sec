use super::*;
use der::{
    Encode as _,
    asn1::{BitStringRef, UintRef},
};

#[cfg(all(feature = "legacy-algorithms", feature = "xmlenc"))]
#[test]
fn optional_legacy_capabilities_fail_without_another_engine() {
    // Compiling RustCrypto compatibility mechanisms cannot make AWS native
    // capability checks silently dispatch into that different provider.
    for algorithm in [
        DataEncryptionAlgorithm::TripleDesCbc,
        DataEncryptionAlgorithm::Aes192Cbc,
        DataEncryptionAlgorithm::Aes192Gcm,
    ] {
        assert!(!AwsLcFipsProvider.supports(ProviderCapability::Encrypt(algorithm)));
        assert!(matches!(
            AwsLcFipsProvider.encrypt_data(algorithm, &[0x31; 24], b"test"),
            Err(ProviderError::Unsupported { .. })
        ));
    }
    for algorithm in [KeyWrapAlgorithm::AesKw192, KeyWrapAlgorithm::TripleDes] {
        assert!(!AwsLcFipsProvider.supports(ProviderCapability::KeyWrap(algorithm)));
        assert!(matches!(
            AwsLcFipsProvider.wrap_key(algorithm, &[0x31; 24], &[0x42; 16]),
            Err(ProviderError::Unsupported { .. })
        ));
    }
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::Pkcs1v15Transport));
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::Pkcs1v15Recovery));
    for digest in [DigestAlgorithm::Md5, DigestAlgorithm::Ripemd160] {
        assert!(!AwsLcFipsProvider.supports(ProviderCapability::Digest(digest)));
        assert!(matches!(
            AwsLcFipsProvider.digest(digest, b"test"),
            Err(ProviderError::Unsupported { .. })
        ));
    }
}

#[test]
fn rsa_verifier_checks_exact_bit_boundaries_without_bigints() {
    // Byte-aligned rounding would accept 2047 or 8193 bits. Exercise the
    // dispatch gate independently of signature correctness and strength policy.
    for (bits, accepted) in [
        (2047usize, false),
        (2048, true),
        (8192, true),
        (8193, false),
    ] {
        let mut modulus = vec![0; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().expect("nonempty boundary modulus") |= 1;
        let rsa = pkcs1::RsaPublicKeyRef {
            modulus: UintRef::new(&modulus).expect("unsigned boundary modulus"),
            public_exponent: UintRef::new(&[1, 0, 1]).expect("unsigned exponent"),
        }
        .to_der()
        .expect("RSA public key DER");
        let spki = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs1::ALGORITHM_ID,
            subject_public_key: BitStringRef::new(0, &rsa).expect("octet-aligned key bits"),
        }
        .to_der()
        .expect("RSA SPKI DER");
        for algorithm in [
            SignatureAlgorithm::RsaSha1,
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
        ] {
            let result = verification_algorithm(
                algorithm,
                &spki,
                crate::policy::EcdsaSignatureValueEncoding::XmlDsig,
            );
            if accepted {
                assert!(result.is_ok(), "{bits} {algorithm:?}");
            } else {
                assert!(
                    matches!(
                        result,
                        Err(
                            crate::xmldsig::SignatureVerificationError::UnsupportedAlgorithm { .. }
                        )
                    ),
                    "{bits} {algorithm:?}"
                );
            }
        }
    }
}

#[test]
fn malformed_rsa_spki_is_not_a_capability_failure() {
    // Invalid DER must remain invalid key data, not unsupported or bad signature.
    assert!(matches!(
        verification_algorithm(
            SignatureAlgorithm::RsaSha256,
            b"not DER",
            crate::policy::EcdsaSignatureValueEncoding::XmlDsig
        ),
        Err(crate::xmldsig::SignatureVerificationError::InvalidKeyDer)
    ));
}
