//! Digest computation for XMLDSig `<Reference>` processing.
//!
//! Implements [XMLDSig §6.1](https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod):
//! compute message digests over transform output bytes using SHA-family algorithms.
//!
//! All digest computation uses RustCrypto hash implementations.

use subtle::ConstantTimeEq;

/// Digest algorithms supported by XMLDSig.
///
/// SHA-1 is supported for verification only (legacy interop with older IdPs).
/// SHA-256 is the recommended default for new signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-1 (160-bit). **Verify-only** — signing with SHA-1 is deprecated.
    Sha1,
    /// SHA-256 (256-bit). Default for SAML.
    Sha256,
    /// SHA-384 (384-bit).
    Sha384,
    /// SHA-512 (512-bit).
    Sha512,
}

impl DigestAlgorithm {
    /// Parse a digest algorithm from its XML namespace URI.
    ///
    /// Returns `None` for unrecognized URIs.
    ///
    /// # URIs
    ///
    /// | Algorithm | URI |
    /// |-----------|-----|
    /// | SHA-1 | `http://www.w3.org/2000/09/xmldsig#sha1` |
    /// | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
    /// | SHA-384 | `http://www.w3.org/2001/04/xmldsig-more#sha384` |
    /// | SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` |
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2000/09/xmldsig#sha1" => Some(Self::Sha1),
            "http://www.w3.org/2001/04/xmlenc#sha256" => Some(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Return the XML namespace URI for this digest algorithm.
    pub fn uri(self) -> &'static str {
        match self {
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// Whether this algorithm is allowed for signing (not just verification).
    ///
    /// SHA-1 is deprecated and restricted to verify-only for interop with
    /// legacy IdPs.
    pub fn signing_allowed(self) -> bool {
        !matches!(self, Self::Sha1)
    }

    /// The expected output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Compute the digest of `data` using the specified algorithm.
///
/// Returns the raw digest bytes (not base64-encoded).
pub fn compute_digest(algorithm: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    compute_digest_with_provider(crate::provider::default_provider(), algorithm, data)
        .expect("default provider advertises every XMLDSig digest")
}

/// Compute a digest with an explicitly selected provider.
pub fn compute_digest_with_provider(
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DigestAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, crate::provider::ProviderError> {
    let digest = provider.digest(algorithm, data)?;
    let expected = algorithm.output_len();
    if digest.len() != expected {
        return Err(crate::provider::ProviderError::InvalidOutputSize {
            operation: crate::provider::ProviderOperation::Digest,
            expected,
            actual: digest.len(),
        });
    }
    Ok(digest)
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if and only if `a` and `b` have equal length and identical
/// content. Execution time depends only on the length of the slices, not on
/// where they differ — preventing timing side-channel attacks on digest
/// comparison.
///
/// Uses `subtle` constant-time equality.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectingDigestProvider {
        output: Option<Vec<u8>>,
    }

    impl crate::provider::CryptoProvider for RejectingDigestProvider {
        fn name(&self) -> &'static str {
            "rejecting-digest"
        }

        fn supports(&self, query: crate::provider::CapabilityQuery<'_>) -> bool {
            crate::provider::default_provider().supports(query)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
            crate::provider::default_provider().fill_random(output)
        }

        fn digest(
            &self,
            algorithm: DigestAlgorithm,
            _data: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            if let Some(output) = &self.output {
                return Ok(output.clone());
            }
            Err(crate::provider::ProviderError::Unsupported {
                operation: crate::provider::ProviderOperation::Digest,
                algorithm: Some(algorithm.uri().to_owned()),
            })
        }

        fn sign(
            &self,
            key: &dyn super::super::SigningKey,
            algorithm: super::super::SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, super::super::SigningKeyError> {
            crate::provider::default_provider().sign(key, algorithm, data)
        }

        fn verify(
            &self,
            key: &dyn super::super::VerifyingKey,
            algorithm: super::super::SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, super::super::DsigError> {
            crate::provider::default_provider().verify(key, algorithm, data, signature)
        }

        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().encrypt_data(algorithm, key, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().decrypt_data(algorithm, key, ciphertext)
        }

        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().wrap_key(algorithm, kek, key)
        }

        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().unwrap_key(algorithm, kek, wrapped)
        }

        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            key: &rsa::RsaPublicKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &rsa::RsaPrivateKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().recover_key(key, parameters, ciphertext)
        }
    }

    #[test]
    fn explicit_provider_digest_failures_are_returned() {
        // A restricted provider is caller-controlled and must never turn an
        // unsupported document-selected digest into a process panic.
        assert!(matches!(
            compute_digest_with_provider(
                &RejectingDigestProvider { output: None },
                DigestAlgorithm::Sha256,
                b"x"
            ),
            Err(crate::provider::ProviderError::Unsupported { .. })
        ));
    }

    #[test]
    fn explicit_provider_digest_output_must_match_the_algorithm() {
        // The facade, rather than an interchangeable provider, owns the XMLDSig
        // algorithm contract and must reject bytes its own parser cannot accept.
        for actual in [0, 31, 33] {
            assert!(matches!(
                compute_digest_with_provider(
                    &RejectingDigestProvider {
                        output: Some(vec![0_u8; actual]),
                    },
                    DigestAlgorithm::Sha256,
                    b"x",
                ),
                Err(crate::provider::ProviderError::InvalidOutputSize {
                    operation: crate::provider::ProviderOperation::Digest,
                    expected: 32,
                    actual: output_len,
                }) if output_len == actual
            ));
        }

        assert_eq!(
            compute_digest_with_provider(
                &RejectingDigestProvider {
                    output: Some(vec![7_u8; 32]),
                },
                DigestAlgorithm::Sha256,
                b"x",
            ),
            Ok(vec![7_u8; 32]),
        );
    }

    // ── from_uri / uri round-trip ────────────────────────────────────

    #[test]
    fn from_uri_sha1() {
        let algo = DigestAlgorithm::from_uri("http://www.w3.org/2000/09/xmldsig#sha1");
        assert_eq!(algo, Some(DigestAlgorithm::Sha1));
    }

    #[test]
    fn from_uri_sha256() {
        let algo = DigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmlenc#sha256");
        assert_eq!(algo, Some(DigestAlgorithm::Sha256));
    }

    #[test]
    fn from_uri_sha384() {
        let algo = DigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#sha384");
        assert_eq!(algo, Some(DigestAlgorithm::Sha384));
    }

    #[test]
    fn from_uri_sha512() {
        let algo = DigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmlenc#sha512");
        assert_eq!(algo, Some(DigestAlgorithm::Sha512));
    }

    #[test]
    fn from_uri_unknown() {
        assert_eq!(
            DigestAlgorithm::from_uri("http://example.com/unknown"),
            None
        );
    }

    #[test]
    fn uri_round_trip() {
        for algo in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            assert_eq!(
                DigestAlgorithm::from_uri(algo.uri()),
                Some(algo),
                "round-trip failed for {algo:?}"
            );
        }
    }

    // ── signing_allowed ──────────────────────────────────────────────

    #[test]
    fn sha1_verify_only() {
        assert!(!DigestAlgorithm::Sha1.signing_allowed());
    }

    #[test]
    fn sha256_signing_allowed() {
        assert!(DigestAlgorithm::Sha256.signing_allowed());
    }

    #[test]
    fn sha384_signing_allowed() {
        assert!(DigestAlgorithm::Sha384.signing_allowed());
    }

    #[test]
    fn sha512_signing_allowed() {
        assert!(DigestAlgorithm::Sha512.signing_allowed());
    }

    // ── output_len ───────────────────────────────────────────────────

    #[test]
    fn output_lengths() {
        assert_eq!(DigestAlgorithm::Sha1.output_len(), 20);
        assert_eq!(DigestAlgorithm::Sha256.output_len(), 32);
        assert_eq!(DigestAlgorithm::Sha384.output_len(), 48);
        assert_eq!(DigestAlgorithm::Sha512.output_len(), 64);
    }

    // ── Known-answer tests (KAT) ────────────────────────────────────
    // Reference values computed with `echo -n "..." | openssl dgst -sha*`

    #[test]
    fn sha1_empty() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let digest = compute_digest(DigestAlgorithm::Sha1, b"");
        assert_eq!(digest.len(), 20);
        assert_eq!(hex(&digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = compute_digest(DigestAlgorithm::Sha256, b"");
        assert_eq!(digest.len(), 32);
        assert_eq!(
            hex(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha384_empty() {
        // SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
        let digest = compute_digest(DigestAlgorithm::Sha384, b"");
        assert_eq!(digest.len(), 48);
        assert_eq!(
            hex(&digest),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha512_empty() {
        // SHA-512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
        let digest = compute_digest(DigestAlgorithm::Sha512, b"");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            hex(&digest),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha256_hello_world() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let digest = compute_digest(DigestAlgorithm::Sha256, b"hello world");
        assert_eq!(
            hex(&digest),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha1_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let digest = compute_digest(DigestAlgorithm::Sha1, b"abc");
        assert_eq!(hex(&digest), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    // ── constant_time_eq ─────────────────────────────────────────────

    #[test]
    fn constant_time_eq_identical() {
        let a = compute_digest(DigestAlgorithm::Sha256, b"test");
        let b = compute_digest(DigestAlgorithm::Sha256, b"test");
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_content() {
        let a = compute_digest(DigestAlgorithm::Sha256, b"test1");
        let b = compute_digest(DigestAlgorithm::Sha256, b"test2");
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(&[], &[]));
    }

    // ── Digest output matches expected length ────────────────────────

    #[test]
    fn digest_output_matches_declared_length() {
        let data = b"test data for length verification";
        for algo in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let digest = compute_digest(algo, data);
            assert_eq!(
                digest.len(),
                algo.output_len(),
                "output length mismatch for {algo:?}"
            );
        }
    }

    /// Helper: format bytes as lowercase hex string.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
