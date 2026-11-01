//! Digest computation for `XMLDSig` `<Reference>` processing.
//!
//! Implements [XMLDSig §6.1](https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod):
//! compute message digests over transform output bytes using the selected algorithm.
//!
//! Operation digest computation uses the selected `CryptoProvider`; the built-in
//! standalone convenience path uses `RustCrypto`.

use alloc::{boxed::Box, vec::Vec};
use subtle::ConstantTimeEq;

/// Digest algorithms supported by `XMLDSig`.
///
/// SHA-1 is disabled for signing by default and requires explicit policy opt-in.
/// SHA-256 is the recommended default for new signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    /// MD5 compatibility capability; operation policy must explicitly permit it.
    #[cfg(feature = "legacy-algorithms")]
    Md5,
    /// RIPEMD-160 compatibility capability; operation policy must explicitly permit it.
    #[cfg(feature = "legacy-algorithms")]
    Ripemd160,
    /// SHA-1 (160-bit). Disabled for signing by default.
    Sha1,
    /// SHA-224 (224-bit), required by `XMLDSig` 1.1 interoperability profiles.
    Sha224,
    /// SHA-256 (256-bit). Default for SAML.
    Sha256,
    /// SHA-384 (384-bit).
    Sha384,
    /// SHA-512 (512-bit).
    Sha512,
    /// SHA3-224 (224-bit).
    Sha3_224,
    /// SHA3-256 (256-bit).
    Sha3_256,
    /// SHA3-384 (384-bit).
    Sha3_384,
    /// SHA3-512 (512-bit).
    Sha3_512,
    /// GOST 34.311-95 with the Ukrainian substitution table number one, the
    /// only one its URI can name; operation policy must explicitly permit it.
    #[cfg(feature = "dstu4145")]
    Gost34311,
    /// DSTU 7564 (Kupyna) with 256-bit output; operation policy must explicitly
    /// permit it.
    #[cfg(feature = "dstu4145")]
    Dstu7564_256,
}

impl DigestAlgorithm {
    /// Every compiled digest capability; this registry grants no policy permission.
    pub const ALL: [Self;
        9 + if cfg!(feature = "legacy-algorithms") {
            2
        } else {
            0
        } + if cfg!(feature = "dstu4145") { 2 } else { 0 }] = [
        #[cfg(feature = "legacy-algorithms")]
        Self::Md5,
        #[cfg(feature = "legacy-algorithms")]
        Self::Ripemd160,
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        #[cfg(feature = "dstu4145")]
        Self::Gost34311,
        #[cfg(feature = "dstu4145")]
        Self::Dstu7564_256,
    ];
    /// Parse a digest algorithm from its XML namespace URI.
    ///
    /// Returns `None` for unrecognized URIs.
    /// Recognition is capability, not permission: operation callers must check
    /// their compiled digest policy before hashing, including `X509Digest` selectors.
    ///
    /// # URIs
    ///
    /// | Algorithm | URI |
    /// |-----------|-----|
    /// | SHA-1 | `http://www.w3.org/2000/09/xmldsig#sha1` |
    /// | SHA-224 | `http://www.w3.org/2001/04/xmldsig-more#sha224` |
    /// | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
    /// | SHA-384 | `http://www.w3.org/2001/04/xmldsig-more#sha384` |
    /// | SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` |
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            // RFC 9231 §§2.1.1, 2.1.4 assign these exact digest identifiers.
            // https://www.rfc-editor.org/rfc/rfc9231#section-2.1
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmldsig-more#md5" => Some(Self::Md5),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#ripemd160" => Some(Self::Ripemd160),
            "http://www.w3.org/2000/09/xmldsig#sha1" => Some(Self::Sha1),
            "http://www.w3.org/2001/04/xmldsig-more#sha224" => Some(Self::Sha224),
            "http://www.w3.org/2001/04/xmlenc#sha256" => Some(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Some(Self::Sha512),
            // RFC 9231 section 2.1.5 fixes the SHA-3 namespace and digest widths:
            // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.1.5
            "http://www.w3.org/2007/05/xmldsig-more#sha3-224" => Some(Self::Sha3_224),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-256" => Some(Self::Sha3_256),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-384" => Some(Self::Sha3_384),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-512" => Some(Self::Sha3_512),
            // No registry assigns these. They are the identifiers of the test
            // signatures the Central Certification Authority of Ukraine publishes:
            // https://czo.gov.ua/testexamples
            #[cfg(feature = "dstu4145")]
            "http://www.w3.org/2001/04/xmlenc#gost34311" => Some(Self::Gost34311),
            #[cfg(feature = "dstu4145")]
            "http://www.w3.org/2001/04/xmlenc#dstu7564-256" => Some(Self::Dstu7564_256),
            _ => None,
        }
    }

    /// Return the XML namespace URI for this digest algorithm.
    #[must_use]
    pub fn uri(self) -> &'static str {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Md5 => "http://www.w3.org/2001/04/xmldsig-more#md5",
            #[cfg(feature = "legacy-algorithms")]
            Self::Ripemd160 => "http://www.w3.org/2001/04/xmlenc#ripemd160",
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha224 => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
            Self::Sha3_224 => "http://www.w3.org/2007/05/xmldsig-more#sha3-224",
            Self::Sha3_256 => "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
            Self::Sha3_384 => "http://www.w3.org/2007/05/xmldsig-more#sha3-384",
            Self::Sha3_512 => "http://www.w3.org/2007/05/xmldsig-more#sha3-512",
            #[cfg(feature = "dstu4145")]
            Self::Gost34311 => "http://www.w3.org/2001/04/xmlenc#gost34311",
            #[cfg(feature = "dstu4145")]
            Self::Dstu7564_256 => "http://www.w3.org/2001/04/xmlenc#dstu7564-256",
        }
    }

    /// Whether this algorithm is allowed for signing (not just verification).
    ///
    /// SHA-1 is deprecated and disabled by secure signing defaults. An explicit
    /// signing policy allowlist can enable it for a trusted compatibility boundary.
    #[must_use]
    pub fn signing_allowed(self) -> bool {
        !matches!(self, Self::Sha1) && !self.requires_explicit_permission()
    }

    /// Whether reference verification requires an explicit digest allowlist entry.
    #[must_use]
    pub const fn requires_explicit_permission(self) -> bool {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Md5 | Self::Ripemd160 => true,
            #[cfg(feature = "dstu4145")]
            Self::Gost34311 | Self::Dstu7564_256 => true,
            _ => false,
        }
    }

    /// The expected output length in bytes.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Md5 => 16,
            #[cfg(feature = "legacy-algorithms")]
            Self::Ripemd160 => 20,
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
            #[cfg(feature = "dstu4145")]
            Self::Gost34311 | Self::Dstu7564_256 => 32,
        }
    }
}

/// Compute the digest of `data` using the specified algorithm.
///
/// Returns the raw digest bytes (not base64-encoded).
///
/// # Panics
/// Panics if the built-in provider violates its advertised digest capability
/// or returns an output width inconsistent with the selected algorithm.
#[must_use]
pub fn compute_digest(algorithm: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    compute_digest_with_provider(
        crate::provider::default_provider(),
        algorithm,
        data,
        &digest_memory(),
    )
    .expect("default provider advertises every XMLDSig digest")
    .to_vec()
}

/// An account for digests without an operation account of their own. It has
/// no ceiling because one state lives per call or per Reference, whose number
/// policy bounds; an allocator refusal still comes back typed.
pub(crate) fn digest_memory() -> structured_asn1::memory::Memory {
    structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(usize::MAX, usize::MAX),
    ))
}

/// Compute a digest with an explicitly selected provider, under `memory`.
///
/// # Errors
/// Returns the provider's capability, update, or finalization error, a resource
/// refusal, or an error if the finalized digest has the wrong width for the
/// selected algorithm.
pub fn compute_digest_with_provider(
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DigestAlgorithm,
    data: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> Result<DigestOutput, crate::provider::ProviderError> {
    let mut state = begin_digest(provider, algorithm, memory)?;
    state.update(data)?;
    finish_digest(algorithm, &mut *state)
}

/// Start an incremental digest after checking the advertised capability.
pub(crate) fn begin_digest<'p>(
    provider: &'p dyn crate::provider::CryptoProvider,
    algorithm: DigestAlgorithm,
    memory: &structured_asn1::memory::Memory,
) -> Result<Box<dyn crate::provider::DigestState + 'p>, crate::provider::ProviderError> {
    provider.require_capability(crate::provider::ProviderCapability::Digest(algorithm))?;
    provider.begin_digest(algorithm, memory)
}

/// The longest digest any `XMLDSig` algorithm produces, in bytes.
pub const MAX_DIGEST_OUTPUT: usize = 64;

/// A finished digest, held inline.
#[derive(Debug, Clone, Copy)]
pub struct DigestOutput {
    bytes: [u8; MAX_DIGEST_OUTPUT],
    len: usize,
}

impl core::ops::Deref for DigestOutput {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for DigestOutput {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Finish an incremental digest. The facade, not an interchangeable provider,
/// owns the output width of each `XMLDSig` algorithm.
///
/// # Errors
/// Returns the provider's finalization failure or a wrong output width.
pub(crate) fn finish_digest(
    algorithm: DigestAlgorithm,
    state: &mut (dyn crate::provider::DigestState + '_),
) -> Result<DigestOutput, crate::provider::ProviderError> {
    let mut bytes = [0; MAX_DIGEST_OUTPUT];
    let len = state.finalize(&mut bytes)?;
    let expected = algorithm.output_len();
    if len != expected {
        return Err(crate::provider::ProviderError::InvalidOutputSize {
            operation: crate::provider::ProviderOperation::Digest,
            expected,
            actual: len,
        });
    }
    Ok(DigestOutput { bytes, len })
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if and only if `a` and `b` have equal length and identical
/// content. Execution time depends only on the length of the slices, not on
/// where they differ — preventing timing side-channel attacks on digest
/// comparison.
///
/// Uses `subtle` constant-time equality.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectingDigestProvider {
        output: Option<Vec<u8>>,
    }

    /// Returns caller-chosen bytes whatever it absorbed.
    struct FixedDigest(Vec<u8>);

    impl crate::provider::DigestState for FixedDigest {
        fn update(&mut self, _: &[u8]) -> Result<(), crate::provider::ProviderError> {
            Ok(())
        }
        fn finalize(
            &mut self,
            output: &mut [u8; super::MAX_DIGEST_OUTPUT],
        ) -> Result<usize, crate::provider::ProviderError> {
            output[..self.0.len()].copy_from_slice(&self.0);
            Ok(self.0.len())
        }
    }

    impl crate::provider::CryptoProvider for RejectingDigestProvider {
        fn name(&self) -> &'static str {
            "rejecting-digest"
        }

        fn supports(&self, capability: crate::provider::ProviderCapability<'_>) -> bool {
            if self.output.is_none()
                && matches!(capability, crate::provider::ProviderCapability::Digest(_))
            {
                return false;
            }
            crate::provider::default_provider().supports(capability)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
            crate::provider::default_provider().fill_random(output)
        }

        fn derive_key(
            &self,
            parameters: &crate::provider::KdfParameters<'_>,
            secret: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().derive_key(parameters, secret)
        }

        fn begin_digest(
            &self,
            _algorithm: DigestAlgorithm,
            _memory: &structured_asn1::memory::Memory,
        ) -> Result<Box<dyn crate::provider::DigestState + '_>, crate::provider::ProviderError>
        {
            if let Some(output) = &self.output {
                return Ok(Box::new(FixedDigest(output.clone())));
            }
            panic!("an unavailable digest capability must not be dispatched")
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
            key: &dyn crate::provider::KeyTransportKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &dyn crate::provider::KeyRecoveryKey,
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
                b"x",
                &digest_memory(),
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
                    &digest_memory(),
                ),
                Err(crate::provider::ProviderError::InvalidOutputSize {
                    operation: crate::provider::ProviderOperation::Digest,
                    expected: 32,
                    actual: output_len,
                }) if output_len == actual
            ));
        }

        assert_eq!(
            &*compute_digest_with_provider(
                &RejectingDigestProvider {
                    output: Some(vec![7_u8; 32]),
                },
                DigestAlgorithm::Sha256,
                b"x",
                &digest_memory(),
            )
            .expect("the width is right"),
            &[7_u8; 32],
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

    #[test]
    fn sha224_uri_round_trips_and_has_standard_width() {
        let algorithm = DigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#sha224")
            .expect("XMLDSig 1.1 SHA-224 must be recognized");

        assert_eq!(
            algorithm.uri(),
            "http://www.w3.org/2001/04/xmldsig-more#sha224"
        );
        assert_eq!(algorithm.output_len(), 28);
        assert!(algorithm.signing_allowed());
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
    fn sha224_empty() {
        let digest = compute_digest(
            DigestAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#sha224")
                .expect("SHA-224 URI must be recognized"),
            b"",
        );
        assert_eq!(
            hex(&digest),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
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
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        }
        out
    }
}
