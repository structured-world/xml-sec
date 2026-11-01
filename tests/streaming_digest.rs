#![cfg(feature = "xmldsig-sign")]
//! Incremental digests at the provider boundary and in Reference processing.

#[path = "support/refusing_state.rs"]
mod refusing_state;

use refusing_state::RefusingStateProvider;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::provider::{
    CryptoProvider, DigestState, ExternalProviderError, KdfParameters, ProviderCapability,
    ProviderError, RustCryptoProvider,
};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigError, MAX_DIGEST_OUTPUT, ReferenceBuilder, ReferenceProcessingError,
    RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder, SigningDigestError,
    SigningError, SigningKey, VerificationKey, VerifyContext,
};

fn providers() -> Vec<&'static dyn CryptoProvider> {
    vec![
        &RustCryptoProvider,
        #[cfg(feature = "aws-lc-fips")]
        &xml_sec::provider::AwsLcFipsProvider,
    ]
}

fn streamed(
    provider: &dyn CryptoProvider,
    algorithm: DigestAlgorithm,
    data: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut state = provider
        .begin_digest(algorithm, &memory())
        .expect("advertised digest starts");
    for part in data.chunks(chunk) {
        state.update(part).expect("digest absorbs input");
        state.update(&[]).expect("an empty update is a no-op");
    }
    let mut output = [0; MAX_DIGEST_OUTPUT];
    let written = state.finalize(&mut output).expect("digest finishes");
    output[..written].to_vec()
}

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)))
}

#[test]
fn streamed_digests_equal_one_shot_digests_for_every_algorithm_and_chunking() {
    // Chunk boundaries come from the serializer, not the algorithm's block
    // size; every split must produce the same digest as one contiguous input.
    let data = (0..=255_u8).cycle().take(4_099).collect::<Vec<_>>();
    for provider in providers() {
        for algorithm in DigestAlgorithm::ALL {
            if !provider.supports(ProviderCapability::Digest(algorithm)) {
                continue;
            }
            let whole = provider
                .digest(algorithm, &data, &memory())
                .expect("advertised digest");
            assert_eq!(whole.len(), algorithm.output_len(), "{algorithm:?}");
            for chunk in [1, 7, 64, 1_000, data.len()] {
                assert_eq!(
                    streamed(provider, algorithm, &data, chunk),
                    &*whole,
                    "{} {algorithm:?} in {chunk}-byte chunks",
                    provider.name()
                );
            }
        }
    }
    // Known answer: SHA-256("abc"), FIPS 180-4 Appendix B.1.
    assert_eq!(
        streamed(&RustCryptoProvider, DigestAlgorithm::Sha256, b"abc", 1),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn every_provider_charges_its_state_and_releases_it() {
    // State creation is refused, not panicked on, and a live state is paid for
    // until it is dropped, whatever the backend.
    for provider in providers() {
        let empty = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert_eq!(
            provider.begin_digest(DigestAlgorithm::Sha256, &empty).err(),
            Some(ProviderError::Resource(MemoryError::LimitExceeded)),
            "{}",
            provider.name()
        );
        assert_eq!(
            provider
                .digest(DigestAlgorithm::Sha256, b"abc", &empty)
                .err(),
            Some(ProviderError::Resource(MemoryError::LimitExceeded))
        );
        let account = memory();
        let state = provider
            .begin_digest(DigestAlgorithm::Sha256, &account)
            .expect("admitted");
        assert!(account.used() > 0);
        drop(state);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn a_storage_refusal_stays_typed_and_terminal() {
    // Not unsupported, not a digest mismatch, not a per-Reference finding with
    // more work after it: the operation ends with the resource cause.
    let key = signing_key();
    let signed = SignContext::new(&key)
        .sign_template(&template())
        .expect("signing with the default provider");
    let provider = RefusingStateProvider::after(0);
    let error = VerifyContext::new()
        .key(&verification_key(&key))
        .provider(&provider)
        .verify(&signed)
        .expect_err("verification cannot pass without a digest");
    assert!(
        matches!(
            error,
            DsigError::Reference(ReferenceProcessingError::Provider(ProviderError::Resource(
                MemoryError::OutOfMemory
            )))
        ),
        "{error:?}"
    );
    let error = SignContext::new(&key)
        .provider(&provider)
        .sign_template(&template())
        .expect_err("signing cannot pass without a digest");
    assert!(
        matches!(
            error,
            SigningError::Digest(SigningDigestError::Provider(ProviderError::Resource(
                MemoryError::OutOfMemory
            )))
        ),
        "{error:?}"
    );
    assert_eq!(provider.finalized(), 0);
}

#[test]
fn a_storage_refusal_in_a_manifest_reference_ends_the_operation() {
    // SignedInfo passes; the Manifest Reference then cannot start its digest. A
    // spent ceiling must not read as an invalid Reference with more work after it.
    let template = r##"<root><payload Id="payload">manifest payload</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#manifest"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="manifest"><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>stale</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##;
    let key = signing_key();
    let signed = SignContext::new(&key)
        .policy(xml_sec::policy::SigningPolicy {
            manifest_processing: xml_sec::policy::ManifestProcessing::Process,
            ..xml_sec::policy::SigningPolicy::default()
        })
        .sign_template(template)
        .expect("signing with the default provider");
    let public = verification_key(&key);
    let verify = |provider: &RefusingStateProvider| {
        VerifyContext::new()
            .key(&public)
            .provider(provider)
            .process_manifests(true)
            .verify(&signed)
    };
    let admitted = verify(&RefusingStateProvider::after(2)).expect("both digests fit");
    assert_eq!(admitted.manifest_references.len(), 1);
    let error =
        verify(&RefusingStateProvider::after(1)).expect_err("the Manifest digest cannot start");
    assert!(
        matches!(
            error,
            DsigError::Reference(ReferenceProcessingError::Provider(ProviderError::Resource(
                MemoryError::OutOfMemory
            )))
        ),
        "{error:?}"
    );
}

/// Counts updates and refuses after `remaining` of them, as a token or HSM may.
struct FailingDigest<'a> {
    remaining: usize,
    calls: &'a std::sync::atomic::AtomicUsize,
    inner: Box<dyn DigestState>,
}

impl DigestState for FailingDigest<'_> {
    fn update(&mut self, data: &[u8]) -> Result<(), ProviderError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Err(ProviderError::External(ExternalProviderError::Operation));
        };
        self.remaining = remaining;
        self.inner.update(data)
    }
    fn finalize(&mut self, output: &mut [u8; MAX_DIGEST_OUTPUT]) -> Result<usize, ProviderError> {
        self.inner.finalize(output)
    }
}

struct FailingDigestProvider {
    updates: usize,
    calls: std::sync::atomic::AtomicUsize,
}

impl FailingDigestProvider {
    fn refusing_after(updates: usize) -> Self {
        Self {
            updates,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl CryptoProvider for FailingDigestProvider {
    fn name(&self) -> &'static str {
        "failing-digest"
    }
    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        RustCryptoProvider.supports(capability)
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        RustCryptoProvider.fill_random(output)
    }
    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.derive_key(parameters, secret)
    }
    fn begin_digest(
        &self,
        algorithm: DigestAlgorithm,
        memory: &Memory,
    ) -> Result<Box<dyn DigestState + '_>, ProviderError> {
        Ok(Box::new(FailingDigest {
            remaining: self.updates,
            calls: &self.calls,
            inner: xml_sec::provider::default_provider().begin_digest(algorithm, memory)?,
        }))
    }
    fn sign(
        &self,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
        RustCryptoProvider.sign(key, algorithm, data)
    }
    fn verify(
        &self,
        key: &dyn xml_sec::xmldsig::VerifyingKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        RustCryptoProvider.verify(key, algorithm, data, signature)
    }
    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.encrypt_data(algorithm, key, plaintext)
    }
    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.decrypt_data(algorithm, key, ciphertext)
    }
    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.wrap_key(algorithm, kek, key)
    }
    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.unwrap_key(algorithm, kek, wrapped)
    }
    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn xml_sec::provider::KeyTransportKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.transport_key(key, parameters, plaintext)
    }
    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn xml_sec::provider::KeyRecoveryKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.recover_key(key, parameters, ciphertext)
    }
}

fn signing_key() -> RsaSigningKey {
    RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem"))
        .expect("test key")
}

/// A `#payload` Reference over enough text for many serializer chunks.
fn template() -> String {
    let payload = "<v>streamed digest input</v>".repeat(4_096);
    let signature = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"))
    .build_template()
    .expect("template");
    format!("<Envelope><Payload Id=\"payload\">{payload}</Payload>{signature}</Envelope>")
}

fn verification_key(key: &RsaSigningKey) -> VerificationKey {
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: key
            .public_key_info()
            .expect("public metadata")
            .spki_der()
            .expect("SPKI")
            .to_vec(),
        certificate_der: None,
        name: None,
    }
}

#[test]
fn a_provider_refusal_mid_stream_keeps_its_typed_cause() {
    // The serializer only observes an I/O stop; the original provider error
    // must still reach the caller, on the first chunk and after several.
    let key = signing_key();
    let signed = SignContext::new(&key)
        .sign_template(&template())
        .expect("signing with the default provider");
    let public = verification_key(&key);
    for updates in [0, 3] {
        let provider = FailingDigestProvider::refusing_after(updates);
        let error = VerifyContext::new()
            .key(&public)
            .provider(&provider)
            .verify(&signed)
            .expect_err("the digest refusal stops verification");
        assert!(
            matches!(
                error,
                DsigError::Reference(ReferenceProcessingError::Provider(ProviderError::External(
                    ExternalProviderError::Operation
                )))
            ),
            "verification after {updates} updates: {error:?}"
        );
        let error = SignContext::new(&key)
            .provider(&provider)
            .sign_template(&template())
            .expect_err("the digest refusal stops signing");
        assert!(
            matches!(
                error,
                SigningError::Digest(SigningDigestError::Provider(ProviderError::External(
                    ExternalProviderError::Operation
                )))
            ),
            "signing after {updates} updates: {error:?}"
        );
    }
}

#[test]
fn token_sized_serializer_writes_reach_the_provider_in_blocks() {
    // Eight escaped attributes per element arrive as many short writes; the
    // provider must see whole blocks, not one update per serializer token.
    let elements =
        "<v a=\"1\" b=\"value\" c=\"&amp;&quot;\" d=\"4\" e=\"5\" f=\"6\" g=\"7\" h=\"8\"/>"
            .repeat(1_024);
    let signature = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"))
    .build_template()
    .expect("template");
    let template =
        format!("<Envelope><Payload Id=\"payload\">{elements}</Payload>{signature}</Envelope>");
    let key = signing_key();
    let provider = FailingDigestProvider::refusing_after(usize::MAX);
    let signed = SignContext::new(&key)
        .provider(&provider)
        .sign_template(&template)
        .expect("signing");
    assert!(signed.contains("<SignatureValue>"));
    // About 75 KB of canonical output is under 20 blocks of 4 KiB, plus the
    // one-shot SignedInfo hash; per-write updates would number in the
    // thousands (at least one per attribute).
    let calls = provider.calls.load(std::sync::atomic::Ordering::Relaxed);
    assert!(calls < 64, "{calls} provider updates for 8,192 attributes");
}

#[test]
fn streamed_reference_digests_round_trip_through_sign_and_verify() {
    // The streamed signing digest is the one verification streams again.
    let key = signing_key();
    let signed = SignContext::new(&key)
        .sign_template(&template())
        .expect("signing");
    let result = VerifyContext::new()
        .key(&verification_key(&key))
        .verify(&signed)
        .expect("verification");
    assert_eq!(
        result.status,
        xml_sec::xmldsig::DsigStatus::Valid,
        "{result:?}"
    );
}

#[test]
fn canonical_output_limit_stops_the_streamed_digest() {
    // The output ceiling is enforced while bytes stream into the digest, with
    // the same typed resource refusal as when they were collected.
    let key = signing_key();
    let signed = SignContext::new(&key)
        .sign_template(&template())
        .expect("signing");
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.resources.max_canonicalized_bytes = 1_024;
    let error = VerifyContext::new()
        .key(&verification_key(&key))
        .policy(policy)
        .verify(&signed)
        .expect_err("the canonical output exceeds the policy");
    assert!(
        // Refused one byte past the ceiling, not after the whole output.
        matches!(
            &error,
            DsigError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "canonicalized bytes",
                maximum: 1_024,
                actual: 1_025,
            })
        ),
        "{error:?}"
    );
}
