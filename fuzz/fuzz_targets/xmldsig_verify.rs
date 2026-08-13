#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, SignatureAlgorithm, UriTypeSet, VerifyContext,
};

const TRUSTED_CERTIFICATE: &[u8] =
    include_bytes!("../../tests/fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-cert.der");

fn resolver() -> &'static DefaultKeyResolver {
    static RESOLVER: OnceLock<DefaultKeyResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![TRUSTED_CERTIFICATE.to_vec()],
            ..KeyResolverConfig::default()
        })
    })
}

fn policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::RsaSha1);
    policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    policy
}

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };

    // Match the upstream 1.3.13 verification harness: exercise parsing,
    // transforms, digesting, signature verification, and X.509 lookup while
    // keeping every reference and key retrieval strictly in-document.
    let _ = VerifyContext::new()
        .policy(policy())
        .key_resolver(resolver())
        .allowed_uri_types(UriTypeSet::SAME_DOCUMENT)
        .allowed_retrieval_method_uri_types(UriTypeSet::SAME_DOCUMENT)
        .verify(xml);
});
