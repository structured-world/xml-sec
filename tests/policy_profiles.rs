//! Profile compilation and real operation gates; fixtures are generated locally.
#![cfg(feature = "xmldsig")]

use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};
use xml_sec::XmlDocument;
use xml_sec::policy::{
    PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicySet, PolicyValidity,
    PolicyViolation, SignatureConstraints,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::{
    HmacSigningKey, HmacVerificationKey, SignContext, SignatureAlgorithm, VerificationRequest,
    VerifyContext,
};

fn context() -> PolicyCompileContext {
    PolicyCompileContext {
        external_resources: false,
        target_evidence: true,
    }
}
fn compiler(profile: PolicyProfile) -> PolicyCompiler<'static> {
    PolicyCompiler::new(profile, &RustCryptoProvider, None).unwrap()
}
fn grant() -> PolicyValidity {
    PolicyValidity {
        authorization_id: "test-grant".into(),
        authority: "caller".into(),
        reason: "local interoperability".into(),
        not_before: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::now() + Duration::from_secs(3600),
    }
}

#[test]
fn profiles_keep_parameterized_pss_permissions() {
    // An explicit preset allowlist must not erase its supported PSS family.
    use xml_sec::policy::RsaPssPermission;
    for (profile, permission) in [
        (PolicyProfile::Modern, RsaPssPermission::SecureSupported),
        (
            PolicyProfile::XmlSecCompatible,
            RsaPssPermission::AllSupported,
        ),
    ] {
        let compiled = compiler(profile).compile(&context()).unwrap();
        assert_eq!(
            compiled.verification().unwrap().parameterized_rsa_pss,
            permission
        );
        assert_eq!(
            compiled
                .verification()
                .unwrap()
                .key_trust
                .parameterized_rsa_pss,
            permission
        );
        assert_eq!(
            compiled.signing().unwrap().parameterized_rsa_pss,
            RsaPssPermission::SecureSupported
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn compiler_checks_every_permitted_oaep_tuple() {
    // Capabilities can differ by digest/MGF even when content ciphers work.
    use xml_sec::provider::{CryptoProvider, ProviderCapability};
    use xml_sec::xmlenc::OaepDigestAlgorithm;
    struct Restricted;
    impl CryptoProvider for Restricted {
        fn name(&self) -> &'static str {
            "restricted-test"
        }
        fn fill_random(&self, _: &mut [u8]) -> Result<(), xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn digest(
            &self,
            _: xml_sec::xmldsig::DigestAlgorithm,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn sign(
            &self,
            _: &dyn xml_sec::xmldsig::SigningKey,
            _: SignatureAlgorithm,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
            panic!("compile must not execute crypto")
        }
        fn verify(
            &self,
            _: &dyn xml_sec::xmldsig::VerifyingKey,
            _: SignatureAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<bool, xml_sec::xmldsig::DsigError> {
            panic!("compile must not execute crypto")
        }
        fn encrypt_data(
            &self,
            _: xml_sec::xmlenc::DataEncryptionAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn decrypt_data(
            &self,
            _: xml_sec::xmlenc::DataEncryptionAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn wrap_key(
            &self,
            _: xml_sec::xmlenc::KeyWrapAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn unwrap_key(
            &self,
            _: xml_sec::xmlenc::KeyWrapAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn transport_key(
            &self,
            _: &dyn xml_sec::provider::KeyTransportKey,
            _: &xml_sec::xmlenc::RsaOaepParameters,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn recover_key(
            &self,
            _: &dyn xml_sec::provider::KeyRecoveryKey,
            _: &xml_sec::xmlenc::RsaOaepParameters,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn derive_key(
            &self,
            _: &xml_sec::provider::KdfParameters<'_>,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
            panic!("compile must not execute crypto")
        }
        fn supports(&self, capability: ProviderCapability<'_>) -> bool {
            match capability {
                ProviderCapability::KeyTransport(p) | ProviderCapability::KeyRecovery(p)
                    if p.mgf_digest == OaepDigestAlgorithm::Sha384 =>
                {
                    false
                }
                _ => RustCryptoProvider.supports(capability),
            }
        }
    }
    // Preset filtering and final capability checks must use the same engine.
    assert!(matches!(
        PolicyCompiler::new(PolicyProfile::Modern, &Restricted, None)
            .unwrap()
            .compile(&context()),
        Err(PolicyViolation::Configuration { .. })
    ));
    let initial = PolicyCompiler::new(PolicyProfile::Modern, &Restricted, None).unwrap();
    let mut recovery_only = initial.policies().clone();
    recovery_only.encryption = None;
    assert!(matches!(
        initial
            .restrict(&recovery_only)
            .unwrap()
            .compile(&context()),
        Err(PolicyViolation::Configuration { .. })
    ));
}

#[cfg(feature = "xmlenc")]
#[test]
fn permitted_oaep_method_requires_a_usable_parameter_tuple() {
    // An empty digest set cannot silently leave a permitted transport unusable.
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    layer.encryption.as_mut().unwrap().oaep_digests = Some(HashSet::new());
    assert!(matches!(
        initial.restrict(&layer).unwrap().compile(&context()),
        Err(PolicyViolation::Configuration { .. })
    ));
}
fn template(namespace: &str, id: &str) -> String {
    format!(
        r##"<Assertion xmlns="{namespace}" ID="{id}"><payload>protected</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></Assertion>"##
    )
}

#[test]
fn all_named_profiles_compile_and_legacy_requires_auditable_expiry() {
    // Presets must be usable, while compatibility exceptions cannot be immortal.
    for profile in [
        PolicyProfile::XmlSecCompatible,
        PolicyProfile::Modern,
        PolicyProfile::SecureSaml,
        PolicyProfile::WsSecurity,
        PolicyProfile::Xades,
    ] {
        let compiled = compiler(profile).compile(&context()).unwrap();
        assert_eq!(compiled.profile(), profile);
        assert!(compiled.verification().is_some());
        assert!(compiled.signing().is_some());
    }
    assert!(PolicyCompiler::new(PolicyProfile::LegacyVerify, &RustCryptoProvider, None).is_err());
    let compiled = PolicyCompiler::new(
        PolicyProfile::LegacyVerify,
        &RustCryptoProvider,
        Some(grant()),
    )
    .unwrap()
    .compile(&context())
    .unwrap();
    assert!(compiled.signing().is_none());
    assert!(compiled.verification().unwrap().validity.is_some());
    #[cfg(feature = "xmlenc")]
    assert!(compiled.encryption().is_none() && compiled.decryption().is_none());
}

#[test]
fn layers_intersect_permissions_minima_and_resource_caps() {
    // An application cannot widen the inherited system policy even by naming
    // a legacy algorithm or raising its resource limit.
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    let policy = layer.verification.as_mut().unwrap();
    policy.signature_algorithms = Some(HashSet::from([
        SignatureAlgorithm::HmacSha256,
        SignatureAlgorithm::HmacSha1,
    ]));
    policy.parameterized_rsa_pss = xml_sec::policy::RsaPssPermission::ExactOnly;
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::HmacSha1);
    policy.hmac.minimum_key_bits = 512;
    policy.resources.max_references = 2;
    policy.resources.max_external_resource_bytes *= 2;
    let original_external = initial
        .policies()
        .verification
        .as_ref()
        .unwrap()
        .resources
        .max_external_resource_bytes;
    let compiled = initial
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
    let policy = compiled.verification().unwrap();
    assert_eq!(
        policy.signature_algorithms.as_ref().unwrap(),
        &HashSet::from([SignatureAlgorithm::HmacSha256])
    );
    assert_eq!(policy.hmac.minimum_key_bits, 512);
    assert_eq!(policy.resources.max_references, 2);
    assert_eq!(
        policy.resources.max_external_resource_bytes,
        original_external
    );
}

#[test]
fn disabled_operations_cannot_be_reenabled_by_ordinary_layers() {
    // None is a disabled operation, not an inheritance or permissive sentinel.
    let initial = compiler(PolicyProfile::Modern);
    let mut disabled = initial.policies().clone();
    disabled.signing = None;
    let permissive = initial.policies().clone();
    let compiled = initial
        .restrict(&disabled)
        .unwrap()
        .restrict(&permissive)
        .unwrap()
        .compile(&context())
        .unwrap();
    assert!(compiled.signing().is_none());
}

#[test]
fn compiler_rejects_impossible_hmac_and_missing_request_contracts() {
    // Contradictions are detected without parsing or executing an operation.
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    let policy = layer.verification.as_mut().unwrap();
    policy.signature_algorithms = Some(HashSet::from([SignatureAlgorithm::HmacSha256]));
    policy.hmac.minimum_output_bits = 512;
    assert!(
        initial
            .restrict(&layer)
            .unwrap()
            .compile(&context())
            .is_err()
    );
    let mut no_targets = context();
    no_targets.target_evidence = false;
    assert!(
        compiler(PolicyProfile::SecureSaml)
            .compile(&no_targets)
            .is_err()
    );
    let mut all_external = compiler(PolicyProfile::Modern).policies().clone();
    all_external.verification.as_mut().unwrap().uris.references = xml_sec::xmldsig::UriTypeSet::ALL;
    assert!(
        compiler(PolicyProfile::Modern)
            .authorize_replacement(all_external, grant())
            .unwrap()
            .compile(&context())
            .is_err()
    );
}

#[test]
fn relaxation_requires_valid_grant_and_preserves_earlier_expiration() {
    // A trusted explicit grant can relax; ordinary composition cannot. Its
    // exclusive expiration remains enforced on the cached operation snapshot.
    let earlier = grant();
    let initial = PolicyCompiler::new(
        PolicyProfile::Modern,
        &RustCryptoProvider,
        Some(earlier.clone()),
    )
    .unwrap();
    let mut restricted = initial.policies().clone();
    restricted
        .verification
        .as_mut()
        .unwrap()
        .resources
        .max_references = 2;
    let initial = initial.restrict(&restricted).unwrap();
    let mut replacement = initial.policies().clone();
    replacement
        .verification
        .as_mut()
        .unwrap()
        .resources
        .max_references = 32;
    let mut later = earlier.clone();
    later.expires_at += Duration::from_secs(3600);
    let compiled = initial
        .authorize_replacement(replacement, later)
        .unwrap()
        .compile(&context())
        .unwrap();
    let policy = compiled.verification().unwrap();
    assert_eq!(policy.resources.max_references, 32);
    assert_eq!(
        policy.validity.as_ref().unwrap().expires_at,
        earlier.expires_at
    );
    assert!(matches!(
        earlier.validate_at(earlier.expires_at),
        Err(PolicyViolation::AuthorizationExpired)
    ));
    let mut expired = policy.clone();
    expired.validity.as_mut().unwrap().expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    assert!(
        VerifyContext::new()
            .policy(expired)
            .verify("not XML")
            .is_err()
    );
}

#[test]
fn saml_profile_signs_and_authenticates_explicit_parent_target() {
    // This exercises the public signing + evidence path, not just profile data.
    let compiled = compiler(PolicyProfile::SecureSaml)
        .compile(&context())
        .unwrap();
    let secret = vec![0x53; 32];
    let signer = HmacSigningKey::new(secret.clone()).unwrap();
    let verifier = HmacVerificationKey::new(secret).unwrap();
    let xml = SignContext::new(&signer)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&template(
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "assertion",
        ))
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let targets = document.with_view(|view| [view.root_element()]);
    let context = VerifyContext::new()
        .key(&verifier)
        .policy(compiled.verification().unwrap().clone());
    let evidence = context
        .verify_request(
            &document,
            &VerificationRequest {
                expected_targets: &targets,
                ..VerificationRequest::default()
            },
        )
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    assert!(
        context
            .verify_request(&document, &VerificationRequest::default())
            .is_err()
    );
    assert!(context.verify_document(&document).is_err());
    let wrong = template("urn:wrong", "assertion");
    let error = SignContext::new(&signer)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&wrong)
        .unwrap_err();
    // Untrusted profile input is not a trusted-policy compilation defect.
    assert!(matches!(
        error,
        xml_sec::xmldsig::SigningError::Policy(PolicyViolation::SignatureProfile {
            profile: SignatureConstraints::Saml,
            ..
        })
    ));
}

#[test]
fn incompatible_protocols_and_interpretation_models_reject_composition() {
    // Restriction cannot silently change which document bytes an ID names.
    let saml = compiler(PolicyProfile::SecureSaml);
    let xades = compiler(PolicyProfile::Xades);
    assert!(saml.restrict(xades.policies()).is_err());
    let modern = compiler(PolicyProfile::Modern);
    let compatibility = compiler(PolicyProfile::XmlSecCompatible);
    assert!(modern.restrict(compatibility.policies()).is_err());
    assert_eq!(
        xades
            .policies()
            .verification
            .as_ref()
            .unwrap()
            .signature_constraints,
        SignatureConstraints::Xades
    );
    let _disabled = PolicySet::default();
}
