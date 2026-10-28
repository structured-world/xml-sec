//! Profile compilation and real operation gates; fixtures are generated locally.
#![cfg(feature = "xmldsig-sign")]

use std::{collections::BTreeSet, time::SystemTime};
use xml_sec::XmlDocument;
use xml_sec::policy::{
    Instant, PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicySet, PolicyValidity,
    PolicyViolation, SignatureConstraints, instant_from_system_time,
};
use xml_sec::provider::RustCryptoProvider;
#[cfg(feature = "xmlenc")]
use xml_sec::provider::{CryptoProvider, ProviderCapability};
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
        not_before: Instant::new(0, 0).unwrap(),
        expires_at: seconds_later(instant_from_system_time(SystemTime::now()).unwrap(), 3600),
    }
}

/// `time` moved forward by whole `seconds`.
fn seconds_later(time: Instant, seconds: i64) -> Instant {
    Instant::new(time.seconds() + seconds, time.nanos()).unwrap()
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
struct ProfileTestProvider {
    inbound_only: bool,
}

#[cfg(feature = "xmlenc")]
impl CryptoProvider for ProfileTestProvider {
    fn name(&self) -> &'static str {
        "restricted-test"
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), xml_sec::provider::ProviderError> {
        panic!("compile must not execute crypto")
    }
    fn begin_digest(
        &self,
        _: xml_sec::xmldsig::DigestAlgorithm,
    ) -> Result<Box<dyn xml_sec::provider::DigestState + '_>, xml_sec::provider::ProviderError>
    {
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
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, xml_sec::provider::ProviderError> {
        assert!(self.inbound_only, "compile must not execute crypto");
        self.require_capability(ProviderCapability::Decrypt(algorithm))?;
        RustCryptoProvider.decrypt_data(algorithm, key, bytes)
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
        if matches!(capability, ProviderCapability::VerifyCertificate(_)) {
            return false;
        }
        if self.inbound_only {
            match capability {
                ProviderCapability::Encrypt(_)
                | ProviderCapability::KeyWrap(_)
                | ProviderCapability::KeyTransport(_) => return false,
                ProviderCapability::Decrypt(algorithm) => {
                    return algorithm == xml_sec::xmlenc::DataEncryptionAlgorithm::Aes128Gcm;
                }
                ProviderCapability::KeyUnwrap(algorithm) => {
                    return algorithm == xml_sec::xmlenc::KeyWrapAlgorithm::AesKw128;
                }
                _ => return RustCryptoProvider.supports(capability),
            }
        }
        match capability {
            ProviderCapability::KeyTransport(p) | ProviderCapability::KeyRecovery(p)
                if p.mgf_digest == xml_sec::xmlenc::OaepDigestAlgorithm::Sha384 =>
            {
                false
            }
            _ => RustCryptoProvider.supports(capability),
        }
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn compiler_rejects_unavailable_certificate_allowlist() {
    // An XML-capable provider need not implement certificate verification.
    // Reject this contradiction at compile time, before any provider work.
    let provider = ProfileTestProvider { inbound_only: true };
    let initial = PolicyCompiler::new(PolicyProfile::Modern, &provider, None).unwrap();
    let mut layer = initial.policies().clone();
    layer.signing = None;
    layer.encryption = None;
    let trust = &mut layer.verification.as_mut().unwrap().key_trust;
    trust.verify_x509_chains = true;
    trust.certificate_signature_algorithms =
        Some(xml_sec::policy::CertificateSignatureAlgorithms::Allowlist(
            BTreeSet::from([xml_sec::provider::X509SignatureAlgorithm::RsaPkcs1v15(
                xml_sec::xmldsig::DigestAlgorithm::Sha256,
            )]),
        ));
    assert!(matches!(
        initial.restrict(&layer).unwrap().compile(&context()),
        Err(PolicyViolation::Configuration { .. })
    ));
}

#[test]
fn denying_certificate_signatures_keeps_trusted_preset_keys_usable() {
    // Chain checking governs certificate-backed resolution, not preset keys.
    // Denying certificate signatures must not disable a trusted HMAC request.
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    let trust = &mut layer.verification.as_mut().unwrap().key_trust;
    trust.verify_x509_chains = true;
    trust.certificate_signature_algorithms = Some(
        xml_sec::policy::CertificateSignatureAlgorithms::Allowlist(BTreeSet::new()),
    );
    let compiled = initial
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let xml = SignContext::new(&key)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&template("urn:test", "root"))
        .unwrap();
    let result = VerifyContext::new()
        .key(&verifier)
        .policy(compiled.verification().unwrap().clone())
        .verify(&xml)
        .unwrap();
    assert_eq!(result.status, xml_sec::xmldsig::DsigStatus::Valid);
}

#[cfg(feature = "xmlenc")]
#[test]
fn compiler_checks_every_permitted_oaep_tuple() {
    // Capabilities can differ by digest/MGF even when content ciphers work.
    let restricted = ProfileTestProvider {
        inbound_only: false,
    };
    // Preset filtering and final capability checks must use the same engine.
    assert!(matches!(
        PolicyCompiler::new(PolicyProfile::Modern, &restricted, None)
            .unwrap()
            .compile(&context()),
        Err(PolicyViolation::Configuration { .. })
    ));
    let initial = PolicyCompiler::new(PolicyProfile::Modern, &restricted, None).unwrap();
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
fn decryption_profile_uses_only_inbound_provider_capabilities() {
    // Disabling outbound work must leave an inbound-only provider usable,
    // including the retained cipher/unwrap permissions and public operation.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, EncryptedDataBuilder, KeyWrapAlgorithm,
        SymmetricKeyDecryptor,
    };
    let provider = ProfileTestProvider { inbound_only: true };
    for profile in [PolicyProfile::Modern, PolicyProfile::XmlSecCompatible] {
        let initial = PolicyCompiler::new(profile, &provider, None).unwrap();
        let mut layer = initial.policies().clone();
        layer.encryption = None;
        let compiled = initial
            .restrict(&layer)
            .unwrap()
            .compile(&context())
            .unwrap();
        let policy = compiled.decryption().unwrap();
        assert_eq!(
            policy.data_algorithms.as_ref().unwrap(),
            &BTreeSet::from([DataEncryptionAlgorithm::Aes128Gcm])
        );
        assert_eq!(
            policy.key_wrap_algorithms.as_ref().unwrap(),
            &BTreeSet::from([KeyWrapAlgorithm::AesKw128])
        );
        let key = [0x31; 16];
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(key)
            .encrypt_binary(b"inbound-only")
            .unwrap();
        let resolver = SymmetricKeyDecryptor::new(key);
        let decrypted = DecryptContext::new(&resolver)
            .provider(&provider)
            .policy(policy.clone())
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap();
        assert_eq!(
            decrypted,
            xml_sec::xmlenc::DecryptedContent::Bytes(b"inbound-only".to_vec())
        );
    }
}

/// Content encrypted with `algorithm` under a policy admitting only it
/// decrypts under the compiled `inbound` policy.
#[cfg(feature = "xmlenc")]
fn assert_inbound_round_trip(
    algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
    inbound: &xml_sec::policy::DecryptionPolicy,
) {
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm as Data, DecryptContext, EncryptedDataBuilder,
        SymmetricKeyDecryptor,
    };
    let key = vec![0x31; algorithm.key_len()];
    let mut builder = EncryptedDataBuilder::new(algorithm)
        .direct_key(key.as_slice())
        .policy(EncryptionPolicy {
            data_algorithms: Some(BTreeSet::from([algorithm])),
            ..Default::default()
        });
    if matches!(algorithm, Data::ChaCha20 | Data::ChaCha20Poly1305) {
        builder = builder.chacha_parameters(xml_sec::xmlenc::ChaChaParameters {
            counter: if algorithm == Data::ChaCha20 {
                Some([0; 4])
            } else {
                None
            },
            ..Default::default()
        });
    }
    let encrypted = builder.encrypt_binary(b"compatibility profile").unwrap();
    let resolver = SymmetricKeyDecryptor::with_kind(key, algorithm.key_kind());
    let result = DecryptContext::new(&resolver)
        .policy(inbound.clone())
        .decrypt(&encrypted.encrypted_data_xml)
        .unwrap();
    assert_eq!(
        result,
        xml_sec::xmlenc::DecryptedContent::Bytes(b"compatibility profile".to_vec())
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn compatibility_decryption_permissions_are_explicit_and_operation_local() {
    // A named compatibility profile grants compiled inbound mechanisms, not
    // implicit defaults, and never relaxes the modern outbound profile.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm as Data, KeyTransportAlgorithm as Transport,
        KeyWrapAlgorithm as Wrap,
    };
    let compiled = compiler(PolicyProfile::XmlSecCompatible)
        .compile(&context())
        .unwrap();
    let inbound = compiled.decryption().unwrap();
    let outbound = compiled.encryption().unwrap();
    let ciphers = [
        Data::Aes128Cbc,
        Data::Camellia128Cbc,
        Data::ChaCha20,
        Data::ChaCha20Poly1305,
        #[cfg(feature = "legacy-algorithms")]
        Data::TripleDesCbc,
        #[cfg(feature = "legacy-algorithms")]
        Data::Aes192Cbc,
        #[cfg(feature = "legacy-algorithms")]
        Data::Aes192Gcm,
    ];
    let wraps = [
        Wrap::CamelliaKw128,
        Wrap::Cbc(Data::Aes128Cbc),
        #[cfg(feature = "legacy-algorithms")]
        Wrap::TripleDes,
        #[cfg(feature = "legacy-algorithms")]
        Wrap::AesKw192,
    ];
    let transports = [
        Transport::RsaOaepMgf1p,
        Transport::RsaOaep11,
        #[cfg(feature = "legacy-algorithms")]
        Transport::RsaPkcs1v15,
    ];
    for algorithm in ciphers {
        assert!(
            inbound
                .data_algorithms
                .as_ref()
                .unwrap()
                .contains(&algorithm)
        );
        if algorithm != Data::ChaCha20Poly1305 {
            assert!(
                !outbound
                    .data_algorithms
                    .as_ref()
                    .unwrap()
                    .contains(&algorithm)
            );
        }
        assert_inbound_round_trip(algorithm, inbound);
    }
    for algorithm in wraps {
        assert!(
            inbound
                .key_wrap_algorithms
                .as_ref()
                .unwrap()
                .contains(&algorithm)
        );
        assert!(
            !outbound
                .key_wrap_algorithms
                .as_ref()
                .unwrap()
                .contains(&algorithm)
        );
    }
    for algorithm in transports {
        assert!(
            inbound
                .key_transport_algorithms
                .as_ref()
                .unwrap()
                .contains(&algorithm)
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn permitted_oaep_method_requires_a_usable_parameter_tuple() {
    // An empty digest set cannot silently leave a permitted transport unusable.
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    layer.encryption.as_mut().unwrap().oaep_digests = Some(BTreeSet::new());
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
        // Only the libxmlsec1-compatible profile reads stylesheets as libxmlsec1 does,
        // for both directions so its signatures match the donor's digests.
        let expected = if profile == PolicyProfile::XmlSecCompatible {
            xml_sec::policy::XsltStylesheetSemantics::Libxmlsec1
        } else {
            xml_sec::policy::XsltStylesheetSemantics::Specification
        };
        assert_eq!(
            compiled
                .verification()
                .unwrap()
                .transforms
                .xslt_stylesheet_semantics,
            expected,
            "{profile:?}"
        );
        assert_eq!(
            compiled
                .signing()
                .unwrap()
                .transforms
                .xslt_stylesheet_semantics,
            expected,
            "{profile:?}"
        );
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
    policy.signature_algorithms = Some(BTreeSet::from([
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
        &BTreeSet::from([SignatureAlgorithm::HmacSha256])
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
    policy.signature_algorithms = Some(BTreeSet::from([SignatureAlgorithm::HmacSha256]));
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
            .authorize_replacement(all_external, &grant())
            .unwrap()
            .compile(&context())
            .is_err()
    );
}

#[test]
fn compiler_requires_a_usable_canonicalization_method() {
    // Reference-only transforms cannot canonicalize SignedInfo. Empty and
    // unknown URI sets must fail compilation for either enabled operation.
    for signing in [false, true] {
        for methods in [
            BTreeSet::new(),
            BTreeSet::from([
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_owned(),
                "urn:unknown:c14n".to_owned(),
            ]),
        ] {
            let initial = compiler(PolicyProfile::Modern);
            let mut layer = initial.policies().clone();
            if signing {
                layer.verification = None;
                layer
                    .signing
                    .as_mut()
                    .unwrap()
                    .transforms
                    .allowed_algorithms = Some(methods);
            } else {
                layer.signing = None;
                layer
                    .verification
                    .as_mut()
                    .unwrap()
                    .transforms
                    .allowed_algorithms = Some(methods);
            }
            assert!(matches!(
                initial.restrict(&layer).unwrap().compile(&context()),
                Err(PolicyViolation::Configuration { .. })
            ));
        }
    }
    let initial = compiler(PolicyProfile::Modern);
    let mut layer = initial.policies().clone();
    layer
        .verification
        .as_mut()
        .unwrap()
        .transforms
        .allowed_algorithms = Some(BTreeSet::from([
        "http://www.w3.org/2001/10/xml-exc-c14n#".into()
    ]));
    initial
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
}

#[test]
fn saml_compiler_requires_its_enveloped_transform() {
    // A canonicalization-only layer still makes every SAML operation
    // impossible because its enclosing Signature must be removed from input.
    for signing in [false, true] {
        let initial = compiler(PolicyProfile::SecureSaml);
        let mut layer = initial.policies().clone();
        let transforms = if signing {
            layer.verification = None;
            &mut layer.signing.as_mut().unwrap().transforms
        } else {
            layer.signing = None;
            &mut layer.verification.as_mut().unwrap().transforms
        };
        transforms.allowed_algorithms = Some(BTreeSet::from([
            "http://www.w3.org/2001/10/xml-exc-c14n#".into(),
        ]));
        assert!(matches!(
            initial.restrict(&layer).unwrap().compile(&context()),
            Err(PolicyViolation::Configuration { .. })
        ));
    }
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
    later.expires_at = seconds_later(later.expires_at, 3600);
    let compiled = initial
        .authorize_replacement(replacement, &later)
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
    expired.validity.as_mut().unwrap().expires_at = Instant::new(1, 0).unwrap();
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
fn saml_profile_rejects_non_message_roots() {
    // Namespace membership cannot authorize signing a Subject, Status or an
    // invented element as though it were an assertion/protocol message root.
    let compiled = compiler(PolicyProfile::SecureSaml)
        .compile(&context())
        .unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    for (namespace, name) in [
        ("urn:oasis:names:tc:SAML:2.0:assertion", "Subject"),
        ("urn:oasis:names:tc:SAML:2.0:protocol", "Status"),
        ("urn:oasis:names:tc:SAML:2.0:protocol", "Assertion"),
        ("urn:oasis:names:tc:SAML:2.0:assertion", "Response"),
    ] {
        let xml = template(namespace, "root").replace("Assertion", name);
        assert!(matches!(
            SignContext::new(&key)
                .policy(compiled.signing().unwrap().clone())
                .sign_template(&xml),
            Err(xml_sec::xmldsig::SigningError::Policy(
                PolicyViolation::SignatureProfile {
                    profile: SignatureConstraints::Saml,
                    ..
                }
            ))
        ));
    }
}

#[test]
fn saml_profile_accepts_defined_protocol_roots() {
    // Every concrete protocol message root has the same XML signature binding;
    // this does not claim to validate its application-specific payload schema.
    let compiled = compiler(PolicyProfile::SecureSaml)
        .compile(&context())
        .unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    for name in [
        "AssertionIDRequest",
        "AuthnQuery",
        "AttributeQuery",
        "AuthzDecisionQuery",
        "AuthnRequest",
        "Response",
        "ArtifactResolve",
        "ArtifactResponse",
        "ManageNameIDRequest",
        "ManageNameIDResponse",
        "LogoutRequest",
        "LogoutResponse",
        "NameIDMappingRequest",
        "NameIDMappingResponse",
    ] {
        let xml =
            template("urn:oasis:names:tc:SAML:2.0:protocol", "root").replace("Assertion", name);
        SignContext::new(&key)
            .policy(compiled.signing().unwrap().clone())
            .sign_template(&xml)
            .unwrap();
    }
    // SubjectQuery's abstract base is extensible; the application validates the
    // derived type rather than this binding gate rejecting the extension root.
    let xml = template("urn:oasis:names:tc:SAML:2.0:protocol", "root")
        .replace("Assertion", "SubjectQuery")
        .replace(" ID=", " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:q=\"urn:query\" xsi:type=\"q:QueryType\" ID=");
    SignContext::new(&key)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&xml)
        .unwrap();
}

fn xades_template(properties: &str) -> String {
    template("urn:test", "root")
        .replace("<ds:Signature ", "<ds:Signature Id=\"sig\" ")
        .replace("</ds:SignedInfo>", r##"<ds:Reference URI="#properties" Type="http://uri.etsi.org/01903#SignedProperties"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>"##)
        .replace("</ds:Signature>", &format!(r##"<ds:Object><x:QualifyingProperties xmlns:x="http://uri.etsi.org/01903/v1.3.2#" Target="#sig"><x:SignedProperties Id="properties">{properties}</x:SignedProperties></x:QualifyingProperties></ds:Object></ds:Signature>"##))
}

#[test]
fn xades_profile_rejects_empty_or_foreign_properties_containers() {
    // An authenticated reference to an empty/foreign-only container does not
    // establish the structural SignedProperties binding required by ETSI.
    let compiled = compiler(PolicyProfile::Xades).compile(&context()).unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    for properties in [
        "",
        " \n<!-- none --><?none?>",
        "<foreign xmlns=\"urn:other\"/>",
    ] {
        assert!(matches!(
            SignContext::new(&key)
                .policy(compiled.signing().unwrap().clone())
                .sign_template(&xades_template(properties)),
            Err(xml_sec::xmldsig::SigningError::Policy(
                PolicyViolation::SignatureProfile {
                    profile: SignatureConstraints::Xades,
                    ..
                }
            ))
        ));
    }
}

#[test]
fn xades_profile_authenticates_nonempty_ordered_properties() {
    // Binding authenticates the entire properties container, not a loose
    // child; detailed qualifying-property semantics belong to the XAdES layer.
    let compiled = compiler(PolicyProfile::Xades).compile(&context()).unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let properties = "<x:SignedSignatureProperties><x:SigningTime>2026-10-14T00:00:00Z</x:SigningTime></x:SignedSignatureProperties>";
    let xml = SignContext::new(&key)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&xades_template(properties))
        .unwrap();
    let document = XmlDocument::parse(xml).unwrap();
    let targets = document.with_view(|view| [view.root_element()]);
    let evidence = VerifyContext::new()
        .key(&verifier)
        .policy(compiled.verification().unwrap().clone())
        .verify_request(
            &document,
            &VerificationRequest {
                expected_targets: &targets,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    for invalid in [
        "<x:SignedDataObjectProperties/><x:SignedSignatureProperties/>",
        "<x:SignedSignatureProperties/><x:SignedSignatureProperties/>",
        "text<x:SignedSignatureProperties/>",
    ] {
        assert!(matches!(
            SignContext::new(&key)
                .policy(compiled.signing().unwrap().clone())
                .sign_template(&xades_template(invalid)),
            Err(xml_sec::xmldsig::SigningError::Policy(
                PolicyViolation::SignatureProfile { .. }
            ))
        ));
    }
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
