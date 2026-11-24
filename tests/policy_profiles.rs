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
fn a_request_selects_only_what_its_policy_lists() {
    // A caller's compatibility option never reaches a mode the deployment did
    // not admit: the libxmlsec1 profile lists libxmlsec1's selections, the
    // modern one none, so the same selection succeeds in one and is refused
    // with a typed violation in the other.
    use xml_sec::policy::{
        EcdsaSignatureValueEncoding, ManifestProcessing, RequestSelections, SameDocumentIdSemantics,
    };
    let compat = compiler(PolicyProfile::XmlSecCompatible)
        .compile(&context())
        .unwrap();
    let mut verification = compat.verification().unwrap().clone();
    assert_eq!(
        verification.request_selections,
        RequestSelections::libxmlsec1()
    );
    verification
        .select_same_document_id_semantics(SameDocumentIdSemantics::XmlSecVisa3d)
        .unwrap();
    assert_eq!(
        verification.transforms.same_document_id_semantics,
        SameDocumentIdSemantics::XmlSecVisa3d
    );
    let mut signing = compat.signing().unwrap().clone();
    signing
        .select_ecdsa_signature_value_encoding(EcdsaSignatureValueEncoding::XmlSecAsn1Der)
        .unwrap();
    signing
        .select_manifest_processing(ManifestProcessing::Process)
        .unwrap();
    assert_eq!(signing.manifest_processing, ManifestProcessing::Process);

    let modern = compiler(PolicyProfile::Modern).compile(&context()).unwrap();
    let mut verification = modern.verification().unwrap().clone();
    assert_eq!(
        verification.select_same_document_id_semantics(SameDocumentIdSemantics::XmlSecVisa3d),
        Err(PolicyViolation::RequestSelection {
            setting: "same_document_id_semantics"
        })
    );
    // The policy's own value is always selectable.
    let current = verification.manifest_processing;
    assert_eq!(verification.select_manifest_processing(current), Ok(()));

    // A layer that lists nothing leaves the compiled policy with nothing: the
    // selection the base listed is refused, the policy's own value stays.
    let compatibility = || compiler(PolicyProfile::XmlSecCompatible);
    let mut layer = compatibility().policies().clone();
    layer.verification.as_mut().unwrap().request_selections = RequestSelections::default();
    let narrowed = compatibility()
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
    let mut verification = narrowed.verification().unwrap().clone();
    assert_eq!(
        verification.select_same_document_id_semantics(SameDocumentIdSemantics::XmlSecVisa3d),
        Err(PolicyViolation::RequestSelection {
            setting: "same_document_id_semantics"
        })
    );
    let current = verification.transforms.same_document_id_semantics;
    assert_eq!(
        verification.select_same_document_id_semantics(current),
        Ok(())
    );
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
        _: &structured_asn1::memory::Memory,
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
        .unwrap()
        .output;
    let result = VerifyContext::new()
        .key(&verifier)
        .policy(compiled.verification().unwrap().clone())
        .verify(&xml)
        .unwrap();
    assert_eq!(result.status, xml_sec::xmldsig::DsigStatus::Valid);
}

#[test]
fn the_compatible_profile_verifies_ids_its_signing_refuses() {
    // The profile accepts what libxmlsec1 signs: its verification resolves a
    // bare-name fragment that is not an NCName. Its own signing keeps to the
    // specification's ID form; only a policy built for libxmlsec1's
    // boundary, as the C library builds it, signs with libxmlsec1's lookup.
    use xml_sec::policy::SameDocumentIdSemantics;
    let compiled = compiler(PolicyProfile::XmlSecCompatible)
        .compile(&context())
        .unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let mut signing = compiled.signing().unwrap().clone();
    assert_eq!(
        signing.transforms.same_document_id_semantics,
        SameDocumentIdSemantics::Specification
    );
    assert!(
        SignContext::new(&key)
            .policy(signing.clone())
            .sign_template(&template("urn:test", "123"))
            .is_err(),
        "a bare name that is not an NCName is no ID by the specification"
    );
    assert_eq!(
        signing.select_same_document_id_semantics(SameDocumentIdSemantics::XmlSecBarename),
        Err(PolicyViolation::RequestSelection {
            setting: "same_document_id_semantics"
        }),
        "a request does not reach libxmlsec1's lookup for signing"
    );
    signing.transforms.same_document_id_semantics = SameDocumentIdSemantics::XmlSecBarename;
    let xml = SignContext::new(&key)
        .policy(signing)
        .sign_template(&template("urn:test", "123"))
        .unwrap()
        .output;
    let result = VerifyContext::new()
        .key(&verifier)
        .policy(compiled.verification().unwrap().clone())
        .verify(&xml)
        .unwrap();
    assert_eq!(result.status, xml_sec::xmldsig::DsigStatus::Valid);
}

#[test]
fn only_signing_layers_must_agree_on_the_generated_canonicalization() {
    // Verification never generates a canonicalization, so a layer that
    // differs from its base only there composes; a signing layer that
    // differs would change the signed output and is refused.
    let compatibility = || compiler(PolicyProfile::XmlSecCompatible);
    let mut layer = compatibility().policies().clone();
    layer
        .verification
        .as_mut()
        .unwrap()
        .transforms
        .generated_canonicalization = xml_sec::policy::GeneratedCanonicalization::Implicit;
    assert!(compatibility().restrict(&layer).is_ok());
    let mut layer = compatibility().policies().clone();
    layer
        .signing
        .as_mut()
        .unwrap()
        .transforms
        .generated_canonicalization = xml_sec::policy::GeneratedCanonicalization::Implicit;
    assert!(matches!(
        compatibility().restrict(&layer),
        Err(PolicyViolation::Configuration { .. })
    ));
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
            .unwrap()
            .output;
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
        .unwrap()
        .output;
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
        // Likewise only that profile reads a Relationships-namespace
        // TargetMode as libxmlsec1 does, in both directions.
        let target_mode = if profile == PolicyProfile::XmlSecCompatible {
            xml_sec::policy::RelationshipTargetModeSemantics::Libxmlsec1
        } else {
            xml_sec::policy::RelationshipTargetModeSemantics::Specification
        };
        for transforms in [
            &compiled.verification().unwrap().transforms,
            &compiled.signing().unwrap().transforms,
        ] {
            assert_eq!(
                transforms.relationship_target_mode_semantics, target_mode,
                "{profile:?}"
            );
        }
        // Every profile signs a node set with an explicit Exclusive C14N, the
        // libxmlsec1-compatible one included; implicit conversion is left to
        // the libxmlsec1 boundaries.
        assert_eq!(
            compiled
                .signing()
                .unwrap()
                .transforms
                .generated_canonicalization,
            xml_sec::policy::GeneratedCanonicalization::ExplicitExclusiveC14n,
            "{profile:?}"
        );
        // Only the libxmlsec1-compatible profile stops on any X509Data child
        // that yields no certificate, as libxmlsec1 does; the others follow
        // its documented flag.
        let unknown = if profile == PolicyProfile::XmlSecCompatible {
            xml_sec::policy::UnknownX509CertificateSemantics::Libxmlsec1
        } else {
            xml_sec::policy::UnknownX509CertificateSemantics::References
        };
        assert_eq!(
            compiled
                .verification()
                .unwrap()
                .key_trust
                .unknown_x509_certificate,
            unknown,
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

#[cfg(feature = "xmlenc")]
#[test]
fn profiles_state_their_key_establishment_explicitly() {
    // Every profile lists what it admits instead of leaving the core's
    // implicit default: the effective policy names it, and a restricting
    // layer intersects it element by element. The modern set is the implicit
    // default plus X448 (RFC 7748); XmlSecCompatible's inbound ceiling adds
    // what libxmlsec1 agrees and derives with, its outbound operations keep
    // the modern set as their other algorithm sets do.
    use xml_sec::policy::{KeyAgreementAlgorithm as A, KeyDerivationAlgorithm as K};
    use xml_sec::xmldsig::DigestAlgorithm as D;
    let modern_agreements = BTreeSet::from([A::EcdhEs, A::X25519, A::X448]);
    let derivations = BTreeSet::from([K::ConcatKdf, K::Hkdf, K::Pbkdf2]);
    let sha2 = BTreeSet::from([D::Sha224, D::Sha256, D::Sha384, D::Sha512]);
    let implicit = xml_sec::policy::KeyEstablishmentPolicy::default();
    for profile in [
        PolicyProfile::Modern,
        PolicyProfile::SecureSaml,
        PolicyProfile::WsSecurity,
        PolicyProfile::Xades,
        PolicyProfile::XmlSecCompatible,
    ] {
        let policies = compiler(profile).policies().clone();
        let outbound = [
            &policies.signing.as_ref().unwrap().key_establishment,
            &policies.encryption.as_ref().unwrap().key_establishment,
        ];
        for policy in outbound {
            assert_eq!(policy.agreement_algorithms, Some(modern_agreements.clone()));
            assert_eq!(policy.derivation_algorithms, Some(derivations.clone()));
            assert_eq!(policy.digest_algorithms, Some(sha2.clone()));
            // Outbound operations transport no key by ML-KEM in any profile.
            assert!(policy.encapsulation_algorithms.is_empty(), "{profile:?}");
            assert_eq!(
                policy.kem_content_authentication,
                xml_sec::policy::KemContentAuthentication::RequireAuthenticatedCipher
            );
            assert_eq!(
                policy.kem_signature_trust,
                xml_sec::policy::KemSignatureTrust::RequireCryptographicOnly
            );
            // The explicit modern set admits what the implicit default
            // admitted and X448, nothing else.
            for algorithm in [A::EcdhEs, A::X25519, A::X448, A::DhEs, A::LegacyDh] {
                assert_eq!(
                    policy.check_agreement(algorithm).is_ok(),
                    algorithm == A::X448 || implicit.check_agreement(algorithm).is_ok(),
                    "{profile:?} {algorithm:?}"
                );
            }
        }
        let inbound = [
            &policies.verification.as_ref().unwrap().key_establishment,
            &policies.decryption.as_ref().unwrap().key_establishment,
        ];
        for policy in inbound {
            let compatible = profile == PolicyProfile::XmlSecCompatible;
            let expected = if compatible {
                BTreeSet::from([A::EcdhEs, A::X25519, A::X448, A::DhEs])
            } else {
                modern_agreements.clone()
            };
            assert_eq!(policy.agreement_algorithms, Some(expected), "{profile:?}");
            assert_eq!(policy.derivation_algorithms, Some(derivations.clone()));
            for digest in [D::Sha1, D::Sha3_256, D::Sha3_512] {
                assert_eq!(
                    policy.check_derivation_digest(digest).is_ok(),
                    compatible,
                    "{profile:?} {digest:?}"
                );
            }
            // No profile admits the legacy DH derivation libxmlsec1 lacks.
            assert!(policy.check_agreement(A::LegacyDh).is_err());
            // libxmlsec1 transports keys by ML-KEM and keys CBC content with
            // the secret; the compatible ceiling admits both where the
            // provider decapsulates, the other profiles neither.
            for algorithm in xml_sec::provider::KeyEncapsulationAlgorithm::all() {
                assert_eq!(
                    policy.check_encapsulation(algorithm).is_ok(),
                    compatible
                        && RustCryptoProvider.supports(
                            xml_sec::provider::ProviderCapability::Decapsulate(algorithm)
                        ),
                    "{profile:?} {algorithm:?}"
                );
            }
            assert_eq!(
                policy.kem_content_authentication,
                if compatible {
                    xml_sec::policy::KemContentAuthentication::ExternalAuthenticated
                } else {
                    xml_sec::policy::KemContentAuthentication::RequireAuthenticatedCipher
                },
                "{profile:?}"
            );
            // libxmlsec1 verifies a KEM/HMAC signature with the recipient key
            // its manager holds; only the compatible ceiling lets that key
            // stand for a trusted one.
            assert_eq!(
                policy.kem_signature_trust,
                if compatible {
                    xml_sec::policy::KemSignatureTrust::AcceptRecipientKey
                } else {
                    xml_sec::policy::KemSignatureTrust::RequireCryptographicOnly
                },
                "{profile:?}"
            );
        }
    }
}

#[test]
fn a_layer_requires_cryptographic_only_kem_signatures_again() {
    // The compatible ceiling takes the recipient key for a trusted key on a
    // KEM/HMAC signature, as libxmlsec1 does; a deployment layer that
    // requires a cryptographic-only verification for it takes that back, and
    // one that grants it to a profile whose ceiling refuses it gains nothing.
    use xml_sec::policy::KemSignatureTrust as Trust;
    for (profile, layer_value, expected) in [
        (
            PolicyProfile::XmlSecCompatible,
            Trust::RequireCryptographicOnly,
            Trust::RequireCryptographicOnly,
        ),
        (
            PolicyProfile::XmlSecCompatible,
            Trust::AcceptRecipientKey,
            Trust::AcceptRecipientKey,
        ),
        (
            PolicyProfile::Modern,
            Trust::AcceptRecipientKey,
            Trust::RequireCryptographicOnly,
        ),
    ] {
        let initial = compiler(profile);
        let mut layer = initial.policies().clone();
        layer
            .verification
            .as_mut()
            .unwrap()
            .key_establishment
            .kem_signature_trust = layer_value;
        let compiled = initial
            .restrict(&layer)
            .unwrap()
            .compile(&context())
            .unwrap();
        assert_eq!(
            compiled
                .verification()
                .unwrap()
                .key_establishment
                .kem_signature_trust,
            expected,
            "{profile:?} {layer_value:?}"
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn a_layer_requires_authenticated_kem_content_again() {
    // The compatible ceiling keys CBC content with an ML-KEM secret, as
    // libxmlsec1 does; a deployment layer that requires an authenticated
    // content cipher takes that back, and one that grants it to a profile
    // whose ceiling refuses it gains nothing.
    use xml_sec::policy::KemContentAuthentication as Kem;
    for (profile, layer_value, expected) in [
        (
            PolicyProfile::XmlSecCompatible,
            Kem::RequireAuthenticatedCipher,
            Kem::RequireAuthenticatedCipher,
        ),
        (
            PolicyProfile::XmlSecCompatible,
            Kem::ExternalAuthenticated,
            Kem::ExternalAuthenticated,
        ),
        (
            PolicyProfile::Modern,
            Kem::ExternalAuthenticated,
            Kem::RequireAuthenticatedCipher,
        ),
    ] {
        let initial = compiler(profile);
        let mut layer = initial.policies().clone();
        layer
            .decryption
            .as_mut()
            .unwrap()
            .key_establishment
            .kem_content_authentication = layer_value;
        let compiled = initial
            .restrict(&layer)
            .unwrap()
            .compile(&context())
            .unwrap();
        assert_eq!(
            compiled
                .decryption()
                .unwrap()
                .key_establishment
                .kem_content_authentication,
            expected,
            "{profile:?} {layer_value:?}"
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn a_layer_narrows_the_compatible_key_establishment_ceiling() {
    // A deployment of the compatible profile switches off what it does not
    // want: X448 and SHA-1 are refused once a layer lists the rest, and a
    // layer naming more than the ceiling (the XML Encryption 1.0 DH) gains
    // nothing.
    use xml_sec::policy::KeyAgreementAlgorithm as A;
    use xml_sec::xmldsig::DigestAlgorithm as D;
    let initial = compiler(PolicyProfile::XmlSecCompatible);
    let mut layer = initial.policies().clone();
    let decryption = layer.decryption.as_mut().unwrap();
    decryption.key_establishment.agreement_algorithms =
        Some(BTreeSet::from([A::EcdhEs, A::X25519, A::DhEs, A::LegacyDh]));
    decryption.key_establishment.digest_algorithms = Some(BTreeSet::from([D::Sha256, D::Sha3_256]));
    let compiled = initial
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
    let policy = &compiled.decryption().unwrap().key_establishment;
    assert!(policy.check_agreement(A::DhEs).is_ok());
    assert!(policy.check_agreement(A::X448).is_err());
    assert!(policy.check_agreement(A::LegacyDh).is_err());
    assert!(policy.check_derivation_digest(D::Sha3_256).is_ok());
    assert!(policy.check_derivation_digest(D::Sha1).is_err());
    assert!(policy.check_derivation_digest(D::Sha512).is_err());
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
        .unwrap()
        .output;
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
        .unwrap()
        .output;
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

/// `xades_template` in ETSI TS 101 903 V1.2.2 syntax: that namespace and
/// that `SignedProperties` reference type (TS 101 903 V1.2.2 §5, §6.3.1).
fn xades_v122_template(properties: &str) -> String {
    xades_template(properties)
        .replace(
            "http://uri.etsi.org/01903#SignedProperties",
            "http://uri.etsi.org/01903/v1.2.2#SignedProperties",
        )
        .replace(
            "http://uri.etsi.org/01903/v1.3.2#",
            "http://uri.etsi.org/01903/v1.2.2#",
        )
}

#[test]
fn only_the_conformant_profile_verifies_ts_101_903_v1_2_2_signatures() {
    // XAdES signatures made before EN 319 132-1 carry TS 101 903 V1.2.2's
    // namespace and reference type. XadesConformant verifies them, as EU DSS
    // does; the other profiles admit only EN 319 132-1, and no profile signs
    // them. Each syntax keeps its own reference type: V1.2.2 properties
    // under EN 319 132-1's type are neither.
    let properties = "<x:SignedSignatureProperties><x:SigningTime>2014-11-07T09:48:27Z</x:SigningTime></x:SignedSignatureProperties>";
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let general = compiler(PolicyProfile::Modern).compile(&context()).unwrap();
    let sign = |template: &str| {
        let xml = SignContext::new(&key)
            .policy(general.signing().unwrap().clone())
            .sign_template(template)
            .unwrap()
            .output;
        XmlDocument::parse(xml).unwrap()
    };
    // Whether `profile` accepts `document`, and the evidence that says why.
    let verify = |profile, document: &XmlDocument| {
        let compiled = compiler(profile).compile(&context()).unwrap();
        let targets = document.with_view(|view| [view.root_element()]);
        let evidence = VerifyContext::new()
            .key(&verifier)
            .policy(compiled.verification().unwrap().clone())
            .verify_request(
                document,
                &VerificationRequest {
                    expected_targets: &targets,
                    ..Default::default()
                },
            )
            .unwrap();
        (
            evidence.accepted(document).unwrap(),
            format!("{evidence:?}"),
        )
    };
    let earlier = sign(&xades_v122_template(properties));
    let (accepted, evidence) = verify(PolicyProfile::XadesConformant, &earlier);
    assert!(accepted, "{evidence}");
    for profile in [PolicyProfile::Xades, PolicyProfile::XadesExtended] {
        let (accepted, evidence) = verify(profile, &earlier);
        assert!(
            !accepted && evidence.contains("SignatureProfile"),
            "{profile:?}: {evidence}"
        );
    }
    let mixed = sign(&xades_template(properties).replace(
        "http://uri.etsi.org/01903/v1.3.2#",
        "http://uri.etsi.org/01903/v1.2.2#",
    ));
    let (accepted, evidence) = verify(PolicyProfile::XadesConformant, &mixed);
    assert!(
        !accepted && evidence.contains("SignatureProfile"),
        "{evidence}"
    );
    let conformant = compiler(PolicyProfile::XadesConformant)
        .compile(&context())
        .unwrap();
    assert!(matches!(
        SignContext::new(&key)
            .policy(conformant.signing().unwrap().clone())
            .sign_template(&xades_v122_template(properties)),
        Err(xml_sec::xmldsig::SigningError::Policy(
            PolicyViolation::SignatureProfile {
                profile: SignatureConstraints::Xades,
                ..
            }
        ))
    ));
}

/// `xades_template` with one more `Reference`, to a `ds:Object` holding
/// base64 text, under `transform`.
fn xades_with_object_reference(transform: &str) -> String {
    xades_template(
        "<x:SignedSignatureProperties><x:SigningTime>2026-10-14T00:00:00Z</x:SigningTime></x:SignedSignatureProperties>",
    )
    .replace(
        "</ds:SignedInfo>",
        &format!(
            r##"<ds:Reference URI="#binary"><ds:Transforms><ds:Transform Algorithm="{transform}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>"##
        ),
    )
    .replace(
        "</ds:Signature>",
        r#"<ds:Object Id="binary">YmluYXJ5IHBheWxvYWQ=</ds:Object></ds:Signature>"#,
    )
}

#[test]
fn strict_profiles_admit_the_base64_transform_but_no_node_set_selection() {
    // XMLDSig 1.1 §6.6.2 makes Base64 a required transform: enveloping
    // signatures over binary data, which EU DSS writes by default, carry it.
    // It decodes octets and selects no nodes, so the strict profiles admit it
    // for signing and verification, while XPath keeps its refusal.
    // https://www.w3.org/TR/xmldsig-core1/#sec-Base-64
    let compiled = compiler(PolicyProfile::Xades).compile(&context()).unwrap();
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let xml = SignContext::new(&key)
        .policy(compiled.signing().unwrap().clone())
        .sign_template(&xades_with_object_reference(
            "http://www.w3.org/2000/09/xmldsig#base64",
        ))
        .unwrap()
        .output;
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
    assert!(evidence.all_valid());
    // SecureSaml keeps its own narrower list: SAML Core §5.4.4 admits only the
    // enveloped-signature and exclusive canonicalization transforms.
    // https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    for profile in [
        PolicyProfile::Modern,
        PolicyProfile::WsSecurity,
        PolicyProfile::Xades,
    ] {
        let compiled = compiler(profile).compile(&context()).unwrap();
        let transforms = &compiled.verification().unwrap().transforms;
        let admitted = |uri: &str| {
            transforms
                .allowed_algorithms
                .as_ref()
                .is_some_and(|methods| methods.contains(uri))
        };
        assert!(
            admitted("http://www.w3.org/2000/09/xmldsig#base64"),
            "{profile:?}"
        );
        for refused in [
            "http://www.w3.org/TR/1999/REC-xpath-19991116",
            "http://www.w3.org/2002/06/xmldsig-filter2",
            "http://www.w3.org/TR/1999/REC-xslt-19991116",
        ] {
            assert!(!admitted(refused), "{profile:?} admits {refused}");
        }
        assert_eq!(
            compiled.signing().unwrap().transforms.allowed_algorithms,
            transforms.allowed_algorithms,
            "{profile:?}"
        );
    }
    assert!(matches!(
        SignContext::new(&key)
            .policy(compiled.signing().unwrap().clone())
            .sign_template(&xades_with_object_reference(
                "http://www.w3.org/TR/1999/REC-xpath-19991116"
            )),
        Err(xml_sec::xmldsig::SigningError::Policy(_))
    ));
}

#[test]
fn each_xades_profile_is_the_wider_one_restricted_by_its_policies() {
    // A named profile is only a set of policy values: restricting the wider
    // profile by the narrower one's policies compiles to exactly the narrower
    // profile, so a deployment reaches any of them with layers alone.
    for (wider, narrower) in [
        (PolicyProfile::XadesConformant, PolicyProfile::XadesExtended),
        (PolicyProfile::XadesExtended, PolicyProfile::Xades),
    ] {
        let layer = compiler(narrower).policies().clone();
        let restricted = compiler(wider)
            .restrict(&layer)
            .unwrap()
            .compile(&context())
            .unwrap();
        let named = compiler(narrower).compile(&context()).unwrap();
        assert_eq!(
            format!("{:?}", restricted.verification()),
            format!("{:?}", named.verification()),
            "{wider:?} -> {narrower:?} verification"
        );
        assert_eq!(
            format!("{:?}", restricted.signing()),
            format!("{:?}", named.signing()),
            "{wider:?} -> {narrower:?} signing"
        );
    }
}

#[test]
fn the_xades_profiles_widen_one_step_at_a_time() {
    // Xades, XadesExtended and XadesConformant differ in exactly the values
    // their contracts name: node-set transforms, then SHA-1 based
    // verification, 1024-bit keys and KeyValue keys. Signing stays modern.
    use xml_sec::policy::KeySourceKind;
    use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
    let compiled = |profile| compiler(profile).compile(&context()).unwrap();
    let (strict, extended, conformant) = (
        compiled(PolicyProfile::Xades),
        compiled(PolicyProfile::XadesExtended),
        compiled(PolicyProfile::XadesConformant),
    );
    let transforms = |policies: &xml_sec::policy::CompiledPolicies, uri: &str| {
        policies
            .verification()
            .unwrap()
            .transforms
            .allowed_algorithms
            .as_ref()
            .is_some_and(|methods| methods.contains(uri))
    };
    for uri in [
        "http://www.w3.org/TR/1999/REC-xpath-19991116",
        "http://www.w3.org/2002/06/xmldsig-filter2",
    ] {
        assert!(!transforms(&strict, uri), "{uri}");
        assert!(transforms(&extended, uri), "{uri}");
        assert!(transforms(&conformant, uri), "{uri}");
    }
    for policies in [&strict, &extended, &conformant] {
        assert!(!transforms(
            policies,
            "http://www.w3.org/TR/1999/REC-xslt-19991116"
        ));
    }
    let verifies = |policies: &xml_sec::policy::CompiledPolicies, method| {
        policies
            .verification()
            .unwrap()
            .signature_algorithms
            .as_ref()
            .is_some_and(|methods| methods.contains(&method))
    };
    assert!(!verifies(&extended, SignatureAlgorithm::RsaSha1));
    assert!(verifies(&conformant, SignatureAlgorithm::RsaSha1));
    assert!(!verifies(&conformant, SignatureAlgorithm::HmacSha1));
    let digests = |policies: &xml_sec::policy::CompiledPolicies| {
        policies
            .verification()
            .unwrap()
            .digest_algorithms
            .clone()
            .unwrap()
    };
    assert!(!digests(&extended).contains(&DigestAlgorithm::Sha1));
    assert!(digests(&conformant).contains(&DigestAlgorithm::Sha1));
    let trust = |policies: &xml_sec::policy::CompiledPolicies| {
        policies.verification().unwrap().key_trust.clone()
    };
    assert_eq!(
        trust(&extended).rsa_keys.minimum_modulus_bits,
        trust(&strict).rsa_keys.minimum_modulus_bits
    );
    assert_eq!(trust(&conformant).rsa_keys.minimum_modulus_bits, 1024);
    let sources =
        |policies: &xml_sec::policy::CompiledPolicies| policies.verification().unwrap().key_sources;
    assert!(!sources(&extended).contains(KeySourceKind::KeyValue));
    assert!(sources(&conformant).contains(KeySourceKind::KeyValue));
    // Signing is the same modern set in all three.
    for policies in [&extended, &conformant] {
        assert_eq!(
            format!("{:?}", policies.signing().unwrap().signature_algorithms),
            format!("{:?}", strict.signing().unwrap().signature_algorithms)
        );
    }
}

#[test]
fn the_extended_profile_signs_and_verifies_an_xpath_selected_reference() {
    // XadesExtended admits node-set selection through the public operations;
    // Xades refuses the same signature with a typed policy violation.
    let transform = r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#;
    let template = xades_template(
        "<x:SignedSignatureProperties><x:SigningTime>2026-10-14T00:00:00Z</x:SigningTime></x:SignedSignatureProperties>",
    )
    .replace(
        "</ds:SignedInfo>",
        &format!(
            r##"<ds:Reference URI="#binary"><ds:Transforms>{transform}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo>"##
        ),
    )
    .replace(
        "</ds:Signature>",
        r#"<ds:Object Id="binary">selected</ds:Object></ds:Signature>"#,
    );
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x53; 32]).unwrap();
    let extended = compiler(PolicyProfile::XadesExtended)
        .compile(&context())
        .unwrap();
    let xml = SignContext::new(&key)
        .policy(extended.signing().unwrap().clone())
        .sign_template(&template)
        .unwrap()
        .output;
    let document = XmlDocument::parse(xml).unwrap();
    let targets = document.with_view(|view| [view.root_element()]);
    let request = VerificationRequest {
        expected_targets: &targets,
        ..Default::default()
    };
    let evidence = VerifyContext::new()
        .key(&verifier)
        .policy(extended.verification().unwrap().clone())
        .verify_request(&document, &request)
        .unwrap();
    assert!(evidence.all_valid());
    let strict = compiler(PolicyProfile::Xades).compile(&context()).unwrap();
    let refused = VerifyContext::new()
        .key(&verifier)
        .policy(strict.verification().unwrap().clone())
        .verify_request(&document, &request);
    let refused = format!("{refused:?}");
    assert!(
        refused.contains("REC-xpath-19991116"),
        "Xades must refuse the XPath transform: {refused}"
    );
}

/// How a signing certificate the caller configured as its trust anchor
/// resolves from `KeyInfo` at `at` under `profile` with X.509 chains
/// checked: `validated`, or the refusal.
fn resolve_anchor_signer(profile: PolicyProfile, at: i64) -> String {
    resolve_anchor_signer_in(profile, at, false)
}

/// [`resolve_anchor_signer`], with `KeyInfo` naming the anchor only by its
/// subject name when `by_name` is set.
fn resolve_anchor_signer_in(profile: PolicyProfile, at: i64, by_name: bool) -> String {
    use xml_sec::xmldsig::{
        DefaultKeyResolver, InspectedKeyCandidateBudget, KeyResolverConfig,
        ResolvedVerificationKey, parse_key_info,
    };
    let pem = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
    )
    .unwrap();
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = structured_base64::STANDARD.decode(body.as_bytes()).unwrap();
    let identification = if by_name {
        "<X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>".to_owned()
    } else {
        format!("<X509Certificate>{body}</X509Certificate>")
    };
    let xml = format!(
        r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>{identification}</X509Data></KeyInfo>"#
    );
    let document = xml_sec::XmlDomDocument::parse(&xml).unwrap();
    let key_info = parse_key_info(document.root_element()).unwrap();
    let mut policy = compiler(profile)
        .compile(&context())
        .unwrap()
        .verification()
        .unwrap()
        .clone();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Some(Instant::new(at, 0).unwrap());
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![der],
        ..KeyResolverConfig::default()
    });
    let mut budget = InspectedKeyCandidateBudget::new(&policy);
    match resolver.resolve_with_candidate_budget(
        Some(&key_info),
        SignatureAlgorithm::RsaSha256,
        &policy,
        &RustCryptoProvider,
        &mut budget,
    ) {
        Ok(Some(ResolvedVerificationKey::Validated(_))) => "validated".into(),
        Ok(Some(_)) => "unvalidated key".into(),
        Ok(None) => "no key".into(),
        Err(error) => format!("{error:?}"),
    }
}

#[test]
fn a_conformant_profile_accepts_a_signing_certificate_that_is_its_trust_anchor() {
    // ETSI EN 319 102-1 V1.4.1 5.2.6.4 step 1(b): when the signing
    // certificate is itself a trust anchor, the policy may pass X.509
    // validation without step 7's validity check. XadesConformant does, as
    // EU DSS does; the stricter profiles keep the check, so the same expired
    // anchor-signer is refused there.
    const LONG_AFTER_EXPIRY: i64 = 7_258_118_400; // 2200-01-01
    assert_eq!(
        resolve_anchor_signer(PolicyProfile::XadesConformant, LONG_AFTER_EXPIRY),
        "validated"
    );
    let refused = resolve_anchor_signer(PolicyProfile::Xades, LONG_AFTER_EXPIRY);
    assert!(refused.contains("CertificateNotValid(0)"), "{refused}");
    // The policy decides the anchor, however KeyInfo identifies it: by its
    // subject name alone the same anchor is accepted and refused alike.
    assert_eq!(
        resolve_anchor_signer_in(PolicyProfile::XadesConformant, LONG_AFTER_EXPIRY, true),
        "validated"
    );
    let refused = resolve_anchor_signer_in(PolicyProfile::Xades, LONG_AFTER_EXPIRY, true);
    assert!(refused.contains("CertificateNotValid(0)"), "{refused}");
    // A permission: a layer that validates the anchor-signer withdraws it.
    let conformant = compiler(PolicyProfile::XadesConformant);
    let mut layer = conformant.policies().clone();
    if let Some(verification) = layer.verification.as_mut() {
        verification.key_trust.trust_anchor_signer = xml_sec::policy::TrustAnchorSigner::Validated;
    }
    let narrowed = conformant
        .restrict(&layer)
        .unwrap()
        .compile(&context())
        .unwrap();
    assert_eq!(
        narrowed
            .verification()
            .unwrap()
            .key_trust
            .trust_anchor_signer,
        xml_sec::policy::TrustAnchorSigner::Validated
    );
}

#[test]
fn a_denial_withdraws_exactly_the_named_permissions() {
    // A deployment narrows any profile without restating it: each denied
    // permission disappears from every operation that had it, and the rest
    // of the profile stays as it was.
    use xml_sec::policy::{Denials, KeySourceKind};
    use xml_sec::xmldsig::{SignatureAlgorithm, UriClass};
    const FILTER2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
    const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    let denials = Denials {
        transforms: [FILTER2.to_owned()].into(),
        signature_algorithms: [SignatureAlgorithm::RsaSha1].into(),
        key_sources: vec![KeySourceKind::KeyValue],
        reference_uri_classes: vec![UriClass::External],
        ..Denials::default()
    };
    let denied = compiler(PolicyProfile::XadesConformant)
        .deny(&denials)
        .unwrap()
        .compile(&context())
        .unwrap();
    let full = compiler(PolicyProfile::XadesConformant)
        .compile(&context())
        .unwrap();
    let verification = denied.verification().unwrap();
    let transforms = verification.transforms.allowed_algorithms.clone().unwrap();
    assert!(!transforms.contains(FILTER2));
    assert!(transforms.contains(XPATH));
    assert!(
        verification
            .check_signature_algorithm(SignatureAlgorithm::RsaSha1)
            .is_err()
    );
    assert_eq!(
        verification.check_signature_algorithm(SignatureAlgorithm::DsaSha1),
        Ok(())
    );
    assert!(!verification.key_sources.contains(KeySourceKind::KeyValue));
    assert!(verification.key_sources.contains(KeySourceKind::X509Data));
    assert!(!verification.uris.references.allows("external.xml"));
    let signing = denied.signing().unwrap();
    assert!(
        !signing
            .transforms
            .allowed_algorithms
            .as_ref()
            .unwrap()
            .contains(FILTER2)
    );
    // Everything not named is unchanged.
    let mut expected = full.verification().unwrap().clone();
    expected.transforms.allowed_algorithms = Some(transforms);
    expected.denied_signature_algorithms = [SignatureAlgorithm::RsaSha1].into();
    // Composition keeps only what both layers admit, so the list drops it too.
    if let Some(methods) = expected.signature_algorithms.as_mut() {
        methods.remove(&SignatureAlgorithm::RsaSha1);
    }
    expected.key_sources.remove(KeySourceKind::KeyValue);
    expected.uris.references = verification.uris.references;
    assert_eq!(format!("{verification:?}"), format!("{expected:?}"));
}

/// An RSA-PSS method over SHA-256 with `salt_len` octets of salt.
fn pss(salt_len: usize) -> SignatureAlgorithm {
    SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters {
        salt_len,
        ..xml_sec::xmldsig::RsaPssParameters::DEFAULT
    })
}

#[test]
fn a_denied_signature_method_wins_over_every_grant() {
    // A denial withdraws the method its URI names (RFC 9231 2.3.10: the
    // RSA-PSS URI carries its parameters in the element), in every
    // parameterization and through the profile's RSA-PSS family grant, in
    // signing and verification alike. Other methods stay admitted.
    use xml_sec::policy::Denials;
    let denied = compiler(PolicyProfile::Modern)
        .deny(&Denials {
            signature_algorithms: [pss(32)].into(),
            ..Denials::default()
        })
        .unwrap()
        .compile(&context())
        .unwrap();
    let (verification, signing) = (denied.verification().unwrap(), denied.signing().unwrap());
    for method in [pss(32), pss(20)] {
        assert!(
            verification.check_signature_algorithm(method).is_err(),
            "{method:?}"
        );
        assert!(
            signing.check_signature_algorithm(method).is_err(),
            "{method:?}"
        );
    }
    assert_eq!(
        verification.check_signature_algorithm(SignatureAlgorithm::RsaSha256),
        Ok(())
    );
    assert_eq!(
        signing.check_signature_algorithm(SignatureAlgorithm::RsaSha256),
        Ok(())
    );
}

#[test]
fn a_denial_keeps_every_method_it_does_not_name() {
    // Without an explicit list a policy admits RSA-PSS tuples no fixed list
    // holds, such as a 20-octet salt; denying another method keeps them.
    use xml_sec::policy::{Denials, RsaPssPermission};
    let mut open = compiler(PolicyProfile::Modern).policies().clone();
    if let Some(verification) = open.verification.as_mut() {
        verification.signature_algorithms = None;
        verification.parameterized_rsa_pss = RsaPssPermission::ExactOnly;
    }
    if let Some(signing) = open.signing.as_mut() {
        signing.signature_algorithms = None;
        signing.parameterized_rsa_pss = RsaPssPermission::ExactOnly;
    }
    let kept = PolicyCompiler::from_policies(PolicyProfile::Modern, &RustCryptoProvider, open)
        .deny(&Denials {
            signature_algorithms: [SignatureAlgorithm::RsaSha1].into(),
            ..Denials::default()
        })
        .unwrap()
        .compile(&context())
        .unwrap();
    assert_eq!(
        kept.verification()
            .unwrap()
            .check_signature_algorithm(pss(20)),
        Ok(())
    );
    assert_eq!(
        kept.signing().unwrap().check_signature_algorithm(pss(20)),
        Ok(())
    );
}

#[test]
fn the_conformant_profile_admits_rsa_pss_down_to_sha1_only() {
    // XadesConformant adds SHA-1 signatures, not MD5 or RIPEMD-160: its
    // RSA-PSS family grant stops at SHA-1 for the message and MGF1 digests.
    use xml_sec::xmldsig::{DigestAlgorithm, RsaPssParameters};
    let compiled = compiler(PolicyProfile::XadesConformant)
        .compile(&context())
        .unwrap();
    let verification = compiled.verification().unwrap();
    let with = |digest| {
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            digest,
            mgf_digest: digest,
            salt_len: 20,
        })
    };
    assert_eq!(
        verification.check_signature_algorithm(with(DigestAlgorithm::Sha256)),
        Ok(())
    );
    assert_eq!(
        verification.check_signature_algorithm(with(DigestAlgorithm::Sha1)),
        Ok(())
    );
    #[cfg(feature = "legacy-algorithms")]
    for digest in [DigestAlgorithm::Md5, DigestAlgorithm::Ripemd160] {
        assert!(
            verification
                .check_signature_algorithm(with(digest))
                .is_err(),
            "{digest:?}"
        );
    }
}

#[test]
#[cfg(feature = "dstu4145")]
fn no_rsa_pss_family_grant_admits_a_digest_that_needs_its_own_permission() {
    // GOST 34.311 and DSTU 7564 need an explicit digest permission; neither
    // the secure nor the SHA-1 RSA-PSS family grant may admit them, so the
    // grants stay ordered SecureSupported < Sha1Supported under composition.
    use xml_sec::xmldsig::{DigestAlgorithm, RsaPssParameters};
    for profile in [PolicyProfile::Modern, PolicyProfile::XadesConformant] {
        let compiled = compiler(profile).compile(&context()).unwrap();
        let verification = compiled.verification().unwrap();
        for digest in [DigestAlgorithm::Gost34311, DigestAlgorithm::Dstu7564_256] {
            let method = SignatureAlgorithm::RsaPss(RsaPssParameters {
                digest,
                mgf_digest: digest,
                salt_len: 32,
            });
            assert!(
                verification.check_signature_algorithm(method).is_err(),
                "{profile:?} {digest:?}"
            );
        }
    }
}

#[test]
fn a_denial_never_grants_and_reaches_absent_allowlists() {
    // Denying what a profile already refuses changes nothing. A profile that
    // admits every implemented transform (no allowlist) still loses exactly
    // the denied one, so signing with it is a typed policy refusal.
    use xml_sec::policy::Denials;
    const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    let absent = Denials {
        transforms: ["http://www.w3.org/TR/1999/REC-xslt-19991116".to_owned()].into(),
        ..Denials::default()
    };
    let unchanged = compiler(PolicyProfile::Xades)
        .deny(&absent)
        .unwrap()
        .compile(&context())
        .unwrap();
    let strict = compiler(PolicyProfile::Xades).compile(&context()).unwrap();
    assert_eq!(
        format!("{:?}", unchanged.verification()),
        format!("{:?}", strict.verification())
    );
    let compatible = compiler(PolicyProfile::XmlSecCompatible)
        .deny(&Denials {
            transforms: [XPATH.to_owned()].into(),
            ..Denials::default()
        })
        .unwrap()
        .compile(&context())
        .unwrap();
    let verification = compatible.verification().unwrap();
    let transforms = verification.transforms.allowed_algorithms.as_ref().unwrap();
    assert!(!transforms.contains(XPATH));
    assert!(transforms.contains("http://www.w3.org/2000/09/xmldsig#base64"));
    assert!(transforms.contains("http://www.w3.org/2002/06/xmldsig-filter2"));
    let key = HmacSigningKey::new(vec![0x53; 32]).unwrap();
    let refused = SignContext::new(&key)
        .policy(compatible.signing().unwrap().clone())
        .sign_template(&xades_with_object_reference(XPATH));
    assert!(
        matches!(
            refused,
            Err(xml_sec::xmldsig::SigningError::Policy(PolicyViolation::Algorithm { ref algorithm, .. }))
                if algorithm == XPATH
        ),
        "{refused:?}"
    );
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
