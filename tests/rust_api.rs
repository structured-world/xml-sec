//! Public facade contracts: real crypto, policy boundaries and document provenance.
#![cfg(feature = "xmldsig-sign")]

use std::sync::Arc;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{
    CompiledPolicies, PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicySet,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::provider::{
    CryptoProvider, DigestState, ExternalProviderError, KdfParameters, ProviderCapability,
    ProviderError,
};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, FailureReason, HmacSigningKey, HmacVerificationKey,
    ReferenceBuilder, SignatureAlgorithm, SignatureBuilder, Transform, VerificationRequest,
};
use xml_sec::{SharedSecurity, XmlDocument, XmlSecError, XmlSecurity, api::Operation};

fn policies() -> CompiledPolicies {
    PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None)
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        })
        .unwrap()
}

// Test-only engine: advertised capabilities can disappear, or execution can
// refuse after compilation. No cryptographic operation may fall back elsewhere.
struct RefusingProvider {
    available: bool,
}

fn refusal() -> ProviderError {
    ProviderError::External(ExternalProviderError::Operation)
}

impl CryptoProvider for RefusingProvider {
    fn name(&self) -> &'static str {
        "facade-refusal"
    }
    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        self.available && RustCryptoProvider.supports(capability)
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), ProviderError> {
        Err(refusal())
    }
    fn derive_key(&self, _: &KdfParameters<'_>, _: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    fn begin_digest(
        &self,
        _: DigestAlgorithm,
        _: &structured_asn1::memory::Memory,
    ) -> Result<Box<dyn DigestState + '_>, ProviderError> {
        Err(refusal())
    }
    fn sign(
        &self,
        _: &dyn xml_sec::xmldsig::SigningKey,
        _: SignatureAlgorithm,
        _: &[u8],
    ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
        Err(refusal().into())
    }
    fn verify(
        &self,
        _: &dyn xml_sec::xmldsig::VerifyingKey,
        _: SignatureAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> Result<bool, xml_sec::xmldsig::DsigError> {
        Err(refusal().into())
    }
    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        _: xml_sec::xmlenc::DataEncryptionAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        _: xml_sec::xmlenc::DataEncryptionAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        _: xml_sec::xmlenc::KeyWrapAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        _: xml_sec::xmlenc::KeyWrapAlgorithm,
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        _: &dyn xml_sec::provider::KeyTransportKey,
        _: &xml_sec::xmlenc::RsaOaepParameters,
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        _: &dyn xml_sec::provider::KeyRecoveryKey,
        _: &xml_sec::xmlenc::RsaOaepParameters,
        _: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(refusal())
    }
}

#[test]
fn request_handles_outlive_the_temporary_facade() {
    // Handles borrow the actual policy/provider and request inputs, not the
    // facade value. Using them on the next statement catches an accidental
    // receiver lifetime constraint at compile time and verifies real execution.
    let compiled = policies();
    let provider = RustCryptoProvider;
    let key = HmacSigningKey::new(vec![7; 32]).unwrap();
    let signer = XmlSecurity::new(&compiled, &provider)
        .unwrap()
        .signer(&key)
        .unwrap();
    let document = signer
        .sign_xml("<root><p Id='payload'>secret</p></root>", &builder())
        .unwrap()
        .output;
    let verify_key = HmacVerificationKey::new(vec![7; 32]).unwrap();
    let api = XmlSecurity::new(&compiled, &provider).unwrap();
    assert_eq!(
        api.verifier()
            .unwrap()
            .key(&verify_key)
            .verify_signature_xml(&document)
            .unwrap()
            .status,
        DsigStatus::Valid
    );

    #[cfg(feature = "xmlenc")]
    {
        use xml_sec::xmlenc::{
            DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataBuilder,
            SymmetricKeyDecryptor,
        };
        let builder =
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).direct_key(vec![9; 16]);
        let encryptor = XmlSecurity::new(&compiled, &provider)
            .unwrap()
            .encryptor(&builder)
            .unwrap();
        let encrypted = encryptor
            .encrypt_xml("<root>secret</root>", DocumentEncryptionOptions::default())
            .unwrap()
            .output;
        let resolver = SymmetricKeyDecryptor::new(vec![9; 16]);
        let decryptor = XmlSecurity::new(&compiled, &provider)
            .unwrap()
            .decryptor(&resolver)
            .unwrap();
        assert_eq!(
            decryptor.decrypt_xml(&encrypted, None).unwrap().output,
            "<root>secret</root>"
        );
    }
}

#[test]
fn every_operation_reports_the_identity_of_the_snapshot_it_enforced() {
    // An audit must name the published policy the operation actually used;
    // losing the identity anywhere between the facade and the result would
    // leave evidence that cannot be tied to a configuration revision.
    use xml_sec::policy::PolicyIdentity;
    let identity = PolicyIdentity::new("modern", 1, 7, [0x5a; 32]);
    let compiled = policies().with_identity(identity.clone());
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let sign_key = HmacSigningKey::new(vec![8; 32]).unwrap();
    let signed = api
        .signer(&sign_key)
        .unwrap()
        .sign_xml("<root><p Id='payload'>secret</p></root>", &builder())
        .unwrap();
    assert_eq!(signed.policy.identity.as_deref(), Some(&identity));
    assert!(
        signed
            .policy
            .decisions
            .contains(&xml_sec::policy::PolicyDecision::Algorithm {
                role: xml_sec::policy::AlgorithmRole::Signature,
                uri: SignatureAlgorithm::HmacSha256.uri().into(),
            })
    );
    let verify_key = HmacVerificationKey::new(vec![8; 32]).unwrap();
    let verified = api
        .verifier()
        .unwrap()
        .key(&verify_key)
        .verify_signature_xml(&signed.output)
        .unwrap();
    assert_eq!(verified.status, DsigStatus::Valid);
    assert_eq!(verified.policy.identity.as_deref(), Some(&identity));
    // Verification permits exactly what signing permitted for this signature.
    assert_eq!(verified.policy.decisions, signed.policy.decisions);

    #[cfg(feature = "xmlenc")]
    {
        use xml_sec::xmlenc::{
            DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataBuilder,
            SymmetricKeyDecryptor,
        };
        let builder =
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).direct_key(vec![2; 16]);
        let encrypted = api
            .encryptor(&builder)
            .unwrap()
            .encrypt_xml("<root>secret</root>", DocumentEncryptionOptions::default())
            .unwrap();
        assert_eq!(encrypted.policy.identity.as_deref(), Some(&identity));
        let resolver = SymmetricKeyDecryptor::new(vec![2; 16]);
        let decrypted = api
            .decryptor(&resolver)
            .unwrap()
            .decrypt_xml(&encrypted.output, None)
            .unwrap();
        assert_eq!(decrypted.output, "<root>secret</root>");
        assert_eq!(decrypted.policy.identity.as_deref(), Some(&identity));
        assert_eq!(decrypted.policy.decisions, encrypted.policy.decisions);
    }
}

#[test]
fn batch_verification_audits_every_signature_and_the_operation() {
    // A signature that fails is still part of the operation: its refusal and
    // the snapshot that refused it belong in the audit, and a document with
    // no signature at all still reports which snapshot examined it.
    use xml_sec::policy::{PolicyDecision, PolicyIdentity, PolicyViolation, SigningPolicy};
    use xml_sec::xmldsig::SignContext;
    let identity = PolicyIdentity::new("modern", 1, 9, [0x3c; 32]);
    let compiled = policies().with_identity(identity.clone());
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let key = HmacSigningKey::new(vec![8; 32]).unwrap();
    let reference = |id: &str, algorithm| {
        SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(format!("#{id}")))
    };
    let first = api
        .signer(&key)
        .unwrap()
        .sign_xml(
            "<root><p Id='first'>one</p><p Id='second'>two</p></root>",
            &reference("first", SignatureAlgorithm::HmacSha256),
        )
        .unwrap()
        .output;
    // A SHA-1 signature the modern verification profile refuses.
    let both = SignContext::new(&key)
        .policy(SigningPolicy {
            signature_algorithms: Some([SignatureAlgorithm::HmacSha1].into()),
            ..SigningPolicy::default()
        })
        .sign_with_builder(&first, &reference("second", SignatureAlgorithm::HmacSha1))
        .unwrap()
        .output;
    let verify_key = HmacVerificationKey::new(vec![8; 32]).unwrap();
    let verifier = api.verifier().unwrap().key(&verify_key);
    let document = api.parse_document(both, Operation::Verify).unwrap();
    let evidence = verifier
        .verify(&document, &VerificationRequest::default())
        .unwrap();
    assert_eq!(evidence.policy_identity(), Some(&identity));
    let [valid, refused] = evidence.signatures() else {
        panic!("two signatures")
    };
    assert_eq!(valid.result().as_ref().unwrap().status, DsigStatus::Valid);
    assert_eq!(valid.policy(), &valid.result().as_ref().unwrap().policy);
    assert!(refused.result().is_err());
    assert_eq!(refused.policy().identity.as_deref(), Some(&identity));
    assert!(
        refused.policy().decisions.iter().any(|decision| matches!(
            decision,
            PolicyDecision::Rejected(PolicyViolation::Algorithm { algorithm, .. })
                if algorithm == SignatureAlgorithm::HmacSha1.uri()
        )),
        "{:?}",
        refused.policy()
    );

    let unsigned = api.parse_document("<root/>", Operation::Verify).unwrap();
    let evidence = verifier
        .verify(&unsigned, &VerificationRequest::default())
        .unwrap();
    assert!(evidence.signatures().is_empty());
    assert_eq!(evidence.policy_identity(), Some(&identity));
}

#[test]
fn capability_mismatch_is_rejected_when_binding_the_real_provider() {
    // Compilation with one provider cannot authorize an unavailable engine.
    let compiled = policies();
    assert!(matches!(
        XmlSecurity::new(&compiled, &RefusingProvider { available: false }),
        Err(XmlSecError::Policy(_))
    ));
}

#[test]
fn a_shared_binding_is_validated_once_and_serves_every_thread() {
    // An owned binding outlives the borrow the facade needs; operations from
    // any thread run under its one validated snapshot and provider, and an
    // engine that cannot satisfy the policy is refused when binding.
    let shared = SharedSecurity::new(Arc::new(policies()), Arc::new(RustCryptoProvider)).unwrap();
    let key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let signed = shared
        .binding()
        .signer(&key)
        .unwrap()
        .sign_xml("<root><p Id='payload'>signed</p></root>", &builder())
        .unwrap()
        .output;
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let key = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
                let binding = shared.binding();
                let verifier = binding.verifier().unwrap().key(&key);
                assert_eq!(
                    verifier.verify_signature_xml(&signed).unwrap().status,
                    DsigStatus::Valid
                );
            });
        }
    });
    assert!(matches!(
        SharedSecurity::new(
            Arc::new(policies()),
            Arc::new(RefusingProvider { available: false })
        ),
        Err(XmlSecError::Policy(_))
    ));
}

#[cfg(feature = "xmlenc")]
#[test]
fn bound_encryption_never_uses_the_builder_provider_or_a_weaker_policy() {
    // Refusal and stricter admission must happen before any document commit.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataBuilder, XmlEncError,
    };
    let compiled = policies();
    let rejecting = RefusingProvider { available: true };
    let api = XmlSecurity::new(&compiled, &rejecting).unwrap();
    let builder =
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).direct_key(vec![5; 16]);
    let mut document = api
        .parse_document("<root>secret</root>", Operation::Encrypt)
        .unwrap();
    assert!(matches!(
        api.encryptor(&builder)
            .unwrap()
            .encrypt(&mut document, DocumentEncryptionOptions::default()),
        Err(XmlSecError::Encryption(XmlEncError::Provider(
            ProviderError::External(ExternalProviderError::Operation)
        )))
    ));
    assert_eq!(document.as_xml(), "<root>secret</root>");
    assert_eq!(document.generation(), 0);
    let profile = PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None).unwrap();
    let mut restrictive = profile.policies().clone();
    restrictive
        .encryption
        .as_mut()
        .unwrap()
        .resources
        .max_encryption_plaintext_bytes = 1;
    let compiled = profile
        .restrict(&restrictive)
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        })
        .unwrap();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    assert!(matches!(
        api.encryptor(&builder).unwrap().encrypt_binary(b"too long"),
        Err(XmlSecError::Encryption(XmlEncError::Policy(_)))
    ));
}

fn builder() -> SignatureBuilder {
    SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(C14nAlgorithm::new(
                C14nMode::Exclusive1_0,
                false,
            ))),
    )
}

#[test]
fn the_audit_names_the_implicit_canonicalization_a_reference_digests_with() {
    // A same-document Reference without a canonicalizing transform is digested
    // through inclusive C14N 1.0; signing and verification audits name it
    // like any explicit transform the policy admitted.
    use xml_sec::policy::{AlgorithmRole, PolicyAudit, PolicyDecision};
    use xml_sec::xmldsig::DEFAULT_IMPLICIT_C14N_URI;
    let names_implicit = |audit: &PolicyAudit| {
        audit.decisions.iter().any(|decision| {
            matches!(
                decision,
                PolicyDecision::Algorithm { role: AlgorithmRole::Transform, uri }
                    if uri == DEFAULT_IMPLICIT_C14N_URI
            )
        })
    };
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    // A received Reference without Transforms; the values need not verify,
    // the audit records what the policy admitted before digesting.
    let received = |value: &str| {
        format!(
            "<root><p Id='payload'>signed</p>\
             <ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo>\
             <ds:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>\
             <ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'/>\
             <ds:Reference URI='#payload'>\
             <ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>\
             <ds:DigestValue>{value}</ds:DigestValue></ds:Reference></ds:SignedInfo>\
             <ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature></root>"
        )
    };
    let verify_key = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
    let result = api
        .verifier()
        .unwrap()
        .key(&verify_key)
        .verify_signature_xml(&received("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
        .unwrap();
    assert_ne!(result.status, DsigStatus::Valid);
    assert!(names_implicit(&result.policy));
    // Signing such a template generates an explicit C14N 1.1 transform, so
    // nothing is applied implicitly and the audit names the explicit one.
    let key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let signed = api
        .signer(&key)
        .unwrap()
        .sign_template_xml(&received(""))
        .unwrap();
    assert!(!names_implicit(&signed.policy));
    assert!(signed.policy.decisions.iter().any(|decision| matches!(
        decision,
        PolicyDecision::Algorithm { role: AlgorithmRole::Transform, uri }
            if uri == "http://www.w3.org/2006/12/xml-c14n11"
    )));
}

#[test]
fn retained_evidence_authenticates_only_the_requested_generation_and_target() {
    // Mathematical success cannot authorize an unsigned sibling or mutated document.
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let sign_key = HmacSigningKey::new(vec![0x31; 32]).unwrap();
    let verify_key = HmacVerificationKey::new(vec![0x31; 32]).unwrap();
    let mut document = api
        .parse_document(
            "<root><p Id='payload'>signed</p><p Id='decoy'>unsigned</p></root>",
            Operation::Sign,
        )
        .unwrap();
    api.signer(&sign_key)
        .unwrap()
        .sign(&mut document, &builder())
        .unwrap();
    let target = document.with_view(|v| v.node_for_id("payload", &[]).unwrap());
    let decoy = document.with_view(|v| v.node_for_id("decoy", &[]).unwrap());
    let verifier = api.verifier().unwrap().key(&verify_key);
    let evidence = verifier
        .verify(
            &document,
            &VerificationRequest {
                expected_targets: &[target],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    let wrong = verifier
        .verify(
            &document,
            &VerificationRequest {
                expected_targets: &[decoy],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(wrong.all_valid());
    assert!(!wrong.accepted(&document).unwrap());
    let foreign = XmlDocument::parse(document.as_xml()).unwrap();
    assert!(evidence.accepted(&foreign).is_err());
    document
        .replace_element(decoy, "<p Id='decoy'>changed</p>")
        .unwrap();
    assert!(evidence.accepted(&document).is_err());
}

#[test]
fn borrowed_string_and_template_paths_share_the_existing_crypto_pipeline() {
    // No facade parse or budget reset may change the low-level string operation.
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let sign_key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let verify_key = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
    let xml = "<root><p Id='payload'>signed</p></root>";
    let signer = api.signer(&sign_key).unwrap();
    let document = signer.sign_xml(xml, &builder()).unwrap().output;
    let verifier = api.verifier().unwrap().key(&verify_key);
    assert_eq!(
        verifier.verify_signature_xml(&document).unwrap().status,
        DsigStatus::Valid
    );
    let invalid = document.replace("signed</p>", "altered</p>");
    assert_ne!(
        verifier.verify_signature_xml(&invalid).unwrap().status,
        DsigStatus::Valid
    );
    assert!(matches!(
        verifier.verify_signature_xml("<broken"),
        Err(XmlSecError::Verification(_))
    ));
    let template = builder().build_template().unwrap();
    let templated = format!("<root><p Id='payload'>signed</p>{template}</root>");
    let signed_template = signer.sign_template_xml(&templated).unwrap().output;
    assert_eq!(
        verifier
            .verify_signature_xml(&signed_template)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
    let mut retained = api.parse_document(templated, Operation::Sign).unwrap();
    signer.sign_template(&mut retained).unwrap();
    assert!(
        verifier
            .verify(&retained, &VerificationRequest::default())
            .unwrap()
            .accepted(&retained)
            .unwrap()
    );
}

#[test]
fn disabled_operations_refuse_before_parsing_or_key_lookup() {
    // Disabled capabilities cannot be recovered through convenience entry points.
    let compiled = PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None)
        .unwrap()
        .restrict(&PolicySet::default())
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: false,
            target_evidence: false,
        })
        .unwrap();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let key = HmacSigningKey::new(vec![1; 32]).unwrap();
    assert!(matches!(
        api.verifier(),
        Err(XmlSecError::OperationDisabled(Operation::Verify))
    ));
    assert!(matches!(
        api.signer(&key),
        Err(XmlSecError::OperationDisabled(Operation::Sign))
    ));
    assert!(matches!(
        api.parse_document("<broken", Operation::Verify),
        Err(XmlSecError::OperationDisabled(Operation::Verify))
    ));
    let inventory = xml_sec::key_manager::KeyInventory::default();
    assert!(matches!(
        api.signing_key(&inventory, "missing", SignatureAlgorithm::HmacSha256),
        Err(XmlSecError::OperationDisabled(Operation::Sign))
    ));
    #[cfg(feature = "xmlenc")]
    {
        use xml_sec::xmlenc::{
            DataEncryptionAlgorithm, EncryptedDataBuilder, SymmetricKeyDecryptor,
        };
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm);
        let resolver = SymmetricKeyDecryptor::new(vec![0; 16]);
        assert!(matches!(
            api.encryptor(&builder),
            Err(XmlSecError::OperationDisabled(Operation::Encrypt))
        ));
        assert!(matches!(
            api.decryptor(&resolver),
            Err(XmlSecError::OperationDisabled(Operation::Decrypt))
        ));
        assert!(matches!(
            api.decryption_key(&inventory, "missing"),
            Err(XmlSecError::OperationDisabled(Operation::Decrypt))
        ));
    }
}

#[test]
fn empty_inventory_keeps_its_original_typed_selection_error() {
    // API errors must preserve the key-store cause instead of formatting it away.
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let inventory = xml_sec::key_manager::KeyInventory::default();
    assert!(matches!(
        api.signing_key(&inventory, "missing", SignatureAlgorithm::HmacSha256),
        Err(XmlSecError::KeyStore(_))
    ));
    #[cfg(feature = "xmlenc")]
    assert!(matches!(
        api.decryption_key(&inventory, "missing"),
        Err(XmlSecError::KeyStore(_))
    ));
}

#[test]
fn facade_is_shareable_without_extending_caller_key_lifetimes() {
    // Only immutable configuration is shared; each short-lived request owns its key scope.
    fn shareable<T: Send + Sync>() {}
    shareable::<XmlSecurity<'static>>();
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    {
        let key = HmacSigningKey::new(vec![8; 32]).unwrap();
        api.signer(&key)
            .unwrap()
            .sign_xml("<root><p Id='payload'>ok</p></root>", &builder())
            .unwrap();
    }
    assert!(api.verifier().is_ok());
}

#[test]
fn named_inventory_uses_the_same_policy_and_verification_resolver() {
    // Named key selection must work end to end, not only return an opaque handle.
    use xml_sec::key_manager::{KeyInventory, KeyUsages, SymmetricKeyKind};
    struct Name;
    impl xml_sec::xmldsig::KeyInfoWriter for Name {
        fn write_key_info(
            &self,
            _: &dyn xml_sec::xmldsig::SigningKey,
        ) -> Result<String, xml_sec::xmldsig::KeyInfoWriteError> {
            Ok("<KeyName>trusted</KeyName>".into())
        }
    }
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let mut inventory = KeyInventory::default();
    let resources = &compiled.signing().unwrap().resources;
    inventory
        .add_symmetric(
            "trusted".into(),
            SymmetricKeyKind::Hmac,
            vec![7; 32],
            KeyUsages::SIGN.union(KeyUsages::VERIFY),
            resources,
        )
        .unwrap();
    let key = api
        .signing_key(&inventory, "trusted", SignatureAlgorithm::HmacSha256)
        .unwrap();
    let mut document = api
        .parse_document("<root><p Id='payload'>ok</p></root>", Operation::Sign)
        .unwrap();
    let original = document.as_xml().to_owned();
    assert!(matches!(
        api.signer(key.as_ref())
            .unwrap()
            .key_info_writer(&Name)
            .sign(&mut document, &builder()),
        Err(XmlSecError::Signing(_))
    ));
    assert_eq!(document.as_xml(), original);
    assert_eq!(document.generation(), 0);
    api.signer(key.as_ref())
        .unwrap()
        .key_info_writer(&Name)
        .sign(&mut document, &builder().key_info(true))
        .unwrap();
    let resolver = inventory.verification_resolver();
    let evidence = api
        .verifier()
        .unwrap()
        .key_resolver(&resolver)
        .verify(&document, &VerificationRequest::default())
        .unwrap();
    assert!(evidence.accepted(&document).unwrap());
    #[cfg(feature = "xmlenc")]
    {
        use xml_sec::xmlenc::{DataEncryptionAlgorithm, EncryptedDataBuilder};
        inventory
            .add_symmetric(
                "content".into(),
                SymmetricKeyKind::Aes,
                vec![9; 16],
                KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT),
                resources,
            )
            .unwrap();
        let key = api.decryption_key(&inventory, "content").unwrap();
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(vec![9; 16])
            .direct_key_name("content");
        let encrypted = api
            .encryptor(&builder)
            .unwrap()
            .encrypt_binary(b"inventory")
            .unwrap();
        assert!(
            matches!(api.decryptor(key.as_ref()).unwrap().decrypt_fragment(&encrypted.encrypted_data_xml).unwrap().output, xml_sec::xmlenc::DecryptedContent::Bytes(value) if value == b"inventory")
        );
    }
}

#[test]
fn request_ids_template_selection_and_owned_input_reach_each_backend() {
    // Scope/ID helpers must affect the actual selected template and target;
    // moving an owned input must not add another source-text allocation.
    use xml_sec::xmldsig::{SignatureRequirement, SignatureTemplateSelection};
    let compiled = policies();
    let sign_key = HmacSigningKey::new(vec![3; 32]).unwrap();
    let verify_key = HmacVerificationKey::new(vec![3; 32]).unwrap();
    let attrs = [xml_sec::IdAttributeRegistration::global("Token")];
    let facts =
        structured_pkix::temporal::LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).unwrap();
    for backend in xml_sec::XmlBackend::available() {
        let api = XmlSecurity::new(&compiled, &RustCryptoProvider)
            .unwrap()
            .xml_backend(backend);
        let first = builder().signature_id("first").build_template().unwrap();
        let second = builder().signature_id("second").build_template().unwrap();
        let xml = format!(
            "<root><scope Id='scope'><p Token='payload'>ok</p>{first}{second}</scope></root>"
        );
        let source_address = xml.as_ptr();
        let mut document = api.parse_document(xml, Operation::Sign).unwrap();
        assert_eq!(document.as_xml().as_ptr(), source_address);
        assert_eq!(document.xml_backend(), backend);
        api.signer(&sign_key)
            .unwrap()
            .id_attributes(&attrs)
            .start_node_id("scope")
            .template_selection(SignatureTemplateSelection::FirstDescendant)
            .sign_template(&mut document)
            .unwrap();
        let target = document.with_view(|v| v.node_for_id("payload", &attrs).unwrap());
        let first = document.with_view(|v| v.node_for_id("first", &attrs).unwrap());
        let verifier = api
            .verifier()
            .unwrap()
            .key(&verify_key)
            .id_attributes(&attrs)
            .utc_facts(facts);
        let evidence = verifier
            .verify(
                &document,
                &VerificationRequest {
                    expected_targets: &[target],
                    signatures: SignatureRequirement::AtLeast(1),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(evidence.accepted(&document).unwrap());
        assert_eq!(evidence.signatures().len(), 2);
        for signature in evidence.signatures() {
            if signature.identity() == first {
                assert_eq!(
                    signature.result().as_ref().unwrap().status,
                    DsigStatus::Valid
                );
            } else {
                assert!(
                    !matches!(signature.result(), Ok(result) if result.status == DsigStatus::Valid)
                );
            }
        }
    }
}

fn external_policies() -> CompiledPolicies {
    use std::time::SystemTime;
    use xml_sec::policy::{Instant, PolicyValidity, instant_from_system_time};
    use xml_sec::xmldsig::UriTypeSet;
    let compiler = PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None).unwrap();
    let mut replacement = compiler.policies().clone();
    replacement.signing.as_mut().unwrap().uris.references = UriTypeSet::ALL;
    replacement.verification.as_mut().unwrap().uris.references = UriTypeSet::ALL;
    #[cfg(feature = "xmlenc")]
    {
        replacement.decryption.as_mut().unwrap().uris.references = UriTypeSet::ALL;
    }
    let now = instant_from_system_time(SystemTime::now()).unwrap();
    compiler
        .authorize_replacement(
            replacement,
            &PolicyValidity {
                authorization_id: "offline-input-test".into(),
                authority: "test caller".into(),
                reason: "caller-supplied detached bytes".into(),
                not_before: now,
                expires_at: Instant::new(now.seconds() + 3600, now.nanos()).unwrap(),
            },
        )
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: true,
            target_evidence: true,
        })
        .unwrap()
}

#[test]
fn detached_signatures_use_only_request_supplied_external_bytes() {
    // Explicit URI permission does not imply discovery; omitted or changed
    // caller input must not authenticate the original detached reference.
    let compiled = external_policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let sign_key = HmacSigningKey::new(vec![4; 32]).unwrap();
    let verify_key = HmacVerificationKey::new(vec![4; 32]).unwrap();
    let inputs =
        std::collections::BTreeMap::from([("urn:test:input".into(), b"detached bytes".to_vec())]);
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("urn:test:input"));
    let signed = api
        .signer(&sign_key)
        .unwrap()
        .external_resources(&inputs)
        .sign_xml("<root/>", &builder)
        .unwrap()
        .output;
    let document = api.parse_document(signed, Operation::Verify).unwrap();
    let verifier = api.verifier().unwrap().key(&verify_key);
    assert!(
        verifier
            .verify(
                &document,
                &VerificationRequest {
                    external_resources: Some(&inputs),
                    ..Default::default()
                }
            )
            .unwrap()
            .accepted(&document)
            .unwrap()
    );
    let absent = verifier
        .verify(&document, &VerificationRequest::default())
        .unwrap();
    assert!(!absent.accepted(&document).unwrap());
    // Omitted caller input is the Reference's own Unavailable outcome.
    let absent_result = absent.signatures()[0]
        .result()
        .as_ref()
        .expect("unsupplied bytes are a verification status");
    assert_eq!(
        absent_result.status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 0 })
    );
    let changed =
        std::collections::BTreeMap::from([("urn:test:input".into(), b"changed bytes".to_vec())]);
    assert!(
        !verifier
            .verify(
                &document,
                &VerificationRequest {
                    external_resources: Some(&changed),
                    ..Default::default()
                }
            )
            .unwrap()
            .accepted(&document)
            .unwrap()
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn recovery_request_ids_and_external_ciphertext_are_not_implicit() {
    // Same-document references need the caller's ID registration, and detached
    // ciphertext needs both compiled URI permission and the supplied map.
    use base64::Engine;
    use xml_sec::xmlenc::{
        CipherData, DataEncryptionAlgorithm, DecryptedContent, EncryptedDataBuilder,
        SymmetricKeyDecryptor, parse_encrypted_data,
    };
    let compiled = external_policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(vec![6; 16])
        .id("encrypted");
    let encrypted = api
        .encryptor(&builder)
        .unwrap()
        .encrypt_fragment("<p>secret</p>")
        .unwrap()
        .encrypted_data_xml;
    let resolver = SymmetricKeyDecryptor::new(vec![6; 16]);
    let attrs = [xml_sec::IdAttributeRegistration::global("Token")];
    let CipherData::Value { value } = parse_encrypted_data(&encrypted).unwrap().cipher_data else {
        panic!("generated embedded ciphertext")
    };
    let reference = format!(
        "<x:EncryptedData xmlns:x='http://www.w3.org/2001/04/xmlenc#' Id='encrypted' Type='http://www.w3.org/2001/04/xmlenc#Element'><x:EncryptionMethod Algorithm='{}'/><x:CipherData><x:CipherReference URI='#cipher'><x:Transforms><d:Transform xmlns:d='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/2000/09/xmldsig#base64'/></x:Transforms></x:CipherReference></x:CipherData></x:EncryptedData>",
        DataEncryptionAlgorithm::Aes128Gcm.uri()
    );
    let wire = format!("<root>{reference}<cipher Token='cipher'>{value}</cipher></root>");
    let mut document = api
        .parse_document(wire.clone(), Operation::Decrypt)
        .unwrap();
    assert!(
        api.decryptor(&resolver)
            .unwrap()
            .decrypt(&mut document, Some("encrypted"))
            .is_err()
    );
    assert_eq!(document.as_xml(), wire);
    assert_eq!(document.generation(), 0);
    api.decryptor(&resolver)
        .unwrap()
        .id_attributes(&attrs)
        .decrypt(&mut document, Some("encrypted"))
        .unwrap();
    assert_eq!(
        document.as_xml(),
        format!("<root><p>secret</p><cipher Token='cipher'>{value}</cipher></root>")
    );
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap();
    let inputs = std::collections::BTreeMap::from([("urn:test:cipher".into(), ciphertext)]);
    let detached = format!(
        "<x:EncryptedData xmlns:x='http://www.w3.org/2001/04/xmlenc#'><x:EncryptionMethod Algorithm='{}'/><x:CipherData><x:CipherReference URI='urn:test:cipher'/></x:CipherData></x:EncryptedData>",
        DataEncryptionAlgorithm::Aes128Gcm.uri()
    );
    assert!(
        api.decryptor(&resolver)
            .unwrap()
            .decrypt_fragment(&detached)
            .is_err()
    );
    assert!(
        matches!(api.decryptor(&resolver).unwrap().external_resources(&inputs).decrypt_fragment(&detached).unwrap().output, DecryptedContent::Bytes(value) if value == b"<p>secret</p>")
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn retained_and_string_encryption_preserve_one_generation_and_rollback() {
    // Bound execution ignores a builder-local resource policy and does not clone its secret.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataBuilder,
        SymmetricKeyDecryptor,
    };
    let compiled = policies();
    let api = XmlSecurity::new(&compiled, &RustCryptoProvider).unwrap();
    let mut ignored = xml_sec::policy::EncryptionPolicy::default();
    ignored.resources.max_encryption_plaintext_bytes = 0;
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(vec![5; 16])
        .policy(ignored);
    let encryptor = api.encryptor(&builder).unwrap();
    let resolver = SymmetricKeyDecryptor::new(vec![5; 16]);
    let decryptor = api.decryptor(&resolver).unwrap();
    let original = "<root><p Id='payload'>secret</p></root>";
    let mut document = api.parse_document(original, Operation::Encrypt).unwrap();
    encryptor
        .encrypt(
            &mut document,
            DocumentEncryptionOptions {
                element_id: Some("payload"),
            },
        )
        .unwrap();
    assert_eq!(document.generation(), 1);
    decryptor.decrypt(&mut document, None).unwrap();
    assert_eq!(document.generation(), 2);
    assert_eq!(document.as_xml(), original);
    let encrypted = encryptor
        .encrypt_xml(original, DocumentEncryptionOptions { element_id: None })
        .unwrap()
        .output;
    assert_eq!(
        decryptor.decrypt_xml(&encrypted, None).unwrap().output,
        original
    );
    let fragment = encryptor.encrypt_fragment("<p>secret</p>").unwrap();
    assert!(
        matches!(decryptor.decrypt_fragment(&fragment.encrypted_data_xml).unwrap().output, xml_sec::xmlenc::DecryptedContent::Xml(value) if value == "<p>secret</p>")
    );
    let binary = encryptor.encrypt_binary(b"not XML\0").unwrap();
    assert!(
        matches!(decryptor.decrypt_fragment(&binary.encrypted_data_xml).unwrap().output, xml_sec::xmlenc::DecryptedContent::Bytes(value) if value == b"not XML\0")
    );
    let mut broken = api.parse_document(encrypted, Operation::Decrypt).unwrap();
    let before = broken.as_xml().to_owned();
    let wrong = SymmetricKeyDecryptor::new(vec![6; 16]);
    assert!(matches!(
        api.decryptor(&wrong).unwrap().decrypt(&mut broken, None),
        Err(XmlSecError::Encryption(_))
    ));
    assert_eq!(broken.as_xml(), before);
    assert_eq!(broken.generation(), 0);
}
