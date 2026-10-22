//! Execute the policy-bound API, including wrong-target and tamper rejection.
//! The signing credential is public test data, never a deployment credential.

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
use xml_sec::provider::{CryptoProvider, RustCryptoProvider};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, ReferenceBuilder, RsaSigningKey, SignatureAlgorithm,
    SignatureBuilder, Transform, VerificationKey, VerificationRequest,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataBuilder, SymmetricKeyDecryptor,
};
use xml_sec::{XmlSecurity, api::Operation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = RustCryptoProvider;
    let policies = PolicyCompiler::new(PolicyProfile::Modern, &provider, None)?.compile(
        &PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        },
    )?;
    let security = XmlSecurity::new(&policies, &provider)?;
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(include_str!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"))?;
    let public = pem::parse(include_str!(
        "../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
    ))?;
    let verification_key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: public.into_contents(),
        certificate_der: None,
        name: None,
    };
    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256).add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#invoice")
            .transform(Transform::C14n(c14n)),
    );
    let mut document = security.parse_document(
        "<root><Invoice Id='invoice'>42.00</Invoice><Note Id='decoy'>unsigned</Note></root>",
        Operation::Sign,
    )?;
    security
        .signer(&signing_key)?
        .sign(&mut document, &builder)?;
    let verifier = security.verifier()?.key(&verification_key);
    for (id, expected) in [("invoice", true), ("decoy", false)] {
        let target = document
            .with_view(|view| view.node_for_id(id, &[]))
            .ok_or("expected example target is absent")?;
        let evidence = verifier.verify(
            &document,
            &VerificationRequest {
                expected_targets: &[target],
                ..Default::default()
            },
        )?;
        // A valid signature over Invoice must never authorize its unsigned sibling.
        assert_eq!(evidence.accepted(&document)?, expected);
    }
    let tampered = document.as_xml().replace("42.00", "99.00");
    assert_ne!(
        verifier.verify_signature_xml(&tampered)?.status,
        DsigStatus::Valid
    );

    let mut key = vec![0; 32];
    provider.fill_random(&mut key)?;
    // These two independently owning request handles each zeroize on drop.
    let resolver = SymmetricKeyDecryptor::new(key.clone());
    let encryption = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm).direct_key(key);
    let original = "<root><secret>confidential</secret></root>";
    let encrypted = security
        .encryptor(&encryption)?
        .encrypt_xml(original, DocumentEncryptionOptions::default())?;
    let decrypted = security
        .decryptor(&resolver)?
        .decrypt_xml(&encrypted, None)?;
    assert_eq!(decrypted, original);
    println!("policy-bound sign/verify/encrypt/decrypt and rejection checks passed");
    Ok(())
}
