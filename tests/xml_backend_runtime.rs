//! Runtime XML backend selection across complete XML Security pipelines.

#![cfg(all(
    feature = "xml-backend-xmloxide",
    feature = "xml-backend-roxmltree",
    feature = "xmldsig",
    feature = "xmlenc"
))]

use std::fs;

use xml_sec::XmlBackend;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml_with_backend};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ReferenceBuilder, RsaSigningKey, SignContext,
    SignatureAlgorithm, SignatureBuilder, Transform, VerifyContext, X509CertificateKeyInfoWriter,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DocumentEncryptionOptions, EncryptedDataBuilder,
    SymmetricKeyDecryptor,
};

const BACKENDS: [XmlBackend; 3] = [
    XmlBackend::Xmloxide,
    XmlBackend::Roxmltree,
    XmlBackend::Differential,
];

#[test]
fn every_compiled_runtime_backend_runs_complete_security_pipelines() {
    // A fat build must dispatch the entire operation, including staged
    // mutation and nested reparsing, through the caller-selected backend.
    let private_key = fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
        .expect("RSA private-key fixture must load");
    let certificate = fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-cert.pem")
        .expect("RSA certificate fixture must load");
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(&private_key).expect("RSA private key must parse");
    let key_info =
        X509CertificateKeyInfoWriter::from_pem(&certificate).expect("RSA certificate must parse");
    let signature = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    )
    .key_info(true);
    let symmetric_key = [0x5a; 16];

    for backend in BACKENDS {
        let canonical = canonicalize_xml_with_backend(
            b"<root b=\"2\" a=\"1\"><value>payload</value></root>",
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
            backend,
        )
        .unwrap_or_else(|error| panic!("{backend:?} C14N failed: {error}"));
        assert_eq!(
            canonical,
            b"<root a=\"1\" b=\"2\"><value>payload</value></root>"
        );

        let signed = SignContext::new(&signing_key)
            .xml_backend(backend)
            .key_info_writer(&key_info)
            .sign_with_builder("<root><value>payload</value></root>", &signature)
            .unwrap_or_else(|error| panic!("{backend:?} signing failed: {error}"));
        let verified = VerifyContext::new()
            .xml_backend(backend)
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&signed)
            .unwrap_or_else(|error| panic!("{backend:?} verification failed: {error}"));
        assert_eq!(verified.status, DsigStatus::Valid);

        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .xml_backend(backend)
            .direct_key(symmetric_key)
            .encrypt_document(
                "<root><value>payload</value></root>",
                DocumentEncryptionOptions::default(),
            )
            .unwrap_or_else(|error| panic!("{backend:?} encryption failed: {error}"));
        let resolver = SymmetricKeyDecryptor::new(symmetric_key);
        let decrypted = DecryptContext::new(&resolver)
            .xml_backend(backend)
            .decrypt_document(&encrypted, None)
            .unwrap_or_else(|error| panic!("{backend:?} decryption failed: {error}"));
        assert_eq!(decrypted, "<root><value>payload</value></root>");
    }
}
