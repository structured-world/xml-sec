//! Shared full-document ML-KEM corpus runner; returns only completed cases.

use std::{collections::BTreeSet, path::Path};
use xml_sec::provider::{KeyDecapsulationKey as _, RustCryptoMlKemPrivateKey};

pub fn execute() -> BTreeSet<String> {
    use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut completed = BTreeSet::new();
    // Independently produced CBC/GCM documents cover all parameter sets and
    // consumer widths. An entry is recorded only after whole-document parity.
    for (name, size, width) in [
        ("enc-aes256-em-ml-kem-512", 512, 32),
        ("enc-aes256-em-ml-kem-768", 768, 32),
        ("enc-aes256-em-ml-kem-1024", 1024, 32),
        ("enc-aes128gcm-em-ml-kem-512", 512, 16),
        ("enc-aes192gcm-em-ml-kem-768", 768, 24),
        ("enc-aes256gcm-em-ml-kem-1024", 1024, 32),
    ] {
        let path = fixtures.join(format!("xmlenc/aleksey-xmlenc-01/{name}"));
        let xml = std::fs::read_to_string(path.with_extension("xml")).unwrap();
        let expected = std::fs::read(path.with_extension("data")).unwrap();
        let private = RustCryptoMlKemPrivateKey::from_pkcs8_der(
            &std::fs::read(fixtures.join(format!("xmldsig/keys/ml-kem/ml-kem-{size}-key.der")))
                .unwrap(),
        )
        .unwrap();
        let key = xml_sec::xmlenc::EncapsulationDecryptor::new(&private);
        let mut policy = xml_sec::policy::DecryptionPolicy::default();
        policy
            .key_establishment
            .encapsulation_algorithms
            .insert(private.algorithm());
        let document = xml_sec::Document::parse(&xml).unwrap();
        let method = document
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "EncryptionMethod"))
            })
            .unwrap();
        let content_algorithm = xml_sec::xmlenc::DataEncryptionAlgorithm::from_uri(
            method.attribute("Algorithm").unwrap(),
        )
        .unwrap();
        assert_eq!(content_algorithm.key_len(), width);
        policy.data_algorithms = Some([content_algorithm].into());
        // A caller-owned permission enables CBC compatibility; padding never
        // becomes authentication merely because a KEM supplied the key.
        policy.key_establishment.kem_content_authentication =
            xml_sec::policy::KemContentAuthentication::ExternalAuthenticated;
        let actual = xml_sec::xmlenc::DecryptContext::new(&key)
            .policy(policy)
            .decrypt_document(&xml, Some("ED"))
            .unwrap();
        let c14n = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        assert_eq!(
            canonicalize_xml(actual.as_bytes(), &c14n).unwrap(),
            canonicalize_xml(&expected, &c14n).unwrap(),
            "{name}"
        );
        assert!(completed.insert(name.to_owned()));
    }
    completed
}
