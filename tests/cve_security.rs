//! Pinned upstream parser regressions; advisory evidence is kept separately.
#![cfg(feature = "xmldsig")]

use std::path::Path;
#[cfg(feature = "c14n")]
use xml_sec::policy::VerificationPolicy;
use xml_sec::{XmlBackend, XmlDocument};

fn corpus() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security/libxml2")
}

#[test]
fn upstream_errors_are_not_recovered_into_authenticated_documents() {
    // The upstream error suites include CVE-2016-1835/1836/1838 and
    // CVE-2017-9049/9050 reproducers. Unlike libxml2 recovery mode, the
    // authentication boundary must not return a partial tree on bad XML.
    let manifest = include_str!("fixtures/security/files.tsv");
    let mut checked = 0;
    for line in manifest.lines() {
        let (_, path) = line.split_once('\t').unwrap();
        if !(path.starts_with("test/errors/") || path.starts_with("test/errors10/"))
            || !path.ends_with(".xml")
        {
            continue;
        }
        let bytes = std::fs::read(corpus().join(path)).unwrap();
        for backend in XmlBackend::available() {
            assert!(
                XmlDocument::parse_bytes_with_backend(&bytes, backend).is_err(),
                "unexpected authenticated parse: {path}, {backend:?}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 47, "pinned suite inventory cannot silently shrink");
    for backend in XmlBackend::available() {
        XmlDocument::parse_with_backend("<r attr='valid'>&amp;<child/></r>", backend).unwrap();
    }
}

#[test]
fn upstream_entity_amplification_cannot_cross_the_secure_boundary() {
    // libxml2's own testrecurse corpus includes the CVE-2021-3541 parameter
    // entity reproducer. Secure refusal is tested on original bytes, not a
    // rewritten or already-expanded approximation of that payload.
    let root = corpus().join("test/recurse");
    let mut checked = 0;
    for entry in std::fs::read_dir(&root).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        if !name.starts_with("lol_") || !name.ends_with(".xml") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for backend in XmlBackend::available() {
            assert!(
                XmlDocument::parse_bytes_with_backend(&bytes, backend).is_err(),
                "{name}, {backend:?}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 10);
}

#[cfg(feature = "c14n")]
#[test]
fn cve_2021_21239_embedded_key_data_cannot_establish_trust() {
    use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
    use xml_sec::provider::RustCryptoProvider;
    use xml_sec::xmldsig::{DefaultKeyResolver, VerifyContext};
    // Original PySAML2 attack bytes, including HMACKeyValue and a private
    // key disguised as X509Certificate. Compatibility algorithm permission
    // does not turn embedded attacker key material into a trusted key.
    let policy = PolicyCompiler::new(PolicyProfile::XmlSecCompatible, &RustCryptoProvider, None)
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        })
        .unwrap();
    for name in [
        "signed-assertion-random-embedded-cert.xml",
        "signed-assertion-with-hmac.xml",
        "signed-response-with-hmac.xml",
    ] {
        let xml = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/security/pysaml2/tests/xmlsec1-keydata")
                .join(name),
        )
        .unwrap();
        for backend in XmlBackend::available() {
            let resolver = DefaultKeyResolver::default();
            let result = VerifyContext::new()
                .xml_backend(backend)
                .key_resolver(&resolver)
                .policy(policy.verification().unwrap().clone())
                .verify(&xml);
            if let Ok(result) = result {
                assert_ne!(
                    result.status,
                    xml_sec::xmldsig::DsigStatus::Valid,
                    "untrusted fixture authenticated: {name}, {backend:?}"
                );
            }
        }
    }
}

#[test]
fn cve_2018_7644_public_key_is_not_recast_as_a_mac_secret() {
    use hmac::{KeyInit as _, Mac as _};
    use xml_sec::xmldsig::{
        DsigError, HmacVerificationKey, KeyResolutionError, SignatureAlgorithm, VerificationKey,
        VerifyingKey,
    };
    // The upstream castKey fix restricts conversions to RSA schemes. Make a
    // genuine attacker MAC using public key bytes, rather than random garbage:
    // an explicitly symmetric key can verify it, but a typed RSA key cannot.
    let pem = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let key = pem::parse(pem).unwrap().into_contents();
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
    mac.update(b"attacker-controlled signed bytes");
    let signature = mac.finalize().into_bytes();
    let symmetric = HmacVerificationKey::new(key.clone()).unwrap();
    assert!(
        symmetric
            .verify(
                SignatureAlgorithm::HmacSha256,
                b"attacker-controlled signed bytes",
                &signature
            )
            .unwrap()
    );
    let rsa = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: key,
        certificate_der: None,
        name: None,
    };
    assert!(matches!(
        rsa.verify(
            SignatureAlgorithm::HmacSha256,
            b"attacker-controlled signed bytes",
            &signature
        ),
        Err(DsigError::KeyResolution(
            KeyResolutionError::AlgorithmMismatch
        ))
    ));
}

#[test]
#[cfg(feature = "c14n")]
fn explicit_dtd_permission_preserves_complete_attribute_values() {
    // CVE-2026-101019: njs exposed only part of an entity-backed attribute
    // while C14N authenticated its expanded value. Our semantic view must
    // expose the full value. This is a semantic analogue, not an njs repro.
    let mut policy = VerificationPolicy::default();
    policy.xml.allow_internal_dtd = true;
    for backend in XmlBackend::available() {
        let document = XmlDocument::parse_with_policy_and_backend(
            "<!DOCTYPE r [<!ENTITY suffix 'tail'>]><r Destination='head-&suffix;' ID='target'/>",
            &policy,
            backend,
        )
        .unwrap();
        let bytes = xml_sec::c14n::canonicalize_document(
            &document,
            &xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
        )
        .unwrap();
        assert_eq!(bytes, b"<r Destination=\"head-tail\" ID=\"target\"></r>");
    }
}

#[cfg(feature = "c14n")]
#[test]
fn cve_2025_66568_canonicalization_failure_is_not_empty_success() {
    // C14N 1.0 §2.3 requires failure on relative namespace URIs. Wrapper
    // advisories CVE-2025-66568/66578 describe treating failure as empty
    // authenticated bytes. Empty *valid* node sets are a different contract.
    // https://www.w3.org/TR/2001/REC-xml-c14n-20010315#DataModel
    let algorithm = xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false);
    for backend in XmlBackend::available() {
        assert!(matches!(
            xml_sec::c14n::canonicalize_xml_with_backend(
                b"<r xmlns:p='relative'><p:a/></r>",
                &algorithm,
                backend
            ),
            Err(xml_sec::c14n::C14nError::RelativeNamespace)
        ));
        assert_eq!(
            xml_sec::c14n::canonicalize_xml_with_backend(
                b"<r xmlns:p='urn:absolute'><p:a/></r>",
                &algorithm,
                backend
            )
            .unwrap(),
            b"<r><p:a xmlns:p=\"urn:absolute\"></p:a></r>"
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn cve_2026_32313_gcm_never_accepts_a_shortened_tag() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
        SymmetricKeyDecryptor, XmlEncError,
    };
    // XMLEnc 1.1 §5.2.4 uses a 128-bit tag, not a caller-selectable prefix.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-AES-GCM
    let key = [0x37; 16];
    let good = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key.as_slice())
        .encrypt_binary(b"x")
        .unwrap()
        .encrypted_data_xml;
    let document = roxmltree::Document::parse(&good).unwrap();
    let value = document
        .descendants()
        .find(|node| node.tag_name().name() == "CipherValue")
        .unwrap()
        .text()
        .unwrap();
    let ciphertext = STANDARD.decode(value).unwrap();
    let resolver = SymmetricKeyDecryptor::new(key);
    for backend in XmlBackend::available() {
        let context = DecryptContext::new(&resolver).xml_backend(backend);
        assert_eq!(
            context.decrypt(&good).unwrap(),
            DecryptedContent::Bytes(b"x".to_vec())
        );
        for removed in 1..=16 {
            let attack = good.replace(
                value,
                &STANDARD.encode(&ciphertext[..ciphertext.len() - removed]),
            );
            assert!(
                matches!(
                    context.decrypt(&attack),
                    Err(XmlEncError::AeadAuthenticationFailed | XmlEncError::DataTooShort { .. })
                ),
                "shortened tag: {removed}, {backend:?}"
            );
        }
    }
}
