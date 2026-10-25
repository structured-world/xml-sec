#![cfg(feature = "xmlenc")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::HashMap;
use xml_sec::policy::DecryptionPolicy;
use xml_sec::xmldsig::UriTypeSet;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder, KekDecryptor,
    KeyWrapAlgorithm, SymmetricKeyDecryptor, XmlEncError,
};

const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

fn external_policy() -> DecryptionPolicy {
    let mut policy = DecryptionPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy
}

#[cfg(feature = "xslt")]
#[test]
fn cipher_reference_xslt_retains_the_detached_entity_base() {
    // XMLEnc's transform adapter must preserve the same resource identity as
    // XMLDSig, including NDATA identifiers relative to the containing DTD.
    let resources = HashMap::from([(
        "https://example.org/data/input.xml".to_owned(),
        br#"<!DOCTYPE root [<!NOTATION image SYSTEM "image"><!ENTITY logo SYSTEM "images/logo.png" NDATA image>]><root/>"#.to_vec(),
    )]);
    let xml = format!(
        r#"<xenc:CipherReference xmlns:xenc="{ENC}" URI="input.xml" xml:base="https://example.org/data/"><xenc:Transforms><ds:Transform xmlns:ds="{DS}" Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="unparsed-entity-uri('logo')"/></xsl:template></xsl:stylesheet></ds:Transform></xenc:Transforms></xenc:CipherReference>"#
    );
    let mut policy = external_policy();
    policy.xml.allow_internal_dtd = true;
    for backend in xml_sec::XmlBackend::available() {
        let document = xml_sec::Document::parse_with_backend(&xml, backend).unwrap();
        let context =
            xml_sec::xmlenc::CipherReferenceContext::new(&policy, Some(&resources), backend, &[])
                .unwrap();
        assert_eq!(
            context.resolve(document.root_element()).unwrap(),
            b"https://example.org/data/images/logo.png"
        );
    }
}

#[cfg(feature = "xslt")]
#[test]
fn decrypt_descriptor_capture_shares_the_cipher_reference_xslt_allowance() {
    // Capturing and executing the same stylesheet must consume one operation
    // allowance, whether resolving a reference directly or decrypting its owner.
    let key = [0x31; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_binary(b"one XSLT allowance")
        .expect("encrypt reference payload");
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml)
        .expect("parse generated ciphertext");
    let encoded = parsed
        .cipher_data
        .inline_value()
        .expect("inline ciphertext");
    let reference = format!(
        "<xenc:CipherReference URI='urn:source'><xenc:Transforms><ds:Transform xmlns:ds='{DS}' Algorithm='http://www.w3.org/TR/1999/REC-xslt-19991116'><xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:output method='text'/><xsl:template match='/'><xsl:text>{encoded}</xsl:text></xsl:template></xsl:stylesheet></ds:Transform><ds:Transform xmlns:ds='{DS}' Algorithm='{DS}base64'/></xenc:Transforms></xenc:CipherReference>"
    );
    let xml = encrypted.encrypted_data_xml.replace(
        &format!("<xenc:CipherValue>{encoded}</xenc:CipherValue>"),
        &reference,
    );
    let resources = HashMap::from([("urn:source".into(), b"<source/>".to_vec())]);
    for backend in xml_sec::XmlBackend::available() {
        let document = xml_sec::XmlDomDocument::parse_with_options_and_backend(
            &xml,
            xml_sec::ParsingOptions::default(),
            backend,
        )
        .expect("parse CipherReference document");
        let node = document
            .descendants()
            .find(|node| node.has_tag_name((ENC, "CipherReference")))
            .expect("CipherReference exists");
        let resolves = |limit| {
            let mut policy = external_policy();
            policy.resources.max_xslt_work = limit;
            xml_sec::xmlenc::CipherReferenceContext::new(&policy, Some(&resources), backend, &[])
                .expect("valid reference policy")
                .resolve(node)
                .is_ok()
        };
        let mut lower = 1;
        let mut upper = external_policy().resources.max_xslt_work;
        assert!(resolves(upper));
        while lower < upper {
            let midpoint = lower + (upper - lower) / 2;
            if resolves(midpoint) {
                upper = midpoint;
            } else {
                lower = midpoint + 1;
            }
        }
        assert!(lower > 1);
        let decryptor = SymmetricKeyDecryptor::new(key);
        let mut policy = external_policy();
        policy.resources.max_xslt_work = lower;
        assert_eq!(
            DecryptContext::new(&decryptor)
                .policy(policy.clone())
                .xml_backend(backend)
                .external_resources(&resources)
                .decrypt(&xml)
                .expect("exact shared allowance fits"),
            DecryptedContent::Bytes(b"one XSLT allowance".to_vec())
        );
        policy.resources.max_xslt_work -= 1;
        let error = DecryptContext::new(&decryptor)
            .policy(policy)
            .xml_backend(backend)
            .external_resources(&resources)
            .decrypt(&xml)
            .expect_err("descriptor capture must not receive a fresh allowance");
        assert!(
            matches!(
                error,
                XmlEncError::Transform(xml_sec::xmldsig::TransformError::Policy(
                    xml_sec::policy::PolicyViolation::ResourceLimit {
                        resource: "XSLT work",
                        ..
                    }
                ))
            ),
            "{backend:?}: {error:?}"
        );
    }
}

#[test]
fn cipher_reference_enveloped_transform_uses_its_actual_signature_ancestor() {
    // XMLDSig 1.1 section 6.6.4 removes the Signature containing the transform,
    // even when its Reference-like origin is an encrypted Object descendant.
    let key = [0x55; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_xml("<payload>restored</payload>")
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let encoded = parsed.cipher_data.inline_value().unwrap();
    let fragment = encrypted.encrypted_data_xml.replace(
        &format!("<xenc:CipherValue>{encoded}</xenc:CipherValue>"),
        &format!("<xenc:CipherReference URI=''><xenc:Transforms><ds:Transform xmlns:ds='{DS}' Algorithm='{DS}enveloped-signature'/><ds:Transform xmlns:ds='{DS}' Algorithm='{DS}base64'/></xenc:Transforms></xenc:CipherReference>"));
    let wire = format!(
        "<root><cipher>{encoded}</cipher><ds:Signature xmlns:ds='{DS}'><ds:SignatureValue>QUFBQQ==</ds:SignatureValue><ds:Object>{fragment}</ds:Object></ds:Signature></root>"
    );
    let mut document = xml_sec::XmlDocument::parse(wire).unwrap();
    DecryptContext::new(&SymmetricKeyDecryptor::new(key))
        .decrypt_owned_document(&mut document, None)
        .unwrap();
    assert!(
        document
            .as_xml()
            .contains("<ds:Object><payload>restored</payload></ds:Object>")
    );
}

#[test]
fn external_cipher_reference_decrypts_authenticated_content() {
    // The public decrypt path consumes caller bytes directly, without creating
    // an artificial inline CipherValue or weakening GCM authentication.
    let key = [0x31; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_binary(b"external ciphertext")
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let encoded = parsed.cipher_data.inline_value().unwrap();
    let ciphertext = STANDARD.decode(encoded).unwrap();
    let xml = encrypted.encrypted_data_xml.replace(
        &format!("<xenc:CipherValue>{encoded}</xenc:CipherValue>"),
        "<xenc:CipherReference URI=\"urn:cipher\"/>",
    );
    let resources = HashMap::from([("urn:cipher".into(), ciphertext.clone())]);
    let resolver = SymmetricKeyDecryptor::new(key);
    let context = DecryptContext::new(&resolver)
        .policy(external_policy())
        .external_resources(&resources);
    assert_eq!(
        context.decrypt(&xml).unwrap(),
        DecryptedContent::Bytes(b"external ciphertext".to_vec())
    );
    assert!(matches!(
        DecryptContext::new(&resolver)
            .external_resources(&resources)
            .decrypt(&xml),
        Err(XmlEncError::Policy(_))
    ));
    let mut corrupted = ciphertext;
    *corrupted.last_mut().unwrap() ^= 1;
    let resources = HashMap::from([("urn:cipher".into(), corrupted)]);
    assert!(
        DecryptContext::new(&resolver)
            .policy(external_policy())
            .external_resources(&resources)
            .decrypt(&xml)
            .is_err()
    );
}

#[test]
fn referenced_wrapped_key_and_content_share_external_budget() {
    // Both levels belong to one decrypt operation. Independently permitted
    // resources must not each receive a fresh aggregate allowance.
    let kek = [0x24; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .recipient_aes_kw(kek, KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"wrapped reference")
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let key_value = parsed.encrypted_keys[0].cipher_data.inline_value().unwrap();
    let content_value = parsed.cipher_data.inline_value().unwrap();
    let key_bytes = STANDARD.decode(key_value).unwrap();
    let content_bytes = STANDARD.decode(content_value).unwrap();
    let xml = encrypted
        .encrypted_data_xml
        .replace(
            &format!("<xenc:CipherValue>{key_value}</xenc:CipherValue>"),
            "<xenc:CipherReference URI=\"urn:key\"/>",
        )
        .replace(
            &format!("<xenc:CipherValue>{content_value}</xenc:CipherValue>"),
            "<xenc:CipherReference URI=\"urn:data\"/>",
        );
    let total = key_bytes.len() + content_bytes.len();
    let resources = HashMap::from([
        ("urn:key".into(), key_bytes),
        ("urn:data".into(), content_bytes),
    ]);
    let resolver = KekDecryptor::new(kek);
    let mut policy = external_policy();
    policy.resources.max_external_resource_total_bytes = total;
    assert_eq!(
        DecryptContext::new(&resolver)
            .policy(policy.clone())
            .external_resources(&resources)
            .decrypt(&xml)
            .unwrap(),
        DecryptedContent::Bytes(b"wrapped reference".to_vec())
    );
    policy.resources.max_external_resource_total_bytes = total - 1;
    assert!(
        DecryptContext::new(&resolver)
            .policy(policy)
            .external_resources(&resources)
            .decrypt(&xml)
            .is_err()
    );
}

#[test]
fn owned_document_same_document_reference_keeps_source_and_generation() {
    // Reference resolution must see siblings outside the selected encrypted
    // subtree, and a failed authenticated decrypt must not mutate the owner.
    let key = [0x55; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_xml("<payload>restored</payload>")
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let encoded = parsed.cipher_data.inline_value().unwrap();
    let fragment = encrypted.encrypted_data_xml.replace(
        &format!("<xenc:CipherValue>{encoded}</xenc:CipherValue>"),
        &format!("<xenc:CipherReference URI=\"#cipher\"><xenc:Transforms><ds:Transform xmlns:ds=\"{DS}\" Algorithm=\"{DS}base64\"/></xenc:Transforms></xenc:CipherReference>"),
    );
    let xml = format!("<root><cipher xml:id=\"cipher\">{encoded}</cipher>{fragment}</root>");
    let mut document = xml_sec::XmlDocument::parse(xml.clone()).unwrap();
    let identity = document.identity();
    let generation = document.generation();
    let wrong = SymmetricKeyDecryptor::new([0x56; 16]);
    assert!(
        DecryptContext::new(&wrong)
            .decrypt_owned_document(&mut document, None)
            .is_err()
    );
    assert_eq!(document.as_xml(), xml);
    assert_eq!(document.generation(), generation);
    let resolver = SymmetricKeyDecryptor::new(key);
    DecryptContext::new(&resolver)
        .decrypt_owned_document(&mut document, None)
        .unwrap();
    assert_eq!(document.identity(), identity);
    assert_eq!(document.generation(), generation + 1);
    assert_eq!(
        document.as_xml(),
        format!(
            "<root><cipher xml:id=\"cipher\">{encoded}</cipher><payload>restored</payload></root>"
        )
    );
}

#[test]
fn cipher_reference_syntax_and_transform_permission_are_not_implicit() {
    // An allowed external resource does not grant permission for an unknown or
    // disallowed transform, and missing URI is distinct from URI="".
    let resolver = SymmetricKeyDecryptor::new([0; 16]);
    let resources = HashMap::from([("urn:data".into(), b"not ciphertext".to_vec())]);
    for reference in [
        "<xenc:CipherReference/>",
        "<xenc:CipherReference URI='urn:data'><ds:Transforms/></xenc:CipherReference>",
        "<xenc:CipherReference URI='urn:data'><xenc:Transforms/></xenc:CipherReference>",
        "<xenc:CipherReference URI='urn:data'><xenc:Transforms><ds:Transform Algorithm='urn:unknown'/></xenc:Transforms></xenc:CipherReference>",
    ] {
        let xml = format!(
            "<xenc:EncryptedData xmlns:xenc='{ENC}' xmlns:ds='{DS}'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/><xenc:CipherData>{reference}</xenc:CipherData></xenc:EncryptedData>"
        );
        assert!(
            DecryptContext::new(&resolver)
                .policy(external_policy())
                .external_resources(&resources)
                .decrypt(&xml)
                .is_err(),
            "{reference}"
        );
    }
}
