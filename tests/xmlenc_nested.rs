#![cfg(feature = "xmlenc")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use xml_sec::provider::{CryptoProvider, RUST_CRYPTO_PROVIDER};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder, KekDecryptor,
    KeyWrapAlgorithm,
};
use xml_sec::xmlenc::{XmlEncError, parse_encrypted_data};

const X: &str = "http://www.w3.org/2001/04/xmlenc#";
const D: &str = "http://www.w3.org/2000/09/xmldsig#";

#[test]
fn retrieval_method_rejects_non_whitespace_text_before_resolution() {
    // XMLDSig 1.1 section 4.5.3 RetrievalMethodType is element-only, unlike
    // KeyInfoType. Ignoring text would accept a malformed indirect source.
    let detached = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='transport'>");
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data("<d:RetrievalMethod URI='#transport'>unexpected</d:RetrievalMethod>")
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    assert!(matches!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()),
        Err(XmlEncError::InvalidStructure(_))
    ));
}

#[test]
fn containing_identifiers_are_bounded_before_key_retrieval() {
    // Identifiers are retained only after all children, but their limit must
    // reject the containing element before an indirect source is evaluated.
    for (tag, attribute) in [("EncryptedData", "Id"), ("EncryptedKey", "Recipient")] {
        let inner =
            "<d:KeyInfo><d:RetrievalMethod URI='https://example.test/missing'/></d:KeyInfo>";
        let wire = if tag == "EncryptedData" {
            data("<d:RetrievalMethod URI='https://example.test/missing'/>")
        } else {
            data(&key(inner))
        };
        let wire = wire.replacen(
            &format!("<x:{tag}"),
            &format!("<x:{tag} {attribute}='{}'", "a".repeat(101)),
            1,
        );
        let mut policy = xml_sec::policy::DecryptionPolicy::default();
        policy.resources.max_encryption_metadata_bytes = 100;
        let result = DecryptContext::new(&xml_sec::xmlenc::SymmetricKeyDecryptor::new([0; 16]))
            .policy(policy)
            .decrypt(&wire);
        assert!(
            matches!(
                result,
                Err(XmlEncError::Policy(
                    xml_sec::policy::PolicyViolation::ResourceLimit {
                        resource: "encryption metadata bytes",
                        maximum: 100,
                        actual: 101
                    }
                ))
            ),
            "{result:?}"
        );
    }
}

#[test]
fn repeated_key_retrieval_charges_retained_cipher_values_during_parsing() {
    // Reusing one source node still retains one ciphertext buffer per candidate.
    // The parser must enforce the cumulative allowance before those copies.
    let detached = key("")
        .replace("<x:EncryptedKey>", "<x:EncryptedKey Id='transport'>")
        .replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &STANDARD.encode([0; 768]),
        );
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data(&"<d:RetrievalMethod URI='#transport'/>".repeat(6))
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.resources.max_xml_document_bytes = wire.len();
    let result = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy);
    assert!(
        matches!(result, Err(XmlEncError::Policy(
        xml_sec::policy::PolicyViolation::ResourceLimit { resource: "aggregate encryption CipherValue bytes", maximum, actual }
    )) if maximum == wire.len() && actual > maximum),
        "{result:?}"
    );
}

fn key(inner: &str) -> String {
    format!(
        "<x:EncryptedKey><x:EncryptionMethod Algorithm='{X}kw-aes128'/>{inner}<x:CipherData><x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</x:CipherValue></x:CipherData></x:EncryptedKey>"
    )
}

fn data(keys: &str) -> String {
    format!(
        "<x:EncryptedData xmlns:x='{X}' xmlns:d='{D}'><x:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/><d:KeyInfo>{keys}</d:KeyInfo><x:CipherData><x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</x:CipherValue></x:CipherData></x:EncryptedData>"
    )
}

#[test]
fn nested_key_sources_are_preserved_instead_of_silently_discarded() {
    // An inner EncryptedKey produces the outer wrapping key, not another CEK.
    let wire = data(&key(&format!("<d:KeyInfo>{}</d:KeyInfo>", key(""))));
    let parsed = parse_encrypted_data(&wire).unwrap();
    assert_eq!(parsed.encrypted_keys[0].sources.encrypted_keys.len(), 1);
}

#[test]
fn nested_key_depth_is_bounded_before_recursive_parsing() {
    // XML depth can be generous while key indirection still has its own hard
    // stack-safety ceiling. Recursive parsing must not reset that allowance.
    let mut nested = key("");
    for _ in 0..9 {
        nested = key(&format!("<d:KeyInfo>{nested}</d:KeyInfo>"));
    }
    assert!(matches!(
        parse_encrypted_data(&data(&nested)),
        Err(XmlEncError::Policy(_))
    ));
}

#[test]
fn retrieval_method_keeps_detached_wrapped_key() {
    // A same-document RetrievalMethod is a required XMLEnc key source; it
    // must not silently turn into direct content-key resolution.
    let detached = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='transport'>");
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data(
            "<d:RetrievalMethod URI='#transport' Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey'/>"
        )
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 1);
    assert_eq!(parsed.encrypted_keys[0].id.as_deref(), Some("transport"));
}

#[test]
fn retrieval_method_resolves_derived_keys_and_checks_declared_type() {
    // XMLEnc 1.1 section 3.5.3 defines retrieval of DerivedKey as well as
    // EncryptedKey. The Type is a contract, not permission to reinterpret it.
    let derived = "<i:DerivedKey xmlns:i='http://www.w3.org/2009/xmlenc11#' Id='derived'><i:MasterKeyName>master</i:MasterKeyName></i:DerivedKey>";
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{derived}</root>",
        data(&format!(
            "<d:RetrievalMethod URI='#derived' Type='{X}DerivedKey'/>"
        ))
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default())
        .expect("retrieved DerivedKey");
    assert_eq!(parsed.derived_keys.len(), 1);
    assert_eq!(
        parsed.derived_keys[0].master_key_name.as_deref(),
        Some("master")
    );
    let invalid = wire.replace(
        &format!("Type='{X}DerivedKey'"),
        &format!("Type='{X}EncryptedKey'"),
    );
    let document = xml_sec::XmlDomDocument::parse(&invalid).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    assert!(matches!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()),
        Err(XmlEncError::InvalidStructure(_))
    ));
}

#[test]
fn retrieval_uses_the_operation_same_document_id_semantics() {
    // Compatibility grammar is an explicit operation policy, not an implicit
    // default in the indirect-key parser. Specification mode stays strict.
    let detached = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='transport:1'>");
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data("<d:RetrievalMethod URI='#transport:1'/>")
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    assert!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).is_err()
    );
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.transforms.same_document_id_semantics =
        xml_sec::policy::SameDocumentIdSemantics::XmlSecBarename;
    assert_eq!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy)
            .unwrap()
            .encrypted_keys
            .len(),
        1
    );
}

#[test]
fn retrieval_cycle_is_rejected_before_key_resolution() {
    // Reusing a referenced key on the current ancestry is a cycle, not a
    // reason to reset the indirection budget or omit the nested source.
    let detached = key("<d:KeyInfo><d:RetrievalMethod URI='#loop'/></d:KeyInfo>")
        .replace("<x:EncryptedKey>", "<x:EncryptedKey Id='loop'>");
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data("<d:RetrievalMethod URI='#loop'/>")
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    assert!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).is_err()
    );
}

#[test]
fn key_info_reference_retains_the_indirect_transport() {
    // XMLDSig 1.1 §4.5.10 refers to KeyInfo, not an arbitrary resource; the
    // referenced encryption sources retain the same bounded parsing session.
    let info = format!("<d:KeyInfo Id='shared'>{}</d:KeyInfo>", key(""));
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{info}</root>",
        data("<i:KeyInfoReference xmlns:i='http://www.w3.org/2009/xmldsig11#' URI='#shared'/>")
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 1);
}

#[test]
fn retrieved_key_decrypts_in_the_original_document_context() {
    // The detached key origin must survive parsing so document replacement
    // uses the retrieved transport rather than treating its KEK as a CEK.
    let kek = [9; 16];
    let content = [3; 16];
    let wrapped = RUST_CRYPTO_PROVIDER
        .wrap_key(KeyWrapAlgorithm::AesKw128, &kek, &content)
        .unwrap();
    let detached = key("")
        .replace("<x:EncryptedKey>", "<x:EncryptedKey Id='transport'>")
        .replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &STANDARD.encode(&wrapped),
        );
    let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content)
        .encrypt_xml("<secret>retrieved</secret>")
        .unwrap();
    let parsed = parse_encrypted_data(&generated.encrypted_data_xml).unwrap();
    let data = data("<d:RetrievalMethod URI='#transport'/>")
        .replace(
            "<x:EncryptedData ",
            &format!("<x:EncryptedData Type='{X}Element' "),
        )
        .replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            parsed.cipher_data.inline_value().unwrap(),
        );
    let wire = format!("<root xmlns:x='{X}' xmlns:d='{D}'>{data}{detached}</root>");
    let resolver = KekDecryptor::new(kek);
    let result = DecryptContext::new(&resolver)
        .decrypt_document(&wire, None)
        .unwrap();
    assert!(result.contains("<secret>retrieved</secret>"));
    assert!(!result.contains("<x:EncryptedData"));
    assert!(result.contains("Id='transport'"));
}

#[test]
fn external_retrieval_and_transforms_share_caller_owned_resources() {
    // Retrieval transforms operate on the original reference; key XML is then
    // parsed under the same operation budgets, without filesystem/network I/O.
    let kek = [9; 16];
    let content = [3; 16];
    let wrapped = RUST_CRYPTO_PROVIDER
        .wrap_key(KeyWrapAlgorithm::AesKw128, &kek, &content)
        .unwrap();
    let transport = key("")
        .replace(
            "<x:EncryptedKey>",
            &format!("<x:EncryptedKey xmlns:x='{X}' xmlns:d='{D}'>"),
        )
        .replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &STANDARD.encode(&wrapped),
        );
    let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content)
        .encrypt_binary(b"retrieved external key")
        .unwrap();
    let parsed = parse_encrypted_data(&generated.encrypted_data_xml).unwrap();
    let mut resources = std::collections::HashMap::new();
    resources.insert(
        "https://example.test/keys/transport.xml".into(),
        transport.as_bytes().to_vec(),
    );
    resources.insert(
        "https://example.test/keys/transport.b64".into(),
        STANDARD.encode(&transport).into_bytes(),
    );
    let referenced = transport.replace(
        &format!(
            "<x:CipherValue>{}</x:CipherValue>",
            STANDARD.encode(&wrapped)
        ),
        "<x:CipherReference URI='wrapped.bin'/>",
    );
    resources.insert(
        "https://example.test/keys/referenced.xml".into(),
        referenced.into_bytes(),
    );
    resources.insert("https://example.test/keys/wrapped.bin".into(), wrapped);
    let utf16 = format!("<?xml version='1.0' encoding='UTF-16'?>{transport}");
    resources.insert(
        "https://example.test/keys/utf16.xml".into(),
        [
            vec![0xff, 0xfe],
            utf16.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        ]
        .concat(),
    );
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.uris.retrieval_methods = xml_sec::xmldsig::UriTypeSet::ALL;
    policy.uris.references = xml_sec::xmldsig::UriTypeSet::ALL;
    let resolver = KekDecryptor::new(kek);
    for (path, transforms) in [
        ("transport.xml", String::new()),
        ("referenced.xml", String::new()),
        ("utf16.xml", String::new()),
        (
            "transport.b64",
            format!("<d:Transforms><d:Transform Algorithm='{D}base64'/></d:Transforms>"),
        ),
    ] {
        let wire = data(&format!("<d:RetrievalMethod xml:base='https://example.test/keys/' URI='{path}' Type='{X}EncryptedKey'>{transforms}</d:RetrievalMethod>")).replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", parsed.cipher_data.inline_value().unwrap());
        assert_eq!(
            DecryptContext::new(&resolver)
                .policy(policy.clone())
                .external_resources(&resources)
                .decrypt(&wire)
                .expect("caller-owned key retrieval"),
            DecryptedContent::Bytes(b"retrieved external key".to_vec())
        );
        assert!(matches!(
            DecryptContext::new(&resolver)
                .external_resources(&resources)
                .decrypt(&wire),
            Err(XmlEncError::Policy(_))
        ));
    }
}

#[test]
fn external_retrieval_rejects_invalid_type_before_resource_lookup() {
    // Invalid type syntax is decided without requiring an unavailable resource
    // or entering a transform chain; it must not become UnsupportedUri.
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.uris.retrieval_methods = xml_sec::xmldsig::UriTypeSet::ALL;
    let resolver = KekDecryptor::new([9; 16]);
    let wire =
        data("<d:RetrievalMethod URI='https://example.test/missing.xml' Type='urn:unknown'/> ");
    assert!(matches!(
        DecryptContext::new(&resolver).policy(policy).decrypt(&wire),
        Err(XmlEncError::InvalidStructure(_))
    ));
}

#[test]
fn containing_cipher_syntax_and_algorithm_are_checked_before_key_retrieval() {
    // An absent key resource must not obscure a malformed CipherValue or a
    // denied content algorithm, nor cause work for an already-refused request.
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.uris.retrieval_methods = xml_sec::xmldsig::UriTypeSet::ALL;
    let resolver = KekDecryptor::new([9; 16]);
    let wire = data("<d:RetrievalMethod URI='https://example.test/missing.xml'/>");
    let invalid = wire.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "!");
    assert!(matches!(
        DecryptContext::new(&resolver)
            .policy(policy.clone())
            .decrypt(&invalid),
        Err(XmlEncError::Base64(_))
    ));
    policy.data_algorithms = Some(std::collections::HashSet::new());
    assert!(matches!(
        DecryptContext::new(&resolver).policy(policy).decrypt(&wire),
        Err(XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::Algorithm {
                operation: "decryption",
                ..
            }
        ))
    ));
}

#[test]
fn external_retrieval_cycles_and_shared_limits_are_not_reset_per_document() {
    // Two external documents can cycle without reusing any local node ID.
    // Byte and candidate budgets cover the entire chain, not each fresh DOM.
    let a = key("<d:KeyInfo><d:RetrievalMethod URI='b.xml'/></d:KeyInfo>").replace(
        "<x:EncryptedKey>",
        &format!("<x:EncryptedKey xmlns:x='{X}' xmlns:d='{D}'>"),
    );
    let b = a.replace("b.xml", "a.xml");
    let resources = std::collections::HashMap::from([
        ("https://example.test/a.xml".into(), a.as_bytes().to_vec()),
        ("https://example.test/b.xml".into(), b.as_bytes().to_vec()),
    ]);
    let wire = data("<d:RetrievalMethod URI='https://example.test/a.xml'/>");
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.uris.retrieval_methods = xml_sec::xmldsig::UriTypeSet::ALL;
    let resolver = KekDecryptor::new([9; 16]);
    assert!(
        matches!(DecryptContext::new(&resolver).policy(policy.clone()).external_resources(&resources).decrypt(&wire), Err(XmlEncError::InvalidStructure(reason)) if reason.contains("cyclic"))
    );
    policy.resources.max_key_candidates = 1;
    assert!(matches!(
        DecryptContext::new(&resolver)
            .policy(policy.clone())
            .external_resources(&resources)
            .decrypt(&wire),
        Err(XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "key candidates",
                maximum: 1,
                actual: 2
            }
        ))
    ));
    policy.resources.max_key_candidates = 10;
    policy.resources.max_external_resource_bytes = a.len().max(b.len());
    policy.resources.max_external_resource_total_bytes = a.len() + b.len();
    assert!(matches!(
        DecryptContext::new(&resolver)
            .policy(policy)
            .external_resources(&resources)
            .decrypt(&wire),
        Err(XmlEncError::Transform(
            xml_sec::xmldsig::TransformError::Policy(
                xml_sec::policy::PolicyViolation::ResourceLimit {
                    resource: "aggregate external resource bytes",
                    ..
                }
            )
        ))
    ));
}

#[test]
fn carried_key_name_finds_detached_key_without_retrieval_method() {
    // XMLEnc §3.5.1 permits detached transports named by ds:KeyName. The
    // label is whitespace-sensitive, not a hint for an unrelated direct key.
    let detached = key("").replace(
        "</x:EncryptedKey>",
        "<x:CarriedKeyName>content key</x:CarriedKeyName></x:EncryptedKey>",
    );
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data("<d:KeyName>content key</d:KeyName>")
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 1);
    assert_eq!(
        parsed.encrypted_keys[0].carried_key_name.as_deref(),
        Some("content key")
    );
}

#[test]
fn detached_inventory_does_not_charge_unrelated_keys_as_candidates() {
    // Candidate limits govern keys usable for this object, not unrelated
    // encrypted payloads elsewhere in a multi-recipient document.
    let selected = key("").replace(
        "</x:EncryptedKey>",
        "<x:CarriedKeyName>selected</x:CarriedKeyName></x:EncryptedKey>",
    );
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{}{selected}</root>",
        data("<d:KeyName>selected</d:KeyName>"),
        key("").repeat(65)
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.resources.max_key_candidates = 1;
    let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 1);
}

#[test]
fn detached_reference_validation_is_scoped_to_associated_keys() {
    // Malformed or oversized unrelated lists cannot abort this selection.
    // Once a key is associated, its complete list remains strictly validated.
    for bad in [
        "<x:DataReference/>",
        "<x:Other/>",
        "text",
        "<x:DataReference URI='#elsewhere'/><x:DataReference URI='#elsewhere'/>",
        "<x:DataReference URI='#xpointer(bad)'/>",
    ] {
        for associated in [false, true] {
            let carried = if associated {
                "<x:CarriedKeyName>selected</x:CarriedKeyName>"
            } else {
                ""
            };
            let detached = key("").replace(
                "</x:EncryptedKey>",
                &format!("<x:ReferenceList>{bad}</x:ReferenceList>{carried}</x:EncryptedKey>"),
            );
            let wire = format!(
                "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
                data("<d:KeyName>selected</d:KeyName>")
            );
            let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
            let node = document
                .descendants()
                .find(|node| node.has_tag_name((X, "EncryptedData")))
                .unwrap();
            let mut policy = xml_sec::policy::DecryptionPolicy::default();
            policy.resources.max_references = 1;
            let parsed = xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy);
            assert_eq!(
                parsed.is_err(),
                associated,
                "associated={associated}, list={bad}: {parsed:?}"
            );
        }
    }
}

#[test]
fn detached_selected_reference_validates_the_whole_list_and_candidate_limit() {
    // A relevant reference after malformed siblings still selects the key,
    // exposing strict validation; two relevant keys still exceed a one-key cap.
    for malformed in [false, true] {
        let list = format!(
            "<x:ReferenceList>{}<x:DataReference URI='#payload'/></x:ReferenceList>",
            if malformed { "<x:Other/>" } else { "" }
        );
        let detached = key("").replace("</x:EncryptedKey>", &format!("{list}</x:EncryptedKey>"));
        let payload = data("").replace("<x:EncryptedData ", "<x:EncryptedData Id='payload' ");
        let wire = format!(
            "<root xmlns:x='{X}' xmlns:d='{D}'>{payload}{}</root>",
            detached.repeat(if malformed { 1 } else { 2 })
        );
        let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
        let node = document
            .descendants()
            .find(|node| node.has_tag_name((X, "EncryptedData")))
            .unwrap();
        let mut policy = xml_sec::policy::DecryptionPolicy::default();
        policy.resources.max_key_candidates = 1;
        assert!(xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &policy).is_err());
    }
}

#[test]
fn detached_selection_does_not_hide_a_second_relevant_reference_list() {
    // A malformed key with a later association must be selected for strict
    // rejection, not treated as unrelated because its first list is irrelevant.
    let detached = key("").replace("</x:EncryptedKey>", "<x:ReferenceList><x:DataReference URI='#other'/></x:ReferenceList><x:ReferenceList><x:DataReference URI='#payload'/></x:ReferenceList></x:EncryptedKey>");
    let payload = data("").replace("<x:EncryptedData ", "<x:EncryptedData Id='payload' ");
    let wire = format!("<root xmlns:x='{X}' xmlns:d='{D}'>{payload}{detached}</root>");
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    assert!(matches!(
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()),
        Err(XmlEncError::InvalidStructure(_))
    ));
}

#[test]
fn data_reference_finds_detached_key_without_key_info() {
    // Association can be expressed solely by the detached transport's
    // ReferenceList, including an explicit XPointer ID reference.
    let detached = key("").replace("</x:EncryptedKey>", "<x:ReferenceList><x:DataReference URI=\"#xpointer(id('payload'))\"/></x:ReferenceList></x:EncryptedKey>");
    let data = data("")
        .replace("<x:EncryptedData ", "<x:EncryptedData Id='payload' ")
        .replace("<d:KeyInfo></d:KeyInfo>", "");
    let wire = format!("<root xmlns:x='{X}' xmlns:d='{D}'>{data}{detached}</root>");
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 1);
}

#[test]
fn key_reference_associates_a_detached_intermediate_transport() {
    // The detached key supplies the wrapping key for an EncryptedKey, not
    // another independent content key; retain it beneath its named consumer.
    let outer = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='outer'>");
    let detached = key("").replace(
        "</x:EncryptedKey>",
        "<x:ReferenceList><x:KeyReference URI='#outer'/></x:ReferenceList></x:EncryptedKey>",
    );
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data(&outer)
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys[0].sources.encrypted_keys.len(), 1);
}

#[test]
fn shared_detached_transport_is_not_dropped_from_the_second_consumer() {
    // Discovery deduplication is scoped to the consuming KeyInfo. A key
    // referenced by two independent consumers must remain on both paths.
    let first = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='first'>");
    let second = key("").replace("<x:EncryptedKey>", "<x:EncryptedKey Id='second'>");
    let detached = key("").replace("</x:EncryptedKey>", "<x:ReferenceList><x:KeyReference URI='#first'/><x:KeyReference URI='#second'/></x:ReferenceList></x:EncryptedKey>");
    let wire = format!(
        "<root xmlns:x='{X}' xmlns:d='{D}'>{}{detached}</root>",
        data(&format!("{first}{second}"))
    );
    let document = xml_sec::XmlDomDocument::parse(&wire).unwrap();
    let node = document
        .descendants()
        .find(|node| node.has_tag_name((X, "EncryptedData")))
        .unwrap();
    let parsed =
        xml_sec::xmlenc::parse_encrypted_data_node_with_policy(node, &Default::default()).unwrap();
    assert_eq!(parsed.encrypted_keys.len(), 2);
    for key in parsed.encrypted_keys {
        assert_eq!(key.sources.encrypted_keys.len(), 1);
    }
}

#[test]
fn nested_encrypted_key_recovers_the_outer_kek_not_a_second_content_key() {
    // Deliberately distinct root, intermediate, and content values expose any
    // shortcut which treats the inner key as an independent content recipient.
    let root = [9; 16];
    let intermediate = [7; 16];
    let content = [3; 16];
    let wrap = KeyWrapAlgorithm::AesKw128;
    let inner_bytes = RUST_CRYPTO_PROVIDER
        .wrap_key(wrap, &root, &intermediate)
        .unwrap();
    let outer_bytes = RUST_CRYPTO_PROVIDER
        .wrap_key(wrap, &intermediate, &content)
        .unwrap();
    let inner = key("").replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &STANDARD.encode(inner_bytes),
    );
    let outer = key(&format!("<d:KeyInfo>{inner}</d:KeyInfo>")).replacen(
        "<x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</x:CipherValue>",
        &format!(
            "<x:CipherValue>{}</x:CipherValue>",
            STANDARD.encode(outer_bytes)
        ),
        1,
    );
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content)
        .encrypt_binary(b"nested key path")
        .unwrap();
    let template = data(&outer);
    let parsed = parse_encrypted_data(&encrypted.encrypted_data_xml).unwrap();
    let wire = template.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        parsed.cipher_data.inline_value().unwrap(),
    );
    let resolver = KekDecryptor::new(root);
    assert_eq!(
        DecryptContext::new(&resolver).decrypt(&wire).unwrap(),
        DecryptedContent::Bytes(b"nested key path".to_vec())
    );
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.resources.max_key_candidates = 2;
    assert!(matches!(
        DecryptContext::new(&resolver).policy(policy).decrypt(&wire),
        Err(XmlEncError::Policy(_))
    ));
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn nested_implicit_rejection_reaches_final_content_authentication() {
    use xml_sec::rsa_encoding::RsaPrivateKeyEncoding as _;
    // A nested RSA-1.5 rejection must not become an early AES-KW oracle.
    // Even a failed intermediate unwrap carries fallback bytes to final GCM.
    let private =
        rsa::RsaPrivateKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem"))
            .unwrap();
    let resolver = xml_sec::xmlenc::PrivateKeyDecryptor::new(private);
    let inner = key("").replace("kw-aes128", "rsa-1_5").replace(
        "<x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</x:CipherValue>",
        &format!(
            "<x:CipherValue>{}</x:CipherValue>",
            STANDARD.encode([0; 256])
        ),
    );
    let wrapped = RUST_CRYPTO_PROVIDER
        .wrap_key(KeyWrapAlgorithm::AesKw128, &[7; 16], &[3; 16])
        .unwrap();
    let outer = key(&format!("<d:KeyInfo>{inner}</d:KeyInfo>")).replacen(
        "<x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</x:CipherValue>",
        &format!(
            "<x:CipherValue>{}</x:CipherValue>",
            STANDARD.encode(wrapped)
        ),
        1,
    );
    let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key([3; 16])
        .encrypt_binary(b"private fallback")
        .unwrap();
    let parsed = parse_encrypted_data(&generated.encrypted_data_xml).unwrap();
    let wire = data(&outer).replace(
        "<x:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</x:CipherValue>",
        &format!(
            "<x:CipherValue>{}</x:CipherValue>",
            parsed.cipher_data.inline_value().unwrap()
        ),
    );
    let policy = xml_sec::policy::DecryptionPolicy {
        key_transport_algorithms: Some(
            [xml_sec::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15].into(),
        ),
        ..Default::default()
    };
    let result = DecryptContext::new(&resolver).policy(policy).decrypt(&wire);
    assert!(
        matches!(result, Err(XmlEncError::AeadAuthenticationFailed)),
        "{result:?}"
    );
}
