//! XMLEnc encryption pipeline integration and donor-template coverage.

#![cfg(feature = "xmlenc")]

use std::fs;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::Node;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptedContent, DocumentEncryptionOptions, EncryptedDataBuilder,
    EncryptedDataType, EncryptionRecipient, KekDecryptor, KeyTransportAlgorithm, KeyWrapAlgorithm,
    OaepDigestAlgorithm, PrivateKeyDecryptor, RsaOaepParameters, SymmetricKeyDecryptor,
    XmlEncError, decrypt, decrypt_document, parse_encrypted_data,
};

const DONOR_DIR: &str = "tests/fixtures/xmlenc/aleksey-xmlenc-01";
const RSA_2048_PRIVATE: &str = "tests/fixtures/keys/rsa/rsa-2048-key.pem";
const RSA_2048_PUBLIC: &str = "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem";
const RSA_4096_PRIVATE: &str = "tests/fixtures/keys/rsa/rsa-4096-key.pem";
const RSA_4096_PUBLIC: &str = "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem";

fn private_key(path: &str) -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(path).expect("RSA fixture must load"))
        .expect("RSA fixture must contain a PKCS#8 private key")
}

fn public_key(path: &str) -> RsaPublicKey {
    RsaPublicKey::from_public_key_pem(
        &fs::read_to_string(path).expect("RSA public-key fixture must load"),
    )
    .expect("RSA fixture must contain an SPKI public key")
}

fn method_algorithm(node: Node<'_, '_>) -> String {
    node.attribute("Algorithm")
        .expect("donor EncryptionMethod must declare Algorithm")
        .to_owned()
}

fn donor_key_name(document: &roxmltree::Document<'_>) -> String {
    document
        .descendants()
        .find(|node| node.tag_name().name() == "KeyName")
        .and_then(|node| node.text())
        .map(str::trim)
        .expect("donor template must contain KeyName")
        .to_owned()
}

#[test]
fn donor_direct_templates_match_generated_algorithm_and_key_contracts() {
    // Each imported xmlsec1 template is an independent schema oracle for the
    // algorithm URI and KeyName placement emitted by the public builder.
    for (name, algorithm, key) in [
        (
            "enc-aes128cbc-keyname",
            DataEncryptionAlgorithm::Aes128Cbc,
            vec![0x11; 16],
        ),
        (
            "enc-aes128gcm-keyname",
            DataEncryptionAlgorithm::Aes128Gcm,
            vec![0x22; 16],
        ),
        (
            "enc-aes256cbc-keyname",
            DataEncryptionAlgorithm::Aes256Cbc,
            vec![0x33; 32],
        ),
        (
            "enc-aes256gcm-keyname",
            DataEncryptionAlgorithm::Aes256Gcm,
            vec![0x44; 32],
        ),
    ] {
        let template = fs::read_to_string(format!("{DONOR_DIR}/{name}.tmpl"))
            .expect("tracked donor template must load");
        let template_document =
            roxmltree::Document::parse(&template).expect("donor template must be XML");
        let template_method = template_document
            .descendants()
            .find(|node| node.tag_name().name() == "EncryptionMethod")
            .expect("donor template must contain EncryptionMethod");
        let generated = EncryptedDataBuilder::new(algorithm)
            .direct_key(key.clone())
            .direct_key_name(if algorithm.key_len() == 16 {
                "test-aes128"
            } else {
                "test-aes256"
            })
            .encrypt_binary(format!("{name} plaintext").as_bytes())
            .expect("donor-shaped direct encryption must succeed");
        let generated_data = parse_encrypted_data(&generated.encrypted_data_xml)
            .expect("generated EncryptedData must parse");

        assert_eq!(
            generated_data.encryption_method.algorithm,
            method_algorithm(template_method),
            "{name}"
        );
        assert_eq!(
            generated_data.key_name.as_deref(),
            Some(donor_key_name(&template_document).as_str()),
            "{name}"
        );
        assert_eq!(
            decrypt(
                &generated.encrypted_data_xml,
                &SymmetricKeyDecryptor::new(key)
            )
            .expect("generated donor-shaped ciphertext must decrypt"),
            DecryptedContent::Bytes(format!("{name} plaintext").into_bytes()),
            "{name}"
        );
    }
}

#[test]
fn donor_rsa_templates_match_legacy_and_xmlenc11_oaep_contracts() {
    // The two donor templates cover an OAEP label on the legacy URI and
    // independently configurable digest/MGF algorithms on the 1.1 URI.
    let public = public_key(RSA_4096_PUBLIC);
    let private = private_key(RSA_4096_PRIVATE);
    let cases = [
        (
            "enc-aes256-kt-rsa_oaep_sha1-params",
            RsaOaepParameters::legacy().label(b"12345678".to_vec()),
        ),
        (
            "enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512",
            RsaOaepParameters::xmlenc11(OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512),
        ),
    ];

    for (name, parameters) in cases {
        let template = fs::read_to_string(format!("{DONOR_DIR}/{name}.tmpl"))
            .expect("tracked donor template must load");
        let template_document =
            roxmltree::Document::parse(&template).expect("donor template must be XML");
        let template_methods = template_document
            .descendants()
            .filter(|node| node.tag_name().name() == "EncryptionMethod")
            .collect::<Vec<_>>();
        assert_eq!(template_methods.len(), 2, "{name}");
        let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Cbc)
            .encryption_type(EncryptedDataType::Content)
            .id("ED")
            .add_recipient(
                EncryptionRecipient::rsa_oaep(public.clone())
                    .oaep_parameters(parameters)
                    .key_name("TestKeyName-rsa-4096"),
            )
            .encrypt_xml("<PaymentInfo><Name>John Smith</Name></PaymentInfo>")
            .expect("donor-shaped OAEP encryption must succeed");
        let generated_data = parse_encrypted_data(&generated.encrypted_data_xml)
            .expect("generated EncryptedData must parse");

        assert_eq!(
            generated_data.encryption_method.algorithm,
            method_algorithm(template_methods[0]),
            "{name}"
        );
        assert_eq!(
            generated_data.encrypted_keys[0].encryption_method.algorithm,
            method_algorithm(template_methods[1]),
            "{name}"
        );
        let donor_digest = template_methods[1]
            .children()
            .find(|node| node.tag_name().name() == "DigestMethod")
            .and_then(|node| node.attribute("Algorithm"))
            .map(str::to_owned);
        let donor_mgf = template_methods[1]
            .children()
            .find(|node| node.tag_name().name() == "MGF")
            .and_then(|node| node.attribute("Algorithm"))
            .map(str::to_owned);
        let donor_label = template_methods[1]
            .children()
            .find(|node| node.tag_name().name() == "OAEPparams")
            .and_then(|node| node.text())
            .map(str::trim)
            .map(|value| {
                STANDARD
                    .decode(value)
                    .expect("donor OAEP label must be base64")
            });
        assert_eq!(
            generated_data.encrypted_keys[0]
                .encryption_method
                .oaep_digest,
            donor_digest,
            "{name}"
        );
        assert_eq!(
            generated_data.encrypted_keys[0]
                .encryption_method
                .mgf_algorithm,
            donor_mgf,
            "{name}"
        );
        assert_eq!(
            generated_data.encrypted_keys[0]
                .encryption_method
                .oaep_params,
            donor_label,
            "{name}"
        );
        assert_eq!(
            generated_data.encrypted_keys[0].key_name.as_deref(),
            Some(donor_key_name(&template_document).as_str()),
            "{name}"
        );
        assert_eq!(
            decrypt(
                &generated.encrypted_data_xml,
                &PrivateKeyDecryptor::new(private.clone())
            )
            .expect("generated donor-shaped OAEP ciphertext must decrypt"),
            DecryptedContent::Xml("<PaymentInfo><Name>John Smith</Name></PaymentInfo>".into()),
            "{name}"
        );
    }
}

#[test]
fn every_supported_oaep_digest_and_mgf_combination_round_trips() {
    // Digest and MGF are independent in XMLEnc 1.1; this matrix guards against
    // accidentally dispatching one parameter for both RSA OAEP hash roles.
    let private = private_key(RSA_2048_PRIVATE);
    let public = RsaPublicKey::from(&private);
    let digests = [
        OaepDigestAlgorithm::Sha1,
        OaepDigestAlgorithm::Sha256,
        OaepDigestAlgorithm::Sha384,
        OaepDigestAlgorithm::Sha512,
    ];
    for digest in digests {
        for mgf_digest in digests {
            let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .add_recipient(
                    EncryptionRecipient::rsa_oaep(public.clone())
                        .oaep_parameters(RsaOaepParameters::xmlenc11(digest, mgf_digest)),
                )
                .encrypt_binary(b"OAEP matrix")
                .expect("supported OAEP combination must encrypt");
            assert_eq!(
                decrypt(
                    &encrypted.encrypted_data_xml,
                    &PrivateKeyDecryptor::new(private.clone())
                )
                .expect("supported OAEP combination must decrypt"),
                DecryptedContent::Bytes(b"OAEP matrix".to_vec()),
                "digest={digest:?}, mgf={mgf_digest:?}"
            );
        }
    }

    for digest in digests {
        let parameters = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest,
            mgf_digest: OaepDigestAlgorithm::Sha1,
            label: b"legacy label".to_vec(),
        };
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Cbc)
            .add_recipient(
                EncryptionRecipient::rsa_oaep(public.clone()).oaep_parameters(parameters),
            )
            .encrypt_binary(b"legacy OAEP digest matrix")
            .expect("legacy OAEP digest with fixed MGF1-SHA1 must encrypt");
        assert_eq!(
            decrypt(
                &encrypted.encrypted_data_xml,
                &PrivateKeyDecryptor::new(private.clone())
            )
            .expect("legacy OAEP digest with fixed MGF1-SHA1 must decrypt"),
            DecryptedContent::Bytes(b"legacy OAEP digest matrix".to_vec()),
            "legacy digest={digest:?}"
        );
    }
}

#[test]
fn one_session_key_is_recoverable_by_each_rsa_recipient() {
    // Either recipient must independently recover the same generated session
    // key even when its EncryptedKey is not first in document order.
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .add_recipient(
            EncryptionRecipient::rsa_oaep(public_key(RSA_2048_PUBLIC))
                .recipient("primary")
                .key_name("rsa-2048"),
        )
        .add_recipient(
            EncryptionRecipient::rsa_oaep(public_key(RSA_4096_PUBLIC))
                .recipient("secondary")
                .key_name("rsa-4096"),
        )
        .encrypt_xml("<secret>shared</secret>")
        .expect("multi-recipient encryption must succeed");
    let parsed = parse_encrypted_data(&encrypted.encrypted_data_xml)
        .expect("multi-recipient output must parse");
    assert_eq!(parsed.encrypted_keys.len(), 2);
    assert_eq!(
        parsed.encrypted_keys[0].recipient.as_deref(),
        Some("primary")
    );
    assert_eq!(
        parsed.encrypted_keys[1].recipient.as_deref(),
        Some("secondary")
    );

    for key_path in [RSA_2048_PRIVATE, RSA_4096_PRIVATE] {
        assert_eq!(
            decrypt(
                &encrypted.encrypted_data_xml,
                &PrivateKeyDecryptor::new(private_key(key_path))
            )
            .expect("each recipient must decrypt the shared content"),
            DecryptedContent::Xml("<secret>shared</secret>".into()),
            "{key_path}"
        );
    }
}

#[test]
fn both_aes_key_wrap_sizes_cover_both_content_key_sizes() {
    // RFC 3394 accepts either supported content-key width under either
    // supported KEK width; all four combinations must remain interoperable.
    for (wrap, kek) in [
        (KeyWrapAlgorithm::AesKw128, vec![0x81; 16]),
        (KeyWrapAlgorithm::AesKw256, vec![0x82; 32]),
    ] {
        for algorithm in [
            DataEncryptionAlgorithm::Aes128Cbc,
            DataEncryptionAlgorithm::Aes256Gcm,
        ] {
            let encrypted = EncryptedDataBuilder::new(algorithm)
                .recipient_aes_kw(kek.clone(), wrap)
                .encrypt_binary(b"wrapped content key")
                .expect("supported AES-KW combination must encrypt");
            assert_eq!(
                decrypt(
                    &encrypted.encrypted_data_xml,
                    &KekDecryptor::new(kek.clone())
                )
                .expect("supported AES-KW combination must decrypt"),
                DecryptedContent::Bytes(b"wrapped content key".to_vec())
            );
        }
    }
}

#[test]
fn document_encryption_selects_one_id_and_preserves_surrounding_xml() {
    // Element and Content replacement must preserve unrelated siblings,
    // inherited namespace context, and the selected element's own attributes.
    let key = [0x91; 16];
    let document = "<root xmlns:p=\"urn:test\"><before/><p:target Id=\"chosen\" role=\"secret\"><p:item/>text</p:target><after/></root>";
    for encrypted_type in [EncryptedDataType::Element, EncryptedDataType::Content] {
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encryption_type(encrypted_type)
            .direct_key(key)
            .id("encrypted-target")
            .encrypt_document(
                document,
                DocumentEncryptionOptions {
                    element_id: Some("chosen"),
                    allow_dtd: false,
                },
            )
            .expect("selected document node must encrypt");
        assert!(encrypted.contains("<before/>"));
        assert!(encrypted.contains("<after/>"));
        assert_eq!(
            decrypt_document(
                &encrypted,
                Some("encrypted-target"),
                &SymmetricKeyDecryptor::new(key)
            )
            .expect("selected document node must decrypt"),
            document
        );
    }
}

#[test]
fn content_encryption_preserves_cdata_with_closing_markers() {
    // A `</` sequence inside CDATA must not be mistaken for the selected
    // element's closing tag when calculating the content replacement range.
    let key = [0x92; 16];
    let document = "<root><target Id=\"chosen\"><![CDATA[</not-a-tag>]]></target></root>";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .encryption_type(EncryptedDataType::Content)
        .direct_key(key)
        .encrypt_document(
            document,
            DocumentEncryptionOptions {
                element_id: Some("chosen"),
                allow_dtd: false,
            },
        )
        .expect("CDATA content containing a closing marker must encrypt");

    assert_eq!(
        decrypt_document(&encrypted, None, &SymmetricKeyDecryptor::new(key))
            .expect("CDATA content containing a closing marker must decrypt"),
        document
    );
}

#[test]
fn saml_encrypted_assertion_round_trips_through_rsa_transport() {
    // A SAML EncryptedAssertion contains an XMLEnc EncryptedData child; this
    // verifies assertion namespaces, attributes, and subject data end to end.
    let assertion = concat!(
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
        "ID=\"assertion-1\" Version=\"2.0\" IssueInstant=\"2026-07-21T00:00:00Z\">",
        "<saml:Issuer>https://idp.example</saml:Issuer>",
        "<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>",
        "</saml:Assertion>"
    );
    let private = private_key(RSA_2048_PRIVATE);
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .add_recipient(EncryptionRecipient::rsa_oaep(RsaPublicKey::from(&private)))
        .encrypt_xml(assertion)
        .expect("SAML Assertion must encrypt");
    let response = format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:EncryptedAssertion>{}</saml:EncryptedAssertion></samlp:Response>",
        encrypted.encrypted_data_xml
    );
    let decrypted = decrypt_document(&response, None, &PrivateKeyDecryptor::new(private))
        .expect("SAML EncryptedAssertion child must decrypt");
    assert_eq!(
        decrypted,
        format!(
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:EncryptedAssertion>{assertion}</saml:EncryptedAssertion></samlp:Response>"
        )
    );
}

#[test]
fn invalid_targets_configuration_and_keys_fail_closed() {
    // Malformed XML, ambiguous IDs, missing IDs, incompatible key sources, and
    // wrong KEKs must fail explicitly rather than processing unintended data.
    let key = [0xa1; 16];
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).direct_key(key);
    assert!(matches!(
        builder.encrypt_xml("<root><unclosed></root>"),
        Err(XmlEncError::XmlParse(_))
    ));
    assert!(matches!(
        builder
            .clone()
            .encryption_type(EncryptedDataType::Content)
            .encrypt_xml("<unclosed>"),
        Err(XmlEncError::XmlParse(_))
    ));
    assert!(matches!(
        builder.encrypt_document(
            "<root><unclosed></root>",
            DocumentEncryptionOptions::default()
        ),
        Err(XmlEncError::XmlParse(_))
    ));
    assert!(matches!(
        builder.encrypt_document(
            "<root><a Id=\"same\"/><b id=\"same\"/></root>",
            DocumentEncryptionOptions {
                element_id: Some("same"),
                allow_dtd: false,
            }
        ),
        Err(XmlEncError::AmbiguousEncryptionTarget)
    ));
    assert!(matches!(
        builder.encrypt_document(
            "<root/>",
            DocumentEncryptionOptions {
                element_id: Some("missing"),
                allow_dtd: false,
            }
        ),
        Err(XmlEncError::EncryptionTargetNotFound)
    ));

    let incompatible = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .add_recipient(EncryptionRecipient::aes_key_wrap(
            [0xb2; 16],
            KeyWrapAlgorithm::AesKw128,
        ))
        .encrypt_binary(b"must not encrypt");
    assert!(matches!(
        incompatible,
        Err(XmlEncError::InvalidEncryptionConfig(_))
    ));

    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .recipient_aes_kw([0xc3; 16], KeyWrapAlgorithm::AesKw128)
        .encrypt_binary(b"secret")
        .expect("valid KEK must encrypt");
    assert!(matches!(
        decrypt(
            &encrypted.encrypted_data_xml,
            &KekDecryptor::new([0xd4; 16])
        ),
        Err(XmlEncError::KeyWrapIntegrity)
    ));
}

#[test]
fn tampered_generated_gcm_ciphertext_fails_authentication() {
    // A generated GCM value must authenticate its ciphertext and tag; changing
    // one base64 character must never yield unauthenticated plaintext.
    let key = [0xf6; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .encrypt_binary(b"authenticated plaintext")
        .expect("GCM encryption must succeed");
    let mut tampered = encrypted.encrypted_data_xml;
    let value_end = tampered
        .find("</xenc:CipherValue>")
        .expect("generated output must contain CipherValue");
    let index = value_end - 2;
    let replacement = if &tampered[index..=index] == "A" {
        "B"
    } else {
        "A"
    };
    tampered.replace_range(index..=index, replacement);

    assert!(matches!(
        decrypt(&tampered, &SymmetricKeyDecryptor::new(key)),
        Err(XmlEncError::AeadAuthenticationFailed)
    ));
}

#[test]
fn generated_metadata_is_xml_escaped_and_legacy_mgf_is_restricted() {
    // Caller metadata must remain data after serialization, and the legacy
    // OAEP URI cannot falsely advertise a configurable non-SHA1 MGF.
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .id("encrypted<&\"")
        .add_recipient(
            EncryptionRecipient::aes_key_wrap([0xe5; 16], KeyWrapAlgorithm::AesKw128)
                .recipient("recipient<&\"")
                .key_name("key<&"),
        )
        .encrypt_binary(b"metadata")
        .expect("metadata must serialize safely");
    let parsed =
        parse_encrypted_data(&encrypted.encrypted_data_xml).expect("escaped metadata must parse");
    assert_eq!(parsed.id.as_deref(), Some("encrypted<&\""));
    assert_eq!(
        parsed.encrypted_keys[0].recipient.as_deref(),
        Some("recipient<&\"")
    );
    assert_eq!(parsed.encrypted_keys[0].key_name.as_deref(), Some("key<&"));

    let invalid_legacy = RsaOaepParameters {
        algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
        digest: OaepDigestAlgorithm::Sha256,
        mgf_digest: OaepDigestAlgorithm::Sha256,
        label: Vec::new(),
    };
    assert!(matches!(
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .add_recipient(
                EncryptionRecipient::rsa_oaep(public_key(RSA_2048_PUBLIC))
                    .oaep_parameters(invalid_legacy)
            )
            .encrypt_binary(b"invalid legacy MGF"),
        Err(XmlEncError::InvalidEncryptionConfig(_))
    ));
}
