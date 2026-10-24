//! Deterministic historical attack classes; sources and scope: docs/historical-security.md.
#![cfg(all(feature = "xmldsig", feature = "c14n"))]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use xml_sec::XmlDocument;
use xml_sec::policy::{
    CompiledPolicies, PolicyCompileContext, PolicyCompiler, PolicyProfile, PolicyViolation,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, HmacSigningKey, HmacVerificationKey, KeyInfo,
    KeyInfoSource, KeyResolutionError, KeyResolver, KeyValueInfo, SignContext, SignatureAlgorithm,
    VerificationRequest, VerifyContext,
};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SECRET: [u8; 32] = [0x39; 32];

fn profile(name: PolicyProfile) -> CompiledPolicies {
    PolicyCompiler::new(name, &RustCryptoProvider, None)
        .unwrap()
        .compile(&PolicyCompileContext {
            external_resources: false,
            target_evidence: true,
        })
        .unwrap()
}

fn template(uri: &str, parameters: &str, key_info: &str) -> String {
    format!(
        r#"<root><payload ID="target">authenticated</payload><ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256">{parameters}</ds:SignatureMethod><ds:Reference URI="{uri}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>{key_info}</ds:Signature></root>"#
    )
}

fn signed(parameters: &str) -> String {
    SignContext::new(&HmacSigningKey::new(SECRET.to_vec()).unwrap())
        .policy(profile(PolicyProfile::Modern).signing().unwrap().clone())
        .sign_template(&template("#target", parameters, ""))
        .unwrap()
}

#[test]
fn wrapping_cannot_authorize_an_unsigned_sibling_even_with_valid_crypto() {
    // W3C XMLDSig Best Practices §3.1.5 / XMLDSig 1.1 §8.1.1: use signed identity,
    // not the first matching element name. Preserve a genuinely valid signature.
    let original = signed("");
    let wrapped = original.replace(
        "<payload ID=\"target\">authenticated</payload>",
        "<payload ID=\"decoy\">admin</payload><hidden><payload ID=\"target\">authenticated</payload></hidden>",
    );
    assert_ne!(original, wrapped);
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    for backend in xml_sec::XmlBackend::available() {
        let document = XmlDocument::parse_with_backend(wrapped.clone(), backend).unwrap();
        let (target, decoy) = document.with_view(|view| {
            (
                view.node_for_id("target", &[]).unwrap(),
                view.node_for_id("decoy", &[]).unwrap(),
            )
        });
        let context = VerifyContext::new().key(&key).xml_backend(backend).policy(
            profile(PolicyProfile::Modern)
                .verification()
                .unwrap()
                .clone(),
        );
        for (expected, accepted) in [(target, true), (decoy, false)] {
            let targets = [expected];
            let evidence = context
                .verify_request(
                    &document,
                    &VerificationRequest {
                        expected_targets: &targets,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(evidence.all_valid());
            assert_eq!(evidence.accepted(&document).unwrap(), accepted);
            assert!(evidence.covers_element(&document, target).unwrap());
            assert!(!evidence.covers_element(&document, decoy).unwrap());
        }
    }
}

#[test]
fn secure_saml_requires_the_authenticated_assertion_not_the_first_assertion() {
    // XMLDSig Best Practices §3.1.5 applies to SAML too: a valid signature on
    // the relocated Assertion cannot grant coverage to an unsigned sibling.
    let policies = profile(PolicyProfile::SecureSaml);
    let signer = HmacSigningKey::new(SECRET.to_vec()).unwrap();
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    let xml = template("#target", "", "")
        .replace("<root><payload ID=\"target\">authenticated</payload>",
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"target\"><payload>authenticated</payload>")
        .replace("</root>", "</saml:Assertion>")
        .replace("<ds:Transforms>", "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>");
    let original = SignContext::new(&signer)
        .policy(policies.signing().unwrap().clone())
        .sign_template(&xml)
        .unwrap();
    let wrapped = format!(
        "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='decoy'><payload>admin</payload></saml:Assertion><hidden>{original}</hidden></samlp:Response>"
    );
    for backend in xml_sec::XmlBackend::available() {
        for source in [&original, &wrapped] {
            let document = XmlDocument::parse_with_backend(source.as_str(), backend).unwrap();
            let target = document.with_view(|view| view.node_for_id("target", &[]).unwrap());
            let targets = [target];
            let context = VerifyContext::new()
                .key(&key)
                .xml_backend(backend)
                .policy(policies.verification().unwrap().clone());
            let evidence = context
                .verify_request(
                    &document,
                    &VerificationRequest {
                        expected_targets: &targets,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(evidence.accepted(&document).unwrap());
            if source == &wrapped {
                let decoy = document.with_view(|view| view.node_for_id("decoy", &[]).unwrap());
                assert!(!evidence.covers_element(&document, decoy).unwrap());
                let targets = [decoy];
                let evidence = context
                    .verify_request(
                        &document,
                        &VerificationRequest {
                            expected_targets: &targets,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                assert!(!evidence.accepted(&document).unwrap());
            }
        }
    }
}

#[test]
fn duplicate_ids_never_choose_an_attacker_controlled_first_or_last_match() {
    // Wrapping through duplicate IDs must fail in both document orders, even
    // when the attacker copies the authentic text rather than changing it.
    let original = signed("");
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    for text in ["authenticated", "admin"] {
        for placement in ["before", "after"] {
            let payload = "<payload ID=\"target\">authenticated</payload>";
            let duplicate = format!("<payload xml:id=\"target\">{text}</payload>");
            let replacement = if placement == "before" {
                format!("{duplicate}{payload}")
            } else {
                format!("{payload}{duplicate}")
            };
            let attack = original.replace(payload, &replacement);
            for backend in xml_sec::XmlBackend::available() {
                let context = VerifyContext::new().key(&key).xml_backend(backend).policy(
                    profile(PolicyProfile::Modern)
                        .verification()
                        .unwrap()
                        .clone(),
                );
                assert_eq!(context.verify(&original).unwrap().status, DsigStatus::Valid);
                assert!(
                    context.verify(&attack).is_err(),
                    "{backend:?}/{placement}/{text}"
                );
            }
        }
    }
}

#[test]
fn hmac_truncation_refuses_genuine_short_prefixes_not_only_random_forgeries() {
    // CERT VU#466161; XMLDSig 1.1 §6.3.1. HMAC length is attacker-controlled.
    // Use an authentic 128-bit MAC and a real prefix rather than random bytes.
    let original = signed("<ds:HMACOutputLength>128</ds:HMACOutputLength>");
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    for backend in xml_sec::XmlBackend::available() {
        let context = VerifyContext::new().key(&key).xml_backend(backend).policy(
            profile(PolicyProfile::Modern)
                .verification()
                .unwrap()
                .clone(),
        );
        assert_eq!(context.verify(&original).unwrap().status, DsigStatus::Valid);
        for bits in [80, 120] {
            let document = roxmltree::Document::parse(&original).unwrap();
            let mac = document
                .descendants()
                .find(|n| n.has_tag_name((DS, "SignatureValue")))
                .unwrap()
                .text()
                .unwrap();
            let prefix = &STANDARD.decode(mac).unwrap()[..bits / 8];
            let attack = original.replace(mac, &STANDARD.encode(prefix)).replace(
                ">128</ds:HMACOutputLength>",
                &format!(">{bits}</ds:HMACOutputLength>"),
            );
            assert!(matches!(context.verify(&attack),
                Err(DsigError::Policy(PolicyViolation::HmacOutputLength { minimum: 128, actual, .. })) if actual == bits));
        }
    }
}

#[test]
fn retrieval_method_self_reference_is_not_recursive_key_discovery() {
    // W3C Best Practices §2.1.5: a RetrievalMethod may point back to itself.
    // X509Data retrieval must select X509Data, not recursively chase arbitrary XML.
    let original = signed("");
    let attack = original.replace("</ds:Signature>", &format!(
        r##"<ds:KeyInfo><ds:RetrievalMethod ID="loop" URI="#loop" Type="{DS}X509Data"/></ds:KeyInfo></ds:Signature>"##));
    for backend in xml_sec::XmlBackend::available() {
        let resolver = DefaultKeyResolver::default();
        let error = VerifyContext::new()
            .xml_backend(backend)
            .key_resolver(&resolver)
            .policy(
                profile(PolicyProfile::Modern)
                    .verification()
                    .unwrap()
                    .clone(),
            )
            .verify(&attack)
            .unwrap_err();
        assert!(
            matches!(
                error,
                DsigError::InvalidStructure {
                    reason: "untransformed X509Data RetrievalMethod must target X509Data directly"
                }
            ),
            "{error:?}"
        );
    }
}

#[test]
fn external_reference_and_retrieval_uris_are_refused_before_acquisition() {
    // W3C Best Practices §2.1.6: neither file nor network identifiers confer
    // authority. No network/filesystem resolver is installed by this test.
    let original = signed("");
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    for uri in [
        "file:///xml-sec-forbidden",
        "https://invalid.example/secret",
        "../secret",
    ] {
        for backend in xml_sec::XmlBackend::available() {
            let context = VerifyContext::new().xml_backend(backend).key(&key).policy(
                profile(PolicyProfile::Modern)
                    .verification()
                    .unwrap()
                    .clone(),
            );
            let reference = original.replace("URI=\"#target\"", &format!("URI=\"{uri}\""));
            assert!(matches!(
                context.verify(&reference),
                Err(DsigError::Policy(PolicyViolation::Uri { .. }))
            ));
            let retrieval = original.replace("</ds:Signature>", &format!(
                r#"<ds:KeyInfo><ds:RetrievalMethod URI="{uri}" Type="{DS}rawX509Certificate"/></ds:KeyInfo></ds:Signature>"#));
            let resolver = DefaultKeyResolver::default();
            assert!(matches!(
                VerifyContext::new()
                    .xml_backend(backend)
                    .key_resolver(&resolver)
                    .policy(
                        profile(PolicyProfile::Modern)
                            .verification()
                            .unwrap()
                            .clone()
                    )
                    .verify(&retrieval),
                Err(DsigError::Policy(PolicyViolation::Uri { .. }))
            ));
        }
    }
}

#[test]
fn entity_amplification_is_refused_at_the_public_xml_policy_boundary() {
    // W3C Best Practices §4.2: DTD processing changes signed XML. Secure
    // profiles refuse it before expansion, including external entity declarations.
    let original = signed("");
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    for subset in [
        "<!ENTITY a '1234567890'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'><!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>",
        "<!ENTITY c SYSTEM 'file:///xml-sec-forbidden'>",
    ] {
        let attack = format!(
            "<!DOCTYPE root [{subset}]>{}",
            original.replace("authenticated", "&c;")
        );
        for backend in xml_sec::XmlBackend::available() {
            let context = VerifyContext::new().key(&key).xml_backend(backend).policy(
                profile(PolicyProfile::Modern)
                    .verification()
                    .unwrap()
                    .clone(),
            );
            assert_eq!(context.verify(&original).unwrap().status, DsigStatus::Valid);
            assert!(matches!(
                context.verify(&attack),
                Err(DsigError::XmlParse(_))
            ));
        }
    }
}

#[test]
fn rsa_oversized_modulus_and_exponent_refuse_before_big_integer_verification() {
    // XMLDSig 1.1 §8.3 discusses algorithm/key-length choices. Concrete CPU
    // ceilings are product safety limits, not invented RSA wire requirements.
    let resolver = DefaultKeyResolver::default();
    let policy = profile(PolicyProfile::Modern)
        .verification()
        .unwrap()
        .clone();
    for (width, exponent) in [
        (2048usize, vec![1, 0, 1]),
        (8193, vec![1, 0, 1]),
        (2048, vec![2, 0, 0, 0, 1]),
    ] {
        let valid = width == 2048 && exponent == [1, 0, 1];
        let mut modulus = vec![0xff; width.div_ceil(8)];
        modulus[0] = if width % 8 == 0 { 0xff } else { 1 };
        let mut info = KeyInfo::default();
        info.sources
            .push(KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus,
                exponent,
            }));
        let result =
            resolver.resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy);
        if valid {
            assert!(result.unwrap().is_some());
            continue;
        }
        let Err(error) = result else {
            panic!("unbounded RSA work admitted");
        };
        assert!(
            matches!(
                error,
                DsigError::KeyResolution(KeyResolutionError::InvalidPublicKey)
            ),
            "{error:?}"
        );
    }
}

#[cfg(feature = "xslt")]
#[test]
fn xslt_amplification_keeps_compatibility_but_cannot_escape_operation_limits() {
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        DigestAlgorithm, ReferenceBuilder, SignatureBuilder, Transform, XsltStylesheet,
    };
    // W3C Best Practices §2.1.1: nested XPath-driven loops multiply work.
    // The bounded, genuinely signed example is valid under compatibility;
    // Modern refuses the transform and a tighter compatibility budget refuses work.
    let sheet = XsltStylesheet::new(concat!(
        "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'>",
        "<xsl:output method='text'/><xsl:template match='/'>",
        "<xsl:for-each select='//item'><xsl:for-each select='//item'>",
        "<xsl:for-each select='//item'><xsl:for-each select='//item'>",
        "<xsl:value-of select='.'/></xsl:for-each></xsl:for-each></xsl:for-each></xsl:for-each>",
        "</xsl:template></xsl:stylesheet>"
    ))
    .unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#target")
            .transform(Transform::Xslt(sheet)),
    );
    let compatibility = profile(PolicyProfile::XmlSecCompatible);
    let signer = HmacSigningKey::new(SECRET.to_vec()).unwrap();
    let key = HmacVerificationKey::new(SECRET.to_vec()).unwrap();
    let original = SignContext::new(&signer).policy(compatibility.signing().unwrap().clone())
        .sign_with_builder("<root><items ID='target'><item>a</item><item>b</item><item>c</item><item>d</item><item>e</item><item>f</item><item>g</item><item>h</item></items></root>", &builder).unwrap();
    let small = SignContext::new(&signer)
        .policy(compatibility.signing().unwrap().clone())
        .sign_with_builder(
            "<root><items ID='target'><item>a</item></items></root>",
            &builder,
        )
        .unwrap();
    for backend in xml_sec::XmlBackend::available() {
        let context = VerifyContext::new().key(&key).xml_backend(backend);
        assert_eq!(
            context
                .policy(compatibility.verification().unwrap().clone())
                .verify(&original)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
        let error = VerifyContext::new()
            .key(&key)
            .xml_backend(backend)
            .policy(
                profile(PolicyProfile::Modern)
                    .verification()
                    .unwrap()
                    .clone(),
            )
            .verify(&original)
            .unwrap_err();
        assert!(
            matches!(error, DsigError::Policy(PolicyViolation::Algorithm { .. })),
            "{error:?}"
        );
        let mut bounded = compatibility.verification().unwrap().clone();
        bounded.resources.max_xslt_work = 50_000;
        let small_result = VerifyContext::new()
            .key(&key)
            .xml_backend(backend)
            .policy(bounded.clone())
            .store_pre_digest(true)
            .verify(&small)
            .unwrap();
        assert_eq!(small_result.status, DsigStatus::Valid);
        assert_eq!(
            small_result.signed_info_references[0]
                .pre_digest_data
                .as_deref(),
            Some(b"a".as_slice())
        );
        let error = VerifyContext::new()
            .key(&key)
            .xml_backend(backend)
            .policy(bounded)
            .verify(&original)
            .unwrap_err();
        assert!(
            matches!(
                error,
                DsigError::Policy(PolicyViolation::ResourceLimit {
                    resource: "XSLT work",
                    ..
                })
            ),
            "{error:?}"
        );
    }
}

#[cfg(feature = "xmlenc")]
#[test]
fn cbc_downgrade_and_padding_probes_have_one_pre_decryption_policy_refusal() {
    use xml_sec::policy::EncryptionPolicy;
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm as Data, DecryptContext, DecryptedContent, DecryptionKeyResolver,
        EncryptedDataBuilder, EncryptedKey, SymmetricKeyDecryptor, XmlEncError,
    };
    struct ForbiddenKey;
    impl DecryptionKeyResolver for ForbiddenKey {
        fn resolve_key(
            &self,
            _: &dyn xml_sec::provider::CryptoProvider,
            _: Data,
            _: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            panic!("denied CBC input must not request a key")
        }
    }
    // XMLEnc 1.1 §6.1.3: secure profiles must not become CBC padding oracles.
    // Assert policy-before-decryption, not timing equality of an XML processor.
    let key = [0x52; 16];
    let resolver = SymmetricKeyDecryptor::new(key);
    let modern = profile(PolicyProfile::Modern);
    let compatibility = profile(PolicyProfile::XmlSecCompatible);
    let plaintext = b"historical regression control";
    let good = EncryptedDataBuilder::new(Data::Aes128Gcm)
        .direct_key(key.as_slice())
        .policy(modern.encryption().unwrap().clone())
        .encrypt_binary(plaintext)
        .unwrap();
    let cbc = EncryptedDataBuilder::new(Data::Aes128Cbc)
        .direct_key(key.as_slice())
        .policy(EncryptionPolicy {
            data_algorithms: Some([Data::Aes128Cbc].into()),
            ..Default::default()
        })
        .encrypt_binary(plaintext)
        .unwrap();
    for backend in xml_sec::XmlBackend::available() {
        let context = DecryptContext::new(&resolver)
            .xml_backend(backend)
            .policy(modern.decryption().unwrap().clone());
        assert_eq!(
            context.decrypt(&good.encrypted_data_xml).unwrap(),
            DecryptedContent::Bytes(plaintext.to_vec())
        );
        let legacy = DecryptContext::new(&resolver)
            .xml_backend(backend)
            .policy(compatibility.decryption().unwrap().clone());
        assert_eq!(
            legacy.decrypt(&cbc.encrypted_data_xml).unwrap(),
            DecryptedContent::Bytes(plaintext.to_vec())
        );
        let downgrade = good
            .encrypted_data_xml
            .replace(Data::Aes128Gcm.uri(), Data::Aes128Cbc.uri());
        let no_key = ForbiddenKey;
        let guarded = DecryptContext::new(&no_key)
            .xml_backend(backend)
            .policy(modern.decryption().unwrap().clone());
        for attack in [&cbc.encrypted_data_xml, &downgrade] {
            assert!(matches!(
                context.decrypt(attack),
                Err(XmlEncError::Policy(PolicyViolation::Algorithm { .. }))
            ));
            assert!(matches!(
                guarded.decrypt(attack),
                Err(XmlEncError::Policy(PolicyViolation::Algorithm { .. }))
            ));
        }
        let document = roxmltree::Document::parse(&cbc.encrypted_data_xml).unwrap();
        let text = document
            .descendants()
            .find(|n| n.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
            .unwrap()
            .text()
            .unwrap();
        let ciphertext = STANDARD.decode(text).unwrap();
        for tail in [0, 1, 16, 17, 255] {
            let mut probe = ciphertext.clone();
            *probe.last_mut().unwrap() = tail;
            let probe = cbc
                .encrypted_data_xml
                .replace(text, &STANDARD.encode(probe));
            assert!(matches!(
                context.decrypt(&probe),
                Err(XmlEncError::Policy(PolicyViolation::Algorithm { .. }))
            ));
            assert!(matches!(
                guarded.decrypt(&probe),
                Err(XmlEncError::Policy(PolicyViolation::Algorithm { .. }))
            ));
        }
    }
}
