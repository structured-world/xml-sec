//! Modern XMLDSig algorithms must work through the public provider and policy paths.
#![cfg(feature = "xmldsig")]

use xml_sec::xmldsig::{DigestAlgorithm, compute_digest};

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

#[test]
fn pure_eddsa_identifiers_are_recognized() {
    // RFC 9231 section 2.3.12 assigns pure EdDSA URIs independently
    // from prehash/context variants; suffix matching cannot substitute.
    for name in ["ed25519", "ed25519ctx", "ed25519ph", "ed448", "ed448ph"] {
        let uri = format!("http://www.w3.org/2021/04/xmldsig-more#eddsa-{name}");
        let algorithm =
            xml_sec::xmldsig::SignatureAlgorithm::from_uri(&uri).expect("pure EdDSA URI");
        assert_eq!(algorithm.uri(), uri);
    }
}

#[test]
fn ed25519ctx_matches_rfc8032_known_answer() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{
        EdDsaSigningKey, SignatureAlgorithm, SignatureContext, SigningKey, VerificationKey,
        VerifyingKey,
    };
    // RFC 8032 section 7.2 "foo" proves exact dom2 placement, not just that
    // our own signer and verifier agree on the same mistake.
    let algorithm =
        SignatureAlgorithm::from_uri("http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ctx")
            .unwrap();
    let secret: [u8; 32] =
        decode_hex("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")
            .try_into()
            .unwrap();
    let der = ed25519_dalek::SigningKey::from_bytes(&secret)
        .to_pkcs8_der()
        .unwrap();
    let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
    let context = SignatureContext::new(b"foo").unwrap();
    let message = decode_hex("f726936d19c800494e3fdaff20b276a8");
    let signature = xml_sec::provider::default_provider()
        .sign_with_context(&key, algorithm, &context, &message)
        .unwrap();
    assert_eq!(
        signature,
        decode_hex(
            "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d"
        )
    );
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert!(
        verifier
            .verify_with_context(algorithm, &context, &message, &signature)
            .unwrap()
    );
    assert!(
        !verifier
            .verify_with_context(
                algorithm,
                &SignatureContext::new(b"bar").unwrap(),
                &message,
                &signature
            )
            .unwrap()
    );
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn builder_preserves_context_through_public_signing_pipeline() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        DsigStatus, EdDsaSigningKey, ReferenceBuilder, SignContext, SignatureAlgorithm,
        SignatureBuilder, SignatureContext, SigningKey, Transform, VerificationKey, VerifyContext,
    };
    // Context is authenticated SignedInfo data, not an out-of-band signer option.
    // The builder must encode it and the verifier must recover the same bytes.
    let algorithm = SignatureAlgorithm::Ed25519Ctx;
    let der = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
        .to_pkcs8_der()
        .unwrap();
    let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
    let builder =
        SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
            .signature_context(SignatureContext::new(b"foo").unwrap())
            .add_reference(
                ReferenceBuilder::new(DigestAlgorithm::Sha256)
                    .uri("")
                    .transform(Transform::Enveloped),
            );
    let signed = SignContext::new(&key)
        .sign_with_builder("<root>payload</root>", &builder)
        .unwrap();
    assert!(signed.contains(">Zm9v</"));
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert_eq!(
        VerifyContext::new()
            .key(&verifier)
            .verify(&signed)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
    // Pure Ed25519 has no context parameter; never silently discard caller input.
    let invalid = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::Ed25519,
    )
    .signature_context(SignatureContext::new(b"foo").unwrap())
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));
    assert!(invalid.build_template().is_err());
}

#[test]
fn all_eddsa_context_and_prehash_methods_complete_xml_pipeline() {
    use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use xml_sec::xmldsig::{
        DsigStatus, EdDsaSigningKey, SignContext, SignatureAlgorithm as A, SignatureContext,
        SigningKey, VerificationKey, VerifyContext, verify_signature_with_pem_key,
    };
    // Context/prehash methods must survive XML parsing and the public PEM
    // convenience path, not merely direct provider calls.
    let small = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let large = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..]).unwrap();
    for algorithm in [A::Ed25519Ctx, A::Ed25519Ph, A::Ed448, A::Ed448Ph] {
        let (der, pem) = if matches!(algorithm, A::Ed25519Ctx | A::Ed25519Ph) {
            (
                small.to_pkcs8_der().unwrap(),
                small
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap(),
            )
        } else {
            (
                large.to_pkcs8_der().unwrap(),
                large
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap(),
            )
        };
        let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
        let xml = template(algorithm);
        let marker = format!("<SignatureMethod Algorithm=\"{}\"/>", algorithm.uri());
        let replacement = format!(
            "<SignatureMethod Algorithm=\"{}\"><e:EdDSAContextString xmlns:e=\"http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#\">Zm9v</e:EdDSAContextString></SignatureMethod>",
            algorithm.uri()
        );
        assert!(xml.contains(&marker));
        let signed = SignContext::new(&key)
            .sign_template(&xml.replace(&marker, &replacement))
            .unwrap();
        let verifier = VerificationKey {
            algorithm,
            public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
            certificate_der: None,
            name: None,
        };
        assert_eq!(
            VerifyContext::new()
                .key(&verifier)
                .verify(&signed)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
        assert_eq!(
            verify_signature_with_pem_key(&signed, &pem, false)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
        assert!(SignatureContext::new(&[0; 256]).is_err());
    }
}

#[test]
fn context_parameter_accepts_exact_wire_limit_and_rejects_malformed_base64() {
    use base64::Engine;
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{EdDsaSigningKey, SignContext, SignatureAlgorithm};
    // RFC 8032 §5 permits exactly 255 octets. Whitespace and text-node
    // boundaries must not change the octets; noncanonical Base64 must fail.
    let algorithm = SignatureAlgorithm::Ed25519Ctx;
    let der = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
        .to_pkcs8_der()
        .unwrap();
    let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
    let xml = template(algorithm);
    let marker = format!("<SignatureMethod Algorithm=\"{}\"/>", algorithm.uri());
    let with_context = |text: &str| {
        xml.replace(&marker, &format!(
        "<SignatureMethod Algorithm=\"{}\"><EdDSAContextString xmlns=\"http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#\">{text}</EdDSAContextString></SignatureMethod>",
        algorithm.uri()
    ))
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode([0x42; 255]);
    let split = format!(
        " {}<!-- text boundary -->\n{} ",
        &encoded[..100],
        &encoded[100..]
    );
    assert!(
        SignContext::new(&key)
            .sign_template(&with_context(&split))
            .is_ok()
    );
    for malformed in [
        base64::engine::general_purpose::STANDARD.encode([0x42; 256]),
        "Zh==".to_owned(),       // Nonzero unused trailing bits.
        "Zm9v=AAA".to_owned(),   // Padding before the final quantum.
        "Zm9v\u{a0}".to_owned(), // Not XML whitespace.
        "<nested/>".to_owned(),
    ] {
        assert!(
            SignContext::new(&key)
                .sign_template(&with_context(&malformed))
                .is_err()
        );
    }
}

#[cfg(feature = "experimental-pq")]
fn pq_pipeline(algorithm: xml_sec::xmldsig::PqAlgorithm, der: &[u8]) {
    use xml_sec::policy::{SigningPolicy, VerificationPolicy};
    use xml_sec::xmldsig::{
        DsigStatus, PostQuantumSigningKey, ReferenceBuilder, SignContext, SignatureAlgorithm,
        SignatureBuilder, SignatureContext, SigningKey, Transform, VerificationKey, VerifyContext,
    };
    // Feature compilation is not permission. Exercise explicit policy, key
    // import/export, domain separation, reference digest and wrong-message failure.
    let key = PostQuantumSigningKey::from_pkcs8_der(algorithm, der).unwrap();
    let exported = key.to_pkcs8_der().unwrap();
    let restored = PostQuantumSigningKey::from_pkcs8_der(algorithm, exported.as_bytes()).unwrap();
    assert_eq!(
        key.public_key_info().unwrap(),
        restored.public_key_info().unwrap()
    );
    let method = SignatureAlgorithm::PostQuantum(algorithm);
    let xml = template(method);
    assert!(SignContext::new(&key).sign_template(&xml).is_err());
    let signing_policy = SigningPolicy {
        signature_algorithms: Some([method].into()),
        ..SigningPolicy::default()
    };
    let builder = SignatureBuilder::new(
        xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Exclusive1_0, false),
        method,
    )
    .signature_context(SignatureContext::new(b"xml-sec test context").unwrap())
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let signed = SignContext::new(&key)
        .policy(signing_policy)
        .sign_with_builder("<root>authenticated</root>", &builder)
        .unwrap();
    let verifier = VerificationKey {
        algorithm: method,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert!(VerifyContext::new().key(&verifier).verify(&signed).is_err());
    let policy = VerificationPolicy {
        signature_algorithms: Some([method].into()),
        ..VerificationPolicy::default()
    };
    assert_eq!(
        VerifyContext::new()
            .policy(policy.clone())
            .key(&verifier)
            .verify(&signed)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
    assert_ne!(
        VerifyContext::new()
            .policy(policy)
            .key(&verifier)
            .verify(&signed.replace("authenticated", "altered"))
            .unwrap()
            .status,
        DsigStatus::Valid
    );
}

#[cfg(feature = "experimental-pq")]
macro_rules! ml_pipeline_test {
    ($name:ident, $parameter:ty, $algorithm:ident) => {
        #[test]
        fn $name() {
            use pkcs8::EncodePrivateKey;
            // Fixed public test seed makes import/export and pipeline reproducible.
            let key = ml_dsa::SigningKey::<$parameter>::from_seed(&[0x42; 32].into());
            pq_pipeline(
                xml_sec::xmldsig::PqAlgorithm::$algorithm,
                key.to_pkcs8_der().unwrap().as_bytes(),
            );
        }
    };
}

#[cfg(feature = "experimental-pq")]
ml_pipeline_test!(ml_dsa44_complete_pipeline, ml_dsa::MlDsa44, MlDsa44);
#[cfg(feature = "experimental-pq")]
ml_pipeline_test!(ml_dsa65_complete_pipeline, ml_dsa::MlDsa65, MlDsa65);
#[cfg(feature = "experimental-pq")]
ml_pipeline_test!(ml_dsa87_complete_pipeline, ml_dsa::MlDsa87, MlDsa87);

#[cfg(feature = "experimental-pq")]
fn ml_expanded_formats<P>(algorithm: xml_sec::xmldsig::PqAlgorithm)
where
    P: ml_dsa::MlDsaParams
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    use pkcs8::der::{Encode, asn1::OctetStringRef};
    use xml_sec::xmldsig::PostQuantumSigningKey;
    // RFC 9881 section 6 defines seed, expanded and both as distinct ASN.1
    // choices. Exercise each through the real signing/verification pipeline.
    let seed = [0x42; 32];
    let native = ml_dsa::SigningKey::<P>::from_seed(&seed.into());
    #[allow(deprecated)] // RFC 9881 requires expanded-key interoperability.
    let expanded = native.expanded_key().to_expanded();
    let expanded_inner = OctetStringRef::new(&expanded).unwrap().to_der().unwrap();
    let wrap = |inner: &[u8]| {
        pkcs8::SecretDocument::encode_msg(&pkcs8::PrivateKeyInfoRef::new(
            P::ALGORITHM_IDENTIFIER,
            OctetStringRef::new(inner).unwrap(),
        ))
        .unwrap()
    };
    let expanded_der = wrap(&expanded_inner);
    pq_pipeline(algorithm, expanded_der.as_bytes());

    let mut both_content = OctetStringRef::new(&seed).unwrap().to_der().unwrap();
    both_content.extend_from_slice(&expanded_inner);
    // All three expanded forms exceed 255 bytes and remain below 65536.
    let length = u16::try_from(both_content.len()).unwrap().to_be_bytes();
    let mut both = vec![0x30, 0x82, length[0], length[1]];
    both.extend_from_slice(&both_content);
    pq_pipeline(algorithm, wrap(&both).as_bytes());

    // A matching public key is not sufficient: a conflicting seed/expanded
    // pair must be rejected per RFC 9881 section 8.2, not silently preferred.
    both[6] ^= 1;
    assert!(PostQuantumSigningKey::from_pkcs8_der(algorithm, wrap(&both).as_bytes()).is_err());
    let mut malformed = expanded.clone();
    malformed[128] = 0xff;
    let inner = OctetStringRef::new(&malformed).unwrap().to_der().unwrap();
    assert!(PostQuantumSigningKey::from_pkcs8_der(algorithm, wrap(&inner).as_bytes()).is_err());
}

#[cfg(feature = "experimental-pq")]
#[test]
fn ml_dsa_all_pkcs8_forms_are_checked() {
    ml_expanded_formats::<ml_dsa::MlDsa44>(xml_sec::xmldsig::PqAlgorithm::MlDsa44);
    ml_expanded_formats::<ml_dsa::MlDsa65>(xml_sec::xmldsig::PqAlgorithm::MlDsa65);
    ml_expanded_formats::<ml_dsa::MlDsa87>(xml_sec::xmldsig::PqAlgorithm::MlDsa87);
}

#[cfg(feature = "experimental-pq")]
#[test]
fn pq_keys_work_through_inventory_and_named_resolver() {
    use pkcs8::{EncodePrivateKey, EncodePublicKey};
    use signature::Keypair;
    use xml_sec::key_manager::{KeyInventory, KeyUsages};
    use xml_sec::policy::{ResourcePolicy, SigningPolicy};
    use xml_sec::xmldsig::{KeyInfo, KeyInfoSource, KeyResolver, PqAlgorithm, SignatureAlgorithm};
    // Import, PKCS#12 identity checking, operation selection and KeyName
    // resolution must recognize PQ SPKI rather than only low-level keys.
    let native = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&[0x42; 32].into());
    let private = native.to_pkcs8_der().unwrap();
    let public = native.verifying_key().to_public_key_der().unwrap();
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_private_der(
            "pq".into(),
            private.as_bytes(),
            None,
            KeyUsages::SIGN,
            &resources,
        )
        .unwrap();
    inventory
        .add_public_der("public".into(), public.as_bytes().to_vec(), &resources)
        .unwrap();
    let method = SignatureAlgorithm::PostQuantum(PqAlgorithm::MlDsa44);
    let policy = SigningPolicy {
        signature_algorithms: Some([method].into()),
        ..Default::default()
    };
    let selected = inventory.signing_key("pq", method, &policy).unwrap();
    let mut info = KeyInfo::default();
    info.sources.push(KeyInfoSource::KeyName("public".into()));
    let resolver = inventory.verification_resolver();
    let resolved = resolver.resolve(Some(&info), method).unwrap().unwrap();
    let signature = xml_sec::provider::default_provider()
        .sign(selected.as_ref(), method, b"inventory")
        .unwrap();
    assert!(
        xml_sec::provider::default_provider()
            .verify(resolved.as_ref(), method, b"inventory", &signature)
            .unwrap()
    );
}

#[cfg(feature = "experimental-pq")]
macro_rules! slh_pipeline_test {
    ($name:ident, $parameter:ty, $algorithm:ident, $width:literal) => {
        #[test]
        fn $name() {
            use pkcs8::EncodePrivateKey;
            // FIPS 205 keygen takes three independently supplied seeds; these
            // reproducible values are test-only and never production entropy.
            let key = slh_dsa::SigningKey::<$parameter>::slh_keygen_internal(
                &[0x41; $width],
                &[0x42; $width],
                &[0x43; $width],
            );
            pq_pipeline(
                xml_sec::xmldsig::PqAlgorithm::$algorithm,
                key.to_pkcs8_der().unwrap().as_bytes(),
            );
        }
    };
}

#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_128f_complete_pipeline,
    slh_dsa::Sha2_128f,
    SlhDsaSha2_128f,
    16
);
#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_128s_complete_pipeline,
    slh_dsa::Sha2_128s,
    SlhDsaSha2_128s,
    16
);
#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_192f_complete_pipeline,
    slh_dsa::Sha2_192f,
    SlhDsaSha2_192f,
    24
);
#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_192s_complete_pipeline,
    slh_dsa::Sha2_192s,
    SlhDsaSha2_192s,
    24
);
#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_256f_complete_pipeline,
    slh_dsa::Sha2_256f,
    SlhDsaSha2_256f,
    32
);
#[cfg(feature = "experimental-pq")]
slh_pipeline_test!(
    slh_sha2_256s_complete_pipeline,
    slh_dsa::Sha2_256s,
    SlhDsaSha2_256s,
    32
);

#[test]
fn pure_eddsa_round_trips_keys_and_complete_xml_pipeline() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{
        DerEncodedKeyValueInfoWriter, DsigStatus, EdDsaSigningKey, SignContext, SignatureAlgorithm,
        SigningKey, VerificationKey, VerifyContext,
    };

    // Import/export, reference hashing, SignedInfo canonicalization and strict
    // signature framing must all agree, not merely the low-level primitives.
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
        .to_pkcs8_der()
        .unwrap();
    let ed448 = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    for (algorithm, der) in [
        (SignatureAlgorithm::Ed25519, ed25519),
        (SignatureAlgorithm::Ed448, ed448),
    ] {
        let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
        let exported = key.to_pkcs8_der().unwrap();
        let restored = EdDsaSigningKey::from_pkcs8_der(algorithm, exported.as_bytes()).unwrap();
        assert_eq!(
            key.public_key_info().unwrap(),
            restored.public_key_info().unwrap()
        );
        let verifier = VerificationKey {
            algorithm,
            public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
            certificate_der: None,
            name: None,
        };
        let signed = SignContext::new(&key)
            .sign_template(&template(algorithm))
            .unwrap();
        assert_eq!(
            VerifyContext::new()
                .key(&verifier)
                .verify(&signed)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
        let modified = signed.replace("authenticated", "altered");
        assert_ne!(
            VerifyContext::new()
                .key(&verifier)
                .verify(&modified)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
        let mut xml = template(algorithm);
        xml = xml.replace("</Signature>", "<KeyInfo/></Signature>");
        let signed = SignContext::new(&key)
            .key_info_writer(&DerEncodedKeyValueInfoWriter)
            .sign_template(&xml)
            .unwrap();
        assert!(signed.contains("DEREncodedKeyValue"));
        let resolver = xml_sec::xmldsig::DefaultKeyResolver::default();
        // An embedded key is not application authorization. The same signed
        // document is accepted only with our explicitly trusted caller key.
        assert!(
            VerifyContext::new()
                .key_resolver(&resolver)
                .verify(&signed)
                .is_err()
        );
        assert_eq!(
            VerifyContext::new()
                .key(&verifier)
                .verify(&signed)
                .unwrap()
                .status,
            DsigStatus::Valid
        );
    }
}

#[test]
fn ed448_certificate_provider_verifies_message_not_external_prehash() {
    use pkcs8::EncodePublicKey;
    use xml_sec::provider::{X509SignatureAlgorithm, default_provider};

    // RFC 8410 certificate signatures use pure Ed448. A valid signature must
    // fail for altered messages, truncated encodings and a different issuer.
    let key = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..]).unwrap();
    let wrong_key = ed448_goldilocks::SigningKey::try_from(&[0x43; 57][..]).unwrap();
    let public = key.verifying_key().to_public_key_der().unwrap();
    let wrong_public = wrong_key.verifying_key().to_public_key_der().unwrap();
    let message = b"certificate signed bytes";
    let signature = key.sign_raw(message).to_bytes();
    let provider = default_provider();
    assert!(
        provider
            .verify_x509_signature(
                X509SignatureAlgorithm::Ed448,
                message,
                &signature,
                public.as_bytes()
            )
            .unwrap()
    );
    assert!(
        !provider
            .verify_x509_signature(
                X509SignatureAlgorithm::Ed448,
                b"modified certificate",
                &signature,
                public.as_bytes()
            )
            .unwrap()
    );
    assert!(
        !provider
            .verify_x509_signature(
                X509SignatureAlgorithm::Ed448,
                message,
                &signature[..113],
                public.as_bytes()
            )
            .unwrap()
    );
    assert!(
        !provider
            .verify_x509_signature(
                X509SignatureAlgorithm::Ed448,
                message,
                &signature,
                wrong_public.as_bytes()
            )
            .unwrap()
    );
}

fn template(algorithm: xml_sec::xmldsig::SignatureAlgorithm) -> String {
    format!(
        r##"<root><payload xml:id="payload">authenticated</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="{}"/><Reference URI="#payload"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha3-256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature></root>"##,
        algorithm.uri(),
    )
}

#[test]
fn ed448_context_survives_the_provider_boundary() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{
        DsigStatus, EdDsaSigningKey, SignContext, SignatureAlgorithm, SigningKey, VerificationKey,
        VerifyContext,
    };
    // Context is cryptographic domain separation, not metadata. A signature
    // must fail after changing only its context and recomputing no references.
    let algorithm = SignatureAlgorithm::Ed448;
    let der = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let key = EdDsaSigningKey::from_pkcs8_der(algorithm, der.as_bytes()).unwrap();
    let xml = template(algorithm).replace("#eddsa-ed448\"/>", "#eddsa-ed448\"><e:EdDSAContextString xmlns:e=\"http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#\">Zm9v</e:EdDSAContextString></SignatureMethod>");
    let signed = SignContext::new(&key).sign_template(&xml).unwrap();
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    assert_eq!(
        VerifyContext::new()
            .key(&verifier)
            .verify(&signed)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
    assert_ne!(
        VerifyContext::new()
            .key(&verifier)
            .verify(&signed.replace("Zm9v", "YmFy"))
            .unwrap()
            .status,
        DsigStatus::Valid
    );
}

#[cfg(feature = "experimental-pq")]
fn donor_pq_key_pipeline(algorithm: xml_sec::xmldsig::PqAlgorithm, family: &str, stem: &str) {
    use xml_sec::provider::X509SignatureAlgorithm;
    use xml_sec::xmldsig::{
        PostQuantumSigningKey, SignatureAlgorithm, SignatureContext, SigningKey,
    };

    // Donor certificates contain PQ subject keys but RSA issuer signatures.
    // Check that imported keys match their certificate, then exercise the
    // separate PKIX provider contract with pure signatures and empty context.
    let der = std::fs::read(format!(
        "tests/fixtures/xmldsig/keys/{family}/{stem}-cert.der"
    ))
    .unwrap();
    let (remaining, certificate) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert!(remaining.is_empty());
    let private = std::fs::read(format!(
        "tests/fixtures/xmldsig/keys/{family}/{stem}-key.der"
    ))
    .unwrap();
    pq_pipeline(algorithm, &private);
    assert_eq!(
        certificate.public_key().algorithm.algorithm.to_id_string(),
        algorithm.oid()
    );
    let key = PostQuantumSigningKey::from_pkcs8_der(algorithm, &private).unwrap();
    donor_key_containers(SignatureAlgorithm::PostQuantum(algorithm), family, stem);
    assert_eq!(
        key.public_key_info().unwrap().spki_der().unwrap(),
        certificate.public_key().raw
    );
    let provider = xml_sec::provider::default_provider();
    let data = certificate.tbs_certificate.as_ref();
    let signature = provider
        .sign_with_context(
            &key,
            SignatureAlgorithm::PostQuantum(algorithm),
            &SignatureContext::default(),
            data,
        )
        .unwrap();
    assert!(
        provider
            .verify_x509_signature(
                X509SignatureAlgorithm::PostQuantum(algorithm),
                data,
                &signature,
                certificate.public_key().raw,
            )
            .unwrap(),
        "{stem}"
    );
    let mut altered = data.to_vec();
    altered[0] ^= 1;
    assert!(
        !provider
            .verify_x509_signature(
                X509SignatureAlgorithm::PostQuantum(algorithm),
                &altered,
                &signature,
                certificate.public_key().raw,
            )
            .unwrap(),
        "{stem}"
    );
    assert!(
        !provider
            .verify_x509_signature(
                X509SignatureAlgorithm::PostQuantum(algorithm),
                data,
                &signature[..signature.len() - 1],
                certificate.public_key().raw,
            )
            .unwrap(),
        "{stem}"
    );
}

fn donor_key_containers(algorithm: xml_sec::xmldsig::SignatureAlgorithm, family: &str, stem: &str) {
    use xml_sec::key_manager::{KeyInventory, KeyUsages};
    use xml_sec::policy::{ResourcePolicy, SigningPolicy};
    // The complete donor key-directory formats must retain identical public
    // identity. Failed authentication must never leave a usable partial key.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/xmldsig/keys/{family}"));
    let certificate = std::fs::read(root.join(format!("{stem}-cert.der"))).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(&certificate).unwrap();
    let resources = ResourcePolicy::default();
    let policy = SigningPolicy {
        signature_algorithms: Some([algorithm].into()),
        ..Default::default()
    };
    for suffix in [".der", ".pem", ".p8-der", ".p8-pem", ".p12", "-win.p12"] {
        let bytes = std::fs::read(root.join(format!("{stem}-key{suffix}"))).unwrap();
        let protected = suffix != ".der" && suffix != ".pem";
        for correct_password in [true, false] {
            if !protected && !correct_password {
                continue;
            }
            let mut inventory = KeyInventory::default();
            let password = if correct_password {
                "secret123"
            } else {
                "wrong-password"
            };
            let result = if suffix.ends_with(".p12") {
                inventory.add_pkcs12_with_usages(
                    "key".into(),
                    &bytes,
                    password,
                    KeyUsages::SIGN,
                    &resources,
                )
            } else if suffix.ends_with("pem") {
                inventory.add_private_pem(
                    "key".into(),
                    &bytes,
                    protected.then_some(password.as_bytes()),
                    KeyUsages::SIGN,
                    &resources,
                )
            } else {
                inventory.add_private_der(
                    "key".into(),
                    &bytes,
                    protected.then_some(password.as_bytes()),
                    KeyUsages::SIGN,
                    &resources,
                )
            };
            if !correct_password {
                assert!(result.is_err(), "{stem}{suffix}: wrong password accepted");
                assert!(
                    inventory.private_keys().is_empty(),
                    "{stem}{suffix}: partial import"
                );
                assert!(
                    inventory.public_keys().is_empty(),
                    "{stem}{suffix}: partial public import"
                );
                continue;
            }
            result.unwrap_or_else(|error| panic!("{stem}{suffix}: {error}"));
            let key = inventory.signing_key("key", algorithm, &policy).unwrap();
            assert_eq!(
                key.public_key_info().unwrap().spki_der().unwrap(),
                certificate.public_key().raw,
                "{stem}{suffix}"
            );
        }
    }
}

#[test]
fn eddsa_donor_containers_keep_identity_and_reject_bad_passwords() {
    // Both EdDSA key sizes must survive every protected donor container.
    donor_key_containers(
        xml_sec::xmldsig::SignatureAlgorithm::Ed25519,
        "eddsa",
        "eddsa-ed25519",
    );
    donor_key_containers(
        xml_sec::xmldsig::SignatureAlgorithm::Ed448,
        "eddsa",
        "eddsa-ed448",
    );
}

#[cfg(feature = "experimental-pq")]
macro_rules! donor_pq_test {
    ($name:ident, $algorithm:ident, $family:literal, $stem:literal) => {
        #[test]
        fn $name() {
            // Isolate each slow parameter set so timeouts identify the exact primitive.
            donor_pq_key_pipeline(xml_sec::xmldsig::PqAlgorithm::$algorithm, $family, $stem);
        }
    };
}

#[cfg(feature = "experimental-pq")]
mod donor_pq {
    use super::donor_pq_key_pipeline;
    donor_pq_test!(ml44, MlDsa44, "ml-dsa", "ml-dsa-44");
    donor_pq_test!(ml65, MlDsa65, "ml-dsa", "ml-dsa-65");
    donor_pq_test!(ml87, MlDsa87, "ml-dsa", "ml-dsa-87");
    donor_pq_test!(slh128f, SlhDsaSha2_128f, "slh-dsa", "slh-dsa-sha2-128f");
    donor_pq_test!(slh128s, SlhDsaSha2_128s, "slh-dsa", "slh-dsa-sha2-128s");
    donor_pq_test!(slh192f, SlhDsaSha2_192f, "slh-dsa", "slh-dsa-sha2-192f");
    donor_pq_test!(slh192s, SlhDsaSha2_192s, "slh-dsa", "slh-dsa-sha2-192s");
    donor_pq_test!(slh256f, SlhDsaSha2_256f, "slh-dsa", "slh-dsa-sha2-256f");
    donor_pq_test!(slh256s, SlhDsaSha2_256s, "slh-dsa", "slh-dsa-sha2-256s");
}

#[test]
fn every_ecdsa_curve_and_modern_digest_runs_the_full_pipeline() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{
        DsigStatus, EcdsaP256SigningKey, EcdsaP384SigningKey, EcdsaP521SigningKey, SignContext,
        SignatureAlgorithm, SigningKey, VerificationKey, VerifyContext,
    };

    // All curve/hash combinations are legal; short hashes on P-521 must not
    // be rejected by a primitive's prehash representation requirements.
    let p256 = p256::SecretKey::from_slice(&[1; 32])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let p384 = p384::SecretKey::from_slice(&[1; 48])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let p521 = p521::SecretKey::from_slice(&[1; 66])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let keys: [Box<dyn SigningKey>; 3] = [
        Box::new(EcdsaP256SigningKey::from_pkcs8_der(p256.as_bytes()).unwrap()),
        Box::new(EcdsaP384SigningKey::from_pkcs8_der(p384.as_bytes()).unwrap()),
        Box::new(EcdsaP521SigningKey::from_pkcs8_der(p521.as_bytes()).unwrap()),
    ];
    let wrong_p256 = p256::SecretKey::from_slice(&[2; 32])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let wrong_p384 = p384::SecretKey::from_slice(&[2; 48])
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let mut scalar521 = [2; 66];
    scalar521[0] = 1;
    let wrong_p521 = p521::SecretKey::from_slice(&scalar521)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let wrong_keys: [Box<dyn SigningKey>; 3] = [
        Box::new(EcdsaP256SigningKey::from_pkcs8_der(wrong_p256.as_bytes()).unwrap()),
        Box::new(EcdsaP384SigningKey::from_pkcs8_der(wrong_p384.as_bytes()).unwrap()),
        Box::new(EcdsaP521SigningKey::from_pkcs8_der(wrong_p521.as_bytes()).unwrap()),
    ];
    for (curve, key) in keys.iter().enumerate() {
        for algorithm in [
            SignatureAlgorithm::EcdsaSha1,
            SignatureAlgorithm::EcdsaSha224,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
            SignatureAlgorithm::EcdsaSha3_224,
            SignatureAlgorithm::EcdsaSha3_256,
            SignatureAlgorithm::EcdsaSha3_384,
            SignatureAlgorithm::EcdsaSha3_512,
        ] {
            let policy = xml_sec::policy::SigningPolicy {
                signature_algorithms: Some([algorithm].into()),
                ..Default::default()
            };
            // Legacy capability needs explicit policy permission; the matrix
            // includes SHA-1 without weakening the default secure profile.
            if algorithm == SignatureAlgorithm::EcdsaSha1 {
                assert!(
                    SignContext::new(key.as_ref())
                        .sign_template(&template(algorithm))
                        .is_err()
                );
            }
            let signed = SignContext::new(key.as_ref())
                .policy(policy)
                .sign_template(&template(algorithm))
                .unwrap_or_else(|error| panic!("curve {curve}/{algorithm:?}: {error}"));
            let verifier = VerificationKey {
                algorithm,
                public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
                certificate_der: None,
                name: None,
            };
            let mut policy = xml_sec::policy::VerificationPolicy {
                signature_algorithms: Some([algorithm].into()),
                ..Default::default()
            };
            if algorithm == SignatureAlgorithm::EcdsaSha1 {
                policy
                    .key_trust
                    .allowed_legacy_signature_algorithms
                    .insert(algorithm);
            }
            let result = VerifyContext::new()
                .policy(policy.clone())
                .key(&verifier)
                .verify(&signed)
                .unwrap();
            assert_eq!(
                result.status,
                DsigStatus::Valid,
                "curve {curve}/{algorithm:?}"
            );
            let tampered = signed.replace("authenticated", "changed");
            let result = VerifyContext::new()
                .policy(policy.clone())
                .key(&verifier)
                .verify(&tampered)
                .unwrap();
            assert_ne!(
                result.status,
                DsigStatus::Valid,
                "curve {curve}/{algorithm:?}"
            );
            let wrong_key = VerificationKey {
                public_key_bytes: wrong_keys[curve]
                    .public_key_info()
                    .unwrap()
                    .spki_der()
                    .unwrap()
                    .to_vec(),
                ..verifier
            };
            let result = VerifyContext::new()
                .policy(policy)
                .key(&wrong_key)
                .verify(&signed)
                .unwrap();
            assert_ne!(
                result.status,
                DsigStatus::Valid,
                "curve {curve}/{algorithm:?}"
            );
        }
    }
}

#[test]
fn sha3_capability_never_overrides_the_operation_policy() {
    use std::collections::HashSet;
    use xml_sec::policy::{SigningPolicy, VerificationPolicy};
    use xml_sec::xmldsig::{
        EcdsaP256SigningKey, SignContext, SignatureAlgorithm, SigningKey, VerificationKey,
        VerifyContext,
    };

    // A compiled algorithm is a capability, not permission: both signing and
    // verification must gate the newly implemented methods and reference hash.
    let key =
        EcdsaP256SigningKey::from_pkcs8_pem(include_str!("fixtures/keys/ec/ec-prime256v1-key.pem"))
            .unwrap();
    let algorithm = SignatureAlgorithm::EcdsaSha3_256;
    let xml = template(algorithm);
    for policy in [
        SigningPolicy {
            signature_algorithms: Some(HashSet::from([SignatureAlgorithm::EcdsaSha256])),
            ..Default::default()
        },
        SigningPolicy {
            digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha256])),
            ..Default::default()
        },
    ] {
        assert!(
            SignContext::new(&key)
                .policy(policy)
                .sign_template(&xml)
                .is_err()
        );
    }
    let signed = SignContext::new(&key).sign_template(&xml).unwrap();
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    for policy in [
        VerificationPolicy {
            signature_algorithms: Some(HashSet::from([SignatureAlgorithm::EcdsaSha256])),
            ..Default::default()
        },
        VerificationPolicy {
            digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha256])),
            ..Default::default()
        },
    ] {
        assert!(
            VerifyContext::new()
                .key(&verifier)
                .policy(policy)
                .verify(&signed)
                .is_err()
        );
    }
}

#[test]
fn sha3_ecdsa_signatures_interoperate_bidirectionally() {
    use xml_sec::xmldsig::{EcdsaP256SigningKey, SignatureAlgorithm};

    // An independent oracle detects errors shared by our signer and verifier.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keys/ec/ec-prime256v1-key.pem");
    let key =
        EcdsaP256SigningKey::from_pkcs8_pem(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
    for algorithm in [
        SignatureAlgorithm::EcdsaSha3_224,
        SignatureAlgorithm::EcdsaSha3_256,
        SignatureAlgorithm::EcdsaSha3_384,
        SignatureAlgorithm::EcdsaSha3_512,
    ] {
        assert_bidirectional_xmlsec1(&key, &key_path, algorithm, template(algorithm));
    }
}

fn assert_bidirectional_xmlsec1(
    key: &dyn xml_sec::xmldsig::SigningKey,
    key_path: &std::path::Path,
    algorithm: xml_sec::xmldsig::SignatureAlgorithm,
    xml: String,
) {
    use xml_sec::xmldsig::{DsigStatus, SignContext, VerificationKey, VerifyContext};
    let directory = tempfile::tempdir().unwrap();
    let template_path = directory.path().join("template.xml");
    let signed_path = directory.path().join("signed.xml");
    let oracle_path = directory.path().join("oracle.xml");
    let signed = SignContext::new(key).sign_template(&xml).unwrap();
    std::fs::write(&signed_path, signed).unwrap();
    let verified = xmlsec1::command()
        .args(["verify", "--lax-key-search", "--privkey-pem"])
        .arg(key_path)
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{algorithm:?}: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    std::fs::write(&template_path, xml).unwrap();
    let generated = xmlsec1::command()
        .args(["sign", "--lax-key-search", "--privkey-pem"])
        .arg(key_path)
        .arg("--output")
        .arg(&oracle_path)
        .arg(&template_path)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{algorithm:?}: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let verifier = VerificationKey {
        algorithm,
        public_key_bytes: key.public_key_info().unwrap().spki_der().unwrap().to_vec(),
        certificate_der: None,
        name: None,
    };
    let signed = std::fs::read_to_string(&oracle_path).unwrap();
    assert_eq!(
        VerifyContext::new()
            .key(&verifier)
            .verify(&signed)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
}

#[test]
fn all_eddsa_methods_interoperate_with_xmlsec1() {
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        EdDsaSigningKey, ReferenceBuilder, SignatureAlgorithm as A, SignatureBuilder,
        SignatureContext, Transform,
    };

    // Independent OpenSSL/xmlsec1 verification tests all five domain-separation
    // variants, including nonempty contexts where the method permits them.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    for (algorithm, stem) in [
        (A::Ed25519, "eddsa-ed25519"),
        (A::Ed25519Ctx, "eddsa-ed25519"),
        (A::Ed25519Ph, "eddsa-ed25519"),
        (A::Ed448, "eddsa-ed448"),
        (A::Ed448Ph, "eddsa-ed448"),
    ] {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/xmldsig/keys/eddsa/{stem}-key.pem"));
        let der = std::fs::read(key_path.with_extension("der")).unwrap();
        let key = EdDsaSigningKey::from_pkcs8_der(algorithm, &der).unwrap();
        // The pinned donor registers a context reader for Ed448ph, but not
        // pure Ed448. Nonempty pure-Ed448 contexts are checked against RFC
        // 8032 §7.4 below, rather than claiming donor support that does not exist.
        let context = if matches!(algorithm, A::Ed25519 | A::Ed448) {
            SignatureContext::default()
        } else {
            SignatureContext::new(b"foo").unwrap()
        };
        let builder =
            SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
                .signature_context(context)
                .add_reference(
                    ReferenceBuilder::new(DigestAlgorithm::Sha256)
                        .uri("")
                        .transform(Transform::Enveloped),
                );
        assert_bidirectional_xmlsec1(
            &key,
            &key_path,
            algorithm,
            format!(
                "<root>authenticated{}</root>",
                builder.build_template().unwrap()
            ),
        );
    }
}

#[test]
fn ed448_nonempty_context_matches_rfc8032_known_answer() {
    use pkcs8::EncodePrivateKey;
    use xml_sec::xmldsig::{EdDsaSigningKey, SignatureAlgorithm, SignatureContext};
    // RFC 8032 §7.4 "1 octet (with context)" proves pure Ed448's context
    // is part of dom4, even though the donor's XML parameter reader omits it.
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.4
    let seed = decode_hex(concat!(
        "c4eab05d357007c632f3dbb48489924d",
        "552b08fe0c353a0d4a1f00acda2c463a",
        "fbea67c5e8d2877c5e3bc397a659949e",
        "f8021e954e0a12274e",
    ));
    let der = ed448_goldilocks::SigningKey::try_from(seed.as_slice())
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let key = EdDsaSigningKey::from_pkcs8_der(SignatureAlgorithm::Ed448, der.as_bytes()).unwrap();
    let signature = xml_sec::provider::default_provider()
        .sign_with_context(
            &key,
            SignatureAlgorithm::Ed448,
            &SignatureContext::new(b"foo").unwrap(),
            &[3],
        )
        .unwrap();
    assert_eq!(
        signature,
        decode_hex(concat!(
            "d4f8f6131770dd46f40867d6fd5d5055",
            "de43541f8c5e35abbcd001b32a89f7d2",
            "151f7647f11d8ca2ae279fb842d60721",
            "7fce6e042f6815ea000c85741de5c8da",
            "1144a6a1aba7f96de42505d7a7298524",
            "fda538fccbbb754f578c1cad10d54d0d",
            "5428407e85dcbc98a49155c13764e66c",
            "3c00",
        ))
    );
}

#[test]
fn ecdsa_sha3_methods_round_trip_standard_identifiers() {
    // RFC 9231 section 2.3.6 uses the 2021 namespace for ECDSA-SHA3,
    // unlike SHA-3 DigestMethod identifiers in the 2007 namespace.
    for bits in [224, 256, 384, 512] {
        let uri = format!("http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-{bits}");
        let algorithm =
            xml_sec::xmldsig::SignatureAlgorithm::from_uri(&uri).expect("standard ECDSA-SHA3 URI");
        assert_eq!(algorithm.uri(), uri);
    }
}

#[test]
fn sha3_digest_uris_have_fips202_known_answers() {
    // RFC 9231 section 2.1.5 names SHA-3, not legacy Keccak. Empty-message
    // known answers detect the wrong domain separator as well as width errors.
    for (bits, expected) in [
        (
            224,
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        ),
        (
            256,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            384,
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        ),
        (
            512,
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        ),
    ] {
        let uri = format!("http://www.w3.org/2007/05/xmldsig-more#sha3-{bits}");
        let algorithm = DigestAlgorithm::from_uri(&uri).expect("standard SHA-3 URI");
        assert_eq!(algorithm.uri(), uri);
        assert_eq!(algorithm.output_len(), bits / 8);
        let actual = compute_digest(algorithm, b"");
        let hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected);
    }
}

#[test]
fn sha3_digest_uri_namespaces_are_not_guessed() {
    // A misspelled URI must not select crypto by suffix alone.
    assert_eq!(
        DigestAlgorithm::from_uri("http://www.w3.org/2021/04/xmldsig-more#sha3-256"),
        None,
    );
}
