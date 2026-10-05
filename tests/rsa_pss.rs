#![cfg(feature = "xmldsig")]

//! RSA-PSS public pipeline, parameter grammar and independent primitive coverage.

use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};
use rsa::{pkcs8::DecodePrivateKey as _, traits::PublicKeyParts as _};
use sha2::Digest as _;
use xml_sec::{
    XmlDomDocument,
    c14n::{C14nAlgorithm, C14nMode},
    provider::{CryptoProvider, RustCryptoProvider},
    xmldsig::{
        DigestAlgorithm, DsigStatus, KeyValueInfoWriter, ReferenceBuilder, RsaPssParameters,
        RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder, SigningKey,
        find_signature_node, signature::verify_rsa_signature_pem,
    },
};

#[path = "support/cryptographic.rs"]
mod cryptographic;

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

const PRIVATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const PUBLIC: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const PSS: &str = "http://www.w3.org/2007/05/xmldsig-more#";

fn parse_method(children: &str) -> Result<SignatureAlgorithm, xml_sec::xmldsig::ParseError> {
    let xml = format!(
        r#"<Signature xmlns="{DS}"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="{PSS}rsa-pss">{children}</SignatureMethod><Reference URI=""><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"#
    );
    let doc = XmlDomDocument::parse(&xml).expect("well-formed parameter test XML");
    let signed_info = find_signature_node(&doc)
        .expect("Signature")
        .first_element_child()
        .expect("SignedInfo");
    xml_sec::xmldsig::parse::parse_signature_method(
        signed_info
            .children()
            .find(|child| child.has_tag_name((DS, "SignatureMethod")))
            .unwrap(),
        &xml_sec::policy::ResourcePolicy::default(),
    )
    .map(|(method, _, _)| method)
}

#[test]
fn pss_xs_int_accepts_negative_zero() {
    // xs:int permits -0; the nonnegative salt value is zero, not a negative length.
    let method = parse_method(&format!(
        r#"<RSAPSSParams xmlns="{PSS}"><SaltLength> -0 </SaltLength></RSAPSSParams>"#
    ))
    .expect("negative zero is zero");
    assert_eq!(
        method,
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            salt_len: 0,
            ..RsaPssParameters::DEFAULT
        })
    );
}

#[test]
fn pss_defaults_and_order_are_strict() {
    // XML defaults are SHA-256, matching MGF1, digest-sized salt and trailer 1.
    assert_eq!(
        parse_method("").unwrap(),
        SignatureAlgorithm::RsaPss(RsaPssParameters::DEFAULT)
    );
    let digest = format!(
        r#"<DigestMethod xmlns="{DS}" Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>"#
    );
    assert_eq!(
        parse_method(&format!(
            r#"<RSAPSSParams xmlns="{PSS}">{digest}</RSAPSSParams>"#
        ))
        .unwrap(),
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            digest: DigestAlgorithm::Sha512,
            mgf_digest: DigestAlgorithm::Sha512,
            salt_len: 64
        })
    );
    assert_eq!(
        parse_method(&format!(
            r#"<RSAPSSParams xmlns="{PSS}">{digest}<MaskGenerationFunction/></RSAPSSParams>"#
        ))
        .unwrap(),
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            digest: DigestAlgorithm::Sha512,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len: 64
        })
    );
    for children in [
        "<SaltLength>-1</SaltLength>",
        "<SaltLength>2147483648</SaltLength>",
        "<SaltLength>1 2</SaltLength>",
        "<SaltLength>+</SaltLength>",
        "<TrailerField>2</TrailerField>",
        "<SaltLength>0</SaltLength><SaltLength>0</SaltLength>",
        "<TrailerField>1</TrailerField><SaltLength>0</SaltLength>",
        "<Unknown/>",
        "<MaskGenerationFunction Algorithm=\"urn:unknown\"/>",
    ] {
        assert!(
            parse_method(&format!(
                r#"<RSAPSSParams xmlns="{PSS}">{children}</RSAPSSParams>"#
            ))
            .is_err(),
            "{children}"
        );
    }
}

#[test]
fn pss_legacy_hash_permission_covers_message_and_mgf() {
    // Capability is not permission: SHA-1 must be explicitly allowed even if
    // it occurs only inside MGF1, and permission names the exact PSS tuple.
    for parameters in [
        RsaPssParameters {
            digest: DigestAlgorithm::Sha1,
            ..RsaPssParameters::DEFAULT
        },
        RsaPssParameters {
            mgf_digest: DigestAlgorithm::Sha1,
            ..RsaPssParameters::DEFAULT
        },
    ] {
        let method = SignatureAlgorithm::RsaPss(parameters);
        let mut policy = xml_sec::policy::VerificationPolicy::default();
        assert!(policy.check_signature_algorithm(method).is_err());
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(SignatureAlgorithm::RsaPssSha1);
        assert!(policy.check_signature_algorithm(method).is_err());
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(method);
        assert!(policy.check_signature_algorithm(method).is_ok());
    }
}

#[test]
fn pss_signatures_cross_verify_with_dependency() {
    // Independent sad-rsa padding checks our PSS implementation in both directions.
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    for salt_len in [0, 1, 32, 222] {
        let method = SignatureAlgorithm::RsaPss(RsaPssParameters {
            salt_len,
            ..RsaPssParameters::DEFAULT
        });
        let signature = RustCryptoProvider
            .sign(&key, method, b"PSS message")
            .unwrap();
        public
            .verify(
                rsa::Pss::<sha2::Sha256>::new_with_salt(salt_len),
                &sha2::Sha256::digest(b"PSS message"),
                &signature,
            )
            .unwrap();
        let signature = private
            .sign_with_rng(
                &mut ChaCha8Rng::seed_from_u64(17),
                rsa::Pss::<sha2::Sha256>::new_with_salt(salt_len),
                &sha2::Sha256::digest(b"PSS message"),
            )
            .unwrap();
        assert!(verify_rsa_signature_pem(method, PUBLIC, b"PSS message", &signature).unwrap());
        assert!(!verify_rsa_signature_pem(method, PUBLIC, b"tampered", &signature).unwrap());
        let wrong_salt = SignatureAlgorithm::RsaPss(RsaPssParameters {
            salt_len: if salt_len == 0 { 1 } else { 0 },
            ..RsaPssParameters::DEFAULT
        });
        assert!(!verify_rsa_signature_pem(wrong_salt, PUBLIC, b"PSS message", &signature).unwrap());
    }
    assert_eq!(public.size(), 256);
}

#[test]
fn pss_rejects_malformed_encoded_messages_and_modulus_boundary() {
    // RFC 8017 section 9.1.2 requires trailer, high bits, zero padding,
    // separator and hash to agree; raw RSA gives independent malformed EMs.
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(PRIVATE).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    let algorithm = SignatureAlgorithm::RsaPssSha256;
    let signature = key.sign(algorithm, b"padding").unwrap();
    let value =
        crypto_bigint::BoxedUint::from_be_slice(&signature, public.n_bits_precision()).unwrap();
    let encoded = rsa::hazmat::rsa_encrypt(&public, &value)
        .unwrap()
        .to_be_bytes();
    for index in [0, 1, 200, 223, 255] {
        let mut invalid = encoded.to_vec();
        if index == 0 {
            invalid[index] = 0x80;
        } else {
            invalid[index] ^= 1;
        }
        let value =
            crypto_bigint::BoxedUint::from_be_slice(&invalid, private.n_bits_precision()).unwrap();
        let signature = rsa::hazmat::rsa_decrypt_and_check(
            &private,
            Some(&mut ChaCha8Rng::seed_from_u64(3)),
            &value,
        )
        .unwrap()
        .to_be_bytes();
        assert!(
            !verify_rsa_signature_pem(algorithm, PUBLIC, b"padding", &signature).unwrap(),
            "offset {index}"
        );
    }
    assert!(!verify_rsa_signature_pem(algorithm, PUBLIC, b"padding", &signature[..255]).unwrap());
    assert!(
        !verify_rsa_signature_pem(algorithm, PUBLIC, b"padding", &public.n().to_be_bytes())
            .unwrap()
    );
    let oversized = SignatureAlgorithm::RsaPss(RsaPssParameters {
        salt_len: 223,
        ..RsaPssParameters::DEFAULT
    });
    assert!(key.sign(oversized, b"padding").is_err());
}

#[test]
fn pss_non_byte_aligned_modulus_preserves_representative_width() {
    // For modBits == 1 mod 8, emLen is one octet smaller than the signature:
    // RFC 8017 section 8.1.2 must reject a nonzero discarded leading octet.
    use rsa::pkcs8::EncodePublicKey as _;
    let private = rsa::RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(2049), 2049).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let method = SignatureAlgorithm::RsaPssSha256;
    let signature = private
        .sign_with_rng(
            &mut ChaCha8Rng::seed_from_u64(6),
            rsa::Pss::<sha2::Sha256>::new(),
            &sha2::Sha256::digest(b"odd modulus"),
        )
        .unwrap();
    let spki = public.to_public_key_der().unwrap();
    assert_eq!(signature.len(), 257);
    assert!(
        xml_sec::xmldsig::signature::verify_rsa_signature_spki(
            method,
            spki.as_bytes(),
            b"odd modulus",
            &signature
        )
        .unwrap()
    );
    let invalid = private.n().as_ref()
        - &crypto_bigint::BoxedUint::one_with_precision(private.n_bits_precision());
    let signature = rsa::hazmat::rsa_decrypt_and_check(
        &private,
        Some(&mut ChaCha8Rng::seed_from_u64(5)),
        &invalid,
    )
    .unwrap()
    .to_be_bytes();
    assert!(
        !xml_sec::xmldsig::signature::verify_rsa_signature_spki(
            method,
            spki.as_bytes(),
            b"odd modulus",
            &signature
        )
        .unwrap()
    );
}

#[test]
fn pss_public_sign_and_verify_all_secure_methods() {
    // All fixed secure URI variants and parameterized independent MGF run through
    // builder -> signing provider -> KeyInfo resolution -> verification provider.
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    for method in [
        SignatureAlgorithm::RsaPssSha224,
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::RsaPssSha384,
        SignatureAlgorithm::RsaPssSha512,
        SignatureAlgorithm::RsaPssSha3_224,
        SignatureAlgorithm::RsaPssSha3_256,
        SignatureAlgorithm::RsaPssSha3_384,
        SignatureAlgorithm::RsaPssSha3_512,
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            digest: DigestAlgorithm::Sha512,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len: 0,
        }),
    ] {
        let builder = SignatureBuilder::new(c14n.clone(), method)
            .key_info(true)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"));
        let signed = SignContext::new(&key)
            .key_info_writer(&KeyValueInfoWriter)
            .sign_with_builder(
                "<root><payload Id=\"payload\">value</payload></root>",
                &builder,
            )
            .unwrap();
        let resolver = xml_sec::xmldsig::DefaultKeyResolver::default();
        let result = cryptographic::context()
            .key_resolver(&resolver)
            .verify(&signed)
            .unwrap();
        assert_eq!(result.status, DsigStatus::Valid, "{method:?}");
    }
}

#[test]
fn pss_invalid_api_salt_is_not_a_provider_capability() {
    // A caller-created parameter value cannot bypass XML's bounded integer contract.
    let method = SignatureAlgorithm::RsaPss(RsaPssParameters {
        salt_len: usize::MAX,
        ..RsaPssParameters::DEFAULT
    });
    assert!(!RustCryptoProvider.supports(xml_sec::provider::ProviderCapability::Sign(method)));
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    assert!(key.sign(method, b"payload").is_err());
}

#[test]
fn pss_key_capacity_is_checked_before_signing_dispatch() {
    // An oversized, but XML-representable salt must not invoke an opaque signer.
    struct NeverSign(RsaSigningKey);
    impl SigningKey for NeverSign {
        fn sign(
            &self,
            _: SignatureAlgorithm,
            _: &[u8],
        ) -> Result<Vec<u8>, xml_sec::xmldsig::SigningKeyError> {
            panic!("PSS capacity preflight must precede signing dispatch");
        }
        fn public_key_info(
            &self,
        ) -> Result<xml_sec::xmldsig::SigningPublicKeyInfo, xml_sec::xmldsig::SigningKeyError>
        {
            self.0.public_key_info()
        }
    }
    let key = NeverSign(RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap());
    let algorithm = SignatureAlgorithm::RsaPss(RsaPssParameters {
        salt_len: 223,
        ..RsaPssParameters::DEFAULT
    });
    let builder =
        SignatureBuilder::new(C14nAlgorithm::new(C14nMode::Exclusive1_0, false), algorithm)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(""));
    assert!(
        SignContext::new(&key)
            .sign_with_builder("<root/>", &builder)
            .is_err()
    );
}

#[test]
fn pss_restricted_spki_enforces_hashes_and_minimum_salt() {
    // RFC 4055 section 3.3 permits a larger salt, but never another message
    // hash/MGF hash or PKCS#1 v1.5 with a PSS-only public key.
    use der::{Decode as _, Encode as _};
    use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier};
    let plain = pem::parse(PUBLIC).unwrap();
    let mut spki = x509_cert::SubjectPublicKeyInfo::from_der(plain.contents()).unwrap();
    let params = der::asn1::Any::from_der(&[
        0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
    ])
    .unwrap();
    spki.algorithm = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
        parameters: Some(params),
    };
    let encoded = spki.to_der().unwrap();
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    for salt_len in [32, 33] {
        let method = SignatureAlgorithm::RsaPss(RsaPssParameters {
            salt_len,
            ..RsaPssParameters::DEFAULT
        });
        let signature = key.sign(method, b"restricted").unwrap();
        let public = xml_sec::xmldsig::VerificationKey {
            algorithm: method,
            public_key_bytes: encoded.clone(),
            certificate_der: None,
            name: None,
        };
        assert!(
            RustCryptoProvider
                .verify(&public, method, b"restricted", &signature)
                .unwrap()
        );
        #[cfg(feature = "aws-lc-fips")]
        if salt_len == 32 {
            assert!(
                xml_sec::provider::AwsLcFipsProvider
                    .verify(&public, method, b"restricted", &signature)
                    .unwrap()
            );
        }
    }
    for method in [
        SignatureAlgorithm::RsaSha256,
        SignatureAlgorithm::RsaPssSha384,
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            salt_len: 31,
            ..RsaPssParameters::DEFAULT
        }),
        SignatureAlgorithm::RsaPss(RsaPssParameters {
            mgf_digest: DigestAlgorithm::Sha384,
            ..RsaPssParameters::DEFAULT
        }),
    ] {
        let signature = key.sign(method, b"restricted").unwrap();
        let public = xml_sec::xmldsig::VerificationKey {
            algorithm: method,
            public_key_bytes: encoded.clone(),
            certificate_der: None,
            name: None,
        };
        assert!(
            RustCryptoProvider
                .verify(&public, method, b"restricted", &signature)
                .is_err()
        );
    }
}

#[test]
fn pss_spki_rejects_unrecognized_parameter_fields() {
    // RFC 8017 appendix A.2.3 permits only the ordered [0]..[3] fields.
    // Unknown fields must not be discarded and interpreted as SHA-1 defaults.
    use der::{Decode as _, Encode as _};
    use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier};
    let public = pem::parse(PUBLIC).unwrap();
    let mut spki = x509_cert::SubjectPublicKeyInfo::from_der(public.contents()).unwrap();
    spki.algorithm = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
        parameters: Some(
            der::asn1::Any::from_der(&[0x30, 0x05, 0xa4, 0x03, 0x02, 0x01, 0x00]).unwrap(),
        ),
    };
    let algorithm = SignatureAlgorithm::RsaPssSha1;
    let signature = RsaSigningKey::from_pkcs8_pem(PRIVATE)
        .unwrap()
        .sign(algorithm, b"bad parameters")
        .unwrap();
    let key = xml_sec::xmldsig::VerificationKey {
        algorithm,
        public_key_bytes: spki.to_der().unwrap(),
        certificate_der: None,
        name: None,
    };
    assert!(
        RustCryptoProvider
            .verify(&key, algorithm, b"bad parameters", &signature)
            .is_err()
    );
}

#[test]
fn pss_independent_mgf_cross_verifies_with_openssl() {
    // RFC 8017 permits different message/MGF hashes; OpenSSL is the independent
    // oracle for both directions, including empty and non-digest-sized salts.
    let directory = tempfile::tempdir().unwrap();
    let message = directory.path().join("message");
    let private = directory.path().join("private.pem");
    let public = directory.path().join("public.pem");
    let signature_path = directory.path().join("signature");
    std::fs::write(&message, b"independent MGF").unwrap();
    std::fs::write(&private, PRIVATE).unwrap();
    std::fs::write(&public, PUBLIC).unwrap();
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    for salt_len in [0, 17, 64] {
        let method = SignatureAlgorithm::RsaPss(RsaPssParameters {
            digest: DigestAlgorithm::Sha512,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len,
        });
        std::fs::write(
            &signature_path,
            key.sign(method, b"independent MGF").unwrap(),
        )
        .unwrap();
        for sign in [false, true] {
            let mut command = std::process::Command::new("openssl");
            command.args(["dgst", "-sha512"]);
            if sign {
                command
                    .arg("-sign")
                    .arg(&private)
                    .arg("-out")
                    .arg(&signature_path);
            } else {
                command
                    .arg("-verify")
                    .arg(&public)
                    .arg("-signature")
                    .arg(&signature_path);
            }
            let output = command
                .args([
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-sigopt",
                    "rsa_mgf1_md:sha256",
                    "-sigopt",
                ])
                .arg(format!("rsa_pss_saltlen:{salt_len}"))
                .arg(&message)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let signature = std::fs::read(&signature_path).unwrap();
        assert!(verify_rsa_signature_pem(method, PUBLIC, b"independent MGF", &signature).unwrap());
        assert!(
            !verify_rsa_signature_pem(
                SignatureAlgorithm::RsaPssSha512,
                PUBLIC,
                b"independent MGF",
                &signature
            )
            .unwrap()
        );
    }
}

#[test]
fn pss_donor_family_verifies_and_signs_every_template() {
    // Execute every fixed-URI PSS signed document and template from upstream,
    // using an independently pinned key rather than trusting document certificates.
    let key =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-4096-key.pem")).unwrap();
    let spki = pem::parse(include_bytes!("fixtures/keys/rsa/rsa-4096-pubkey.pem")).unwrap();
    let signing = xml_sec::policy::SigningPolicy {
        signature_algorithms: Some(SignatureAlgorithm::ALL.into_iter().collect()),
        digest_algorithms: Some(DigestAlgorithm::ALL.into_iter().collect()),
        ..xml_sec::policy::SigningPolicy::default()
    };
    let mut count = 0;
    for hash in [
        "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384",
        "sha3_512",
    ] {
        for stem in [
            format!("enveloping-rsa-pss-{hash}"),
            format!("enveloped-{hash}-rsa-pss-{hash}"),
        ] {
            if hash == "sha1" && stem.starts_with("enveloped-") {
                continue;
            }
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/xmldsig/aleksey-xmldsig-01");
            let xml = std::fs::read_to_string(root.join(format!("{stem}.xml"))).unwrap();
            let document = XmlDomDocument::parse(&xml).unwrap();
            let info = xml_sec::xmldsig::parse_signed_info(
                find_signature_node(&document)
                    .unwrap()
                    .first_element_child()
                    .unwrap(),
            )
            .unwrap();
            let method = info.signature_method;
            let public = xml_sec::xmldsig::VerificationKey {
                algorithm: method,
                public_key_bytes: spki.contents().to_vec(),
                certificate_der: None,
                name: None,
            };
            let mut policy = xml_sec::policy::VerificationPolicy::default();
            policy
                .key_trust
                .allowed_legacy_signature_algorithms
                .insert(SignatureAlgorithm::RsaPssSha1);
            assert_eq!(
                xml_sec::xmldsig::VerifyContext::new()
                    .key(&public)
                    .policy(policy.clone())
                    .verify(&xml)
                    .unwrap()
                    .status,
                DsigStatus::Valid,
                "{stem}"
            );
            let template = std::fs::read_to_string(root.join(format!("{stem}.tmpl"))).unwrap();
            let signed = SignContext::new(&key)
                .policy(signing.clone())
                .sign_template(&template)
                .unwrap();
            if std::env::var_os("XMLSEC1_BIN").is_some() {
                assert!(xmlsec1::is_available(), "{}", xmlsec1::skip_reason());
                let directory = tempfile::tempdir().unwrap();
                let candidate = directory.path().join("signed.xml");
                std::fs::write(&candidate, &signed).unwrap();
                let output = xmlsec1::command()
                    .args(["--verify", "--pubkey-pem:TestKeyName-rsa-4096"])
                    .arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"),
                    )
                    .arg(&candidate)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{stem}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert_eq!(
                xml_sec::xmldsig::VerifyContext::new()
                    .key(&public)
                    .policy(policy)
                    .verify(&signed)
                    .unwrap()
                    .status,
                DsigStatus::Valid,
                "{stem} template"
            );
            count += 1;
        }
    }
    assert_eq!(count, 17);
}

#[cfg(feature = "aws-lc-fips")]
#[test]
fn pss_native_engines_interoperate_without_parameter_downgrades() {
    // AWS-LC's supported PSS forms cross-verify; mixed hashes remain unsupported.
    use xml_sec::provider::{AwsLcFipsProvider, AwsLcSigningKey, ProviderCapability};
    let private = pem::parse(PRIVATE).unwrap();
    let rust = RsaSigningKey::from_pkcs8_pem(PRIVATE).unwrap();
    for method in [
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::RsaPssSha384,
        SignatureAlgorithm::RsaPssSha512,
        SignatureAlgorithm::RsaPss(RsaPssParameters::DEFAULT),
    ] {
        let aws = AwsLcSigningKey::from_pkcs8_der(method, private.contents()).unwrap();
        let public = xml_sec::xmldsig::VerificationKey {
            algorithm: method,
            public_key_bytes: pem::parse(PUBLIC).unwrap().into_contents(),
            certificate_der: None,
            name: None,
        };
        for signature in [
            RustCryptoProvider
                .sign(&rust, method, b"cross engine")
                .unwrap(),
            AwsLcFipsProvider
                .sign(&aws, method, b"cross engine")
                .unwrap(),
        ] {
            for provider in [
                &RustCryptoProvider as &dyn CryptoProvider,
                &AwsLcFipsProvider,
            ] {
                assert!(
                    provider
                        .verify(&public, method, b"cross engine", &signature)
                        .unwrap()
                );
                assert!(
                    !provider
                        .verify(&public, method, b"wrong", &signature)
                        .unwrap()
                );
            }
        }
    }
    let mixed = SignatureAlgorithm::RsaPss(RsaPssParameters {
        mgf_digest: DigestAlgorithm::Sha384,
        ..RsaPssParameters::DEFAULT
    });
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::Sign(mixed)));
    assert!(!AwsLcFipsProvider.supports(ProviderCapability::Verify(mixed)));
}
