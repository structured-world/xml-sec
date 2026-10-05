//! HMAC policy and complete XMLDSig pipeline regression coverage.
#![cfg(feature = "xmldsig")]

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

use xml_sec::policy::{PolicyViolation, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DsigError, DsigStatus, HmacSigningKey, HmacVerificationKey, ParseError, SignContext,
    SignatureAlgorithm, SigningError, SigningKey, SigningKeyError, SigningPublicKeyInfo,
    VerifyContext,
};

fn template(algorithm: SignatureAlgorithm, output: Option<usize>) -> String {
    let parameter = output
        .map(|bits| format!("<HMACOutputLength>{bits}</HMACOutputLength>"))
        .unwrap_or_default();
    format!(
        r##"<root><payload xml:id="payload">authenticated</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="{}">{parameter}</SignatureMethod><Reference URI="#payload"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature></root>"##,
        algorithm.uri()
    )
}

#[test]
fn every_hmac_algorithm_and_legal_octet_length_round_trips() {
    // Every legal truncation boundary must work through reference digesting,
    // canonicalization, signing and verification, not just direct MAC calls.
    let signing_key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let verifying_key = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
    let wrong_key = HmacVerificationKey::new(vec![0x43; 32]).unwrap();
    for (algorithm, width) in [
        #[cfg(feature = "legacy-algorithms")]
        (SignatureAlgorithm::HmacMd5, 128),
        #[cfg(feature = "legacy-algorithms")]
        (SignatureAlgorithm::HmacRipemd160, 160),
        (SignatureAlgorithm::HmacSha1, 160),
        (SignatureAlgorithm::HmacSha224, 224),
        (SignatureAlgorithm::HmacSha256, 256),
        (SignatureAlgorithm::HmacSha384, 384),
        (SignatureAlgorithm::HmacSha512, 512),
    ] {
        let mut policy = VerificationPolicy {
            signature_algorithms: Some(std::collections::HashSet::from([algorithm])),
            ..VerificationPolicy::default()
        };
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(algorithm);
        let signing_policy = SigningPolicy {
            signature_algorithms: Some(std::collections::HashSet::from([algorithm])),
            ..SigningPolicy::default()
        };
        for output in (128usize.max(width / 2)..=width)
            .step_by(8)
            .map(Some)
            .chain([None])
        {
            let signed = SignContext::new(&signing_key)
                .policy(signing_policy.clone())
                .sign_template(&template(algorithm, output))
                .unwrap();
            let result = VerifyContext::new()
                .policy(policy.clone())
                .key(&verifying_key)
                .verify(&signed)
                .unwrap();
            assert_eq!(result.status, DsigStatus::Valid, "{algorithm:?}/{output:?}");
            let wrong = VerifyContext::new()
                .policy(policy.clone())
                .key(&wrong_key)
                .verify(&signed)
                .unwrap();
            assert_ne!(wrong.status, DsigStatus::Valid, "{algorithm:?}/{output:?}");
            let tampered = signed.replace("authenticated", "unauthenticated");
            let result = VerifyContext::new()
                .policy(policy.clone())
                .key(&verifying_key)
                .verify(&tampered)
                .unwrap();
            assert_ne!(result.status, DsigStatus::Valid, "{algorithm:?}/{output:?}");
        }
    }
}

#[test]
fn hmac_parameter_and_signature_boundaries_are_strict() {
    // Neither malformed integer syntax nor an implicit full-width declaration
    // can authorize a differently sized MAC, even when its prefix is genuine.
    let key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
    let algorithm = SignatureAlgorithm::HmacSha256;
    for invalid in [
        "0",
        "-128",
        "129",
        "264",
        "1 28",
        "128.0",
        "128suffix",
        "184467440737095516160",
    ] {
        let xml = template(algorithm, Some(128)).replace(
            "<HMACOutputLength>128</HMACOutputLength>",
            &format!("<HMACOutputLength>{invalid}</HMACOutputLength>"),
        );
        assert!(
            SignContext::new(&key).sign_template(&xml).is_err(),
            "{invalid}"
        );
        assert!(
            VerifyContext::new().key(&verifier).verify(&xml).is_err(),
            "{invalid}"
        );
    }
    let signed = SignContext::new(&key)
        .sign_template(&template(algorithm, Some(128)))
        .unwrap();
    let implicit_full = signed.replace("<HMACOutputLength>128</HMACOutputLength>", "");
    assert!(matches!(
        VerifyContext::new().key(&verifier).verify(&implicit_full),
        Err(DsigError::InvalidStructure {
            reason: "SignatureValue length does not match HMACOutputLength"
        })
    ));
    let stricter = VerificationPolicy {
        hmac: xml_sec::policy::HmacPolicy {
            minimum_output_bits: 192,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(matches!(
        VerifyContext::new()
            .policy(stricter)
            .key(&verifier)
            .verify(&signed),
        Err(DsigError::Policy(PolicyViolation::HmacOutputLength {
            minimum: 192,
            actual: 128,
            ..
        }))
    ));
}

#[test]
fn all_hmac_methods_interoperate_bidirectionally_with_xmlsec1() {
    // An independent implementation guards against shared sign/verify bugs.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let secret = vec![0x42; 32];
    let key_path = directory.path().join("key.bin");
    let template_path = directory.path().join("template.xml");
    let signed_path = directory.path().join("signed.xml");
    let oracle_path = directory.path().join("oracle.xml");
    std::fs::write(&key_path, &secret).unwrap();
    let signing_key = HmacSigningKey::new(secret.clone()).unwrap();
    let verifying_key = HmacVerificationKey::new(secret).unwrap();
    for (algorithm, minimum, full) in [
        (SignatureAlgorithm::HmacSha1, 128, 160),
        (SignatureAlgorithm::HmacSha224, 128, 224),
        (SignatureAlgorithm::HmacSha256, 128, 256),
        (SignatureAlgorithm::HmacSha384, 192, 384),
        (SignatureAlgorithm::HmacSha512, 256, 512),
        #[cfg(feature = "legacy-algorithms")]
        (SignatureAlgorithm::HmacMd5, 128, 128),
        #[cfg(feature = "legacy-algorithms")]
        (SignatureAlgorithm::HmacRipemd160, 128, 160),
    ] {
        let signing_policy = SigningPolicy {
            signature_algorithms: Some(std::collections::HashSet::from([algorithm])),
            ..SigningPolicy::default()
        };
        let mut verification_policy = VerificationPolicy {
            signature_algorithms: Some([algorithm].into()),
            ..VerificationPolicy::default()
        };
        verification_policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(algorithm);
        for output in [Some(minimum), Some(full), None] {
            let template = template(algorithm, output);
            let signed = SignContext::new(&signing_key)
                .policy(signing_policy.clone())
                .sign_template(&template)
                .unwrap();
            std::fs::write(&signed_path, signed).unwrap();
            let verified = xmlsec1::command()
                .arg("verify")
                .arg("--lax-key-search")
                .arg("--hmac-key")
                .arg(&key_path)
                .arg(&signed_path)
                .output()
                .unwrap();
            assert!(
                verified.status.success(),
                "{algorithm:?}/{output:?}: {}",
                String::from_utf8_lossy(&verified.stderr)
            );
            std::fs::write(&template_path, template).unwrap();
            let generated = xmlsec1::command()
                .arg("sign")
                .arg("--lax-key-search")
                .arg("--hmac-key")
                .arg(&key_path)
                .arg("--output")
                .arg(&oracle_path)
                .arg(&template_path)
                .output()
                .unwrap();
            assert!(
                generated.status.success(),
                "{algorithm:?}/{output:?}: {}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let signed = std::fs::read_to_string(&oracle_path).unwrap();
            let result = VerifyContext::new()
                .policy(verification_policy.clone())
                .key(&verifying_key)
                .verify(&signed)
                .unwrap();
            assert_eq!(result.status, DsigStatus::Valid, "{algorithm:?}/{output:?}");
        }
    }
}

#[test]
fn unknown_signing_method_preserves_typed_parse_error() {
    // Early method validation must retain the public unsupported-algorithm error.
    let key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    let xml = template(SignatureAlgorithm::HmacSha256, None).replace(
        SignatureAlgorithm::HmacSha256.uri(),
        "urn:unsupported:signature",
    );
    assert!(matches!(
        SignContext::new(&key).sign_template(&xml),
        Err(SigningError::ParseSignedInfo(ParseError::UnsupportedAlgorithm { uri }))
            if uri == "urn:unsupported:signature"
    ));
}

#[test]
fn weak_hmac_output_does_not_query_the_signing_key() {
    // Policy refusal must precede even failed external/HSM key callbacks.
    struct UnavailableKey(std::cell::Cell<usize>);
    impl SigningKey for UnavailableKey {
        fn sign(&self, _: SignatureAlgorithm, _: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
            panic!("policy-rejected input must not be signed")
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            self.0.set(self.0.get() + 1);
            Err(SigningKeyError::InvalidPublicKeyInfo)
        }
    }
    let key = UnavailableKey(std::cell::Cell::new(0));
    let xml = template(SignatureAlgorithm::HmacSha256, Some(120));
    assert!(matches!(
        SignContext::new(&key).sign_template(&xml),
        Err(SigningError::Policy(PolicyViolation::HmacOutputLength {
            actual: 120,
            ..
        }))
    ));
    assert_eq!(key.0.get(), 0);
}

#[test]
fn valid_hmac_template_queries_key_metadata_once() {
    // Parameter validation must not add a redundant external/HSM metadata call.
    struct CountedKey {
        key: HmacSigningKey,
        calls: std::cell::Cell<usize>,
    }
    impl SigningKey for CountedKey {
        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            bytes: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            self.key.sign(algorithm, bytes)
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            self.calls.set(self.calls.get() + 1);
            self.key.public_key_info()
        }
    }
    let key = CountedKey {
        key: HmacSigningKey::new(vec![0x42; 32]).unwrap(),
        calls: std::cell::Cell::new(0),
    };
    let verifier = HmacVerificationKey::new(vec![0x42; 32]).unwrap();
    for output in [None, Some(128), Some(256)] {
        key.calls.set(0);
        let signed = SignContext::new(&key)
            .sign_template(&template(SignatureAlgorithm::HmacSha256, output))
            .unwrap();
        assert_eq!(key.calls.get(), 1);
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
fn weak_hmac_output_is_rejected_before_signing_reference_work() {
    // Signing must refuse the selected output before resolving a missing target.
    let xml = r##"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"><HMACOutputLength>120</HMACOutputLength></SignatureMethod>
        <Reference URI="#missing"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>
        </SignedInfo><SignatureValue/></Signature>"##;
    let key = HmacSigningKey::new(vec![0x42; 32]).unwrap();
    assert!(matches!(
        SignContext::new(&key).sign_template(xml),
        Err(SigningError::Policy(PolicyViolation::HmacOutputLength {
            actual: 120,
            ..
        }))
    ));
}

#[test]
fn weak_hmac_output_is_rejected_before_reference_work() {
    // A nonexistent target must not hide the policy refusal or cause reference
    // resolution before rejecting an attacker-selected weak authenticator.
    let xml = r##"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"><HMACOutputLength>120</HMACOutputLength></SignatureMethod>
        <Reference URI="#missing"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue></Reference>
        </SignedInfo><SignatureValue>AAAAAAAAAAAAAAAAAAAA</SignatureValue></Signature>"##;
    assert!(matches!(
        VerifyContext::new()
            .policy(VerificationPolicy::default())
            .verify(xml),
        Err(DsigError::Policy(PolicyViolation::HmacOutputLength {
            minimum: 128,
            maximum: 256,
            actual: 120
        }))
    ));
}
