use xml_sec::{policy::PolicyCompileContext, provider::default_provider};
use xml_sec_config::{Configuration, Direction, LoadLimits};

fn config(extra: &str) -> Configuration {
    Configuration::from_str(
        &format!("schema_version = 1\n[profiles.team]\nbase = 'Modern'\n{extra}"),
        LoadLimits::default(),
    )
    .expect("strict config")
}
fn effective(config: &Configuration, name: &str) -> xml_sec_config::EffectivePolicy {
    config
        .compile(
            name,
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: true,
            },
            None,
        )
        .expect("compiled policy")
}

#[test]
fn all_ordinary_profiles_round_trip_effective_policy() {
    // Every exposed setting must survive canonical output and re-compilation,
    // independent of HashSet order or profile-specific restrictions.
    for base in [
        "Modern",
        "XmlSecCompatible",
        "SecureSaml",
        "WsSecurity",
        "Xades",
    ] {
        let config = Configuration::from_str(
            &format!("schema_version=1\n[profiles.team]\nbase='{base}'"),
            LoadLimits::default(),
        )
        .unwrap();
        let original = effective(&config, "team");
        let output = original.to_toml().unwrap();
        let parsed = Configuration::from_str(&output, LoadLimits::default()).unwrap();
        let restored = effective(&parsed, "effective");
        assert_eq!(output, restored.to_toml().unwrap());
        assert!(original.diff(&restored).is_empty());
    }
}

#[test]
fn strict_schema_rejects_typos_versions_cycles_and_irrelevant_fields() {
    // No unknown setting can be ignored and accidentally inherit permission.
    for input in [
        "schema_version=2\n[profiles.a]\nbase='Modern'",
        "schema_version=1\nextra=true\n[profiles.a]\nbase='Modern'",
        "schema_version=1\n[profiles.a]\nbase='Modern'\nverify=true",
        "schema_version=1\n[profiles.a]\nextends='b'\n[profiles.b]\nextends='a'",
        "schema_version=1\n[profiles.a]\nextends='missing'",
        "schema_version=1\n[profiles.a]\nbase='Modern'\n[profiles.a.verification.resources]\nmax_xml_node=3",
        "schema_version=1\n[profiles.a]\nbase='Modern'\n[profiles.a.signing.key_sources]\nkey_value=false",
        "schema_version=1\n[profiles.a]\nbase='Modern'\n[profiles.a.encryption]\nmanifest_processing='Ignore'",
    ] {
        assert!(
            Configuration::from_str(input, LoadLimits::default()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn restrictive_inheritance_cannot_raise_ceiling_or_enable_operations() {
    // Child omission inherits, whereas an explicit disabled operation stays
    // disabled; permissive child limits never undo the parent's restriction.
    let config = Configuration::from_str("schema_version=1\n[profiles.parent]\nbase='Modern'\n[profiles.parent.verification.resources]\nmax_xml_nodes=10\n[profiles.parent.signing]\nenabled=false\n[profiles.child]\nextends='parent'\n[profiles.child.verification.resources]\nmax_xml_nodes=20", LoadLimits::default()).unwrap();
    let child = effective(&config, "child");
    assert_eq!(
        child
            .compiled()
            .verification()
            .unwrap()
            .resources
            .max_xml_nodes,
        10
    );
    assert!(child.compiled().signing().is_none());
    let bad = Configuration::from_str("schema_version=1\n[profiles.a]\nbase='Modern'\n[profiles.a.signing]\nenabled=false\n[profiles.b]\nextends='a'\n[profiles.b.signing]\nenabled=true", LoadLimits::default()).unwrap();
    assert!(
        bad.compile(
            "b",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: false
            },
            None
        )
        .is_err()
    );
}

#[test]
fn directional_diff_covers_minima_limits_and_disabled_operations() {
    // A change report must not confuse higher security minima with higher
    // resource ceilings; those have opposite directions.
    let old = effective(&config(""), "team");
    let next = effective(
        &config(
            "[profiles.team.verification.resources]\nmax_xml_nodes=10\n[profiles.team.signing]\nenabled=false",
        ),
        "team",
    );
    let changes = old.diff(&next);
    assert!(
        changes
            .iter()
            .any(|c| c.field == "verification.resources.max_xml_nodes"
                && c.direction == Direction::Restrictive)
    );
    assert!(
        changes
            .iter()
            .any(|c| c.field == "signing.enabled" && c.direction == Direction::Restrictive)
    );
    let reverse = next.diff(&old);
    assert!(
        reverse
            .iter()
            .any(|c| c.field == "verification.resources.max_xml_nodes"
                && c.direction == Direction::Relaxing)
    );
}

#[test]
fn bounded_readers_and_paths_admit_bytes_before_parsing() {
    // The exact boundary passes, one extra byte fails without heap growth for
    // that byte, and caller-selected paths are the only files consulted.
    let source = "schema_version=1\n[profiles.a]\nbase='Modern'";
    let limits = LoadLimits {
        max_bytes: source.len(),
        max_profiles: 1,
    };
    assert!(Configuration::from_reader(source.as_bytes(), limits).is_ok());
    assert!(Configuration::from_reader(format!("{source}\n").as_bytes(), limits).is_err());
    assert!(
        Configuration::from_str(
            source,
            LoadLimits {
                max_bytes: 1,
                max_profiles: 1
            }
        )
        .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, source).unwrap();
    assert!(Configuration::from_path(&path, limits).is_ok());
    assert!(Configuration::from_path(dir.path().join("absent.toml"), limits).is_err());
}

#[test]
fn certificate_default_to_classical_allowlist_is_restrictive() {
    // The default admits classical methods, not PQ. Narrowing to one classical
    // method must not be reported as permission growth merely due to TOML types.
    let old = effective(&config(""), "team");
    let new = effective(
        &config(
            "[profiles.team.verification.key_trust]\ncertificate_signature_algorithms=[{kind='Ed25519'}]",
        ),
        "team",
    );
    let field = "verification.key_trust.certificate_signature_algorithms";
    assert_eq!(
        old.diff(&new)
            .iter()
            .find(|c| c.field == field)
            .unwrap()
            .direction,
        Direction::Restrictive
    );
    assert_eq!(
        new.diff(&old)
            .iter()
            .find(|c| c.field == field)
            .unwrap()
            .direction,
        Direction::Relaxing
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn configured_snapshots_enforce_real_encrypt_and_decrypt_limits() {
    // Exercise the config-to-public-context boundary with actual authenticated
    // encryption, then prove each configured resource limit refuses work.
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
        SymmetricKeyDecryptor, XmlEncError,
    };
    let policies = effective(&config(""), "team");
    let key = vec![7; 16];
    let resolver = SymmetricKeyDecryptor::new(key.clone());
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key.clone())
        .policy(policies.compiled().encryption().unwrap().clone())
        .encrypt_binary(b"protected")
        .unwrap();
    assert_eq!(
        DecryptContext::new(&resolver)
            .policy(policies.compiled().decryption().unwrap().clone())
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        DecryptedContent::Bytes(b"protected".to_vec())
    );
    let restricted = effective(
        &config(
            "[profiles.team.encryption.resources]\nmax_encryption_plaintext_bytes=0\n[profiles.team.decryption.resources]\nmax_xml_nodes=0",
        ),
        "team",
    );
    assert!(matches!(
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(key)
            .policy(restricted.compiled().encryption().unwrap().clone())
            .encrypt_binary(b"protected"),
        Err(XmlEncError::Policy(_))
    ));
    assert!(matches!(
        DecryptContext::new(&resolver)
            .policy(restricted.compiled().decryption().unwrap().clone())
            .decrypt(&encrypted.encrypted_data_xml),
        Err(XmlEncError::Policy(_))
    ));
}

#[test]
fn disabling_operation_has_only_restrictive_effective_changes() {
    // Removing an operation's subordinate settings is not a relaxation: they
    // are unreachable once enabled=false. The reverse enables all those paths.
    let old = effective(&config(""), "team");
    let new = effective(&config("[profiles.team.signing]\nenabled=false"), "team");
    assert!(
        old.diff(&new)
            .iter()
            .all(|c| c.direction == Direction::Restrictive)
    );
    assert!(
        new.diff(&old)
            .iter()
            .all(|c| c.direction == Direction::Relaxing)
    );
}

#[test]
fn effective_time_preserves_fractional_and_negative_unix_time() {
    // Historical certificate time is not constrained to the Unix epoch, and
    // canonical policy output must not discard a nanosecond boundary.
    let original = effective(
        &config(
            "[profiles.team.verification.key_trust]\nverification_time={seconds=-1, nanoseconds=123456789}",
        ),
        "team",
    );
    let expected = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1)
        + std::time::Duration::from_nanos(123456789);
    assert_eq!(
        original
            .compiled()
            .verification()
            .unwrap()
            .key_trust
            .verification_time,
        Some(expected)
    );
    let output = original.to_toml().unwrap();
    let parsed = Configuration::from_str(&output, LoadLimits::default()).unwrap();
    let restored = effective(&parsed, "effective");
    assert_eq!(
        restored
            .compiled()
            .verification()
            .unwrap()
            .key_trust
            .verification_time,
        Some(expected)
    );
    assert!(original.diff(&restored).is_empty());
}

#[test]
fn legacy_authority_must_come_from_caller_and_retains_exact_interval() {
    // A TOML audit record is not proof of authority. A supplied authenticated
    // grant is retained exactly, including fractional expiry, on round trip.
    use std::time::{Duration, SystemTime};
    use xml_sec::policy::PolicyValidity;
    let config = Configuration::from_str(
        "schema_version=1\n[profiles.legacy]\nbase='LegacyVerify'",
        LoadLimits::default(),
    )
    .unwrap();
    let context = PolicyCompileContext {
        external_resources: false,
        target_evidence: false,
    };
    assert!(
        config
            .compile("legacy", default_provider(), &context, None)
            .is_err()
    );
    let now = SystemTime::now();
    let grant = PolicyValidity {
        authorization_id: "audit-record".into(),
        authority: "trusted-application".into(),
        reason: "historical validation".into(),
        not_before: now - Duration::from_secs(60),
        expires_at: now + Duration::from_secs(3600),
    };
    let policy = config
        .compile("legacy", default_provider(), &context, Some(grant.clone()))
        .unwrap();
    assert!(policy.compiled().signing().is_none());
    let output = policy.to_toml().unwrap();
    let restored = Configuration::from_str(&output, LoadLimits::default()).unwrap();
    assert!(
        restored
            .compile("effective", default_provider(), &context, None)
            .is_err()
    );
    let restored = restored
        .compile(
            "effective",
            default_provider(),
            &context,
            Some(grant.clone()),
        )
        .unwrap();
    assert_eq!(
        restored
            .compiled()
            .verification()
            .unwrap()
            .validity
            .as_ref(),
        Some(&grant)
    );
    assert!(policy.diff(&restored).is_empty());
}

#[test]
fn conflicting_semantics_empty_algorithms_and_invalid_limits_fail_compilation() {
    // Restrictive composition is not a bypass for contradictory public-policy
    // requirements; the normal compiler must refuse unusable snapshots.
    for fields in [
        "[profiles.team.verification.key_trust]\nmax_x509_chain_depth=0",
        "[profiles.team.signing]\nsignature_algorithms=[]\nparameterized_rsa_pss='ExactOnly'",
        "[profiles.team.verification.transforms]\nallowed_algorithms=[]",
        "[profiles.team.verification]\necdsa_signature_value_encoding='XmlSecAsn1Der'",
        "[profiles.team.verification.key_trust]\ncheck_crls=true\nverify_x509_chains=false",
    ] {
        let input = config(fields);
        assert!(
            input
                .compile(
                    "team",
                    default_provider(),
                    &PolicyCompileContext {
                        external_resources: false,
                        target_evidence: false
                    },
                    None
                )
                .is_err(),
            "accepted {fields}"
        );
    }
}

#[test]
fn configured_snapshots_enforce_real_sign_and_verify_limits() {
    // The loader must deliver enforced core snapshots, not a parallel config
    // object that the cryptographic operation ignores.
    use xml_sec::xmldsig::{
        DsigStatus, HmacSigningKey, HmacVerificationKey, SignContext, VerifyContext,
    };
    let input = r##"<root ID="target"><payload>protected</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let policies = effective(&config(""), "team");
    let signer = HmacSigningKey::new(vec![7; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![7; 32]).unwrap();
    let signed = SignContext::new(&signer)
        .policy(policies.compiled().signing().unwrap().clone())
        .sign_template(input)
        .unwrap();
    let result = VerifyContext::new()
        .key(&verifier)
        .policy(policies.compiled().verification().unwrap().clone())
        .verify(&signed)
        .unwrap();
    assert_eq!(result.status, DsigStatus::Valid);
    let restricted = effective(
        &config(
            "[profiles.team.signing.resources]\nmax_xml_nodes=0\n[profiles.team.verification.resources]\nmax_xml_nodes=0",
        ),
        "team",
    );
    assert!(
        SignContext::new(&signer)
            .policy(restricted.compiled().signing().unwrap().clone())
            .sign_template(input)
            .is_err()
    );
    assert!(
        VerifyContext::new()
            .key(&verifier)
            .policy(restricted.compiled().verification().unwrap().clone())
            .verify(&signed)
            .is_err()
    );
}

#[test]
fn custom_purpose_preserves_full_u64_oid_arcs() {
    // TOML integers are signed i64; decimal-string arcs preserve the public
    // u64 OID model without wrapping, on both 32- and 64-bit consumers.
    let original = effective(
        &config(
            "[profiles.team.verification.key_trust]\nallowed_extended_key_usages=[['2', '18446744073709551615', '1']]",
        ),
        "team",
    );
    // The default Modern profile denies explicit EKUs, so this overlay must
    // remain empty rather than grant the supplied purpose. Syntax still must
    // preserve the arc domain before restrictive composition.
    assert!(
        original
            .compiled()
            .verification()
            .unwrap()
            .key_trust
            .allowed_extended_key_usages
            .is_empty()
    );
    let output = original.to_toml().unwrap();
    assert!(Configuration::from_str(&output, LoadLimits::default()).is_ok());
}
