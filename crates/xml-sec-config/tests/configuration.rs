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

const NANOS_PER_SECOND: i128 = 1_000_000_000;

fn now() -> xml_sec::policy::Instant {
    xml_sec::policy::instant_from_system_time(std::time::SystemTime::now()).unwrap()
}

/// `time` moved by `nanos`, carrying across whole seconds.
fn shifted(time: xml_sec::policy::Instant, nanos: i128) -> xml_sec::policy::Instant {
    let total = i128::from(time.seconds()) * NANOS_PER_SECOND + i128::from(time.nanos()) + nanos;
    xml_sec::policy::Instant::new(
        i64::try_from(total.div_euclid(NANOS_PER_SECOND)).unwrap(),
        u32::try_from(total.rem_euclid(NANOS_PER_SECOND)).unwrap(),
    )
    .unwrap()
}

#[test]
fn earliest_signed_verification_time_round_trips_effective_policy() {
    // Schema-admitted lower-bound instants must compile and survive effective
    // output, not fail only when the snapshot serializes their unsigned span.
    for nanoseconds in [0, 1, 999_999_999] {
        let original = effective(
            &config(&format!(
                "[profiles.team.verification.key_trust]\nverification_time={{seconds={},nanoseconds={nanoseconds}}}",
                i64::MIN
            )),
            "team",
        );
        let output = original.to_toml().unwrap();
        let restored = Configuration::from_str(&output, LoadLimits::default()).unwrap();
        let restored = effective(&restored, "effective");
        assert_eq!(output, restored.to_toml().unwrap());
        assert_eq!(original.diff(&restored), []);
    }
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
        assert_eq!(original.diff(&restored), []);
    }
}

#[cfg(feature = "pkcs11")]
#[test]
fn pkcs11_configuration_retains_encryption_policies() {
    // PKCS#11 enables encryption in the core; configuration must admit and
    // retain the same policy sections even without its default features.
    let policy = effective(
        &config(
            "[profiles.team.encryption]\nenabled=true\n[profiles.team.decryption]\nenabled=true",
        ),
        "team",
    );
    assert!(policy.compiled().encryption().is_some());
    assert!(policy.compiled().decryption().is_some());
    let output = policy.to_toml().expect("effective output");
    assert!(output.contains("[profiles.effective.encryption]"));
    assert!(output.contains("[profiles.effective.decryption]"));
    let restored =
        Configuration::from_str(&output, LoadLimits::default()).expect("effective configuration");
    assert_eq!(
        output,
        effective(&restored, "effective")
            .to_toml()
            .expect("round trip")
    );
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
fn detached_payload_settings_compose_restrictively() {
    // An ordinary layer only restricts: it cannot accept caller-attested
    // digests the base profile forbids, just as it cannot enable external URIs.
    // The streamed byte limits narrow like every other resource ceiling and
    // both settings survive effective output.
    use xml_sec::policy::DetachedDigestAttestation;
    let old = effective(&config(""), "team");
    let next = effective(
        &config(
            "[profiles.team.verification]\ndetached_digest_attestation='Accepted'\n[profiles.team.verification.resources]\nmax_detached_payload_bytes=1024\nmax_detached_payload_total_bytes=4096",
        ),
        "team",
    );
    let verification = next.compiled().verification().unwrap();
    assert_eq!(
        verification.detached_digest_attestation,
        DetachedDigestAttestation::Forbidden
    );
    assert_eq!(verification.resources.max_detached_payload_bytes, 1024);
    assert_eq!(
        verification.resources.max_detached_payload_total_bytes,
        4096
    );
    let changes = old.diff(&next);
    for field in [
        "verification.resources.max_detached_payload_bytes",
        "verification.resources.max_detached_payload_total_bytes",
    ] {
        assert!(
            changes
                .iter()
                .any(|c| c.field == field && c.direction == Direction::Restrictive),
            "{field}: {changes:?}"
        );
    }
    let output = next.to_toml().unwrap();
    assert!(output.contains("detached_digest_attestation = \"Forbidden\""));
    let restored = Configuration::from_str(&output, LoadLimits::default()).unwrap();
    assert_eq!(effective(&restored, "effective").to_toml().unwrap(), output);
    assert!(
        Configuration::from_str(
            "schema_version=1\n[profiles.a]\nbase='Modern'\n[profiles.a.signing]\ndetached_digest_attestation='Accepted'",
            LoadLimits::default(),
        )
        .is_err(),
        "attestation applies to verification only"
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
fn signature_constraint_diff_matches_typed_composition() {
    // General is the identity of constraint intersection. Different specialized
    // constraints are incomparable, not progressively stricter protocol levels.
    use xml_sec::policy::{PolicyCompiler, PolicyProfile, SignatureConstraints};
    let variants = [
        SignatureConstraints::General,
        SignatureConstraints::Saml,
        SignatureConstraints::WsSecurity,
        SignatureConstraints::Xades,
    ];
    let load = |constraints| {
        effective(
            &config(&format!(
                "[profiles.team.verification]\nsignature_constraints='{constraints:?}'\n[profiles.team.verification.key_trust]\nmode='RequireTrustedKey'\n[profiles.team.signing]\nsignature_constraints='{constraints:?}'"
            )),
            "team",
        )
    };
    for before in variants {
        let old = load(before);
        for after in variants {
            let new = load(after);
            let compiler = PolicyCompiler::new(PolicyProfile::Modern, default_provider(), None)
                .expect("base compiler");
            let mut layer = compiler.policies().clone();
            layer
                .verification
                .as_mut()
                .expect("verification")
                .signature_constraints = before;
            layer
                .signing
                .as_mut()
                .expect("signing")
                .signature_constraints = before;
            let compiler = compiler.restrict(&layer).expect("initial restriction");
            let mut layer = compiler.policies().clone();
            layer
                .verification
                .as_mut()
                .expect("verification")
                .signature_constraints = after;
            layer
                .signing
                .as_mut()
                .expect("signing")
                .signature_constraints = after;
            let intersection = compiler.restrict(&layer);
            let expected = if before == after {
                Direction::Neutral
            } else if intersection.as_ref().is_ok_and(|c| {
                c.policies()
                    .verification
                    .as_ref()
                    .expect("verification")
                    .signature_constraints
                    == after
            }) {
                Direction::Restrictive
            } else {
                Direction::Relaxing
            };
            for operation in ["verification", "signing"] {
                let field = format!("{operation}.signature_constraints");
                let changes = old.diff(&new);
                let change = changes.iter().find(|c| c.field == field);
                if expected == Direction::Neutral {
                    assert!(change.is_none(), "{operation}: {before:?} -> {after:?}");
                } else {
                    assert_eq!(
                        change.expect("constraint change").direction,
                        expected,
                        "{operation}: {before:?} -> {after:?}"
                    );
                }
            }
        }
    }
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

#[test]
fn default_transform_and_agreement_permissions_narrow_to_allowlists() {
    // None is field-specific, not an empty set: transforms permit implemented
    // methods, while agreement defaults permit ECDH-ES/X25519 but not X448.
    let load = |extra: &str| {
        Configuration::from_str(
            &format!("schema_version=1\n[profiles.team]\nbase='XmlSecCompatible'\n{extra}"),
            LoadLimits::default(),
        )
        .unwrap()
    };
    let old = effective(&load(""), "team");
    let new = effective(
        &load(
            "[profiles.team.verification.transforms]\nallowed_algorithms=['http://www.w3.org/TR/2001/REC-xml-c14n-20010315']\n[profiles.team.verification.key_establishment]\nagreement_algorithms=['http://www.w3.org/2009/xmlenc11#ECDH-ES']\nderivation_algorithms=['http://www.w3.org/2009/xmlenc11#ConcatKDF']\ndigest_algorithms=['http://www.w3.org/2001/04/xmlenc#sha256']",
        ),
        "team",
    );
    for field in [
        "verification.transforms.allowed_algorithms",
        "verification.key_establishment.agreement_algorithms",
        "verification.key_establishment.derivation_algorithms",
        "verification.key_establishment.digest_algorithms",
    ] {
        assert_eq!(
            old.diff(&new)
                .iter()
                .find(|change| change.field == field)
                .unwrap()
                .direction,
            Direction::Restrictive,
            "{field}"
        );
        assert_eq!(
            new.diff(&old)
                .iter()
                .find(|change| change.field == field)
                .unwrap()
                .direction,
            Direction::Relaxing,
            "{field}"
        );
    }
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
    let expected = xml_sec::policy::Instant::new(-1, 123_456_789).unwrap();
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
    assert_eq!(original.diff(&restored), []);
}

#[test]
fn validity_presence_diff_is_one_directional_change_per_operation() {
    // Binding a grant narrows every operation to its time window; removing it
    // widens permission. Audit metadata must not split this into false relaxations.
    use xml_sec::policy::PolicyValidity;
    let configuration = config("");
    let ordinary = effective(&configuration, "team");
    let now = now();
    let grant = PolicyValidity {
        authorization_id: "test-grant".into(),
        authority: "test-application".into(),
        reason: "bounded operation".into(),
        not_before: shifted(now, -60 * NANOS_PER_SECOND),
        expires_at: shifted(now, 3600 * NANOS_PER_SECOND),
    };
    let bounded = configuration
        .compile(
            "team",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: true,
            },
            Some(grant.clone()),
        )
        .unwrap();
    let mut operations = vec!["verification", "signing"];
    if cfg!(feature = "xmlenc") {
        operations.extend(["encryption", "decryption"]);
    }
    for (before, after, expected) in [
        (&ordinary, &bounded, Direction::Restrictive),
        (&bounded, &ordinary, Direction::Relaxing),
    ] {
        let changes = before.diff(after);
        assert_eq!(changes.len(), operations.len(), "{changes:?}");
        for operation in &operations {
            let field = format!("{operation}.validity");
            let change = changes.iter().find(|change| change.field == field).unwrap();
            assert_eq!(change.direction, expected, "{field}");
        }
    }
    let narrower = configuration
        .compile(
            "team",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: true,
            },
            Some(PolicyValidity {
                not_before: shifted(grant.not_before, 1),
                expires_at: shifted(grant.expires_at, -1),
                ..grant
            }),
        )
        .unwrap();
    // Existing windows retain exact leaf-level comparisons, including nanos.
    for (before, after, expected) in [
        (&bounded, &narrower, Direction::Restrictive),
        (&narrower, &bounded, Direction::Relaxing),
    ] {
        let changes = before.diff(after);
        assert_eq!(changes.len(), operations.len() * 2);
        for change in changes {
            assert!(
                change.field.ends_with(".validity.not_before")
                    || change.field.ends_with(".validity.expires_at")
            );
            assert_eq!(change.direction, expected, "{}", change.field);
        }
    }
}

#[test]
fn legacy_authority_must_come_from_caller_and_retains_exact_interval() {
    // A TOML audit record is not proof of authority. A supplied authenticated
    // grant is retained exactly, including fractional expiry, on round trip.
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
    let now = now();
    let grant = PolicyValidity {
        authorization_id: "audit-record".into(),
        authority: "trusted-application".into(),
        reason: "historical validation".into(),
        not_before: shifted(now, -60 * NANOS_PER_SECOND),
        expires_at: shifted(now, 3600 * NANOS_PER_SECOND),
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
    assert_eq!(policy.diff(&restored), []);
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
fn xslt_stylesheet_semantics_comes_from_the_base_profile() {
    // Interpretation semantics are not relaxations: the libxmlsec1-compatible base
    // selects libxmlsec1 stylesheet reading, a layer may only restate its base, and
    // unknown names are schema errors.
    use xml_sec::policy::{PolicyViolation, XsltStylesheetSemantics};
    let base = |base: &str, extra: &str| {
        Configuration::from_str(
            &format!("schema_version = 1\n[profiles.team]\nbase = '{base}'\n{extra}"),
            LoadLimits::default(),
        )
    };
    let semantics = |base_name: &str| {
        effective(&base(base_name, "").expect("strict config"), "team")
            .compiled()
            .verification()
            .unwrap()
            .transforms
            .xslt_stylesheet_semantics
    };
    assert_eq!(
        semantics("XmlSecCompatible"),
        XsltStylesheetSemantics::Libxmlsec1
    );
    assert_eq!(semantics("Modern"), XsltStylesheetSemantics::Specification);

    let restated = base(
        "XmlSecCompatible",
        "[profiles.team.verification.transforms]\nxslt_stylesheet_semantics='Libxmlsec1'",
    )
    .expect("strict config");
    assert_eq!(
        effective(&restated, "team")
            .compiled()
            .verification()
            .unwrap()
            .transforms
            .xslt_stylesheet_semantics,
        XsltStylesheetSemantics::Libxmlsec1
    );
    let compile = |value: &str| {
        base(
            "Modern",
            &format!(
                "[profiles.team.verification.transforms]\nxslt_stylesheet_semantics='{value}'"
            ),
        )
        .expect("strict config")
        .compile(
            "team",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: true,
            },
            None,
        )
    };
    assert!(matches!(
        compile("Libxmlsec1"),
        Err(xml_sec_config::Error::Policy(PolicyViolation::Configuration { reason }))
            if reason.contains("incompatible interpretation semantics")
    ));
    assert!(matches!(
        base(
            "Modern",
            "[profiles.team.verification.transforms]\nxslt_stylesheet_semantics='Lenient'",
        ),
        Err(xml_sec_config::Error::Schema(message)) if message.contains("xslt_stylesheet_semantics")
    ));
}

#[cfg(feature = "xmldsig-sign")]
#[test]
fn configured_snapshots_enforce_real_sign_and_verify_limits() {
    // The loader must deliver enforced core snapshots, not a parallel config
    // object that the cryptographic operation ignores.
    use xml_sec::xmldsig::{
        DsigStatus, HmacSigningKey, HmacVerificationKey, SignContext, VerifyContext,
    };
    let input = r##"<root ID="target"><payload>protected</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let policies = effective(&config(""), "team");
    let signing_key = HmacSigningKey::new(vec![7; 32]).unwrap();
    let verifier = HmacVerificationKey::new(vec![7; 32]).unwrap();
    let signed = SignContext::new(&signing_key)
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
        SignContext::new(&signing_key)
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
