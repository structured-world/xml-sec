use super::{KeySourceKind, KeySourcePolicy, Table, Value, key_sources, source_snapshot};

#[test]
fn all_key_source_subsets_preserve_the_toml_contract() {
    // Every old Boolean combination keeps its exact names and values in both
    // directions; the compact Rust representation must not change the schema.
    let fields = [
        ("preset_key", KeySourceKind::PresetKey),
        ("key_name", KeySourceKind::KeyName),
        ("key_value", KeySourceKind::KeyValue),
        ("der_encoded_key_value", KeySourceKind::DerEncodedKeyValue),
        ("x509_data", KeySourceKind::X509Data),
        ("key_info_reference", KeySourceKind::KeyInfoReference),
    ];
    for subset in 0_u8..64 {
        let expected = Value::Table(
            fields
                .iter()
                .enumerate()
                .map(|(index, (name, _))| {
                    (
                        (*name).to_string(),
                        Value::Boolean(subset & (1 << index) != 0),
                    )
                })
                .collect(),
        );
        let mut policy = KeySourcePolicy::ALL;
        key_sources(&mut policy, &expected).unwrap();
        for (index, (_, kind)) in fields.iter().enumerate() {
            assert_eq!(policy.contains(*kind), subset & (1 << index) != 0);
        }
        assert_eq!(source_snapshot(policy), expected);
    }
}

#[test]
fn partial_key_source_tables_do_not_change_other_permissions() {
    // A partial override changes only its named permission, including when
    // the inherited set starts empty rather than at the permissive default.
    for mut policy in [KeySourcePolicy::NONE, KeySourcePolicy::ALL] {
        let original = policy;
        let permitted = !policy.contains(KeySourceKind::KeyValue);
        let value = Value::Table(Table::from_iter([(
            "key_value".into(),
            Value::Boolean(permitted),
        )]));
        key_sources(&mut policy, &value).unwrap();
        for source in KeySourceKind::ALL {
            assert_eq!(
                policy.contains(source),
                if source == KeySourceKind::KeyValue {
                    permitted
                } else {
                    original.contains(source)
                }
            );
        }
    }
}

#[test]
fn key_source_parser_keeps_unknown_names_and_non_booleans_invalid() {
    // Neither compact bit positions nor an integer encoding becomes an
    // accepted configuration input, and failure leaves this entry unchanged.
    for (name, value) in [
        ("unknown_source", Value::Boolean(true)),
        ("key_value", Value::Integer(1)),
        ("preset_key", Value::String("true".into())),
    ] {
        let mut policy = KeySourcePolicy::NONE;
        let input = Value::Table(Table::from_iter([(name.into(), value)]));
        assert!(key_sources(&mut policy, &input).is_err());
        assert_eq!(policy, KeySourcePolicy::NONE);
    }
}
