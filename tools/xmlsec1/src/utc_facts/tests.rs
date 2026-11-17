use super::*;

#[test]
fn file_loading_checks_external_input_ceiling() {
    // A valid UTC file cannot bypass the stricter external input ceiling
    // merely because it fits the X.509 workspace and work allowances.
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"#@ 2303683201\n2272060800 10\n").unwrap();
    let invocation = Invocation::parse([
        "xmlsec1".into(),
        "verify".into(),
        "--utc-facts".into(),
        file.path().as_os_str().to_owned(),
        "unused.xml".into(),
    ])
    .unwrap();
    let resources = ResourcePolicy {
        max_external_resource_bytes: 1,
        ..Default::default()
    };
    assert!(matches!(
        UtcFacts::load(
            &invocation,
            &resources,
            &mut ExternalMaterialBudget::new(resources.max_external_resource_total_bytes)
        ),
        Err(CommandError::ExternalMaterialTooLarge { maximum: 1 })
    ));
}

#[test]
fn utc_files_and_later_evidence_share_aggregate_admission() {
    // Prior input and subsequent evidence consume the same account. Exact
    // admission is accepted; one extra byte is rejected, without a reset.
    let file = tempfile::NamedTempFile::new().unwrap();
    let bytes = b"#@ 2303683201\n2272060800 10\n";
    std::fs::write(file.path(), bytes).unwrap();
    let invocation = Invocation::parse([
        "xmlsec1".into(),
        "verify".into(),
        "--utc-facts".into(),
        file.path().as_os_str().to_owned(),
        "unused.xml".into(),
    ])
    .unwrap();
    let limits = ResourcePolicy {
        max_external_resource_bytes: bytes.len(),
        max_external_resource_total_bytes: bytes.len() + 1,
        ..Default::default()
    };
    let mut budget = ExternalMaterialBudget::new(limits.max_external_resource_total_bytes);
    budget.charge(1).unwrap();
    assert!(
        UtcFacts::load(&invocation, &limits, &mut budget)
            .unwrap()
            .is_some()
    );
    assert_eq!(budget.remaining(), 0);
    assert!(matches!(
        budget.charge(1),
        Err(CommandError::ExternalMaterialTooLarge { .. })
    ));
    let mut budget = ExternalMaterialBudget::new(limits.max_external_resource_total_bytes);
    budget.charge(2).unwrap();
    assert!(matches!(
        UtcFacts::load(&invocation, &limits, &mut budget),
        Err(CommandError::ExternalMaterialTooLarge { .. })
    ));
}

#[test]
fn a_malformed_file_is_a_usage_error() {
    // The core refuses the list; the command names the option.
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"2272060800 10\n").unwrap();
    let invocation = Invocation::parse([
        "xmlsec1".into(),
        "verify".into(),
        "--utc-facts".into(),
        file.path().as_os_str().to_owned(),
        "unused.xml".into(),
    ])
    .unwrap();
    let limits = ResourcePolicy::default();
    let refused = UtcFacts::load(
        &invocation,
        &limits,
        &mut ExternalMaterialBudget::new(limits.max_external_resource_total_bytes),
    );
    assert!(
        matches!(&refused, Err(CommandError::Usage(message)) if message.contains("--utc-facts")),
        "{:?}",
        refused.err()
    );
}
