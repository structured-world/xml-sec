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

fn memory(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}

#[test]
fn corrections_are_relative_and_coverage_is_explicit() {
    // The first offset is a baseline, not a correction at coverage start.
    let facts = UtcFacts::parse(
        b"#@ 2303683201\n2272060800 10\n2287785600 11\n2303683200 10\n",
        &memory(4096, 4096),
    )
    .unwrap();
    assert_eq!(
        facts.table().unwrap().transitions(),
        &[
            Transition::new(78_796_800, 1),
            Transition::new(94_694_400, 0)
        ]
    );
}

#[test]
fn malformed_or_incomplete_facts_never_become_a_default_table() {
    // Missing expiry, duplicate dates, non-unit corrections and invalid
    // numeric spellings must not silently claim a covered UTC interval.
    for input in [
        "2272060800 10\n",
        "#@ 2303683201\n#@ 2303683201\n2272060800 10\n",
        "#@ 2303683201\n2272060800 10\n2272060800 11\n",
        "#@ 2303683201\n2272060800 10\n2287785600 12\n",
        "#@ 2303683201\n+2272060800 10\n",
    ] {
        assert!(
            UtcFacts::parse(input.as_bytes(), &memory(4096, 4096)).is_err(),
            "{input}"
        );
    }
}

#[test]
fn fact_loading_preserves_work_and_capacity_limits() {
    // Parsing and retained transitions must both be admitted before work.
    let input = b"#@ 2303683201\n2272060800 10\n2287785600 11\n";
    assert!(UtcFacts::parse(input, &memory(4096, 0)).is_err());
    assert!(UtcFacts::parse(input, &memory(0, 4096)).is_err());
}
