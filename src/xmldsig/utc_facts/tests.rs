use super::*;

fn limits(bytes: usize, work: usize) -> ResourcePolicy {
    ResourcePolicy {
        max_x509_workspace_bytes: bytes,
        max_x509_work: work,
        ..ResourcePolicy::default()
    }
}

#[test]
fn corrections_are_relative_and_coverage_is_explicit() {
    // The first offset is a baseline, not a correction at coverage start.
    let facts = LeapSecondsList::parse(
        b"#@ 2303683201\n2272060800 10\n2287785600 11\n2303683200 10\n",
        &limits(4096, 4096),
    )
    .expect("a complete list");
    assert_eq!(
        facts.table().transitions(),
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
        assert_eq!(
            LeapSecondsList::parse(input.as_bytes(), &limits(4096, 4096)).err(),
            Some(LeapSecondsError::Malformed),
            "{input}"
        );
    }
}

#[test]
fn fact_loading_preserves_work_and_capacity_limits() {
    // Parsing and retained transitions must both be admitted before work.
    let input = b"#@ 2303683201\n2272060800 10\n2287785600 11\n";
    assert_eq!(
        LeapSecondsList::parse(input, &limits(4096, 0)).err(),
        Some(LeapSecondsError::ResourceLimit)
    );
    assert_eq!(
        LeapSecondsList::parse(input, &limits(0, 4096)).err(),
        Some(LeapSecondsError::ResourceLimit)
    );
}

#[test]
fn the_input_counts_against_the_x509_workspace() {
    // A comment-heavy list holds few transitions but its whole text while it
    // is read: the text takes its share of the workspace too.
    let mut input = String::from("#@ 2303683201\n2272060800 10\n");
    input.push_str(&"# a comment line\n".repeat(32));
    let fits = input.len() + 1024;
    assert!(LeapSecondsList::parse(input.as_bytes(), &limits(fits, 1 << 20)).is_ok());
    assert_eq!(
        LeapSecondsList::parse(input.as_bytes(), &limits(input.len() - 1, 1 << 20)).err(),
        Some(LeapSecondsError::ResourceLimit)
    );
}

#[test]
fn a_list_beyond_the_resource_byte_limit_is_refused_before_parsing() {
    // The per-resource limit holds for a list passed as bytes too.
    let input = b"#@ 2303683201\n2272060800 10\n";
    let resources = ResourcePolicy {
        max_external_resource_bytes: input.len() - 1,
        ..ResourcePolicy::default()
    };
    assert_eq!(
        LeapSecondsList::parse(input, &resources).err(),
        Some(LeapSecondsError::TooLarge {
            maximum: input.len() - 1
        })
    );
}
