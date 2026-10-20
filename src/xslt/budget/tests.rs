use super::*;

#[test]
fn serialized_bytes_are_admitted_before_output_work() {
    // The output quota is independent, but serialization still consumes the
    // caller's aggregate execution remainder before any bytes are written.
    let mut limits = execution_budget(1024);
    limits.serialized_bytes = 128;
    let mut meter = Meter::new(limits, 0)
        .expect("empty source fits the budget")
        .with_work_ceiling(31);
    assert!(matches!(
        meter.charge(BudgetKind::SerializedBytes, 32),
        Err(Error::Budget {
            kind: BudgetKind::AggregateWork,
            limit: 31,
            actual: 32
        })
    ));
    assert_eq!(
        meter
            .usage(BudgetKind::SerializedBytes)
            .expect("serialized bytes have a usage counter")
            .0,
        0
    );
}

fn execution_budget(owned_bytes: usize) -> ExecutionBudget {
    ExecutionBudget {
        source_bytes: 64,
        external_documents: 0,
        recursion_depth: 1,
        xpath_evaluations: 0,
        xpath_operations: 0,
        extension_operations: 0,
        pattern_evaluations: 0,
        template_applications: 0,
        sort_comparisons: 0,
        key_entries: 0,
        result_nodes: 0,
        serialized_bytes: 0,
        messages: 0,
        owned_bytes,
    }
}

#[test]
fn meter_rejects_initial_source_ownership_above_its_limit() {
    assert!(Meter::new(execution_budget(8), 8).is_ok());
    assert!(matches!(
        Meter::new(execution_budget(7), 8),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: 7,
            actual: 8,
        })
    ));
}

#[test]
fn failed_vec_replacement_shortfall_rolls_back_accounting() {
    // An allocator may grant more capacity than Vec::try_reserve_exact requests. Rejecting
    // that temporary replacement must restore the meter before the replacement is dropped.
    let mut meter = Meter::new(execution_budget(10), 0).expect("meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, 8)
        .expect("requested growth fits");
    assert!(matches!(
        reconcile_replacement_growth(&mut meter, 8, 12),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: 10,
            actual: 12,
        })
    ));
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available"),
        (0, 10)
    );
    meter
        .charge(BudgetKind::OwnedBytes, 10)
        .expect("failed replacement leaves the original allowance available");
}

#[test]
fn overflowing_replacement_shortfall_releases_the_provisional_charge() {
    // check_additional saturates at usize::MAX, while charge detects the arithmetic overflow.
    // The replacement's provisional reservation must still be released on that error path.
    let mut meter = Meter::new(execution_budget(usize::MAX), 0).expect("meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, usize::MAX - 2)
        .expect("baseline fits");
    meter
        .charge(BudgetKind::OwnedBytes, 1)
        .expect("provisional replacement charge fits");

    assert!(matches!(
        reconcile_replacement_growth(&mut meter, 1, 3),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: usize::MAX,
            actual: usize::MAX,
        })
    ));
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available"),
        (usize::MAX - 2, usize::MAX)
    );
}

#[test]
fn metered_string_growth_fails_before_replacing_the_live_buffer() {
    let mut value = String::with_capacity(8);
    value.push_str("12345678");
    let original_capacity = value.capacity();
    let mut meter =
        Meter::new(execution_budget(original_capacity + 4), 0).expect("meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, original_capacity)
        .expect("existing allocation is retained");

    assert!(matches!(
        append_metered_string(&mut value, "5678", &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(value, "12345678");
    assert_eq!(value.capacity(), original_capacity);
}

#[test]
fn overflowing_owned_charge_leaves_the_meter_fail_closed() {
    let mut meter = Meter::new(execution_budget(usize::MAX), 1).expect("meter initializes");

    assert!(matches!(
        meter.charge(BudgetKind::OwnedBytes, usize::MAX),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: usize::MAX,
            actual: usize::MAX,
        })
    ));
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available"),
        (usize::MAX, usize::MAX)
    );
    assert!(meter.charge(BudgetKind::OwnedBytes, 1).is_err());
}
