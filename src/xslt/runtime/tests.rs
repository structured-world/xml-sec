use std::cmp::Ordering;
use std::sync::Arc;

use super::{
    ApplyFrame, AttributeSetExpansion, EvaluatedParameters, SortKey, SourceNode, TemplateTask,
    append_localized_decimal, apply_source_whitespace_rules, clone_allocation_free_variable_value,
    format_number_sequence, metered_node_id_snapshot, select_attribute_set_declarations,
    validate_parameter_value, value_string,
};
use crate::budget::Meter;
use crate::compiler::{AttributeSet, Instruction};
use crate::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExpandedName,
    NoResolver, NodeId, NodeKind, NodeReference, Value,
};

#[test]
fn terminating_message_prefix_accounts_for_peak_string_capacity() {
    // The old check covered only prefix length; insert_str then allocated a second buffer
    // while the original serialized message was still charged and live.
    let mut content = String::with_capacity(4096);
    content.extend(std::iter::repeat_n('x', 4096));
    let mut constrained = meter(content.capacity() * 2 - 1);
    constrained
        .charge(BudgetKind::OwnedBytes, content.capacity())
        .expect("serialized message fits");
    assert!(matches!(
        super::terminating_message_error(content, &mut constrained),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));

    let mut content = String::with_capacity(4096);
    content.extend(std::iter::repeat_n('x', 4096));
    let mut sufficient = meter(content.capacity() * 3);
    sufficient
        .charge(BudgetKind::OwnedBytes, content.capacity())
        .expect("serialized message fits");
    assert!(matches!(
        super::terminating_message_error(content, &mut sufficient),
        Ok(Error::Dynamic(message)) if message.starts_with("xsl:message terminated transformation: ")
    ));
}

#[test]
fn variable_scope_retains_its_hash_storage_charge() {
    // Scope payload accounting must include the backing table until the scope is dropped.
    let mut scope = super::VariableScope::default();
    let mut meter = meter(usize::MAX);
    let name = ExpandedName::new(None::<String>, "value");
    scope
        .insert_retained(
            &name,
            super::RetainedValue {
                value: Value::Boolean(true),
                retained_owned_bytes: 0,
            },
            &mut meter,
        )
        .expect("scope insertion remains within budget");
    let index_bytes =
        crate::budget::retained_hash_storage::<(ExpandedName, Value)>(scope.values.capacity());

    assert!(index_bytes > 0);
    assert_eq!(scope.retained_owned_bytes, index_bytes);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        index_bytes
    );
    scope.release(&mut meter);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        0
    );
}

#[test]
fn saved_variable_scopes_are_metered_before_detach_and_released_on_restore() {
    let scope_bytes = std::mem::size_of::<super::VariableScope>();
    let mut scopes = Vec::new();
    let mut reserved = 0;
    let mut constrained = meter(scope_bytes * 6 - 1);
    crate::budget::reserve_temporary_vec_slot(&mut scopes, &mut constrained, &mut reserved)
        .expect("active scope vector fits");
    scopes.extend((0..3).map(|_| super::VariableScope::default()));
    assert!(matches!(
        super::save_local_scopes(&mut scopes, &mut constrained),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(scopes.len(), 3, "rejection leaves all scopes live");

    let mut sufficient = meter(scope_bytes * 16);
    let mut scopes = Vec::new();
    let mut reserved = 0;
    crate::budget::reserve_temporary_vec_slot(&mut scopes, &mut sufficient, &mut reserved)
        .expect("active scope vector fits");
    scopes.extend((0..3).map(|_| super::VariableScope::default()));
    let before = sufficient.remaining_owned_bytes();
    let saved = super::save_local_scopes(&mut scopes, &mut sufficient).expect("saved scopes fit");
    assert_eq!(scopes.len(), 1);
    assert!(sufficient.remaining_owned_bytes() < before);
    super::restore_local_scopes(&mut scopes, saved, &mut sufficient);
    assert_eq!(scopes.len(), 3);
    assert_eq!(sufficient.remaining_owned_bytes(), before);
}

#[test]
fn evaluated_parameters_retain_their_hash_storage_charge() {
    // Staged with-param values can outlive this frame through template-task Arcs, so their
    // backing table must remain charged until the last owner releases the parameter set.
    let mut parameters = EvaluatedParameters::default();
    let mut unlimited_meter = meter(usize::MAX);
    let name = ExpandedName::new(None::<String>, "value");
    let payload_bytes = super::expanded_name_owned_bytes(&name);
    unlimited_meter
        .charge(BudgetKind::OwnedBytes, payload_bytes)
        .expect("parameter payload fits the test budget");
    parameters
        .insert_retained(
            &name,
            super::RetainedValue {
                value: Value::Boolean(true),
                retained_owned_bytes: payload_bytes,
            },
            &mut unlimited_meter,
        )
        .expect("parameter table fits the test budget");
    let index_bytes =
        crate::budget::retained_hash_storage::<(ExpandedName, Value)>(parameters.values.capacity());

    assert!(index_bytes > 0);
    assert_eq!(parameters.retained_owned_bytes, payload_bytes + index_bytes);
    assert_eq!(
        unlimited_meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        payload_bytes + index_bytes
    );
    parameters.release(&mut unlimited_meter);
    assert_eq!(
        unlimited_meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        0
    );

    let mut constrained = meter(payload_bytes);
    constrained
        .charge(BudgetKind::OwnedBytes, payload_bytes)
        .expect("parameter payload alone fits the constrained budget");
    let mut rejected = EvaluatedParameters::default();
    assert!(matches!(
        rejected.insert_retained(
            &name,
            super::RetainedValue {
                value: Value::Boolean(true),
                retained_owned_bytes: payload_bytes,
            },
            &mut constrained,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert!(rejected.values.is_empty());
    assert_eq!(rejected.values.capacity(), 0);
    assert_eq!(
        constrained
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        0
    );
}

#[test]
fn attribute_set_selection_reserves_pointer_storage_before_growth() {
    let name = ExpandedName::new(None::<String>, "attrs");
    let declarations = (0..256)
        .map(|order| AttributeSet {
            name: name.clone(),
            uses: Vec::new(),
            attributes: Vec::new().into(),
            precedence: 0,
            order,
        })
        .collect::<Vec<_>>();
    let required = declarations
        .len()
        .saturating_mul(std::mem::size_of::<&AttributeSet>());
    let peak_growth = required.saturating_add(required / 2);
    let mut insufficient = meter(peak_growth - 1);

    assert!(matches!(
        select_attribute_set_declarations(&declarations, &name, &mut insufficient),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(
        insufficient
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        0
    );

    let mut exact = meter(peak_growth);
    let (selected, reserved) = select_attribute_set_declarations(&declarations, &name, &mut exact)
        .expect("exact pointer-storage budget fits");
    assert_eq!(selected.len(), declarations.len());
    assert_eq!(reserved, required);
}

#[test]
fn remapped_parameter_accounting_matches_retained_capacity() {
    // Remapping must reserve the exact backing allocation before it is retained by a scope;
    // logical node count alone cannot account for an implicitly grown Vec.
    let source = NodeId::test(1);
    let target = NodeId::test(2);
    let value = Value::NodeSet(vec![NodeReference::Node(source)]);
    let remap = std::collections::HashMap::from([(source, target)]);

    let mut unlimited_meter = meter(usize::MAX);
    let remapped = super::clone_parameter_value(&value, Some(&remap), &mut unlimited_meter)
        .expect("remapping fits the test budget");
    let Value::NodeSet(nodes) = &remapped.value else {
        unreachable!("node-set remapping preserves the value kind")
    };
    assert_eq!(
        super::parameter_value_owned_bytes(&value, Some(&remap)),
        nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<NodeReference>())
    );
    assert_eq!(
        remapped.retained_owned_bytes,
        unlimited_meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0
    );

    let required = super::parameter_value_owned_bytes(&value, Some(&remap));
    let mut constrained = meter(required - 1);
    assert!(matches!(
        super::clone_parameter_value(&value, Some(&remap), &mut constrained),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(
        constrained
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        0
    );
}

#[test]
fn exslt_call_stack_meters_capacity_and_active_default_names() {
    // Unwinding releases active frame payloads, but not live reusable vector allocations.
    let mut calls = super::ExsltCallStack::default();
    let mut meter = meter(usize::MAX);
    let names = (0..32)
        .map(|index| {
            ExpandedName::new(
                Some("urn:functions"),
                format!("function_{index}_{}", "x".repeat(128)),
            )
        })
        .collect::<Vec<_>>();
    let names_owned_bytes = names
        .iter()
        .map(super::expanded_name_owned_bytes)
        .sum::<usize>();

    for name in &names {
        calls
            .enter(Some(name), &mut meter)
            .expect("call-stack entry remains within budget");
    }
    let active_owned_bytes = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    assert!(active_owned_bytes > names_owned_bytes);

    for _ in &names {
        assert_eq!(calls.leave(true, &mut meter), None);
    }
    let retained_capacity_bytes = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    assert_eq!(
        active_owned_bytes - retained_capacity_bytes,
        names_owned_bytes,
        "unwinding releases names but not still-allocated vector capacity"
    );
}

#[test]
fn variable_snapshot_borrows_only_visible_bindings() {
    // Shadowed values must not be cloned temporarily: reservation and construction
    // need exactly the same bindings, regardless of hidden payload size.
    let name = ExpandedName::new(None::<String>, "value");
    let scopes = [
        super::VariableScope {
            values: std::collections::HashMap::from([(
                name.clone(),
                Value::String("x".repeat(100_000)),
            )]),
            retained_owned_bytes: 0,
        },
        super::VariableScope {
            values: std::collections::HashMap::from([(
                name.clone(),
                Value::String("visible".into()),
            )]),
            retained_owned_bytes: 0,
        },
    ];
    let bindings: Vec<_> = super::visible_variable_bindings(&scopes).collect();
    assert_eq!(bindings.len(), 1);
    assert!(std::ptr::eq(
        bindings[0].1,
        scopes[1].get(&name).expect("inner binding exists")
    ));
    let (count, bytes) = super::visible_variable_snapshot_size(&scopes);
    assert_eq!(count, 1);
    assert!(
        bytes < 1000,
        "hidden payload must not be reserved or copied"
    );
}

#[test]
fn xsl_copy_does_not_charge_shared_namespace_storage_twice() {
    let kind = NodeKind::Element {
        name: ExpandedName::new(Some("urn:element"), "item"),
        prefix: Some("p".into()),
        attributes: Vec::new(),
        namespaces: Arc::new(vec![crate::Namespace {
            prefix: Some("large".into()),
            uri: format!("urn:{}", "x".repeat(4096)),
        }]),
    };
    let unique_bytes = match &kind {
        NodeKind::Element { name, prefix, .. } => super::expanded_name_owned_bytes(name)
            .saturating_add(prefix.as_ref().map_or(0, String::len)),
        _ => unreachable!(),
    };

    super::clone_for_xsl_copy(&kind, &meter(unique_bytes))
        .expect("Arc namespace storage remains shared by xsl:copy");
}

#[test]
fn namespace_copy_on_write_crosses_budget_before_cloning() {
    let retained = Arc::new(vec![crate::Namespace {
        prefix: Some("p".into()),
        uri: "urn:namespace".into(),
    }]);
    let required = std::mem::size_of::<crate::Namespace>()
        + retained[0].prefix.as_deref().map_or(0, str::len)
        + retained[0].uri.len();
    let mut shared = Arc::clone(&retained);
    assert!(matches!(
        super::make_namespaces_mut_metered(&mut shared, &mut meter(required - 1)),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert!(Arc::ptr_eq(&shared, &retained));

    super::make_namespaces_mut_metered(&mut shared, &mut meter(required))
        .expect("an exact COW reservation permits the namespace clone");
    assert!(!Arc::ptr_eq(&shared, &retained));
}

#[test]
fn global_initialization_stack_and_cycle_diagnostic_are_metered() {
    let first = ExpandedName::new(None::<String>, "first");
    let second = ExpandedName::new(None::<String>, "second");
    let mut active = Vec::new();
    let mut reservation = 0;
    assert!(matches!(
        super::push_initializing_global(&mut active, &first, &mut meter(0), &mut reservation,),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert!(
        active.is_empty(),
        "failed reservation cannot mutate the stack"
    );

    let active = [&first, &second];
    assert!(matches!(
        super::circular_global_dependency_error(&active, &first, &mut meter(1)),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

fn meter(owned_bytes: usize) -> Meter {
    meter_with_xpath_operations(owned_bytes, usize::MAX)
}

fn meter_with_xpath_operations(owned_bytes: usize, xpath_operations: usize) -> Meter {
    Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            xpath_operations,
            extension_operations: usize::MAX,
            pattern_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes,
        },
        0,
    )
    .expect("empty source fits")
}

fn minimum_execution_owned_bytes(stylesheet: &crate::Stylesheet, source: &Document) -> usize {
    let mut rejected = 0usize;
    let mut accepted = 1usize << 20;
    while rejected + 1 < accepted {
        let candidate = rejected + (accepted - rejected) / 2;
        let budget = ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            xpath_operations: usize::MAX,
            extension_operations: usize::MAX,
            pattern_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: candidate,
        };
        match stylesheet.execute(
            source,
            &crate::Parameters::new(),
            Arc::new(NoResolver),
            crate::ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ) {
            Ok(_) => accepted = candidate,
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            }) => rejected = candidate,
            Err(error) => panic!("unexpected execution error: {error}"),
        }
    }
    accepted
}

#[test]
fn appended_text_accounts_for_retained_capacity() {
    // One extra byte can double String capacity. Both ordinary and already-reserved
    // append paths must retain that capacity charge, not only the logical text length.
    for precharged in [false, true] {
        let mut document = Document::parse("<r>12345678</r>", None).expect("fixture parses");
        let parent = document
            .node(document.root())
            .expect("document root exists")
            .children[0];
        let text = document.node(parent).expect("element exists").children[0];
        let NodeKind::Text { value, .. } = &document.node(text).expect("text exists").kind else {
            panic!("text")
        };
        let mut meter = meter(1000);
        meter
            .charge(BudgetKind::OwnedBytes, value.capacity())
            .expect("initial text fits");
        if precharged {
            meter
                .charge(BudgetKind::OwnedBytes, 1)
                .expect("suffix fits");
            super::append_precharged_result_text(
                &mut document,
                &mut meter,
                parent,
                "x".into(),
                1,
                false,
            )
            .expect("precharged append fits");
        } else {
            super::append_result_text(
                &mut document,
                &mut meter,
                parent,
                std::borrow::Cow::Borrowed("x"),
                false,
            )
            .expect("ordinary append fits");
        }
        let NodeKind::Text { value, .. } = &document.node(text).expect("text remains").kind else {
            panic!("text")
        };
        assert_eq!(value, "12345678x");
        assert_eq!(
            meter
                .usage(BudgetKind::OwnedBytes)
                .expect("owned bytes are metered")
                .0,
            value.capacity()
        );
    }
}

#[test]
fn logical_root_snapshot_reserves_before_allocation_and_releases_on_failure() {
    // key() snapshots every logical document before mutating key indexes. The temporary node
    // vector must cross OwnedBytes before its first allocation and unwind a partial reserve.
    let nodes = (0..5).map(crate::NodeId::test).collect::<Vec<_>>();
    let first_allocation = 4 * std::mem::size_of::<crate::NodeId>();
    let mut rejected = meter(first_allocation - 1);

    assert!(matches!(
        metered_node_id_snapshot(&nodes, &mut rejected),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(
        rejected
            .usage(BudgetKind::OwnedBytes)
            .expect("usage is available")
            .0,
        0
    );
}

#[test]
fn attribute_set_recursion_stack_borrows_names_and_meters_only_pointer_storage() {
    // Attribute-set names belong to the immutable stylesheet. Recursion tracking borrows them
    // and reserves its pointer stack before growth instead of cloning attacker-sized strings.
    let names = (0..5)
        .map(|index| ExpandedName::new(None::<String>, format!("{index}{}", "x".repeat(4096))))
        .collect::<Vec<_>>();
    let first_allocation = 4 * std::mem::size_of::<&ExpandedName>();
    let mut meter = meter(first_allocation);
    let mut expansion = AttributeSetExpansion::new(&[]);
    for name in &names[..4] {
        expansion
            .push(name, &mut meter)
            .expect("four borrowed names fit the first stack allocation");
    }
    assert_eq!(expansion.reserved_owned_bytes, first_allocation);
    assert!(matches!(
        expansion.push(&names[4], &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    meter.release_owned_bytes(expansion.reserved_owned_bytes);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("usage is available")
            .0,
        0
    );
}

#[test]
fn avt_nodeset_conversion_reserves_both_live_copies() {
    // XPath node-set conversion and the growing AVT output coexist until the converted value
    // is appended, so the owned-byte gate must cover both allocations before conversion.
    let compile = |attribute: &str| {
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(
            &format!(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{attribute}"/></xsl:template></xsl:stylesheet>"#),
            None,
        )
        .expect("stylesheet compiles")
    };
    let literal = compile("");
    let avt = compile("{/root}");
    let minimum_delta = |payload_bytes: usize| {
        let payload = "x".repeat(payload_bytes);
        let source =
            Document::parse(&format!("<root>{payload}</root>"), None).expect("source parses");
        minimum_execution_owned_bytes(&avt, &source)
            .saturating_sub(minimum_execution_owned_bytes(&literal, &source))
    };
    // Keep both probes above the bounded XPath-context baseline so this assertion measures
    // the payload-dependent slope rather than the fixed context setup cost.
    let small_payload_bytes = 32 * 1_024;
    let large_payload_bytes = 128 * 1_024;
    let small_delta = minimum_delta(small_payload_bytes);
    let large_delta = minimum_delta(large_payload_bytes);
    // Compare the marginal slope because the two execution paths have different fixed-size
    // task layouts and allocator buckets. A slope near 2 still proves both payload-sized
    // allocations are live; one missing charge would cap it near 1.
    assert!(
        large_delta.saturating_sub(small_delta) * 10
            >= large_payload_bytes
                .saturating_sub(small_payload_bytes)
                .saturating_mul(19),
        "small_delta={small_delta}, large_delta={large_delta}"
    );
}

#[test]
fn compiled_nested_instruction_sequences_are_shared() {
    // Execution tasks may retain a reached sequence, but must never recursively copy its
    // instruction subtree. A large unreachable branch then costs no execution-time storage.
    let payload = "x".repeat(64 * 1024);
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 32, 2 << 20),
    )
    .compile(
        &format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="false()"><xsl:text>{payload}</xsl:text></xsl:if></xsl:template></xsl:stylesheet>"#
        ),
        None,
    )
    .expect("stylesheet compiles");
    let instruction = &stylesheet.templates[0].body[0];
    let Instruction::If { body, .. } = instruction else {
        panic!("compiled instruction is xsl:if");
    };
    let cloned = instruction.clone();
    let Instruction::If {
        body: cloned_body, ..
    } = cloned
    else {
        panic!("cloned instruction remains xsl:if");
    };

    assert!(Arc::ptr_eq(body, &cloned_body));
}

#[test]
fn template_dispatch_shares_only_execution_metadata() {
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 32, 2 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:unused="urn:large-matching-metadata"><xsl:template match="/"><xsl:param name="value"/><out/></xsl:template></xsl:stylesheet>"#,
        None,
    )
    .expect("stylesheet compiles");
    let template = &stylesheet.templates[0];
    let task = TemplateTask::enter_template(
        template,
        Arc::new(EvaluatedParameters::default()),
        SourceNode::Node(crate::NodeId::test(0)),
        ApplyFrame::new(1, 1, 1),
        Some(template.precedence),
    );
    let TemplateTask::EnterTemplate { program, .. } = task else {
        panic!("template dispatch creates an entry task");
    };

    assert!(Arc::ptr_eq(&program.parameters, &template.params));
    assert!(Arc::ptr_eq(&program.body, &template.body));
}

#[test]
fn new_result_attributes_consume_result_node_budget() {
    // XPath 1.0 section 5.2 models attributes as nodes, so the result-node ceiling must count
    // a newly inserted expanded name while allowing replacement of that same node.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#attribute-nodes
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><root><xsl:attribute name="a"/><xsl:attribute name="a"/><xsl:attribute name="b"/></root></xsl:template></xsl:stylesheet>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source = Document::parse("<source/>", None).expect("source parses");
    let budget = ExecutionBudget {
        source_bytes: usize::MAX,
        external_documents: usize::MAX,
        recursion_depth: usize::MAX,
        xpath_evaluations: usize::MAX,
        xpath_operations: usize::MAX,
        extension_operations: usize::MAX,
        pattern_evaluations: usize::MAX,
        template_applications: usize::MAX,
        sort_comparisons: usize::MAX,
        key_entries: usize::MAX,
        result_nodes: 2,
        serialized_bytes: usize::MAX,
        messages: usize::MAX,
        owned_bytes: usize::MAX,
    };
    let error = stylesheet
        .execute(
            &source,
            &crate::Parameters::new(),
            Arc::new(NoResolver),
            crate::ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("one element plus two unique attributes exceed two result nodes");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::ResultNodes,
            limit: 2,
            actual: 3,
        }
    ));
}

#[test]
fn direct_variable_fast_path_never_clones_owned_payloads() {
    assert!(clone_allocation_free_variable_value(&Value::Boolean(true)).is_some());
    assert!(clone_allocation_free_variable_value(&Value::Number(1.0)).is_some());
    assert!(clone_allocation_free_variable_value(&Value::String("payload".into())).is_none());
    assert!(
        clone_allocation_free_variable_value(&Value::NodeSet(vec![NodeReference::Node(
            crate::NodeId::test(0),
        )]))
        .is_none()
    );
}

#[test]
fn avt_string_and_output_share_peak_owned_byte_budget() {
    // The evaluated string remains live while the AVT output grows.
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source = Document::parse("<root/>", None).expect("source parses");
    let mut setup_meter = meter(usize::MAX);
    let source_options = super::EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared =
        super::prepare_evaluator_source(&source, &NoResolver, &mut setup_meter, &source_options)
            .expect("source prepares");
    let execution = super::Execution::new(
        &stylesheet,
        prepared,
        &super::Parameters::new(),
        super::PreparedParameters {
            effective_globals: std::collections::HashMap::new(),
            source_remap: super::SourceParameterRemap {
                mapping: None,
                owned_bytes: 0,
            },
        },
        crate::ExecutionEnvironment::new(Arc::new(NoResolver)),
        setup_meter,
        source_options,
    )
    .expect("execution initializes");
    let value = "x".repeat(4096);
    let mut output = super::MeteredString::new();
    let mut constrained = meter(value.capacity());

    assert!(matches!(
        super::append_avt_expression_value(
            &mut output,
            super::XPathValue::String(value),
            &execution.evaluator,
            &mut constrained,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert!(output.is_empty());

    let value = "x".repeat(4096);
    let mut sufficient = meter(value.capacity() * 2);
    super::append_avt_expression_value(
        &mut output,
        super::XPathValue::String(value),
        &execution.evaluator,
        &mut sufficient,
    )
    .expect("budget for both live strings succeeds");
    assert_eq!(output.len(), 4096);
}

#[test]
fn apply_one_mode_clone_consumes_owned_byte_budget() {
    // A long mode survives in the task while its template is selected.
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source = Document::parse("<root/>", None).expect("source parses");
    let mut setup_meter = meter(usize::MAX);
    let source_options = super::EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared =
        super::prepare_evaluator_source(&source, &NoResolver, &mut setup_meter, &source_options)
            .expect("source prepares");
    let mut execution = super::Execution::new(
        &stylesheet,
        prepared,
        &super::Parameters::new(),
        super::PreparedParameters {
            effective_globals: std::collections::HashMap::new(),
            source_remap: super::SourceParameterRemap {
                mapping: None,
                owned_bytes: 0,
            },
        },
        crate::ExecutionEnvironment::new(Arc::new(NoResolver)),
        setup_meter,
        source_options,
    )
    .expect("execution initializes");
    let mode = ExpandedName::new(Some("urn:mode"), "m".repeat(4096));
    let task_capacity = 4 * std::mem::size_of::<super::TemplateTask>();
    execution.meter = meter(task_capacity + 128);
    let owner = execution.evaluator.source.logical_roots()[0];

    assert!(matches!(
        execution.apply_one(
            NodeReference::Namespace { owner, index: 0 },
            Some(&mode),
            Arc::new(super::EvaluatedParameters::default()),
            ApplyFrame::new(1, 1, 0),
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn output_parent_stack_charges_capacity_growth() {
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source = Document::parse("<root/>", None).expect("source parses");
    let source_options = super::EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared = super::prepare_evaluator_source(
        &source,
        &NoResolver,
        &mut meter(usize::MAX),
        &source_options,
    )
    .expect("source prepares");
    let mut execution = super::Execution::new(
        &stylesheet,
        prepared,
        &super::Parameters::new(),
        super::PreparedParameters {
            effective_globals: std::collections::HashMap::new(),
            source_remap: super::SourceParameterRemap {
                mapping: None,
                owned_bytes: 0,
            },
        },
        crate::ExecutionEnvironment::new(Arc::new(NoResolver)),
        meter(usize::MAX),
        source_options,
    )
    .expect("execution initializes");
    let old_capacity = execution.output_stack.capacity();
    let before = execution
        .meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    let root = execution.result.root();
    while execution.output_stack.capacity() == old_capacity {
        execution.push_output_node(root).expect("stack fits");
    }
    let new_capacity = execution.output_stack.capacity();
    let after = execution
        .meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    assert_eq!(
        after - before,
        (new_capacity - old_capacity) * std::mem::size_of::<NodeId>()
    );

    let previous = execution
        .enter_result_tree(None, true)
        .expect("temporary tree fits");
    let temporary_charge = super::metered_document_owned_bytes(&execution.result)
        + execution.output_stack_reserved_owned_bytes;
    assert_eq!(
        execution
            .meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0
            - after,
        temporary_charge
    );
    let temporary = execution.restore_result_tree(previous);
    execution
        .meter
        .release_owned_bytes(super::metered_document_owned_bytes(&temporary));
    assert_eq!(
        execution
            .meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        after
    );
}

#[test]
fn sibling_and_comment_fast_paths_charge_traversal() {
    // Reset only the work meter after setup, isolating execution from projection cost.
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source = Document::parse("<root><a><nested>payload</nested></a><a/></root>", None)
        .expect("source parses");
    let mut initial_meter = meter(usize::MAX);
    let source_options = super::EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared =
        super::prepare_evaluator_source(&source, &NoResolver, &mut initial_meter, &source_options)
            .expect("source prepares");
    let mut execution = super::Execution::new(
        &stylesheet,
        prepared,
        &super::Parameters::new(),
        super::PreparedParameters {
            effective_globals: std::collections::HashMap::new(),
            source_remap: super::SourceParameterRemap {
                mapping: None,
                owned_bytes: 0,
            },
        },
        crate::ExecutionEnvironment::new(Arc::new(NoResolver)),
        initial_meter,
        source_options,
    )
    .expect("execution initializes");
    let root = execution.evaluator.source.logical_roots()[0];
    let element = execution
        .evaluator
        .source
        .node(root)
        .expect("logical root")
        .children[0];
    let last = *execution
        .evaluator
        .source
        .node(element)
        .expect("element")
        .children
        .last()
        .expect("last child");
    let target = super::SourceNode::Node(last);
    let budget = ExecutionBudget {
        source_bytes: usize::MAX,
        external_documents: usize::MAX,
        recursion_depth: usize::MAX,
        xpath_evaluations: usize::MAX,
        xpath_operations: 1,
        extension_operations: usize::MAX,
        pattern_evaluations: usize::MAX,
        template_applications: usize::MAX,
        sort_comparisons: usize::MAX,
        key_entries: usize::MAX,
        result_nodes: usize::MAX,
        serialized_bytes: usize::MAX,
        messages: usize::MAX,
        owned_bytes: usize::MAX,
    };
    execution.meter = Meter::new(budget, 0).expect("fresh work meter");
    assert!(matches!(
        execution.sibling_number(&target, &mut |_, _| Ok(true)),
        Err(Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        })
    ));
    execution.meter = Meter::new(budget, 0).expect("fresh work meter");
    assert!(matches!(
        execution
            .evaluator
            .preceding_nonempty_comment(&target, &mut execution.meter),
        Err(Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        })
    ));
    // Implicit count/from patterns must not bypass the work gate while level="any"
    // traverses preceding nodes, even though no XPath expression is evaluated.
    execution.meter = Meter::new(budget, 0).expect("fresh work meter");
    let instruction = crate::compiler::NumberInstruction {
        value: None,
        count: None,
        from: None,
        level: "any".into(),
        format: crate::compiler::AttributeValueTemplate(Vec::new()),
        lang: None,
        letter_value: None,
        grouping_separator: None,
        grouping_size: None,
        forward_compatible: false,
    };
    assert!(matches!(
        execution.number_sequence(&instruction, &target),
        Err(Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        })
    ));
}

#[test]
fn normalize_space_fast_path_charges_descendant_traversal() {
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="normalize-space(.)"/></xsl:template></xsl:stylesheet>"#,
        None,
    )
    .expect("stylesheet compiles");
    let source =
        Document::parse("<root><a>alpha</a><b>beta</b></root>", None).expect("source parses");
    let budget = ExecutionBudget {
        source_bytes: usize::MAX,
        external_documents: usize::MAX,
        recursion_depth: usize::MAX,
        xpath_evaluations: usize::MAX,
        xpath_operations: 1,
        extension_operations: usize::MAX,
        pattern_evaluations: usize::MAX,
        template_applications: usize::MAX,
        sort_comparisons: usize::MAX,
        key_entries: usize::MAX,
        result_nodes: usize::MAX,
        serialized_bytes: usize::MAX,
        messages: usize::MAX,
        owned_bytes: usize::MAX,
    };
    let error = stylesheet
        .execute(
            &source,
            &crate::Parameters::new(),
            Arc::new(NoResolver),
            crate::ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("descendant traversal exceeds the baseline XPath operation");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        }
    ));
}

#[test]
fn whitespace_stripping_reserves_and_releases_its_workspaces() {
    // The retained remap remains charged after in-place compaction, while the DFS and indexed
    // remap workspaces are released before transformation execution continues.
    let source_xml = format!("<root>{}</root>", "<item> </item>".repeat(2_048));
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="*"/></xsl:stylesheet>"#,
        None,
    )
    .expect("strip-space stylesheet compiles");
    let mut document = Document::parse(&source_xml, None).expect("wide source parses");
    let mut unbounded = meter(usize::MAX);
    let (remap, retained_bytes) =
        apply_source_whitespace_rules(&mut document, &stylesheet.whitespace, &mut unbounded)
            .expect("workspace fits")
            .expect("whitespace nodes are removed");
    assert_eq!(
        unbounded
            .usage(BudgetKind::OwnedBytes)
            .expect("usage is available")
            .0,
        retained_bytes
    );
    assert!(retained_bytes >= 2_048 * std::mem::size_of::<(crate::NodeId, crate::NodeId)>());
    drop(remap);
    unbounded.release_owned_bytes(retained_bytes);
    assert_eq!(
        unbounded
            .usage(BudgetKind::OwnedBytes)
            .expect("usage is available")
            .0,
        0
    );

    let mut constrained_document =
        Document::parse(&source_xml, None).expect("wide source parses again");
    let mut constrained = meter(retained_bytes - 1);
    assert!(matches!(
        apply_source_whitespace_rules(
            &mut constrained_document,
            &stylesheet.whitespace,
            &mut constrained,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn grouped_decimal_writer_checks_before_writing() {
    let mut rejected = super::MeteredString::new();
    let mut meter = meter(4096);
    let error = append_localized_decimal(
        &mut rejected,
        "1",
        4096,
        '0',
        Some(','),
        Some(1),
        &mut meter,
    )
    .expect_err("wide grouped number exceeds its allocation budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
    assert!(rejected.is_empty(), "budget rejection precedes all writes");
}

#[test]
fn number_format_tokens_remain_reserved_while_output_is_built() {
    // Token vectors and serialized output coexist; checking either allocation in isolation
    // permits their combined peak to exceed OwnedBytes.
    let format = "1.1.1.1";
    let token_workspace = 7 * std::mem::size_of::<(bool, &str)>()
        + 4 * std::mem::size_of::<&str>()
        + 3 * std::mem::size_of::<&str>();
    let mut meter = meter(token_workspace);

    assert!(matches!(
        format_number_sequence(&[1.0], format, None, None, None, None, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn number_format_output_retains_its_actual_capacity_charge() {
    // The formatter hands its allocation directly to the result tree, so the meter must
    // retain the actual String capacity rather than merely checking the logical length.
    let mut meter = meter(4096);
    let output = format_number_sequence(
        &[1.0, 2.0, 3.0, 4.0],
        "1.1.1.1",
        None,
        None,
        None,
        None,
        &mut meter,
    )
    .expect("number sequence fits");
    let charged = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage exists")
        .0;

    assert_eq!(charged, output.retained_owned_bytes);
}

#[test]
fn text_sort_key_reserves_its_exact_retained_payload() {
    // The underscore sentinel expands from one to four UTF-8 bytes, so the pre-allocation
    // accounting must use the produced collation key rather than the source byte length.
    let value = "A_".to_owned();
    let mut rejected = meter(value.len() + 4);
    rejected
        .charge(BudgetKind::OwnedBytes, value.len())
        .expect("source value fits");
    assert!(matches!(
        SortKey::text_precharged(value.clone(), value.len(), &mut rejected),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    let mut accepted = meter(value.len() + 5);
    accepted
        .charge(BudgetKind::OwnedBytes, value.len())
        .expect("source value fits");
    SortKey::text_precharged(value.clone(), value.len(), &mut accepted)
        .expect("the exact retained sort-key payload fits");
}

#[test]
fn text_sort_key_construction_obeys_xpath_work_budget() {
    // Default collation computes the lowercased key in two complete passes. Both passes must
    // cross the work gate before scanning a caller-controlled sort value.
    let value = "A_".repeat(1_024);
    let mut meter = meter_with_xpath_operations(value.len() * 3, value.len());
    meter
        .charge(BudgetKind::OwnedBytes, value.len())
        .expect("source value fits");

    assert!(matches!(
        SortKey::text_precharged(value.clone(), value.len(), &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        })
    ));
}

#[test]
fn avt_buffer_retains_and_releases_its_capacity_charge() {
    // Every AVT part is evaluated while the prefix buffer remains live. Its actual capacity
    // must stay charged until ownership is explicitly transferred to the consumer.
    let mut meter = meter(16);
    let mut output = super::MeteredString::new();
    output
        .push_str("12345678", &mut meter)
        .expect("prefix fits");
    assert!(matches!(
        meter.charge(BudgetKind::OwnedBytes, 9),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));

    assert_eq!(output.transfer(&mut meter), "12345678");
    meter
        .charge(BudgetKind::OwnedBytes, 16)
        .expect("consuming the AVT releases its complete capacity");
}

#[test]
fn text_sort_key_resolves_internal_sentinel_collisions_without_allocation() {
    let mut left_meter = meter(64);
    left_meter
        .charge(BudgetKind::OwnedBytes, 1)
        .expect("source value fits");
    let left = SortKey::text_precharged("_".into(), 1, &mut left_meter).expect("left key fits");
    let right_value = char::MAX.to_string();
    let mut right_meter = meter(64);
    right_meter
        .charge(BudgetKind::OwnedBytes, right_value.len())
        .expect("source value fits");
    let right = SortKey::text_precharged(right_value.clone(), right_value.len(), &mut right_meter)
        .expect("right key fits");
    let mut comparison_meter = meter(0);
    assert_eq!(
        left.compare(&right, Some("lower-first"), None, &mut comparison_meter,)
            .expect("comparison work fits"),
        Ordering::Less
    );
}

#[test]
fn value_string_preflights_owned_projection_but_borrows_existing_strings() {
    let payload = "x".repeat(4096);
    let fragment = Value::ResultTreeFragment(Arc::new(
        Document::parse(&format!("<fragment>{payload}</fragment>"), None).expect("fragment parses"),
    ));
    let source = Document::parse("<source/>", None).expect("source parses");
    assert!(matches!(
        value_string(&fragment, &source, &meter(payload.len() - 1), 0),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));

    let retained = Value::String(payload);
    let borrowed = value_string(&retained, &source, &meter(0), 0)
        .expect("an existing string needs no projection allocation");
    assert!(matches!(borrowed, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn parameter_validation_rejects_stale_and_out_of_range_members() {
    let mut source =
        Document::parse("<root id=\"value\"><removed/></root>", None).expect("source parses");
    let root = source
        .nodes()
        .find_map(|(id, node)| matches!(node.kind, NodeKind::Element { .. }).then_some(id))
        .expect("root exists");
    let removed = source
        .nodes()
        .find_map(|(id, node)| {
            matches!(node.kind, NodeKind::Element { ref name, .. } if name.local == "removed")
                .then_some(id)
        })
        .expect("removed node exists");

    assert!(
        validate_parameter_value(
            &Value::NodeSet(vec![NodeReference::Attribute {
                owner: root,
                index: usize::MAX,
            }]),
            &source,
        )
        .is_err()
    );

    let mut operation_meter = meter(usize::MAX);
    source
        .retain_nodes(&mut operation_meter, |_, id, _| id != removed)
        .expect("source compacts");
    assert!(
        validate_parameter_value(&Value::NodeSet(vec![NodeReference::Node(removed)]), &source,)
            .is_err()
    );
}

#[test]
fn retained_attributes_charge_allocated_string_capacities() {
    // AVT construction may leave spare capacity in every retained string. Accounting the
    // logical lengths would let repeated attributes retain more memory than OwnedBytes.
    let mut local = String::with_capacity(64);
    local.push('n');
    let mut namespace = String::with_capacity(128);
    namespace.push('u');
    let mut prefix = String::with_capacity(32);
    prefix.push('p');
    let mut value = String::with_capacity(256);
    value.push('v');
    let attribute = crate::Attribute {
        name: ExpandedName::new(Some(namespace), local),
        prefix: Some(prefix),
        value,
    };

    assert_eq!(
        super::attribute_owned_bytes(&attribute),
        64 + 128 + 32 + 256
    );
}
