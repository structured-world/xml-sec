fn owned_byte_budget(owned_bytes: usize) -> ExecutionBudget {
    ExecutionBudget {
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
        owned_bytes,
    }
}

#[test]
fn xinclude_line_normalization_replaces_accounted_storage() {
    let mut text = String::with_capacity(8);
    text.push_str("a\r\nb");
    let old_capacity = text.capacity();
    let mut value = MeteredDecodedResource {
        value: text,
        temporary_bytes: old_capacity,
    };
    let mut meter =
        Meter::new(owned_byte_budget(old_capacity + 4), 0).expect("empty meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, old_capacity)
        .expect("decoded text is already accounted");

    normalize_xinclude_text_line_endings(&mut value, &mut meter)
        .expect("replacement fits its provisional allocation");

    assert_eq!(value.value, "a\nb");
    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        value.value.capacity(),
        "the dropped source buffer must leave the live-memory budget"
    );
}

#[test]
fn generated_id_result_crosses_the_allocation_gate_before_formatting() {
    // The cached identity itself requires no new storage here, leaving only the rendered
    // generate-id() result to exercise the XPath result-allocation gate.
    let package = Package::new();
    let document = package.as_document();
    let root = document.root();
    let path = typed_path_to(&nodeset::Node::Root(root));
    let identity = GeneratedNodeIdentity {
        document: document.identity(),
        path,
    };
    let mut assigned = HashMap::new();
    assigned.insert(identity, 1);
    let function = GenerateId {
        assigned: Rc::new(RefCell::new(GeneratedIdCache {
            assigned,
            owned_bytes: 0,
        })),
    };
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);
    let mut context = Context::new();
    context.set_string_allocation_limit(2);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, root.into());

    let error = function
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("generated ID must cross the two-byte gate");

    assert!(error.to_string().contains("allocation budget"));
    assert_eq!(context.string_allocation_exceeded(), Some(3));
}

#[test]
fn generated_id_table_growth_charges_peak_live_storage() {
    // Replaced hash tables die after each growth. A live-memory gate must retain the current
    // table, not accumulate every superseded table from the evaluation.
    const ENTRIES: usize = 64;
    let package = Package::new();
    let document = package.as_document();
    let unlimited = Context::new();
    let probe_evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&unlimited, document.root().into());
    let probe = RefCell::new(GeneratedIdCache::default());
    let mut entry_bytes = 0usize;
    let mut peak_live_bytes = 0usize;

    for index in 0..ENTRIES {
        let path = NodePath::Ordinary(vec![index]);
        let identity = GeneratedNodeIdentity {
            document: document.identity(),
            path,
        };
        let new_entry_bytes = identity
            .path
            .owned_bytes()
            .saturating_add(std::mem::size_of::<(GeneratedNodeIdentity, usize)>());
        let old_capacity = probe.borrow().assigned.capacity();
        assign_generated_id(&probe_evaluation, &probe, identity)
            .expect("probe generated ID is assigned");
        entry_bytes = entry_bytes.saturating_add(new_entry_bytes);
        let new_capacity = probe.borrow().assigned.capacity();
        let live_bytes = if new_capacity == old_capacity {
            entry_bytes.saturating_add(retained_hash_storage::<(GeneratedNodeIdentity, usize)>(
                new_capacity,
            ))
        } else {
            entry_bytes
                .saturating_add(retained_hash_storage::<(GeneratedNodeIdentity, usize)>(
                    old_capacity,
                ))
                .saturating_add(retained_hash_storage::<(GeneratedNodeIdentity, usize)>(
                    new_capacity,
                ))
        };
        peak_live_bytes = peak_live_bytes.max(live_bytes);
    }

    let mut bounded = Context::new();
    bounded.set_string_allocation_limit(peak_live_bytes);
    let bounded_evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&bounded, document.root().into());
    let cache = RefCell::new(GeneratedIdCache::default());
    for index in 0..ENTRIES {
        assign_generated_id(
            &bounded_evaluation,
            &cache,
            GeneratedNodeIdentity {
                document: document.identity(),
                path: NodePath::Ordinary(vec![index]),
            },
        )
        .expect("peak-live allocation budget must permit every table growth");
    }
}

#[test]
fn generated_id_cache_accounts_for_hash_table_storage() {
    // Distinct generate-id() calls retain both each path and the backing hash table. The
    // execution reservation transferred after XPath evaluation must cover both allocations.
    let package = Package::new();
    let document = package.as_document();
    let context = Context::new();
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let cache = RefCell::new(GeneratedIdCache::default());
    let path = NodePath::Ordinary(vec![0]);
    let identity = GeneratedNodeIdentity {
        document: document.identity(),
        path,
    };
    let payload = identity
        .path
        .owned_bytes()
        .saturating_add(std::mem::size_of::<(GeneratedNodeIdentity, usize)>());

    assign_generated_id(&evaluation, &cache, identity).expect("generated ID is assigned");

    let cache = cache.borrow();
    let table = retained_hash_storage::<(GeneratedNodeIdentity, usize)>(cache.assigned.capacity());
    assert_eq!(cache.owned_bytes, payload.saturating_add(table));
}

#[test]
fn generated_id_distinguishes_equal_paths_in_different_documents() {
    let first = Package::new();
    let second = Package::new();
    let first_document = first.as_document();
    let second_document = second.as_document();
    let context = Context::new();
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, first_document.root().into());
    let cache = RefCell::new(GeneratedIdCache::default());
    let path = NodePath::Ordinary(Vec::new());

    let first_id = assign_generated_id(
        &evaluation,
        &cache,
        GeneratedNodeIdentity {
            document: first_document.identity(),
            path: path.clone(),
        },
    )
    .expect("first document ID is assigned");
    let second_id = assign_generated_id(
        &evaluation,
        &cache,
        GeneratedNodeIdentity {
            document: second_document.identity(),
            path,
        },
    )
    .expect("second document ID is assigned");

    assert_ne!(first_id, second_id);
}

#[test]
fn completed_custom_calls_account_for_vector_storage() {
    // The continuation session survives every replay, so its released reservation must
    // include the completed-call vector even when the cached call carries no heap payload.
    let call = Rc::new(DeferredCustomCall {
        name: ExpandedName::new(None::<String>, "f"),
        node: NodePath::Ordinary(Vec::new()),
        position: 1,
        size: 1,
        arguments: Vec::new(),
    });
    let completed_call = CompletedCustomCall {
        call,
        result: DeferredXPathValue::Boolean(true),
        fragment: None,
    };
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
        owned_bytes: usize::MAX,
    };
    let mut meter = Meter::new(budget, 0).expect("empty meter initializes");
    let mut state = CustomCallState::default();
    state
        .reserve_completed_slot(&mut meter)
        .expect("completed-call slot fits");
    state.completed.push(completed_call);
    let vector_bytes = state
        .completed
        .capacity()
        .saturating_mul(std::mem::size_of::<CompletedCustomCall>());
    let session = CustomCallSession {
        state: Rc::new(RefCell::new(state)),
    };

    assert_eq!(session.retained_bytes(), vector_bytes);
}

#[test]
fn dynamic_map_document_accounts_for_all_retained_storage() {
    // The temporary EXSLT result tree owns expanded names, prefixes, namespace declarations,
    // and text. Its reservation must cover the complete tree before it can be imported.
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
        owned_bytes: usize::MAX,
    };
    let mut meter = Meter::new(budget, 0).expect("empty meter initializes");
    let (document, reservation) = dynamic_map_document(&[("boolean", "true".into())], &mut meter)
        .expect("dynamic map document builds");
    let charged = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage exists")
        .0;

    assert!(
        charged >= document.estimated_owned_bytes(),
        "charged={charged}, retained={}",
        document.estimated_owned_bytes()
    );
    assert_eq!(reservation, charged);
}

#[test]
fn xinclude_identity_clone_crosses_the_owned_bytes_gate() {
    // Resolver provenance is retained once per active include-chain entry. The clone must be
    // rejected before allocation when no owned-memory budget remains.
    let identity = XIncludeDocumentIdentity::External(ResourceIdentity("identity".into()));
    let mut meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: 0,
        },
        0,
    )
    .expect("empty meter initializes");

    assert!(matches!(
        clone_xinclude_identity(&identity, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn variable_references_preserve_non_xpath_whitespace() {
    // XPath 1.0 production [1] limits expression whitespace to XML S. A host-language trim
    // must not turn NBSP-prefixed input into a bound variable reference.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#NT-ExprWhitespace
    assert_eq!(variable_reference_name("\u{a0}$value", &[]), None);
    assert_eq!(
        variable_reference_name(" \t\r\n$value \t\r\n", &[]),
        Some(ExpandedName::new(None::<String>, "value"))
    );
}

#[test]
fn string_consumers_gate_nodeset_work_before_allocation() {
    // All argument consumers must reject traversal before attempting string allocation.
    let package =
        sxd_document_no_unsafe::parser::parse("<root><a>payload</a></root>").expect("test XML");
    let document = package.as_document();
    let root = document.root().children()[0]
        .element()
        .expect("root element");
    for extension in [true, false] {
        let mut context = Context::new();
        context.set_string_allocation_limit(0);
        if extension {
            context.set_extension_work_limit(0);
        } else {
            context.set_evaluation_work_limit(0);
        }
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, root.into());
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(root);
        let result = if extension {
            ExsltCryptoFunction::Md5.evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        } else {
            one_qname_argument(
                &evaluation,
                vec![SxdValue::Nodeset(nodes)],
                &[],
                "system-property",
            )
            .map(|_| SxdValue::Boolean(true))
        };
        assert!(result.is_err());
        assert_eq!(
            context.string_allocation_exceeded(),
            None,
            "work must be rejected before materialization (extension={extension})"
        );
        assert!(if extension {
            context.extension_work_exceeded().is_some()
        } else {
            context.evaluation_work_exceeded().is_some()
        });
    }
}

#[test]
fn key_name_coercion_rejects_work_before_lookup() {
    // key() must share QName coercion with availability/property queries, before index work.
    let package = sxd_document_no_unsafe::parser::parse("<root>payload</root>").expect("test XML");
    let document = package.as_document();
    let mut context = Context::new();
    context.set_evaluation_work_limit(0);
    context.set_string_allocation_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(document.root());
    let key = KeyFunction {
        index: Rc::new(RefCell::new(HashMap::new())),
        namespaces: Arc::new(Vec::new()),
        declarations: Arc::from([]),
        name_indices: Arc::from([]),
        ready: Rc::new(RefCell::new(HashSet::new())),
        pending: Rc::new(RefCell::new(None)),
    };
    assert!(
        key.evaluate(
            &evaluation,
            vec![SxdValue::Nodeset(nodes), SxdValue::Number(1.0)]
        )
        .is_err()
    );
    assert!(context.evaluation_work_exceeded().is_some());
    assert_eq!(context.string_allocation_exceeded(), None);
    assert!(key.pending.borrow().is_none());
}

#[test]
fn identity_extension_moves_owned_string_without_allocation() {
    // An identity operation consumes an already-owned argument instead of copying it.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_string_allocation_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let text = String::from("identity");
    let pointer = text.as_ptr();
    let SxdValue::String(result) = IdentityStringFunction
        .evaluate(&evaluation, vec![SxdValue::String(text)])
        .expect("existing owned text needs no allocation")
    else {
        panic!("string result")
    };
    assert_eq!(result, "identity");
    assert_eq!(result.as_ptr(), pointer);
}
use super::*;
use crate::ExecutionBudget;
use sxd_xpath_no_unsafe::function::Function;

#[test]
fn live_result_tree_fragment_handles_do_not_alias() {
    let first = Arc::new(Document::empty(None));
    let first_identity = result_tree_fragment_handle(&first);
    let second = Arc::new(Document::empty(None));
    assert_ne!(first_identity, result_tree_fragment_handle(&second));
}

#[test]
fn request_base_uri_is_rejected_before_clone_when_budget_is_exhausted() {
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    let mut context = Context::new();
    context.set_string_allocation_limit(0);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, root.into());
    let function = DocumentFunction {
        resolver: &crate::NoResolver,
        access_error: &RefCell::new(None),
        roots: Rc::new(RefCell::new(HashMap::new())),
        pending: Rc::new(RefCell::new(PendingDocumentRequests::default())),
        node_base_uris: Rc::new(RefCell::new(HashMap::new())),
        static_base_uri: Some(Arc::from("memory:principal.xsl")),
        static_document: StylesheetDocumentId::PRINCIPAL,
    };

    assert!(
        function
            .evaluate(&evaluation, vec![SxdValue::String(String::new())])
            .expect_err("static base URI must cross the allocation gate")
            .to_string()
            .contains("allocation budget")
    );
}

#[test]
fn auxiliary_document_indexes_charge_empty_document_slots() {
    let source = Document::parse("<root/>", None).expect("source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: source.source_bytes(),
            external_documents: 0,
            recursion_depth: 8,
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("meter initializes");
    let before = meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0;
    let mut ids = Vec::new();
    let maps = NodeMaps::new(&source, &mut meter).expect("node maps build");
    extend_id_index(&source, &maps, 0, &mut ids, &mut meter).expect("empty ID index builds");
    let mut entities = Vec::new();
    append_unparsed_entity_document(&source, source.root(), &mut entities, &mut meter)
        .expect("empty unparsed-entity index builds");
    let charged = meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0 - before;
    let retained_outer_capacity = ids
        .capacity()
        .saturating_mul(std::mem::size_of::<HashMap<String, NodePath>>())
        .saturating_add(
            entities
                .capacity()
                .saturating_mul(std::mem::size_of::<HashMap<String, String>>()),
        );
    assert!(charged >= retained_outer_capacity);
}

#[test]
fn node_maps_release_semantic_path_workspace_after_projection() {
    // Semantic paths are only construction workspace. Once the permanent indexes own their
    // path payloads, the workspace reservation must be released rather than retained for the
    // rest of the transformation. Hash-table backing storage already includes each inline
    // `NodePath`; only its heap payload needs a separate charge.
    let source = Document::parse("<root><first><nested/></first><second/></root>", None)
        .expect("source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: source.source_bytes(),
            external_documents: 0,
            recursion_depth: 8,
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("meter initializes");
    let before = meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0;

    let maps = NodeMaps::new(&source, &mut meter).expect("node maps build");

    let expected_retained = maps
        .forward
        .values()
        .fold(0usize, |total, path| {
            total.saturating_add(
                path.owned_bytes()
                    .saturating_sub(std::mem::size_of::<NodePath>())
                    .saturating_mul(2),
            )
        })
        .saturating_add(maps.forward_index_bytes)
        .saturating_add(maps.reverse_index_bytes)
        .saturating_add(maps.order_index_bytes);
    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        before.saturating_add(expected_retained)
    );
}

#[test]
fn node_base_uri_index_charges_hash_backing_storage() {
    let source = Document::parse("<root xml:base='memory:base'/>", None).expect("source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: source.source_bytes(),
            external_documents: 0,
            recursion_depth: 8,
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("meter initializes");
    let element = source
        .nodes()
        .find_map(|(id, node)| matches!(node.kind, NodeKind::Element { .. }).then_some(id))
        .expect("document element exists");
    let path = NodePath::Ordinary(vec![0, 0, 0]);
    let node = SourceNode::Node(element);
    let mut index = HashMap::new();
    let mut index_bytes = 0;
    let before = meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0;

    extend_node_base_uri_entries(
        &source,
        std::iter::once((&path, &node)),
        &mut index,
        &mut index_bytes,
        &mut meter,
    )
    .expect("base URI index builds");

    let charged = meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0 - before;
    assert_eq!(
        index_bytes,
        retained_hash_storage::<(Vec<usize>, Option<String>)>(index.capacity())
    );
    assert!(charged >= index_bytes.saturating_add("memory:base".len()));
}

struct StaticResolver {
    bytes: Vec<u8>,
}

#[test]
fn fully_metered_owned_string_charges_retained_capacity() {
    // SXD string functions can return a short value in a source-sized allocation. Callers
    // retain that allocation, so the reservation must describe capacity rather than length.
    let source = Document::parse("<root/>", None).expect("source parses");
    let stylesheet = Document::parse("<stylesheet/>", None).expect("stylesheet parses");
    let unlimited = ExecutionBudget {
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
        owned_bytes: usize::MAX,
    };
    let options = EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let mut setup_meter = Meter::new(unlimited, source.source_bytes()).expect("setup meter");
    let prepared =
        prepare_evaluator_source(&source, &crate::NoResolver, &mut setup_meter, &options)
            .expect("source prepares");
    let evaluator = Evaluator::new(
        prepared,
        &stylesheet,
        None,
        &[],
        Arc::new(crate::NoResolver),
        &mut setup_meter,
        options,
    )
    .expect("evaluator initializes");
    let mut value = String::with_capacity(4096);
    value.push('x');
    let capacity = value.capacity();
    let mut limits = unlimited;
    limits.owned_bytes = capacity - 1;
    let mut meter = Meter::new(limits, 0).expect("meter initializes");

    assert!(matches!(
        XPathValue::String(value)
            .into_fully_metered_temporary_string(&evaluator, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        }) if actual == capacity
    ));
}

#[test]
fn child_axis_fast_path_rejects_unbound_prefix_without_candidates() {
    // XPath 1.0 section 2.3 resolves QName prefixes from the expression context; an
    // undeclared prefix is an error even when the selected axis happens to be empty.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#node-tests
    let source = Document::parse("<root/>", None).expect("source parses");
    let stylesheet = Document::parse("<stylesheet/>", None).expect("stylesheet parses");
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
        owned_bytes: usize::MAX,
    };
    let mut meter = Meter::new(budget, source.source_bytes()).expect("meter initializes");
    let options = EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared = prepare_evaluator_source(&source, &crate::NoResolver, &mut meter, &options)
        .expect("source prepares");
    let evaluator = Evaluator::new(
        prepared,
        &stylesheet,
        None,
        &[],
        Arc::new(crate::NoResolver),
        &mut meter,
        options,
    )
    .expect("evaluator initializes");
    let logical_root = evaluator.source.logical_roots()[0];
    let empty_element = evaluator
        .source
        .node(logical_root)
        .and_then(|node| node.children.first())
        .copied()
        .expect("source element exists");
    let expression = Expression::generated("missing:item", Vec::new());

    let error = evaluator
        .select_child_axis(&expression, &SourceNode::Node(empty_element), &mut meter)
        .expect_err("unbound QName prefix must fail before child traversal");
    assert!(matches!(error, Error::Static(message) if message.contains("missing")));
}

#[test]
fn child_axis_fast_path_retains_its_node_storage_reservation() {
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(32));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let stylesheet = Document::parse("<stylesheet/>", None).expect("stylesheet parses");
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
        owned_bytes: usize::MAX,
    };
    let mut meter = Meter::new(budget, source.source_bytes()).expect("meter initializes");
    let options = EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared = prepare_evaluator_source(&source, &crate::NoResolver, &mut meter, &options)
        .expect("source prepares");
    let evaluator = Evaluator::new(
        prepared,
        &stylesheet,
        None,
        &[],
        Arc::new(crate::NoResolver),
        &mut meter,
        options,
    )
    .expect("evaluator initializes");
    let root = evaluator.source.logical_roots()[0];
    let document_element = evaluator
        .source
        .node(root)
        .expect("logical root remains present")
        .children[0];
    let before = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    let (selected, selected_reservation) = evaluator
        .select_child_axis(
            &Expression::generated("item", Vec::new()),
            &SourceNode::Node(document_element),
            &mut meter,
        )
        .expect("selection succeeds")
        .expect("child-axis shortcut applies");
    let retained = selected
        .capacity()
        .saturating_mul(std::mem::size_of::<SourceNode>());

    assert_eq!(selected_reservation, retained);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0
            - before,
        retained
    );
    meter.release_owned_bytes(selected_reservation);
}

#[test]
fn node_name_functions_charge_copied_bytes_as_xpath_work() {
    let package = Package::new();
    let document = package.as_document();
    let element = document.create_element("long-element-name");
    document.root().append_child(element);
    let mut context = Context::new();
    context.set_evaluation_work_limit(0);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, element.into());

    assert!(
        NodeNameFunction::Local
            .evaluate(&evaluation, vec![])
            .is_err()
    );
}

#[test]
fn relative_node_fast_path_charges_rejected_candidates() {
    // The current()-relative shortcut must charge every candidate it inspects, including
    // children rejected by the name test without producing result storage.
    let xml = format!("<root>{}</root>", "<other/>".repeat(64));
    let source = Document::parse(&xml, None).expect("source parses");
    let stylesheet = Document::parse("<stylesheet/>", None).expect("stylesheet parses");
    let mut setup_meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("setup meter initializes");
    let options = EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };
    let prepared =
        prepare_evaluator_source(&source, &crate::NoResolver, &mut setup_meter, &options)
            .expect("source prepares");
    let evaluator = Evaluator::new(
        prepared,
        &stylesheet,
        None,
        &[],
        Arc::new(crate::NoResolver),
        &mut setup_meter,
        options,
    )
    .expect("evaluator initializes");
    let root = evaluator.source.logical_roots()[0];
    let element = evaluator.source.node(root).expect("logical root").children[0];
    let mut work_budget = ExecutionBudget {
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
        owned_bytes: usize::MAX,
    };
    work_budget.xpath_operations = 1;
    let mut meter = Meter::new(work_budget, 0).expect("work meter initializes");

    let error = evaluator
        .relative_nodes("missing", &SourceNode::Node(element), &[], &mut meter)
        .expect_err("candidate scans must cross the XPath work gate");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::XPathOperations,
            ..
        }
    ));
}

#[test]
fn current_namespace_identity_charges_binding_resolution() {
    // current() must use the same metered binding lookup as continuation restoration.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    let prefix = "p".repeat(128);
    root.register_prefix(&prefix, "urn:test");
    document.root().append_child(root);
    let function = CurrentNode {
        path: NodePath::Namespace {
            parent: vec![0],
            prefix,
            uri: "urn:test".into(),
        },
    };
    let mut context = Context::new();
    context.set_evaluation_work_limit(2);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    assert!(function.evaluate(&evaluation, vec![]).is_err());
}

#[test]
fn xinclude_decode_errors_preserve_resource_and_fatal_boundaries() {
    // XInclude 1.0 sections 4.2 and 4.3 permit fallback for an unsupported encoding in both
    // parse modes, but malformed bytes remain fatal after an encoding has been selected.
    // https://www.w3.org/TR/xinclude/#xml
    // https://www.w3.org/TR/xinclude/#text_included
    for mode in [XIncludeParseMode::Xml, XIncludeParseMode::Text] {
        assert!(matches!(
            classify_xinclude_decode_error(
                xml_sec_xml_input::Error::UnsupportedEncoding("unknown".into()),
                mode,
            ),
            XIncludeFailure::Resource(_)
        ));
        assert!(matches!(
            classify_xinclude_decode_error(xml_sec_xml_input::Error::InvalidBytes("UTF-8"), mode,),
            XIncludeFailure::Fatal(_)
        ));
    }
}

#[test]
fn xpointer_accepts_adjacent_pointer_parts() {
    // XPointer Framework section 3.3 defines `PointerPart (S? PointerPart)*`: XML
    // whitespace between parts is optional, and evaluation continues after an empty part.
    // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#scheme
    let document = Document::parse("<root><selected/></root>", None).expect("source parses");
    let selected = select_xpointer_element(&document, "element(/1/9)element(/1/1)")
        .expect("adjacent pointer parts parse")
        .expect("second pointer part selects an element");

    assert!(matches!(
        &document.node(selected).expect("selected node exists").kind,
        NodeKind::Element { name, .. } if name.local == "selected"
    ));
}

#[test]
fn small_nodeset_projection_checks_its_vector_capacity() {
    // XPath does not define resource ceilings. The engine's OwnedBytes contract must reject
    // the second projection vector before allocation even on the <=64-node fast path.
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(32));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let unlimited = || ExecutionBudget {
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
        owned_bytes: usize::MAX,
    };
    let mut setup_meter = Meter::new(unlimited(), 0).expect("setup meter initializes");
    let package = project_semantic_document(&source, &mut setup_meter)
        .expect("source projects into the XPath DOM");
    let maps = NodeMaps::new(&source, &mut setup_meter).expect("node maps build");
    let document = package.as_document();
    let source_root = document.root().children()[0]
        .element()
        .expect("projection container exists")
        .children()[0]
        .element()
        .expect("logical-document wrapper exists")
        .children()[0]
        .element()
        .expect("source root exists");
    let mut selected = nodeset::Nodeset::new();
    for child in source_root.children() {
        selected.add(child);
    }
    let required = 32usize.saturating_mul(std::mem::size_of::<SourceNode>());
    let mut limits = unlimited();
    limits.owned_bytes = required - 1;
    let mut meter = Meter::new(limits, 0).expect("empty source fits");

    assert!(matches!(
        maps.project_value(
            &source,
            document.root().into(),
            SxdValue::Nodeset(selected),
            &mut meter,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn principal_xinclude_remap_reports_its_retained_reservation() {
    // The remap is retained until public parameter node identities are translated. Its
    // reservation must travel with it so dropping the map releases the same budget charge.
    let source =
        Document::parse("<root><first/><second/></root>", None).expect("source document parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: 0,
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("test meter initializes");
    let prepared = prepare_evaluator_source(
        &source,
        &crate::NoResolver,
        &mut meter,
        &EvaluatorSourceOptions {
            process_xinclude: true,
            whitespace: Arc::from([]),
            clock: Some(Arc::new(crate::SystemClock)),
        },
    )
    .expect("XInclude preprocessing succeeds without external resources");
    assert!(prepared.remap.is_some());
    assert!(
        prepared.remap_owned_bytes > 0,
        "retained mapping bytes must remain attributable to the map owner"
    );
}
#[test]
fn xinclude_text_transfers_decoded_storage_to_the_expanded_document() {
    let resolver = StaticResolver {
        bytes: vec![b'x'; 64 * 1024],
    };
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude">before<xi:include href="value.txt" parse="text"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: 1,
            recursion_depth: 16,
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("meter initializes");
    let before = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("owned-byte usage is available")
        .0;
    let mut identities = HashMap::new();
    let expanded = expand_xinclude_document(
        &source,
        &XIncludeDocumentIdentity::InMemory(&source as *const Document as usize),
        &resolver,
        &mut meter,
        &mut identities,
        0,
        None,
    )
    .expect("text inclusion succeeds");
    let cache_bytes = identities
        .values()
        .map(resource_identity_cache_entry_owned_bytes)
        .sum::<usize>();

    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0
            - before,
        expanded.retained_owned_bytes + cache_bytes,
        "all live owned bytes must belong to an explicit retained owner"
    );
}

#[test]
fn replacing_xinclude_xml_base_releases_discarded_storage() {
    // A copied xml:base value is already part of the retained clone reservation. Replacing it
    // must transfer that reservation to the acquired URI rather than retaining both strings.
    let source = Document::parse(
        r#"<included xml:base="source/"/>"#,
        Some("memory:external.xml"),
    )
    .expect("included source parses");
    let mut output = Document::parse(
        r#"<included xml:base="discarded/"/>"#,
        Some("memory:principal.xml"),
    )
    .expect("copied output parses");
    let target = output
        .node(output.root())
        .expect("output root exists")
        .children[0];
    let target_parent = output.root();
    let source_element = source
        .node(source.root())
        .expect("source root exists")
        .children[0];
    let retained_before = output.estimated_clone_bytes();
    let mut meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: usize::MAX,
        },
        0,
    )
    .expect("meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, retained_before)
        .expect("initial clone reservation fits");
    let delta = preserve_xinclude_base(
        &source,
        source_element,
        &mut output,
        target_parent,
        target,
        &mut meter,
    )
    .expect("XInclude base fixup succeeds");
    let mut retained = retained_before;
    delta.apply(&mut retained);

    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        output.estimated_clone_bytes(),
        "the meter must retain only the replacement allocation"
    );
    assert_eq!(retained, output.estimated_clone_bytes());
}

#[test]
fn node_remap_composition_reuses_the_first_allocation() {
    // Both input maps are retained before composition. Updating the first in place keeps peak
    // memory flat and releases the second map's complete reservation when it is consumed.
    let document =
        Document::parse("<root><first/><second/></root>", None).expect("identity source parses");
    let ids = document.nodes().map(|(id, _)| id).collect::<Vec<_>>();
    let first = HashMap::from([(ids[1], ids[2]), (ids[2], ids[3])]);
    let second = HashMap::from([(ids[2], ids[3])]);
    let first_bytes = xinclude_remap_bytes(first.len());
    let second_bytes = xinclude_remap_bytes(second.len());
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: 0,
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
            owned_bytes: usize::MAX,
        },
        0,
    )
    .expect("test meter initializes");
    meter
        .charge(BudgetKind::OwnedBytes, first_bytes + second_bytes)
        .expect("input maps fit");

    let (composed, retained_bytes) = compose_node_remaps(
        Some(first),
        first_bytes,
        Some(second),
        second_bytes,
        &mut meter,
    )
    .expect("remaps compose");
    let composed = composed.expect("the first remap remains retained");
    assert_eq!(composed, HashMap::from([(ids[1], ids[3])]));
    assert_eq!(retained_bytes, first_bytes);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("usage is available")
            .0,
        first_bytes
    );
}

impl Resolver for StaticResolver {
    fn authorize(&self, _: crate::ResourceAccess<'_>) -> Result<()> {
        // This test resolver owns a permanently authorized immutable byte buffer.
        Ok(())
    }
    fn resolve(&self, request: ResolveRequest<'_>) -> Result<ResolvedResource> {
        let uri = request.uri;
        Ok(ResolvedResource {
            canonical_uri: format!("memory:{uri}"),
            identity: ResourceIdentity(uri.into()),
            bytes: self.bytes.clone(),
            media_type: Some("application/xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

#[test]
fn xpath_adapter_workspace_includes_namespace_copies() {
    let plain = Expression::generated("/source", Vec::new());
    let namespaced = Expression::generated(
        "/source",
        vec![("prefix".into(), "urn:namespace:retained".into())],
    );

    assert!(
        xpath_adapter_workspace_upper_bound(&namespaced)
            >= xpath_adapter_workspace_upper_bound(&plain)
                + hash_table_entry_bytes::<(String, String)>()
                + "prefix".len()
                + "urn:namespace:retained".len()
    );
}

#[test]
fn identity_cache_takes_ownership_of_resolver_payload() {
    let resource = ResolvedResource {
        canonical_uri: "memory:resource.xml".into(),
        identity: ResourceIdentity("resource".into()),
        bytes: vec![7; 4_096],
        media_type: Some("application/xml".into()),
        encoding: Some("UTF-8".into()),
    };
    let payload = resource.bytes.as_ptr();
    let mut identities = HashMap::new();
    let mut meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: usize::MAX,
        },
        0,
    )
    .expect("meter initializes");

    let identity = cache_new_resource_identity(&mut identities, resource, &mut meter)
        .expect("new identity is cached");

    assert_eq!(
        identities
            .get(&identity)
            .expect("resource is retained")
            .bytes
            .as_ptr(),
        payload,
        "cache insertion must move rather than clone resolver bytes"
    );
}

#[test]
fn unparsed_entity_index_accounts_for_retained_containers() {
    // Names and URIs are only the payload: the per-document vector and hash-table capacity
    // remain live for the evaluator lifetime and must cross the same OwnedBytes gate.
    let source = Document::parse(
        r#"<!DOCTYPE root [<!NOTATION image SYSTEM "image/png"><!ENTITY logo SYSTEM "logo.png" NDATA image>]><root/>"#,
        None,
    )
    .expect("unparsed-entity source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: source.source_bytes(),
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
            owned_bytes: usize::MAX,
        },
        source.source_bytes(),
    )
    .expect("test meter initializes");
    let before = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("valid budget kind")
        .0;
    let index =
        build_unparsed_entity_index(&source, &mut meter).expect("unparsed-entity index builds");
    let charged = meter
        .usage(BudgetKind::OwnedBytes)
        .expect("valid budget kind")
        .0
        - before;
    let containers = index
        .capacity()
        .saturating_mul(std::mem::size_of::<HashMap<String, String>>())
        .saturating_add(
            index
                .iter()
                .map(|entities| unparsed_entity_table_bytes(entities.capacity()))
                .sum::<usize>(),
        );

    assert!(charged >= containers.saturating_add("logo".len() + "logo.png".len()));
}

#[test]
fn expanded_xinclude_retains_shared_namespace_arena_reservation() {
    // Projected nodes keep the parsed document's shared namespace arena alive after the
    // temporary included document is dropped, so that allocation remains part of the result.
    let namespace_payload = "n".repeat(128 * 1024);
    let resolver = StaticResolver {
        bytes: format!(r#"<included xmlns:p="urn:{namespace_payload}"><child/></included>"#)
            .into_bytes(),
    };
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: source.source_bytes(),
            external_documents: 1,
            recursion_depth: 16,
            xpath_evaluations: 1,
            xpath_operations: usize::MAX,
            extension_operations: 1,
            pattern_evaluations: 1,
            template_applications: 1,
            sort_comparisons: 1,
            key_entries: 1,
            result_nodes: 16,
            serialized_bytes: 1,
            messages: 1,
            owned_bytes: 4 * 1024 * 1024,
        },
        source.source_bytes(),
    )
    .expect("test meter initializes");
    let expanded = expand_xinclude_document(
        &source,
        &XIncludeDocumentIdentity::InMemory(&source as *const Document as usize),
        &resolver,
        &mut meter,
        &mut HashMap::new(),
        0,
        None,
    )
    .expect("XInclude expands");

    assert!(
        expanded.retained_owned_bytes >= namespace_payload.len(),
        "shared namespace arena must remain charged after projection"
    );
}

#[test]
fn xpath_parser_distinguishes_div_name_tests_from_operators() {
    // XPath 1.0 section 3.7 distinguishes operator names lexically; validation
    // must use that parser rather than rewriting '/' based on string suffixes.
    // https://www.w3.org/TR/xpath/#exprlex
    let package = sxd_document_no_unsafe::parser::parse("<root><div><span>2</span></div></root>")
        .expect("fixture parses");
    let document = package.as_document();
    let context = Context::new();
    let root = document.root().children()[0]
        .element()
        .expect("root element exists");
    for (source, node, expected) in [
        ("div/span", nodeset::Node::Element(root), 2.0),
        ("root/div/span", nodeset::Node::Root(document.root()), 2.0),
        ("1 div /root", nodeset::Node::Root(document.root()), 0.5),
    ] {
        let expression = Factory::new().build(source).expect("valid XPath");
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, node.clone());
        assert_eq!(
            expression
                .evaluate(&context, node)
                .expect("expression evaluates")
                .number(&evaluation)
                .expect("number conversion fits"),
            expected
        );
    }
}

#[test]
fn variable_overlay_borrows_existing_payloads() {
    let name = ExpandedName::new(None::<String>, "payload");
    let mut base = HashMap::new();
    base.insert(name.clone(), Value::String("retained payload".into()));
    let overlay = VariableOverlay::new(&base);
    let Some(Value::String(original)) = base.get(&name) else {
        panic!("base payload is missing");
    };
    let Some(Value::String(borrowed)) = overlay.get(&name) else {
        panic!("overlay payload is missing");
    };
    assert!(std::ptr::eq(original, borrowed));
}

#[test]
fn function_available_shares_the_stylesheet_catalog() {
    let catalog = Arc::new(HashSet::from([ExpandedName::new(
        Some("urn:extension"),
        "function",
    )]));
    let function = FunctionAvailable {
        namespaces: Arc::new(vec![]),
        stylesheet_functions: Arc::clone(&catalog),
    };

    assert!(Arc::ptr_eq(&function.stylesheet_functions, &catalog));
}

#[test]
fn outer_context_functions_accept_xpath_whitespace() {
    // XPath allows whitespace between a function name and its empty
    // argument list; rewriting must not depend on one lexical spelling.
    assert_eq!(
        rewrite_outer_context_functions("position \t( ) + last\n(\r)", "__xml_sec_ctx",),
        "$__xml_sec_ctx:position + $__xml_sec_ctx:last"
    );
}

#[test]
fn outer_context_rewrite_respects_unicode_ncname_boundaries() {
    // XML Names permits combining marks after the first NCName character. A built-in-looking
    // suffix inside such a QName must remain a call to that QName, not become an outer-context
    // variable reference.
    let source = "f:a\u{0301}position() + position()";
    assert_eq!(
        rewrite_outer_context_functions(source, "__xml_sec_ctx"),
        "f:a\u{0301}position() + $__xml_sec_ctx:position"
    );
}

#[test]
fn rc4_extensions_reserve_workspace_before_allocating() {
    // The extension must preflight all key, input, cipher, and hexadecimal buffers against
    // the evaluator's allocation budget before materializing attacker-controlled data.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_string_allocation_limit(1024);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    for (function, input) in [
        (ExsltCryptoFunction::Rc4Encrypt, "x".repeat(2048)),
        (ExsltCryptoFunction::Rc4Decrypt, "00".repeat(2048)),
    ] {
        let error = function
            .evaluate(
                &evaluation,
                vec![SxdValue::String("key".into()), SxdValue::String(input)],
            )
            .expect_err("workspace exceeds the evaluator budget");
        assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
    }
}

#[test]
fn rc4_decrypt_rejects_non_ascii_hex_without_panicking() {
    // Ciphertext is attacker-controlled XPath string data. Invalid UTF-8 byte pairs must
    // reach the typed hexadecimal error instead of an infallible conversion assertion.
    let package = Package::new();
    let document = package.as_document();
    let context = Context::new();
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let error = ExsltCryptoFunction::Rc4Decrypt
        .evaluate(
            &evaluation,
            vec![
                SxdValue::String("key".into()),
                SxdValue::String("😀".into()),
            ],
        )
        .expect_err("non-ASCII ciphertext is not hexadecimal");
    assert!(matches!(
        error,
        function::Error::Other { what } if what.contains("invalid hex")
    ));
}

#[test]
fn hash_extensions_reserve_materialization_and_output_before_allocating() {
    // Node string-value coercion and fixed-size hexadecimal output must both cross the
    // evaluator allocation gate before the extension materializes either buffer.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.append_child(document.create_text(&"x".repeat(2048)));
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);

    for function in [ExsltCryptoFunction::Md5, ExsltCryptoFunction::Sha1] {
        let mut context = Context::new();
        context.set_string_allocation_limit(1024);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let error = function
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes.clone())])
            .expect_err("hash workspace exceeds the evaluator budget");
        assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
    }

    for (function, output_len) in [
        (ExsltCryptoFunction::Md5, 32),
        (ExsltCryptoFunction::Sha1, 40),
    ] {
        let mut context = Context::new();
        context.set_string_allocation_limit(output_len - 1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let error = function
            .evaluate(&evaluation, vec![SxdValue::String("x".into())])
            .expect_err("hexadecimal output exceeds the evaluator budget");
        assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
    }
}

#[test]
fn node_name_functions_reserve_qualified_name_before_materializing_it() {
    // General XPath evaluation can reduce name() to a scalar immediately, but the temporary
    // QName must still cross the evaluator's owned-memory gate before allocation.
    let package = Package::new();
    let document = package.as_document();
    let local = "n".repeat(2048);
    let element = document.create_element(("urn:test", local.as_str()));
    element.set_preferred_prefix(Some("prefix"));
    document.root().append_child(element);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(element);
    let mut context = Context::new();
    context.set_string_allocation_limit(1024);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = NodeNameFunction::Qualified
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("qualified name exceeds the evaluator allocation budget");
    assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
}

#[test]
fn lang_reserves_nodeset_string_materialization() {
    // A node-set argument can expose an attacker-sized string-value even though lang()
    // returns only a boolean. The conversion must cross the evaluator allocation gate.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.set_attribute_value(("http://www.w3.org/XML/1998/namespace", "lang"), "en-GB");
    root.append_child(document.create_text(&"x".repeat(2_048)));
    document.root().append_child(root);
    let item = document.create_element("item");
    root.append_child(item);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);
    let mut xpath_context = Context::new();
    xpath_context.set_string_allocation_limit(128);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&xpath_context, item.into());

    let error = LangFunction
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("node string-value exceeds the evaluator allocation budget");
    assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
}

#[test]
fn lang_matches_ascii_case_and_sublanguage_without_folding() {
    assert!(language_tag_matches("EN-gb", "en"));
    assert!(language_tag_matches("en", "EN"));
    assert!(!language_tag_matches("english", "en"));
    assert!(!language_tag_matches("fr", "en"));
}
#[test]
fn lang_ancestor_search_obeys_work_budget() {
    // Even a failed lookup must charge ancestor and attribute visits without
    // materializing an attribute vector at every level.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    root.set_attribute_value("other", "value");
    let child = document.create_element("child");
    root.append_child(child);
    for limit in [0, 1, 2] {
        let mut context = Context::new();
        context.set_evaluation_work_limit(limit);
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, child.into());
        let error = LangFunction
            .evaluate(&evaluation, vec![SxdValue::String("en".into())])
            .expect_err("ancestor and attribute visits must cross the work gate");
        assert!(error.to_string().contains("work budget"));
    }
}

#[test]
fn id_result_nodes_cross_the_xpath_allocation_gate() {
    // A wide id() result is temporary XPath-owned storage even when its caller consumes only
    // the first node. Every unique result insertion must therefore consume the shared gate.
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    let logical_document = document.create_element("document");
    let target = document.create_element("target");
    document.root().append_child(documents);
    documents.append_child(logical_document);
    logical_document.append_child(target);
    let index = vec![HashMap::from([(
        "target".into(),
        NodePath::Ordinary(vec![0, 0, 0]),
    )])];
    let function = IdFunction {
        nodes_by_document: Rc::new(RefCell::new(index)),
    };
    let mut context = Context::new();
    context.set_string_allocation_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, logical_document.into());

    let error = function
        .evaluate(&evaluation, vec![SxdValue::String("target".into())])
        .expect_err("id() result storage must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn id_string_tokenization_obeys_work_budget() {
    // Existing String values avoid coercion, but splitting and hashing their ID tokens is
    // still attacker-controlled XPath work even when every lookup misses.
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    let logical_document = document.create_element("document");
    document.root().append_child(documents);
    documents.append_child(logical_document);
    let function = IdFunction {
        nodes_by_document: Rc::new(RefCell::new(vec![HashMap::new()])),
    };
    let mut context = Context::new();
    context.set_evaluation_work_limit(8);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, logical_document.into());

    let error = function
        .evaluate(&evaluation, vec![SxdValue::String("x ".repeat(128))])
        .expect_err("ID token scans must cross the XPath work gate");
    assert!(error.to_string().contains("work budget"));
}

#[test]
fn scalar_math_extension_obeys_extension_work_budget() {
    // Scalar EXSLT math has no node traversal to charge implicitly; the intrinsic operation
    // itself must still be denied when extension work is disabled.
    let package = Package::new();
    let mut context = Context::new();
    context.set_extension_work_limit(0);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
        &context,
        package.as_document().root().into(),
    );

    let error = ExsltMathFunction::Power
        .evaluate(
            &evaluation,
            vec![SxdValue::Number(2.0), SxdValue::Number(1024.0)],
        )
        .expect_err("math:power must cross the extension work gate");
    assert!(error.to_string().contains("extension work budget"));
}

#[test]
fn runtime_node_paths_obey_work_budget() {
    // id() needs document identity even for an empty lookup; finding it must not scan
    // arbitrarily many preceding siblings outside the evaluation work allowance.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    for _ in 0..128 {
        root.append_child(document.create_element("sibling"));
    }
    let target = document.create_element("target");
    root.append_child(target);
    let function = IdFunction {
        nodes_by_document: Rc::new(RefCell::new(Vec::new())),
    };
    let mut context = Context::new();
    context.set_evaluation_work_limit(0);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, target.into());
    assert!(
        function
            .evaluate(&evaluation, vec![SxdValue::String(String::new())])
            .is_err()
    );
}

#[test]
fn restored_function_results_obey_evaluation_budgets() {
    // Owned strings/node projections require replay storage; immutable RTF projections
    // must instead preserve shared ownership without copying their retained payload.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    let results = [
        DeferredXPathValue::String("x".repeat(4096)),
        DeferredXPathValue::ResultTreeFragment {
            identity: 1,
            value: Arc::new("x".repeat(4096)),
        },
        DeferredXPathValue::NodeSet(vec![NodePath::Ordinary(vec![0])]),
    ];
    for result in results {
        let shared = match &result {
            DeferredXPathValue::ResultTreeFragment { value, .. } => Some(Arc::clone(value)),
            _ => None,
        };
        let name = ExpandedName {
            namespace: None,
            local: "f".into(),
        };
        let call = DeferredCustomCall {
            name: name.clone(),
            node: NodePath::Ordinary(vec![]),
            position: 1,
            size: 1,
            arguments: vec![],
        };
        let function = DeferredStylesheetFunction {
            name,
            session: Rc::new(RefCell::new(CustomCallState {
                completed: vec![CompletedCustomCall {
                    call: Rc::new(call),
                    result,
                    fragment: None,
                }],
                ..CustomCallState::default()
            })),
        };
        let mut context = Context::new();
        context.set_string_allocation_limit(1024);
        context.set_evaluation_work_limit(1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let result = function.evaluate(&evaluation, vec![]);
        if let Some(shared) = shared {
            let SxdValue::ResultTreeFragment(identity, value) = result.expect("shared RTF replay")
            else {
                panic!("RTF expected");
            };
            assert_eq!(identity, 1);
            assert!(Arc::ptr_eq(&shared, &value));
        } else {
            let error = result.expect_err(
                "copying or resolving the cached result must cross the remaining budget",
            );
            assert!(error.to_string().contains("budget"));
        }
    }
}

#[test]
fn restored_nodes_preserve_identity_and_enforce_both_budgets() {
    // Replay must retain ordinary, attribute and namespace identities without
    // enumerating the entire namespace axis; stale paths remain errors.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    root.set_attribute_value("id", "value");
    root.register_prefix("p", "urn:p");
    root.set_default_namespace_uri(Some("urn:default"));
    let paths = vec![
        NodePath::Ordinary(vec![0]),
        NodePath::Attribute {
            parent: vec![0],
            namespace: None,
            local: "id".into(),
        },
        NodePath::Namespace {
            parent: vec![0],
            prefix: "p".into(),
            uri: "urn:p".into(),
        },
        NodePath::Namespace {
            parent: vec![0],
            prefix: String::new(),
            uri: "urn:default".into(),
        },
        NodePath::Namespace {
            parent: vec![0],
            prefix: "xml".into(),
            uri: "http://www.w3.org/XML/1998/namespace".into(),
        },
    ];
    for path in paths {
        let value = DeferredXPathValue::NodeSet(vec![path.clone()]);
        for (memory, work) in [(0, usize::MAX), (usize::MAX, 0), (usize::MAX, usize::MAX)] {
            let mut context = Context::new();
            context.set_string_allocation_limit(memory);
            context.set_evaluation_work_limit(work);
            let evaluation =
                sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
            let result = restore_sxd_value(&value, &evaluation);
            if memory == 0 || work == 0 {
                assert!(
                    result
                        .expect_err("replay obeys both independent gates")
                        .to_string()
                        .contains("budget")
                );
            } else {
                let SxdValue::Nodeset(nodes) = result.expect("unlimited replay") else {
                    panic!("node-set expected")
                };
                assert_eq!(nodes.size(), 1);
                assert_eq!(
                    typed_path_to(&nodes.iter().next().expect("one restored node")),
                    path
                );
            }
        }
    }
    let context = Context::new();
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let stale = DeferredXPathValue::NodeSet(vec![NodePath::Ordinary(vec![99])]);
    assert!(
        restore_sxd_value(&stale, &evaluation)
            .expect_err("missing child must be a stale identity")
            .to_string()
            .contains("stale")
    );
}

#[test]
fn exslt_set_result_nodes_cross_the_xpath_allocation_gate() {
    // Difference allocates its result, but no longer allocates an unnecessary sorted input.
    let package = Package::new();
    let document = package.as_document();
    let mut left = nodeset::Nodeset::new();
    left.add(document.root());
    let mut context = Context::new();
    context.set_string_allocation_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltSetFunction::Difference
        .evaluate(
            &evaluation,
            vec![
                SxdValue::Nodeset(left),
                SxdValue::Nodeset(nodeset::Nodeset::new()),
            ],
        )
        .expect_err("EXSLT result storage must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn key_and_document_nodeset_arguments_obey_the_allocation_budget() {
    // XSLT node-set arguments can contain many large string-values. key() and document()
    // must not retain an unmetered batch before performing their lookups.
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    let logical = document.create_element("logical");
    document.root().append_child(documents);
    documents.append_child(logical);
    let mut nodes = nodeset::Nodeset::new();
    for _ in 0..8 {
        let item = document.create_element("item");
        item.append_child(document.create_text(&"x".repeat(1_024)));
        logical.append_child(item);
        nodes.add(item);
    }
    let mut xpath_context = Context::new();
    xpath_context.set_string_allocation_limit(128);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&xpath_context, logical.into());

    let key = KeyFunction {
        index: Rc::new(RefCell::new(HashMap::new())),
        namespaces: Arc::new(Vec::new()),
        declarations: Arc::from([]),
        name_indices: Arc::from([]),
        ready: Rc::new(RefCell::new(HashSet::new())),
        pending: Rc::new(RefCell::new(None)),
    };
    assert!(matches!(
        key.evaluate(
            &evaluation,
            vec![SxdValue::String("missing".into()), SxdValue::Nodeset(nodes.clone())],
        ),
        Err(function::Error::Other { what }) if what.contains("budget")
    ));

    let document_function = DocumentFunction {
        resolver: &crate::NoResolver,
        access_error: &RefCell::new(None),
        roots: Rc::new(RefCell::new(HashMap::new())),
        pending: Rc::new(RefCell::new(PendingDocumentRequests::default())),
        node_base_uris: Rc::new(RefCell::new(HashMap::new())),
        static_base_uri: None,
        static_document: StylesheetDocumentId::PRINCIPAL,
    };
    assert!(matches!(
        document_function
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)]),
        Err(function::Error::Other { what }) if what.contains("budget")
    ));
}

#[test]
fn document_scalar_uri_obeys_the_xpath_work_budget() {
    // An existing scalar avoids string coercion allocation, but URI materialization and the
    // document-cache probe must still charge the caller-controlled URI bytes.
    let package = Package::new();
    let document = package.as_document();
    let logical = document.create_element("logical");
    document.root().append_child(logical);
    let mut context = Context::new();
    context.set_evaluation_work_limit(0);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, logical.into());
    let document_function = DocumentFunction {
        resolver: &crate::NoResolver,
        access_error: &RefCell::new(None),
        roots: Rc::new(RefCell::new(HashMap::new())),
        pending: Rc::new(RefCell::new(PendingDocumentRequests::default())),
        node_base_uris: Rc::new(RefCell::new(HashMap::new())),
        static_base_uri: None,
        static_document: StylesheetDocumentId::PRINCIPAL,
    };

    let error = document_function
        .evaluate(&evaluation, vec![SxdValue::String("x".repeat(4_096))])
        .expect_err("scalar document URI work must cross the XPath work gate");
    assert!(error.to_string().contains("work budget"));
}

#[test]
fn key_lookup_borrows_scalar_payload() {
    // An already-owned scalar argument needs no payload copy for a hash lookup.
    // Keep enough room for the context path/QName, but not for another large string.
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    let logical = document.create_element("logical");
    document.root().append_child(documents);
    documents.append_child(logical);
    let mut context = Context::new();
    context.set_string_allocation_limit(512);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, logical.into());
    let key = KeyFunction {
        index: Rc::new(RefCell::new(HashMap::new())),
        namespaces: Arc::new(Vec::new()),
        declarations: Arc::from([]),
        name_indices: Arc::from([]),
        ready: Rc::new(RefCell::new(HashSet::new())),
        pending: Rc::new(RefCell::new(None)),
    };
    let result = key
        .evaluate(
            &evaluation,
            vec![
                SxdValue::String("missing".into()),
                SxdValue::String("x".repeat(65_536)),
            ],
        )
        .expect("lookup borrows its argument");
    assert_eq!(result, SxdValue::Nodeset(nodeset::Nodeset::new()));
}

#[test]
fn ordinary_xpath_rewrite_pipeline_keeps_borrowed_storage() {
    // Repeated evaluation of a cached relative XPath must not allocate intermediate
    // normalization strings when none of the internal rewrites apply.
    let source = "item/@name";
    let normalized = normalize_xpath_for_sxd(source);
    assert!(matches!(&normalized, std::borrow::Cow::Borrowed(_)));
    let isolated = hide_projection_elements_from_axes(&normalized);
    assert!(matches!(&isolated, std::borrow::Cow::Borrowed(_)));
    let context = rewrite_outer_context_functions(&isolated, "__xml_sec_ctx");
    assert!(matches!(context, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn document_fragment_decode_reserves_owned_output_before_allocation() {
    // Percent decoding must cross the same operation-owned-memory gate as every other
    // attacker-controlled temporary buffer, before capacity is allocated.
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: 0,
            external_documents: 0,
            recursion_depth: 0,
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
            owned_bytes: 1,
        },
        0,
    )
    .expect("empty source fits the test budget");
    assert!(matches!(
        decode_document_fragment("%C3%A9", &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn external_parse_rejects_workspace_before_deriving_the_node_limit() {
    let per_node = std::mem::size_of::<Node>() + std::mem::size_of::<NodeId>();
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: 32,
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
            owned_bytes: per_node.saturating_mul(3),
        },
        0,
    )
    .expect("empty source fits");

    let required = parser_workspace_bytes("<root><a/><b/></root>");
    assert!(matches!(
        parse_external_document_metered("<root><a/><b/></root>", None, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        }) if actual == required
    ));
}

#[test]
fn semantic_projection_estimate_includes_structural_storage() {
    let source = Document::parse("<root><a/><b/><c/></root>", None).expect("source parses");
    let lexical_payload = "rootab c".len();

    assert!(semantic_projection_size(&source) > lexical_payload);
}

#[test]
fn token_documents_charge_tree_containers_in_addition_to_payloads() {
    // Two one-byte token payloads consume twelve bytes including their element names. A
    // budget of exactly that size must still reject the arena and child-vector allocations.
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: 0,
            external_documents: 0,
            recursion_depth: 0,
            xpath_evaluations: 0,
            xpath_operations: 0,
            extension_operations: usize::MAX,
            pattern_evaluations: 0,
            template_applications: 0,
            sort_comparisons: 0,
            key_entries: 0,
            result_nodes: 4,
            serialized_bytes: 0,
            messages: 0,
            owned_bytes: 12,
        },
        0,
    )
    .expect("empty source fits the payload-only budget");
    assert!(matches!(
        token_document("a b", " ", ExtensionCallKind::Split, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}
#[test]
fn clear_pattern_cache_releases_owned_bytes() {
    // Cache invalidation must return the exact reservation charged for keys and node sets;
    // otherwise repeated key-index construction eventually exhausts a bounded operation.
    let key: PatternCacheKey = (
        "item[@kind='retained']".into(),
        vec![("p".into(), "urn:retained".into())],
        NodeId::test(0),
    );
    let nodes = HashSet::from([
        SourceNode::Node(NodeId::test(1)),
        SourceNode::Node(NodeId::test(2)),
    ]);
    let mut cache = HashMap::new();
    let mut index_owned_bytes = 0usize;
    let mut meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: usize::MAX,
        },
        0,
    )
    .expect("empty source fits the test budget");
    let key_owned_bytes = pattern_cache_key_owned_bytes(&key);
    meter
        .charge(BudgetKind::OwnedBytes, key_owned_bytes)
        .expect("key reservation fits");
    insert_pattern_cache_entry(
        &mut cache,
        &mut index_owned_bytes,
        key,
        key_owned_bytes,
        nodes,
        &mut meter,
    )
    .expect("cache insertion fits");
    let reserved = pattern_cache_retained_owned_bytes(&cache);
    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        reserved
    );

    clear_pattern_cache(&mut cache, &mut index_owned_bytes, &mut meter);

    assert!(cache.is_empty());
    assert_eq!(cache.capacity(), 0);
    assert_eq!(index_owned_bytes, 0);
    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        0
    );

    let namespaces = [("p".repeat(64), "urn:retained".repeat(64))];
    let required = "//p:item".len()
        + namespaces.len() * std::mem::size_of::<(String, String)>()
        + namespaces
            .iter()
            .map(|(prefix, uri)| prefix.len() + uri.len())
            .sum::<usize>();
    let mut constrained = Meter::new(
        ExecutionBudget {
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
            owned_bytes: required - 1,
        },
        0,
    )
    .expect("empty source fits the test budget");
    assert!(matches!(
        clone_pattern_cache_key("//p:item", &namespaces, NodeId::test(0), &mut constrained),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(
        constrained
            .usage(BudgetKind::OwnedBytes)
            .expect("valid kind")
            .0,
        0
    );
}

#[test]
fn document_cache_keys_reserve_both_owned_requests() {
    // The request is cloned into document_roots and moved into documents, so both retained
    // keys and both copies of their attacker-controlled strings must cross the same gate.
    let request = DocumentRequest {
        href: "relative/retained/document.xml".repeat(8),
        base_uri: Some("memory:retained/base/".repeat(8)),
        empty_document: None,
    };
    let reserved = document_cache_key_owned_bytes(&request);
    let limits = |owned_bytes| ExecutionBudget {
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
        owned_bytes,
    };
    let mut insufficient =
        Meter::new(limits(reserved - 1), 0).expect("empty source fits the test budget");
    assert!(matches!(
        charge_document_cache_keys(&request, &mut insufficient),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        }) if actual == reserved
    ));

    let mut exact = Meter::new(limits(reserved), 0).expect("empty source fits the exact budget");
    charge_document_cache_keys(&request, &mut exact).expect("exact reservation fits");
    assert_eq!(
        exact.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        reserved
    );
}

#[test]
fn resolver_identity_cache_accounts_for_retained_metadata() {
    // Resolver bytes are charged during decode; every retained key, URI, metadata string,
    // spare byte capacity, and hash entry must cross the same gate before cache insertion.
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(b"<r/>");
    let resource = ResolvedResource {
        canonical_uri: "memory:metadata/document.xml".repeat(4),
        identity: ResourceIdentity("stable-resource-identity".repeat(4)),
        bytes,
        media_type: Some("application/xml".repeat(8)),
        encoding: Some("UTF-8".repeat(8)),
    };
    let source_owned_bytes = resource.bytes.capacity();
    let additional =
        resource_identity_cache_entry_owned_bytes(&resource).saturating_sub(source_owned_bytes);
    let limits = |owned_bytes| ExecutionBudget {
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
        owned_bytes,
    };
    let mut insufficient =
        Meter::new(limits(source_owned_bytes + additional - 1), 0).expect("empty source fits");
    insufficient
        .charge(BudgetKind::OwnedBytes, source_owned_bytes)
        .expect("resolver byte allocation fits");
    assert!(matches!(
        charge_resource_identity_cache_entry(&resource, &mut insufficient),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));

    let mut exact =
        Meter::new(limits(source_owned_bytes + additional), 0).expect("empty source fits");
    exact
        .charge(BudgetKind::OwnedBytes, source_owned_bytes)
        .expect("resolver byte allocation fits");
    charge_resource_identity_cache_entry(&resource, &mut exact)
        .expect("exact metadata reservation fits");
}

#[test]
fn xinclude_rejects_resolver_capacity_before_decode_or_fallback() {
    // Resolver-owned capacity is live before decoding starts. An unavailable encoding is a
    // recoverable XInclude resource error, but it must not hide an already-exceeded memory
    // budget or activate fallback.
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(b"payload");
    let resource = ResolvedResource {
        canonical_uri: "memory:oversized.txt".into(),
        identity: ResourceIdentity("oversized".into()),
        bytes,
        media_type: Some("text/plain".into()),
        encoding: Some("unsupported-encoding".into()),
    };
    let mut meter = Meter::new(
        ExecutionBudget {
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
            owned_bytes: resource.bytes.capacity() - 1,
        },
        0,
    )
    .expect("meter initializes below the resolver allocation");

    assert!(matches!(
        decode_xinclude_resource(
            &resource,
            resource.encoding.as_deref(),
            &mut meter,
            XIncludeParseMode::Text,
        ),
        Err(XIncludeFailure::Fatal(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        })) if actual == resource.bytes.capacity()
    ));
}

#[test]
fn resource_decoding_charges_allocated_capacity() {
    // UTF-16 ASCII decodes to fewer logical bytes than the decoder reserves. Both the
    // retained allocation and a parser-owned copy must be represented in peak memory.
    let bytes: Vec<u8> = "a"
        .repeat(4096)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let limits = |owned_bytes| ExecutionBudget {
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
        owned_bytes,
    };

    for parsed_xml in [false, true] {
        let mut meter = Meter::new(limits(usize::MAX), 0).expect("empty source fits");
        let Ok(decoded) = decode_resource_metered_inner(
            &bytes,
            bytes.capacity(),
            Some("UTF-16LE"),
            &mut meter,
            if parsed_xml {
                ResourceDecodeMode::Xml
            } else {
                ResourceDecodeMode::Text
            },
        ) else {
            panic!("UTF-16 resource must decode");
        };
        let parser_owned_bytes = if parsed_xml { decoded.value.len() } else { 0 };
        let expected = bytes
            .capacity()
            .saturating_add(decoded.value.capacity())
            .saturating_add(parser_owned_bytes);
        assert_eq!(
            meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
            expected
        );
    }
}

#[test]
fn source_clone_is_reserved_even_without_retained_source_xml() {
    // Result-like documents have no lexical source bytes, but cloning their semantic arena
    // must still cross the same owned-memory gate before allocation.
    let source = Document::empty(None);
    let limits = ExecutionBudget {
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
        owned_bytes: 0,
    };
    let mut meter = Meter::new(limits, 0).expect("zero lexical bytes fit");
    let options = EvaluatorSourceOptions {
        process_xinclude: false,
        whitespace: Arc::from([]),
        clock: Some(Arc::new(crate::SystemClock)),
    };

    assert!(matches!(
        prepare_evaluator_source(&source, &crate::NoResolver, &mut meter, &options),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn stylesheet_imports_are_reserved_as_one_batch_before_copying() {
    // Principal and module arenas are imported into one execution document. The complete
    // clone footprint must cross OwnedBytes before the first import can allocate anything.
    let principal = Document::parse("<stylesheet/>", None).expect("principal parses");
    let module = Document::parse("<stylesheet><node/></stylesheet>", None).expect("module parses");
    let modules = [ModuleDocument {
        id: StylesheetDocumentId(1),
        document: module,
    }];
    let required = principal
        .estimated_clone_bytes()
        .saturating_add(modules[0].document.estimated_clone_bytes());
    let limits = ExecutionBudget {
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
        owned_bytes: required - 1,
    };
    let mut meter = Meter::new(limits, 0).expect("empty source fits");

    assert!(matches!(
        reserve_stylesheet_imports(&principal, &modules, &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        }) if actual == required
    ));
    assert_eq!(
        meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
        0
    );
}

#[test]
fn set_distinct_reserves_string_values_before_allocating_them() {
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    for value in ["first retained value", "second retained value"] {
        let child = document.create_element("item");
        child.append_child(document.create_text(value));
        root.append_child(child);
        nodes.add(child);
    }
    let mut context = Context::new();
    context.set_string_allocation_limit(1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltSetFunction::Distinct
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("distinct storage must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn set_distinct_charges_descendant_string_traversal_as_extension_work() {
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.append_child(document.create_text("alpha"));
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);
    let mut context = Context::new();
    context.set_extension_work_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltSetFunction::Distinct
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("set:distinct string traversal requires extension work");
    assert!(error.to_string().contains("extension work budget"));
}

#[test]
fn id_nodeset_arguments_stream_through_the_allocation_gate() {
    // id() needs every node's string-value but does not retain those values. It must meter
    // each temporary while avoiding simultaneous retention in an unbounded Vec<String>.
    let package = Package::new();
    let document = package.as_document();
    let container = document.create_element("container");
    let logical_document = document.create_element("document");
    let target = document.create_element("target");
    let argument = document.create_element("ids");
    argument.append_child(document.create_text("target"));
    logical_document.append_child(target);
    logical_document.append_child(argument);
    container.append_child(logical_document);
    document.root().append_child(container);

    let mut indexed = HashMap::new();
    indexed.insert(
        "target".into(),
        typed_path_to(&nodeset::Node::Element(target)),
    );
    let function = IdFunction {
        nodes_by_document: Rc::new(RefCell::new(vec![indexed])),
    };
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(argument);
    let mut context = Context::new();
    context.set_string_allocation_limit("target".len() - 1);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
        &context,
        nodeset::Node::Element(logical_document),
    );

    let error = function
        .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
        .expect_err("id node string-value must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn unparsed_entity_uri_uses_the_dynamic_context_document() {
    // XSLT 1.0 section 12.4 resolves the entity in the document containing the context node,
    // not in the principal document captured when the expression was compiled.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#misc-func
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    document.root().append_child(documents);
    let first = document.create_element("document");
    let second = document.create_element("document");
    documents.append_child(first);
    documents.append_child(second);
    let context_node = document.create_element("external");
    second.append_child(context_node);
    let context = Context::new();
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
        &context,
        nodeset::Node::Element(context_node),
    );
    let function = UnparsedEntityUriFunction {
        documents: Rc::new(RefCell::new(vec![
            HashMap::from([("logo".into(), "principal.png".into())]),
            HashMap::from([("logo".into(), "external.png".into())]),
        ])),
    };

    assert_eq!(
        function
            .evaluate(&evaluation, vec![SxdValue::String("logo".into())])
            .expect("entity URI resolves"),
        SxdValue::String("external.png".into())
    );
}

#[test]
fn unparsed_entity_uri_reserves_the_returned_uri() {
    // The retained entity index owns one URI copy. Returning the XPath string creates a
    // second allocation, which must cross the operation allocation gate first.
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element("documents");
    let logical_document = document.create_element("document");
    document.root().append_child(documents);
    documents.append_child(logical_document);
    let uri = "memory:entity/".repeat(32);
    let function = UnparsedEntityUriFunction {
        documents: Rc::new(RefCell::new(vec![HashMap::from([(
            "logo".into(),
            uri.clone(),
        )])])),
    };
    let mut context = Context::new();
    context.set_string_allocation_limit(uri.len() - 1);
    let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
        &context,
        nodeset::Node::Element(logical_document),
    );

    let error = function
        .evaluate(&evaluation, vec![SxdValue::String("logo".into())])
        .expect_err("returned URI must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn document_function_reserves_explicit_base_selection_before_cloning() {
    // The second argument's effective base is retained for the complete document() call.
    // Reserve that first clone independently of each request constructed later.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    let base = document.create_element("base");
    root.append_child(base);
    document.root().append_child(root);
    let path = typed_path_to(&nodeset::Node::Element(base));
    let base_uri = "memory:base/".repeat(32);
    let function = DocumentFunction {
        resolver: &crate::NoResolver,
        access_error: &RefCell::new(None),
        roots: Rc::new(RefCell::new(HashMap::new())),
        pending: Rc::new(RefCell::new(PendingDocumentRequests::default())),
        node_base_uris: Rc::new(RefCell::new(HashMap::from([(
            path.ordinary().to_vec(),
            Some(base_uri.clone()),
        )]))),
        static_base_uri: None,
        static_document: StylesheetDocumentId::PRINCIPAL,
    };
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(base);
    let mut context = Context::new();
    context.set_string_allocation_limit(base_uri.len() - 1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, nodeset::Node::Element(root));

    let error = function
        .evaluate(
            &evaluation,
            vec![
                SxdValue::String("resource.xml".into()),
                SxdValue::Nodeset(nodes),
            ],
        )
        .expect_err("explicit base URI must cross the allocation gate before cloning");
    assert!(
        context
            .string_allocation_exceeded()
            .is_some_and(|attempted| attempted > base_uri.len()),
        "base URI must be charged on top of node-ordering workspace"
    );
    assert!(error.to_string().contains("allocation budget"));
}
#[test]
fn exslt_replace_charges_candidate_search_work() {
    // A small result can still require attacker-controlled input x search fan-out. Internal
    // candidate tests must consume a typed execution budget before each comparison.
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            xpath_operations: usize::MAX,
            extension_operations: 2,
            pattern_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: usize::MAX,
        },
        0,
    )
    .expect("test meter initializes");
    let searches = vec!["b".into(), "c".into(), "d".into()];

    assert!(matches!(
        replace_exslt_string("a", &searches, &[], &mut meter),
        Err(Error::Budget {
            kind: BudgetKind::ExtensionOperations,
            ..
        })
    ));
}

#[test]
fn uri_encoder_does_not_select_decoder_only_encodings() {
    for label in ["replacement", "ISO-2022-KR"] {
        assert!(
            uri_encoding(Some(label), UriEncodingCapability::Encode).is_none(),
            "accepted decoder-only encoding {label}"
        );
    }
}

#[test]
fn unsupported_exslt_uri_encodings_return_empty_strings() {
    let package = Package::new();
    let document = package.as_document();
    let context = Context::new();
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    for function in [
        ExsltStringFunction::EncodeUri,
        ExsltStringFunction::DecodeUri,
    ] {
        let mut arguments = vec![SxdValue::String("value".into())];
        if matches!(function, ExsltStringFunction::EncodeUri) {
            arguments.push(SxdValue::Boolean(true));
        }
        arguments.push(SxdValue::String("not-a-real-encoding".into()));
        assert_eq!(
            function
                .evaluate(&evaluation, arguments)
                .expect("unsupported encodings produce a successful empty result"),
            SxdValue::String(String::new())
        );
    }
}

#[test]
fn exslt_hashes_charge_cryptographic_work() {
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_extension_work_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    for function in [ExsltCryptoFunction::Md5, ExsltCryptoFunction::Sha1] {
        assert!(
            function
                .evaluate(&evaluation, vec![SxdValue::String("payload".into())])
                .is_err()
        );
    }
}

#[test]
fn math_node_functions_reserve_workspace_before_allocating_it() {
    // All four node-set math functions share ordered-node, numeric, and string-value
    // workspace, which must be rejected before allocation when the budget is exhausted.
    for function in [
        ExsltMathFunction::Max,
        ExsltMathFunction::Min,
        ExsltMathFunction::Highest,
        ExsltMathFunction::Lowest,
    ] {
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        document.root().append_child(root);
        let child = document.create_element("item");
        child.append_child(document.create_text("123456789"));
        root.append_child(child);
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(child);
        let mut context = Context::new();
        context.set_string_allocation_limit(1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = function
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
            .expect_err("math workspace must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }
}

#[test]
fn math_node_functions_charge_descendant_string_traversal_as_extension_work() {
    for function in [
        ExsltMathFunction::Max,
        ExsltMathFunction::Min,
        ExsltMathFunction::Highest,
        ExsltMathFunction::Lowest,
    ] {
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        document.root().append_child(root);
        let child = document.create_element("item");
        child.append_child(document.create_text("123456789"));
        root.append_child(child);
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(child);
        let mut context = Context::new();
        context.set_extension_work_limit(0);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = function
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
            .expect_err("math string traversal must cross the extension-work gate");
        assert!(error.to_string().contains("extension work budget"));
    }
}

#[test]
fn string_align_reserves_output_before_constructing_it() {
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_string_allocation_limit(1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltStringFunction::Align
        .evaluate(
            &evaluation,
            vec![
                SxdValue::String("λ".into()),
                SxdValue::String("........".into()),
                SxdValue::String("center".into()),
            ],
        )
        .expect_err("aligned output must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn padding_obeys_extension_work() {
    // Owned arguments must not bypass work accounting inside extension functions.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_extension_work_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let error = ExsltStringFunction::Padding
        .evaluate(
            &evaluation,
            vec![SxdValue::Number(4096.0), SxdValue::String("λx".into())],
        )
        .expect_err("padding must charge work before rendering");
    assert!(error.to_string().contains("extension work budget"));
}

#[test]
fn set_membership_obeys_extension_work() {
    // A disjoint membership scan must consume extension work even with owned arguments.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_extension_work_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let mut left = nodeset::Nodeset::new();
    left.add(document.root());
    let error = ExsltSetFunction::HasSameNode
        .evaluate(
            &evaluation,
            vec![
                SxdValue::Nodeset(left),
                SxdValue::Nodeset(nodeset::Nodeset::new()),
            ],
        )
        .expect_err("membership scan must charge extension work");
    assert!(error.to_string().contains("extension work budget"));
}

#[test]
fn set_partition_reuses_owned_input_for_empty_boundary() {
    // An empty boundary is the identity operation, so it needs neither a copy nor work.
    let package = Package::new();
    let document = package.as_document();
    for function in [ExsltSetFunction::Leading, ExsltSetFunction::Trailing] {
        let mut left = nodeset::Nodeset::new();
        left.add(document.root());
        let mut context = Context::new();
        context.set_string_allocation_limit(0);
        context.set_extension_work_limit(0);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let value = function
            .evaluate(
                &evaluation,
                vec![
                    SxdValue::Nodeset(left),
                    SxdValue::Nodeset(nodeset::Nodeset::new()),
                ],
            )
            .expect("identity transfer needs no new allocation");
        let SxdValue::Nodeset(nodes) = value else {
            panic!("expected node-set")
        };
        assert_eq!(nodes.size(), 1);
        assert!(nodes.contains(document.root()));
    }
}

#[test]
fn format_number_obeys_picture_work_budget() {
    // Runtime pictures are untrusted even when coercion can move an existing string.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_evaluation_work_limit(0);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let function = FormatNumberFunction {
        formats: Arc::from([]),
        namespaces: Arc::new(Vec::new()),
    };
    let error = function
        .evaluate(
            &evaluation,
            vec![SxdValue::Number(1.25), SxdValue::String("0.0000".into())],
        )
        .expect_err("picture rendering must charge XPath work");
    assert!(error.to_string().contains("work budget"));
}

#[test]
fn format_number_special_values_obey_allocation_budget() {
    // Decimal-format symbols can exceed the picture-based workspace bound.
    let package = Package::new();
    let document = package.as_document();
    for value in [f64::NAN, f64::INFINITY] {
        let mut format = default_decimal_format();
        format.nan = "N".repeat(16_384);
        format.infinity = "I".repeat(16_384);
        let function = FormatNumberFunction {
            formats: Arc::from([format]),
            namespaces: Arc::new(Vec::new()),
        };
        let mut context = Context::new();
        context.set_string_allocation_limit(4096);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        assert!(
            function
                .evaluate(
                    &evaluation,
                    vec![SxdValue::Number(value), SxdValue::String("0".into())]
                )
                .is_err()
        );
        assert!(context.string_allocation_exceeded().is_some());
    }
}

#[test]
fn string_align_scans_obey_extension_work_budget() {
    // Already-owned strings need no coercion but their Unicode scans still
    // consume extension work, including the truncation path.
    let package = Package::new();
    let document = package.as_document();
    for (value, padding) in [("λ", "...."), ("λλλλ", ".")] {
        let mut context = Context::new();
        context.set_extension_work_limit(0);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let error = ExsltStringFunction::Align
            .evaluate(
                &evaluation,
                vec![
                    SxdValue::String(value.into()),
                    SxdValue::String(padding.into()),
                ],
            )
            .expect_err("character scans must cross the extension-work gate");
        assert!(error.to_string().contains("extension work budget"));
    }
}

#[test]
fn string_align_work_boundary_preserves_unicode_output() {
    // Both padding and truncation are character-based, not byte-based;
    // exact work succeeds while one unit less cannot copy the result.
    let package = Package::new();
    let document = package.as_document();
    for (value, padding, expected, required) in [("λ", "....", "λ...", 15), ("λλλλ", ".", "λ", 19)]
    {
        for limit in [required - 1, required] {
            let mut context = Context::new();
            context.set_extension_work_limit(limit);
            let evaluation =
                sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
            let result = ExsltStringFunction::Align.evaluate(
                &evaluation,
                vec![
                    SxdValue::String(value.into()),
                    SxdValue::String(padding.into()),
                ],
            );
            if limit < required {
                assert!(
                    result
                        .expect_err("copy exceeds remaining work")
                        .to_string()
                        .contains("extension work budget")
                );
            } else {
                assert_eq!(
                    result.expect("exact work allowance"),
                    SxdValue::String(expected.into())
                );
            }
        }
    }
}

#[test]
fn string_align_reserves_xpath_coercions_before_materializing_them() {
    // A narrow padding result must not let an untrusted node string bypass the temporary
    // allocation gate before str:align truncates it.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.append_child(document.create_text("untrusted node text"));
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);
    let mut context = Context::new();
    context.set_string_allocation_limit(1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltStringFunction::Align
        .evaluate(
            &evaluation,
            vec![SxdValue::Nodeset(nodes), SxdValue::String(".".into())],
        )
        .expect_err("node string coercion must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn string_padding_reserves_pattern_coercion_before_empty_result() {
    // A zero-length result must not let the node-set pattern bypass the temporary allocation
    // gate before str:padding determines that no output bytes are needed.
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("root");
    root.append_child(document.create_text("untrusted node text"));
    document.root().append_child(root);
    let mut nodes = nodeset::Nodeset::new();
    nodes.add(root);
    let mut context = Context::new();
    context.set_string_allocation_limit(1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

    let error = ExsltStringFunction::Padding
        .evaluate(
            &evaluation,
            vec![SxdValue::Number(0.0), SxdValue::Nodeset(nodes)],
        )
        .expect_err("pattern coercion must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn format_number_reserves_dynamic_pattern_workspace_before_rendering() {
    // The decimal pattern may come from untrusted XPath data. Token and precision buffers
    // must cross the operation allocation gate before the renderer materializes them.
    let package = Package::new();
    let document = package.as_document();
    let mut context = Context::new();
    context.set_string_allocation_limit(1);
    let evaluation =
        sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
    let function = FormatNumberFunction {
        formats: Arc::from([]),
        namespaces: Arc::new(Vec::new()),
    };

    let error = function
        .evaluate(
            &evaluation,
            vec![SxdValue::Number(1.25), SxdValue::String("0.0000".into())],
        )
        .expect_err("decimal rendering workspace must cross the allocation gate");
    assert!(error.to_string().contains("allocation budget"));
}

#[test]
fn format_number_reserves_each_string_conversion_before_materializing_it() {
    // Both dynamic picture and decimal-format name values may require owned XPath string
    // conversions. Their exact byte lengths must cross the gate before either clone occurs.
    let package = Package::new();
    let document = package.as_document();
    let function = FormatNumberFunction {
        formats: Arc::from([]),
        namespaces: Arc::new(Vec::new()),
    };

    for args in [
        vec![SxdValue::Number(1.0), SxdValue::Boolean(true)],
        vec![
            SxdValue::Number(1.0),
            SxdValue::String("0".into()),
            SxdValue::Boolean(true),
        ],
    ] {
        let mut context = Context::new();
        context.set_string_allocation_limit(3);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let error = function
            .evaluate(&evaluation, args)
            .expect_err("four-byte conversion must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
        assert_eq!(context.string_allocation_exceeded(), Some(4));
    }
}

#[test]
fn encode_uri_uses_the_rfc_2396_reserved_set() {
    // RFC 2396 section 2.2 does not classify square brackets as reserved, so EXSLT encodes
    // them even when reserved delimiters are preserved.
    // https://www.rfc-editor.org/rfc/rfc2396#section-2.2
    assert_eq!(
        percent_encode_uri("[]", false, 6, UriEncoding::Standard(encoding_rs::UTF_8))
            .expect("UTF-8 encoding succeeds"),
        "%5B%5D"
    );
}

#[test]
fn uri_functions_reserve_xpath_coercions_before_empty_results() {
    // An EXSLT-defined empty result must not bypass metering of the node string inspected to
    // decide that outcome.
    for (function, text, extra_args) in [
        (
            ExsltStringFunction::EncodeUri,
            "€",
            vec![
                SxdValue::Boolean(true),
                SxdValue::String("ISO-8859-1".into()),
            ],
        ),
        (ExsltStringFunction::DecodeUri, "%", Vec::new()),
    ] {
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text(text));
        document.root().append_child(root);
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(root);
        let mut args = vec![SxdValue::Nodeset(nodes)];
        args.extend(extra_args);
        let mut context = Context::new();
        context.set_string_allocation_limit(0);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = function
            .evaluate(&evaluation, args)
            .expect_err("URI coercion must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }
}
