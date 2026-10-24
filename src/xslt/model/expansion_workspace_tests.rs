use std::fmt::Write;

#[test]
fn unused_literal_declarations_do_not_spend_expansion_output() {
    // Retaining a literal declaration is workspace, not expansion output.
    // No reference is expanded here, even with a zero expansion quota.
    let mut meter = EntityExpansionMeter::new(0);
    let declarations =
        collect_internal_entity_declarations("<!ENTITY unused 'literal'>", &mut meter)
            .expect("literal declaration needs no expansion output");
    assert_eq!(declarations.general["unused"], "literal");
    assert_eq!(meter.used, 0);
}

#[test]
fn coalesced_text_keeps_reference_carriage_returns() {
    // XML 1.0 section 2.11 normalizes literal CR/CRLF, not a CR produced
    // by a character reference. Text and CDATA still coalesce in one node.
    let document = Document::parse("<r>a\r\nb\rc&#13;<![CDATA[d\r\ne]]>f</r>", None)
        .expect("mixed text parses");
    assert_eq!(document.string_value(document.root()), "a\nb\nc\rd\nef");
}

#[test]
fn retained_dtd_declarations_are_admitted_before_materialization() {
    // Unused values, name indexes, spans and ATTLIST vectors remain live
    // while the tiny tree is parsed; output expansion limits cannot pay for them.
    let large = "x".repeat(64 * 1024);
    let mut general = String::new();
    let mut parameter = String::new();
    let mut external = String::new();
    let mut unparsed = String::new();
    let mut attributes = String::new();
    for index in 0..128 {
        write!(general, "<!ENTITY e{index} ''>").expect("String write");
        write!(parameter, "<!ENTITY % p{index} ''>").expect("String write");
        write!(external, "<!ENTITY x{index} SYSTEM 'external'>").expect("String write");
        write!(unparsed, "<!ENTITY u{index} SYSTEM 'asset' NDATA n>").expect("String write");
        write!(attributes, " a{index} CDATA #IMPLIED").expect("String write");
    }
    let subsets = [
        format!("<!ENTITY e '{large}'>"),
        format!("<!ENTITY % p '{large}'>"),
        format!("<!ATTLIST other a CDATA '{large}'>"),
        format!("<!NOTATION n SYSTEM 'n'><!ENTITY u SYSTEM '{large}' NDATA n>"),
        general,
        parameter,
        external,
        format!("<!NOTATION n SYSTEM 'n'>{unparsed}"),
        format!("<!ATTLIST other{attributes}>"),
    ];
    let mut violations = Vec::new();
    for (case, subset) in subsets.into_iter().enumerate() {
        let xml = format!("<!DOCTYPE r [{subset}]><r/>");
        DECLARATION_BYTES.with(|bytes| bytes.set(0));
        let result =
            Document::parse_with_budget(&xml, None, ParseBudget::UNBOUNDED.with_owned_bytes(4096));
        let peak = DECLARATION_BYTES.with(std::cell::Cell::get);
        let refused = matches!(
            result,
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        );
        if !refused || peak > 4096 {
            violations.push((case, peak, refused));
        }
        Document::parse_with_budget(&xml, None, ParseBudget::UNBOUNDED.with_owned_bytes(1 << 22))
            .expect("the same valid declarations fit sufficient workspace");
    }
    assert!(
        violations.is_empty(),
        "declarations escaped workspace: {violations:?}"
    );
}

#[test]
fn initial_root_storage_is_admitted_before_construction() {
    // The initial arena and copied base URI are allocations too, even if
    // the first opening tag would subsequently refuse the tiny workspace.
    let long_base = format!("https://example.test/{}", "x".repeat(8192));
    for (base, limit) in [(None, 0), (Some(long_base.as_str()), 4096)] {
        CREATED_ROOTS.with(|count| count.set(0));
        assert!(matches!(
            Document::parse_with_budget(
                "<r/>",
                base,
                ParseBudget::UNBOUNDED.with_owned_bytes(limit)
            ),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
        CREATED_ROOTS.with(|count| assert_eq!(count.get(), 0));
    }
}

#[test]
fn scalar_text_is_admitted_before_normalization() {
    // Text, CDATA, comments and PI content share the same normalization
    // allocation; none may materialize a large value before workspace admission.
    let large = "x".repeat(64 * 1024);
    let mut materialized = Vec::new();
    for xml in [
        format!("<r>{large}</r>"),
        format!("<r><![CDATA[{large}]]></r>"),
        format!("<r><!--{large}--></r>"),
        format!("<r><?p {large}?></r>"),
    ] {
        NORMALIZED_BYTES.with(|bytes| bytes.set(0));
        let result =
            Document::parse_with_budget(&xml, None, ParseBudget::UNBOUNDED.with_owned_bytes(4096));
        assert!(matches!(
            result,
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
        materialized.push(NORMALIZED_BYTES.with(std::cell::Cell::get));
    }
    assert_eq!(materialized, [0; 4], "normalization ran before admission");
}

#[test]
fn discarded_misc_whitespace_needs_no_owned_copy() {
    // XPath's root node has no whitespace text children; ignored XML Misc
    // must not allocate a document-sized normalization buffer.
    let xml = format!("{}<r/>{}", " \r\n".repeat(8192), " \r\n".repeat(8192));
    NORMALIZED_BYTES.with(|bytes| bytes.set(0));
    Document::parse_with_budget(&xml, None, ParseBudget::UNBOUNDED.with_owned_bytes(4096))
        .expect("tiny tree fits despite ignored whitespace");
    NORMALIZED_BYTES.with(|bytes| assert_eq!(bytes.get(), 0));
}

#[test]
fn live_element_stack_capacity_remains_charged() {
    // The identical projected element needs more live storage when its
    // closing tag is still pending. Semantic staging must not refund frames.
    let xml = "<root>";
    let mut scanner = Scanner::new(xml);
    let Some(Event::Start(start)) = scanner.next_event().expect("opening tag") else {
        panic!("expected start element");
    };
    let measure = |empty| {
        let mut document = Document::empty(None);
        let mut elements = vec![StreamElementFrame {
            node: document.root(),
            lexical_name: None,
        }];
        let budget = ParseBudget::UNBOUNDED;
        let mut meter = StreamParseMeter {
            budget,
            nodes: 1,
            entity_references: 0,
            entity_expansion: EntityExpansionMeter::with_parse_budget(budget),
            namespace_scope_bytes: 0,
            owned_bytes: elements.capacity() * std::mem::size_of::<StreamElementFrame>(),
        };
        push_stream_element(
            &mut document,
            &mut elements,
            &start,
            empty,
            &InternalEntityDeclarations::default(),
            &mut meter,
        )
        .expect("element fits unbounded workspace");
        (meter.retained_bytes(), elements.capacity())
    };
    let (closed_bytes, closed_capacity) = measure(true);
    let (open_bytes, open_capacity) = measure(false);
    assert!(
        open_capacity > closed_capacity,
        "test exercises frame growth"
    );
    assert!(
        open_bytes
            >= closed_bytes
                + (open_capacity - closed_capacity) * std::mem::size_of::<StreamElementFrame>(),
        "live frame capacity was refunded with semantic staging"
    );
}

#[test]
fn lexical_attributes_cannot_materialize_before_workspace_admission() {
    // The lexical event itself owns a vector; refusing semantic staging
    // afterwards cannot pay for that already-materialized opening tag.
    let mut attributes = String::new();
    for index in 0..128 {
        write!(attributes, " a{index}='v'").expect("String write");
    }
    let xml = format!("<root{attributes}/>");
    SCANNED_ATTRIBUTES.with(|count| count.set(0));
    let result =
        Document::parse_with_budget(&xml, None, ParseBudget::UNBOUNDED.with_owned_bytes(128));
    assert!(matches!(
        result,
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    SCANNED_ATTRIBUTES.with(|count| {
        assert_eq!(
            count.get(),
            0,
            "opening-tag vector was materialized before the workspace refusal"
        );
    });
}

#[test]
fn attribute_staging_is_admitted_before_semantic_processing() {
    // Ordinary and DTD-defaulted attributes must not reach QName resolution
    // after constructing attacker-sized staging buffers without workspace.
    for defaults in [false, true] {
        let attributes = (0..64)
            .map(|i| {
                if defaults {
                    format!("a{i} CDATA 'value' ")
                } else {
                    format!("a{i}='value' ")
                }
            })
            .collect::<String>();
        let xml = if defaults {
            format!("<!DOCTYPE root [<!ATTLIST root {attributes} missing:last CDATA 'v'>]><root/>")
        } else {
            format!("<root {attributes} missing:last='v'/>")
        };
        let mut references = 0;
        let mut expansion = EntityExpansionMeter::new(1 << 20);
        let (_, declarations) = internal_general_entities(&xml, &mut references, &mut expansion)
            .expect("declarations parse");
        let mut scanner = Scanner::new(&xml);
        let start = loop {
            if let Event::Empty(start) = scanner
                .next_event()
                .expect("lexical event")
                .expect("root start")
            {
                break start;
            }
        };
        let mut document = Document::empty(None);
        let mut elements = vec![StreamElementFrame {
            node: document.root(),
            lexical_name: None,
        }];
        let budget = ParseBudget::UNBOUNDED.with_owned_bytes(1024);
        let mut meter = StreamParseMeter {
            budget,
            nodes: 1,
            entity_references: 0,
            entity_expansion: EntityExpansionMeter::with_parse_budget(budget),
            namespace_scope_bytes: 0,
            owned_bytes: 0,
        };
        let result = push_stream_element(
            &mut document,
            &mut elements,
            &start,
            true,
            &declarations,
            &mut meter,
        );
        assert!(
            matches!(
                result,
                Err(Error::Budget {
                    kind: BudgetKind::OwnedBytes,
                    ..
                })
            ),
            "defaults={defaults}: {result:?}"
        );
    }
}

#[test]
fn parser_work_stops_entity_materialization_before_append() {
    // A later scan refusal cannot pay for strings already materialized.
    let xml = format!(
        "<!DOCTYPE doc [<!ENTITY e '{}'>]><doc>{}</doc>",
        "x".repeat(2000),
        "&e;".repeat(100)
    );
    APPENDED.with(|bytes| bytes.set(0));
    let report = Document::parse_with_budget_reported(
        &xml,
        None,
        ParseBudget::new(1 << 20, 100, 32, 1000, 1 << 20, 1 << 20)
            .with_owned_bytes(1 << 20)
            .with_parse_work_bytes(25_000),
    );
    assert!(matches!(
        report.outcome,
        Err(Error::Budget {
            kind: BudgetKind::ParseWorkBytes,
            ..
        })
    ));
    APPENDED.with(|bytes| {
        assert!(
            bytes.get() <= 25_000,
            "{} bytes appended before work admission",
            bytes.get()
        );
    });
}

#[test]
fn entity_expansion_cannot_outgrow_parser_workspace() {
    // Expansion is temporary parser storage, not merely a limit on the
    // tree eventually retained after a much larger string was allocated.
    let budget = ParseBudget::new(4096, 100, 32, 100, 4096, 4096).with_owned_bytes(128);
    let mut meter = EntityExpansionMeter::with_parse_budget(budget);
    assert!(matches!(
        meter.charge(129),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}
