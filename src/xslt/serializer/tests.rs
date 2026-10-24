use super::{
    EncodingCounter, OutputDefinition, OutputEncoding, OutputMethod, RenderBuffer, RenderTask,
    push_cdata_range, serialize, serialize_fragment,
};
use crate::budget::Meter;
use crate::{BudgetKind, Document, ExecutionBudget, ExpandedName, NodeKind};

#[test]
fn output_definition_accounts_for_retained_cdata_hash_capacity() {
    let plain = OutputDefinition::default();
    let mut with_cdata = plain.clone();
    with_cdata.cdata_section_elements = std::collections::HashSet::with_capacity(64);
    with_cdata
        .cdata_section_elements
        .insert(ExpandedName::new(None::<String>, "e"));
    let storage = crate::budget::retained_hash_storage::<ExpandedName>(
        with_cdata.cdata_section_elements.capacity(),
    );
    assert!(
        with_cdata.owned_bytes()
            >= plain
                .owned_bytes()
                .saturating_add(storage)
                .saturating_add(1),
        "CDATA hash buckets and owned name strings must be reserved before cloning"
    );
}

fn serialize_audit_document(
    document: &Document,
    definition: &OutputDefinition,
) -> crate::Result<Vec<u8>> {
    let limits = ExecutionBudget {
        source_bytes: 0,
        external_documents: 0,
        recursion_depth: 128,
        xpath_evaluations: 0,
        xpath_operations: 100_000,
        extension_operations: 0,
        pattern_evaluations: 0,
        template_applications: 0,
        sort_comparisons: 0,
        key_entries: 0,
        result_nodes: 0,
        serialized_bytes: 100_000,
        messages: 0,
        owned_bytes: 100_000,
    };
    let mut meter = Meter::new(limits, 0)?;
    serialize(document, definition, &mut meter).map(|output| output.bytes)
}

#[test]
fn html_inference_requires_no_preceding_nonwhitespace_text() {
    // XSLT 1.0 section 16: an html element alone does not determine the default method.
    let mut document = Document::parse("<html><br/></html>", None).expect("XML");
    let root = document.root();
    let text = document.push(
        root,
        NodeKind::Text {
            value: "X".into(),
            disable_output_escaping: false,
        },
        None,
    );
    document
        .node_mut(root)
        .expect("root")
        .children
        .rotate_right(1);
    let definition = OutputDefinition {
        omit_xml_declaration: true,
        explicit: super::ExplicitOutput {
            indent: true,
            ..super::ExplicitOutput::default()
        },
        ..OutputDefinition::default()
    };
    assert_eq!(
        serialize_audit_document(&document, &definition).expect("serializes"),
        b"X<html><br/></html>"
    );
    if let NodeKind::Text { value, .. } = &mut document.node_mut(text).expect("text").kind {
        *value = " ".into();
    }
    assert_eq!(
        serialize_audit_document(&document, &definition).expect("serializes"),
        b" <html><br></html>"
    );
}

#[test]
fn html_namespaced_attributes_preserve_xml_values() {
    // Namespaced elements retain XML escaping even under the HTML output method.
    let document = Document::parse("<e xmlns='urn:e' a='&lt;&#10;'/>", None).expect("XML");
    let definition = OutputDefinition {
        method: OutputMethod::Html,
        explicit: super::ExplicitOutput {
            method: true,
            ..super::ExplicitOutput::default()
        },
        ..OutputDefinition::default()
    };
    let output = serialize_audit_document(&document, &definition).expect("serializes");
    assert!(
        String::from_utf8(output)
            .expect("UTF-8")
            .contains("a=\"&lt;&#10;\"")
    );
}

#[test]
fn html_uri_attributes_preserve_leading_whitespace() {
    // XSLT 1.0 section 16.2 permits URI escaping, not trimming the result-tree value.
    let document = Document::parse("<a href='  relative'/>", None).expect("XML");
    let definition = OutputDefinition {
        method: OutputMethod::Html,
        explicit: super::ExplicitOutput {
            method: true,
            ..super::ExplicitOutput::default()
        },
        ..OutputDefinition::default()
    };

    assert_eq!(
        serialize_audit_document(&document, &definition).expect("serializes"),
        b"<a href=\"%20%20relative\"></a>\n"
    );
}

#[test]
fn standalone_and_doctype_output_require_a_document() {
    // XSLT erratum E4 strengthens the shape contract only when these declarations are emitted.
    let mut document = Document::parse("<a/>", None).expect("XML");
    let first = document.node(document.root()).expect("root").children[0];
    let extra = document.node(first).expect("element").kind.clone();
    document.push(document.root(), extra, None);
    for definition in [
        OutputDefinition {
            standalone: Some(true),
            ..OutputDefinition::default()
        },
        OutputDefinition {
            standalone: Some(false),
            ..OutputDefinition::default()
        },
        OutputDefinition {
            doctype_system: Some("urn:example:dtd".into()),
            ..OutputDefinition::default()
        },
    ] {
        assert!(matches!(
            serialize_audit_document(&document, &definition),
            Err(crate::Error::Serialization(_))
        ));
    }
    assert!(serialize_audit_document(&document, &OutputDefinition::default()).is_ok());
    let suppressed = OutputDefinition {
        standalone: Some(true),
        omit_xml_declaration: true,
        ..OutputDefinition::default()
    };
    assert!(serialize_audit_document(&document, &suppressed).is_ok());
}

#[test]
fn xml11_line_end_characters_are_referenced_in_all_text_modes() {
    // Literal NEL/LS normalize on XML 1.1 input; escaping must preserve the result value.
    let document = Document::parse("<e a='&#x85;&#x2028;'>&#x85;&#x2028;</e>", None).expect("XML");
    let mut definition = OutputDefinition {
        version: Some("1.1".into()),
        ..OutputDefinition::default()
    };
    for cdata in [false, true] {
        if cdata {
            definition
                .cdata_section_elements
                .insert(ExpandedName::new(None::<String>, "e"));
        }
        let output = String::from_utf8(
            serialize_audit_document(&document, &definition).expect("serializes"),
        )
        .expect("UTF-8");
        assert!(!output.contains(['\u{85}', '\u{2028}']), "{output}");
        assert!(
            output.contains("&#x85;") && output.contains("&#x2028;"),
            "{output}"
        );
    }
}

#[test]
fn inferred_html_output_does_not_clone_caller_owned_output_metadata() {
    // Method inference changes two scalar properties; a large caller-owned CDATA set must not
    // be copied into the execution allocation budget merely to apply those overrides.
    let document = Document::parse("<html/>", None).expect("document parses");
    let mut definition = OutputDefinition::default();
    definition
        .cdata_section_elements
        .extend((0..1024).map(|index| ExpandedName::new(None::<String>, format!("item-{index}"))));
    let traversal_workspace = 4 * std::mem::size_of::<RenderTask>();
    let limits = ExecutionBudget {
        source_bytes: 0,
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
        serialized_bytes: 64,
        messages: 0,
        owned_bytes: 64 + traversal_workspace,
    };
    let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");

    let output = serialize(&document, &definition, &mut meter)
        .expect("inferred method borrows the output definition");
    assert_eq!(output.bytes, b"<html></html>\n");
}

#[test]
fn counting_buffer_rejects_repeated_indentation_beyond_the_encoded_limit() {
    // Indentation is emitted without a temporary repeated String, and counting stops before
    // work can exceed the configured serialized-output ceiling.
    let mut output = RenderBuffer::counting(
        EncodingCounter::new(&OutputEncoding::Utf8),
        crate::BudgetKind::SerializedBytes,
        0,
        6,
    );
    output.push_str("<a>");
    assert!(output.push_repeated(b' ', 4).is_err());
}

#[test]
fn legacy_encoding_bounds_character_representability_cache() {
    let encoding = OutputEncoding::new("windows-1252").expect("encoding is registered");
    for character in (0x20..0x220).filter_map(char::from_u32) {
        let _ = encoding.represents(character);
    }
    assert!(encoding.represents('€'));
    let OutputEncoding::Other { representable, .. } = encoding else {
        panic!("windows-1252 uses the cached encoding path");
    };
    assert_eq!(
        representable
            .iter()
            .filter(|slot| slot.get().is_some())
            .count(),
        representable.len()
    );
}

#[test]
fn decoder_only_output_encodings_are_rejected() {
    // encoding_rs exposes these labels for decoding compatibility but cannot encode output;
    // accepting them here would reach an internal unreachable branch during serialization.
    for label in ["replacement", "ISO-2022-KR"] {
        assert!(
            matches!(OutputEncoding::new(label), Err(crate::Error::Serialization(message)) if message.contains(label)),
            "accepted decoder-only encoding {label}"
        );
    }
}

#[test]
fn cdata_range_preserves_terminators_split_across_text_nodes() {
    // A result tree may retain adjacent text nodes. CDATA serialization must treat their
    // concatenation as one stream so a cross-node `]]>` cannot escape into XML markup.
    let mut document = Document::parse("<out/>", None).expect("result document parses");
    let parent = document
        .nodes()
        .find_map(|(id, node)| matches!(node.kind, NodeKind::Element { .. }).then_some(id))
        .expect("result element exists");
    document.push(
        parent,
        NodeKind::Text {
            value: "left]]".into(),
            disable_output_escaping: false,
        },
        None,
    );
    document.push(
        parent,
        NodeKind::Text {
            value: "><tag/>right".into(),
            disable_output_escaping: false,
        },
        None,
    );
    let mut output = RenderBuffer::Text(String::new());
    push_cdata_range(
        &document,
        parent,
        0,
        2,
        "1.0",
        &OutputEncoding::Utf8,
        &mut output,
    )
    .expect("CDATA range serializes");

    let serialized = format!("<out>{}</out>", output.into_string());
    let reparsed = Document::parse(&serialized, None).expect("serialized CDATA reparses");
    assert_eq!(reparsed.string_value(reparsed.root()), "left]]><tag/>right");
}

#[test]
fn transcoding_reserves_utf8_and_encoded_buffers_concurrently() {
    // UTF-16 allocation overlaps the rendered UTF-8 workspace, and the returned encoding and
    // media-type metadata remain live beside the encoded bytes in SerializedOutput.
    let payload = "a".repeat(512);
    let document =
        Document::parse(&format!("<root>{payload}</root>"), None).expect("document parses");
    let definition = OutputDefinition {
        method: OutputMethod::Text,
        encoding: "UTF-16".into(),
        ..OutputDefinition::default()
    };
    let encoded_bytes = 2 + payload.len() * 2;
    let concurrent_buffers = payload.len() + encoded_bytes;
    debug_assert!(concurrent_buffers > payload.len() + 4 * std::mem::size_of::<RenderTask>());
    let base_limits = ExecutionBudget {
        source_bytes: 0,
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
        serialized_bytes: encoded_bytes,
        messages: 0,
        owned_bytes: 0,
    };
    let succeeds = |owned_bytes| {
        let limits = ExecutionBudget {
            owned_bytes,
            ..base_limits
        };
        let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
        serialize(&document, &definition, &mut meter).is_ok()
    };
    let mut rejected = 0;
    let mut accepted = concurrent_buffers * 2;
    while rejected + 1 < accepted {
        let candidate = rejected + (accepted - rejected) / 2;
        if succeeds(candidate) {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    assert_eq!(accepted, concurrent_buffers);

    let limits = ExecutionBudget {
        owned_bytes: accepted,
        ..base_limits
    };
    let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
    let output = serialize(&document, &definition, &mut meter)
        .expect("encoded bytes and retained metadata fit exactly");
    assert_eq!(output.bytes.len(), encoded_bytes);
    assert_eq!(
        meter
            .usage(BudgetKind::OwnedBytes)
            .expect("owned-byte usage is available")
            .0,
        encoded_bytes + "UTF-16".len() + "text/plain".len()
    );
}

#[test]
fn traversal_workspace_crosses_the_owned_memory_gate() {
    // Output storage is not the serializer's only live allocation: even a minimal iterative
    // traversal must reserve its task stack before rendering starts.
    let document = Document::parse("<root/>", None).expect("document parses");
    let limits = ExecutionBudget {
        source_bytes: 0,
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
        owned_bytes: "<root></root>".len(),
    };
    let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");

    assert!(matches!(
        serialize_fragment(&document, &mut meter),
        Err(crate::Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn namespace_workspace_tracks_depth_instead_of_sibling_count() {
    // Namespace scopes are live only along the current ancestor path. A wide result must reuse
    // that workspace rather than retaining one allocation charge for every completed sibling.
    fn minimum_workspace(source: &str) -> usize {
        let document = Document::parse(source, None).expect("document parses");
        let limits = ExecutionBudget {
            source_bytes: 0,
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
        };
        let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
        let output = serialize_fragment(&document, &mut meter).expect("fixture serializes");
        let mut rejected = output.len().saturating_sub(1);
        let mut accepted = output.len().saturating_add(64 * 1024);
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            let limits = ExecutionBudget {
                owned_bytes: candidate,
                ..limits
            };
            let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
            if serialize_fragment(&document, &mut meter).is_ok() {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted - output.len()
    }

    let narrow = "<root><item xmlns:p='urn:test'/></root>";
    let wide = format!("<root>{}</root>", "<item xmlns:p='urn:test'/>".repeat(512));
    assert_eq!(minimum_workspace(narrow), minimum_workspace(&wide));
}
