#![cfg(feature = "xmldsig")]

use std::fmt::Write as _;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Parser};
use xml_sec::document::XmlDocument;
use xml_sec::xmldsig::{LexicalSource, extension::*};

const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const XML: &str = "http://www.w3.org/XML/1998/namespace";

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn named<'a>(namespace: Option<&'a str>, local_name: &'a str) -> ScalarFact<'a> {
    ScalarFact::Value(ScalarValue::QName(QNameValue {
        namespace,
        local_name,
    }))
}

#[test]
fn qname_lexical_and_binding_failures_are_distinct_without_normalization_storage() {
    // XSD QName syntax is independent of prefix resolution; malformed names
    // must not allocate collapse buffers or masquerade as missing bindings.
    for (text, expected) in [
        ("Name", named(None, "Name")),
        (" p:Type ", named(Some("urn:p"), "Type")),
        ("&#x9;p:Type&#xD;&#xA;", named(Some("urn:p"), "Type")),
        ("p:名", named(Some("urn:p"), "名")),
        ("名:型", named(Some("urn:unicode"), "型")),
        ("é:Type", named(Some("urn:composed"), "Type")),
        ("e\u{301}:Type", ScalarFact::UnboundPrefix("e\u{301}")),
        ("P:Type", ScalarFact::UnboundPrefix("P")),
        ("xml:space", named(Some(XML), "space")),
        ("missing:Type", ScalarFact::UnboundPrefix("missing")),
        ("xmlns:Type", ScalarFact::UnboundPrefix("xmlns")),
        ("", ScalarFact::Malformed),
        (" ", ScalarFact::Malformed),
        (":Type", ScalarFact::Malformed),
        ("p:", ScalarFact::Malformed),
        ("p::Type", ScalarFact::Malformed),
        ("p:Type:Other", ScalarFact::Malformed),
        ("1p:Type", ScalarFact::Malformed),
        ("p:1Type", ScalarFact::Malformed),
        ("1Type", ScalarFact::Malformed),
        ("p :Type", ScalarFact::Malformed),
        ("p: Type", ScalarFact::Malformed),
        ("p:&#x9;Type", ScalarFact::Malformed),
        ("Name  Other", ScalarFact::Malformed),
        ("&#xA0;Name", ScalarFact::Malformed),
        ("p:&#x301;Type", ScalarFact::Malformed),
    ] {
        let document = XmlDocument::parse(format!(
            "<r Id='r' xmlns:p='urn:p' xmlns:名='urn:unicode' xmlns:é='urn:composed' value='{text}'>{text}</r>"
        ))
        .unwrap();
        for source in [
            LexicalSource::SimpleContent,
            LexicalSource::Attribute {
                namespace: None,
                local_name: "value",
            },
        ] {
            let work = memory(0, 1 << 20);
            document.with_view(|view| {
                let owner = view.node_for_id("r", &[]).unwrap();
                with_scalar(view, owner, source, ScalarType::QName, &work, |read| {
                    assert_eq!(read.owner, owner);
                    assert_eq!(read.fact, expected, "{text}");
                    assert_eq!(work.used(), 0);
                    Ok::<_, ()>(())
                })
                .unwrap();
            });
        }
    }
}

#[test]
fn qname_uses_original_inherited_shadowed_default_and_undeclared_bindings() {
    // QName *values* use the default namespace; rebinding and xmlns=""
    // belong to the original owner, not the root or a later reader context.
    for (declarations, text, expected) in [
        ("", "p:Type", named(Some("urn:outer-p"), "Type")),
        (
            "xmlns:p='urn:inner-p'",
            "p:Type",
            named(Some("urn:inner-p"), "Type"),
        ),
        ("", "Type", named(Some("urn:outer"), "Type")),
        (
            "xmlns='urn:inner'",
            "Type",
            named(Some("urn:inner"), "Type"),
        ),
        ("xmlns=''", "Type", named(None, "Type")),
        ("xmlns=''", "xml:lang", named(Some(XML), "lang")),
    ] {
        let document = XmlDocument::parse(format!(
            "<r xmlns='urn:outer' xmlns:p='urn:outer-p'><child Id='child' {declarations} value='{text}'>{text}</child></r>"
        ))
        .unwrap();
        document.with_view(|view| {
            let owner = view.node_for_id("child", &[]).unwrap();
            for source in [
                LexicalSource::SimpleContent,
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "value",
                },
            ] {
                with_scalar(
                    view,
                    owner,
                    source,
                    ScalarType::QName,
                    &memory(0, 100_000),
                    |read| {
                        assert_eq!(read.fact, expected);
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            }
        });
    }
}

#[test]
fn xsi_attribute_selection_and_qname_value_do_not_share_default_namespace_rules() {
    // Match xsi:type by its attribute expanded name. The QName value then
    // uses default namespace context without loading schemaLocation hints.
    let document = XmlDocument::parse(format!(
        "<r Id='r' xmlns='urn:default' xmlns:i='{XSI}' xmlns:f='urn:foreign' i:type=' Type ' f:type='absent:Other' i:nil=' 1 ' i:schemaLocation='urn:remote https://untrusted.invalid/schema.xsd'/>"
    ))
    .unwrap();
    let work = memory(0, 100_000);
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        with_scalar(
            view,
            owner,
            LexicalSource::Attribute {
                namespace: Some(XSI),
                local_name: "type",
            },
            ScalarType::QName,
            &work,
            |read| {
                assert_eq!(read.lexical, Some(" Type "));
                assert_eq!(read.fact, named(Some("urn:default"), "Type"));
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert_eq!(
            boolean_attribute(view, owner, Some(XSI), "nil", &work).unwrap(),
            BooleanAttribute::Value(true)
        );
        let mut hints = 0;
        visit_direct_attributes(view, owner, &work, |attribute| {
            if attribute.namespace == Some(XSI) && attribute.local_name == "schemaLocation" {
                assert_eq!(
                    attribute.value,
                    "urn:remote https://untrusted.invalid/schema.xsd"
                );
                hints += 1;
            }
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(hints, 1);
        assert_eq!(work.used(), 0);
    });
}

#[test]
fn qname_join_preserves_original_spelling_and_releases_on_typed_refusal() {
    // Split QName components need one accounted lexical join, not another XML
    // parse. Neither successful nor refused callbacks may retain its capacity.
    let document = XmlDocument::parse(
        "<r Id='r' xmlns:p='urn:p'> p<!--split-->:<![CDATA[Type]]><?ignore x?> </r>",
    )
    .unwrap();
    let work = memory(10000, 100_000);
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        for refuse in [false, true] {
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::QName,
                &work,
                |read| {
                    assert_eq!(read.lexical, Some(" p:Type "));
                    assert_eq!(read.fact, named(Some("urn:p"), "Type"));
                    assert!(work.used() > 0);
                    if refuse { Err(37u8) } else { Ok(()) }
                },
            );
            if refuse {
                assert!(matches!(result, Err(InspectionError::Visitor(37))));
            } else {
                result.unwrap();
            }
            assert_eq!(work.used(), 0);
        }
        let no_storage = memory(0, 100_000);
        assert!(matches!(
            with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::QName,
                &no_storage,
                |_| panic!("join must refuse")
            ),
            Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Resource(
                MemoryError::LimitExceeded
            )))
        ));
    });
}

#[test]
fn qname_preserves_absence_complex_content_and_foreign_or_stale_identity() {
    // A lexical QName never authenticates its owner or flattens child elements.
    let mut document = XmlDocument::parse("<r Id='r'>Type<child/></r>").unwrap();
    let stale = document.with_view(|view| view.node_for_id("r", &[]).unwrap());
    let foreign = XmlDocument::parse("<r Id='r'>Type</r>")
        .unwrap()
        .with_view(|view| view.node_for_id("r", &[]).unwrap());
    document.with_view(|view| {
        for (source, expected) in [
            (LexicalSource::SimpleContent, ScalarFact::ComplexContent),
            (
                LexicalSource::Attribute {
                    namespace: Some(XSI),
                    local_name: "type",
                },
                ScalarFact::Absent,
            ),
        ] {
            with_scalar(
                view,
                stale,
                source,
                ScalarType::QName,
                &memory(0, 10000),
                |read| {
                    assert_eq!(read.fact, expected);
                    assert_eq!(read.lexical, None);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        }
    });
    document.replace_content(stale, "Type").unwrap();
    document.with_view(|view| {
        for owner in [stale, foreign] {
            assert!(matches!(
                with_scalar(
                    view,
                    owner,
                    LexicalSource::SimpleContent,
                    ScalarType::QName,
                    &memory(0, 10000),
                    |_| panic!("identity must refuse")
                ),
                Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Document(
                    _
                )))
            ));
        }
    });
}

#[test]
fn qname_namespace_lookup_charges_current_local_and_aggregate_work_exactly_once() {
    // A retained namespace table is not prepayment for future lookup. Admit
    // prefix comparison and returned URI bytes before the scoped callback.
    let uri = format!("urn:{}", "namespace".repeat(256));
    let mut declarations = String::new();
    for index in 0..64 {
        write!(declarations, " xmlns:p{index}='urn:p{index}'")
            .expect("writing to a String cannot fail");
    }
    let document = XmlDocument::parse(format!(
        "<r Id='r' {declarations} xmlns:last='{uri}' value='last:Type'/>"
    ))
    .unwrap();
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        let source = LexicalSource::Attribute {
            namespace: None,
            local_name: "value",
        };
        let measured = memory(0, 100_000);
        with_scalar(view, owner, source, ScalarType::QName, &measured, |read| {
            assert_eq!(read.fact, named(Some(&uri), "Type"));
            Ok::<_, ()>(())
        })
        .unwrap();
        let exact = measured.work_used();
        assert!(exact > uri.len(), "namespace lookup must be charged");
        for (local, aggregate, passes) in [
            (exact, exact, 1),
            (exact - 1, exact, 0),
            (exact, exact - 1, 0),
            (0, exact, 0),
            (exact, 0, 0),
            (exact * 2, exact * 2, 2),
        ] {
            let work = memory(0, aggregate);
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: u64::try_from(local).unwrap(),
                    ..Limits::default()
                },
                work,
            );
            let reader = parser.read(&[], 0).unwrap();
            let execution = reader.execution();
            let mut callbacks = 0;
            for _ in 0..passes {
                with_scalar(view, owner, source, ScalarType::QName, &execution, |_| {
                    callbacks += 1;
                    Ok::<_, ()>(())
                })
                .unwrap();
            }
            let result = with_scalar(view, owner, source, ScalarType::QName, &execution, |_| {
                callbacks += 1;
                Ok::<_, ()>(())
            });
            assert!(matches!(
                result,
                Err(InspectionError::Processing(ScalarError::Resource(
                    MemoryError::WorkExceeded
                )))
            ));
            assert_eq!(callbacks, passes);
            assert_eq!(execution.memory().used(), 0);
        }
    });
}

#[test]
fn qname_uses_retained_namespace_context_across_deep_boundary_inputs() {
    // Depth must not select another QName grammar or lose inherited namespace
    // provenance. Queries use the retained owner's axis, not ancestor reparsing.
    for depth in 126..=130 {
        let mut xml = String::new();
        for index in 0..depth {
            write!(xml, "<n xmlns:p{index}='urn:p{index}'>")
                .expect("writing to a String cannot fail");
        }
        xml.push_str("<leaf Id='leaf' xmlns='urn:leaf' value='p0:Type'/>");
        for _ in 0..depth {
            xml.push_str("</n>");
        }
        let document = XmlDocument::parse(xml).unwrap();
        document.with_view(|view| {
            let owner = view.node_for_id("leaf", &[]).unwrap();
            let work = memory(0, 100_000);
            with_scalar(
                view,
                owner,
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "value",
                },
                ScalarType::QName,
                &work,
                |read| {
                    assert_eq!(read.owner, owner);
                    assert_eq!(read.fact, named(Some("urn:p0"), "Type"));
                    assert_eq!(work.used(), 0);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        });
    }
}
