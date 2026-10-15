#![cfg(feature = "xmldsig")]

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_asn1::{Encoding, Limits, Parser};
use xml_sec::document::XmlDocument;
use xml_sec::xmldsig::{LexicalSource, extension::*};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}

#[test]
fn attributes_are_exhaustive_expanded_and_separate_from_namespaces() {
    // Default and prefixed namespace bindings must not masquerade as attributes;
    // same-local-name attributes remain separate original expanded names.
    let document = XmlDocument::parse(
        "<root xmlns='urn:root' xmlns:p='urn:p' Id='r' a='one' p:a='two'><child Id='c'/></root>",
    )
    .unwrap();
    let work = account();
    document.with_view(|view| {
        let root = view.node_for_id("r", &[]).unwrap();
        let mut attrs = Vec::new();
        visit_direct_attributes(view, root, &work, |a| {
            assert_eq!(a.owner, root);
            attrs.push((
                a.namespace.map(str::to_owned),
                a.local_name.to_owned(),
                a.value.to_owned(),
            ));
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(
            attrs,
            vec![
                (None, "Id".into(), "r".into()),
                (None, "a".into(), "one".into()),
                (Some("urn:p".into()), "a".into(), "two".into())
            ]
        );
        let child = view.node_for_id("c", &[]).unwrap();
        let mut bindings = Vec::new();
        visit_in_scope_namespaces(view, child, &work, |n| {
            bindings.push((n.prefix.map(str::to_owned), n.uri.to_owned()));
            Ok::<_, ()>(())
        })
        .unwrap();
        assert!(bindings.contains(&(Some("p".into()), "urn:p".into())));
        assert!(bindings.contains(&(None, "urn:root".into())));
        assert!(bindings.contains(&(
            Some("xml".into()),
            "http://www.w3.org/XML/1998/namespace".into()
        )));
    });
}

#[test]
fn visitor_error_and_resource_refusal_are_terminal_before_next_callback() {
    // A caller refusal keeps its original type and stops traversal immediately;
    // zero work must prevent even the first callback.
    let document = XmlDocument::parse("<r Id='r' a='a' b='b'/>").unwrap();
    document.with_view(|view| {
        let root = view.node_for_id("r", &[]).unwrap();
        let mut calls = 0;
        let result = visit_direct_attributes(view, root, &account(), |_| {
            calls += 1;
            Err(17u8)
        });
        assert!(matches!(result, Err(InspectionError::Visitor(17))));
        assert_eq!(calls, 1);
        let exhausted = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let result = visit_direct_attributes(view, root, &exhausted, |_| {
            calls += 1;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(InspectionError::Processing(ScalarError::Resource(
                MemoryError::WorkExceeded
            )))
        ));
        assert_eq!(calls, 1);
    });
}

#[test]
fn namespace_axis_includes_implicit_xml_but_not_an_undeclared_default() {
    // Namespaces in XML 1.0 §§3,6.2: xml is predefined, xmlns='' removes
    // the default binding, and an explicit xml declaration must not duplicate it.
    let document = XmlDocument::parse("<r xmlns='urn:r' xmlns:p='urn:p'><child xmlns='' xmlns:xml='http://www.w3.org/XML/1998/namespace' Id='c'/></r>").unwrap();
    document.with_view(|view| {
        let owner = view.node_for_id("c", &[]).unwrap();
        let mut xml = 0;
        let mut p = 0;
        visit_in_scope_namespaces(view, owner, &account(), |binding| {
            assert!(
                binding.prefix.is_some(),
                "undeclared default is not a binding"
            );
            if binding.prefix == Some("xml") {
                xml += 1;
            }
            if binding.prefix == Some("p") {
                p += 1;
                assert_eq!(binding.uri, "urn:p");
            }
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(xml, 1);
        assert_eq!(p, 1);
    });
}

#[test]
fn exact_datetime_retains_unbounded_year_fraction_zone_and_end_of_day() {
    // Valid XSD 1.0 lexical components must not narrow through time/RFC3339/f64.
    let year = "1234567890123456789012345678901200";
    let fraction = "0123456789".repeat(1000);
    let xml = format!("<r Id='r'>{year}-02-29T23:59:59.{fraction}-14:00</r>");
    let document = XmlDocument::parse(xml).unwrap();
    document.with_view(|view| {
        let root = view.node_for_id("r", &[]).unwrap();
        with_scalar(
            view,
            root,
            LexicalSource::SimpleContent,
            ScalarType::DateTime,
            &account(),
            |read| {
                let ScalarFact::Value(ScalarValue::DateTime(date)) = read.fact else {
                    panic!("{read:?}")
                };
                assert_eq!(date.year_digits, year);
                assert_eq!(date.fraction_digits, Some(fraction.as_str()));
                assert_eq!(date.timezone_minutes, Some(-840));
                assert!(!date.negative_year);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
    });
    for (text, negative, zone) in [
        ("-0001-12-31T24:00:00.000", true, None),
        ("2000-01-01T00:00:00Z", false, Some(0)),
        ("2000-01-01T00:00:00-00:00", false, Some(0)),
    ] {
        let document = XmlDocument::parse(format!("<r Id='r'>{text}</r>")).unwrap();
        document.with_view(|view| {
            with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::DateTime,
                &account(),
                |read| {
                    let ScalarFact::Value(ScalarValue::DateTime(date)) = read.fact else {
                        panic!("{read:?}")
                    };
                    assert_eq!(date.negative_year, negative);
                    assert_eq!(date.timezone_minutes, zone);
                    Ok::<_, ()>(())
                },
            )
            .unwrap()
        });
    }
}

#[test]
fn datetime_schema_boundaries_are_not_rfc3339_or_xsd11() {
    // XSD 1.0 rejects year zero, seconds beyond 60, fractional nonzero end-of-day,
    // invalid Gregorian days, malformed fields and timezone beyond fourteen hours.
    for text in [
        "0000-01-01T00:00:00Z",
        "-0000-01-01T00:00:00Z",
        "+2000-01-01T00:00:00Z",
        "02000-01-01T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2000-02-30T00:00:00Z",
        "2000-00-01T00:00:00Z",
        "2000-01-00T00:00:00Z",
        "2000-01-01T24:00:00.1Z",
        "2000-01-01T24:01:00Z",
        "2000-01-01T00:00:61Z",
        "2000-01-01T00:00:00+14:01",
        "2000-01-01T00:00:00+00:60",
        "2000-01-01T00:00:00.Z",
        "2000-01-01t00:00:00Z",
        "2000-01-01T0:00:00Z",
        "2000-01-01T00:00:00Zx",
    ] {
        let document = XmlDocument::parse(format!("<r Id='r'>{text}</r>")).unwrap();
        document.with_view(|view| {
            with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::DateTime,
                &account(),
                |read| {
                    assert_eq!(read.fact, ScalarFact::Malformed, "{text}");
                    Ok::<_, ()>(())
                },
            )
            .unwrap()
        });
    }
}

#[test]
fn presence_complex_content_unsupported_and_schema_normalization_are_distinct() {
    // Text/CDATA joins retain original text while schema collapse is a separate
    // view. Comments/PIs do not contribute characters; elements are not flattened.
    for (content, expected) in [
        (
            " a<![CDATA[  b]]><!--ignore--><?x y?> c ",
            ScalarFact::Value(ScalarValue::AnyUri("a b c")),
        ),
        ("<child/>", ScalarFact::ComplexContent),
    ] {
        let document = XmlDocument::parse(format!("<r Id='r'>{content}</r>")).unwrap();
        let work = account();
        document.with_view(|view| {
            let root = view.node_for_id("r", &[]).unwrap();
            with_scalar(
                view,
                root,
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &work,
                |read| {
                    assert_eq!(read.fact, expected);
                    if read.lexical.is_some() {
                        assert_eq!(read.lexical, Some(" a  b c "));
                    }
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
            with_scalar(
                view,
                root,
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "missing",
                },
                ScalarType::Id,
                &work,
                |read| {
                    assert_eq!(read.fact, ScalarFact::Absent);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
            with_scalar(
                view,
                root,
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "Id",
                },
                ScalarType::Other {
                    namespace: "urn:unsupported",
                    local_name: "type",
                },
                &work,
                |read| {
                    assert_eq!(read.fact, ScalarFact::Unsupported);
                    assert_eq!(read.lexical, Some("r"));
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        });
    }
}

#[test]
fn id_lexical_facts_never_register_an_attribute() {
    // Valid ID spelling alone must not alter the operation's ID index.
    for (text, valid) in [
        ("  token  ", true),
        ("name:part", false),
        ("a b", false),
        ("1x", false),
        ("", false),
        ("caf&#xE9;", true),
        ("&#xA0;a", false),
    ] {
        let document = XmlDocument::parse(format!("<r Id='r' custom='{text}'/>")).unwrap();
        document.with_view(|view| {
            let root = view.node_for_id("r", &[]).unwrap();
            with_scalar(
                view,
                root,
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "custom",
                },
                ScalarType::Id,
                &account(),
                |read| {
                    assert_eq!(
                        matches!(read.fact, ScalarFact::Value(ScalarValue::Id(_))),
                        valid,
                        "{text}"
                    );
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
            assert!(view.node_for_id("token", &[]).is_none());
        });
    }
}

#[test]
fn anyuri_applies_schema_escaping_not_url_policy() {
    // Relative/empty/Unicode/spaces are legal; escaping never repairs malformed
    // percent triplets or invented schemes, nor implies dereferencing.
    for (text, valid) in [
        ("", true),
        ("../some path", true),
        ("../caf&#xE9;/a&#x9; b", true),
        ("urn:example:test", true),
        ("urn:[abc]", false),
        ("urn:]abc", false),
        ("urn:%5Babc%5D", true),
        ("urn:%5Dabc", true),
        ("urn:a[bc]", true),
        ("urn:?a", true),
        ("urn:&#xE9;", true),
        ("https://[::1]:443/a?b#c", true),
        ("http://[::192.009.005.005]/", true),
        ("http://[0:0:0:0:0:ffff:192.000.002.001]/", true),
        ("http://[::192.999.005.005]/", false),
        ("http://[::192.0009.005.005]/", false),
        ("http://[192.009.005.005::]/", false),
        ("http://[::000.000.000.000]/", true),
        ("http://[1:2:3:4:5:6:7:8]/", true),
        ("http://[1:2:3:4:5:6:7]/", false),
        ("http://[1::2::3]/", false),
        ("http://[:::]/", false),
        ("http://[1:2:3:4:5:6::192.9.5.5]/", false),
        ("a%20b", true),
        ("a%", false),
        ("a%xx", false),
        ("1bad:x", false),
        ("a#b#c", false),
        ("http://[xyz]/", false),
        ("urn:", false),
    ] {
        let document = XmlDocument::parse(format!("<r Id='r'>{text}</r>")).unwrap();
        document.with_view(|view| {
            with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &account(),
                |read| {
                    assert_eq!(
                        matches!(read.fact, ScalarFact::Value(ScalarValue::AnyUri(_))),
                        valid,
                        "{text}"
                    );
                    Ok::<_, ()>(())
                },
            )
            .unwrap()
        });
    }
}

#[test]
fn scalar_refuses_both_live_work_ceilings_and_join_memory_before_callback() {
    // Retained XML is not prepayment for future scalar reads; either current
    // local or aggregate Work and actual join storage can refuse the callback.
    let document = XmlDocument::parse("<r Id='r'>a<!--split--><![CDATA[b]]>c</r>").unwrap();
    for (local, aggregate, memory) in [(0, 100000, 10000), (100000, 0, 10000), (100000, 100000, 0)]
    {
        let account = Arc::new(MemoryAccount::new(memory, aggregate));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            Memory::new(account),
        );
        let reader = parser.read(&[], 0).unwrap();
        document.with_view(|view| {
            let result = with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &reader.execution(),
                |_| panic!("refusal must precede consumer"),
            );
            assert!(matches!(
                result,
                Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Resource(
                    _
                )))
            ));
        });
    }
}

#[test]
fn scalar_join_admits_byte_work_before_requesting_capacity() {
    // Even with no allocation allowance, insufficient byte work must be the
    // first refusal: an input-sized join cannot precede its work admission.
    let document = XmlDocument::parse(format!(
        "<r Id='r'>{}<!--split-->{}</r>",
        "a".repeat(2048),
        "b".repeat(2048)
    ))
    .unwrap();
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 8192)));
    document.with_view(|view| {
        let result = with_scalar(
            view,
            view.node_for_id("r", &[]).unwrap(),
            LexicalSource::SimpleContent,
            ScalarType::AnyUri,
            &memory,
            |_| Ok::<_, ()>(()),
        );
        assert!(
            matches!(
                result,
                Err(InspectionError::Processing(ScalarError::Resource(
                    MemoryError::WorkExceeded
                )))
            ),
            "{result:?}"
        );
        assert_eq!(memory.used(), 0);
    });
}

#[test]
fn scalar_join_admits_trailing_child_visits_before_requesting_capacity() {
    // Comments after two text fragments still require a second traversal.
    // Its known work must refuse before a join can request unavailable memory.
    let document = XmlDocument::parse(format!(
        "<r Id='r'>a<!--split-->b{}</r>",
        "<!--tail-->".repeat(64)
    ))
    .unwrap();
    for (local, aggregate) in [(100, 100000), (100000, 100)] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        document.with_view(|view| {
            let result = with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &reader.execution(),
                |_| panic!("work refusal must precede callback"),
            );
            assert!(
                matches!(
                    result,
                    Err::<(), InspectionError<()>>(InspectionError::Processing(
                        ScalarError::Resource(MemoryError::WorkExceeded)
                    ))
                ),
                "{result:?}"
            );
            assert_eq!(memory.used(), 0);
        });
    }
}

#[test]
fn xsd10_leap_second_lexical_components_are_not_posix_time() {
    // XSD 1.0 Appendix D.1 permits 60, unlike XSD 1.1 and libxml2.
    // This lexical receipt neither certifies a UTC adjustment nor normalizes it.
    for text in [
        "2016-12-31T23:59:60.123Z",
        "2017-01-01T00:59:60+01:00",
        "2016-12-31T23:59:60",
    ] {
        let document = XmlDocument::parse(format!("<r Id='r'>{text}</r>")).unwrap();
        document.with_view(|view| {
            with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::DateTime,
                &account(),
                |read| {
                    let ScalarFact::Value(ScalarValue::DateTime(date)) = read.fact else {
                        panic!("{read:?}")
                    };
                    assert_eq!(date.second, 60);
                    assert_eq!(read.lexical, Some(text));
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        });
    }
}

#[test]
fn borrowed_inspection_needs_no_owned_memory() {
    // Original contiguous text, attributes and namespace bindings are borrowed;
    // inspection must not allocate merely to visit already retained XML.
    let document = XmlDocument::parse("<r Id='r'>2000-02-29T00:00:00Z</r>").unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 100000)));
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        visit_direct_attributes(view, owner, &work, |_| Ok::<_, ()>(())).unwrap();
        visit_in_scope_namespaces(view, owner, &work, |_| Ok::<_, ()>(())).unwrap();
        with_scalar(
            view,
            owner,
            LexicalSource::SimpleContent,
            ScalarType::DateTime,
            &work,
            |read| {
                assert!(matches!(
                    read.fact,
                    ScalarFact::Value(ScalarValue::DateTime(_))
                ));
                assert_eq!(work.used(), 0);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
        assert_eq!(work.used(), 0);
    });
}

#[test]
fn unsupported_schema_does_not_allocate_unused_normalization() {
    // No schema value is produced for an unknown datatype. Its original
    // retained spelling must not be copied into a discarded collapsed value.
    let document = XmlDocument::parse("<r Id='r' a='one  two'/>").unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 100000)));
    document.with_view(|view| {
        with_scalar(
            view,
            view.node_for_id("r", &[]).unwrap(),
            LexicalSource::Attribute {
                namespace: None,
                local_name: "a",
            },
            ScalarType::Other {
                namespace: "urn:unknown",
                local_name: "type",
            },
            &work,
            |read| {
                assert_eq!(read.fact, ScalarFact::Unsupported);
                assert_eq!(read.lexical, Some("one  two"));
                assert_eq!(work.used(), 0);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
    });
}

#[test]
fn malformed_simple_content_does_not_allocate_a_partial_join() {
    // A nested element is a structural fact, not a reason to build a text
    // prefix and fail its memory allocation before reporting complex content.
    let document = XmlDocument::parse("<r Id='r'>a<!--split-->b<child/></r>").unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 100000)));
    document.with_view(|view| {
        with_scalar(
            view,
            view.node_for_id("r", &[]).unwrap(),
            LexicalSource::SimpleContent,
            ScalarType::AnyUri,
            &work,
            |read| {
                assert_eq!(read.fact, ScalarFact::ComplexContent);
                Ok::<_, ()>(())
            },
        )
        .unwrap()
    });
}

#[test]
fn foreign_and_stale_owners_fail_before_visitation() {
    // An identical node ordinal from another document or earlier generation
    // cannot be used to read a different original scalar.
    let mut document = XmlDocument::parse("<r Id='r'>text</r>").unwrap();
    let stale = document.with_view(|view| view.node_for_id("r", &[]).unwrap());
    document.replace_content(stale, "new").unwrap();
    let foreign = XmlDocument::parse("<r Id='r'/>")
        .unwrap()
        .with_view(|view| view.node_for_id("r", &[]).unwrap());
    document.with_view(|view| {
        for owner in [stale, foreign] {
            let result = visit_direct_attributes(view, owner, &account(), |_| {
                panic!("invalid identity must precede visitor")
            });
            assert!(matches!(
                result,
                Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Document(
                    _
                )))
            ));
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &account(),
                |_| panic!("invalid identity must precede reader"),
            );
            assert!(matches!(
                result,
                Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Document(
                    _
                )))
            ));
        }
    });
}

#[test]
fn scoped_join_and_collapse_release_capacity_and_repeated_reads_consume_work() {
    // Joined original text and normalized value remain charged during the
    // callback, release on success/refusal, and never reset current Work.
    let document = XmlDocument::parse("<r Id='r'> a<!--split-->  b </r>").unwrap();
    let work = account();
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        let before = work.work_used();
        for refuse in [false, true] {
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::AnyUri,
                &work,
                |read| {
                    assert!(work.used() > 0);
                    assert_eq!(read.fact, ScalarFact::Value(ScalarValue::AnyUri("a b")));
                    if refuse { Err(91u8) } else { Ok(()) }
                },
            );
            if refuse {
                assert!(matches!(result, Err(InspectionError::Visitor(91))));
            } else {
                result.unwrap();
            }
            assert_eq!(work.used(), 0);
        }
        assert!(work.work_used() > before);
    });
}
