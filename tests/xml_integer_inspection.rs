#![cfg(feature = "xmldsig")]

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Parser};
use xml_sec::document::XmlDocument;
use xml_sec::xmldsig::{LexicalSource, extension::*};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

#[test]
fn integer_lexical_space_is_not_a_machine_number_or_canonical_form() {
    // XSD 1.0 3.3.13.1 permits signs, leading zeros and arbitrary finite digit
    // sequences. Canonical-representation restrictions do not limit validity.
    let long = format!("-{}", "1234567890".repeat(1000));
    for (text, valid) in [
        ("0", true),
        ("-0", true),
        ("+0000", true),
        ("000123", true),
        ("9223372036854775808", true),
        (long.as_str(), true),
        (" &#x9;-123&#xD;&#xA; ", true),
        ("", false),
        (" ", false),
        ("+", false),
        ("-", false),
        ("+-1", false),
        ("--1", false),
        ("1.0", false),
        ("1.", false),
        ("1e3", false),
        ("0x10", false),
        ("+ 1", false),
        ("1  2", false),
        ("1&#x9;2", false),
        ("&#xA0;1", false),
        ("&#x0661;", false),
        ("&#xFF11;", false),
        ("1&#x2003;", false),
    ] {
        for source in [
            LexicalSource::SimpleContent,
            LexicalSource::Attribute {
                namespace: None,
                local_name: "number",
            },
        ] {
            let document =
                XmlDocument::parse(format!("<r Id='r' number='{text}'>{text}</r>")).unwrap();
            // Both valid and invalid contiguous values need no normalization
            // allocation, including internal runs of XML whitespace.
            let work = memory(0, 1 << 22);
            document.with_view(|view| {
                let owner = view.node_for_id("r", &[]).unwrap();
                with_scalar(view, owner, source, ScalarType::Integer, &work, |read| {
                    assert_eq!(read.owner, owner);
                    assert_eq!(
                        read.fact,
                        if valid {
                            ScalarFact::Value(ScalarValue::Integer)
                        } else {
                            ScalarFact::Malformed
                        },
                        "{text}"
                    );
                    assert_eq!(work.used(), 0);
                    Ok::<_, ()>(())
                })
                .unwrap();
            });
        }
    }
}

#[test]
fn integer_join_keeps_original_lexical_bytes_and_releases_capacity() {
    // Direct text/CDATA joins happen before schema validation; comments and PIs
    // contribute nothing. A typed visitor refusal releases the temporary join.
    let document =
        XmlDocument::parse("<r Id='r'> &#x9;-00<!--split--><![CDATA[123]]><?ignore x?>\n</r>")
            .unwrap();
    let work = memory(1 << 16, 1 << 20);
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        for refuse in [false, true] {
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::Integer,
                &work,
                |read| {
                    assert_eq!(read.lexical, Some(" \t-00123\n"));
                    assert_eq!(read.fact, ScalarFact::Value(ScalarValue::Integer));
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
    });
}

#[test]
fn integer_preserves_absence_complex_content_and_original_identity() {
    // Scalar validity neither authenticates an owner nor permits stale/foreign
    // ordinals. Nested elements must not be flattened into an integer.
    let mut document = XmlDocument::parse("<r Id='r'>1<child/>2</r>").unwrap();
    let stale = document.with_view(|view| view.node_for_id("r", &[]).unwrap());
    let foreign = XmlDocument::parse("<r Id='r'>12</r>")
        .unwrap()
        .with_view(|view| view.node_for_id("r", &[]).unwrap());
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        for (source, expected) in [
            (LexicalSource::SimpleContent, ScalarFact::ComplexContent),
            (
                LexicalSource::Attribute {
                    namespace: None,
                    local_name: "missing",
                },
                ScalarFact::Absent,
            ),
        ] {
            with_scalar(
                view,
                owner,
                source,
                ScalarType::Integer,
                &memory(0, 10000),
                |read| {
                    assert_eq!(read.lexical, None);
                    assert_eq!(read.fact, expected);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        }
    });
    document.replace_content(stale, "12").unwrap();
    document.with_view(|view| {
        for owner in [stale, foreign] {
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::Integer,
                &memory(0, 10000),
                |_| panic!("invalid owner"),
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
fn integer_admission_enforces_current_local_aggregate_and_join_capacity() {
    // A retained document is not prepayment. Refusal at any current boundary
    // precedes consumer effects, and repeated reads cannot reset local work.
    let document = XmlDocument::parse("<r Id='r'>12<!--split-->34</r>").unwrap();
    for (local, aggregate, capacity) in
        [(0, 100000, 10000), (100000, 0, 10000), (100000, 100000, 0)]
    {
        let work = memory(capacity, aggregate);
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            work,
        );
        let reader = parser.read(&[], 0).unwrap();
        document.with_view(|view| {
            let result = with_scalar(
                view,
                view.node_for_id("r", &[]).unwrap(),
                LexicalSource::SimpleContent,
                ScalarType::Integer,
                &reader.execution(),
                |_| panic!("refusal must precede callback"),
            );
            assert!(matches!(
                result,
                Err::<(), InspectionError<()>>(InspectionError::Processing(ScalarError::Resource(
                    _
                )))
            ));
        });
    }
    document.with_view(|view| {
        let owner = view.node_for_id("r", &[]).unwrap();
        let measured = memory(10000, 100000);
        with_scalar(
            view,
            owner,
            LexicalSource::SimpleContent,
            ScalarType::Integer,
            &measured,
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        let exact = measured.work_used();
        for (local, aggregate, passes) in [
            (exact, exact, 1),
            (exact - 1, exact, 0),
            (exact, exact - 1, 0),
            (exact * 2, exact * 2, 2),
        ] {
            let work = memory(10000, aggregate);
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
                with_scalar(
                    view,
                    owner,
                    LexicalSource::SimpleContent,
                    ScalarType::Integer,
                    &execution,
                    |_| {
                        callbacks += 1;
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            }
            let result = with_scalar(
                view,
                owner,
                LexicalSource::SimpleContent,
                ScalarType::Integer,
                &execution,
                |_| {
                    callbacks += 1;
                    Ok::<_, ()>(())
                },
            );
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
