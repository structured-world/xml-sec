//! Datatype checks of values that are not read from a document.

#![cfg(feature = "xmldsig")]

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::xmldsig::extension::{
    InspectionError, ScalarError, ScalarFact, ScalarType, ScalarValue, with_lexical_scalar,
};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}

fn fact(text: &str, datatype: ScalarType<'_>) -> String {
    with_lexical_scalar(text, datatype, &account(), |fact| {
        Ok::<_, ()>(format!("{fact:?}"))
    })
    .expect("check completes")
}

#[test]
fn values_use_the_same_kernels_as_document_scalars() {
    // A writer validates what it is about to emit with the reader's rules, so
    // a value accepted here reads back as the same fact.
    assert_eq!(
        fact("  sig-1 ", ScalarType::Id),
        format!("{:?}", ScalarFact::Value(ScalarValue::Id("sig-1")))
    );
    assert_eq!(fact("1sig", ScalarType::Id), "Malformed");
    assert_eq!(
        fact("#sig\n value", ScalarType::AnyUri),
        format!("{:?}", ScalarFact::Value(ScalarValue::AnyUri("#sig value")))
    );
    assert_eq!(fact("+42", ScalarType::Integer), "Value(Integer)");
    assert_eq!(fact("4 2", ScalarType::Integer), "Malformed");
}

#[test]
fn date_times_keep_an_absent_timezone_distinct_from_utc() {
    // XSD 1.0 §3.2.7: a dateTime without a timezone is not UTC. A producer that
    // requires a zoned instant must be able to tell the two apart.
    let timezone = |text| {
        with_lexical_scalar(text, ScalarType::DateTime, &account(), |fact| {
            Ok::<_, ()>(match fact {
                ScalarFact::Value(ScalarValue::DateTime(value)) => Some(value.timezone_minutes),
                _ => None,
            })
        })
        .expect("check completes")
    };
    assert_eq!(timezone("2026-10-18T12:00:00Z"), Some(Some(0)));
    assert_eq!(timezone("2026-10-18T12:00:00+02:00"), Some(Some(120)));
    assert_eq!(timezone("2026-10-18T12:00:00"), Some(None));
    assert_eq!(timezone("2026-13-18T12:00:00Z"), None);
}

#[test]
fn a_qname_needs_a_namespace_scope() {
    // Without an element there are no in-scope prefixes to expand, so the
    // check reports no semantics instead of guessing.
    assert_eq!(fact("p:local", ScalarType::QName), "Unsupported");
}

#[test]
fn exhausted_work_refuses_before_the_callback() {
    // The value's passes are admitted first; a refusal never reaches the caller.
    let exhausted = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let mut called = false;
    let result = with_lexical_scalar("value", ScalarType::Id, &exhausted, |_| {
        called = true;
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(InspectionError::Processing(ScalarError::Resource(
            MemoryError::WorkExceeded
        )))
    ));
    assert!(!called);
}

#[test]
fn the_callback_error_is_returned_unchanged() {
    // The caller's refusal keeps its own type.
    let result = with_lexical_scalar("value", ScalarType::Id, &account(), |_| Err::<(), _>(7u8));
    assert!(matches!(result, Err(InspectionError::Visitor(7))));
}
