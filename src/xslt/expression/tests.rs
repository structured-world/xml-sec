use super::{
    has_unprefixed_function_call, innermost_namespaced_call, metered_unprefixed_call_arguments,
};
use crate::budget::{ExecutionBudget, Meter};

fn metered_calls<'a>(source: &'a str, name: &str) -> Vec<(usize, &'a str)> {
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
    .expect("test meter");
    let (calls, reservation) = metered_unprefixed_call_arguments(source, name, &mut meter)
        .expect("call scan fits the test budget");
    meter.release_owned_bytes(reservation);
    calls
}

#[test]
fn namespaced_call_discovery_is_iterative_at_extreme_depth() {
    let source = format!("{}1{}", "x:f(".repeat(1_000), ")".repeat(1_000));
    let call = innermost_namespaced_call(
        &source,
        &[("x".into(), "urn:test".into())],
        |namespace, local| namespace == "urn:test" && local == "f",
    )
    .expect("nested call is discovered");
    assert_eq!(&source[call.start..call.end], "x:f(1)");
}

#[test]
fn namespaced_call_discovery_scans_mixed_nesting_once() {
    // Extension discovery must remain linear when accepted and ordinary calls are interleaved.
    let source =
        format!("plain({}x:target(')'))", "x:outer(plain(".repeat(1_000)) + &"))".repeat(1_000);
    let call = innermost_namespaced_call(
        &source,
        &[("x".into(), "urn:test".into())],
        |namespace, _| namespace == "urn:test",
    )
    .expect("innermost accepted call is discovered");
    assert_eq!(&source[call.start..call.end], "x:target(')')");
}

#[test]
fn namespaced_call_discovery_accepts_complete_ncname_grammar() {
    // XML NameStartChar includes U+200C; extension discovery must share
    // the same QName grammar as stylesheet compilation.
    let prefix = "\u{200c}";
    let source = format!("{prefix}:function()");
    let call = innermost_namespaced_call(
        &source,
        &[(prefix.into(), "urn:test".into())],
        |namespace, local| namespace == "urn:test" && local == "function",
    )
    .expect("valid Unicode-prefixed call is discovered");
    assert_eq!(&source[call.start..call.end], source);
}

#[test]
fn unprefixed_call_discovery_excludes_qualified_names() {
    // A prefixed extension function whose local name matches a core function
    // must not activate the core function's compile-time or runtime behavior.
    assert_eq!(metered_calls("x:key()", "key"), Vec::<(usize, &str)>::new());
    assert_eq!(metered_calls("key()", "key").len(), 1);
}

#[test]
fn function_arguments_preserve_non_xpath_whitespace() {
    // XPath 1.0 section 3.7 limits ExprWhitespace to XML S; NBSP remains expression input.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let calls = metered_calls("key(\u{a0}'value')", "key");
    assert_eq!(calls[0].1, "\u{a0}'value'");
}

#[test]
fn unprefixed_call_detection_ignores_literals_and_qualified_names() {
    // Pattern context selection must react only to an actual unprefixed function call.
    assert!(has_unprefixed_function_call("current ()/item", "current"));
    assert!(!has_unprefixed_function_call("'current()'", "current"));
    assert!(!has_unprefixed_function_call("x:current()", "current"));
    assert!(!has_unprefixed_function_call("current(", "current"));
    assert!(has_unprefixed_function_call(
        "current(('current())'))",
        "current"
    ));
}

#[test]
fn unprefixed_boolean_detection_does_not_retain_matches() {
    // Boolean capability checks must scan a caller-sized expression without retaining every
    // lexical call; the first complete match is sufficient.
    let source = "ordinary(),".repeat(100_000) + "current()";
    assert!(has_unprefixed_function_call(&source, "current"));
}

#[test]
fn unprefixed_call_discovery_is_linear_at_extreme_depth() {
    // Deep caller-controlled expressions must not trigger one complete rescan per call.
    let source = format!("{}1{}", "key(".repeat(1_000), ")".repeat(1_000));
    let calls = metered_calls(&source, "key");
    assert_eq!(calls.len(), 1_000);
    assert_eq!(calls[0].0, 0);
    let innermost = calls.last().expect("nested expression has calls");
    assert_eq!(innermost.1, "1");
}

#[test]
fn key_call_scan_reserves_temporary_stack_before_growing() {
    let mut budget = ExecutionBudget {
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
        owned_bytes: 0,
    };
    let mut meter = Meter::new(budget, 0).expect("zero-size source");
    assert!(metered_unprefixed_call_arguments("key('name', /)", "key", &mut meter).is_err());
    budget.owned_bytes = 1024;
    let mut meter = Meter::new(budget, 0).expect("meter");
    let (calls, reservation) =
        metered_unprefixed_call_arguments("key('name', /)", "key", &mut meter)
            .expect("sufficient budget");
    assert_eq!(calls, [(0, "'name', /")]);
    meter.release_owned_bytes(reservation);
}
