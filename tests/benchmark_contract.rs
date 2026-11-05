#![cfg(feature = "benchmark-internals")]
#[path = "../benches/support/mod.rs"]
mod support;

#[test]
fn all_workloads_are_correct_on_every_backend() {
    use support::{Fixture, OPERATIONS, specs};
    // Every shape must sign, authenticate and decrypt, including independent signatures.
    for spec in specs().filter(|spec| spec.units == 16) {
        let fixture = Fixture::new(spec);
        for operation in OPERATIONS {
            assert!(fixture.input_bytes(operation) > 0);
            assert!(fixture.run(operation) > 0);
        }
    }
}

#[test]
fn benchmark_graphs_execute_after_compilation() {
    // Exercise actual graph admission/evidence, not a mock implementation of the planner.
    for width in [1, 8, 32, 64] {
        let mut plan = xml_sec::benchmark_support::Plan::new(width);
        plan.compile();
        plan.execute();
    }
}

#[test]
fn rejection_workloads_are_invalid_on_every_backend() {
    // Rejection benchmarks must not accidentally time successful parses.
    for backend in xml_sec::XmlBackend::available() {
        for input in ["<root><unclosed></root>", "<p:root/>", "<root/><extra/>"] {
            assert!(xml_sec::XmlDocument::parse_with_backend(input, backend).is_err());
        }
    }
}
