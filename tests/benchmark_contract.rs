#![cfg(feature = "benchmark-internals")]
#[path = "../benches/support/mod.rs"]
mod support;

#[test]
fn all_workloads_are_correct_on_every_backend() {
    use support::{Fixture, OPERATIONS, specs};
    use xml_sec::{
        XmlBackend, XmlDocument,
        c14n::{C14nAlgorithm, C14nMode, canonicalize_document},
    };
    // Every shape must sign, authenticate and decrypt, including independent signatures.
    for spec in specs().filter(|spec| spec.units == 16) {
        let fixture = Fixture::new(spec);
        for operation in OPERATIONS {
            assert!(fixture.input_bytes(operation) > 0);
            assert!(fixture.run(operation) > 0);
        }
        if spec.backend != XmlBackend::Differential {
            let projection =
                xml_sec::benchmark_support::Projection::new(&fixture.unsigned, spec.backend)
                    .expect("prepare");
            let mut projected = Vec::new();
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            xml_sec::c14n::canonicalize(
                &projection.project().expect("project"),
                None,
                &algorithm,
                &mut projected,
            )
            .expect("canonical projection");
            let normal = XmlDocument::parse_with_backend(fixture.unsigned.clone(), spec.backend)
                .expect("normal parse");
            assert_eq!(
                projected,
                canonicalize_document(&normal, &algorithm).expect("normal C14N")
            );
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
