//! Timing and allocation runs share workloads but never share measurement artifacts.
mod support;

use support::{Fixture, Spec, specs};

#[cfg(feature = "benchmark-alloc")]
#[global_allocator]
static ALLOCATOR: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

macro_rules! operation {
    ($name:ident) => {
        #[divan::bench(args = specs())]
        fn $name(bencher: divan::Bencher, spec: Spec) {
            debug_assert!(support::OPERATIONS.contains(&stringify!($name)));
            let fixture = Fixture::new(spec);
            bencher
                .counter(divan::counter::BytesCount::new(
                    fixture.input_bytes(stringify!($name)),
                ))
                .bench_local(|| fixture.run(stringify!($name)));
        }
    };
}
operation!(parse);
operation!(c14n);
operation!(sign);
operation!(verify);
operation!(verify_retained);
operation!(verify_reject);
operation!(encrypt);
operation!(decrypt);

/// One `#payload` Reference over `units` KiB of text, so the canonical output
/// dominates: the peak allocation shows whether its bytes are retained.
fn large_reference(units: usize) -> Fixture {
    reference_fixture(support::BULK, units)
}

fn reference_fixture(shape: usize, units: usize) -> Fixture {
    Fixture::new(Spec {
        shape,
        units,
        backend: xml_sec::XmlBackend::default(),
        engine: support::Engine::RustCrypto,
    })
}

/// Many short serializer writes (eight escaped attributes per element) for
/// the per-write cost of feeding the Reference digest.
#[divan::bench]
fn attribute_reference_verify(bencher: divan::Bencher) {
    let shape = support::SHAPES
        .iter()
        .position(|shape| *shape == "attributes")
        .expect("attributes shape");
    let fixture = reference_fixture(shape, 2_048);
    bencher
        .counter(divan::counter::BytesCount::new(
            fixture.input_bytes("verify_retained"),
        ))
        .bench_local(|| fixture.run("verify_retained"));
}

#[divan::bench(args = [256, 4_096])]
fn large_reference_verify(bencher: divan::Bencher, units: usize) {
    let fixture = large_reference(units);
    bencher
        .counter(divan::counter::BytesCount::new(
            fixture.input_bytes("verify_retained"),
        ))
        .bench_local(|| fixture.run("verify_retained"));
}

#[divan::bench(args = [256, 4_096])]
fn large_reference_sign(bencher: divan::Bencher, units: usize) {
    let fixture = large_reference(units);
    bencher
        .counter(divan::counter::BytesCount::new(fixture.input_bytes("sign")))
        .bench_local(|| fixture.run("sign"));
}

#[divan::bench(args = specs().filter(|spec| spec.backend != xml_sec::XmlBackend::Differential))]
fn projection(bencher: divan::Bencher, spec: Spec) {
    let fixture = Fixture::new(spec);
    let projection = xml_sec::benchmark_support::Projection::new(&fixture.unsigned, spec.backend)
        .expect("prepared backend");
    bencher
        .counter(divan::counter::BytesCount::new(fixture.unsigned.len()))
        .bench_local(|| {
            std::hint::black_box(projection.project().expect("project"));
        });
}

/// Signed-document shape for node-set measurements: `elements` siblings with
/// two attributes under two in-scope namespace declarations.
fn node_set_document(elements: usize) -> String {
    use std::fmt::Write as _;
    let mut xml = String::from("<p:root xmlns:p='urn:p' xmlns:a='urn:a'>");
    for index in 0..elements {
        write!(xml, "<p:e id='e{index}' a:k='{index}'>text {index}</p:e>")
            .expect("writing to a String cannot fail");
    }
    xml.push_str("<p:Signature/></p:root>");
    xml
}

#[divan::bench(args = [1_024, 16_384])]
fn node_set_enveloped(bencher: divan::Bencher, elements: usize) {
    let xml = node_set_document(elements);
    let sets = xml_sec::benchmark_support::NodeSets::new(&xml).expect("node-set document");
    bencher.bench_local(|| std::hint::black_box(sets.enveloped()));
}

/// Selected-element strides from half the document to two elements.
const NODE_SET_STRIDES: [usize; 7] = [2, 8, 32, 128, 512, 2_048, 8_192];

#[divan::bench(args = NODE_SET_STRIDES)]
fn node_set_sparse(bencher: divan::Bencher, stride: usize) {
    let xml = node_set_document(16_384);
    let sets = xml_sec::benchmark_support::NodeSets::new(&xml).expect("node-set document");
    bencher.bench_local(|| std::hint::black_box(sets.selection(stride, false)));
}

#[divan::bench(args = NODE_SET_STRIDES)]
fn node_set_dense(bencher: divan::Bencher, stride: usize) {
    let xml = node_set_document(16_384);
    let sets = xml_sec::benchmark_support::NodeSets::new(&xml).expect("node-set document");
    bencher.bench_local(|| std::hint::black_box(sets.selection(stride, true)));
}

#[divan::bench(args = [1, 8, 32, 64])]
fn plan_compile(bencher: divan::Bencher, references: usize) {
    bencher
        .with_inputs(|| xml_sec::benchmark_support::Plan::new(references))
        .bench_values(|mut plan| {
            plan.compile();
            plan
        });
}

#[divan::bench(args = [1, 8, 32, 64])]
fn plan_execute(bencher: divan::Bencher, references: usize) {
    bencher
        .with_inputs(|| {
            let mut plan = xml_sec::benchmark_support::Plan::new(references);
            plan.compile();
            plan
        })
        .bench_values(|plan| plan.execute());
}

#[divan::bench(args = [1, 8, 32, 64])]
fn policy_validate(bencher: divan::Bencher, algorithms: usize) {
    use xml_sec::xmldsig::SignatureAlgorithm;
    // Different input cardinalities are exercised by graph benchmarks; policy validation
    // is measured independently without silently disabling enforcement in the pipelines.
    let policy = xml_sec::policy::VerificationPolicy {
        signature_algorithms: Some([SignatureAlgorithm::RsaSha256].into_iter().collect()),
        ..Default::default()
    };
    bencher.bench(|| {
        for _ in 0..algorithms {
            let policy = std::hint::black_box(&policy);
            policy.validate().expect("policy");
            policy
                .check_signature_algorithm(SignatureAlgorithm::RsaSha256)
                .expect("permitted");
        }
    });
}

#[divan::bench(args = xml_sec::XmlBackend::available())]
fn reject_xml(bencher: divan::Bencher, backend: xml_sec::XmlBackend) {
    bencher.bench_local(|| {
        for input in ["<root><unclosed></root>", "<p:root/>", "<root/><extra/>"] {
            assert!(xml_sec::XmlDocument::parse_with_backend(input, backend).is_err());
        }
    });
}
