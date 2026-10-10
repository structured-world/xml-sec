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
