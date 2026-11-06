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

/// Signing through `SignatureBuilder`, as an application signs each new
/// message: every operation builds the template with an escaped `Object`
/// (`units` copies of its text) that a second Reference signs (enveloping),
/// checks it against the policy, then digests `#payload` and `#object` and
/// signs inside the document's transaction. Parsing the input is excluded.
#[divan::bench(args = [16, 256])]
fn builder_sign(bencher: divan::Bencher, units: usize) {
    use xml_sec::XmlDocument;
    use xml_sec::c14n::{C14nAlgorithm, C14nMode};
    use xml_sec::xmldsig::{
        DigestAlgorithm, ObjectBuilder, ObjectContent, ReferenceBuilder, RsaSigningKey,
        SignContext, SignatureAlgorithm, SignatureBuilder,
    };
    let shape = support::SHAPES
        .iter()
        .position(|shape| *shape == "saml")
        .expect("saml shape");
    let unsigned = reference_fixture(shape, units).unsigned;
    let key =
        RsaSigningKey::from_pkcs8_pem(include_str!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("test key");
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .ns_prefix("ds")
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"))
    .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#object"))
    .add_object(
        ObjectBuilder::new(ObjectContent::Text(
            "deterministic object text & escaping ".repeat(units),
        ))
        .id("object"),
    );
    let sign = |document: &mut XmlDocument| {
        SignContext::new(&key)
            .sign_document_with_builder(document, &builder)
            .expect("builder signing");
    };
    let parse = || XmlDocument::parse(&*unsigned).expect("unsigned document");
    let mut expected = parse();
    sign(&mut expected);
    let expected = expected.into_xml();
    assert!(expected.contains("URI=\"#object\""), "the Object is signed");
    bencher
        .counter(divan::counter::BytesCount::new(unsigned.len()))
        .with_inputs(parse)
        .bench_local_values(|mut document| {
            sign(&mut document);
            assert_eq!(document.as_xml(), expected);
            document
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
