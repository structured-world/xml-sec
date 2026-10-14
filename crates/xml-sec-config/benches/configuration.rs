use xml_sec::{policy::PolicyCompileContext, provider::default_provider};
use xml_sec_config::{Configuration, LoadLimits};

#[global_allocator]
static ALLOCATOR: divan::AllocProfiler = divan::AllocProfiler::system();

const SOURCE: &str = "schema_version=1\n[profiles.system]\nbase='Modern'\n[profiles.tenant]\nextends='system'\n[profiles.tenant.verification.resources]\nmax_xml_nodes=10000";

fn main() {
    divan::main();
}

#[divan::bench]
fn parse() {
    divan::black_box(
        Configuration::from_str(divan::black_box(SOURCE), LoadLimits::default()).unwrap(),
    );
}

#[divan::bench]
fn compile(bencher: divan::Bencher) {
    let config = Configuration::from_str(SOURCE, LoadLimits::default()).unwrap();
    let context = PolicyCompileContext {
        external_resources: false,
        target_evidence: false,
    };
    bencher.bench_local(|| {
        divan::black_box(
            config
                .compile("tenant", default_provider(), &context, None)
                .unwrap(),
        )
    });
}

#[divan::bench]
fn effective_output(bencher: divan::Bencher) {
    let config = Configuration::from_str(SOURCE, LoadLimits::default()).unwrap();
    let policy = config
        .compile(
            "tenant",
            default_provider(),
            &PolicyCompileContext {
                external_resources: false,
                target_evidence: false,
            },
            None,
        )
        .unwrap();
    bencher.bench_local(|| divan::black_box(policy.to_toml().unwrap()));
}
