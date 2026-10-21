#[path = "../benches/support/xslt.rs"]
mod support;
use support::Fixture;

#[global_allocator]
static ALLOCATOR: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

macro_rules! phases {
    ($name:ident) => {
        #[divan::bench(args = [16, 256])]
        fn $name(bencher: divan::Bencher, size: usize) {
            let fixture = Fixture::new(stringify!($name), size);
            let sheet = fixture.compile();
            let source = fixture.parse();
            assert_eq!(
                fixture.execute(&sheet, &source).serialized.bytes,
                fixture.expected
            );
            let _ = support::PHASES;
            bencher.bench_local(|| {
                std::hint::black_box(fixture.execute(&sheet, &source));
            });
        }
    };
}
phases!(items);
phases!(amplification);

#[divan::bench(args = [16, 256])]
fn end_to_end(bencher: divan::Bencher, size: usize) {
    let fixture = Fixture::new("items", size);
    bencher.bench_local(|| {
        std::hint::black_box(fixture.execute(&fixture.compile(), &fixture.parse()))
    });
}

#[divan::bench(args = [16, 256])]
fn compile(bencher: divan::Bencher, size: usize) {
    let fixture = Fixture::new("items", size);
    bencher.bench_local(|| std::hint::black_box(fixture.compile()));
}

#[divan::bench(args = [16, 256])]
fn tree(bencher: divan::Bencher, size: usize) {
    let fixture = Fixture::new("items", size);
    let sheet = fixture.compile();
    let source = fixture.parse();
    bencher.bench_local(|| std::hint::black_box(fixture.tree(&sheet, &source)));
}

#[divan::bench(args = [16, 256])]
fn serialize(bencher: divan::Bencher, size: usize) {
    let fixture = Fixture::new("items", size);
    let sheet = fixture.compile();
    let source = fixture.parse();
    bencher
        .with_inputs(|| fixture.tree(&sheet, &source))
        .bench_values(|tree| tree.serialize().expect("serialize"));
}
