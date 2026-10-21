//! Standalone-engine latency; phase preparation is outside timing.
#[path = "../benches/support/xslt.rs"]
mod support;

use std::{error::Error, fs, time::Instant};
use support::{Fixture, PHASES};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--export" {
        fs::create_dir(&args[1])?;
        for shape in ["items", "amplification"] {
            for size in [16, 256] {
                let fixture = Fixture::new(shape, size);
                let base = format!("{}/{shape}-{size}", args[1]);
                fs::write(format!("{base}.xml"), fixture.source)?;
                fs::write(format!("{base}.xsl"), fixture.stylesheet)?;
                fs::write(format!("{base}.expected"), fixture.expected)?;
            }
        }
        return Ok(());
    }
    if args.len() != 4 || !PHASES.contains(&args[0].as_str()) {
        return Err("usage: xslt_latency PHASE SHAPE SIZE SAMPLES | --export DIRECTORY".into());
    }
    let phase = &args[0];
    let size = args[2].parse::<usize>()?;
    if ![16, 256].contains(&size) || !["items", "amplification"].contains(&args[1].as_str()) {
        return Err("unsupported fixture".into());
    }
    let count = args[3].parse::<usize>()?;
    if !(1..=100_000).contains(&count) {
        return Err("samples must be 1..=100000".into());
    }
    let fixture = Fixture::new(&args[1], size);
    let sheet = fixture.compile();
    let source = fixture.parse();
    let result_tree_bytes = fixture.tree(&sheet, &source).result_tree_bytes();
    assert_eq!(
        fixture.execute(&sheet, &source).serialized.bytes,
        fixture.expected
    );
    let mut samples = Vec::with_capacity(count);
    for iteration in 0..count + 3 {
        // Preparing a tree for serialization must not enter the phase timer.
        let tree = (phase == "serialize").then(|| fixture.tree(&sheet, &source));
        let start = Instant::now();
        let bytes = match phase.as_str() {
            "compile" => {
                std::hint::black_box(fixture.compile());
                None
            }
            "tree" => {
                std::hint::black_box(fixture.tree(&sheet, &source));
                None
            }
            "serialize" => Some(tree.expect("prepared tree").serialize()?.bytes),
            "retained" => Some(fixture.execute(&sheet, &source).serialized.bytes),
            "end_to_end" => Some(
                fixture
                    .execute(&fixture.compile(), &fixture.parse())
                    .serialized
                    .bytes,
            ),
            _ => unreachable!(),
        };
        let elapsed = start.elapsed().as_nanos();
        if let Some(bytes) = bytes {
            assert_eq!(bytes, fixture.expected);
        }
        if iteration >= 3 {
            samples.push(elapsed);
        }
    }
    println!(
        "{}",
        serde_json::json!({"engine":"xml-sec", "phase":phase, "shape":args[1], "size":size,
        "samples_ns":samples, "source_bytes":fixture.source.len(), "stylesheet_bytes":fixture.stylesheet.len(),
        "output_bytes":fixture.expected.len(), "result_tree_accounted_bytes":result_tree_bytes,
        "retained_stylesheet_bytes":sheet.retained_bytes()})
    );
    Ok(())
}
