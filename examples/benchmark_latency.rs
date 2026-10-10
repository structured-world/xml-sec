//! Individual-operation latency samples without an instrumented allocator.
#[path = "../benches/support/mod.rs"]
mod support;

use std::{error::Error, time::Instant};
use support::{Engine, Fixture, OPERATIONS, SHAPES, Spec};
use xml_sec::XmlBackend;

const PHASES: [&str; 4] = [
    "projection",
    "plan_compile",
    "plan_execute",
    "policy_validate",
];

fn percentile(sorted: &[u128], percent: usize) -> u128 {
    sorted[(percent * sorted.len()).div_ceil(100) - 1]
}

fn measure(
    fixture: &Fixture,
    operation: &str,
    projection: Option<&xml_sec::benchmark_support::Projection<'_>>,
    policy: &xml_sec::policy::VerificationPolicy,
) -> (u128, usize) {
    // Per-sample preparation is excluded, just as Divan's with_inputs excludes it.
    let mut plan = match operation {
        "plan_compile" | "plan_execute" => Some(xml_sec::benchmark_support::Plan::new(
            fixture.spec.units.min(64),
        )),
        _ => None,
    };
    if operation == "plan_execute" {
        plan.as_mut().expect("plan").compile();
    }
    let start = Instant::now();
    let bytes = match operation {
        "projection" => {
            std::hint::black_box(
                projection
                    .expect("prepared projection")
                    .project()
                    .expect("project"),
            );
            fixture.unsigned.len()
        }
        "plan_compile" => {
            plan.as_mut().expect("plan").compile();
            0
        }
        "plan_execute" => {
            plan.as_ref().expect("plan").execute();
            0
        }
        "policy_validate" => {
            policy.validate().expect("policy");
            policy
                .check_signature_algorithm(xml_sec::xmldsig::SignatureAlgorithm::RsaSha256)
                .expect("permitted");
            0
        }
        _ => fixture.run(operation),
    };
    std::hint::black_box(&plan);
    (start.elapsed().as_nanos(), std::hint::black_box(bytes))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--list"] {
        for spec in support::specs() {
            let backend = match spec.backend {
                XmlBackend::Xmloxide => "xmloxide",
                XmlBackend::Roxmltree => "roxmltree",
                XmlBackend::Differential => "differential",
            };
            let provider = match spec.engine {
                Engine::RustCrypto => "rustcrypto",
                #[cfg(feature = "aws-lc-fips")]
                Engine::AwsLcFips => "aws-lc-fips",
            };
            for operation in OPERATIONS.into_iter().chain(PHASES) {
                if operation == "projection" && spec.backend == XmlBackend::Differential {
                    continue;
                }
                println!(
                    "{operation} {} {} {backend} {provider}",
                    SHAPES[spec.shape], spec.units
                );
            }
        }
        return Ok(());
    }
    if args.len() != 6 {
        return Err("usage: benchmark_latency <operation> <shape> <units> <backend> <provider> <samples> (or --list)".into());
    }
    let operation = args[0].as_str();
    if !OPERATIONS.contains(&operation) && !PHASES.contains(&operation) {
        return Err("unknown operation".into());
    }
    let shape = SHAPES
        .iter()
        .position(|shape| *shape == args[1])
        .ok_or("unknown shape")?;
    let units = args[2].parse::<usize>()?;
    if ![16, 256].contains(&units) {
        return Err("units must be 16 or 256".into());
    }
    let backend = match args[3].as_str() {
        "xmloxide" => XmlBackend::Xmloxide,
        "roxmltree" => XmlBackend::Roxmltree,
        "differential" => XmlBackend::Differential,
        _ => return Err("unknown backend".into()),
    };
    let engine = match args[4].as_str() {
        "rustcrypto" => Engine::RustCrypto,
        #[cfg(feature = "aws-lc-fips")]
        "aws-lc-fips" => Engine::AwsLcFips,
        _ => return Err("unavailable provider".into()),
    };
    if operation == "projection" && backend == XmlBackend::Differential {
        return Err("projection requires one backend, not differential parsing".into());
    }
    let samples = args[5].parse::<usize>()?;
    if !(1..=100_000).contains(&samples) {
        return Err("samples must be 1..=100000".into());
    }
    let fixture = Fixture::new(Spec {
        shape,
        units,
        backend,
        engine,
    });
    let projection = if operation == "projection" {
        Some(xml_sec::benchmark_support::Projection::new(
            &fixture.unsigned,
            backend,
        )?)
    } else {
        None
    };
    let policy = xml_sec::policy::VerificationPolicy {
        signature_algorithms: Some(
            [xml_sec::xmldsig::SignatureAlgorithm::RsaSha256]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    for _ in 0..8 {
        std::hint::black_box(measure(&fixture, operation, projection.as_ref(), &policy));
    }
    let mut timings = Vec::with_capacity(samples);
    let mut output_bytes = 0;
    for _ in 0..samples {
        let (elapsed, bytes) = measure(&fixture, operation, projection.as_ref(), &policy);
        output_bytes = bytes;
        timings.push(elapsed);
    }
    let total: u128 = timings.iter().sum();
    let raw = timings.clone();
    timings.sort_unstable();
    // Nearest-rank order statistics, not percentiles of batched iteration averages.
    let input_bytes = if ["plan_compile", "plan_execute", "policy_validate"].contains(&operation) {
        0
    } else {
        fixture.input_bytes(operation)
    };
    let amplification = if ["c14n", "sign", "encrypt", "decrypt"].contains(&operation) {
        Some(output_bytes as f64 / input_bytes as f64)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({
            "schema": 1, "operation": operation, "shape": args[1], "units": units,
            "backend": args[3], "provider": args[4], "samples": samples,
            "plan_references": if operation.starts_with("plan_") { Some(units.min(64)) } else { None },
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "allocator": "system-uninstrumented", "setup_and_warmup_excluded": true,
            "validation_included": true, "input_bytes": input_bytes, "output_bytes": output_bytes,
            "output_amplification": amplification, "p50_ns": percentile(&timings, 50),
            "p95_ns": percentile(&timings, 95), "p99_ns": percentile(&timings, 99), "raw_ns": raw,
            "operations_per_second": samples as f64 * 1e9 / total as f64,
            "input_bytes_per_second": input_bytes as f64 * samples as f64 * 1e9 / total as f64
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn nearest_rank_handles_single_and_non_hundred_sample_counts() {
        // Tail percentiles use individual order statistics, including small smoke samples.
        assert_eq!(super::percentile(&[7], 99), 7);
        assert_eq!(super::percentile(&[10, 20, 30], 50), 20);
        assert_eq!(super::percentile(&[10, 20, 30], 95), 30);
        let values: Vec<_> = (1..=100).collect();
        assert_eq!(super::percentile(&values, 99), 99);
    }
}
