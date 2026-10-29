use super::{execute, manifests};
use crate::repo::{Run, Step};
use serde_json::{Value, json};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

const NAMES: [&str; 5] = [
    "structured-asn1",
    "structured-pkix",
    "structured-cms",
    "structured-ltv",
    "structured-xades",
];

fn packages() -> Vec<Value> {
    NAMES
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "version": "0.13.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": format!("/store/registry/src/index/{name}-0.13.0/Cargo.toml"),
            })
        })
        .collect()
}

/// Answers `cargo metadata` with the given packages and records the checks.
struct Cargo {
    packages: Vec<Value>,
    fail_metadata: bool,
    fail_check: bool,
    checks: Vec<Vec<String>>,
}

impl Cargo {
    fn new(packages: Vec<Value>) -> Self {
        Self {
            packages,
            fail_metadata: false,
            fail_check: false,
            checks: Vec::new(),
        }
    }
}

fn exit(failed: bool) -> ExitStatus {
    ExitStatus::from_raw(if failed { 37 << 8 } else { 0 })
}

impl Run for Cargo {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        self.checks.push(step.args.clone());
        Ok(exit(self.fail_check))
    }

    fn stdout(&mut self, _: &Step) -> Result<(ExitStatus, String), String> {
        let metadata = json!({ "packages": self.packages }).to_string();
        Ok((exit(self.fail_metadata), metadata))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        self.stdout(step)
    }
}

#[test]
fn the_published_pkix_and_xades_alloc_graphs_qualify_on_both_non_std_targets() {
    // The high XAdES entry point must qualify CMS and LTV too, not just a host std union.
    let mut cargo = Cargo::new(packages());
    execute(&mut cargo).unwrap();
    assert_eq!(cargo.checks.len(), 4);
    for name in ["structured-pkix", "structured-xades"] {
        for target in ["thumbv7em-none-eabihf", "wasm32-unknown-unknown"] {
            let args = cargo
                .checks
                .iter()
                .find(|args| {
                    args.iter().any(|arg| arg == target)
                        && args.iter().any(|arg| arg.contains(&format!("/{name}-")))
                })
                .unwrap_or_else(|| panic!("{name} {target}"));
            assert!(args.iter().any(|arg| arg == "--locked"));
            assert!(args.iter().any(|arg| arg == "--no-default-features"));
            let features = args.iter().position(|arg| arg == "--features").unwrap();
            assert_eq!(args[features + 1], "alloc");
        }
    }
}

#[test]
fn mixed_generations_duplicate_packages_and_non_registry_substitutes_fail_before_checking() {
    // A successful PKIX-only probe cannot hide another ASN.1 generation or a local patch.
    let mut mixed = packages();
    mixed[0]["version"] = json!("0.11.0");
    let mut local = packages();
    local[2]["source"] = Value::Null;
    let mut path = packages();
    path[1]["manifest_path"] = json!("/work/structured-pkix/Cargo.toml");
    let mut duplicated = packages();
    duplicated.push(packages()[0].clone());
    for shared in [mixed, local, path, packages()[1..].to_vec(), duplicated] {
        assert!(manifests(&json!({ "packages": shared.clone() })).is_err());
        let mut cargo = Cargo::new(shared);
        assert!(execute(&mut cargo).is_err());
        assert_eq!(cargo.checks.len(), 0);
    }
}

#[test]
fn a_target_failure_terminates_qualification_with_its_original_status() {
    // Later successful targets must not conceal an alloc-only compile failure.
    let mut cargo = Cargo {
        fail_check: true,
        ..Cargo::new(packages())
    };
    assert_eq!(execute(&mut cargo).unwrap_err().code, 37);
    assert_eq!(cargo.checks.len(), 1);
}

#[test]
fn a_metadata_process_failure_cannot_be_hidden_by_valid_partial_output() {
    // A failed discovery must stop qualification even when its output parses.
    let mut cargo = Cargo {
        fail_metadata: true,
        ..Cargo::new(packages())
    };
    assert_eq!(execute(&mut cargo).unwrap_err().code, 37);
    assert_eq!(cargo.checks.len(), 0);
}
