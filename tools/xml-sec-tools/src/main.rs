//! Repository tooling: one subcommand per responsibility.

mod bench;
mod check_features;
mod ci_blocks;
mod coverage;
mod documentation;
mod donor_fixtures;
mod fuzz_security;
mod hardening;
mod kernel_examples;
mod libxslt_fixtures;
mod pedantic_lints;
mod pkcs11;
mod publish_crate;
mod repo;
mod security_corpus;
mod shared_pkix;
#[cfg(test)]
mod test_support;
mod wasm_c14n;
#[cfg(test)]
mod workflow_contracts;
mod xades;
mod xslt_conformance;

use repo::Failure;
use std::process::ExitCode;

const USAGE: &str = "usage: xml-sec-tools COMMAND [ARGS...]
commands:
  bench-cli NEW_OUTPUT_DIR [SAMPLES] [--heap]
  bench-compare NEW_OUTPUT_DIR [SAMPLES] [--heap]
  bench-dashboard COMPARISON_DIR NEW_SITE_DIR
  bench-identity NAME=VALUE...
  bench-latency OUTPUT_DIR [SAMPLES] [EXTRA_FEATURES]
  bench-library COMPARISON_DIR SAMPLES
  bench-regression BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR
  bench-xslt NEW_OUTPUT [SAMPLES]
  check-features PROFILE [all|lint|test|doc]
  ci-blocks BLOCK
  competitor-lock
  documentation [all|docs]
  donor-fixtures [--xmlenc-corpora | PATH...]
  fuzz-security TARGET|asan [smoke|campaign|replay] [--cache-managed]
  hardening [all|dependencies|safety|coverage] [EVIDENCE_DIR]
  kernel-examples roxmltree|xmloxide ROOT SOURCE...
  libxslt-fixtures [--check]
  pedantic-lints TOOLCHAIN...
  pkcs11-tests MODULE [--workspace] ARGS...
  publish-crate PACKAGE
  security-corpus check|report|import LIBXML2_SOURCE DATA_DIR LIBXSLT_SOURCE
  shared-pkix
  wasm-c14n
  xades check|corpus|dss|binding|package ...
  xslt-conformance [--cache-managed]";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result: Result<(), Failure> = match args.next().as_deref() {
        Some("bench-cli") => bench::cli::run(args),
        Some("bench-compare") => bench::compare::run(args),
        Some("bench-dashboard") => bench::dashboard::run(args),
        Some("bench-identity") => bench::identity::run(args),
        Some("bench-latency") => bench::latency::run(args),
        Some("bench-library") => bench::library::run(args),
        Some("bench-regression") => bench::regression::run(args),
        Some("bench-xslt") => bench::xslt::run(args),
        Some("check-features") => check_features::run(args),
        Some("ci-blocks") => ci_blocks::run(args).map_err(Failure::from),
        Some("competitor-lock") => bench::compare::run_lock(args),
        Some("documentation") => documentation::run(args),
        Some("donor-fixtures") => donor_fixtures::run(args),
        Some("fuzz-security") => fuzz_security::run(args),
        Some("hardening") => hardening::run(args),
        Some("kernel-examples") => kernel_examples::run(args).map_err(Failure::from),
        Some("libxslt-fixtures") => libxslt_fixtures::run(args),
        Some("pedantic-lints") => pedantic_lints::run(args),
        Some("pkcs11-tests") => pkcs11::run(args),
        Some("publish-crate") => publish_crate::run(args),
        Some("security-corpus") => security_corpus::run(args),
        Some("shared-pkix") => shared_pkix::run(args),
        Some("wasm-c14n") => wasm_c14n::run(args),
        Some("xades") => xades::run(args),
        Some("xslt-conformance") => xslt_conformance::run(args),
        _ => Err(Failure {
            code: 2,
            message: USAGE.into(),
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if !failure.message.is_empty() {
                eprintln!("{}", failure.message);
            }
            ExitCode::from(failure.code)
        }
    }
}
