//! `xslt-conformance [--cache-managed]`: the XSLT conformance gate. It admits
//! only an xmlsec1 oracle the installer built, with its XSLT transform, then
//! runs the engine suites and the reciprocal oracle checks on the complete corpus.

use crate::repo::{Failure, Run, Step, System, require};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Developer case slicing; useful for diagnosis, never for the gate.
const SLICING: [&str; 2] = ["XML_SEC_LIBXSLT_CASE_RANGE", "XML_SEC_LIBXSLT_CASE"];

/// The suites of the gate, then cleanup unless the cache owns the build.
/// The admitted oracle may live under `target`, so cleanup runs only after
/// both halves, never between them.
pub(crate) fn plan(cleanup: bool) -> Vec<Step> {
    let unsliced = |step: Step| SLICING.iter().fold(step, |step, key| step.without_env(key));
    let mut steps = vec![
        unsliced(Step::new(
            "XSLT engine",
            "cargo",
            &["nextest", "run", "-p", "xml-sec-xslt", "--no-fail-fast"],
        )),
        unsliced(Step::new(
            "XSLT signatures and reciprocal oracle",
            "cargo",
            &[
                "nextest",
                "run",
                "-p",
                "xml-sec",
                "--features",
                "xslt,xml-backends-all",
                "--test",
                "xslt_transform_integration",
                "--test",
                "xmlsec1_interop",
                "--test",
                "donor_interop_suite",
                "--test",
                "merlin_interop",
                "--test",
                "phaos_interop",
                "--test",
                "capability_ledger",
                "-E",
                "not binary(xmlsec1_interop) or test(xslt)",
                "--no-fail-fast",
            ],
        )),
    ];
    if cleanup {
        steps.push(Step::new("cleanup", "cargo", &["clean"]));
    }
    steps
}

/// Admits only an oracle the installer built, whose binary reports the
/// version of the source it recorded, with its XSLT transform; anything else
/// would let the interoperability tests skip silently. Returns that source.
pub(crate) fn admit(
    run: &mut impl Run,
    xmlsec: &Path,
) -> Result<crate::install_xmlsec1::Source, Failure> {
    let prefix = xmlsec
        .parent()
        .and_then(Path::parent)
        .ok_or("XMLSEC1_BIN must name an installed oracle binary")?;
    let recorded = crate::install_xmlsec1::installed(prefix)
        .ok_or("The oracle has no source provenance from the installer")?;
    let binary = xmlsec.display().to_string();
    let query = |flag: &str| Step::new(format!("xmlsec1 {flag}"), &binary, &[flag]);
    let (status, version) = run.stdout(&query("--version"))?;
    require(status)?;
    if !version.starts_with(&format!("xmlsec1 {} ", recorded.version)) {
        return Err(format!(
            "Expected xmlsec1 {} built from {}, got {}",
            recorded.version,
            recorded.commit,
            version.trim()
        )
        .into());
    }
    let (status, transforms) = run.stdout(&query("--list-transforms"))?;
    require(status)?;
    if !transforms.contains("\"xslt\"") {
        return Err("The oracle must provide its XSLT transform".into());
    }
    Ok(recorded)
}

/// Runs the gate; a failed suite keeps its exit status and the build evidence.
pub(crate) fn execute(
    run: &mut impl Run,
    variable: impl Fn(&str) -> Option<String>,
    cleanup: bool,
    fixtures: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
    let required = |name: &str, purpose: &str| {
        variable(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Failure::from(format!("{name}: set {purpose}")))
    };
    required("LIBXSLT_SOURCE_DIR", "the pinned libxslt source checkout")?;
    let xmlsec = required("XMLSEC1_BIN", "the explicitly provisioned xmlsec1 oracle")?;
    let oracle = admit(run, Path::new(&xmlsec))?;
    println!(
        "XSLT conformance oracle: xmlsec1 {} built from upstream {}",
        oracle.version, oracle.commit
    );
    fixtures()?;
    for step in plan(cleanup) {
        require(run.status(&step)?)?;
    }
    println!(
        "XSLT conformance: engine, Recommendation examples, donor signatures and reciprocal oracle passed"
    );
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let cleanup = match args.as_slice() {
        [] => true,
        [flag] if flag == "--cache-managed" => false,
        [other, ..] => {
            return Err(Failure {
                code: 2,
                message: format!("Unknown conformance option: {other}"),
            });
        }
    };
    execute(
        &mut System,
        |name| std::env::var(name).ok(),
        cleanup,
        || crate::libxslt_fixtures::run(std::iter::once("--check".to_owned())),
    )
}
