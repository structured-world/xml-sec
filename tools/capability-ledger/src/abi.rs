//! `abi-generate` / `abi-check`: the binary baseline of one installed pinned
//! libxmlsec1 build. Exported symbols come from the built libraries, layouts
//! and enumerator values from a probe compiled against the installed headers,
//! and ownership from reviewed rules over the source ledger.

mod layout;
mod ownership;
mod symbols;
#[cfg(test)]
mod tests;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The installed libraries the baseline covers: the core and its OpenSSL backend.
const LIBRARIES: [&str; 2] = ["libxmlsec1", "libxmlsec1-openssl"];

#[derive(Deserialize)]
struct LedgerFile {
    upstream: Upstream,
    items: Vec<LedgerEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Upstream {
    project: String,
    version: String,
    commit: String,
    repository: String,
}

/// One item of the source ledger, as far as the binary baseline reads it.
#[derive(Deserialize)]
struct LedgerEntry {
    kind: String,
    name: String,
    source: String,
    detail: String,
}

#[derive(Serialize)]
struct Snapshot {
    schema_version: u32,
    upstream: Upstream,
    generated_by: &'static str,
    tuple: Tuple,
    libraries: Vec<symbols::Library>,
    structs: Vec<layout::Struct>,
    enums: Vec<layout::Enum>,
    functions: Vec<ownership::Function>,
}

/// What makes this baseline differ from another build: platform, data model,
/// crypto backend and the build's feature defines. Toolchain versions are not
/// part of it; the run prints them instead.
#[derive(Serialize)]
struct Tuple {
    os: &'static str,
    object_format: String,
    architecture: String,
    data_model: layout::DataModel,
    crypto: &'static str,
    defines: Vec<String>,
}

pub(crate) fn run(check: bool, mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut next = || args.next().map(PathBuf::from).ok_or_else(usage);
    let (ledger_path, rules_path, prefix, output) = (next()?, next()?, next()?, next()?);
    if args.next().is_some() {
        return Err(usage());
    }
    let ledger: LedgerFile = read_json(&ledger_path)?;
    verify_oracle(&prefix, &ledger.upstream.commit)?;
    let cflags = configured_cflags(&prefix)?;
    let (libraries, binary) = symbols::read(&prefix.join("lib"), &ledger.items)?;
    let probe = layout::measure(&prefix, &cflags, &ledger.items)?;
    let functions = ownership::classify(&read_json(&rules_path)?, &ledger.items, &libraries)?;
    let mut defines: Vec<String> = cflags
        .iter()
        .filter(|flag| flag.starts_with("-D"))
        .cloned()
        .collect();
    defines.sort();
    let snapshot = Snapshot {
        schema_version: 1,
        upstream: ledger.upstream,
        generated_by: "xml-sec-capability-ledger abi-generate",
        tuple: Tuple {
            os: std::env::consts::OS,
            object_format: binary.format,
            architecture: binary.architecture,
            data_model: probe.data_model,
            crypto: "openssl",
            defines,
        },
        libraries,
        structs: probe.structs,
        enums: probe.enums,
        functions,
    };
    let mut bytes = serde_json::to_vec_pretty(&snapshot).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if check {
        let existing = fs::read(&output)
            .map_err(|error| format!("read ABI snapshot {}: {error}", output.display()))?;
        if existing != bytes {
            return Err(format!(
                "{} does not match the installed build; regenerate it with abi-generate and review the diff",
                output.display()
            ));
        }
        return Ok(());
    }
    fs::write(&output, bytes).map_err(|error| format!("write {}: {error}", output.display()))
}

fn usage() -> String {
    "usage: xml-sec-capability-ledger <abi-generate|abi-check> <ledger.json> <ownership-rules.json> <xmlsec1-prefix> <snapshot.json>".into()
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

/// The installation must be built from the pinned commit; the installer
/// records it beside the build.
fn verify_oracle(prefix: &Path, commit: &str) -> Result<(), String> {
    if commit != super::EXPECTED_COMMIT.trim() {
        return Err(format!(
            "the ledger is for commit {commit}, not the pinned donor"
        ));
    }
    let marker = prefix.join(".xmlsec-source-commit");
    let recorded = fs::read_to_string(&marker)
        .map_err(|error| format!("read {}: {error}", marker.display()))?;
    if recorded.trim() != commit {
        return Err(format!(
            "{} was built from {}, not the pinned {commit}",
            prefix.display(),
            recorded.trim()
        ));
    }
    Ok(())
}

/// The compiler flags the installation gives its consumers, generic (no crypto
/// backend selected), so the probe sees exactly the configured layouts.
fn configured_cflags(prefix: &Path) -> Result<Vec<String>, String> {
    let config = prefix.join("bin/xmlsec1-config");
    let output = Command::new(&config)
        .arg("--cflags")
        .output()
        .map_err(|error| format!("run {}: {error}", config.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --cflags failed: {}",
            config.display(),
            output.status
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| format!("{} --cflags printed non-UTF-8", config.display()))?;
    Ok(text.split_whitespace().map(str::to_owned).collect())
}
