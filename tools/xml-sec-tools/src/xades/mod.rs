//! `xades ACTION`: the `XAdES` interoperability corpus. Synthetic signed inputs
//! are verified by xml-sec, libxmlsec1 and EU DSS, and every canonical octet
//! vector is compared with the independently captured goldens.

use crate::repo::Failure;
use process::{DEADLINE, Logged};
use serde_json::{Map, Value, json};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

pub(crate) mod binding;
pub(crate) mod check;
pub(crate) mod corpus;
pub(crate) mod dss;
pub(crate) mod fixtures;
pub(crate) mod levels;
pub(crate) mod package;
pub(crate) mod process;
pub(crate) mod xml;

#[cfg(test)]
mod tests;

pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const F2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
pub(crate) const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub(crate) const C11: &str = "http://www.w3.org/2006/12/xml-c14n11";
pub(crate) const SP: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// One command line from mixed string and path parts.
pub(crate) fn line(parts: &[&dyn AsRef<OsStr>]) -> Vec<OsString> {
    parts.iter().map(|part| part.as_ref().to_owned()).collect()
}

/// The repository, its corpus and the native oracle every action runs against.
pub(crate) struct Corpus {
    pub(crate) root: PathBuf,
    pub(crate) xmlsec: OsString,
}

impl Corpus {
    /// The checkout's corpus with `XMLSEC1_BIN`, or `xmlsec1` from `PATH`.
    pub(crate) fn from_env() -> Self {
        Self {
            root: crate::repo::root(),
            xmlsec: std::env::var_os("XMLSEC1_BIN")
                .filter(|binary| !binary.is_empty())
                .unwrap_or_else(|| "xmlsec1".into()),
        }
    }

    pub(crate) fn package(&self) -> PathBuf {
        self.root.join("interop/xades")
    }

    /// Runs a logged command from the repository root.
    pub(crate) fn command(&self, args: &[OsString], log: &Path) -> Result<Logged, String> {
        process::run(args, log, &self.root, &[], DEADLINE)
    }

    /// Runs a logged command that must succeed.
    pub(crate) fn require(&self, args: &[OsString], log: &Path) -> Result<Logged, String> {
        let result = self.command(args, log)?;
        if result.success() {
            Ok(result)
        } else {
            Err(format!(
                "failed ({}): inspect {}",
                result
                    .code
                    .map_or_else(|| "signal".into(), |code| code.to_string()),
                log.display()
            ))
        }
    }

    /// Arguments of the native oracle for `--sign` or `--verify`.
    pub(crate) fn oracle_args(&self, action: &str) -> Vec<OsString> {
        let mut args = line(&[
            &self.xmlsec,
            &action,
            &"--enabled-reference-uris",
            &"empty,same-doc",
            &"--enabled-retrieval-method-uris",
            &"empty,same-doc",
            &"--enabled-key-info-reference-uris",
            &"empty,same-doc",
            &"--id-attr:Id",
            &format!("{DS}:Signature"),
            &"--id-attr:Id",
            &format!("{SP}:SignedProperties"),
            &"--id-attr:Id",
            &"Data",
            &"--id-attr:Id",
            &"Outside",
        ]);
        if action == "--verify" {
            args.extend(line(&[
                &"--trusted-der",
                &self.package().join("fixtures/baseline/root.der"),
                &"--verification-gmt-time",
                &"2027-01-15 08:00:00",
                &"--store-references",
                &"--store-signatures",
                &"--print-debug",
                &"--verbose",
            ]));
        }
        args
    }

    /// Builds the Rust probe and returns the executable Cargo reported for
    /// this build, never a guessed default target path.
    pub(crate) fn build_probe(&self, log: &Path) -> Result<PathBuf, String> {
        let build = self.command(
            &line(&[
                &"cargo",
                &"build",
                &"-p",
                &"xml-sec-xades",
                &"--example",
                &"interop_probe",
                &"--message-format=json-render-diagnostics",
            ]),
            log,
        )?;
        if !build.success() {
            return Err(format!(
                "probe build failed; inspect {}.stderr",
                log.display()
            ));
        }
        probe_executable(&build.stdout, log)
    }
}

/// The one example executable in Cargo's build messages. Build scripts may
/// also print plain lines; library artifacts have no executable.
/// <https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages>
pub(crate) fn probe_executable(messages: &[u8], log: &Path) -> Result<PathBuf, String> {
    let ambiguous = || {
        format!(
            "probe build must report exactly one example executable; inspect {}.stdout",
            log.display()
        )
    };
    let mut binary = None;
    for message in messages.split(|byte| *byte == b'\n') {
        if !message.starts_with(b"{") {
            continue;
        }
        let message: Value = serde_json::from_slice(message).map_err(|error| error.to_string())?;
        let target = &message["target"];
        let example = target["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "example"));
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || target["name"] != "interop_probe" || !example
        {
            continue;
        }
        if binary.replace(PathBuf::from(executable)).is_some() {
            return Err(ambiguous());
        }
    }
    binary.ok_or_else(ambiguous)
}

/// SHA-256 of `data`, as hex.
pub(crate) fn digest(data: &[u8]) -> String {
    crate::security_corpus::sha256(data)
}

/// Lowercase hex of `data`.
pub(crate) fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Byte comparison of two octet vectors with the first difference and its
/// surrounding context, distinguishing a changed byte from a matching prefix.
pub(crate) fn compare(expected: &[u8], actual: &[u8]) -> Map<String, Value> {
    let first = expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right)
        .or_else(|| (expected.len() != actual.len()).then(|| expected.len().min(actual.len())));
    let context = |data: &[u8]| {
        first.map(|first| {
            // The context window is clamped at the start of the buffer.
            let start = first.saturating_sub(24);
            hex(&data[start.min(data.len())..(first + 25).min(data.len())])
        })
    };
    let mut result = Map::new();
    let status = if first.is_none() {
        "verified"
    } else {
        "failed"
    };
    result.insert("status".into(), status.into());
    result.insert("first_different_byte".into(), first.into());
    result.insert("expected_length".into(), expected.len().into());
    result.insert("actual_length".into(), actual.len().into());
    result.insert("expected_sha256".into(), digest(expected).into());
    result.insert("actual_sha256".into(), digest(actual).into());
    result.insert("expected_context_hex".into(), context(expected).into());
    result.insert("actual_context_hex".into(), context(actual).into());
    result
}

/// One buffer of libxmlsec1's `DebugHexDump` output (1.3.12/1.3.13), which is
/// hex, not XML text. A zero-allocation empty buffer is omitted by the dump,
/// so absence is `None`, never an implicit empty buffer.
/// <https://github.com/lsh123/xmlsec/blob/1.3.12/src/xmldsig.c>
pub(crate) fn debug_buffer(block: &[u8], kind: &str) -> Result<Option<Vec<u8>>, String> {
    let kind = regex::escape(kind);
    let pattern = regex::bytes::Regex::new(&format!(
        r"(?s)== {kind} data - start buffer:\n(.*?)\n== {kind} data - end buffer"
    ))
    .map_err(|error| error.to_string())?;
    let Some(found) = pattern.captures(block) else {
        return Ok(None);
    };
    let digits: Vec<u8> = found[1]
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits in a debug buffer".into());
    }
    digits
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "non-hex content in a debug buffer".to_owned())
        })
        .collect::<Result<Vec<u8>, String>>()
        .map(Some)
}

/// Dependency names, versions and features without Cargo's absolute package IDs.
pub(crate) fn resolved_versions(metadata: &Value) -> Result<Value, String> {
    let nodes: Map<String, Value> = metadata["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| Some((node["id"].as_str()?.to_owned(), node["features"].clone())))
        .collect();
    let mut packages = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let id = package["id"].as_str().unwrap_or_default();
        let features = nodes
            .get(id)
            .ok_or_else(|| format!("package {id} is not in the resolved graph"))?;
        packages.push(
            json!({ "name": package["name"], "version": package["version"], "features": features }),
        );
    }
    packages.sort_by(|left, right| {
        let key = |item: &Value| {
            (
                item["name"].as_str().map(str::to_owned),
                item["version"].as_str().map(str::to_owned),
            )
        };
        key(left).cmp(&key(right))
    });
    Ok(Value::Array(packages))
}

/// Writes JSON with two-space indentation and a final newline.
pub(crate) fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, text + "\n").map_err(|error| format!("write {}: {error}", path.display()))
}

/// Reads a file as bytes.
pub(crate) fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

/// Writes bytes to a file.
pub(crate) fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<(), String> {
    std::fs::write(path, data).map_err(|error| format!("write {}: {error}", path.display()))
}

/// An absolute form of a command-line path, which need not exist yet.
pub(crate) fn absolute(path: &str) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|error| format!("{path}: {error}"))
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let usage = "usage: xades check|corpus|dss|binding|fixtures|levels|package ...";
    let action = args.next().ok_or(usage)?;
    let args: Vec<String> = args.collect();
    let corpus = Corpus::from_env();
    match action.as_str() {
        "check" => check::run(&corpus, &args),
        "corpus" => corpus::run(&corpus, &args),
        "dss" => dss::run(&corpus, &args),
        "binding" => binding::run(&corpus, &args),
        "fixtures" => fixtures::run(&corpus, &args),
        "levels" => levels::run(&corpus, &args),
        "package" => package::run(&corpus, &args),
        _ => Err(usage.into()),
    }
}
