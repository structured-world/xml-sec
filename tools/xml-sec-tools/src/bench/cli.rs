//! `bench-cli NEW_OUTPUT_DIR [SAMPLES] [--heap]`: compares fresh command-line
//! processes of every engine on the exported corpus. Every produced result is
//! cross-checked by every other engine before anything is timed.

use super::{
    Captured, capture, case_files, checked, cpu_model, create_evidence_directory, digest_file,
    document_body, heap_stats, number, operations, platform, policy_refusal, read_json, resources,
    sample_count, tamper, timestamp, to_f64, unsupported, wrap, write_json,
};
use crate::repo::Failure;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const VALIDATION: Duration = Duration::from_mins(2);

/// One measured engine; `kind` selects its argument dialect.
pub(crate) struct Engine {
    pub(crate) name: &'static str,
    pub(crate) id: &'static str,
    pub(crate) kind: Kind,
    pub(crate) binary: PathBuf,
    pub(crate) backend: Option<&'static str>,
}

/// The two command-line dialects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// xmlsec1-compatible CLIs: xml-sec and libxmlsec1.
    Xmlsec,
    Bergshamra,
}

/// Paths one invocation reads and writes.
pub(crate) struct Files<'a> {
    pub(crate) template: &'a str,
    pub(crate) signed: &'a str,
    pub(crate) plain: &'a str,
    pub(crate) encrypted: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) corpus: &'a Path,
}

/// One argument of an invocation template.
#[derive(Clone, Copy)]
enum Arg {
    Literal(&'static str),
    /// A corpus file.
    Corpus(&'static str),
    /// A prefix followed by a corpus file, such as `bench:private.pem`.
    Prefixed(&'static str, &'static str),
    /// Two corpus files separated by a comma.
    Pair(&'static str, &'static str),
    Template,
    Signed,
    Plain,
    Encrypted,
    Destination,
}

use Arg::{Corpus, Destination, Encrypted, Literal, Pair, Plain, Prefixed, Signed, Template};

const ASSERTION_ID: Arg = Literal("urn:oasis:names:tc:SAML:2.0:assertion:Assertion");

const BERG_PAYLOAD_SIGN: &[Arg] = &[
    Literal("sign"),
    Template,
    Literal("--key-name"),
    Prefixed("bench:", "private.pem"),
    Literal("--output"),
    Destination,
];
const BERG_PAYLOAD_VERIFY: &[Arg] = &[
    Literal("verify"),
    Signed,
    Literal("--key-name"),
    Prefixed("bench:", "public.pem"),
    Literal("--trusted-keys-only"),
];
const BERG_PAYLOAD_ENCRYPT: &[Arg] = &[
    Literal("encrypt"),
    Corpus("encryption.xml"),
    Literal("--data"),
    Plain,
    Literal("--keys-file"),
    Corpus("keys.xml"),
    Literal("--output"),
    Destination,
];
const BERG_PAYLOAD_DECRYPT: &[Arg] = &[
    Literal("decrypt"),
    Encrypted,
    Literal("--keys-file"),
    Corpus("keys.xml"),
    Literal("--output"),
    Destination,
];
/// Bergshamra's documented SAML configuration: chain validation plus strict positions.
const BERG_ASSERTION_VERIFY: &[Arg] = &[
    Literal("verify"),
    Signed,
    Literal("--trusted"),
    Corpus("root.pem"),
    Literal("--untrusted"),
    Corpus("intermediate.pem"),
    Literal("--enabled-key-data"),
    Literal("x509"),
    Literal("--strict"),
];
const BERG_ELEMENT_ENCRYPT: &[Arg] = &[
    Literal("encrypt"),
    Corpus("element.template.xml"),
    Literal("--data"),
    Plain,
    Literal("--cert"),
    Corpus("leaf.pem"),
    Literal("--output"),
    Destination,
];
const BERG_ELEMENT_DECRYPT: &[Arg] = &[
    Literal("decrypt"),
    Encrypted,
    Literal("--key"),
    Corpus("private.pem"),
    Literal("--output"),
    Destination,
];
const XMLSEC_PAYLOAD_SIGN: &[Arg] = &[
    Literal("sign"),
    Literal("--privkey-pem:bench"),
    Corpus("private.pem"),
    Literal("--id-attr:Id"),
    Literal("Payload"),
    Literal("--output"),
    Destination,
    Template,
];
const XMLSEC_PAYLOAD_VERIFY: &[Arg] = &[
    Literal("verify"),
    Literal("--pubkey-pem:bench"),
    Corpus("public.pem"),
    Literal("--id-attr:Id"),
    Literal("Payload"),
    Signed,
];
const XMLSEC_PAYLOAD_ENCRYPT: &[Arg] = &[
    Literal("encrypt"),
    Literal("--keys-file"),
    Corpus("keys.xml"),
    Literal("--binary-data"),
    Plain,
    Literal("--output"),
    Destination,
    Corpus("encryption.xml"),
];
const XMLSEC_PAYLOAD_DECRYPT: &[Arg] = &[
    Literal("decrypt"),
    Literal("--keys-file"),
    Corpus("keys.xml"),
    Literal("--output"),
    Destination,
    Encrypted,
];
const XMLSEC_ASSERTION_SIGN: &[Arg] = &[
    Literal("sign"),
    Literal("--privkey-pem:bench"),
    Pair("private.pem", "leaf.pem"),
    Literal("--id-attr:ID"),
    ASSERTION_ID,
    Literal("--output"),
    Destination,
    Template,
];
const XMLSEC_ASSERTION_VERIFY: &[Arg] = &[
    Literal("verify"),
    Literal("--trusted-pem"),
    Corpus("root.pem"),
    Literal("--untrusted-pem"),
    Corpus("intermediate.pem"),
    Literal("--id-attr:ID"),
    ASSERTION_ID,
    Signed,
];
const XMLSEC_ELEMENT_ENCRYPT: &[Arg] = &[
    Literal("encrypt"),
    Literal("--pubkey-cert-pem:recipient"),
    Corpus("leaf.pem"),
    Literal("--session-key"),
    Literal("aes-256"),
    Literal("--xml-data"),
    Plain,
    Literal("--output"),
    Destination,
    Corpus("element.template.xml"),
];
const XMLSEC_IN_PLACE_ENCRYPT: &[Arg] = &[
    Literal("encrypt"),
    Literal("--pubkey-cert-pem:recipient"),
    Corpus("leaf.pem"),
    Literal("--session-key"),
    Literal("aes-256"),
    Literal("--id-attr:Id"),
    Literal("Payment"),
    Literal("--xml-data"),
    Plain,
    Literal("--node-id"),
    Literal("payment"),
    Literal("--output"),
    Destination,
    Corpus("element.template.xml"),
];
const XMLSEC_ELEMENT_DECRYPT: &[Arg] = &[
    Literal("decrypt"),
    Literal("--privkey-pem:recipient"),
    Corpus("private.pem"),
    Literal("--output"),
    Destination,
    Encrypted,
];
const XMLSEC_XSLT_SIGN: &[Arg] = &[
    Literal("sign"),
    Literal("--privkey-pem:bench"),
    Corpus("private.pem"),
    Literal("--id-attr:Id"),
    Literal("List"),
    Literal("--output"),
    Destination,
    Template,
];
const XMLSEC_XSLT_VERIFY: &[Arg] = &[
    Literal("verify"),
    Literal("--pubkey-pem:bench"),
    Corpus("public.pem"),
    Literal("--id-attr:Id"),
    Literal("List"),
    Signed,
];

/// The invocation template of one engine dialect, workload and operation.
fn template(kind: Kind, scenario: &str, operation: &str) -> Option<&'static [Arg]> {
    Some(match (kind, scenario, operation) {
        (Kind::Bergshamra, "payload", "sign") => BERG_PAYLOAD_SIGN,
        (Kind::Bergshamra, "payload", "verify") => BERG_PAYLOAD_VERIFY,
        (Kind::Bergshamra, "payload", "encrypt") => BERG_PAYLOAD_ENCRYPT,
        (Kind::Bergshamra, "payload", "decrypt") => BERG_PAYLOAD_DECRYPT,
        (Kind::Bergshamra, "assertion", "verify") => BERG_ASSERTION_VERIFY,
        (Kind::Bergshamra, "element", "encrypt") => BERG_ELEMENT_ENCRYPT,
        (Kind::Bergshamra, "element" | "element_in_place", "decrypt") => BERG_ELEMENT_DECRYPT,
        (Kind::Xmlsec, "payload", "sign") => XMLSEC_PAYLOAD_SIGN,
        (Kind::Xmlsec, "payload", "verify") => XMLSEC_PAYLOAD_VERIFY,
        (Kind::Xmlsec, "payload", "encrypt") => XMLSEC_PAYLOAD_ENCRYPT,
        (Kind::Xmlsec, "payload", "decrypt") => XMLSEC_PAYLOAD_DECRYPT,
        (Kind::Xmlsec, "assertion", "sign") => XMLSEC_ASSERTION_SIGN,
        (Kind::Xmlsec, "assertion", "verify") => XMLSEC_ASSERTION_VERIFY,
        (Kind::Xmlsec, "element", "encrypt") => XMLSEC_ELEMENT_ENCRYPT,
        (Kind::Xmlsec, "element_in_place", "encrypt") => XMLSEC_IN_PLACE_ENCRYPT,
        (Kind::Xmlsec, "element" | "element_in_place", "decrypt") => XMLSEC_ELEMENT_DECRYPT,
        (Kind::Xmlsec, "xslt", "sign") => XMLSEC_XSLT_SIGN,
        (Kind::Xmlsec, "xslt", "verify") => XMLSEC_XSLT_VERIFY,
        _ => return None,
    })
}

/// Arguments for one engine and operation, or `None` without a dialect for it.
pub(crate) fn engine_arguments(
    kind: Kind,
    scenario: &str,
    operation: &str,
    files: &Files<'_>,
) -> Option<Vec<String>> {
    let corpus = |name: &str| files.corpus.join(name).display().to_string();
    let render = |arg: &Arg| match *arg {
        Literal(text) => text.to_owned(),
        Corpus(name) => corpus(name),
        Prefixed(prefix, name) => format!("{prefix}{}", corpus(name)),
        Pair(first, second) => format!("{},{}", corpus(first), corpus(second)),
        Template => files.template.to_owned(),
        Signed => files.signed.to_owned(),
        Plain => files.plain.to_owned(),
        Encrypted => files.encrypted.to_owned(),
        Destination => files.destination.to_owned(),
    };
    template(kind, scenario, operation).map(|args| args.iter().map(render).collect())
}

/// Prefix that restores the dynamic loader path inside a child: macOS
/// `/usr/bin/time` strips `DYLD_*` from what it inherits.
pub(crate) fn loader() -> Vec<String> {
    match std::env::var("DYLD_LIBRARY_PATH") {
        Ok(path) if platform() == "darwin" && !path.is_empty() => {
            vec!["/usr/bin/env".into(), format!("DYLD_LIBRARY_PATH={path}")]
        }
        _ => Vec::new(),
    }
}

/// The process-metrics wrapper arguments for this platform.
pub(crate) fn time_args() -> Vec<String> {
    if platform() == "darwin" {
        vec!["-l".into()]
    } else {
        vec!["-f".into(), "__METRICS %U %S %M".into()]
    }
}

fn process(line: &[String]) -> Command {
    let mut command = Command::new(&line[0]);
    command.args(&line[1..]);
    command
}

fn require(line: &[String]) -> Result<Captured, String> {
    let result = capture(&mut process(line), false, VALIDATION);
    if result.succeeded() {
        Ok(result)
    } else {
        Err(format!(
            "{} failed: {}\n{}",
            line[0],
            result.failure(),
            result.stderr
        ))
    }
}

/// Runs a validation command; returns the engine's resource-policy refusal, if any.
fn attempt(line: &[String]) -> Result<Option<String>, String> {
    let result = capture(&mut process(line), false, VALIDATION);
    if result.succeeded() {
        return Ok(None);
    }
    let refusal = if result.error.is_some() || result.signal.is_some() {
        None
    } else {
        policy_refusal(&result.stderr)
    };
    refusal.map(Some).ok_or_else(|| {
        format!(
            "{} failed: {}\n{}",
            line[0],
            result.failure(),
            result.stderr
        )
    })
}

fn text(item: &Value, field: &str) -> String {
    item[field].as_str().unwrap_or_default().to_owned()
}

struct Run {
    corpus: PathBuf,
    engines: Vec<Engine>,
    loader: Vec<String>,
}

impl Run {
    fn file(&self, name: &str) -> PathBuf {
        self.corpus.join(name)
    }

    fn command(
        &self,
        engine: &Engine,
        item: &Value,
        operation: &str,
        destination: Option<&Path>,
        input: Option<&Path>,
    ) -> Result<Vec<String>, String> {
        let (name, scenario) = (text(item, "name"), text(item, "scenario"));
        let files = case_files(&name, &scenario, &item["units"]);
        let path = |name: &str| self.file(name).display().to_string();
        let input = input.map(|input| input.display().to_string());
        let (template, plain) = (path(&files.template), path(&files.plain));
        let signed = input.clone().unwrap_or_else(|| path(&files.signed));
        let encrypted = input.unwrap_or_else(|| path(&files.encrypted));
        let destination = destination
            .map(|destination| destination.display().to_string())
            .unwrap_or_default();
        let files = Files {
            template: &template,
            signed: &signed,
            plain: &plain,
            encrypted: &encrypted,
            destination: &destination,
            corpus: &self.corpus,
        };
        let args = engine_arguments(engine.kind, &scenario, operation, &files)
            .ok_or_else(|| format!("no arguments for {} {scenario} {operation}", engine.name))?;
        let mut line = self.loader.clone();
        line.push(engine.binary.display().to_string());
        line.push(args[0].clone());
        if let Some(backend) = engine.backend {
            line.extend(["--xml-backend".into(), backend.into()]);
        }
        line.extend(args[1..].iter().cloned());
        Ok(line)
    }

    fn reject(
        &self,
        engine: &Engine,
        item: &Value,
        input: &Path,
        what: &str,
    ) -> Result<(), String> {
        let line = self.command(engine, item, "verify", None, Some(input))?;
        let rejection = capture(&mut process(&line), false, VALIDATION);
        // A crash or timeout is not a successful verification rejection.
        if rejection.error.is_some() || rejection.signal.is_some() || rejection.code != Some(1) {
            return Err(format!(
                "Invalid {what} rejection: {}, {}",
                engine.name,
                text(item, "name")
            ));
        }
        Ok(())
    }

    /// The engines able to run `operation` for this case, by index.
    fn able(&self, refused: &Refusals, scenario: &str, operation: &str) -> Vec<usize> {
        (0..self.engines.len())
            .filter(|&index| {
                refused
                    .blocked(&self.engines[index], scenario, operation)
                    .is_none()
            })
            .collect()
    }
}

/// Engines refused for one case, by `engine name/operation`.
struct Refusals(BTreeMap<String, String>);

impl Refusals {
    fn blocked(&self, engine: &Engine, scenario: &str, operation: &str) -> Option<String> {
        unsupported(engine.id, scenario, operation)
            .map(String::from)
            .or_else(|| self.0.get(&format!("{}/{operation}", engine.name)).cloned())
    }

    fn refuse(&mut self, engine: &Engine, operation: &str, reason: &str) {
        self.0.insert(
            format!("{}/{operation}", engine.name),
            format!("refused under the engine's default policy: {reason}"),
        );
    }
}

/// Cross-checks one signing case: every signer's output must verify with every
/// verifier, and a changed signed value (and, for assertions, a wrapped
/// forgery) must be rejected before anything is timed.
fn validate_signing(run: &Run, item: &Value, refused: &mut Refusals) -> Result<(), String> {
    let (name, scenario) = (text(item, "name"), text(item, "scenario"));
    let mut outputs = Vec::new();
    for (position, index) in run.able(refused, &scenario, "sign").into_iter().enumerate() {
        let signer = &run.engines[index];
        let output = run.file(&format!("{name}.signed-{position}.xml"));
        if let Some(refusal) = attempt(&run.command(signer, item, "sign", Some(&output), None)?)? {
            refused.refuse(signer, "sign", &refusal);
            continue;
        }
        let contents = std::fs::read_to_string(&output).map_err(|error| error.to_string())?;
        if scenario == "assertion" && !contents.contains("X509Certificate>") {
            return Err(format!("No signer certificate: {}, {name}", signer.name));
        }
        outputs.push(output);
    }
    let first = outputs
        .first()
        .ok_or_else(|| format!("No engine signed {name}"))?;
    for signed in &outputs {
        for index in run.able(refused, &scenario, "verify") {
            let verifier = &run.engines[index];
            if let Some(refusal) =
                attempt(&run.command(verifier, item, "verify", None, Some(signed))?)?
            {
                refused.refuse(verifier, "verify", &refusal);
            }
        }
    }
    let canonical = run.file(&format!("{name}.signed.xml"));
    std::fs::copy(first, &canonical).map_err(|error| error.to_string())?;
    let signed_text = std::fs::read_to_string(&canonical).map_err(|error| error.to_string())?;
    let mut forgeries = vec![("tampered", tamper(&signed_text, &scenario)?)];
    if scenario == "assertion" {
        forgeries.push(("wrapped", wrap(&signed_text)?));
    }
    for (kind, forged) in forgeries {
        let path = run.file(&format!("{name}.{kind}.xml"));
        std::fs::write(&path, forged).map_err(|error| error.to_string())?;
        // A refusing verifier says nothing about forgery detection, so it is not counted.
        for index in run.able(refused, &scenario, "verify") {
            run.reject(&run.engines[index], item, &path, kind)?;
        }
    }
    Ok(())
}

/// Cross-checks one encryption case: every encryptor's output must decrypt with
/// every decryptor to the original plaintext.
fn validate_encryption(run: &Run, item: &Value, refused: &mut Refusals) -> Result<(), String> {
    let (name, scenario) = (text(item, "name"), text(item, "scenario"));
    let files = case_files(&name, &scenario, &item["units"]);
    let plain = std::fs::read(run.file(&files.plain)).map_err(|error| error.to_string())?;
    let mut outputs = Vec::new();
    for (position, index) in run
        .able(refused, &scenario, "encrypt")
        .into_iter()
        .enumerate()
    {
        let encryptor = &run.engines[index];
        let encrypted = run.file(&format!("{name}.encrypted-{position}.xml"));
        if let Some(refusal) =
            attempt(&run.command(encryptor, item, "encrypt", Some(&encrypted), None)?)?
        {
            refused.refuse(encryptor, "encrypt", &refusal);
            continue;
        }
        outputs.push((index, encrypted));
    }
    let (_, first) = outputs
        .first()
        .ok_or_else(|| format!("No engine encrypted {name}"))?;
    for (encryptor, encrypted) in &outputs {
        for index in run.able(refused, &scenario, "decrypt") {
            let decryptor = &run.engines[index];
            let decrypted = run.file(&format!("{name}.decrypted.xml"));
            if let Some(refusal) = attempt(&run.command(
                decryptor,
                item,
                "decrypt",
                Some(&decrypted),
                Some(encrypted),
            )?)? {
                refused.refuse(decryptor, "decrypt", &refusal);
                continue;
            }
            // Byte payloads must round-trip exactly; XML results may differ only in
            // the declaration and surrounding whitespace the writing engine adds.
            let output = std::fs::read(&decrypted).map_err(|error| error.to_string())?;
            let equal = if scenario == "payload" {
                output == plain
            } else {
                document_body(&output) == document_body(&plain)
            };
            if !equal {
                return Err(format!(
                    "Plaintext mismatch: {} -> {}, {name}",
                    run.engines[*encryptor].name, decryptor.name
                ));
            }
        }
    }
    std::fs::copy(first, run.file(&format!("{name}.encrypted.xml")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// The fields every result of `engine` shares, in report order.
fn base_entry(engine: &Engine, operation: &str, item: &Value) -> Map<String, Value> {
    let mut entry = Map::new();
    entry.insert("level".into(), "cli".into());
    entry.insert("engine".into(), engine.name.into());
    entry.insert("operation".into(), operation.into());
    entry.extend(item.as_object().cloned().unwrap_or_default());
    entry
}

/// One wall-clock observation of `line` under the process-metrics wrapper.
fn observe(line: &[String]) -> Result<(f64, Value), String> {
    let mut timed = vec!["/usr/bin/time".to_owned()];
    timed.extend(time_args());
    timed.extend(line.iter().cloned());
    let start = Instant::now();
    let measured = require(&timed)?;
    let wall =
        u64::try_from(start.elapsed().as_nanos()).map_err(|_| "elapsed time out of range")?;
    let (cpu, rss) = resources(&measured.stderr, platform())?;
    Ok((
        to_f64(wall),
        json!({ "wall_ns": wall, "cpu_seconds": number(cpu), "rss_bytes": number(rss) }),
    ))
}

/// Three repetitions of `samples` rotated observations of every line.
fn repetitions(lines: &[Vec<String>], samples: u32) -> Result<Vec<Vec<Value>>, String> {
    let mut per_line = vec![Vec::new(); lines.len()];
    for repetition in 0..3_usize {
        let mut walls: Vec<Vec<f64>> = vec![Vec::new(); lines.len()];
        let mut raw: Vec<Vec<Value>> = vec![Vec::new(); lines.len()];
        for sample in 0..usize::try_from(samples).unwrap_or(usize::MAX) {
            // Rotate order to avoid giving one engine every first or cold slot.
            for step in 0..lines.len() {
                let index = (step + sample + repetition) % lines.len();
                let (wall, observation) = observe(&lines[index])?;
                walls[index].push(wall);
                raw[index].push(observation);
            }
        }
        for (index, raw) in raw.into_iter().enumerate() {
            per_line[index].push(json!({
                "raw": raw,
                "p50_ns": number(super::percentile(&walls[index], 50)?),
                "p95_ns": number(super::percentile(&walls[index], 95)?),
                "p99_ns": number(super::percentile(&walls[index], 99)?),
            }));
        }
    }
    Ok(per_line)
}

/// The Valgrind allocation profile of one measured command.
fn heap_profile(line: &[String], raw: &Path, id: &str) -> Result<Value, String> {
    let log = raw.join(format!("{id}.memcheck.txt"));
    let massif = raw.join(format!("{id}.massif.txt"));
    let mut memcheck = vec![
        "valgrind".to_owned(),
        "--tool=memcheck".into(),
        "--leak-check=no".into(),
        format!("--log-file={}", log.display()),
    ];
    memcheck.extend(line.iter().cloned());
    require(&memcheck)?;
    let mut profile = vec![
        "valgrind".to_owned(),
        "--tool=massif".into(),
        "--stacks=no".into(),
        "--time-unit=B".into(),
        format!("--massif-out-file={}", massif.display()),
    ];
    profile.extend(line.iter().cloned());
    require(&profile)?;
    let read = |path: &Path| std::fs::read_to_string(path).map_err(|error| error.to_string());
    let (calls, bytes, peak) = heap_stats(&read(&log)?, &read(&massif)?)?;
    Ok(json!({ "allocation_calls": calls, "allocated_bytes": bytes, "peak_heap_bytes": peak }))
}

fn size(path: &Path) -> Result<u64, String> {
    std::fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Measures every able engine on one operation of one case.
fn measure(
    run: &Run,
    item: &Value,
    operation: &str,
    refused: &Refusals,
    samples: u32,
    heap: Option<&Path>,
) -> Result<Vec<Value>, String> {
    let (name, scenario) = (text(item, "name"), text(item, "scenario"));
    let able = run.able(refused, &scenario, operation);
    let mut lines = Vec::new();
    for (position, &index) in able.iter().enumerate() {
        let output = run.file(&format!("{name}.{operation}-{position}.output"));
        lines.push(run.command(&run.engines[index], item, operation, Some(&output), None)?);
    }
    let files = case_files(&name, &scenario, &item["units"]);
    let input = match operation {
        "sign" => &files.template,
        "verify" => &files.signed,
        "encrypt" => &files.plain,
        _ => &files.encrypted,
    };
    let input_bytes = size(&run.file(input))?;
    let mut results = Vec::new();
    for ((position, &index), repetitions) in
        able.iter().enumerate().zip(repetitions(&lines, samples)?)
    {
        let mut entry = base_entry(&run.engines[index], operation, item);
        entry.insert(
            "boundary".into(),
            "fresh CLI process + key loading + file I/O + operation".into(),
        );
        entry.insert("repetitions".into(), Value::Array(repetitions));
        entry.insert("memory".into(), Value::Null);
        entry.insert("commands".into(), json!(lines[position]));
        entry.insert("input_bytes".into(), input_bytes.into());
        if operation == "verify" {
            entry.insert("output_bytes".into(), Value::Null);
            entry.insert("output_amplification".into(), Value::Null);
        } else {
            let output_bytes = size(&run.file(&format!("{name}.{operation}-{position}.output")))?;
            entry.insert("output_bytes".into(), output_bytes.into());
            entry.insert(
                "output_amplification".into(),
                number(ratio(output_bytes, input_bytes)),
            );
        }
        if let Some(raw) = heap {
            entry.insert(
                "memory".into(),
                heap_profile(
                    &lines[position],
                    raw,
                    &format!("{name}-{operation}-{position}"),
                )?,
            );
        }
        results.push(Value::Object(entry));
    }
    for engine in &run.engines {
        if let Some(reason) = refused.blocked(engine, &scenario, operation) {
            let mut entry = base_entry(engine, operation, item);
            entry.insert("unsupported".into(), reason.into());
            results.push(Value::Object(entry));
        }
    }
    Ok(results)
}

/// `numerator / denominator` for byte counts.
pub(crate) fn ratio(numerator: u64, denominator: u64) -> f64 {
    to_f64(numerator) / to_f64(denominator)
}

/// The engine binaries named by the environment.
pub(crate) struct Binaries {
    pub(crate) xml_sec: PathBuf,
    pub(crate) bergshamra: PathBuf,
    pub(crate) xmlsec1: PathBuf,
    pub(crate) export: PathBuf,
}

fn binaries() -> Result<Binaries, String> {
    let resolve = |name: &str| {
        let path = std::env::var(name)
            .ok()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| format!("Missing {name}"))?;
        std::fs::canonicalize(&path).map_err(|error| format!("{name}: {error}"))
    };
    Ok(Binaries {
        xml_sec: resolve("XML_SEC_BENCH_BIN")?,
        bergshamra: resolve("BERGSHAMRA_BIN")?,
        xmlsec1: resolve("XMLSEC1_BIN")?,
        export: resolve("BENCH_EXPORT_BIN")?,
    })
}

/// Template, plaintext and signed case files of the exported corpus.
pub(crate) fn corpus_file(name: &str) -> bool {
    if name.ends_with(".template.xml") || name.ends_with(".plain.xml") {
        return true;
    }
    name.strip_suffix(".signed.xml")
        .and_then(|stem| stem.rsplit_once('-'))
        .is_some_and(|(scenario, units)| {
            !scenario.is_empty()
                && scenario
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                && !units.is_empty()
                && units.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Digests of the corpus files that identify a run's inputs.
fn corpus_digests(corpus: &Path) -> Result<Vec<Value>, String> {
    const FIXED: [&str; 9] = [
        "keys.xml",
        "encryption.xml",
        "element.template.xml",
        "private.pem",
        "public.pem",
        "leaf.pem",
        "intermediate.pem",
        "root.pem",
        "cases.json",
    ];
    let mut names: Vec<String> = std::fs::read_dir(corpus)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
        .into_iter()
        .filter(|name| corpus_file(name) || FIXED.contains(&name.as_str()))
        .map(|name| Ok(json!({ "sha256": digest_file(&corpus.join(&name))?, "name": name })))
        .map(|entry: Result<Value, String>| {
            entry.map(|value| json!({ "name": value["name"], "sha256": value["sha256"] }))
        })
        .collect()
}

/// Versions, sizes and digests of the three measured engine binaries.
fn describe_binaries(run: &Run, binaries: &Binaries) -> Result<Vec<Value>, String> {
    let mut described = Vec::new();
    for binary in [&binaries.xml_sec, &binaries.bergshamra, &binaries.xmlsec1] {
        let mut line = run.loader.clone();
        line.push(binary.display().to_string());
        line.push("--version".into());
        let version = checked(process(&line), VALIDATION)?.trim().to_owned();
        let bytes = size(binary)?;
        described
            .push(json!({ "sha256": digest_file(binary)?, "bytes": bytes, "version": version }));
    }
    Ok(described)
}

/// Validates and measures every case, then writes `comparison.json`.
fn execute(output: &Path, samples: u32, heap: bool, binaries: &Binaries) -> Result<Value, String> {
    if heap {
        checked(super::command("valgrind", &["--version"]), VALIDATION)?;
    }
    create_evidence_directory(output)?;
    let root = std::fs::canonicalize(output).map_err(|error| error.to_string())?;
    let corpus = root.join("corpus");
    checked(
        super::command(
            &binaries.export,
            &["--export".into(), corpus.display().to_string()],
        ),
        VALIDATION,
    )?;
    let engines = vec![
        Engine {
            name: "xml-sec / xmloxide / RustCrypto",
            id: "xml-sec",
            kind: Kind::Xmlsec,
            binary: binaries.xml_sec.clone(),
            backend: Some("xmloxide"),
        },
        Engine {
            name: "xml-sec / roxmltree / RustCrypto",
            id: "xml-sec",
            kind: Kind::Xmlsec,
            binary: binaries.xml_sec.clone(),
            backend: Some("roxmltree"),
        },
        Engine {
            name: "bergshamra / Uppsala / RustCrypto",
            id: "bergshamra",
            kind: Kind::Bergshamra,
            binary: binaries.bergshamra.clone(),
            backend: None,
        },
        Engine {
            name: "libxmlsec1 / libxml2 / OpenSSL",
            id: "libxmlsec1",
            kind: Kind::Xmlsec,
            binary: binaries.xmlsec1.clone(),
            backend: None,
        },
    ];
    let run = Run {
        corpus: corpus.clone(),
        engines,
        loader: loader(),
    };
    let raw = root.join("raw");
    std::fs::create_dir(&raw).map_err(|error| error.to_string())?;
    let mut results = Vec::new();
    for item in read_json(&run.file("cases.json"))?
        .as_array()
        .into_iter()
        .flatten()
    {
        let mut case = Map::new();
        case.insert("scenario".into(), "payload".into());
        case.extend(item.as_object().cloned().unwrap_or_default());
        let item = Value::Object(case);
        let operations = operations(&text(&item, "scenario"))?;
        let mut refused = Refusals(BTreeMap::new());
        if operations.contains(&"sign") {
            validate_signing(&run, &item, &mut refused)?;
        }
        if operations.contains(&"encrypt") {
            validate_encryption(&run, &item, &mut refused)?;
        }
        for operation in operations {
            results.extend(measure(
                &run,
                &item,
                operation,
                &refused,
                samples,
                heap.then_some(raw.as_path()),
            )?);
        }
    }
    let report = json!({
        "schema": 2,
        "generated": timestamp(),
        "source_revision": checked(super::command("git", &["rev-parse", "HEAD"]), VALIDATION)?.trim(),
        "environment": {
            "platform": platform(),
            "architecture": super::architecture(),
            "cpu": cpu_model(),
            "samples": samples,
            "repetitions": 3,
            "timing": "unprofiled, warm filesystem cache, fresh processes; includes measurement wrapper and process launch",
            "memory": "RSS includes full process lifetime; optional Valgrind heap excludes stacks and non-malloc mmap allocations; profiling timing never used",
        },
        "binaries": describe_binaries(&run, binaries)?,
        "corpus": corpus_digests(&corpus)?,
        "results": results,
    });
    write_json(&root.join("comparison.json"), &report)?;
    Ok(report)
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let usage = || Failure::from("Usage: bench-cli NEW_OUTPUT_DIR SAMPLES [--heap]");
    let output = args.first().ok_or_else(usage)?;
    let samples = sample_count(args.get(1).map_or("30", String::as_str), 1000).ok_or_else(usage)?;
    let heap = match args.get(2).map(String::as_str) {
        None | Some("") => false,
        Some("--heap") => true,
        Some(_) => return Err(usage()),
    };
    if !matches!(platform(), "linux" | "darwin") {
        return Err("CPU/RSS requires Linux or macOS".into());
    }
    if heap && platform() != "linux" {
        return Err("Valgrind heap comparison requires Linux".into());
    }
    let report = execute(Path::new(output), samples, heap, &binaries()?)?;
    let results = report["results"].as_array().map_or(&[][..], Vec::as_slice);
    let measured = results
        .iter()
        .filter(|entry| entry.get("unsupported").is_none())
        .count();
    println!(
        "Validated {measured} comparable cases, {} unsupported; {samples} samples x 3 repetitions, heap={heap}",
        results.len() - measured
    );
    Ok(())
}
