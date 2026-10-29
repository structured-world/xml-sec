//! Benchmark runners and reports: command-line and library comparisons with
//! competitor engines, XSLT measurements, regression reports and the
//! published dashboard.

use regex::Regex;
use serde_json::{Number, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) mod cli;
pub(crate) mod compare;
pub(crate) mod dashboard;
pub(crate) mod identity;
pub(crate) mod latency;
pub(crate) mod library;
pub(crate) mod regression;
pub(crate) mod xslt;

#[cfg(test)]
mod tests;

/// Operations measured for each workload family; `payload` is the original five shapes.
pub(crate) const SCENARIOS: [(&str, &[&str]); 5] = [
    ("payload", &["sign", "verify", "encrypt", "decrypt"]),
    ("assertion", &["sign", "verify"]),
    ("element", &["encrypt", "decrypt"]),
    ("element_in_place", &["encrypt", "decrypt"]),
    ("xslt", &["sign", "verify"]),
];

pub(crate) fn operations(scenario: &str) -> Result<&'static [&'static str], String> {
    SCENARIOS
        .iter()
        .find(|(name, _)| *name == scenario)
        .map(|(_, operations)| *operations)
        .ok_or_else(|| format!("unknown workload {scenario}"))
}

/// Why `engine` cannot run `operation` of `scenario` at the pinned competitor
/// revision, or `None` when it can; never timed.
pub(crate) fn unsupported(engine: &str, scenario: &str, operation: &str) -> Option<&'static str> {
    match (engine, scenario, operation) {
        ("bergshamra", "assertion", "sign") => {
            Some("leaves the template X509Data empty; the signer certificate is never written")
        }
        ("bergshamra", "element_in_place", "encrypt") => Some(
            "CLI --node-id writes a standalone EncryptedData instead of replacing the element inside its document",
        ),
        ("bergshamra", "xslt", "sign") => Some("no XSLT transform"),
        ("bergshamra", "xslt", "verify") => {
            Some("no XSLT transform: an XSLT-transformed Reference fails with a digest mismatch")
        }
        _ => None,
    }
}

/// Nearest-rank percentile (`percent` of 100); the input is not reordered.
pub(crate) fn percentile(values: &[f64], percent: usize) -> Result<f64, String> {
    if values.is_empty()
        || values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err("Invalid samples".into());
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = percent
        .checked_mul(sorted.len())
        .map(|scaled| scaled.div_ceil(100))
        .filter(|rank| (1..=sorted.len()).contains(rank))
        .ok_or("Invalid samples")?;
    Ok(sorted[rank - 1])
}

/// The CPU seconds and peak RSS bytes `/usr/bin/time` reported for one process.
pub(crate) fn resources(text: &str, platform: &str) -> Result<(f64, f64), String> {
    let missing = || "Missing process CPU/RSS report".to_owned();
    if platform == "darwin" {
        let pattern = Regex::new(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys(?s:.*?)(\d+)\s+maximum resident set size")
            .expect("valid pattern");
        let found = pattern.captures(text).ok_or_else(missing)?;
        let value = |index: usize| found[index].parse::<f64>().map_err(|_| missing());
        Ok((value(2)? + value(3)?, value(4)?))
    } else {
        let pattern = Regex::new(r"__METRICS ([\d.]+) ([\d.]+) (\d+)").expect("valid pattern");
        let found = pattern.captures(text).ok_or_else(missing)?;
        let value = |index: usize| found[index].parse::<f64>().map_err(|_| missing());
        Ok((value(1)? + value(2)?, value(3)? * 1024.0))
    }
}

/// Valgrind memcheck totals and the massif high-water mark of requested plus
/// allocator bytes.
pub(crate) fn heap_stats(memcheck: &str, massif: &str) -> Result<(u64, u64, u64), String> {
    let missing = || "Missing Valgrind allocation/heap report".to_owned();
    let total =
        Regex::new(r"total heap usage: ([\d,]+) allocs, [\d,]+ frees, ([\d,]+) bytes allocated")
            .expect("valid pattern")
            .captures(memcheck)
            .ok_or_else(missing)?;
    let number = |text: &str| text.replace(',', "").parse::<u64>().map_err(|_| missing());
    let snapshot = Regex::new(r"mem_heap_B=(\d+)\nmem_heap_extra_B=(\d+)").expect("valid pattern");
    let mut peak: Option<u64> = None;
    for found in snapshot.captures_iter(massif) {
        let bytes = number(&found[1])?
            .checked_add(number(&found[2])?)
            .ok_or_else(missing)?;
        peak = Some(peak.map_or(bytes, |peak| peak.max(bytes)));
    }
    Ok((
        number(&total[1])?,
        number(&total[2])?,
        peak.ok_or_else(missing)?,
    ))
}

/// The reason an engine gave for refusing an input over one of its default
/// resource limits, or `None` for any other failure. A refusal is recorded per
/// input and never timed, so a later revision that accepts it is measured again.
pub(crate) fn policy_refusal(stderr: &str) -> Option<String> {
    Regex::new(r"policy violation: (.*exceeds policy maximum.*)")
        .expect("valid pattern")
        .captures(stderr)
        .map(|found| found[1].trim().to_owned())
}

/// Creates a new evidence directory; existing evidence is never overwritten.
pub(crate) fn create_evidence_directory(output: &Path) -> Result<(), String> {
    let absolute = std::path::absolute(output).map_err(|error| error.to_string())?;
    if let Some(parent) = absolute.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    std::fs::create_dir(output).map_err(|error| format!("create {}: {error}", output.display()))
}

/// The XML document without the declaration and surrounding whitespace
/// engines add on output.
pub(crate) fn document_body(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    let body = if text.starts_with("<?xml") {
        text.find("?>").map_or(text, |end| &text[end + 2..])
    } else {
        text
    };
    body.trim().to_owned()
}

/// Changes one signed value so that every engine must reject the document. A
/// replacement that matches nothing would turn the rejection check into a
/// check of an intact document.
pub(crate) fn tamper(xml: &str, scenario: &str) -> Result<String, String> {
    let (from, to) = match scenario {
        "payload" => (
            "<Payload Id=\"payload\">",
            "<Payload Id=\"payload\" altered=\"true\">",
        ),
        "assertion" => (
            "<saml:AttributeValue>value</saml:AttributeValue>",
            "<saml:AttributeValue>tampered</saml:AttributeValue>",
        ),
        "xslt" => (
            "<Item n=\"0\">value</Item>",
            "<Item n=\"0\">tampered</Item>",
        ),
        _ => return Err(format!("Tamper target missing for {scenario}")),
    };
    if !xml.contains(from) {
        return Err(format!("Tamper target missing for {scenario}"));
    }
    Ok(xml.replacen(from, to, 1))
}

/// Signature wrapping: an unsigned forged assertion with the signed
/// assertion's ID and another subject precedes the untouched signed one. A
/// verifier that reported success would leave the application free to read
/// the forgery.
pub(crate) fn wrap(xml: &str) -> Result<String, String> {
    let close = "</saml:Assertion>";
    let start = xml
        .find("<saml:Assertion ID=\"assertion\"")
        .ok_or("Signed assertion missing")?;
    let end = start + xml[start..].find(close).ok_or("Signed assertion missing")?;
    let signed = &xml[start..end + close.len()];
    let signature = Regex::new(r"<ds:Signature[\s>](?s:.*)</ds:Signature>").expect("valid pattern");
    let subject = "<saml:NameID>user@example.invalid</saml:NameID>";
    if !signature.is_match(signed) || !signed.contains(subject) {
        return Err("Signed assertion has no signature or subject".into());
    }
    let forged = signature.replace(signed, "").replacen(
        subject,
        "<saml:NameID>attacker@example.invalid</saml:NameID>",
        1,
    );
    Ok(format!(
        "{}{forged}{signed}{}",
        &xml[..start],
        &xml[end + close.len()..]
    ))
}

/// Input files of one case: what each operation reads.
pub(crate) struct CaseFiles {
    pub(crate) template: String,
    pub(crate) signed: String,
    pub(crate) plain: String,
    pub(crate) encrypted: String,
}

pub(crate) fn case_files(name: &str, scenario: &str, units: &Value) -> CaseFiles {
    let units = match units {
        Value::String(units) => units.clone(),
        other => other.to_string(),
    };
    CaseFiles {
        template: format!("{name}.template.xml"),
        signed: format!("{name}.signed.xml"),
        plain: match scenario {
            "element" => format!("element-{units}.plain.xml"),
            "element_in_place" => format!("order-{units}.plain.xml"),
            _ => format!("{name}.plain.xml"),
        },
        encrypted: format!("{name}.encrypted.xml"),
    }
}

/// A JSON number written the way a JavaScript report writes it: integral
/// values without a fraction.
pub(crate) fn number(value: f64) -> Value {
    const SAFE: f64 = 9_007_199_254_740_991.0;
    if value.is_finite() && value.fract() == 0.0 && value.abs() <= SAFE {
        // An integral value in the exact range prints as its integer, so this
        // conversion loses nothing.
        format!("{value}")
            .parse::<i64>()
            .map_or(Value::Null, |integer| Value::Number(Number::from(integer)))
    } else {
        Number::from_f64(value).map_or(Value::Null, Value::Number)
    }
}

/// A count as `f64`, exact below 2^53, which nanosecond timings and byte
/// counts of these runs stay under.
pub(crate) fn to_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).expect("the high half fits 32 bits");
    let low = u32::try_from(value & u64::from(u32::MAX)).expect("the low half fits 32 bits");
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

/// A finite JSON number as `f64`.
pub(crate) fn float(value: &Value) -> Option<f64> {
    value.as_f64().filter(|value| value.is_finite())
}

/// An integer JSON consumers represent exactly.
pub(crate) fn safe_integer(value: &Value) -> Option<f64> {
    float(value).filter(|value| value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0)
}

/// The current time as an ISO 8601 UTC timestamp with milliseconds.
pub(crate) fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp(elapsed)
}

pub(crate) fn format_timestamp(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let of_day = seconds % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian calendar).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60,
        elapsed.subsec_millis()
    )
}

/// The platform name JavaScript reports used, so earlier runs stay comparable.
pub(crate) fn platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    }
}

/// The architecture name JavaScript reports used.
pub(crate) fn architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        arch => arch,
    }
}

/// The processor model the operating system reports for the first CPU.
pub(crate) fn cpu_model() -> Value {
    if platform() == "darwin" {
        return Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map_or(Value::Null, |output| {
                Value::from(String::from_utf8_lossy(&output.stdout).trim().to_owned())
            });
    }
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| {
                    line.strip_prefix("model name")
                        .and_then(|rest| rest.split_once(':'))
                })
                .map(|(_, model)| Value::from(model.trim().to_owned()))
        })
        .unwrap_or(Value::Null)
}

/// The result of one captured child process.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub(crate) code: Option<i32>,
    pub(crate) signal: Option<i32>,
    /// Spawning failed or the process outlived its time limit.
    pub(crate) error: Option<String>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Captured {
    pub(crate) fn succeeded(&self) -> bool {
        self.error.is_none() && self.signal.is_none() && self.code == Some(0)
    }

    /// Why the process did not succeed, in the order a report names it.
    pub(crate) fn failure(&self) -> String {
        self.error
            .clone()
            .or_else(|| self.signal.map(|signal| format!("signal {signal}")))
            .unwrap_or_else(|| {
                self.code
                    .map_or_else(|| "unknown".into(), |code| code.to_string())
            })
    }
}

fn drain(mut reader: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        // A read error leaves what was read; the exit status reports the failure.
        if reader.read_to_end(&mut bytes).is_err() {
            bytes.extend_from_slice(b"\n[output read failed]");
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// Runs `command` with stdin closed, stderr captured and stdout captured only
/// when `keep_stdout`; the process is killed after `limit`.
pub(crate) fn capture(command: &mut Command, keep_stdout: bool, limit: Duration) -> Captured {
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(if keep_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return Captured {
                error: Some(error.to_string()),
                ..Captured::default()
            };
        }
    };
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let deadline = Instant::now() + limit;
    let mut error = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                error = Some(format!("timed out after {} s", limit.as_secs()));
                // The process may have exited meanwhile; either way it is reaped below.
                if child.kill().is_err() {
                    error = Some("timed out and could not be stopped".into());
                }
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(failure) => {
                error = Some(failure.to_string());
                break None;
            }
        }
    };
    let join = |handle: Option<std::thread::JoinHandle<String>>| {
        handle
            .map(|handle| handle.join().unwrap_or_default())
            .unwrap_or_default()
    };
    #[cfg(unix)]
    let signal = status.and_then(|status| std::os::unix::process::ExitStatusExt::signal(&status));
    #[cfg(not(unix))]
    let signal = None;
    Captured {
        code: status.and_then(|status| status.code()),
        signal,
        error,
        stdout: join(stdout),
        stderr: join(stderr),
    }
}

/// A command for `program` with `args`.
pub(crate) fn command<S: AsRef<std::ffi::OsStr>>(
    program: impl AsRef<std::ffi::OsStr>,
    args: &[S],
) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

/// Runs a command that must succeed and returns its stdout.
pub(crate) fn checked(mut command: Command, limit: Duration) -> Result<String, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let result = capture(&mut command, true, limit);
    if result.succeeded() {
        Ok(result.stdout)
    } else {
        Err(format!(
            "{program} failed: {}\n{}",
            result.failure(),
            result.stderr
        ))
    }
}

/// SHA-256 of a file's bytes, as hex.
pub(crate) fn digest_file(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| crate::security_corpus::sha256(&bytes))
        .map_err(|error| format!("read {}: {error}", path.display()))
}

/// Reads a JSON file.
pub(crate) fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

/// Writes `value` as compact JSON.
pub(crate) fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    std::fs::write(path, value.to_string())
        .map_err(|error| format!("write {}: {error}", path.display()))
}

/// Writes `value` as JSON indented by two spaces.
pub(crate) fn write_pretty(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))
}

/// Parses a sample count of at most `maximum`, written as plain digits.
pub(crate) fn sample_count(text: &str, maximum: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|samples| (1..=maximum).contains(samples))
}
