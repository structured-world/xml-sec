//! Shape and identity checks of an LLVM coverage export. LLVM owns the
//! executable-line and threshold semantics; this only refuses a report whose
//! sources are duplicated or not canonical, so no competing metric arises.

use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

/// Largest integer every JSON consumer represents exactly.
const SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn integer(value: Option<&Value>) -> Option<f64> {
    let number = value?.as_f64()?;
    (number.fract() == 0.0 && number.abs() <= SAFE_INTEGER).then_some(number)
}

/// Validates `report`; `canonical` resolves a filename to its physical path.
/// Returns the summary `{sources, count, covered, percent}`.
pub(crate) fn check(
    report: &Value,
    canonical: impl Fn(&str) -> Result<String, String>,
) -> Result<Value, String> {
    let export = report.get("type").and_then(Value::as_str) == Some("llvm.coverage.json.export");
    let data = report
        .get("data")
        .and_then(Value::as_array)
        .filter(|data| export && data.len() == 1);
    let files = data
        .and_then(|data| data[0].get("files"))
        .and_then(Value::as_array)
        .filter(|files| !files.is_empty())
        .ok_or("Expected one nonempty LLVM coverage export")?;
    let mut seen = BTreeSet::new();
    for file in files {
        let name = file
            .get("filename")
            .and_then(Value::as_str)
            .ok_or("Expected one nonempty LLVM coverage export")?;
        let physical = canonical(name)?;
        if seen.contains(&physical) {
            return Err(format!("Duplicate coverage source: {name}"));
        }
        if physical != name {
            return Err(format!("Noncanonical coverage source: {name}"));
        }
        seen.insert(physical);
    }
    let lines = data
        .and_then(|data| data[0].get("totals"))
        .and_then(|totals| totals.get("lines"));
    let count = integer(lines.and_then(|lines| lines.get("count")));
    let covered = integer(lines.and_then(|lines| lines.get("covered")));
    let percent = lines
        .and_then(|lines| lines.get("percent"))
        .and_then(Value::as_f64);
    match (count, covered, percent) {
        (Some(count), Some(covered), Some(percent))
            if count > 0.0
                && covered >= 0.0
                && covered <= count
                && percent.is_finite()
                && (0.0..=100.0).contains(&percent) => {}
        _ => return Err("Invalid LLVM line totals".into()),
    }
    let lines = lines.expect("validated totals");
    let mut summary = Map::new();
    summary.insert("sources".into(), Value::Number(Number::from(seen.len())));
    for field in ["count", "covered", "percent"] {
        summary.insert(field.into(), lines[field].clone());
    }
    Ok(Value::Object(summary))
}

/// Checks the report file at `path` against the physical filesystem.
pub(crate) fn check_file(path: &std::path::Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let report: Value = serde_json::from_str(&text)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    check(&report, |name| {
        std::fs::canonicalize(name)
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| format!("resolve coverage source {name}: {error}"))
    })
}
