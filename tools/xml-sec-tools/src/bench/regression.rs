//! `bench-regression BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR`: compares one
//! comparison run against an earlier one. Only runs measured on the same
//! environment, build and corpus are compared; anything else is reported as
//! incomparable with its reason. The report records observations, never a
//! pass or fail verdict: no fixed latency threshold is established.

use super::{float, number, read_json, timestamp, write_json};
use crate::repo::Failure;
use serde_json::{Map, Value, json};
use std::path::Path;

#[cfg(test)]
mod tests;

/// The contract's minimum before drawing any performance conclusion.
pub(crate) const MIN_REPETITIONS: f64 = 3.0;
const ENVIRONMENT: [&str; 5] = ["platform", "architecture", "cpu", "samples", "repetitions"];
const PERCENTILES: [&str; 3] = ["p50_ns", "p95_ns", "p99_ns"];
const ALLOCATIONS: [&str; 3] = ["allocation_calls", "allocated_bytes", "peak_heap_bytes"];

/// One run directory's reports and build identity, or why it is unusable.
#[derive(Debug, Clone)]
pub(crate) enum Run {
    Usable {
        cli: Value,
        library: Value,
        build: Value,
    },
    Missing(String),
}

impl Run {
    pub(crate) fn load(directory: &Path) -> Self {
        let mut parts = Vec::new();
        for (file, schema, measured) in [
            ("comparison.json", 2, true),
            ("library.json", 1, true),
            ("build.json", 1, false),
        ] {
            let location = directory.join(file);
            if !location.exists() {
                return Self::Missing(format!("{file} is missing"));
            }
            let Ok(value) = read_json(&location) else {
                return Self::Missing(format!("{file} is not valid JSON"));
            };
            if value.get("schema").and_then(Value::as_u64) != Some(schema) {
                let found = value
                    .get("schema")
                    .map_or_else(|| "undefined".into(), js_text);
                return Self::Missing(format!("{file} has schema {found}, expected {schema}"));
            }
            if measured {
                if !value["results"].is_array() {
                    return Self::Missing(format!("{file} has no results"));
                }
                if let Some(invalid) = invalid_case(&value) {
                    return Self::Missing(format!("{file} case {invalid}"));
                }
            }
            parts.push(value);
        }
        let [cli, library, build] = <[Value; 3]>::try_from(parts).expect("three reports");
        Self::Usable {
            cli,
            library,
            build,
        }
    }
}

/// A value as `JSON.stringify` would write it, `undefined` for absence.
pub(crate) fn js_text(value: &Value) -> String {
    match value {
        Value::Number(_) => {
            float(value).map_or_else(|| value.to_string(), |float| number(float).to_string())
        }
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(js_text).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, value)| format!("{}:{}", Value::from(key.clone()), js_text(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => other.to_string(),
    }
}

/// Equality as JavaScript reports compared it: equal JSON text.
fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    left.map(js_text) == right.map(js_text)
}

fn measurement(value: &Value) -> bool {
    float(value).is_some_and(|value| value >= 0.0)
}

fn case_key(entry: &Value) -> String {
    [
        "level",
        "engine",
        "scenario",
        "name",
        "operation",
        "boundary",
    ]
    .iter()
    .map(|field| match &entry[*field] {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => js_text(other),
    })
    .collect::<Vec<_>>()
    .join(" | ")
}

fn supported(entry: &Value) -> bool {
    !matches!(&entry["unsupported"], Value::String(text) if !text.is_empty())
        && !matches!(&entry["unsupported"], Value::Bool(true))
}

/// The first supported case whose measurements no runner would write.
pub(crate) fn invalid_case(report: &Value) -> Option<String> {
    let expected = &report["environment"]["repetitions"];
    for entry in report["results"].as_array().into_iter().flatten() {
        if !supported(entry) {
            continue;
        }
        let repetitions = entry["repetitions"].as_array();
        let reason = if repetitions
            .is_none_or(|items| !same(Some(&number_of(items.len())), Some(expected)))
        {
            let count = repetitions.map_or_else(|| "no".into(), |items| items.len().to_string());
            Some(format!(
                "has {count} repetitions, expected {}",
                js_or_undefined(expected)
            ))
        } else if repetitions.into_iter().flatten().any(|item| {
            !PERCENTILES.iter().all(|field| {
                measurement(&item[*field]) && float(&item[*field]).is_some_and(|value| value > 0.0)
            })
        }) {
            Some("has a missing or non-positive percentile".into())
        } else if entry["memory"].is_object()
            && !ALLOCATIONS
                .iter()
                .all(|field| measurement(&entry["memory"][*field]))
        {
            Some("has an incomplete allocation profile".into())
        } else {
            None
        };
        if let Some(reason) = reason {
            return Some(format!("{} {reason}", case_key(entry)));
        }
    }
    None
}

fn number_of(count: usize) -> Value {
    Value::from(count)
}

fn js_or_undefined(value: &Value) -> String {
    if value.is_null() {
        "undefined".into()
    } else {
        js_text(value)
    }
}

fn run_parts(run: &Run) -> Option<(&Value, &Value, &Value)> {
    match run {
        Run::Usable {
            cli,
            library,
            build,
        } => Some((cli, library, build)),
        Run::Missing(_) => None,
    }
}

/// Reasons the two runs cannot be compared; empty when they can.
pub(crate) fn incomparability(
    baseline: (&Value, &Value, &Value),
    candidate: (&Value, &Value, &Value),
) -> Vec<String> {
    let mut reasons = Vec::new();
    for (label, (cli, library, _)) in [("baseline", baseline), ("candidate", candidate)] {
        for (level, report) in [("cli", cli), ("library", library)] {
            let samples = &report["environment"]["samples"];
            let repetitions = &report["environment"]["repetitions"];
            let enough = float(samples).is_some_and(|samples| samples > 1.0)
                && float(repetitions).is_some_and(|repetitions| repetitions >= MIN_REPETITIONS);
            if !enough {
                reasons.push(format!(
                    "{label} {level} run has {} samples x {} repetitions; it proves harness operation only",
                    js_or_undefined(samples),
                    js_or_undefined(repetitions)
                ));
            }
        }
    }
    for (level, base, next) in [
        ("cli", baseline.0, candidate.0),
        ("library", baseline.1, candidate.1),
    ] {
        for field in ENVIRONMENT {
            let left = base["environment"].get(field);
            let right = next["environment"].get(field);
            if !same(left, right) {
                let show =
                    |value: Option<&Value>| value.map_or_else(|| "undefined".into(), js_text);
                reasons.push(format!(
                    "{level} environment {field} differs: {} vs {}",
                    show(left),
                    show(right)
                ));
            }
        }
    }
    let fields = |build: &Value| -> Vec<String> {
        build
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, _)| key.clone())
            .filter(|key| key != "schema")
            .collect()
    };
    let mut names = fields(baseline.2);
    for name in fields(candidate.2) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for name in names {
        if !same(baseline.2.get(&name), candidate.2.get(&name)) {
            reasons.push(format!("build {name} differs"));
        }
    }
    if !same(baseline.0.get("corpus"), candidate.0.get("corpus")) {
        reasons.push("corpus digests differ".into());
    }
    reasons
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        f64::midpoint(sorted[middle - 1], sorted[middle])
    }
}

fn extreme(values: &[f64], larger: bool) -> f64 {
    values.iter().copied().fold(
        if larger {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        },
        |acc, value| {
            if larger {
                acc.max(value)
            } else {
                acc.min(value)
            }
        },
    )
}

/// Threshold-free ordering of two repetition sets.
pub(crate) fn ordering(baseline: &[f64], candidate: &[f64]) -> &'static str {
    if extreme(candidate, false) > extreme(baseline, true) {
        "higher in every repetition"
    } else if extreme(candidate, true) < extreme(baseline, false) {
        "lower in every repetition"
    } else {
        "overlapping"
    }
}

fn metric(baseline: &[f64], candidate: &[f64]) -> Value {
    let (base, next) = (median(baseline), median(candidate));
    json!({
        "baseline": baseline.iter().map(|value| number(*value)).collect::<Vec<_>>(),
        "candidate": candidate.iter().map(|value| number(*value)).collect::<Vec<_>>(),
        "baseline_median": number(base),
        "candidate_median": number(next),
        "median_ratio": if base > 0.0 { number(next / base) } else { Value::Null },
        "ordering": ordering(baseline, candidate),
    })
}

/// Per-repetition peak RSS: library repetitions carry it, CLI samples carry it each.
fn rss(repetition: &Value) -> f64 {
    float(&repetition["rss_bytes"]).unwrap_or_else(|| {
        repetition["raw"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|sample| float(&sample["rss_bytes"]).unwrap_or(0.0))
            .fold(f64::NEG_INFINITY, f64::max)
    })
}

/// Pairs one entry from each run that measured the same thing.
pub(crate) fn compare_entry(baseline: &Value, candidate: &Value) -> Value {
    let series = |entry: &Value, read: &dyn Fn(&Value) -> f64| -> Vec<f64> {
        entry["repetitions"]
            .as_array()
            .into_iter()
            .flatten()
            .map(read)
            .collect()
    };
    let mut latency = Map::new();
    for field in PERCENTILES {
        let read = |item: &Value| float(&item[field]).unwrap_or(f64::NAN);
        latency.insert(
            field.into(),
            metric(&series(baseline, &read), &series(candidate, &read)),
        );
    }
    let mut result = json!({
        "status": "compared",
        "latency": latency,
        "rss_bytes": metric(&series(baseline, &rss), &series(candidate, &rss)),
    });
    // Allocation counts come from one instrumented operation; a missing profile stays missing.
    let (base, next) = (&baseline["memory"], &candidate["memory"]);
    result["allocations"] = if base.is_object() && next.is_object() {
        let mut allocations = Map::new();
        for field in ALLOCATIONS {
            let change = match (float(&base[field]), float(&next[field])) {
                (Some(base), Some(next)) => number(next - base),
                _ => Value::Null,
            };
            allocations.insert(
                field.into(),
                json!({ "baseline": base[field], "candidate": next[field], "change": change }),
            );
        }
        Value::Object(allocations)
    } else {
        let missing = if base.is_object() {
            "candidate"
        } else if next.is_object() {
            "baseline"
        } else {
            "both"
        };
        json!({ "not_measured": missing })
    };
    result
}

fn index(cli: &Value, library: &Value) -> Vec<(String, Value)> {
    let mut entries: Vec<(String, Value)> = Vec::new();
    for entry in cli["results"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(library["results"].as_array().into_iter().flatten())
    {
        let key = case_key(entry);
        // A later entry with the same identity replaces the earlier one, in its place.
        if let Some(existing) = entries.iter_mut().find(|(name, _)| *name == key) {
            existing.1 = entry.clone();
        } else {
            entries.push((key, entry.clone()));
        }
    }
    entries
}

fn unsupported_reason(entry: &Value) -> Value {
    match &entry["unsupported"] {
        Value::Null => Value::Null,
        other => other.clone(),
    }
}

/// The complete report; every entry of either run appears exactly once.
pub(crate) fn report(baseline_run: &Run, candidate_run: &Run) -> Result<Value, String> {
    let candidate = match candidate_run {
        Run::Missing(reason) => return Err(format!("candidate run is unusable: {reason}")),
        Run::Usable { .. } => run_parts(candidate_run).expect("usable"),
    };
    let baseline = run_parts(baseline_run);
    let reasons = match (baseline_run, baseline) {
        (Run::Missing(reason), _) => vec![format!("no usable baseline: {reason}")],
        (_, Some(baseline)) => incomparability(baseline, candidate),
        (_, None) => Vec::new(),
    };
    let candidates = index(candidate.0, candidate.1);
    let baselines = baseline
        .map(|baseline| index(baseline.0, baseline.1))
        .unwrap_or_default();
    let mut names: Vec<&String> = baselines.iter().map(|(name, _)| name).collect();
    for (name, _) in &candidates {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let find = |list: &[(String, Value)], name: &str| {
        list.iter()
            .find(|(key, _)| key == name)
            .map(|(_, entry)| entry.clone())
    };
    let mut entries = Vec::new();
    let mut counts = Map::new();
    for name in names {
        let base = find(&baselines, name);
        let next = find(&candidates, name);
        let mut entry = match (&base, &next) {
            (_, None) => json!({ "status": "missing in candidate" }),
            (None, Some(_)) => {
                json!({ "status": if baseline.is_none() { "no baseline" } else { "missing in baseline" } })
            }
            (Some(base), Some(next)) if !supported(base) || !supported(next) => json!({
                "status": "unsupported",
                "baseline": unsupported_reason(base),
                "candidate": unsupported_reason(next),
            }),
            (Some(_), Some(_)) if !reasons.is_empty() => json!({ "status": "incomparable" }),
            (Some(base), Some(next)) => compare_entry(base, next),
        };
        let label = if entry["status"] == "compared" {
            format!(
                "compared, p50 {}",
                entry["latency"]["p50_ns"]["ordering"]
                    .as_str()
                    .unwrap_or_default()
            )
        } else {
            entry["status"].as_str().unwrap_or_default().to_owned()
        };
        let count = counts.get(&label).and_then(Value::as_u64).unwrap_or(0) + 1;
        counts.insert(label, Value::from(count));
        let mut ordered = Map::new();
        ordered.insert("case".into(), Value::from(name.clone()));
        ordered.extend(
            entry
                .as_object_mut()
                .map(std::mem::take)
                .unwrap_or_default(),
        );
        entries.push(Value::Object(ordered));
    }
    let revision = |cli: &Value| {
        json!({
            "source_revision": cli.get("source_revision").cloned().unwrap_or(Value::Null),
            "generated": cli.get("generated").cloned().unwrap_or(Value::Null),
        })
    };
    Ok(json!({
        "schema": 1,
        "generated": timestamp(),
        "comparable": reasons.is_empty(),
        "incomparable_reasons": reasons,
        "baseline": baseline.map_or(Value::Null, |baseline| revision(baseline.0)),
        "candidate": revision(candidate.0),
        "counts": counts,
        "entries": entries,
    }))
}

fn rounded(value: &Value) -> String {
    float(value).map_or_else(|| "NaN".into(), |value| number(value.round()).to_string())
}

/// A short human summary; the JSON report is the evidence.
pub(crate) fn summary(report: &Value) -> String {
    let text = |value: &Value, absent: &str| {
        value
            .as_str()
            .map_or_else(|| absent.to_owned(), str::to_owned)
    };
    let mut lines = vec![
        "## Benchmark regression report".to_owned(),
        String::new(),
        format!(
            "Candidate {}, baseline {}.",
            text(&report["candidate"]["source_revision"], "unknown"),
            text(&report["baseline"]["source_revision"], "none")
        ),
        "Observations only: no fixed threshold is applied, and nothing here is a pass or fail verdict.".into(),
        String::new(),
    ];
    if report["comparable"] != true {
        lines.push("Not comparable:".into());
        for reason in report["incomparable_reasons"]
            .as_array()
            .into_iter()
            .flatten()
        {
            lines.push(format!("- {}", reason.as_str().unwrap_or_default()));
        }
        lines.push(String::new());
    }
    lines.push("| Outcome | Cases |".into());
    lines.push("|---|---|".into());
    for (label, count) in report["counts"].as_object().into_iter().flatten() {
        lines.push(format!("| {label} | {count} |"));
    }
    let separated: Vec<&Value> = report["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry["status"] == "compared" && entry["latency"]["p50_ns"]["ordering"] != "overlapping"
        })
        .collect();
    if !separated.is_empty() {
        lines.push(String::new());
        lines.push("| Case | p50 | baseline median ns | candidate median ns |".into());
        lines.push("|---|---|---|---|".into());
        for entry in separated {
            let p50 = &entry["latency"]["p50_ns"];
            // The case identity joins its parts with pipes, which a table cell must escape.
            lines.push(format!(
                "| {} | {} | {} | {} |",
                entry["case"]
                    .as_str()
                    .unwrap_or_default()
                    .replace('|', "\\|"),
                p50["ordering"].as_str().unwrap_or_default(),
                rounded(&p50["baseline_median"]),
                rounded(&p50["candidate_median"]),
            ));
        }
    }
    format!("{}\n", lines.join("\n"))
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let [baseline, candidate, output] = args.as_slice() else {
        return Err("Usage: bench-regression BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR".into());
    };
    let report = report(
        &Run::load(Path::new(baseline)),
        &Run::load(Path::new(candidate)),
    )?;
    let output = Path::new(output);
    write_json(&output.join("regression.json"), &report)?;
    let text = summary(&report);
    std::fs::write(output.join("regression.md"), &text).map_err(|error| error.to_string())?;
    print!("{text}");
    Ok(())
}
