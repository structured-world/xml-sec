//! Explicit operator policy commands, separate from the donor XML grammar.
use std::{collections::BTreeMap, ffi::OsString, io::Write, path::PathBuf};
use xml_sec::policy::{Instant, PolicyCompileContext, PolicyValidity};
use xml_sec_config::{Configuration, LoadLimits};

pub(crate) fn execute(
    args: impl Iterator<Item = OsString>,
    output: &mut dyn Write,
) -> Result<(), String> {
    let mut args = args;
    let action = args
        .next()
        .and_then(|v| v.into_string().ok())
        .ok_or("policy action required: check, show-effective or diff")?;
    if action == "help" || action == "--help" {
        return writeln!(output, "Usage: xmlsec1 policy <check|show-effective|diff> --file PATH --profile NAME [--other-file PATH --other-profile NAME] [--crypto rustcrypto|aws-lc-fips] [--external-resources] [--target-evidence]\nLegacy authorization: --authorization-id ID --authority NAME --reason TEXT --not-before UNIX_SECONDS --expires-at UNIX_SECONDS").map_err(|e| e.to_string());
    }
    if !matches!(action.as_str(), "check" | "show-effective" | "diff") {
        return Err(format!("unknown policy action {action}"));
    }
    let mut values = BTreeMap::new();
    let mut external_resources = false;
    let mut target_evidence = false;
    parse_options(
        &mut args,
        &mut values,
        &mut external_resources,
        &mut target_evidence,
    )?;
    if action != "diff"
        && (values.contains_key("--other-file") || values.contains_key("--other-profile"))
    {
        return Err("comparison options require policy diff".into());
    }
    let required = |key: &str| values.get(key).ok_or_else(|| format!("{key} is required"));
    let provider =
        crate::commands::provider_by_name(utf8(&values, "--crypto")?.unwrap_or("default"))
            .map_err(|e| e.to_string())?;
    let context = PolicyCompileContext {
        external_resources,
        target_evidence,
    };
    let grant = authorization(&values)?;
    let file = PathBuf::from(required("--file")?);
    let name = utf8(&values, "--profile")?.ok_or("--profile is required")?;
    let configuration =
        Configuration::from_path(file, LoadLimits::default()).map_err(|e| e.to_string())?;
    let policy = configuration
        .compile(name, provider, &context, grant.clone())
        .map_err(|e| e.to_string())?;
    match action.as_str() {
        "check" => writeln!(output, "policy {name}: valid").map_err(|e| e.to_string()),
        "show-effective" => output
            .write_all(policy.to_toml().map_err(|e| e.to_string())?.as_bytes())
            .map_err(|e| e.to_string()),
        "diff" => {
            let next = Configuration::from_path(
                PathBuf::from(required("--other-file")?),
                LoadLimits::default(),
            )
            .map_err(|e| e.to_string())?;
            let next_name =
                utf8(&values, "--other-profile")?.ok_or("--other-profile is required")?;
            let next = next
                .compile(next_name, provider, &context, grant)
                .map_err(|e| e.to_string())?;
            write_diff(output, policy.diff(&next)).map_err(|e| e.to_string())
        }
        _ => Err("invalid policy action".into()),
    }
}

fn utf8<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<Option<&'a str>, String> {
    values
        .get(key)
        .map(|v| v.to_str().ok_or_else(|| format!("{key} must be UTF-8")))
        .transpose()
}

/// The operator grant, present only when any of its fields is supplied and
/// then requiring all of them.
fn authorization(values: &BTreeMap<String, OsString>) -> Result<Option<PolicyValidity>, String> {
    let grant_fields = [
        "--authorization-id",
        "--authority",
        "--reason",
        "--not-before",
        "--expires-at",
    ];
    if !grant_fields.iter().any(|key| values.contains_key(*key)) {
        return Ok(None);
    }
    let text = |key| -> Result<String, String> {
        Ok(utf8(values, key)?
            .ok_or_else(|| format!("{key} is required"))?
            .to_owned())
    };
    let time = |key| -> Result<Instant, String> {
        let seconds = utf8(values, key)?
            .ok_or_else(|| format!("{key} is required"))?
            .parse::<i64>()
            .map_err(|_| format!("{key} requires signed Unix seconds"))?;
        // The configuration's signed epoch model: every i64 second is an instant.
        Instant::new(seconds, 0).ok_or_else(|| format!("{key} is not a valid instant"))
    };
    Ok(Some(PolicyValidity {
        authorization_id: text("--authorization-id")?,
        authority: text("--authority")?,
        reason: text("--reason")?,
        not_before: time("--not-before")?,
        expires_at: time("--expires-at")?,
    }))
}

fn write_diff(output: &mut dyn Write, changes: Vec<xml_sec_config::Change>) -> std::io::Result<()> {
    if changes.is_empty() {
        writeln!(output, "neutral: effective policies are identical")?;
    }
    for change in changes {
        writeln!(
            output,
            "{:?}: {}: {:?} -> {:?}",
            change.direction, change.field, change.before, change.after
        )?;
    }
    Ok(())
}

fn parse_options(
    args: &mut impl Iterator<Item = OsString>,
    values: &mut BTreeMap<String, OsString>,
    external: &mut bool,
    targets: &mut bool,
) -> Result<(), String> {
    while let Some(key) = args.next() {
        let key = key
            .into_string()
            .map_err(|_| "policy option must be UTF-8")?;
        match key.as_str() {
            "--external-resources" | "--target-evidence" => {
                let flag = if key == "--external-resources" {
                    &mut *external
                } else {
                    &mut *targets
                };
                if std::mem::replace(flag, true) {
                    return Err(format!("duplicate option {key}"));
                }
            }
            "--file" | "--profile" | "--other-file" | "--other-profile" | "--crypto"
            | "--authorization-id" | "--authority" | "--reason" | "--not-before"
            | "--expires-at" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{key} requires a value"))?;
                match values.entry(key) {
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        return Err(format!("duplicate option {}", entry.key()));
                    }
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                }
            }
            _ => return Err(format!("unknown policy option {key}")),
        }
    }
    Ok(())
}
