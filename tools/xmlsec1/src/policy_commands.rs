//! Explicit operator policy commands, separate from the donor XML grammar.
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Write,
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};
use xml_sec::policy::{PolicyCompileContext, PolicyValidity};
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
    for_loop(
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
    let utf8 = |key: &str| -> Result<Option<&str>, String> {
        values
            .get(key)
            .map(|v: &OsString| v.to_str().ok_or_else(|| format!("{key} must be UTF-8")))
            .transpose()
    };
    let required = |key: &str| values.get(key).ok_or_else(|| format!("{key} is required"));
    let provider = crate::commands::provider_by_name(utf8("--crypto")?.unwrap_or("default"))
        .map_err(|e| e.to_string())?;
    let context = PolicyCompileContext {
        external_resources,
        target_evidence,
    };
    let grant_fields = [
        "--authorization-id",
        "--authority",
        "--reason",
        "--not-before",
        "--expires-at",
    ];
    let grant = if grant_fields.iter().any(|key| values.contains_key(*key)) {
        let text = |key| -> Result<String, String> {
            Ok(required(key)?
                .to_str()
                .ok_or_else(|| format!("{key} must be UTF-8"))?
                .to_owned())
        };
        let time = |key| -> Result<std::time::SystemTime, String> {
            let seconds = utf8(key)?
                .ok_or_else(|| format!("{key} is required"))?
                .parse::<i64>()
                .map_err(|_| format!("{key} requires signed Unix seconds"))?;
            // Match the configuration's signed epoch model; unsigned_abs also
            // handles i64::MIN without a signed negation overflow.
            let duration = Duration::from_secs(seconds.unsigned_abs());
            let time = if seconds < 0 {
                UNIX_EPOCH.checked_sub(duration)
            } else {
                UNIX_EPOCH.checked_add(duration)
            };
            time.ok_or_else(|| format!("{key} overflows SystemTime"))
        };
        Some(PolicyValidity {
            authorization_id: text("--authorization-id")?,
            authority: text("--authority")?,
            reason: text("--reason")?,
            not_before: time("--not-before")?,
            expires_at: time("--expires-at")?,
        })
    } else {
        None
    };
    let file = PathBuf::from(required("--file")?);
    let name = utf8("--profile")?.ok_or("--profile is required")?;
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
            let next_name = utf8("--other-profile")?.ok_or("--other-profile is required")?;
            let next = next
                .compile(next_name, provider, &context, grant)
                .map_err(|e| e.to_string())?;
            let changes = policy.diff(&next);
            if changes.is_empty() {
                writeln!(output, "neutral: effective policies are identical")
                    .map_err(|e| e.to_string())?;
            }
            for change in changes {
                writeln!(
                    output,
                    "{:?}: {}: {:?} -> {:?}",
                    change.direction, change.field, change.before, change.after
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        _ => Err("invalid policy action".into()),
    }
}

fn for_loop(
    args: &mut impl Iterator<Item = OsString>,
    values: &mut BTreeMap<String, OsString>,
    external: &mut bool,
    targets: &mut bool,
) -> Result<(), String> {
    let mut flags = std::collections::BTreeSet::new();
    while let Some(key) = args.next() {
        let key = key
            .into_string()
            .map_err(|_| "policy option must be UTF-8")?;
        match key.as_str() {
            "--external-resources" | "--target-evidence" => {
                if !flags.insert(key.clone()) {
                    return Err(format!("duplicate option {key}"));
                }
                if key == "--external-resources" {
                    *external = true;
                } else {
                    *targets = true;
                }
            }
            "--file" | "--profile" | "--other-file" | "--other-profile" | "--crypto"
            | "--authorization-id" | "--authority" | "--reason" | "--not-before"
            | "--expires-at" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{key} requires a value"))?;
                if values.insert(key.clone(), value).is_some() {
                    return Err(format!("duplicate option {key}"));
                }
            }
            _ => return Err(format!("unknown policy option {key}")),
        }
    }
    Ok(())
}
