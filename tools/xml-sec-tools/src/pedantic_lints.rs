//! `pedantic-lints TOOLCHAIN...`: keeps the per-lint `forbid` list of the
//! workspace manifest equal to clippy's pedantic group, and rejects sources
//! that allow the pedantic lints the list cannot forbid.

use crate::repo::{Failure, root};
use regex::Regex;
use std::collections::BTreeSet;
use std::process::Command;

#[cfg(test)]
mod tests;

/// Pedantic lints that stay out of the forbid list, each with its reason.
pub(crate) const EXEMPT: [(&str, &str); 1] = [(
    "used_underscore_binding",
    "thiserror's derive allows it in its own expansion",
)];

fn exempt(lint: &str) -> bool {
    EXEMPT.iter().any(|(name, _)| *name == lint)
}

fn normalize(name: &str) -> String {
    let name = name.trim();
    name.strip_prefix("clippy::")
        .unwrap_or(name)
        .replace('-', "_")
}

/// One toolchain's clippy: its pedantic members and every lint it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Clippy {
    pub(crate) name: String,
    pub(crate) pedantic: BTreeSet<String>,
    pub(crate) known: BTreeSet<String>,
}

/// Reads `clippy-driver -W help`.
pub(crate) fn parse_lint_help(name: &str, text: &str) -> Result<Clippy, String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let group = lines
        .iter()
        .find_map(|line| line.strip_prefix("clippy::pedantic "))
        .ok_or("clippy lint help lists no pedantic group")?;
    let pedantic = group
        .split(',')
        .map(normalize)
        .filter(|lint| !lint.is_empty())
        .collect();
    let level =
        Regex::new(r"^clippy::[a-z0-9-]+\s+(allow|warn|deny|forbid)\s").expect("valid pattern");
    let known = lines
        .iter()
        .filter(|line| level.is_match(line))
        .filter_map(|line| line.split_whitespace().next())
        .map(normalize)
        .collect();
    Ok(Clippy {
        name: name.into(),
        pedantic,
        known,
    })
}

/// Lints the manifest forbids by name in `[workspace.lints.clippy]`.
pub(crate) fn forbidden_lints(manifest: &str) -> Result<BTreeSet<String>, String> {
    let start = manifest
        .find("[workspace.lints.clippy]")
        .ok_or("the manifest has no [workspace.lints.clippy] table")?;
    let entry = Regex::new(r#"^([a-z0-9_]+)\s*=\s*"forbid"\s*$"#).expect("valid pattern");
    Ok(manifest[start..]
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .filter_map(|line| entry.captures(line.trim()).map(|lint| lint[1].to_owned()))
        .collect())
}

/// Every inconsistency between the forbid list and the toolchains' clippy.
pub(crate) fn list_problems(forbidden: &BTreeSet<String>, toolchains: &[Clippy]) -> Vec<String> {
    let mut problems = Vec::new();
    for clippy in toolchains {
        for lint in forbidden {
            if !clippy.known.contains(lint) {
                problems.push(format!(
                    "{lint} is forbidden but unknown to clippy {}",
                    clippy.name
                ));
            }
        }
        for lint in &clippy.pedantic {
            if forbidden.contains(lint) || exempt(lint) {
                continue;
            }
            // A lint another toolchain does not know cannot be listed; that
            // toolchain already fails a local allow of it as an unknown lint.
            if toolchains.iter().all(|other| other.known.contains(lint)) {
                problems.push(format!(
                    "pedantic {lint} of clippy {} is neither forbidden nor exempt",
                    clippy.name
                ));
            }
        }
    }
    for lint in forbidden {
        if !toolchains
            .iter()
            .any(|clippy| clippy.pedantic.contains(lint))
        {
            problems.push(format!("{lint} is forbidden but pedantic in no toolchain"));
        }
    }
    for (lint, _) in EXEMPT {
        if forbidden.contains(lint) {
            problems.push(format!("{lint} is exempt and must not be forbidden"));
        }
    }
    problems
}

/// Allow and expect attributes naming the pedantic group or an exempt lint.
pub(crate) fn suppressions(path: &str, text: &str) -> Vec<String> {
    // Arguments may hold quoted reasons with parentheses or escaped quotes.
    let attribute = Regex::new(r#"\b(?:allow|expect)\s*\(((?:[^()"]|"(?:[^"\\]|\\.)*")*)\)"#)
        .expect("valid pattern");
    let quoted = Regex::new(r#""(?:[^"\\]|\\.)*""#).expect("valid pattern");
    let mut found = Vec::new();
    for capture in attribute.captures_iter(text) {
        // A reason's own text is not a lint name, however it is worded.
        let arguments = quoted.replace_all(&capture[1], "\"\"");
        let named = arguments.split(',').any(|item| {
            // Whitespace between path tokens is insignificant: `clippy :: pedantic`
            // is the same lint path.
            let lint: String = item.split_whitespace().collect();
            lint.starts_with("clippy::") && {
                let lint = normalize(&lint);
                lint == "pedantic" || exempt(&lint)
            }
        });
        if named {
            let whole = capture.get(0).expect("the whole match");
            let line = text[..whole.start()].matches('\n').count() + 1;
            found.push(format!("{path}:{line}: {}", whole.as_str()));
        }
    }
    found
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let names: Vec<String> = args.collect();
    if names.is_empty() {
        return Err("usage: xml-sec-tools pedantic-lints TOOLCHAIN...".into());
    }
    let mut toolchains = Vec::new();
    for name in &names {
        let help = Command::new("rustup")
            .args(["run", name, "clippy-driver", "-W", "help"])
            .output()
            .map_err(|error| format!("clippy {name} lint help failed: {error}"))?;
        if !help.status.success() {
            return Err(format!(
                "clippy {name} lint help failed: {}",
                String::from_utf8_lossy(&help.stderr)
            )
            .into());
        }
        toolchains.push(parse_lint_help(
            name,
            &String::from_utf8_lossy(&help.stdout),
        )?);
    }
    let root = root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("read Cargo.toml: {error}"))?;
    let mut problems = list_problems(&forbidden_lints(&manifest)?, &toolchains);
    let files = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(&root)
        .output()
        .map_err(|error| format!("listing sources failed: {error}"))?;
    if !files.status.success() {
        return Err(format!(
            "listing sources failed: {}",
            String::from_utf8_lossy(&files.stderr)
        )
        .into());
    }
    for path in String::from_utf8_lossy(&files.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
    {
        let text = std::fs::read_to_string(root.join(path))
            .map_err(|error| format!("read {path}: {error}"))?;
        problems.extend(
            suppressions(path, &text)
                .into_iter()
                .map(|found| format!("suppressed: {found}")),
        );
    }
    if !problems.is_empty() {
        return Err(problems.join("\n").into());
    }
    println!("Pedantic lint list matches clippy {}", names.join(", "));
    Ok(())
}
