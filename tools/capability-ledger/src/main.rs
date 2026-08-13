use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXPECTED_VERSION: &str = "1.3.13";
const EXPECTED_COMMIT: &str = "5fdd47dc35753438bdc38b6e96c1a3805c67a483";

#[derive(Debug, Deserialize)]
struct RulesFile {
    schema_version: u32,
    evidence: BTreeMap<String, Evidence>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Evidence {
    test: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct Rule {
    id: String,
    kinds: Vec<String>,
    #[serde(default)]
    name_regex: Option<String>,
    #[serde(default)]
    source_regex: Option<String>,
    outcome: Outcome,
    rationale: String,
    evidence: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    Exact,
    SourceCompatible,
    BehaviorCompatible,
    CompatibilityProfileOnly,
    ProviderLimited,
    IntentionallyUnsupported,
    BinaryAbiIncompatible,
    Planned,
}

#[derive(Debug, Serialize)]
struct Ledger {
    schema_version: u32,
    upstream: Upstream,
    generated_by: String,
    evidence: BTreeMap<String, Evidence>,
    items: Vec<LedgerItem>,
}

#[derive(Debug, Serialize)]
struct Upstream {
    project: String,
    version: String,
    commit: String,
    repository: String,
}

#[derive(Debug, Clone)]
struct SurfaceItem {
    kind: String,
    name: String,
    source: String,
    line: usize,
    detail: String,
}

#[derive(Debug, Serialize)]
struct LedgerItem {
    id: String,
    kind: String,
    name: String,
    source: String,
    line: usize,
    detail: String,
    outcome: Outcome,
    rationale: String,
    evidence: String,
    classification_rule: String,
}

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if command != "generate" && command != "check" {
        return Err(usage());
    }
    let donor = PathBuf::from(args.next().ok_or_else(usage)?);
    let rules_path = PathBuf::from(args.next().ok_or_else(usage)?);
    let output = PathBuf::from(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
        return Err(usage());
    }

    verify_donor(&donor)?;
    let rules: RulesFile = serde_json::from_slice(
        &fs::read(&rules_path)
            .map_err(|error| format!("read {}: {error}", rules_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", rules_path.display()))?;
    if rules.schema_version != 1 {
        return Err(format!("unsupported rules schema {}", rules.schema_version));
    }

    let surface = extract_surface(&donor)?;
    let ledger = classify(surface, rules)?;
    let mut bytes = serde_json::to_vec_pretty(&ledger).map_err(|error| error.to_string())?;
    bytes.push(b'\n');

    if command == "check" {
        let existing = fs::read(&output)
            .map_err(|error| format!("read generated ledger {}: {error}", output.display()))?;
        if existing != bytes {
            return Err(format!(
                "{} is stale; regenerate it with the capability-ledger tool",
                output.display()
            ));
        }
    } else {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        fs::write(&output, bytes)
            .map_err(|error| format!("write {}: {error}", output.display()))?;
    }
    Ok(())
}

fn usage() -> String {
    "usage: xml-sec-capability-ledger <generate|check> <donor> <rules.json> <ledger.json>".into()
}

fn verify_donor(donor: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .args([
            "-C",
            donor.to_str().ok_or("donor path is not UTF-8")?,
            "rev-parse",
            "HEAD",
        ])
        .output()
        .map_err(|error| format!("run git for donor identity: {error}"))?;
    if !output.status.success() {
        return Err("donor is not a readable Git checkout".into());
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| "git donor identity is not UTF-8")?
        .trim()
        .to_owned();
    if commit != EXPECTED_COMMIT {
        return Err(format!(
            "libxmlsec donor revision mismatch: expected {EXPECTED_COMMIT}, got {commit}"
        ));
    }
    let configure = fs::read_to_string(donor.join("configure.ac"))
        .map_err(|error| format!("read donor configure.ac: {error}"))?;
    if !configure.contains(&format!("AC_INIT([xmlsec1],[{EXPECTED_VERSION}]")) {
        return Err(format!("donor does not declare xmlsec1 {EXPECTED_VERSION}"));
    }
    Ok(())
}

fn extract_surface(donor: &Path) -> Result<Vec<SurfaceItem>, String> {
    let headers = installed_headers(donor)?;
    let mut items = Vec::new();
    for header in &headers {
        items.push(item("header", header, header, 1, "installed public header"));
        extract_header(donor, header, &mut items)?;
    }
    extract_build_defines(donor, &mut items)?;
    extract_algorithm_uris(donor, &mut items)?;
    extract_cli(donor, &mut items)?;
    extract_test_families(donor, &mut items)?;

    let mut seen = BTreeSet::new();
    items.retain(|entry| {
        seen.insert((entry.kind.clone(), entry.name.clone(), entry.source.clone()))
    });
    items.sort_by(|left, right| {
        (&left.kind, &left.name, &left.source, left.line).cmp(&(
            &right.kind,
            &right.name,
            &right.source,
            right.line,
        ))
    });
    Ok(items)
}

fn installed_headers(donor: &Path) -> Result<Vec<String>, String> {
    let root = donor.join("include/xmlsec");
    let mut makefiles = vec![root.join("Makefile.am")];
    for entry in fs::read_dir(&root).map_err(|error| format!("read {}: {error}", root.display()))? {
        let path = entry
            .map_err(|error| error.to_string())?
            .path()
            .join("Makefile.am");
        if path.is_file() {
            makefiles.push(path);
        }
    }
    makefiles.sort();

    let header = Regex::new(r"([A-Za-z0-9_./-]+\.h)\s*\\?").expect("valid header regex");
    let mut result = BTreeSet::new();
    for makefile in makefiles {
        let content = fs::read_to_string(&makefile)
            .map_err(|error| format!("read {}: {error}", makefile.display()))?;
        let relative_dir = makefile
            .parent()
            .and_then(|path| path.strip_prefix(&root).ok())
            .unwrap_or(Path::new(""));
        let mut in_headers = false;
        for line in content.lines() {
            if line.contains("inc_HEADERS") && line.contains('=') {
                in_headers = true;
            }
            if in_headers {
                for capture in header.captures_iter(line) {
                    result.insert(
                        Path::new("include/xmlsec")
                            .join(relative_dir)
                            .join(&capture[1])
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
                if line.contains("$(NULL)") {
                    in_headers = false;
                }
            }
        }
    }
    if result.len() < 50 {
        return Err(format!(
            "only {} installed headers discovered",
            result.len()
        ));
    }
    Ok(result.into_iter().collect())
}

fn extract_header(donor: &Path, source: &str, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source_path = donor.join(source);
    let template_path = donor.join(format!("{source}.in"));
    let extraction_source = if source_path.is_file() {
        source.to_owned()
    } else if template_path.is_file() {
        format!("{source}.in")
    } else {
        return Err(format!(
            "installed header {source} has no source or configure template"
        ));
    };
    let content = fs::read_to_string(donor.join(&extraction_source))
        .map_err(|error| format!("read {extraction_source}: {error}"))?;
    let lines: Vec<_> = content.lines().collect();
    let macro_re =
        Regex::new(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)").expect("valid macro regex");
    let class_re = Regex::new(r"^\s*#\s*define\s+(xmlSec[A-Za-z0-9_]*Id)\s+.*GetKlass")
        .expect("valid class regex");
    let callback_re =
        Regex::new(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)").expect("valid callback regex");
    let enum_name = Regex::new(r"}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;").expect("valid enum regex");
    let struct_name =
        Regex::new(r"^\s*struct\s+(_xmlSec[A-Za-z0-9_]*)").expect("valid struct regex");

    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let line_number = index + 1;
        if let Some(capture) = class_re.captures(line) {
            items.push(item(
                "class-id",
                &capture[1],
                &extraction_source,
                line_number,
                line.trim(),
            ));
        }
        if let Some(capture) = macro_re.captures(line) {
            let name = &capture[1];
            if name.starts_with("XMLSEC") || name.starts_with("xmlSec") {
                items.push(item(
                    "macro",
                    name,
                    &extraction_source,
                    line_number,
                    line.trim(),
                ));
            }
        }
        if line.trim_start().starts_with("typedef enum") {
            let (block, end) = collect_until(&lines, index, ";");
            let name = enum_name
                .captures(&block)
                .map(|capture| capture[1].to_owned())
                .unwrap_or_else(|| format!("anonymous-enum-{line_number}"));
            items.push(item(
                "enum",
                &name,
                &extraction_source,
                line_number,
                &normalize(&block),
            ));
            if name == "xmlSecKeyDataFormat" {
                for value in extract_identifiers(&block, "xmlSecKeyDataFormat") {
                    items.push(item(
                        "key-format",
                        &value,
                        &extraction_source,
                        line_number,
                        &name,
                    ));
                }
            }
            index = end;
        } else if let Some(capture) = struct_name.captures(line) {
            let (block, end) = collect_until(&lines, index, "};");
            items.push(item(
                "struct-layout",
                capture.get(1).expect("struct capture").as_str(),
                &extraction_source,
                line_number,
                &normalize(&block),
            ));
            index = end;
        } else if line.contains("typedef") && line.contains("(*") {
            let (block, end) = collect_until(&lines, index, ";");
            if let Some(capture) = callback_re.captures(&block) {
                items.push(item(
                    "callback",
                    &capture[1],
                    &extraction_source,
                    line_number,
                    &normalize(&block),
                ));
            }
            index = end;
        } else if line.contains("_EXPORT") && !line.trim_start().starts_with('#') {
            let (block, end) = collect_until(&lines, index, ";");
            if let Some(name) = exported_name(&block) {
                let backend = source.split('/').count() > 3;
                let kind = if backend {
                    "backend-api"
                } else if block.contains("_EXPORT_VAR") {
                    "export-variable"
                } else {
                    "export-function"
                };
                items.push(item(
                    kind,
                    &name,
                    &extraction_source,
                    line_number,
                    &normalize(&block),
                ));
                if name.contains("Register") || name.contains("GetKlass") && name.contains("Ids") {
                    items.push(item(
                        "registry",
                        &name,
                        &extraction_source,
                        line_number,
                        &normalize(&block),
                    ));
                }
                if block.contains("XMLSEC_DEPRECATED") {
                    items.push(item(
                        "deprecated-api",
                        &name,
                        &extraction_source,
                        line_number,
                        &normalize(&block),
                    ));
                }
            }
            index = end;
        }
        index += 1;
    }
    Ok(())
}

fn extract_build_defines(donor: &Path, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source = "configure.ac";
    let content = fs::read_to_string(donor.join(source))
        .map_err(|error| format!("read donor {source}: {error}"))?;
    let regex =
        Regex::new(r"\b(XMLSEC_(?:NO|CRYPTO)_[A-Z0-9_]+)\b").expect("valid configure define regex");
    for (index, line) in content.lines().enumerate() {
        for capture in regex.captures_iter(line) {
            items.push(item(
                "build-define",
                &capture[1],
                source,
                index + 1,
                line.trim(),
            ));
        }
    }
    Ok(())
}

fn extract_algorithm_uris(donor: &Path, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source = "src/strings.c";
    let content = fs::read_to_string(donor.join(source))
        .map_err(|error| format!("read donor {source}: {error}"))?;
    let macro_regex = Regex::new(r#"(?m)^#define\s+([A-Z][A-Z0-9_]+)\s+\"([^\"]*)\""#)
        .expect("valid string macro regex");
    let macros: BTreeMap<_, _> = macro_regex
        .captures_iter(&content)
        .map(|capture| (capture[1].to_owned(), capture[2].to_owned()))
        .collect();
    let regex = Regex::new(
        r#"(?m)^const xmlChar (xmlSec(?:Href[A-Za-z0-9_]+|XPath2?Ns))\[\]\s*=\s*([^;]+);"#,
    )
    .expect("valid URI declaration regex");
    for capture in regex.captures_iter(&content) {
        let line = content[..capture.get(0).expect("whole URI capture").start()]
            .lines()
            .count()
            + 1;
        let value = resolve_c_string_expression(&capture[2], &macros)?;
        items.push(item("algorithm-uri", &capture[1], source, line, &value));
    }
    Ok(())
}

fn resolve_c_string_expression(
    expression: &str,
    macros: &BTreeMap<String, String>,
) -> Result<String, String> {
    let token =
        Regex::new(r#"([A-Z][A-Z0-9_]+)|\"([^\"]*)\""#).expect("valid C string token regex");
    let mut value = String::new();
    for capture in token.captures_iter(expression) {
        if let Some(literal) = capture.get(2) {
            value.push_str(literal.as_str());
        } else {
            let name = capture.get(1).expect("macro token").as_str();
            value.push_str(
                macros
                    .get(name)
                    .ok_or_else(|| format!("unresolved string macro {name} in {expression}"))?,
            );
        }
    }
    if value.is_empty() {
        return Err(format!("empty C string expression: {expression}"));
    }
    Ok(value)
}

fn extract_cli(donor: &Path, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source = "apps/xmlsec.c";
    let content = fs::read_to_string(donor.join(source))
        .map_err(|error| format!("read donor {source}: {error}"))?;
    let command = Regex::new(r#"strcmp\(cmd, \"([^\"]+)\"\)"#).expect("valid command regex");
    for (index, line) in content.lines().enumerate() {
        for capture in command.captures_iter(line) {
            items.push(item(
                "cli-command",
                &capture[1],
                source,
                index + 1,
                line.trim(),
            ));
        }
    }
    items.push(item("cli-exit-status", "success", source, 1430, "0"));
    items.push(item(
        "cli-exit-status",
        "unknown-command",
        source,
        1378,
        "0 after printing usage",
    ));
    items.push(item(
        "cli-exit-status",
        "failure",
        source,
        1338,
        "1 for invalid parameters, missing input, initialization, or processing failure",
    ));
    Ok(())
}

fn extract_test_families(donor: &Path, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let tests = donor.join("tests");
    for entry in fs::read_dir(&tests).map_err(|error| format!("read donor tests: {error}"))? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            items.push(item(
                "test-family",
                &name,
                &format!("tests/{name}/"),
                1,
                "upstream test directory",
            ));
        }
    }
    for script in ["testDSig.sh", "testEnc.sh", "testKeys.sh", "testRes.sh"] {
        items.push(item(
            "test-family",
            script,
            &format!("tests/{script}"),
            1,
            "upstream runner family",
        ));
    }
    Ok(())
}

fn classify(surface: Vec<SurfaceItem>, rules: RulesFile) -> Result<Ledger, String> {
    let compiled: Vec<_> = rules
        .rules
        .iter()
        .map(|rule| {
            Ok((
                rule,
                rule.name_regex
                    .as_ref()
                    .map(|value| {
                        Regex::new(value)
                            .map_err(|error| format!("rule {} name regex: {error}", rule.id))
                    })
                    .transpose()?,
                rule.source_regex
                    .as_ref()
                    .map(|value| {
                        Regex::new(value)
                            .map_err(|error| format!("rule {} source regex: {error}", rule.id))
                    })
                    .transpose()?,
            ))
        })
        .collect::<Result<_, String>>()?;

    let mut items = Vec::with_capacity(surface.len());
    let mut rule_matches = vec![0_usize; compiled.len()];
    for entry in surface {
        let matching = compiled
            .iter()
            .enumerate()
            .find(|(_, (rule, name, source))| {
                rule.kinds.iter().any(|kind| kind == &entry.kind)
                    && name.as_ref().is_none_or(|regex| {
                        regex.is_match(&entry.name) || regex.is_match(&entry.detail)
                    })
                    && source
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&entry.source))
            })
            .ok_or_else(|| {
                format!(
                    "{} {} at {}:{} matched no classification rule",
                    entry.kind, entry.name, entry.source, entry.line
                )
            })?;
        let rule_index = matching.0;
        let rule = matching.1.0;
        rule_matches[rule_index] += 1;
        if !rules.evidence.contains_key(&rule.evidence) {
            return Err(format!(
                "rule {} references missing evidence {}",
                rule.id, rule.evidence
            ));
        }
        let id = format!(
            "{}:{}:{}:{}",
            entry.kind, entry.source, entry.line, entry.name
        );
        items.push(LedgerItem {
            id,
            kind: entry.kind,
            name: entry.name,
            source: entry.source,
            line: entry.line,
            detail: entry.detail,
            outcome: rule.outcome,
            rationale: rule.rationale.clone(),
            evidence: rule.evidence.clone(),
            classification_rule: rule.id.clone(),
        });
    }
    for (index, count) in rule_matches.into_iter().enumerate() {
        if count == 0 {
            return Err(format!(
                "classification rule {} matched no surface item",
                compiled[index].0.id
            ));
        }
    }
    Ok(Ledger {
        schema_version: 1,
        upstream: Upstream {
            project: "libxmlsec1".into(),
            version: EXPECTED_VERSION.into(),
            commit: EXPECTED_COMMIT.into(),
            repository: "https://github.com/lsh123/xmlsec".into(),
        },
        generated_by: "xml-sec-capability-ledger/1".into(),
        evidence: rules.evidence,
        items,
    })
}

fn collect_until(lines: &[&str], start: usize, terminator: &str) -> (String, usize) {
    let mut end = start;
    let mut block = String::new();
    while end < lines.len() {
        block.push_str(lines[end]);
        block.push('\n');
        if lines[end].contains(terminator) {
            break;
        }
        end += 1;
    }
    (block, end)
}

fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn exported_name(declaration: &str) -> Option<String> {
    let function = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("valid function regex");
    if let Some(capture) = function.captures_iter(declaration).last() {
        return Some(capture[1].to_owned());
    }
    let variable =
        Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\])?\s*;").expect("valid variable regex");
    variable
        .captures(declaration)
        .map(|capture| capture[1].to_owned())
}

fn extract_identifiers(block: &str, prefix: &str) -> Vec<String> {
    let regex =
        Regex::new(&format!(r"\b({prefix}[A-Za-z0-9_]+)\b")).expect("valid identifier regex");
    regex
        .captures_iter(block)
        .map(|capture| capture[1].to_owned())
        .filter(|identifier| identifier != prefix)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn item(kind: &str, name: &str, source: &str, line: usize, detail: &str) -> SurfaceItem {
    SurfaceItem {
        kind: kind.into(),
        name: name.into(),
        source: source.into(),
        line,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> BTreeMap<String, Evidence> {
        BTreeMap::from([(
            "test".into(),
            Evidence {
                test: "capability_ledger::test".into(),
                description: "classification evidence".into(),
            },
        )])
    }

    fn rule(id: &str, kinds: &[&str], name_regex: Option<&str>) -> Rule {
        Rule {
            id: id.into(),
            kinds: kinds.iter().map(|kind| (*kind).into()).collect(),
            name_regex: name_regex.map(str::to_owned),
            source_regex: None,
            outcome: Outcome::Planned,
            rationale: "not implemented".into(),
            evidence: "test".into(),
        }
    }

    #[test]
    fn resolves_adjacent_literals_and_upstream_prefix_macros() {
        // Experimental 1.3.13 URIs concatenate a private namespace macro and suffix.
        let macros = BTreeMap::from([(
            "XMLSEC_EXPERIMENTAL".into(),
            "https://example.test/algorithms#".into(),
        )]);
        assert_eq!(
            resolve_c_string_expression(r#"XMLSEC_EXPERIMENTAL "ml-dsa" "-44""#, &macros)
                .expect("expression must resolve"),
            "https://example.test/algorithms#ml-dsa-44"
        );
    }

    #[test]
    fn rejects_unresolved_uri_macros() {
        // Silent macro loss would omit the newest upstream algorithm families.
        let error = resolve_c_string_expression("XMLSEC_UNKNOWN \"suffix\"", &BTreeMap::new())
            .expect_err("unknown macro must fail");
        assert!(error.contains("XMLSEC_UNKNOWN"));
    }

    #[test]
    fn first_matching_rule_wins() {
        // Ordered rules allow a precise supported subset before a planned fallback.
        let ledger = classify(
            vec![
                item(
                    "algorithm-uri",
                    "supported",
                    "strings.c",
                    1,
                    "urn:supported",
                ),
                item("algorithm-uri", "future", "strings.c", 2, "urn:future"),
            ],
            RulesFile {
                schema_version: 1,
                evidence: evidence(),
                rules: vec![
                    rule("supported", &["algorithm-uri"], Some("^supported$")),
                    rule("fallback", &["algorithm-uri"], None),
                ],
            },
        )
        .expect("both ordered rules must classify at least one item");
        assert_eq!(ledger.items[0].classification_rule, "supported");
        assert_eq!(ledger.items[1].classification_rule, "fallback");
    }

    #[test]
    fn rejects_items_without_a_classification() {
        // New upstream categories cannot disappear from the generated baseline.
        let error = classify(
            vec![item("new-kind", "new-item", "new.h", 1, "new")],
            RulesFile {
                schema_version: 1,
                evidence: evidence(),
                rules: vec![rule("headers", &["header"], None)],
            },
        )
        .expect_err("unclassified item must fail");
        assert!(error.contains("matched no classification rule"));
    }

    #[test]
    fn rejects_rules_that_no_longer_match_upstream() {
        // Stale allowlist entries must be reviewed instead of silently surviving upgrades.
        let error = classify(
            vec![item("header", "current.h", "current.h", 1, "header")],
            RulesFile {
                schema_version: 1,
                evidence: evidence(),
                rules: vec![
                    rule("current", &["header"], None),
                    rule("removed", &["algorithm-uri"], None),
                ],
            },
        )
        .expect_err("unused rule must fail");
        assert!(error.contains("removed"));
    }

    #[test]
    fn export_parser_ignores_return_type_and_calling_convention() {
        // Exported symbol identity comes from the declarator, not macro-like prefixes.
        assert_eq!(
            exported_name("XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void);").as_deref(),
            Some("xmlSecInit")
        );
        assert_eq!(
            exported_name("XMLSEC_EXPORT_VAR const xmlChar xmlSecNameId[];").as_deref(),
            Some("xmlSecNameId")
        );
    }

    #[test]
    fn rejects_a_different_donor_commit() {
        // A version-shaped checkout at another Git object must not regenerate the baseline.
        let directory =
            env::temp_dir().join(format!("xml-sec-ledger-donor-drift-{}", std::process::id()));
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("stale donor test directory must be removable");
        }
        fs::create_dir_all(&directory).expect("donor test directory must be creatable");
        fs::write(
            directory.join("configure.ac"),
            "AC_INIT([xmlsec1],[1.3.13])\n",
        )
        .expect("donor version fixture must be writable");
        assert!(
            Command::new("git")
                .arg("init")
                .arg(&directory)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args(["-C", directory.to_str().unwrap(), "add", "configure.ac"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.name=Capability Ledger Test",
                    "-c",
                    "user.email=ledger@example.invalid",
                    "-C",
                    directory.to_str().unwrap(),
                    "commit",
                    "-m",
                    "test fixture",
                ])
                .status()
                .unwrap()
                .success()
        );

        let error = verify_donor(&directory).expect_err("different donor commit must fail");
        assert!(error.contains("revision mismatch"));
        fs::remove_dir_all(directory).expect("donor test directory must be removable");
    }
}
