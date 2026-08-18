use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXPECTED_VERSION: &str = "1.3.13";
const EXPECTED_COMMIT: &str =
    include_str!("../../../compatibility/libxmlsec1-1.3.13-donor-commit.txt");

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
    classifications: BTreeMap<String, Classification>,
    availability: Vec<AvailabilitySpan>,
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
    exit_code: Option<i32>,
    conditions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LedgerItem {
    kind: String,
    name: String,
    source: String,
    line: usize,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    classification: String,
}

#[derive(Debug, Clone, Serialize)]
struct Classification {
    outcome: Outcome,
    rationale: String,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct AvailabilitySpan {
    source: String,
    start_line: usize,
    end_line: usize,
    conditions: Vec<String>,
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
    let donor_snapshot = snapshot_donor(&donor, EXPECTED_COMMIT.trim())?;
    verify_donor_version(donor_snapshot.path())?;
    let rules: RulesFile = serde_json::from_slice(
        &fs::read(&rules_path)
            .map_err(|error| format!("read {}: {error}", rules_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", rules_path.display()))?;
    if rules.schema_version != 1 {
        return Err(format!("unsupported rules schema {}", rules.schema_version));
    }

    let surface = extract_surface(donor_snapshot.path())?;
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
    let expected_commit = EXPECTED_COMMIT.trim();
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
    if commit != expected_commit {
        return Err(format!(
            "libxmlsec donor revision mismatch: expected {expected_commit}, got {commit}"
        ));
    }
    Ok(())
}

fn verify_donor_version(donor: &Path) -> Result<(), String> {
    let configure = fs::read_to_string(donor.join("configure.ac"))
        .map_err(|error| format!("read donor configure.ac: {error}"))?;
    if !configure.contains(&format!("AC_INIT([xmlsec1],[{EXPECTED_VERSION}]")) {
        return Err(format!("donor does not declare xmlsec1 {EXPECTED_VERSION}"));
    }
    Ok(())
}

fn snapshot_donor(donor: &Path, commit: &str) -> Result<tempfile::TempDir, String> {
    let snapshot =
        tempfile::tempdir().map_err(|error| format!("create donor snapshot: {error}"))?;
    let output = Command::new("git")
        .args(["clone", "--quiet", "--no-checkout"])
        .arg(donor)
        .arg(snapshot.path())
        .output()
        .map_err(|error| format!("clone donor snapshot: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "clone donor snapshot: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = Command::new("git")
        .args(["-C"])
        .arg(snapshot.path())
        .args(["checkout", "--quiet", "--detach", commit])
        .output()
        .map_err(|error| format!("checkout donor snapshot: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "checkout donor snapshot: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(snapshot)
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

    items = deduplicate_surface(items);
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

fn deduplicate_surface(mut items: Vec<SurfaceItem>) -> Vec<SurfaceItem> {
    let mut seen = BTreeSet::new();
    items.retain(|entry| {
        seen.insert((
            entry.kind.clone(),
            entry.name.clone(),
            entry.source.clone(),
            entry.line,
        ))
    });
    items
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

    let mut result = BTreeSet::new();
    for makefile in makefiles {
        let content = fs::read_to_string(&makefile)
            .map_err(|error| format!("read {}: {error}", makefile.display()))?;
        let relative_dir = makefile
            .parent()
            .and_then(|path| path.strip_prefix(&root).ok())
            .unwrap_or(Path::new(""));
        collect_installed_headers(&content, relative_dir, &mut result);
    }
    if result.len() < 50 {
        return Err(format!(
            "only {} installed headers discovered",
            result.len()
        ));
    }
    Ok(result.into_iter().collect())
}

fn collect_installed_headers(content: &str, relative_dir: &Path, result: &mut BTreeSet<String>) {
    let assignment = Regex::new(r"^[A-Za-z0-9_]*inc_HEADERS\s*=")
        .expect("valid installed header assignment regex");
    let header = Regex::new(r"([A-Za-z0-9_./-]+\.h)\s*\\?").expect("valid header regex");
    let mut in_headers = false;
    for line in content.lines() {
        if assignment.is_match(line) {
            in_headers = true;
        }
        if !in_headers {
            continue;
        }
        for capture in header.captures_iter(line) {
            result.insert(
                Path::new("include/xmlsec")
                    .join(relative_dir)
                    .join(&capture[1])
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
        if line.contains("$(NULL)") || !line.trim_end().ends_with('\\') {
            in_headers = false;
        }
    }
}

fn extract_header(donor: &Path, source: &str, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source_path = donor.join(source);
    let template_path = donor.join(format!("{source}.in"));
    let (extraction_source, content) = if template_path.is_file() {
        let extraction_source = format!("{source}.in");
        let template = fs::read_to_string(&template_path)
            .map_err(|error| format!("read {extraction_source}: {error}"))?;
        let configure = fs::read_to_string(donor.join("configure.ac"))
            .map_err(|error| format!("read donor configure.ac: {error}"))?;
        let content = render_configured_header(&template, &configure)
            .map_err(|error| format!("configure {extraction_source}: {error}"))?;
        (extraction_source, content)
    } else if source_path.is_file() {
        let content =
            fs::read_to_string(&source_path).map_err(|error| format!("read {source}: {error}"))?;
        (source.to_owned(), content)
    } else {
        return Err(format!(
            "installed header {source} has no source or configure template"
        ));
    };
    let lines: Vec<_> = content.lines().collect();
    let conditions = preprocessor_conditions(&content)
        .map_err(|error| format!("parse conditions in {extraction_source}: {error}"))?;
    let macro_re =
        Regex::new(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)").expect("valid macro regex");
    let callback_re =
        Regex::new(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)").expect("valid callback regex");
    let enum_name = Regex::new(r"}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;").expect("valid enum regex");
    let struct_name =
        Regex::new(r"^\s*struct\s+(_xmlSec[A-Za-z0-9_]*)").expect("valid struct regex");

    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let line_number = index + 1;
        let item_start = items.len();
        if let Some(capture) = macro_re.captures(line) {
            let name = &capture[1];
            if name.starts_with("XMLSEC") || name.starts_with("xmlSec") {
                let (definition, end) = collect_macro_definition(&lines, index);
                let detail = normalize_c(&definition).map_err(|error| {
                    format!("normalize macro at {extraction_source}:{line_number}: {error}")
                })?;
                items.push(item(
                    "macro",
                    name,
                    &extraction_source,
                    line_number,
                    &detail,
                ));
                if is_class_id_macro(name, &definition) {
                    items.push(item(
                        "class-id",
                        name,
                        &extraction_source,
                        line_number,
                        &detail,
                    ));
                }
                index = end;
            }
        }
        if line.trim_start().starts_with("typedef enum") {
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse enum at {extraction_source}:{line_number}: {error}")
            })?;
            let name = enum_name
                .captures(&block)
                .map(|capture| capture[1].to_owned())
                .unwrap_or_else(|| format!("anonymous-enum-{line_number}"));
            let detail = normalize_c(&block).map_err(|error| {
                format!("normalize enum at {extraction_source}:{line_number}: {error}")
            })?;
            items.push(item(
                "enum",
                &name,
                &extraction_source,
                line_number,
                &detail,
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
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse struct at {extraction_source}:{line_number}: {error}")
            })?;
            let detail = normalize_c(&block).map_err(|error| {
                format!("normalize struct at {extraction_source}:{line_number}: {error}")
            })?;
            items.push(item(
                "struct-layout",
                capture.get(1).expect("struct capture").as_str(),
                &extraction_source,
                line_number,
                &detail,
            ));
            index = end;
        } else if line.contains("typedef") && line.contains("(*") {
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse callback at {extraction_source}:{line_number}: {error}")
            })?;
            let detail = normalize_c(&block).map_err(|error| {
                format!("normalize callback at {extraction_source}:{line_number}: {error}")
            })?;
            if let Some(capture) = callback_re.captures(&block) {
                items.push(item(
                    "callback",
                    &capture[1],
                    &extraction_source,
                    line_number,
                    &detail,
                ));
            }
            index = end;
        } else if line.trim_start().starts_with("typedef") {
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse typedef at {extraction_source}:{line_number}: {error}")
            })?;
            let detail = normalize_c(&block).map_err(|error| {
                format!("normalize typedef at {extraction_source}:{line_number}: {error}")
            })?;
            let aliases = typedef_aliases(&block);
            if aliases.is_empty() {
                return Err(format!(
                    "cannot extract typedef alias at {extraction_source}:{line_number}: {}",
                    detail
                ));
            }
            for alias in aliases {
                items.push(item(
                    "typedef",
                    &alias,
                    &extraction_source,
                    line_number,
                    &detail,
                ));
            }
            index = end;
        } else if line.contains("_EXPORT") && !line.trim_start().starts_with('#') {
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse export at {extraction_source}:{line_number}: {error}")
            })?;
            let detail = normalize_c(&block).map_err(|error| {
                format!("normalize export at {extraction_source}:{line_number}: {error}")
            })?;
            let name = exported_name(&block).ok_or_else(|| {
                format!(
                    "cannot extract exported symbol at {extraction_source}:{line_number}: {}",
                    detail
                )
            })?;
            let backend = source.split('/').count() > 3;
            let kind = if backend {
                "backend-api"
            } else if block.contains("_EXPORT_VAR") {
                "export-variable"
            } else {
                "export-function"
            };
            items.push(item(kind, &name, &extraction_source, line_number, &detail));
            if is_registry_api(&name) {
                items.push(item(
                    "registry",
                    &name,
                    &extraction_source,
                    line_number,
                    &detail,
                ));
            }
            if block.contains("XMLSEC_DEPRECATED") {
                items.push(item(
                    "deprecated-api",
                    &name,
                    &extraction_source,
                    line_number,
                    &detail,
                ));
            }
            index = end;
        }
        for entry in &mut items[item_start..] {
            entry.conditions.clone_from(&conditions[line_number - 1]);
        }
        index += 1;
    }
    Ok(())
}

#[derive(Debug)]
struct PreprocessorFrame {
    branches: Vec<String>,
    saw_else: bool,
}

fn preprocessor_conditions(content: &str) -> Result<Vec<Vec<String>>, String> {
    let lines: Vec<_> = content.lines().collect();
    let directive = Regex::new(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
        .expect("valid preprocessor condition regex");
    let mut contexts = vec![Vec::new(); lines.len()];
    let mut stack: Vec<PreprocessorFrame> = Vec::new();
    let mut index = 0_usize;
    while index < lines.len() {
        let start = index;
        let mut logical = String::new();
        loop {
            let physical = lines[index].trim_end();
            let continued = physical.ends_with('\\');
            let fragment = physical.strip_suffix('\\').unwrap_or(physical).trim();
            if !logical.is_empty() {
                logical.push(' ');
            }
            logical.push_str(fragment);
            if !continued {
                break;
            }
            index += 1;
            if index == lines.len() {
                return Err(format!(
                    "preprocessor directive at line {} has a dangling continuation",
                    start + 1
                ));
            }
        }

        if let Some(capture) = directive.captures(&logical) {
            let kind = capture.get(1).expect("directive kind").as_str();
            let normalized = normalize_c(&logical).map_err(|error| {
                format!(
                    "normalize preprocessor directive at line {}: {error}",
                    start + 1
                )
            })?;
            match kind {
                "if" | "ifdef" | "ifndef" => stack.push(PreprocessorFrame {
                    branches: vec![normalized],
                    saw_else: false,
                }),
                "elif" => {
                    let frame = stack
                        .last_mut()
                        .ok_or_else(|| format!("unmatched #elif at line {}", start + 1))?;
                    if frame.saw_else {
                        return Err(format!("#elif after #else at line {}", start + 1));
                    }
                    frame.branches.push(normalized);
                }
                "else" => {
                    let frame = stack
                        .last_mut()
                        .ok_or_else(|| format!("unmatched #else at line {}", start + 1))?;
                    if frame.saw_else {
                        return Err(format!("duplicate #else at line {}", start + 1));
                    }
                    frame.saw_else = true;
                    frame.branches.push(normalized);
                }
                "endif" => {
                    stack
                        .pop()
                        .ok_or_else(|| format!("unmatched #endif at line {}", start + 1))?;
                }
                _ => unreachable!(),
            }
        }

        let active = stack
            .iter()
            .flat_map(|frame| frame.branches.iter().cloned())
            .collect::<Vec<_>>();
        for context in &mut contexts[start..=index] {
            context.clone_from(&active);
        }
        index += 1;
    }
    if !stack.is_empty() {
        return Err(format!(
            "{} unterminated preprocessor condition(s)",
            stack.len()
        ));
    }
    Ok(contexts)
}

fn is_class_id_macro(name: &str, definition: &str) -> bool {
    if !name.starts_with("xmlSec") || !name.ends_with("Id") {
        return false;
    }
    definition
        .split_once(name)
        .is_some_and(|(_, replacement)| !replacement.starts_with('('))
}

fn is_registry_api(name: &str) -> bool {
    name.contains("Register")
        || name.starts_with("xmlSecKeyDataIds")
        || name.starts_with("xmlSecTransformIds")
}

fn render_configured_header(template: &str, configure: &str) -> Result<String, String> {
    let version = Regex::new(r"AC_INIT\(\[xmlsec1\],\[([0-9]+)\.([0-9]+)\.([0-9]+)\]")
        .expect("valid configured version regex")
        .captures(configure)
        .ok_or("configure.ac has no three-part xmlsec1 version")?;
    let major = version[1]
        .parse::<u32>()
        .map_err(|error| format!("parse major version: {error}"))?;
    let minor = version[2]
        .parse::<u32>()
        .map_err(|error| format!("parse minor version: {error}"))?;
    let subminor = version[3]
        .parse::<u32>()
        .map_err(|error| format!("parse subminor version: {error}"))?;
    for required in [
        "XMLSEC_VERSION_MAJOR=$(echo $PACKAGE_VERSION | cut -d. -f1)",
        "XMLSEC_VERSION_MINOR=$(echo $PACKAGE_VERSION | cut -d. -f2)",
        "XMLSEC_VERSION_SUBMINOR=$(echo $PACKAGE_VERSION | cut -d. -f3)",
        "XMLSEC_VERSION=\"$PACKAGE_VERSION\"",
        "XMLSEC_VERSION_CURRENT=$((10000 * XMLSEC_VERSION_MAJOR + 100 * XMLSEC_VERSION_MINOR + XMLSEC_VERSION_SUBMINOR))",
        "XMLSEC_VERSION_INFO=\"${XMLSEC_VERSION_CURRENT}:0:0\"",
    ] {
        if !configure.contains(required) {
            return Err(format!(
                "configure.ac version contract is missing: {required}"
            ));
        }
    }

    let semantic_version = format!("{major}.{minor}.{subminor}");
    let version_current = major
        .checked_mul(10_000)
        .and_then(|value| {
            minor
                .checked_mul(100)
                .and_then(|minor| value.checked_add(minor))
        })
        .and_then(|value| value.checked_add(subminor))
        .ok_or("configured version info exceeds u32")?;
    let version_info = format!("{version_current}:0:0");
    let substitutions = [
        ("@XMLSEC_VERSION@", semantic_version.as_str()),
        (
            "@XMLSEC_VERSION_MAJOR@",
            version.get(1).expect("major capture").as_str(),
        ),
        (
            "@XMLSEC_VERSION_MINOR@",
            version.get(2).expect("minor capture").as_str(),
        ),
        (
            "@XMLSEC_VERSION_SUBMINOR@",
            version.get(3).expect("subminor capture").as_str(),
        ),
        ("@XMLSEC_VERSION_INFO@", version_info.as_str()),
    ];
    let mut rendered = template.to_owned();
    for (placeholder, value) in substitutions {
        rendered = rendered.replace(placeholder, value);
    }
    let unresolved = Regex::new(r"@([A-Z0-9_]+)@").expect("valid placeholder regex");
    if let Some(capture) = unresolved.captures(&rendered) {
        return Err(format!("unresolved Autoconf placeholder {}", &capture[1]));
    }
    Ok(rendered)
}

fn extract_build_defines(donor: &Path, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let source = "configure.ac";
    let content = fs::read_to_string(donor.join(source))
        .map_err(|error| format!("read donor {source}: {error}"))?;
    items.extend(extract_build_defines_from_content(&content));
    Ok(())
}

fn extract_build_defines_from_content(content: &str) -> Vec<SurfaceItem> {
    let regex =
        Regex::new(r#"-D(XMLSEC_[A-Z0-9_]+)(?:=[^\s"']+)?"#).expect("valid compiler define regex");
    let mut items = Vec::new();
    for (index, line) in content.lines().enumerate() {
        for capture in regex.captures_iter(line) {
            items.push(item(
                "build-define",
                &capture[1],
                "configure.ac",
                index + 1,
                line.trim(),
            ));
        }
    }
    items
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
    let mut cursor = 0;
    for capture in token.captures_iter(expression) {
        let whole = capture.get(0).expect("whole token capture");
        if !expression[cursor..whole.start()].trim().is_empty() {
            return Err(format!(
                "unparsed token in C string expression: {expression}"
            ));
        }
        cursor = whole.end();
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
    if !expression[cursor..].trim().is_empty() {
        return Err(format!(
            "unparsed trailing token in C string expression: {expression}"
        ));
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
    items.extend(extract_cli_options_from_content(&content)?);
    items.extend(extract_cli_exit_statuses(&content)?);
    Ok(())
}

fn extract_cli_options_from_content(content: &str) -> Result<Vec<SurfaceItem>, String> {
    let lines: Vec<_> = content.lines().collect();
    let declaration =
        Regex::new(r"^static\s+xmlSecAppCmdLineParam\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{")
            .expect("valid CLI option declaration regex");
    let full_name = Regex::new(
        r#"(?s)^static\s+xmlSecAppCmdLineParam\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{\s*[^,]+,\s*\"([^\"]+)\"\s*,"#,
    )
    .expect("valid CLI option name regex");
    let mut items = Vec::new();
    let mut index = 0_usize;
    while index < lines.len() {
        if !declaration.is_match(lines[index].trim_start()) {
            index += 1;
            continue;
        }
        let (block, end) = collect_declaration(&lines, index)
            .map_err(|error| format!("parse CLI option at apps/xmlsec.c:{}: {error}", index + 1))?;
        // fullName is the stable option identity; retaining the whole initializer
        // below also captures aliases, argument grammar, topics, type, and flags.
        let name = full_name
            .captures(&block)
            .and_then(|capture| capture.get(1))
            .ok_or_else(|| {
                format!(
                    "CLI option at apps/xmlsec.c:{} has no literal full name",
                    index + 1
                )
            })?
            .as_str();
        let detail = normalize_c(&block).map_err(|error| {
            format!(
                "normalize CLI option at apps/xmlsec.c:{}: {error}",
                index + 1
            )
        })?;
        items.push(item(
            "cli-option",
            name,
            "apps/xmlsec.c",
            index + 1,
            &detail,
        ));
        index = end + 1;
    }
    Ok(items)
}

fn extract_cli_exit_statuses(content: &str) -> Result<Vec<SurfaceItem>, String> {
    let definitions = [
        (
            "success",
            r"(?m)^[ \t]*/\* sucecss! \*/\r?\n(?P<target>[ \t]*res = 0;)$",
            "0",
            0,
        ),
        (
            "unknown-command",
            r"(?s)if\(command == xmlSecAppCommandUnknown\) \{.*?\n(?P<target>[ \t]*res = 0;)\r?\n[ \t]*goto done;",
            "0 after printing usage",
            0,
        ),
        (
            "failure",
            r"(?m)^(?P<target>[ \t]*int res = 1;)$",
            "1 for invalid parameters, missing input, initialization, or processing failure",
            1,
        ),
    ];
    definitions
        .into_iter()
        .map(|(name, pattern, detail, exit_code)| {
            let regex = Regex::new(pattern).expect("valid CLI evidence regex");
            let mut matches = regex.captures_iter(content);
            let capture = matches
                .next()
                .ok_or_else(|| format!("donor CLI {name} exit path is missing"))?;
            if matches.next().is_some() {
                return Err(format!("donor CLI {name} exit path is ambiguous"));
            }
            let target = capture.name("target").expect("CLI target capture");
            let line = content[..target.start()].lines().count() + 1;
            let mut status = item("cli-exit-status", name, "apps/xmlsec.c", line, detail);
            status.exit_code = Some(exit_code);
            Ok(status)
        })
        .collect()
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
    items.extend(required_test_runner_items(&tests)?);
    Ok(())
}

fn required_test_runner_items(tests: &Path) -> Result<Vec<SurfaceItem>, String> {
    ["testDSig.sh", "testEnc.sh", "testKeys.sh", "testRes.sh"]
        .into_iter()
        .map(|script| {
            if !tests.join(script).is_file() {
                return Err(format!("donor test runner tests/{script} is missing"));
            }
            Ok(item(
                "test-family",
                script,
                &format!("tests/{script}"),
                1,
                "upstream runner family",
            ))
        })
        .collect()
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

    let availability = availability_spans(&surface)?;
    let mut items = Vec::with_capacity(surface.len());
    let mut classifications = BTreeMap::new();
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
        classifications.insert(
            rule.id.clone(),
            Classification {
                outcome: rule.outcome,
                rationale: rule.rationale.clone(),
                evidence: rule.evidence.clone(),
            },
        );
        items.push(LedgerItem {
            kind: entry.kind,
            name: entry.name,
            source: entry.source,
            line: entry.line,
            detail: entry.detail,
            exit_code: entry.exit_code,
            classification: rule.id.clone(),
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
        schema_version: 2,
        upstream: Upstream {
            project: "libxmlsec1".into(),
            version: EXPECTED_VERSION.into(),
            commit: EXPECTED_COMMIT.trim().into(),
            repository: "https://github.com/lsh123/xmlsec".into(),
        },
        generated_by: "xml-sec-capability-ledger/2".into(),
        evidence: rules.evidence,
        classifications,
        availability,
        items,
    })
}

fn availability_spans(surface: &[SurfaceItem]) -> Result<Vec<AvailabilitySpan>, String> {
    let mut lines = BTreeMap::<(&str, usize), &[String]>::new();
    for item in surface {
        let key = (item.source.as_str(), item.line);
        if let Some(existing) = lines.insert(key, &item.conditions)
            && existing != item.conditions
        {
            return Err(format!(
                "items at {}:{} have inconsistent preprocessor conditions",
                item.source, item.line
            ));
        }
    }

    let mut spans: Vec<AvailabilitySpan> = Vec::new();
    let mut interrupted = false;
    for ((source, line), conditions) in lines {
        if conditions.is_empty() {
            interrupted = true;
            continue;
        }
        if let Some(last) = spans.last_mut()
            && !interrupted
            && last.source == source
            && last.conditions == conditions
        {
            last.end_line = line;
            continue;
        }
        spans.push(AvailabilitySpan {
            source: source.to_owned(),
            start_line: line,
            end_line: line,
            conditions: conditions.to_vec(),
        });
        interrupted = false;
    }
    Ok(spans)
}

fn collect_macro_definition(lines: &[&str], start: usize) -> (String, usize) {
    let mut end = start;
    let mut block = String::new();
    while end < lines.len() {
        block.push_str(lines[end]);
        block.push('\n');
        if !lines[end].trim_end().ends_with('\\') {
            break;
        }
        end += 1;
    }
    (block, end)
}

fn collect_declaration(lines: &[&str], start: usize) -> Result<(String, usize), String> {
    let mut block = String::new();
    let mut in_block_comment = false;
    let mut quote = None;
    let mut escaped = false;
    let mut braces = 0_usize;
    let mut parentheses = 0_usize;
    let mut brackets = 0_usize;

    for (end, line) in lines.iter().enumerate().skip(start) {
        block.push_str(line);
        block.push('\n');
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if in_block_comment {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            if let Some(delimiter) = quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == delimiter {
                    quote = None;
                }
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_block_comment = true;
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'/') {
                break;
            }
            match ch {
                '\'' | '"' => quote = Some(ch),
                '{' => braces += 1,
                '}' => braces = braces.saturating_sub(1),
                '(' => parentheses += 1,
                ')' => parentheses = parentheses.saturating_sub(1),
                '[' => brackets += 1,
                ']' => brackets = brackets.saturating_sub(1),
                ';' if braces == 0 && parentheses == 0 && brackets == 0 => {
                    return Ok((block, end));
                }
                _ => {}
            }
        }
    }
    Err("declaration has no top-level semicolon".into())
}

fn typedef_aliases(declaration: &str) -> Vec<String> {
    let sanitized = sanitize_c(declaration);
    let alias = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?$")
        .expect("valid typedef alias regex");
    let mut aliases = Vec::new();
    let mut segment_start = sanitized.find("typedef").map_or(0, |start| start + 7);
    let scan_start = segment_start;
    let mut braces = 0_usize;
    let mut parentheses = 0_usize;
    let mut brackets = 0_usize;
    for (index, ch) in sanitized
        .char_indices()
        .skip_while(|(index, _)| *index < scan_start)
    {
        match ch {
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            '(' => parentheses += 1,
            ')' => parentheses = parentheses.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            ',' | ';' if braces == 0 && parentheses == 0 && brackets == 0 => {
                if let Some(capture) = alias.captures(sanitized[segment_start..index].trim()) {
                    aliases.push(capture[1].to_owned());
                }
                segment_start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    aliases
}

fn sanitize_c(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    let mut quote = None;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                output.push(ch);
            } else {
                output.push(' ');
            }
        } else if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                output.push(' ');
                output.push(' ');
                chars.next();
                in_block_comment = false;
            } else if ch == '\n' {
                output.push(ch);
            } else {
                output.push(' ');
            }
        } else if let Some(delimiter) = quote {
            output.push(' ');
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            output.push(' ');
            output.push(' ');
            chars.next();
            in_block_comment = true;
        } else if ch == '/' && chars.peek() == Some(&'/') {
            output.push(' ');
            output.push(' ');
            chars.next();
            in_line_comment = true;
        } else if ch == '\'' || ch == '"' {
            output.push(' ');
            quote = Some(ch);
        } else {
            output.push(ch);
        }
    }
    output
}

fn normalize_c(value: &str) -> Result<String, String> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    let mut quote = None;
    let mut escaped = false;
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    let mut pending_space = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\\' && chars.peek() == Some(&'\n') {
                chars.next();
            } else if ch == '\n' {
                in_line_comment = false;
                pending_space = true;
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
                pending_space = true;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            pending_space = true;
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            pending_space = true;
        } else if ch == '\'' || ch == '"' {
            if pending_space && !output.is_empty() {
                output.push(' ');
            }
            pending_space = false;
            output.push(ch);
            quote = Some(ch);
        } else if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !output.is_empty() {
                output.push(' ');
            }
            pending_space = false;
            output.push(ch);
        }
    }

    if in_block_comment {
        return Err("unterminated block comment".into());
    }
    if let Some(delimiter) = quote {
        return Err(format!("unterminated {delimiter} literal"));
    }
    Ok(output)
}

fn exported_name(declaration: &str) -> Option<String> {
    let function = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("valid function regex");
    let mut depth = 0_usize;
    let mut cursor = 0_usize;
    for capture in function.captures_iter(declaration) {
        let whole = capture.get(0).expect("whole function capture");
        for byte in declaration[cursor..whole.start()].bytes() {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if depth == 0 && capture[1].starts_with("xmlSec") {
            return Some(capture[1].to_owned());
        }
        // The regex includes the opening parenthesis, so account for it before
        // scanning the gap that precedes the next candidate.
        depth += 1;
        cursor = whole.end();
    }
    let variable =
        Regex::new(r"(xmlSec[A-Za-z0-9_]*)\s*(?:\[\])?\s*;").expect("valid variable regex");
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
        exit_code: None,
        conditions: Vec::new(),
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
    fn rejects_unparsed_uri_expression_tokens() {
        // A partially parsed expression would publish a truncated URI as donor truth.
        let macros = BTreeMap::from([("XMLSEC_PREFIX".into(), "urn:test:".into())]);
        for expression in [
            "XMLSEC_PREFIX lowercase \"suffix\"",
            "XMLSEC_PREFIX \"suffix\" trailing",
        ] {
            let error = resolve_c_string_expression(expression, &macros)
                .expect_err("every expression byte must be recognized");
            assert!(error.contains("unparsed"), "{error}");
        }
    }

    #[test]
    fn installed_header_assignment_stops_without_a_continuation() {
        // A later distribution entry must not become a public header accidentally.
        let content = "inc_HEADERS = public.h\nEXTRA_DIST = private.h\n";
        let mut headers = BTreeSet::new();
        collect_installed_headers(content, Path::new("backend"), &mut headers);
        assert_eq!(
            headers,
            BTreeSet::from(["include/xmlsec/backend/public.h".into()])
        );
    }

    #[test]
    fn cli_exit_statuses_are_derived_from_donor_control_flow() {
        // Evidence lines must follow the donor statements instead of generator constants.
        let content = r#"int main(void) {
    int res = 1;
    if(command == xmlSecAppCommandUnknown) {
        xmlSecAppPrintUsage();
        res = 0;
        goto done;
    }
    /* sucecss! */
    res = 0;
done:
    return(res);
}"#;
        let entries = extract_cli_exit_statuses(content).expect("fixture must be recognized");
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.name.as_str(), entry.line, entry.exit_code))
                .collect::<Vec<_>>(),
            vec![
                ("success", 9, Some(0)),
                ("unknown-command", 5, Some(0)),
                ("failure", 2, Some(1)),
            ]
        );

        let error = extract_cli_exit_statuses(&content.replace("/* sucecss! */", "/* done */"))
            .expect_err("missing semantic marker must fail closed");
        assert!(error.contains("success"), "{error}");
    }

    #[test]
    fn required_test_runners_fail_closed() {
        // A renamed donor runner must disappear only through an explicit baseline update.
        let directory = env::temp_dir().join(format!(
            "xml-sec-ledger-runner-drift-{}",
            std::process::id()
        ));
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("stale runner fixture must be removable");
        }
        fs::create_dir_all(&directory).expect("runner fixture must be creatable");
        for script in ["testDSig.sh", "testEnc.sh", "testKeys.sh"] {
            fs::write(directory.join(script), "#!/bin/sh\n")
                .expect("runner fixture must be writable");
        }
        let error = required_test_runner_items(&directory)
            .expect_err("a missing required runner must fail");
        assert!(error.contains("testRes.sh"), "{error}");
        fs::remove_dir_all(directory).expect("runner fixture must be removable");
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
        assert_eq!(ledger.items[0].classification, "supported");
        assert_eq!(ledger.items[1].classification, "fallback");
        assert_eq!(ledger.classifications.len(), 2);
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
    fn export_parser_selects_the_outer_function_declarator() {
        // Nested callback types and trailing annotations are not exported symbols.
        assert_eq!(
            exported_name(
                "XMLSEC_EXPORT int XMLSEC_CALL xmlSecRegister(int (*callback)(void *ctx));"
            )
            .as_deref(),
            Some("xmlSecRegister")
        );
        assert_eq!(
            exported_name("XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void) XMLSEC_API(1);")
                .as_deref(),
            Some("xmlSecInit")
        );
        assert_eq!(
            exported_name("XMLSEC_DEPRECATED(1) XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void);")
                .as_deref(),
            Some("xmlSecInit")
        );
    }

    #[test]
    fn declaration_collector_ignores_semicolons_in_comments_and_literals() {
        // Documentation entities and examples must not truncate a public declaration.
        let lines = [
            "typedef enum {",
            "    value = 0, /* compares as value &lt; limit; */",
            "    other = 1 /* example: \"done;\" */",
            "} xmlSecExample;",
        ];
        let (declaration, end) = collect_declaration(&lines, 0).expect("enum must parse");
        assert_eq!(end, 3);
        assert!(declaration.contains("xmlSecExample;"));
    }

    #[test]
    fn macro_collector_preserves_the_complete_definition() {
        // A continuation-body change must produce a generated ledger diff.
        let lines = [
            "#define xmlSecAssert(condition) \\",
            "    do { \\",
            "        check(condition); \\",
            "    } while(0)",
            "#define xmlSecNext 1",
        ];
        let (definition, end) = collect_macro_definition(&lines, 0);
        assert_eq!(end, 3);
        assert!(definition.contains("check(condition)"));
        assert!(!definition.contains("xmlSecNext"));
    }

    #[test]
    fn typedef_parser_extracts_public_alias_declarators() {
        // Scalar, pointer, and inline-layout aliases are separate public C names.
        assert_eq!(
            typedef_aliases("typedef size_t xmlSecSize;"),
            vec!["xmlSecSize"]
        );
        assert_eq!(
            typedef_aliases("typedef struct _xmlSecKey xmlSecKey, *xmlSecKeyPtr;"),
            vec!["xmlSecKey", "xmlSecKeyPtr"]
        );
        assert_eq!(
            typedef_aliases("typedef struct { int member; } xmlSecInline, *xmlSecInlinePtr;"),
            vec!["xmlSecInline", "xmlSecInlinePtr"]
        );
    }

    #[test]
    fn build_define_parser_only_accepts_compiler_definitions() {
        // Configure shell variables are not part of the public preprocessor surface,
        // while every XMLSEC_* compiler token is part of the donor build contract.
        let content = r#"XMLSEC_CRYPTO_CFLAGS=\"-I/example\"
XMLSEC_CRYPTO_DISABLED_LIST=\"openssl\"
CFLAGS=\"$CFLAGS -DXMLSEC_NO_DES -DXMLSEC_CRYPTO_OPENSSL=1\"
XMLSEC_DEFINES=\"$XMLSEC_DEFINES -DXMLSEC_STATIC=1 -DXMLSEC_DL_LIBLTDL=1\"
OPENSSL_CFLAGS=\"$OPENSSL_CFLAGS -DXMLSEC_OPENSSL3_ENGINES=1\"
MSCRYPTO_CFLAGS=\"$MSCRYPTO_CFLAGS -DXMLSEC_CUSTOM_CRYPT32=1\""#;
        let entries = extract_build_defines_from_content(content);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "XMLSEC_NO_DES",
                "XMLSEC_CRYPTO_OPENSSL",
                "XMLSEC_STATIC",
                "XMLSEC_DL_LIBLTDL",
                "XMLSEC_OPENSSL3_ENGINES",
                "XMLSEC_CUSTOM_CRYPT32",
            ]
        );
    }

    #[test]
    fn normalization_preserves_c_literal_bytes() {
        // Whitespace trivia may collapse, but bytes inside C literals are semantic.
        assert_eq!(
            normalize_c("#define VALUE   \" \"\n  \"  \"").unwrap(),
            "#define VALUE \" \" \"  \""
        );
        assert_ne!(
            normalize_c("#define VALUE \" \"").unwrap(),
            normalize_c("#define VALUE \"  \"").unwrap()
        );
    }

    #[test]
    fn c_normalization_removes_comments_but_preserves_literal_markers() {
        // Donor comments are trivia, while identical bytes inside literals are public data.
        assert_eq!(
            normalize_c(
                "int value /* owner's note */ = call(\"/*kept*/\", '//'); // tail \\\ndiscarded\n;"
            )
            .unwrap(),
            "int value = call(\"/*kept*/\", '//'); ;"
        );
    }

    #[test]
    fn c_normalization_rejects_unterminated_lexical_states() {
        // Truncated donor input must fail generation rather than enter the baseline.
        for malformed in ["int x; /*", "const char *x = \"unterminated", "int x = '"] {
            assert!(normalize_c(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn preprocessor_conditions_preserve_nested_branch_history() {
        // Availability evidence includes both the selected branch and alternatives passed over.
        let conditions = preprocessor_conditions(
            "#ifdef XMLSEC_FEATURE\n#if XMLSEC_BACKEND\nint first;\n#elif XMLSEC_FALLBACK\nint second;\n#else\nint third;\n#endif\n#endif\n",
        )
        .expect("balanced conditions must parse");
        assert_eq!(
            conditions[2],
            ["#ifdef XMLSEC_FEATURE", "#if XMLSEC_BACKEND"]
        );
        assert_eq!(
            conditions[4],
            [
                "#ifdef XMLSEC_FEATURE",
                "#if XMLSEC_BACKEND",
                "#elif XMLSEC_FALLBACK",
            ]
        );
        assert_eq!(
            conditions[6],
            [
                "#ifdef XMLSEC_FEATURE",
                "#if XMLSEC_BACKEND",
                "#elif XMLSEC_FALLBACK",
                "#else",
            ]
        );
    }

    #[test]
    fn preprocessor_conditions_reject_malformed_branching() {
        // A damaged donor guard stack must fail generation instead of losing availability data.
        for malformed in ["#else\n", "#if A\n#else\n#elif B\n#endif\n", "#if A\n"] {
            assert!(preprocessor_conditions(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn availability_spans_normalize_repeated_item_conditions() {
        // One source span replaces repeated per-item arrays without covering unguarded entries.
        let mut guarded_a = item("macro", "A", "public.h", 10, "A");
        guarded_a.conditions = vec!["#ifndef XMLSEC_NO_A".into()];
        let mut guarded_b = item("macro", "B", "public.h", 20, "B");
        guarded_b.conditions = guarded_a.conditions.clone();
        let unguarded = item("macro", "C", "public.h", 30, "C");
        let mut guarded_d = item("macro", "D", "public.h", 40, "D");
        guarded_d.conditions = guarded_a.conditions.clone();

        let spans = availability_spans(&[guarded_a, guarded_b, unguarded, guarded_d])
            .expect("consistent item conditions must normalize");
        assert_eq!(spans.len(), 2);
        assert_eq!((spans[0].start_line, spans[0].end_line), (10, 20));
        assert_eq!((spans[1].start_line, spans[1].end_line), (40, 40));
    }

    #[test]
    fn cli_option_parser_preserves_the_typed_option_contract() {
        // Name, aliases, help syntax, topic, type, and flags must drift together.
        let content = r#"static xmlSecAppCmdLineParam outputParam = {
    xmlSecAppCmdLineTopicAll,
    "--output",
    "-o",
    "--output <filename>\n\twrite result to file",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};"#;
        let options = extract_cli_options_from_content(content).expect("option must parse");
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].name, "--output");
        assert!(options[0].detail.contains("\"-o\""));
        assert!(options[0].detail.contains("<filename>"));
        assert!(
            options[0]
                .detail
                .contains("xmlSecAppCmdLineParamTypeString")
        );
    }

    #[test]
    fn deduplication_preserves_conditional_macro_variants() {
        // Alternative preprocessor branches are separate donor surface locations.
        let entries = deduplicate_surface(vec![
            item("macro", "XMLSEC_EXPORT", "exports.h", 41, "dllexport"),
            item("macro", "XMLSEC_EXPORT", "exports.h", 48, "dllimport"),
        ]);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn registry_predicate_covers_lifecycle_lookup_and_registration() {
        // Registry compatibility includes the complete public ID-list lifecycle.
        for name in [
            "xmlSecKeyDataIdsGet",
            "xmlSecKeyDataIdsGetEnabled",
            "xmlSecKeyDataIdsInit",
            "xmlSecKeyDataIdsShutdown",
            "xmlSecKeyDataIdsRegisterDefault",
            "xmlSecKeyDataIdsRegister",
            "xmlSecKeyDataIdsRegisterDisabled",
            "xmlSecTransformIdsGet",
            "xmlSecTransformIdsInit",
            "xmlSecTransformIdsShutdown",
            "xmlSecTransformIdsRegisterDefault",
            "xmlSecTransformIdsRegister",
            "xmlSecIORegisterCallbacks",
        ] {
            assert!(is_registry_api(name), "{name}");
        }
        assert!(!is_registry_api("xmlSecTransformGetName"));
    }

    #[test]
    fn class_id_detection_uses_the_complete_macro_definition() {
        // Backend class IDs commonly put GetKlass() on a continuation line.
        assert!(is_class_id_macro(
            "xmlSecGCryptTransformAes128CbcId",
            "#define xmlSecGCryptTransformAes128CbcId \\\n             xmlSecGCryptTransformAes128CbcGetKlass()"
        ));
        assert!(is_class_id_macro(
            "xmlSecTransformAes128CbcId",
            "#define xmlSecTransformAes128CbcId xmlSecGCryptTransformAes128CbcId"
        ));
        assert!(!is_class_id_macro(
            "xmlSecKeyCheckId",
            "#define xmlSecKeyCheckId(key, keyId) ((key)->id == (keyId))"
        ));
    }

    #[test]
    fn configured_header_substitutes_pinned_version_values() {
        // Installed header details must represent configure output, not @...@ tokens.
        let configure = r#"AC_INIT([xmlsec1],[1.3.13],[https://example.invalid])
XMLSEC_VERSION_MAJOR=$(echo $PACKAGE_VERSION | cut -d. -f1)
XMLSEC_VERSION_MINOR=$(echo $PACKAGE_VERSION | cut -d. -f2)
XMLSEC_VERSION_SUBMINOR=$(echo $PACKAGE_VERSION | cut -d. -f3)
XMLSEC_VERSION="$PACKAGE_VERSION"
XMLSEC_VERSION_CURRENT=$((10000 * XMLSEC_VERSION_MAJOR + 100 * XMLSEC_VERSION_MINOR + XMLSEC_VERSION_SUBMINOR))
XMLSEC_VERSION_INFO="${XMLSEC_VERSION_CURRENT}:0:0""#;
        let rendered = render_configured_header(
            "#define XMLSEC_VERSION \"@XMLSEC_VERSION@\"\n#define XMLSEC_VERSION_INFO \"@XMLSEC_VERSION_INFO@\"\n",
            configure,
        )
        .expect("known substitutions must render");
        assert!(rendered.contains("\"1.3.13\""));
        assert!(rendered.contains("\"10313:0:0\""));

        let error = render_configured_header("@UNKNOWN_VALUE@", configure)
            .expect_err("unknown substitutions must fail closed");
        assert!(error.contains("UNKNOWN_VALUE"), "{error}");
    }

    #[test]
    fn donor_snapshot_ignores_tracked_and_generated_worktree_changes() {
        // Extraction is commit-based: configure/build output and local edits in
        // the caller's checkout must neither contaminate nor block the ledger.
        let directory =
            env::temp_dir().join(format!("xml-sec-ledger-dirty-donor-{}", std::process::id()));
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("stale donor fixture must be removable");
        }
        fs::create_dir_all(&directory).expect("fixture must be creatable");
        fs::write(directory.join("tracked.h"), "original\n").expect("fixture must be writable");
        fs::write(directory.join(".gitignore"), "generated/\n")
            .expect("ignore fixture must be writable");
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
                .args([
                    "-C",
                    directory.to_str().unwrap(),
                    "add",
                    ".gitignore",
                    "tracked.h"
                ])
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
                    "test fixture"
                ])
                .status()
                .unwrap()
                .success()
        );
        fs::create_dir_all(directory.join("generated")).expect("ignored fixture must be creatable");
        fs::write(directory.join("generated/header.h"), "generated\n")
            .expect("ignored fixture must be writable");
        fs::write(directory.join("tracked.h"), "modified\n").expect("fixture must be writable");
        let commit = Command::new("git")
            .args(["-C", directory.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap();
        let commit = String::from_utf8(commit.stdout).unwrap();
        let snapshot = snapshot_donor(&directory, commit.trim())
            .expect("dirty caller checkout must produce an immutable commit snapshot");
        assert_eq!(
            fs::read_to_string(snapshot.path().join("tracked.h")).unwrap(),
            "original\n"
        );
        assert!(!snapshot.path().join("generated").exists());
        assert_eq!(
            fs::read_to_string(directory.join("tracked.h")).unwrap(),
            "modified\n"
        );
        assert!(directory.join("generated/header.h").exists());
        fs::remove_dir_all(directory).expect("donor fixture must be removable");
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
