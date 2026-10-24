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

#[derive(Debug, Deserialize)]
struct BehaviorRulesFile {
    schema_version: u32,
    evidence: BTreeMap<String, BehaviorEvidence>,
    behaviors: Vec<BehaviorRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BehaviorEvidence {
    /// Assertions proving accepted/successful behavior. A differential test may
    /// also appear in `negative` when it proves both outcomes in one execution.
    positive: Vec<BehaviorTest>,
    /// Assertions proving rejected/failing behavior, not necessarily separate
    /// test executables from the paired positive assertions.
    negative: Vec<BehaviorTest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BehaviorTest {
    file: String,
    test: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct BehaviorRule {
    id: String,
    category: String,
    summary: String,
    classification: BehaviorClassification,
    control: BehaviorControl,
    evidence: String,
    donor_anchors: Vec<DonorAnchorRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BehaviorClassification {
    Native,
    CompatibilityPolicy,
    PlannedCCompatibilityBoundary,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BehaviorControl {
    boundary: String,
    setting: String,
    default: String,
}

#[derive(Debug, Deserialize)]
struct DonorAnchorRule {
    source: String,
    needle: String,
}

#[derive(Debug, Serialize)]
struct BehaviorLedger {
    schema_version: u32,
    upstream: Upstream,
    generated_by: String,
    evidence: BTreeMap<String, BehaviorEvidence>,
    behaviors: Vec<BehaviorLedgerItem>,
}

#[derive(Debug, Serialize)]
struct BehaviorLedgerItem {
    id: String,
    category: String,
    summary: String,
    classification: BehaviorClassification,
    control: BehaviorControl,
    evidence: String,
    donor_anchors: Vec<DonorAnchor>,
}

#[derive(Debug, Serialize)]
struct DonorAnchor {
    source: String,
    line: usize,
    needle: String,
}

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if !matches!(
        command.as_str(),
        "generate" | "check" | "behavior-generate" | "behavior-check"
    ) {
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
    if command.starts_with("behavior-") {
        return generate_behavior_ledger(
            command == "behavior-check",
            donor_snapshot.path(),
            &rules_path,
            &output,
        );
    }
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
    "usage: xml-sec-capability-ledger <generate|check|behavior-generate|behavior-check> <donor> <rules.json> <ledger.json>".into()
}

fn generate_behavior_ledger(
    check: bool,
    donor: &Path,
    rules_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let rules: BehaviorRulesFile = serde_json::from_slice(
        &fs::read(rules_path).map_err(|error| format!("read {}: {error}", rules_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", rules_path.display()))?;
    if rules.schema_version != 1 {
        return Err(format!(
            "unsupported behavior rules schema {}",
            rules.schema_version
        ));
    }
    validate_behavior_categories(&rules.behaviors)?;
    validate_behavior_evidence(&rules.evidence)?;
    let referenced_evidence = rules
        .behaviors
        .iter()
        .map(|behavior| behavior.evidence.clone())
        .collect::<BTreeSet<_>>();
    validate_behavior_evidence_references(&rules.evidence, &referenced_evidence)?;

    let mut ids = BTreeSet::new();
    let mut behaviors = Vec::with_capacity(rules.behaviors.len());
    for rule in rules.behaviors {
        if !ids.insert(rule.id.clone()) {
            return Err(format!("duplicate behavior id {}", rule.id));
        }
        if !rules.evidence.contains_key(&rule.evidence) {
            return Err(format!(
                "behavior {} references missing evidence {}",
                rule.id, rule.evidence
            ));
        }
        if rule.control.boundary.trim().is_empty()
            || rule.control.setting.trim().is_empty()
            || rule.control.default.trim().is_empty()
        {
            return Err(format!(
                "behavior {} has an incomplete control boundary",
                rule.id
            ));
        }
        if rule.donor_anchors.is_empty() {
            return Err(format!("behavior {} has no donor anchors", rule.id));
        }
        let donor_anchors = rule
            .donor_anchors
            .into_iter()
            .map(|anchor| resolve_donor_anchor(donor, anchor))
            .collect::<Result<Vec<_>, _>>()?;
        behaviors.push(BehaviorLedgerItem {
            id: rule.id,
            category: rule.category,
            summary: rule.summary,
            classification: rule.classification,
            control: rule.control,
            evidence: rule.evidence,
            donor_anchors,
        });
    }
    behaviors.sort_by(|left, right| left.id.cmp(&right.id));
    let ledger = BehaviorLedger {
        schema_version: 1,
        upstream: Upstream {
            project: "libxmlsec1".into(),
            version: EXPECTED_VERSION.into(),
            commit: EXPECTED_COMMIT.trim().into(),
            repository: "https://github.com/lsh123/xmlsec".into(),
        },
        generated_by: "xml-sec-capability-ledger behavior-generate".into(),
        evidence: rules.evidence,
        behaviors,
    };
    let mut bytes = serde_json::to_vec_pretty(&ledger).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if check {
        let existing = fs::read(output)
            .map_err(|error| format!("read generated ledger {}: {error}", output.display()))?;
        if existing != bytes {
            return Err(format!(
                "{} is stale; regenerate it with behavior-generate",
                output.display()
            ));
        }
    } else {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        fs::write(output, bytes).map_err(|error| format!("write {}: {error}", output.display()))?;
    }
    Ok(())
}

fn validate_behavior_categories(behaviors: &[BehaviorRule]) -> Result<(), String> {
    let actual = behaviors
        .iter()
        .map(|behavior| behavior.category.as_str())
        .collect::<BTreeSet<_>>();
    let required = [
        "callback-ordering",
        "context-after-failure",
        "dom-mutation",
        "dtd-xml-id-caller-id",
        "empty-uri-xpointer",
        "error-invalid-classification",
        "here-semantics",
        "implicit-c14n-adapters",
        "manifest-status",
        "multiple-signatures",
        "signature-value-encoding",
        "visa3d-ids",
    ];
    for category in required {
        if !actual.contains(category) {
            return Err(format!("behavior ledger is missing category {category}"));
        }
    }
    Ok(())
}

fn validate_behavior_evidence(evidence: &BTreeMap<String, BehaviorEvidence>) -> Result<(), String> {
    for (id, evidence) in evidence {
        if evidence.positive.is_empty() || evidence.negative.is_empty() {
            return Err(format!(
                "evidence {id} must have positive and negative tests"
            ));
        }
        validate_unique_behavior_assertions(id, "positive", &evidence.positive)?;
        validate_unique_behavior_assertions(id, "negative", &evidence.negative)?;
        for negative in &evidence.negative {
            if evidence.positive.iter().any(|positive| {
                behavior_assertion_key(positive) == behavior_assertion_key(negative)
            }) {
                return Err(format!(
                    "evidence {id} repeats an identical positive and negative assertion for {}",
                    negative.test
                ));
            }
        }
        for test in evidence.positive.iter().chain(&evidence.negative) {
            let path = Path::new(&test.file);
            if path.is_absolute() || test.file.contains("..") {
                return Err(format!("evidence {id} has unsafe test path {}", test.file));
            }
            let source = fs::read_to_string(path)
                .map_err(|error| format!("read evidence test {}: {error}", path.display()))?;
            if !contains_test_declaration(&source, &test.test)? {
                return Err(format!(
                    "evidence {id} test {} is absent from {}",
                    test.test, test.file
                ));
            }
        }
    }
    Ok(())
}

fn validate_unique_behavior_assertions(
    evidence_id: &str,
    polarity: &str,
    assertions: &[BehaviorTest],
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for assertion in assertions {
        if !seen.insert(behavior_assertion_key(assertion)) {
            return Err(format!(
                "evidence {evidence_id} has a duplicate {polarity} assertion for {}",
                assertion.test
            ));
        }
    }
    Ok(())
}

fn behavior_assertion_key(assertion: &BehaviorTest) -> (&str, &str, &str) {
    (&assertion.file, &assertion.test, &assertion.description)
}

fn validate_behavior_evidence_references(
    evidence: &BTreeMap<String, BehaviorEvidence>,
    referenced: &BTreeSet<String>,
) -> Result<(), String> {
    for id in evidence.keys() {
        if !referenced.contains(id) {
            return Err(format!("evidence {id} is referenced by no behavior"));
        }
    }
    Ok(())
}

fn contains_test_declaration(source: &str, test_name: &str) -> Result<bool, String> {
    let file =
        syn::parse_file(source).map_err(|error| format!("parse Rust evidence source: {error}"))?;
    Ok(attributes_allow_behavior_evidence(&file.attrs)
        && enabled_test_declaration_count(&file.items, test_name) == 1)
}

fn enabled_test_declaration_count(items: &[syn::Item], test_name: &str) -> usize {
    items
        .iter()
        .map(|item| match item {
            syn::Item::Fn(function) => usize::from(is_enabled_test(function, test_name)),
            syn::Item::Mod(module) if attributes_allow_behavior_evidence(&module.attrs) => {
                module.content.as_ref().map_or(0, |(_, nested)| {
                    enabled_test_declaration_count(nested, test_name)
                })
            }
            _ => 0,
        })
        .sum()
}

fn is_enabled_test(function: &syn::ItemFn, test_name: &str) -> bool {
    function.sig.ident == test_name
        && function
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        // Ledger evidence must execute in every supported build, not merely
        // exist behind a target/feature condition or ignore.
        && !function.attrs.iter().any(|attribute| {
            ["ignore", "should_panic", "cfg", "cfg_attr"]
                .iter()
                .any(|name| attribute.path().is_ident(name))
        })
}

fn attributes_allow_behavior_evidence(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().all(|attribute| {
        if attribute.path().is_ident("cfg") {
            // Unit tests conventionally live in a cfg(test) module. Any other
            // module condition means the evidence is absent from some builds.
            return attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|condition| condition == "test");
        }
        !attribute.path().is_ident("cfg_attr") && !attribute.path().is_ident("ignore")
    })
}

fn resolve_donor_anchor(donor: &Path, anchor: DonorAnchorRule) -> Result<DonorAnchor, String> {
    let source_path = Path::new(&anchor.source);
    if source_path.is_absolute() || anchor.source.contains("..") {
        return Err(format!("unsafe donor source {}", anchor.source));
    }
    let source = fs::read_to_string(donor.join(source_path))
        .map_err(|error| format!("read donor source {}: {error}", anchor.source))?;
    let matches = source.match_indices(&anchor.needle).collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "donor anchor {:?} in {} matched {} times; expected exactly one",
            anchor.needle,
            anchor.source,
            matches.len()
        ));
    }
    let line = source[..matches[0].0]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    Ok(DonorAnchor {
        source: anchor.source,
        line,
        needle: anchor.needle,
    })
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
    let output = donor_clone_command(donor, snapshot.path())
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

fn donor_clone_command(donor: &Path, snapshot: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .args(["clone", "--quiet", "--no-checkout", "--"])
        .arg(donor)
        .arg(snapshot);
    command
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

/// Declaration patterns shared by every scanned header, compiled once.
struct HeaderPatterns {
    macro_name: Regex,
    callback: Regex,
    enum_name: Regex,
    struct_name: Regex,
}

static HEADER_PATTERNS: std::sync::LazyLock<HeaderPatterns> =
    std::sync::LazyLock::new(|| HeaderPatterns {
        macro_name: Regex::new(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid macro regex"),
        callback: Regex::new(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
            .expect("valid callback regex"),
        enum_name: Regex::new(r"}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;").expect("valid enum regex"),
        struct_name: Regex::new(r"^\s*struct\s+(_xmlSec[A-Za-z0-9_]*)")
            .expect("valid struct regex"),
    });

/// The installed header text and its reported source, rendering a
/// configure template when the donor ships one.
fn header_source(donor: &Path, source: &str) -> Result<(String, String), String> {
    let source_path = donor.join(source);
    let template_path = donor.join(format!("{source}.in"));
    if template_path.is_file() {
        let extraction_source = format!("{source}.in");
        let template = fs::read_to_string(&template_path)
            .map_err(|error| format!("read {extraction_source}: {error}"))?;
        let configure = fs::read_to_string(donor.join("configure.ac"))
            .map_err(|error| format!("read donor configure.ac: {error}"))?;
        let content = render_configured_header(&template, &configure)
            .map_err(|error| format!("configure {extraction_source}: {error}"))?;
        Ok((extraction_source, content))
    } else if source_path.is_file() {
        let content =
            fs::read_to_string(&source_path).map_err(|error| format!("read {source}: {error}"))?;
        Ok((source.to_owned(), content))
    } else {
        Err(format!(
            "installed header {source} has no source or configure template"
        ))
    }
}

/// Record one exported declaration with its registry and deprecation facets.
fn extract_export(
    block: &str,
    source: &str,
    extraction_source: &str,
    line_number: usize,
    items: &mut Vec<SurfaceItem>,
) -> Result<(), String> {
    let detail = normalize_c(block).map_err(|error| {
        format!("normalize export at {extraction_source}:{line_number}: {error}")
    })?;
    let name = exported_name(block).ok_or_else(|| {
        format!("cannot extract exported symbol at {extraction_source}:{line_number}: {detail}")
    })?;
    let backend = source.split('/').count() > 3;
    let kind = if backend {
        "backend-api"
    } else if block.contains("_EXPORT_VAR") {
        "export-variable"
    } else {
        "export-function"
    };
    items.push(item(kind, &name, extraction_source, line_number, &detail));
    if is_registry_api(&name) {
        items.push(item(
            "registry",
            &name,
            extraction_source,
            line_number,
            &detail,
        ));
    }
    if block.contains("XMLSEC_DEPRECATED") {
        items.push(item(
            "deprecated-api",
            &name,
            extraction_source,
            line_number,
            &detail,
        ));
    }
    Ok(())
}

/// Record every alias a typedef declares; a typedef without one is malformed.
fn extract_typedef(
    block: &str,
    extraction_source: &str,
    line_number: usize,
    items: &mut Vec<SurfaceItem>,
) -> Result<(), String> {
    let detail = normalize_c(block).map_err(|error| {
        format!("normalize typedef at {extraction_source}:{line_number}: {error}")
    })?;
    let aliases = typedef_aliases(block);
    if aliases.is_empty() {
        return Err(format!(
            "cannot extract typedef alias at {extraction_source}:{line_number}: {detail}"
        ));
    }
    for alias in aliases {
        items.push(item(
            "typedef",
            &alias,
            extraction_source,
            line_number,
            &detail,
        ));
    }
    Ok(())
}

/// Record one enum declaration and, for key data formats, each format value.
fn extract_enum(
    block: &str,
    extraction_source: &str,
    line_number: usize,
    items: &mut Vec<SurfaceItem>,
) -> Result<(), String> {
    let name = HEADER_PATTERNS.enum_name.captures(block).map_or_else(
        || format!("anonymous-enum-{line_number}"),
        |capture| capture[1].to_owned(),
    );
    let detail = normalize_c(block)
        .map_err(|error| format!("normalize enum at {extraction_source}:{line_number}: {error}"))?;
    items.push(item("enum", &name, extraction_source, line_number, &detail));
    if name == "xmlSecKeyDataFormat" {
        for value in extract_identifiers(block, "xmlSecKeyDataFormat") {
            items.push(item(
                "key-format",
                &value,
                extraction_source,
                line_number,
                &name,
            ));
        }
    }
    Ok(())
}

fn extract_header(donor: &Path, source: &str, items: &mut Vec<SurfaceItem>) -> Result<(), String> {
    let (extraction_source, content) = header_source(donor, source)?;
    let lines: Vec<_> = content.lines().collect();
    let conditions = preprocessor_conditions(&content)
        .map_err(|error| format!("parse conditions in {extraction_source}: {error}"))?;
    let HeaderPatterns {
        macro_name: macro_re,
        callback: callback_re,
        struct_name,
        ..
    } = &*HEADER_PATTERNS;

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
            extract_enum(&block, &extraction_source, line_number, items)?;
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
            extract_typedef(&block, &extraction_source, line_number, items)?;
            index = end;
        } else if line.contains("_EXPORT") && !line.trim_start().starts_with('#') {
            let (block, end) = collect_declaration(&lines, index).map_err(|error| {
                format!("parse export at {extraction_source}:{line_number}: {error}")
            })?;
            extract_export(&block, source, &extraction_source, line_number, items)?;
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
        r"(?m)^const xmlChar (xmlSec(?:Href[A-Za-z0-9_]+|XPath2?Ns))\[\]\s*=\s*([^;]+);",
    )
    .expect("valid URI declaration regex");
    // Matches start at line beginnings, so the line is one plus the newlines
    // before it; counting only the gap since the previous match stays linear.
    let mut counted = 0;
    let mut line = 1;
    for capture in regex.captures_iter(&content) {
        let start = capture.get(0).expect("whole URI capture").start();
        line += content[counted..start].matches('\n').count();
        counted = start;
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
mod tests;
