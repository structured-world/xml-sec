//! Ownership of what each exported function returns, hands out through
//! output parameters and adopts from its arguments, from reviewed rules over
//! the ledger declarations. A returned pointer or a writable pointer-to-pointer
//! parameter that no rule covers fails generation, and so does a rule that
//! matches nothing. An export no header marks has no declaration to classify;
//! each must be listed with a rationale, and any other fails generation.

use super::LedgerEntry;
use super::layout::declarator_names;
use super::symbols::{Kind, Library};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
pub(super) struct Rules {
    schema_version: u32,
    /// Release functions outside libxmlsec1 that a rule may name (libxml2's
    /// and OpenSSL's).
    external_releases: Vec<String>,
    /// The first matching rule decides what a pointer-returning function returns.
    returns: Vec<ReturnRule>,
    /// The first matching rule decides what an output parameter hands out.
    outputs: Vec<OutputRule>,
    /// Every matching rule adds the arguments a function adopts.
    adopts: Vec<AdoptRule>,
    /// Exports no header declares with an export marker, by reason.
    unmarked_exports: Vec<UnmarkedExports>,
}

#[derive(Deserialize)]
struct UnmarkedExports {
    id: String,
    names: Vec<String>,
    /// Why no consumer can rely on these symbols, checked against the donor.
    rationale: String,
}

#[derive(Deserialize)]
struct Selector {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    name_regex: Option<String>,
    #[serde(default)]
    returns_regex: Option<String>,
}

#[derive(Deserialize)]
struct ReturnRule {
    id: String,
    #[serde(flatten)]
    selector: Selector,
    returns: Returns,
    /// Why the rule is right, checked against the donor when it was reviewed.
    rationale: String,
}

#[derive(Deserialize)]
struct OutputRule {
    id: String,
    #[serde(flatten)]
    selector: Selector,
    parameter: String,
    gives: Returns,
    /// Why the rule is right, checked against the donor when it was reviewed.
    rationale: String,
}

#[derive(Deserialize)]
struct AdoptRule {
    id: String,
    #[serde(flatten)]
    selector: Selector,
    /// Parameter names, or `$last-pointer` for the last pointer parameter.
    parameters: Vec<String>,
    /// Why the rule is right, checked against the donor when it was reviewed.
    rationale: String,
}

/// What a pointer handed to the caller is. `owner` and `release` may use the
/// placeholders `$first` (the first parameter) and `{type}` (the returned type
/// without `const` and its `Ptr` suffix).
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Returns {
    /// Not a pointer.
    Value,
    /// Library-lifetime data: class objects, constant strings, registries.
    Static,
    /// Points into an argument and lives as long as it does.
    Borrowed { owner: String },
    /// The caller owns it and releases it with `release`.
    Owned { release: String },
    /// The caller takes over a container element; the container's item class
    /// destroys it.
    OwnedElement,
    /// An output-shaped parameter the function only reads, such as an array
    /// of strings: nothing is handed out. Valid only in output rules.
    Input,
}

#[derive(Serialize)]
pub(super) struct Function {
    name: String,
    returns: Returns,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    outputs: BTreeMap<String, Returns>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    adopts: Vec<String>,
}

/// A declaration split into the parts ownership needs.
pub(super) struct Signature {
    pub(super) return_type: String,
    pub(super) parameters: Vec<Parameter>,
}

pub(super) struct Parameter {
    pub(super) name: String,
    pub(super) pointer: bool,
    /// A writable pointer to a pointer: the function may hand something out.
    pub(super) output: bool,
}

pub(super) fn classify(
    rules: &Rules,
    ledger: &[LedgerEntry],
    libraries: &[Library],
) -> Result<Vec<Function>, String> {
    if rules.schema_version != 1 {
        return Err(format!(
            "unsupported ownership rules schema {}",
            rules.schema_version
        ));
    }
    if let Some(rule) = rules
        .returns
        .iter()
        .find(|rule| matches!(rule.returns, Returns::Input))
    {
        return Err(format!(
            "return rule {} classifies a returned pointer as input",
            rule.id
        ));
    }
    check_unmarked(&rules.unmarked_exports, libraries)?;
    let pointer_types = pointer_typedefs(ledger);
    let exported: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library| &library.symbols)
        .filter(|symbol| symbol.kind == Kind::Function && symbol.declaration.is_some())
        .map(|symbol| symbol.name.as_str())
        .collect();
    let releases: BTreeSet<&str> = exported
        .iter()
        .copied()
        .chain(rules.external_releases.iter().map(String::as_str))
        .collect();
    let mut classifier = Classifier {
        rules,
        returns: compile(&rules.returns, |rule| {
            (&rule.id, &rule.selector, &rule.rationale)
        })?,
        outputs: compile(&rules.outputs, |rule| {
            (&rule.id, &rule.selector, &rule.rationale)
        })?,
        adopts: compile(&rules.adopts, |rule| {
            (&rule.id, &rule.selector, &rule.rationale)
        })?,
        releases,
        used: BTreeSet::new(),
        unclassified: Vec::new(),
    };
    let mut functions = BTreeMap::new();
    for item in ledger {
        if !matches!(
            item.kind.as_str(),
            "export-function" | "backend-api" | "internal-export"
        ) || !exported.contains(item.name.as_str())
        {
            continue;
        }
        let signature = signature(&item.name, &item.detail, &pointer_types)?;
        let function = classifier.function(&item.name, &signature, &pointer_types)?;
        if functions.insert(item.name.clone(), function).is_some() {
            return Err(format!("{} is declared twice", item.name));
        }
    }
    classifier.finish()?;
    Ok(functions.into_values().collect())
}

/// The listed unmarked exports are exactly the exports without a declaration.
fn check_unmarked(groups: &[UnmarkedExports], libraries: &[Library]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut listed = BTreeSet::new();
    for group in groups {
        if !ids.insert(group.id.as_str()) {
            return Err(format!(
                "unmarked export group {} is defined twice",
                group.id
            ));
        }
        if group.rationale.trim().is_empty() {
            return Err(format!(
                "unmarked export group {} gives no rationale",
                group.id
            ));
        }
        for name in &group.names {
            if !listed.insert(name.as_str()) {
                return Err(format!("unmarked export {name} is listed twice"));
            }
        }
    }
    let undeclared: BTreeSet<&str> = libraries
        .iter()
        .flat_map(|library| &library.symbols)
        .filter(|symbol| symbol.declaration.is_none())
        .map(|symbol| symbol.name.as_str())
        .collect();
    let unlisted: Vec<&str> = undeclared.difference(&listed).copied().collect();
    if !unlisted.is_empty() {
        return Err(format!(
            "exports without a declaration: {}",
            unlisted.join(", ")
        ));
    }
    let stale: Vec<&str> = listed.difference(&undeclared).copied().collect();
    if !stale.is_empty() {
        return Err(format!(
            "unmarked exports that are declared or not exported: {}",
            stale.join(", ")
        ));
    }
    Ok(())
}

/// The compiled rules and what classifying the exports has found so far.
struct Classifier<'a> {
    rules: &'a Rules,
    returns: Vec<Matcher<'a>>,
    outputs: Vec<Matcher<'a>>,
    adopts: Vec<Matcher<'a>>,
    releases: BTreeSet<&'a str>,
    used: BTreeSet<&'a str>,
    unclassified: Vec<String>,
}

impl Classifier<'_> {
    fn function(
        &mut self,
        name: &str,
        signature: &Signature,
        pointer_types: &BTreeSet<String>,
    ) -> Result<Function, String> {
        let mut returned = Returns::Value;
        if is_pointer(&signature.return_type, pointer_types) {
            let rule = self
                .returns
                .iter()
                .zip(&self.rules.returns)
                .find(|(matcher, _)| matcher.matches(name, &signature.return_type));
            match rule {
                Some((matcher, rule)) => {
                    self.used.insert(matcher.id);
                    returned = resolve(&rule.returns, name, signature, &self.releases)?;
                }
                None => self.unclassified.push(format!("{name} (return value)")),
            }
        }
        let mut handed = BTreeMap::new();
        for (matcher, rule) in self.outputs.iter().zip(&self.rules.outputs) {
            if !matcher.matches(name, &signature.return_type) {
                continue;
            }
            self.used.insert(matcher.id);
            let parameter_name = parameter(&rule.parameter, name, signature)?;
            let gives = resolve(&rule.gives, name, signature, &self.releases)?;
            handed.entry(parameter_name).or_insert(gives);
        }
        for output in signature
            .parameters
            .iter()
            .filter(|parameter| parameter.output && !handed.contains_key(&parameter.name))
        {
            self.unclassified
                .push(format!("{name} (output {})", output.name));
        }
        let mut adopted = BTreeSet::new();
        for (matcher, rule) in self.adopts.iter().zip(&self.rules.adopts) {
            if !matcher.matches(name, &signature.return_type) {
                continue;
            }
            self.used.insert(matcher.id);
            for selector in &rule.parameters {
                adopted.insert(parameter(selector, name, signature)?);
            }
        }
        Ok(Function {
            name: name.to_owned(),
            returns: returned,
            outputs: handed,
            adopts: adopted.into_iter().collect(),
        })
    }

    /// Every pointer the exports hand out is covered, and every rule is used.
    fn finish(self) -> Result<(), String> {
        if !self.unclassified.is_empty() {
            return Err(format!(
                "no ownership rule covers: {}",
                self.unclassified.join(", ")
            ));
        }
        let stale: Vec<&str> = self
            .returns
            .iter()
            .chain(&self.outputs)
            .chain(&self.adopts)
            .map(|matcher| matcher.id)
            .filter(|id| !self.used.contains(id))
            .collect();
        if !stale.is_empty() {
            return Err(format!(
                "ownership rules match nothing: {}",
                stale.join(", ")
            ));
        }
        Ok(())
    }
}

struct Matcher<'a> {
    id: &'a str,
    names: &'a [String],
    name: Option<Regex>,
    returns: Option<Regex>,
}

impl Matcher<'_> {
    fn matches(&self, name: &str, return_type: &str) -> bool {
        if self.names.iter().any(|listed| listed == name) {
            return true;
        }
        if self.name.is_none() && self.returns.is_none() {
            return false;
        }
        self.name.as_ref().is_none_or(|regex| regex.is_match(name))
            && self
                .returns
                .as_ref()
                .is_none_or(|regex| regex.is_match(return_type))
    }
}

fn compile<'a, T>(
    rules: &'a [T],
    parts: impl Fn(&'a T) -> (&'a String, &'a Selector, &'a String),
) -> Result<Vec<Matcher<'a>>, String> {
    let mut ids = BTreeSet::new();
    rules
        .iter()
        .map(|rule| {
            let (id, selector, rationale) = parts(rule);
            if !ids.insert(id.as_str()) {
                return Err(format!("ownership rule {id} is defined twice"));
            }
            if rationale.trim().is_empty() {
                return Err(format!("ownership rule {id} gives no rationale"));
            }
            let regex = |pattern: &Option<String>| {
                pattern
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|error| format!("ownership rule {id}: {error}"))
            };
            let matcher = Matcher {
                id,
                names: &selector.names,
                name: regex(&selector.name_regex)?,
                returns: regex(&selector.returns_regex)?,
            };
            if matcher.names.is_empty() && matcher.name.is_none() && matcher.returns.is_none() {
                return Err(format!("ownership rule {id} selects nothing"));
            }
            Ok(matcher)
        })
        .collect()
}

/// Replaces the placeholders of a rule's result for one function and checks
/// that what it names exists.
fn resolve(
    returns: &Returns,
    name: &str,
    signature: &Signature,
    releases: &BTreeSet<&str>,
) -> Result<Returns, String> {
    Ok(match returns {
        Returns::Borrowed { owner } => Returns::Borrowed {
            owner: parameter(owner, name, signature)?,
        },
        Returns::Owned { release } => {
            let base = signature
                .return_type
                .trim_start_matches("const ")
                .trim()
                .trim_end_matches("Ptr");
            let release = release.replace("{type}", base);
            if !releases.contains(release.as_str()) {
                return Err(format!(
                    "{name} is released by {release}, which is not exported"
                ));
            }
            Returns::Owned { release }
        }
        other => other.clone(),
    })
}

/// A parameter selector resolved to the parameter's name.
fn parameter(selector: &str, name: &str, signature: &Signature) -> Result<String, String> {
    let found = match selector {
        "$first" => signature.parameters.first(),
        "$last-pointer" => signature
            .parameters
            .iter()
            .rev()
            .find(|parameter| parameter.pointer),
        listed => signature
            .parameters
            .iter()
            .find(|parameter| parameter.name == listed),
    };
    found
        .map(|parameter| parameter.name.clone())
        .ok_or_else(|| format!("{name} has no parameter {selector}"))
}

/// The typedef names that are pointers (to data or to functions).
fn pointer_typedefs(ledger: &[LedgerEntry]) -> BTreeSet<String> {
    ledger
        .iter()
        .filter(|item| item.kind == "typedef")
        .filter(|item| {
            let pointer = Regex::new(&format!(r"\*\s*{}\b", regex::escape(&item.name)))
                .expect("valid typedef pointer regex");
            pointer.is_match(&item.detail) || item.detail.contains("(*")
        })
        .map(|item| item.name.clone())
        .collect()
}

/// Whether a type is a pointer: written with `*`, a pointer typedef of the
/// ledger, or a libxml2 `...Ptr` typedef.
pub(super) fn is_pointer(type_text: &str, pointer_types: &BTreeSet<String>) -> bool {
    let last = type_text.split_whitespace().last().unwrap_or_default();
    type_text.contains('*') || pointer_types.contains(last) || last.ends_with("Ptr")
}

/// Whether a parameter type is a pointer to a writable pointer, by the same
/// pointer test as everything else, so every pointer typedef counts. Only a
/// `const` on the pointee itself makes it read-only: `const xmlChar **` is a
/// writable cursor, `xmlChar * const *` is not.
fn is_output(type_text: &str, pointer_types: &BTreeSet<String>) -> bool {
    let Some(pointee) = type_text.trim_end().strip_suffix('*') else {
        return false;
    };
    let pointee = pointee.trim_end();
    let east_const = pointee
        .strip_suffix("const")
        .is_some_and(|rest| !rest.ends_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_'));
    let west_const =
        !pointee.contains('*') && pointee.split_whitespace().any(|word| word == "const");
    !east_const && !west_const && is_pointer(pointee, pointer_types)
}

/// Splits `<return type> name(<parameters>);` as the ledger normalized it.
pub(super) fn signature(
    name: &str,
    declaration: &str,
    pointer_types: &BTreeSet<String>,
) -> Result<Signature, String> {
    let at = Regex::new(&format!(r"\b{}\s*\(", regex::escape(name)))
        .expect("valid function name regex")
        .find(declaration)
        .ok_or_else(|| format!("{name} is not declared as a function: {declaration}"))?;
    // The export and deprecation markers are macros, not part of the type.
    let return_type = declaration[..at.start()]
        .split_whitespace()
        .filter(|word| !word.starts_with("XMLSEC_"))
        .collect::<Vec<_>>()
        .join(" ");
    let end = closing_parenthesis(&declaration[at.end()..])
        .map(|offset| at.end() + offset)
        .ok_or_else(|| format!("{name} has unbalanced parameters"))?;
    let list = declaration[at.end()..end].trim();
    let mut parameters = Vec::new();
    if list == "void" || list.is_empty() {
        return Ok(Signature {
            return_type,
            parameters,
        });
    }
    let mut depth = 0_usize;
    let mut start = 0;
    for (index, ch) in list
        .char_indices()
        .chain(std::iter::once((list.len(), ',')))
    {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("{name} has unbalanced parameters"))?;
            }
            ',' if depth == 0 => {
                let text = list[start..index].trim();
                start = index + 1;
                if text == "..." {
                    continue;
                }
                let parameter_name = declarator_names(text)
                    .map_err(|error| format!("{name}: {error}"))?
                    .pop()
                    .ok_or_else(|| format!("{name} has an unnamed parameter"))?;
                // Everything but the name is the type; arrays decay to pointers.
                let type_text = text
                    .rsplit_once(parameter_name.as_str())
                    .map_or(text, |(before, _)| before);
                parameters.push(Parameter {
                    pointer: is_pointer(type_text, pointer_types) || text.contains('['),
                    output: is_output(type_text, pointer_types),
                    name: parameter_name,
                });
            }
            _ => {}
        }
    }
    Ok(Signature {
        return_type,
        parameters,
    })
}

/// The offset of the parenthesis closing one already opened before `text`.
fn closing_parenthesis(text: &str) -> Option<usize> {
    let mut depth = 1_usize;
    for (offset, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}
