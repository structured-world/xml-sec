//! Embedded XML parser kernels are private implementation details, not
//! external crates. Their Rust documentation examples are preserved as unit
//! tests of that exact source.

use std::fmt::Write as _;
use std::path::Path;

#[cfg(test)]
mod tests;

/// One executable documentation example.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Example {
    /// Line of the opening fence.
    pub(crate) line: usize,
    pub(crate) body: String,
    pub(crate) no_run: bool,
    /// `cfg(...)` attributes of the documented item.
    pub(crate) cfgs: Vec<String>,
}

const EXAMPLE_LABELS: [&str; 5] = [
    "",
    "rust",
    "no_run",
    "text,xml-sec-example",
    "text,xml-sec-example,no_run",
];

/// Splits a documentation comment line into its comment prefix and content.
fn doc_line(line: &str) -> Option<(&str, &str)> {
    let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
    let marker = &line[indent..];
    if !(marker.starts_with("///") || marker.starts_with("//!")) {
        return None;
    }
    let prefix = &line[..indent + 3];
    let rest = &line[indent + 3..];
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
    matches!(&rest[end..], "" | "\n" | "\r" | "\r\n").then(|| (prefix, &rest[..end]))
}

fn is_doc_comment(line: &str) -> bool {
    let line = line.trim_start_matches([' ', '\t']);
    line.starts_with("///") || line.starts_with("//!")
}

/// The `cfg(...)` of a line holding exactly one `#[cfg(...)]` attribute.
fn cfg_attribute(line: &str) -> Option<&str> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let line = line.trim_matches([' ', '\t']);
    let inner = line.strip_prefix("#[")?.strip_suffix(']')?;
    (inner.starts_with("cfg(") && inner.ends_with(')') && !inner.contains(['\r', '\n']))
        .then_some(inner)
}

/// Whether `content` declares `fn main(`, which needs a harness adapter.
fn declares_main(content: &str) -> bool {
    content.match_indices("fn").any(|(at, _)| {
        let boundary = content[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !(before.is_alphanumeric() || before == '_'));
        let rest = &content[at + 2..];
        let after_fn = rest.trim_start();
        boundary
            && after_fn.len() < rest.len()
            && after_fn
                .strip_prefix("main")
                .is_some_and(|tail| tail.trim_start().starts_with('('))
    })
}

/// Rewrites example fences to inert `text` fences and returns the examples.
pub(crate) fn extract(source: &str, file: &str) -> Result<(String, Vec<Example>), String> {
    let (mut fenced, mut example, mut no_run) = (false, false, false);
    let mut rewritten = String::with_capacity(source.len());
    let mut examples: Vec<Example> = Vec::new();
    let mut body: Vec<String> = Vec::new();
    let mut pending: Vec<usize> = Vec::new();
    let mut start = 0;
    for (index, line) in source.split_inclusive('\n').enumerate() {
        let line_number = index + 1;
        // An example exists only where its documented item is compiled, so the
        // item's `cfg` attributes gate the generated test too.
        if !pending.is_empty() && !is_doc_comment(line) {
            if let Some(cfg) = cfg_attribute(line) {
                for &pending_index in &pending {
                    examples[pending_index].cfgs.push(cfg.to_owned());
                }
            } else if !line.trim_start_matches([' ', '\t']).starts_with("#[") {
                pending.clear();
            }
        }
        if let Some((prefix, content)) = doc_line(line) {
            if let Some(label) = content
                .strip_prefix("```")
                .filter(|label| !label.contains('`'))
            {
                if fenced {
                    if !label.is_empty() {
                        return Err(format!(
                            "{file}:{line_number}: unterminated documentation fence"
                        ));
                    }
                    if example {
                        pending.push(examples.len());
                        examples.push(Example {
                            line: start,
                            body: body.join("\n"),
                            no_run,
                            cfgs: Vec::new(),
                        });
                    }
                    (fenced, example) = (false, false);
                } else {
                    fenced = true;
                    example = EXAMPLE_LABELS.contains(&label);
                    no_run = label.contains("no_run");
                    if label.contains("compile_fail") || label.contains("ignore") {
                        return Err(format!(
                            "{file}:{line_number}: unsupported executable example {label}"
                        ));
                    }
                    if example {
                        start = line_number;
                        body.clear();
                        rewritten.push_str(prefix);
                        rewritten.push_str(" ```text,xml-sec-example");
                        if no_run {
                            rewritten.push_str(",no_run");
                        }
                        rewritten.push('\n');
                        continue;
                    }
                }
            } else if fenced && example {
                // rustdoc hides `# ` lines from rendering and unescapes `##`.
                let content = if content.starts_with("# ") || content == "#" {
                    content.strip_prefix("# ").unwrap_or(&content[1..])
                } else {
                    content
                };
                let content = match content.strip_prefix("##") {
                    Some(rest) => format!("#{rest}"),
                    None => content.to_owned(),
                };
                if declares_main(&content) {
                    return Err(format!(
                        "{file}:{line_number}: explicit main needs a harness adapter"
                    ));
                }
                body.push(content);
            }
        } else if fenced {
            return Err(format!(
                "{file}:{line_number}: documentation fence escaped its comment"
            ));
        }
        rewritten.push_str(line);
    }
    if fenced {
        return Err(format!("{file}: unclosed documentation fence"));
    }
    Ok((rewritten, examples))
}

/// Renders the unit tests for the examples of `files`, in order.
pub(crate) fn render(
    backend: &str,
    files: &[(String, Vec<Example>)],
) -> Result<String, std::fmt::Error> {
    let mut tests = String::from(
        "// Generated by `cargo run -p xml-sec-tools -- kernel-examples`; edit the source examples.\n",
    );
    // rustdoc itself permits unused example imports, bindings and mutability.
    tests.push_str("#![allow(unused_imports, unused_variables, unused_mut)]\n");
    for (file, examples) in files {
        let name: String = file
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        for (ordinal, example) in examples.iter().enumerate() {
            let kind = if example.no_run {
                "compile-only"
            } else {
                "runnable"
            };
            write!(
                tests,
                "\n// {file}:{}; original {kind} example.\n",
                example.line
            )?;
            for cfg in &example.cfgs {
                writeln!(tests, "#[{cfg}]")?;
            }
            writeln!(
                tests,
                "#[test]\nfn {name}_example_{}() -> impl std::process::Termination {{",
                ordinal + 1
            )?;
            writeln!(tests, "    use crate::parser_{backend} as {backend};")?;
            if example.no_run {
                tests.push_str("    let _ = || {\n");
            }
            // Leading bytes inside multiline Rust strings are data, not indentation.
            // rustfmt may format tokens afterwards but must see the original bytes.
            tests.push_str(&example.body);
            tests.push('\n');
            tests.push_str(if example.no_run { "    };\n}\n" } else { "}\n" });
        }
    }
    Ok(tests)
}

/// `kernel-examples BACKEND ROOT SOURCE...`: rewrites the example fences of
/// each source under `ROOT` and writes `ROOT/documentation_tests.rs`.
pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let usage = "usage: xml-sec-tools kernel-examples roxmltree|xmloxide ROOT SOURCE...";
    let backend = args.next().ok_or(usage)?;
    let root = args.next().ok_or(usage)?;
    let sources: Vec<String> = args.collect();
    if sources.is_empty() || !matches!(backend.as_str(), "roxmltree" | "xmloxide") {
        return Err(usage.into());
    }
    let root = Path::new(&root);
    let mut files = Vec::with_capacity(sources.len());
    for file in sources {
        let path = root.join(&file);
        let original =
            std::fs::read_to_string(&path).map_err(|error| format!("read {file}: {error}"))?;
        let (rewritten, examples) = extract(&original, &file)?;
        if rewritten != original {
            std::fs::write(&path, rewritten).map_err(|error| format!("write {file}: {error}"))?;
        }
        files.push((file, examples));
    }
    let count: usize = files.iter().map(|(_, examples)| examples.len()).sum();
    let tests = render(&backend, &files).map_err(|error| format!("render examples: {error}"))?;
    std::fs::write(root.join("documentation_tests.rs"), tests)
        .map_err(|error| format!("write examples: {error}"))?;
    println!("Embedded {count} {backend} documentation examples");
    Ok(())
}
