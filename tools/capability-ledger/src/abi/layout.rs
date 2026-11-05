//! Public struct layouts, enumerator values and the data model, measured by a
//! C probe compiled against the installed headers with the build's own flags,
//! so preprocessor-dependent members appear exactly as consumers see them.

use super::LedgerEntry;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

static FUNCTION_POINTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)").expect("valid function pointer regex")
});
static TRAILING_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)*$").expect("valid declarator regex")
});
static ENUMERATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=.*)?$").expect("valid enumerator regex")
});

#[derive(Serialize)]
pub(super) struct DataModel {
    pointer: u64,
    long: u64,
    size_t: u64,
    time_t: u64,
}

#[derive(Serialize)]
pub(super) struct Struct {
    pub(super) name: String,
    size: u64,
    align: u64,
    fields: Vec<Field>,
}

#[derive(Serialize)]
struct Field {
    name: String,
    offset: u64,
    size: u64,
}

#[derive(Serialize)]
pub(super) struct Enum {
    pub(super) name: String,
    values: Vec<Enumerator>,
}

#[derive(Serialize)]
struct Enumerator {
    name: String,
    value: i64,
}

pub(super) struct Probe {
    pub(super) data_model: DataModel,
    pub(super) structs: Vec<Struct>,
    pub(super) enums: Vec<Enum>,
}

/// One line of a struct or enum body as the probe repeats it: a member name,
/// or a preprocessor directive kept so the probe sees the same members.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Member {
    Directive(String),
    Name(String),
}

/// A struct tag or enum typedef name with its body.
pub(super) struct Body {
    pub(super) name: String,
    pub(super) members: Vec<Member>,
}

pub(super) fn measure(
    prefix: &Path,
    cflags: &[String],
    ledger: &[LedgerEntry],
) -> Result<Probe, String> {
    let include = prefix.join("include/xmlsec1/xmlsec");
    let headers = generic_headers(&include)?;
    let mut structs = Vec::new();
    let mut enums = Vec::new();
    for item in ledger {
        let parse = match item.kind.as_str() {
            "struct-layout" => struct_members,
            "enum" => enum_members,
            _ => continue,
        };
        let text = installed_header(&include, &item.source)?;
        let members =
            parse(&text, &item.name).map_err(|error| format!("{}: {error}", item.source))?;
        let body = Body {
            name: item.name.clone(),
            members,
        };
        if item.kind == "enum" {
            enums.push(body);
        } else {
            structs.push(body);
        }
    }
    let work = tempfile::tempdir().map_err(|error| error.to_string())?;
    let source = work.path().join("probe.c");
    let executable = work.path().join("probe");
    fs::write(&source, probe_source(&headers, &structs, &enums))
        .map_err(|error| format!("write {}: {error}", source.display()))?;
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    report_compiler(&compiler)?;
    let build = Command::new(&compiler)
        .args(cflags)
        .arg("-o")
        .arg(&executable)
        .arg(&source)
        .output()
        .map_err(|error| format!("run {compiler}: {error}"))?;
    if !build.status.success() {
        return Err(format!(
            "the layout probe does not compile: {}",
            String::from_utf8_lossy(&build.stderr)
        ));
    }
    let run = Command::new(&executable)
        .output()
        .map_err(|error| format!("run the layout probe: {error}"))?;
    if !run.status.success() {
        return Err(format!("the layout probe failed: {}", run.status));
    }
    let output = String::from_utf8(run.stdout).map_err(|_| "the probe printed non-UTF-8")?;
    parse_output(&output, &structs, &enums)
}

/// The toolchain is not part of the baseline; the run states which one measured it.
fn report_compiler(compiler: &str) -> Result<(), String> {
    let version = Command::new(compiler)
        .arg("--version")
        .output()
        .map_err(|error| format!("run {compiler} --version: {error}"))?;
    let text = String::from_utf8_lossy(&version.stdout);
    println!(
        "layout probe compiler: {}",
        text.lines().next().unwrap_or("unknown")
    );
    Ok(())
}

/// The generic public headers, in a stable order.
fn generic_headers(include: &Path) -> Result<Vec<String>, String> {
    let entries =
        fs::read_dir(include).map_err(|error| format!("read {}: {error}", include.display()))?;
    let mut headers = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        // C include names are case-sensitive, so the extension is too.
        if path.extension().is_some_and(|extension| extension == "h") && path.is_file() {
            headers.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    headers.sort();
    if headers.is_empty() {
        return Err(format!("no headers in {}", include.display()));
    }
    Ok(headers)
}

/// The installed copy of a ledger header (`include/xmlsec/<name>`).
fn installed_header(include: &Path, source: &str) -> Result<String, String> {
    let relative = source
        .strip_prefix("include/xmlsec/")
        .ok_or_else(|| format!("{source} is not a public header"))?;
    let path: PathBuf = include.join(relative);
    fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))
}

/// The members of `struct <tag> { ... }` in declaration order.
pub(super) fn struct_members(header: &str, tag: &str) -> Result<Vec<Member>, String> {
    let clean = super::super::sanitize_c(header);
    let start = Regex::new(&format!(r"\bstruct\s+{}\s*\{{", regex::escape(tag)))
        .expect("valid struct regex");
    let found = start
        .find(&clean)
        .ok_or_else(|| format!("no definition of struct {tag}"))?;
    let body =
        braced_body(&clean, found.end()).map_err(|error| format!("struct {tag}: {error}"))?;
    members(body, ';', declarator_names, false).map_err(|error| format!("struct {tag}: {error}"))
}

/// The enumerators of `typedef enum { ... } <name>;` in declaration order.
pub(super) fn enum_members(header: &str, name: &str) -> Result<Vec<Member>, String> {
    let clean = super::super::sanitize_c(header);
    let end = Regex::new(&format!(r"\}}\s*{}\s*;", regex::escape(name)))
        .expect("valid enum regex")
        .find(&clean)
        .ok_or_else(|| format!("no definition of enum {name}"))?;
    let before = &clean[..end.start()];
    let declaration = before
        .rfind("typedef enum")
        .ok_or_else(|| format!("enum {name} has no typedef enum"))?;
    let open = before[declaration..]
        .find('{')
        .map(|offset| declaration + offset + 1)
        .ok_or_else(|| format!("enum {name} has no body"))?;
    let body = &clean[open..end.start()];
    if body.contains('{') || body.contains('}') {
        return Err(format!("enum {name} body is not a plain enumerator list"));
    }
    members(body, ',', enumerator_name, true).map_err(|error| format!("enum {name}: {error}"))
}

/// The text from `start` up to the brace closing the one just before it.
fn braced_body(text: &str, start: usize) -> Result<&str, String> {
    let mut depth = 1_usize;
    for (offset, ch) in text[start..].char_indices() {
        match ch {
            '{' => return Err("nested definitions are not supported".into()),
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&text[start..start + offset]);
                }
            }
            _ => {}
        }
    }
    Err("unterminated body".into())
}

/// Splits a body into members at `separator`, keeping directive lines. A final
/// member without a separator is allowed only where C allows it (enums).
fn members(
    body: &str,
    separator: char,
    names: fn(&str) -> Result<Vec<String>, String>,
    trailing_allowed: bool,
) -> Result<Vec<Member>, String> {
    let mut result = Vec::new();
    let mut pending = String::new();
    let mut depth = 0_usize;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            if !pending.trim().is_empty() {
                // The last enumerator of a conditional branch needs no comma.
                if !trailing_allowed || depth != 0 {
                    return Err(format!("directive inside a member: {trimmed}"));
                }
                result.extend(names(&pending)?.into_iter().map(Member::Name));
                pending.clear();
            }
            result.push(Member::Directive(trimmed.to_owned()));
            continue;
        }
        for ch in line.chars() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| format!("unbalanced {ch}"))?;
                }
                _ => {}
            }
            if ch == separator && depth == 0 {
                result.extend(names(&pending)?.into_iter().map(Member::Name));
                pending.clear();
            } else {
                pending.push(ch);
            }
        }
        pending.push('\n');
    }
    if !pending.trim().is_empty() {
        if !trailing_allowed {
            return Err(format!("member without a terminator: {}", pending.trim()));
        }
        result.extend(names(&pending)?.into_iter().map(Member::Name));
    }
    Ok(result)
}

/// The names a struct member declaration declares.
pub(super) fn declarator_names(statement: &str) -> Result<Vec<String>, String> {
    let statement = statement.trim();
    if let Some(capture) = FUNCTION_POINTER.captures(statement) {
        return Ok(vec![capture[1].to_owned()]);
    }
    let mut names = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    for (index, ch) in statement
        .char_indices()
        .chain(std::iter::once((statement.len(), ',')))
    {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unbalanced {ch} in `{statement}`"))?;
            }
            ',' if depth == 0 => {
                let declarator = statement[start..index].trim();
                let capture = TRAILING_IDENTIFIER
                    .captures(declarator)
                    .ok_or_else(|| format!("no member name in `{statement}`"))?;
                names.push(capture[1].to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    Ok(names)
}

fn enumerator_name(piece: &str) -> Result<Vec<String>, String> {
    if piece.trim().is_empty() {
        return Err("empty enumerator".into());
    }
    let capture = ENUMERATOR
        .captures(piece)
        .ok_or_else(|| format!("no enumerator name in `{}`", piece.trim()))?;
    Ok(vec![capture[1].to_owned()])
}

pub(super) fn probe_source(headers: &[String], structs: &[Body], enums: &[Body]) -> String {
    let mut source = String::from(
        "/* Generated by xml-sec-capability-ledger abi-generate. */\n\
         /* Crypto backends see the private declarations; so does the probe. */\n\
         #define XMLSEC_PRIVATE 1\n\
         #include <stddef.h>\n#include <stdio.h>\n#include <time.h>\n",
    );
    for header in headers {
        writeln!(source, "#include <xmlsec/{header}>").expect("writing to a String");
    }
    source.push_str(
        "#define LAYOUT_STRUCT(tag) printf(\"S %s %zu %zu\\n\", #tag, sizeof(struct tag), _Alignof(struct tag))\n\
         #define LAYOUT_FIELD(tag, field) printf(\"F %s %s %zu %zu\\n\", #tag, #field, offsetof(struct tag, field), sizeof(((struct tag *)0)->field))\n\
         #define LAYOUT_VALUE(name, value) printf(\"E %s %s %lld\\n\", #name, #value, (long long)(value))\n\
         int main(void) {\n\
         printf(\"D pointer %zu\\n\", sizeof(void *));\n\
         printf(\"D long %zu\\n\", sizeof(long));\n\
         printf(\"D size_t %zu\\n\", sizeof(size_t));\n\
         printf(\"D time_t %zu\\n\", sizeof(time_t));\n",
    );
    for body in structs {
        writeln!(source, "LAYOUT_STRUCT({});", body.name).expect("writing to a String");
        for member in &body.members {
            match member {
                Member::Directive(directive) => writeln!(source, "{directive}"),
                Member::Name(field) => writeln!(source, "LAYOUT_FIELD({}, {field});", body.name),
            }
            .expect("writing to a String");
        }
    }
    for body in enums {
        for member in &body.members {
            match member {
                Member::Directive(directive) => writeln!(source, "{directive}"),
                Member::Name(value) => writeln!(source, "LAYOUT_VALUE({}, {value});", body.name),
            }
            .expect("writing to a String");
        }
    }
    source.push_str("return 0;\n}\n");
    source
}

/// Reads the probe's lines back. Every struct and enum the probe was asked for
/// must be reported; any other line is an error.
pub(super) fn parse_output(
    output: &str,
    structs: &[Body],
    enums: &[Body],
) -> Result<Probe, String> {
    let mut model = BTreeMap::new();
    let mut layouts: BTreeMap<&str, Struct> = BTreeMap::new();
    let mut values: BTreeMap<&str, Vec<Enumerator>> = BTreeMap::new();
    let number = |text: &str| -> Result<u64, String> {
        text.parse().map_err(|_| format!("bad probe number {text}"))
    };
    for line in output.lines() {
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["D", name, size] => {
                model.insert((*name).to_owned(), number(size)?);
            }
            ["S", tag, size, align] => {
                let body = structs
                    .iter()
                    .find(|body| body.name == *tag)
                    .ok_or_else(|| format!("probe reported unknown struct {tag}"))?;
                layouts.insert(
                    body.name.as_str(),
                    Struct {
                        name: body.name.clone(),
                        size: number(size)?,
                        align: number(align)?,
                        fields: Vec::new(),
                    },
                );
            }
            ["F", tag, field, offset, size] => {
                let layout = layouts
                    .get_mut(tag)
                    .ok_or_else(|| format!("field {field} before its struct {tag}"))?;
                layout.fields.push(Field {
                    name: (*field).to_owned(),
                    offset: number(offset)?,
                    size: number(size)?,
                });
            }
            ["E", name, value, number] => {
                let body = enums
                    .iter()
                    .find(|body| body.name == *name)
                    .ok_or_else(|| format!("probe reported unknown enum {name}"))?;
                values
                    .entry(body.name.as_str())
                    .or_default()
                    .push(Enumerator {
                        name: (*value).to_owned(),
                        value: number
                            .parse()
                            .map_err(|_| format!("bad enumerator value {number}"))?,
                    });
            }
            _ => return Err(format!("unexpected probe output line `{line}`")),
        }
    }
    let mut data = |name: &str| {
        model
            .remove(name)
            .ok_or_else(|| format!("probe did not report sizeof {name}"))
    };
    let data_model = DataModel {
        pointer: data("pointer")?,
        long: data("long")?,
        size_t: data("size_t")?,
        time_t: data("time_t")?,
    };
    let mut measured = Vec::with_capacity(structs.len());
    for body in structs {
        measured.push(
            layouts
                .remove(body.name.as_str())
                .ok_or_else(|| format!("probe did not measure struct {}", body.name))?,
        );
    }
    let mut enumerated = Vec::with_capacity(enums.len());
    for body in enums {
        enumerated.push(Enum {
            name: body.name.clone(),
            values: values
                .remove(body.name.as_str())
                .ok_or_else(|| format!("probe reported no values of enum {}", body.name))?,
        });
    }
    Ok(Probe {
        data_model,
        structs: measured,
        enums: enumerated,
    })
}
