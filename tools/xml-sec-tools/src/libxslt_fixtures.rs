//! `libxslt-fixtures [--check]`: vendors the complete libxslt 1.1.45 test
//! tree at its pinned commit with a case manifest and a hash of every file;
//! `--check` compares a fresh import with the committed one.

use crate::repo::{Failure, root};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
mod tests;

const PIN: &str = "compatibility/libxslt-1.1.45-donor-commit.txt";
const DESTINATION: &str = "crates/xml-sec-xslt/tests/fixtures/libxslt-1.1.45";
/// The suite directories `runtest.c` registers.
const RUNTEST_SUITES: [&str; 20] = [
    "REC2",
    "REC",
    "general",
    "encoding",
    "documents",
    "numbers",
    "keys",
    "namespaces",
    "extensions",
    "reports",
    "exslt/common",
    "exslt/crypto",
    "exslt/date",
    "exslt/dynamic",
    "exslt/functions",
    "exslt/math",
    "exslt/saxon",
    "exslt/sets",
    "exslt/strings",
    "plugins",
];

/// The corpus README after the line naming the pinned commit.
const README: &str = "It includes the core `runtest.c` suites, REC/REC2, EXSLT, XSLTMark, DocBook,
multiple-output, XInclude, xmlspec, fuzz inputs, dependencies, and golden files.

`cases.tsv` is generated from the suite directories registered by `runtest.c`.
`files.sha256` accounts for every upstream file and makes accidental corpus
truncation or fixture rewriting visible in CI. The original MIT license is in
`LICENSE`.
";

const FIRST_NAMES: [&str; 10] = [
    "Al", "Bob", "Charles", "David", "Egon", "Farbood", "George", "Hank", "Inki", "James",
];
const LAST_NAMES: [&str; 10] = [
    "Aranow",
    "Barker",
    "Corsetti",
    "Dershowitz",
    "Engleman",
    "Franklin",
    "Grice",
    "Haverford",
    "Ilvedson",
    "Jones",
];
const STATES: [&str; 50] = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS",
    "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY",
    "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY",
];

/// The `XSLTMark` database of `size` rows, as upstream `dbgen.pl` writes it
/// (its integer `%` and `%d` truncate the divisions).
pub(crate) fn database(size: usize) -> String {
    let mut text = String::from("<?xml version=\"1.0\"?>\n\n<table>\n");
    for row in 0..size {
        let fields = [
            ("id", format!("{row:04}")),
            ("firstname", FIRST_NAMES[row % 10].to_owned()),
            ("lastname", LAST_NAMES[(row / 10) % 10].to_owned()),
            ("street", format!("{} Any St.", row % 100 + 1)),
            ("city", "Anytown".to_owned()),
            ("state", STATES[(row / 100) % 50].to_owned()),
            ("zip", (22000 + row / 5000).to_string()),
        ];
        text.push_str("  <row>\n");
        for (name, value) in fields {
            text.push_str("    <");
            text.push_str(name);
            text.push('>');
            text.push_str(&value);
            text.push_str("</");
            text.push_str(name);
            text.push_str(">\n");
        }
        text.push_str("  </row>\n");
    }
    text.push_str("</table>\n");
    text
}

/// The `XSLTMark` stylesheet and source of one committed output, as its
/// Makefile pairs them.
pub(crate) fn xsltmark_pair(name: &str) -> (String, String) {
    let source = match name {
        "alphabetize" | "avts" | "creation" | "dbtail" | "decoy" | "encrypt" | "functions"
        | "patterns" | "prettyprint" => "db100.xml".to_owned(),
        "identity" | "stringsort" => "db1000.xml".to_owned(),
        "dbonerow" => "db10000.xml".to_owned(),
        "attsets" | "chart" | "total" => "chart.xml".to_owned(),
        "backwards" | "game" => "game.xml".to_owned(),
        "reverser" => "gettysburg.xml".to_owned(),
        "summarize" => "queens.xsl".to_owned(),
        "xslbench2" | "xslbench3" => "xslbenchdream.xml".to_owned(),
        _ => format!("{name}.xml"),
    };
    let stylesheet = if matches!(name, "breadth" | "depth") {
        "find.xsl".to_owned()
    } else {
        format!("{name}.xsl")
    };
    (stylesheet, source)
}

/// The stems of regular files directly in `directory` named
/// `{prefix}{stem}{suffix}`, in byte order of their names.
fn listed(directory: &Path, prefix: &str, suffix: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let regular = entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file();
        let matched = name.starts_with(prefix) && name.strip_suffix(suffix).is_some();
        if regular && matched {
            names.push(name);
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| name[..name.len() - suffix.len()].to_owned())
        .collect())
}

/// One `cases.tsv` row.
fn row(columns: [&str; 6]) -> String {
    columns.join("\t") + "\n"
}

/// `{stem}{suffix}` when that file exists below `tests`, else empty.
fn optional(tests: &Path, stem: &str, suffix: &str) -> String {
    let path = format!("{stem}{suffix}");
    if tests.join(&path).is_file() {
        path
    } else {
        String::new()
    }
}

/// The cases of the suite directories and standalone documents `runtest.c` runs.
fn runtest_rows(tests: &Path, text: &mut String) -> Result<(), String> {
    for suite in RUNTEST_SUITES {
        let directory = tests.join(suite);
        if !directory.is_dir() {
            continue;
        }
        for name in listed(&directory, "", ".xsl")? {
            let stem = format!("{suite}/{name}");
            if !tests.join(format!("{stem}.xml")).is_file() {
                continue;
            }
            text.push_str(&row([
                "runtest",
                &format!("{stem}.xsl"),
                &format!("{stem}.xml"),
                &optional(tests, &stem, ".out"),
                &optional(tests, &stem, ".err"),
                "transform",
            ]));
        }
    }
    // runtest.c runs standalone stylesheet documents separately: the XML file is
    // both stylesheet and source, and its xml-stylesheet PI resolves the module.
    for name in listed(&tests.join("REC"), "stand", ".xml")? {
        let stem = format!("REC/{name}");
        let document = format!("{stem}.xml");
        text.push_str(&row([
            "runtest-standalone",
            &document,
            &document,
            &optional(tests, &stem, ".stand.out"),
            &optional(tests, &stem, ".stand.err"),
            "standalone",
        ]));
    }
    Ok(())
}

/// The case manifest of a donor `tests` tree.
pub(crate) fn manifest(tests: &Path) -> Result<String, String> {
    let mut text = row(["suite", "stylesheet", "source", "output", "errors", "kind"]);
    runtest_rows(tests, &mut text)?;
    for name in listed(&tests.join("XSLTMark"), "", ".out")? {
        let name = name.as_str();
        let (stylesheet, source) = xsltmark_pair(name);
        text.push_str(&row([
            "xsltmark",
            &format!("XSLTMark/{stylesheet}"),
            &format!("XSLTMark/{source}"),
            &format!("XSLTMark/{name}.out"),
            "",
            "transform",
        ]));
    }
    // DocBook runs each source document through the HTML, XHTML and FO roots.
    for name in listed(&tests.join("docbook/test"), "", ".xml")? {
        for format in ["html", "xhtml", "fo"] {
            let output = format!("docbook/result/{format}/{name}.{format}");
            if tests.join(&output).is_file() {
                text.push_str(&row([
                    "docbook",
                    &format!("docbook/{format}/docbook.xsl"),
                    &format!("docbook/test/{name}.xml"),
                    &output,
                    "",
                    "transform",
                ]));
            }
        }
    }
    for columns in [
        [
            "multiple",
            "multiple/dict.xsl",
            "multiple/dict.xml",
            "multiple/result.xml",
            "",
            "multiple-output",
        ],
        [
            "xinclude",
            "xinclude/e.xsl",
            "xinclude/e.xml",
            "xinclude/normal.out",
            "",
            "transform",
        ],
        [
            "xinclude",
            "xinclude/e.xsl",
            "xinclude/e.xml",
            "xinclude/xinclude.out",
            "",
            "xinclude",
        ],
        [
            "xmlspec",
            "xmlspec/REC-xml-2e.xsl",
            "xmlspec/REC-xml-20001006.xml",
            "xmlspec/REC-xml-20001006.html",
            "",
            "transform",
        ],
        [
            "xmlspec",
            "xmlspec/REC-xml-2e.xsl",
            "xmlspec/REC-xml-20001006.xml",
            "xmlspec/REC-xml-20001006-review.html",
            "",
            "xmlspec-review",
        ],
    ] {
        text.push_str(&row(columns));
    }
    Ok(text)
}

/// Every regular file below `directory`, keyed by its `/`-separated path
/// relative to `base`. Links are refused: the corpus holds bytes only.
pub(crate) fn files(
    directory: &Path,
    base: &Path,
    into: &mut BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            files(&path, base, into)?;
        } else if kind.is_file() {
            let relative = path.strip_prefix(base).map_err(|error| error.to_string())?;
            let key = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            into.insert(key, path);
        } else {
            return Err(format!("unexpected non-regular file: {}", path.display()));
        }
    }
    Ok(())
}

/// The pinned donor `tests` tree and `Copyright`, unpacked from Git objects
/// rather than the worktree, whose ignored build outputs are not upstream source.
fn archive(source: &Path, commit: &str, into: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(source)
        .args(["archive", "--format=tar", commit, "tests", "Copyright"])
        // The pinned object must resolve directly, never through replacement refs.
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .output()
        .map_err(|error| format!("git archive: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git archive failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    tar::Archive::new(output.stdout.as_slice())
        .unpack(into)
        .map_err(|error| format!("unpack libxslt tests: {error}"))
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::copy(from, to)
        .map(drop)
        .map_err(|error| format!("copy {}: {error}", from.display()))
}

/// Builds the complete vendored corpus in `stage`.
fn stage_corpus(donor: &Path, commit: &str, stage: &Path) -> Result<(), String> {
    let mut donor_files = BTreeMap::new();
    files(&donor.join("tests"), donor, &mut donor_files)?;
    for (relative, path) in &donor_files {
        copy(path, &stage.join("upstream").join(relative))?;
    }
    copy(&donor.join("Copyright"), &stage.join("LICENSE"))?;
    let tests = stage.join("upstream/tests");
    // XSLTMark's Makefile drives every committed output; its three databases
    // come from its own deterministic generator.
    for size in [100, 1000, 10000] {
        std::fs::write(tests.join(format!("XSLTMark/db{size}.xml")), database(size))
            .map_err(|error| error.to_string())?;
    }
    std::fs::write(stage.join("cases.tsv"), manifest(&donor.join("tests"))?)
        .map_err(|error| error.to_string())?;
    let mut vendored = BTreeMap::new();
    files(&tests, &stage.join("upstream"), &mut vendored)?;
    let mut sums = String::new();
    for (relative, path) in &vendored {
        let data = std::fs::read(path).map_err(|error| error.to_string())?;
        sums.push_str(&crate::security_corpus::sha256(&data));
        sums.push_str("  ");
        sums.push_str(relative);
        sums.push('\n');
    }
    std::fs::write(stage.join("files.sha256"), sums).map_err(|error| error.to_string())?;
    let readme = format!(
        "# libxslt 1.1.45 oracle corpus\n\n`upstream/tests` is the complete test tree from libxslt 1.1.45 commit\n`{commit}`, not a curated fixture subset.\n{README}"
    );
    std::fs::write(stage.join("README.md"), readme).map_err(|error| error.to_string())
}

/// Paths that differ between two trees, each with its reason.
pub(crate) fn differences(expected: &Path, actual: &Path) -> Result<Vec<String>, String> {
    let (mut left, mut right) = (BTreeMap::new(), BTreeMap::new());
    files(expected, expected, &mut left)?;
    files(actual, actual, &mut right)?;
    let mut found = Vec::new();
    for (relative, path) in &left {
        match right.get(relative) {
            None => found.push(format!("only in {}: {relative}", expected.display())),
            Some(other) => {
                let read = |path: &Path| std::fs::read(path).map_err(|error| error.to_string());
                if read(path)? != read(other)? {
                    found.push(format!("differs: {relative}"));
                }
            }
        }
    }
    found.extend(
        right
            .keys()
            .filter(|relative| !left.contains_key(*relative))
            .map(|relative| format!("only in {}: {relative}", actual.display())),
    );
    Ok(found)
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let check = match args.as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => return Err("usage: libxslt-fixtures [--check]".into()),
    };
    let refuse = |message: &str| Failure {
        code: 2,
        message: message.into(),
    };
    let source = std::env::var_os("LIBXSLT_SOURCE_DIR")
        .filter(|source| !source.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| refuse("LIBXSLT_SOURCE_DIR must point to a libxslt checkout"))?;
    let head = Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["rev-parse", "HEAD"])
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .output()
        .map_err(|error| format!("git: {error}"))?;
    if !head.status.success() {
        return Err(refuse(
            "LIBXSLT_SOURCE_DIR must point to a libxslt checkout",
        ));
    }
    let pin = root().join(PIN);
    let commit =
        std::fs::read_to_string(&pin).map_err(|error| format!("{}: {error}", pin.display()))?;
    let commit = commit.trim();
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{PIN} does not hold a commit").into());
    }
    if String::from_utf8_lossy(&head.stdout).trim() != commit {
        return Err(refuse(&format!(
            "libxslt checkout must be at pinned commit {commit}"
        )));
    }
    let donor = tempfile::tempdir().map_err(|error| error.to_string())?;
    let stage = tempfile::tempdir().map_err(|error| error.to_string())?;
    archive(&source, commit, donor.path())?;
    stage_corpus(donor.path(), commit, stage.path())?;
    let destination = root().join(DESTINATION);
    if check {
        let found = differences(&destination, stage.path())?;
        if found.is_empty() {
            return Ok(());
        }
        return Err(found.join("\n").into());
    }
    if destination.exists() {
        std::fs::remove_dir_all(&destination).map_err(|error| error.to_string())?;
    }
    let mut staged = BTreeMap::new();
    files(stage.path(), stage.path(), &mut staged)?;
    for (relative, path) in &staged {
        copy(path, &destination.join(relative))?;
    }
    Ok(())
}
