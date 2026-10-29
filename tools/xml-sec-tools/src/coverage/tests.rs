use super::{check, check_file};
use serde_json::{Value, json};

fn report(files: &[&str]) -> Value {
    let files: Vec<Value> = files
        .iter()
        .map(|name| json!({ "filename": name }))
        .collect();
    json!({
        "type": "llvm.coverage.json.export",
        "data": [{ "files": files, "totals": { "lines": { "count": 100, "covered": 85, "percent": 85 } } }],
    })
}

/// Resolves `..` lexically, as a filesystem without links would.
fn resolve(name: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in name.split('/').filter(|part| !part.is_empty()) {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    format!("/{}", parts.join("/"))
}

#[test]
fn coverage_identities_are_unique_physical_sources_not_independently_selected_percentages() {
    // The same embedded source must not contribute two denominators.
    let lexical = |name: &str| Ok(resolve(name));
    assert_eq!(
        check(&report(&["/source.rs"]), lexical).unwrap(),
        json!({ "sources": 1, "count": 100, "covered": 85, "percent": 85 })
    );
    let duplicate = check(&report(&["/source.rs", "/source.rs"]), lexical).unwrap_err();
    assert!(duplicate.starts_with("Duplicate"), "{duplicate}");
    let noncanonical = check(&report(&["/lib/../source.rs"]), lexical).unwrap_err();
    assert!(noncanonical.starts_with("Noncanonical"), "{noncanonical}");
    let mut empty_data = report(&["/source.rs"]);
    empty_data["data"] = json!([]);
    for invalid in [json!({}), report(&[]), empty_data] {
        assert!(check(&invalid, lexical).unwrap_err().contains("nonempty"));
    }
    let mut overcovered = report(&["/source.rs"]);
    overcovered["data"][0]["totals"]["lines"]["covered"] = json!(101);
    assert!(check(&overcovered, lexical).unwrap_err().contains("totals"));
    let mut fractional = report(&["/source.rs"]);
    fractional["data"][0]["totals"]["lines"]["count"] = json!(100.5);
    assert!(check(&fractional, lexical).unwrap_err().contains("totals"));
}

#[test]
fn report_files_are_checked_against_the_physical_filesystem() {
    // A symlinked or duplicated physical source must not pass the real resolver.
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let source = root.join("source.rs");
    std::fs::write(&source, "").unwrap();
    let linked = root.join("linked.rs");
    std::os::unix::fs::symlink(&source, &linked).unwrap();
    let fixture = root.join("report.json");
    let write = |value: &Value| std::fs::write(&fixture, value.to_string()).unwrap();
    let source = source.to_str().unwrap();
    write(&report(&[source]));
    assert_eq!(check_file(&fixture).unwrap()["sources"], 1);
    write(&report(&[source, source]));
    assert!(
        check_file(&fixture)
            .unwrap_err()
            .starts_with("Duplicate coverage source")
    );
    write(&report(&[linked.to_str().unwrap()]));
    assert!(
        check_file(&fixture)
            .unwrap_err()
            .starts_with("Noncanonical coverage source")
    );
    write(&json!({}));
    assert_eq!(
        check_file(&fixture).unwrap_err(),
        "Expected one nonempty LLVM coverage export"
    );
}
