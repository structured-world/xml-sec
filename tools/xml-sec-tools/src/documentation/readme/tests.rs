use super::{Stale, align, documents, execute, requirement};
use std::path::Path;

#[test]
fn the_release_line_is_the_minor_below_one_and_the_major_from_one() {
    // Cargo treats 0.5 and 0.6 as incompatible, so "0" would admit a breaking
    // release; from 1.0 the major is the compatible line.
    assert_eq!(requirement("0.6.0").unwrap(), "0.6");
    assert_eq!(requirement("0.10.3").unwrap(), "0.10");
    assert_eq!(requirement("1.2.3").unwrap(), "1");
    assert_eq!(requirement("2.0.0-rc.1").unwrap(), "2");
    assert!(requirement("7").is_err());
    assert!(requirement("x.6.0").is_err());
}

#[test]
fn a_stale_requirement_is_reported_and_rewritten_in_place() {
    // The README showed 0.4 for a 0.6 release: the reported line is the one a
    // user copies, and only the requirement changes in it.
    let text = "```toml\n\
                xml-sec = { version = \"0.4\", default-features = false, features = [\"xmldsig\"] }\n\
                xml-sec = \"0.4.1\"\n\
                xml-sec = { version = \"0.6\" }\n\
                ```\n";
    let (aligned, stale) = align(text, "0.6");
    assert_eq!(
        stale,
        [
            Stale {
                line: 2,
                found: "0.4".into()
            },
            Stale {
                line: 3,
                found: "0.4.1".into()
            },
        ]
    );
    assert_eq!(
        aligned,
        "```toml\n\
         xml-sec = { version = \"0.6\", default-features = false, features = [\"xmldsig\"] }\n\
         xml-sec = \"0.6\"\n\
         xml-sec = { version = \"0.6\" }\n\
         ```\n"
    );
}

#[test]
fn a_single_quoted_requirement_is_reported_and_keeps_its_quotes() {
    // TOML literal strings are valid in both declaration forms; a stale one
    // must not pass the check, and the rewrite keeps the author's delimiter.
    let text = "xml-sec = '0.4'\n\
                xml-sec = { version = '0.5', features = [\"xmldsig\"] }\n\
                xml-sec = '0.6'\n";
    let (aligned, stale) = align(text, "0.6");
    assert_eq!(
        stale,
        [
            Stale {
                line: 1,
                found: "0.4".into()
            },
            Stale {
                line: 2,
                found: "0.5".into()
            },
        ]
    );
    assert_eq!(
        aligned,
        "xml-sec = '0.6'\n\
         xml-sec = { version = '0.6', features = [\"xmldsig\"] }\n\
         xml-sec = '0.6'\n"
    );
}

#[test]
fn other_packages_and_path_declarations_are_left_alone() {
    // A sibling crate has its own versions, and a path dependency has none.
    let text = "xml-sec-config = \"0.1\"\n\
                xml-sec = { path = \"../..\", features = [\"std\"] }\n\
                cargo add xml-sec\n";
    let (aligned, stale) = align(text, "0.6");
    assert_eq!(stale, []);
    assert_eq!(aligned, text);
}

#[test]
fn the_check_fails_on_drift_and_the_write_fixes_it() {
    // CI must go red on a stale example, and the release branch rewrite must
    // leave nothing for the check to find.
    let base = tempfile::tempdir().unwrap();
    let write = |path: &str, text: &str| {
        let path = base.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write("README.md", "xml-sec = { version = \"0.4\" }\n");
    write("docs/guide/install.md", "xml-sec = \"0.5\"\n");
    write("crates/xml-sec-cli/README.md", "no dependency here\n");
    let error = execute(base.path(), "0.6", false).unwrap_err();
    assert!(
        error.message.contains("README.md:1: xml-sec 0.4"),
        "{}",
        error.message
    );
    assert!(
        error
            .message
            .contains("docs/guide/install.md:1: xml-sec 0.5"),
        "{}",
        error.message
    );
    execute(base.path(), "0.6", true).unwrap();
    execute(base.path(), "0.6", false).unwrap();
    assert_eq!(
        std::fs::read_to_string(base.path().join("docs/guide/install.md")).unwrap(),
        "xml-sec = \"0.6\"\n"
    );
}

#[test]
fn the_documents_are_the_readme_the_guides_and_crate_readmes() {
    // A guide added later is checked without registering it anywhere.
    let base = tempfile::tempdir().unwrap();
    for path in [
        "README.md",
        "docs/a.md",
        "docs/deep/b.md",
        "docs/c.txt",
        "crates/x/README.md",
    ] {
        let path = base.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    std::fs::create_dir_all(base.path().join("crates/y")).unwrap();
    let found: Vec<_> = documents(base.path())
        .unwrap()
        .into_iter()
        .map(|path| path.strip_prefix(base.path()).unwrap().to_path_buf())
        .collect();
    assert_eq!(
        found,
        [
            Path::new("README.md"),
            Path::new("crates/x/README.md"),
            Path::new("docs/a.md"),
            Path::new("docs/deep/b.md"),
        ]
    );
}
