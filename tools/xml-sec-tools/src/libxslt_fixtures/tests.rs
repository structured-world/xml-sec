use super::{DESTINATION, database, differences, manifest, xsltmark_pair};
use crate::repo::root;

#[test]
fn the_generated_databases_match_upstream_dbgen_output() {
    // The committed databases were written by upstream dbgen.pl; any drift in
    // the port changes the XSLTMark inputs.
    let directory = root().join(DESTINATION).join("upstream/tests/XSLTMark");
    for size in [100, 1000, 10000] {
        let committed = std::fs::read_to_string(directory.join(format!("db{size}.xml"))).unwrap();
        assert_eq!(database(size), committed, "db{size}.xml");
    }
}

#[test]
fn the_manifest_of_the_vendored_tree_is_the_committed_one() {
    // The case list is derived from the donor tree alone, so regenerating it
    // from the vendored copy must reproduce it byte for byte.
    let corpus = root().join(DESTINATION);
    let committed = std::fs::read_to_string(corpus.join("cases.tsv")).unwrap();
    assert_eq!(manifest(&corpus.join("upstream/tests")).unwrap(), committed);
}

#[test]
fn xsltmark_outputs_use_the_makefile_inputs() {
    // Shared databases and renamed stylesheets follow XSLTMark's Makefile.
    assert_eq!(
        xsltmark_pair("dbonerow"),
        ("dbonerow.xsl".into(), "db10000.xml".into())
    );
    assert_eq!(
        xsltmark_pair("depth"),
        ("find.xsl".into(), "depth.xml".into())
    );
    assert_eq!(
        xsltmark_pair("summarize"),
        ("summarize.xsl".into(), "queens.xsl".into())
    );
    assert_eq!(
        xsltmark_pair("bottles"),
        ("bottles.xsl".into(), "bottles.xml".into())
    );
}

#[test]
fn a_check_names_missing_extra_and_changed_files() {
    // Truncation and rewriting of the vendored corpus are both visible.
    let directory = tempfile::tempdir().unwrap();
    let (expected, actual) = (
        directory.path().join("expected"),
        directory.path().join("actual"),
    );
    for tree in [&expected, &actual] {
        std::fs::create_dir_all(tree.join("tests")).unwrap();
        std::fs::write(tree.join("tests/same.xsl"), "same").unwrap();
    }
    assert_eq!(
        differences(&expected, &actual).unwrap(),
        Vec::<String>::new()
    );
    std::fs::write(expected.join("tests/gone.xsl"), "x").unwrap();
    std::fs::write(actual.join("tests/new.xsl"), "x").unwrap();
    std::fs::write(actual.join("tests/same.xsl"), "changed").unwrap();
    let found = differences(&expected, &actual).unwrap();
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(
        found.contains(&"differs: tests/same.xsl".to_owned()),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line.ends_with(": tests/gone.xsl")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line.ends_with(": tests/new.xsl")),
        "{found:?}"
    );
}
