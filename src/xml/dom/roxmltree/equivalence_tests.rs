//! The arena the roxmltree parser builds directly equals the projection of its
//! backend DOM, node for node.

use std::path::{Path, PathBuf};

use super::*;

fn files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("fixture directory") {
        let path = entry.expect("fixture entry").path();
        if path.is_dir() {
            files(&path, found);
        } else {
            found.push(path);
        }
    }
}

/// Every node, with its range, actionability and subtree, then each element's
/// in-scope namespace bindings.
fn shape(document: &Document<'_>) -> String {
    let mut shape = format!("{document:?}");
    for node in document.root().descendants() {
        for namespace in node.namespaces() {
            shape.push_str(&format!("\n{:?}={}", namespace.name(), namespace.uri()));
        }
        shape.push('|');
    }
    shape
}

fn compare(label: &str, xml: &str, nodes_limit: u32) -> bool {
    let Ok(preflight) = LexicalPreflight::scan(xml, true) else {
        return false;
    };
    let options = ParsingOptions {
        allow_dtd: true,
        nodes_limit,
    };
    let projected = backend::Document::parse_with_options(
        xml,
        backend::ParsingOptions {
            allow_dtd: true,
            nodes_limit,
            entity_resolver: None,
        },
    )
    .map_err(map_error)
    .and_then(|parsed| project(xml, &parsed, &preflight));
    let direct = RoxmltreeBackend::parse(xml, options, &preflight);
    match (projected, direct) {
        (Ok(projected), Ok(direct)) => {
            assert_eq!(shape(&projected), shape(&direct), "{label}");
        }
        (Err(projected), Err(direct)) => {
            assert_eq!(projected.to_string(), direct.to_string(), "{label}");
        }
        (projected, direct) => panic!(
            "{label}: projection {:?}, direct {:?}",
            projected.map(|_| ()),
            direct.map(|_| ())
        ),
    }
    true
}

#[test]
fn direct_population_matches_projection_on_every_fixture() {
    let mut found = Vec::new();
    files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        &mut found,
    );
    let mut compared = 0;
    for path in found {
        let Ok(xml) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !xml.contains('<') {
            continue;
        }
        compared += usize::from(compare(&path.display().to_string(), &xml, u32::MAX));
    }
    assert!(compared > 1000, "only {compared} fixtures compared");
}

#[test]
fn direct_population_matches_projection_on_entities_and_limits() {
    let cases = [
        "<!DOCTYPE r [<!ENTITY e '<a x=\"1\">t&amp;</a>'><!-- c --><?pi v?>]><r>a&e;b&e;<![CDATA[c]]>\r\nd</r>",
        "<!DOCTYPE r [<!ENTITY a 'x&b;y'><!ENTITY b '<i/>'>]><r k='&a;'>&a;</r>",
        "<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED>]><r id=' v  w '><s xml:id=' 1 '/></r>",
        "<p:r xmlns:p='urn:p' xmlns='urn:d'><e xmlns=''><p:f xmlns:p='urn:q' p:a='1' a='2'/></e><g/></p:r>",
        "<?xml version='1.0'?><!-- head --><r>&#x20;&#65;<!--in--><?t d?>x</r><!-- tail -->",
        "<r a='l&#xA;i\tn\r\ne'>\r\n<e/>\r</r>",
    ];
    for (index, xml) in cases.iter().enumerate() {
        assert!(
            compare(&format!("case {index}"), xml, u32::MAX),
            "case {index} scans"
        );
        for nodes_limit in 1..24 {
            compare(
                &format!("case {index} limit {nodes_limit}"),
                xml,
                nodes_limit,
            );
        }
    }
}
