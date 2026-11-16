use super::{CORPUS, SCHEMA, corpus, fetch, imports, relocate, resolve, validate};
use crate::repo::{Run, Step, root};
use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

/// A publisher serving fixed schemas by URL, recording every command it runs.
struct Publisher {
    schemas: BTreeMap<&'static str, &'static str>,
    commands: Vec<Vec<String>>,
}

impl Run for Publisher {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        self.commands.push(step.args.clone());
        if step.program != "curl" {
            return Ok(ExitStatus::from_raw(0));
        }
        let output = step
            .args
            .iter()
            .skip_while(|arg| *arg != "-o")
            .nth(1)
            .unwrap();
        let url = step.args.iter().rev().nth(2).unwrap();
        let Some(body) = self.schemas.get(url.as_str()) else {
            return Ok(ExitStatus::from_raw(22 << 8));
        };
        std::fs::write(output, body).unwrap();
        Ok(ExitStatus::from_raw(0))
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected query: {}", step.label))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected query: {}", step.label))
    }
}

const DCC: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="https://ptb.de/dcc">
  <xs:import namespace="https://ptb.de/si" schemaLocation="https://example.invalid/si/SI.xsd"/>
  <xs:import namespace="http://www.w3.org/2000/09/xmldsig#" schemaLocation='https://example.invalid/d-sig/xmldsig.xsd'/>
</xs:schema>"#;
const SI: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="https://ptb.de/si">
  <xs:import namespace="http://qudt.org/vocab/" schemaLocation="qudt/quantitykind.xsd"/>
</xs:schema>"#;
const QUDT: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#;
const DSIG: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#;

fn publisher() -> Publisher {
    Publisher {
        schemas: BTreeMap::from([
            ("https://example.invalid/dcc.xsd", DCC),
            ("https://example.invalid/si/SI.xsd", SI),
            ("https://example.invalid/si/qudt/quantitykind.xsd", QUDT),
            ("https://example.invalid/d-sig/xmldsig.xsd", DSIG),
        ]),
        commands: Vec::new(),
    }
}

#[test]
fn imports_lists_import_and_include_locations() {
    // Only schema composition elements name further schemas to read.
    let xsd = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
      <xs:import namespace="urn:a" schemaLocation="a.xsd"/>
      <xs:include schemaLocation="b.xsd"/>
      <xs:import namespace="urn:c"/>
      <xs:element name="import"/>
    </xs:schema>"#;
    assert_eq!(imports(xsd).unwrap(), ["a.xsd", "b.xsd"]);
    assert!(imports("<unclosed").is_err());
}

#[test]
fn relative_locations_resolve_against_the_importing_schema() {
    // XSD 1.0 Part 1 section 4.2.3: schemaLocation is a URI reference read
    // against the base URI of the importing schema.
    assert_eq!(
        resolve(
            "https://www.ptb.de/si/v2.2.1/SI_Format.xsd",
            "qudt/quantitykind.xsd"
        ),
        "https://www.ptb.de/si/v2.2.1/qudt/quantitykind.xsd"
    );
    assert_eq!(
        resolve("https://www.ptb.de/dcc/dcc.xsd", "https://ptb.de/si/SI.xsd"),
        "https://ptb.de/si/SI.xsd"
    );
}

#[test]
fn relocate_rewrites_only_the_quoted_attribute() {
    // Both XML quote styles are rewritten; an unwritten location is an error
    // rather than a schema left pointing at the network.
    assert_eq!(
        relocate(r#"<i schemaLocation="u"/>"#, "u", "l.xsd").unwrap(),
        r#"<i schemaLocation="l.xsd"/>"#
    );
    assert_eq!(
        relocate("<i schemaLocation='u'/>", "u", "l.xsd").unwrap(),
        "<i schemaLocation='l.xsd'/>"
    );
    assert!(relocate(r#"<i schemaLocation = "u"/>"#, "u", "l.xsd").is_err());
}

#[test]
fn fetch_reads_every_imported_schema_and_points_at_local_copies() {
    // The validator must never reach the network: each local schema names the
    // local copies of its imports, including relative and transitive ones.
    let directory = tempfile::tempdir().unwrap();
    let mut publisher = publisher();
    let entry = fetch(
        &mut publisher,
        "https://example.invalid/dcc.xsd",
        directory.path(),
    )
    .unwrap();
    assert_eq!(publisher.commands.len(), 4);
    let entry = std::fs::read_to_string(entry).unwrap();
    assert!(!entry.contains("example.invalid"), "{entry}");
    for location in imports(&entry).unwrap() {
        let imported = std::fs::read_to_string(directory.path().join(location)).unwrap();
        for nested in imports(&imported).unwrap() {
            assert!(directory.path().join(nested).exists());
        }
    }
}

#[test]
fn an_unavailable_schema_fails_the_check() {
    // A schema PTB no longer serves is a failure, not a silent skip.
    let directory = tempfile::tempdir().unwrap();
    let mut publisher = publisher();
    publisher
        .schemas
        .remove("https://example.invalid/si/qudt/quantitykind.xsd");
    assert!(
        fetch(
            &mut publisher,
            "https://example.invalid/dcc.xsd",
            directory.path()
        )
        .is_err()
    );
}

#[test]
fn validation_covers_every_committed_corpus_document_offline() {
    // xmllint runs without network access over the whole corpus.
    let documents = corpus(&root().join(CORPUS)).unwrap();
    assert!(documents.len() >= 2, "{documents:?}");
    let mut publisher = publisher();
    validate(
        &mut publisher,
        std::path::Path::new("schema-0.xsd"),
        &documents,
    )
    .unwrap();
    let [command] = publisher.commands.as_slice() else {
        panic!("one validation command expected");
    };
    assert_eq!(
        command[..4],
        ["--nonet", "--noout", "--schema", "schema-0.xsd"]
    );
    assert_eq!(command.len(), 4 + documents.len());
    assert!(SCHEMA.starts_with("https://www.ptb.de/dcc/"));
}
