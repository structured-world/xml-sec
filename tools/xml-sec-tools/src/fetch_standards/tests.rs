use super::{Source, execute, sources};
use crate::repo::{Run, Step, root};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

/// A publisher that serves `body` for every URL and records what was fetched.
struct Publisher {
    body: &'static [u8],
    fetched: Vec<String>,
}

impl Run for Publisher {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        let output = step
            .args
            .iter()
            .skip_while(|arg| *arg != "-o")
            .nth(1)
            .unwrap();
        std::fs::write(output, self.body).unwrap();
        self.fetched
            .push(step.args.iter().rev().nth(2).unwrap().clone());
        Ok(ExitStatus::from_raw(0))
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected query: {}", step.label))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected query: {}", step.label))
    }
}

fn source(name: &str, url: &str) -> Source {
    Source {
        name: name.into(),
        url: url.into(),
    }
}

#[test]
fn the_committed_source_list_parses() {
    // Every listed line names a file and an official URL.
    let text = std::fs::read_to_string(root().join("docs/standards-sources.tsv")).unwrap();
    let listed = sources(&text).unwrap();
    assert!(listed.len() > 1);
    assert!(
        listed
            .iter()
            .all(|source| source.url.starts_with("https://"))
    );
    assert!(sources("# comment\n\nname-without-url\n").is_err());
}

#[test]
fn rfc_texts_bring_their_status_metadata_and_everything_is_inventoried() {
    // The status record tells whether an RFC was obsoleted or updated.
    let directory = tempfile::tempdir().unwrap();
    let mut publisher = Publisher {
        body: b"text",
        fetched: Vec::new(),
    };
    let listed = [
        source("rfc3275.txt", "https://example.invalid/rfc3275.txt"),
        source("xml.html", "https://example.invalid/xml"),
    ];
    execute(
        &mut publisher,
        &listed,
        directory.path(),
        "2026-10-29T12:00:00Z",
    )
    .unwrap();
    assert_eq!(
        publisher.fetched,
        [
            "https://example.invalid/rfc3275.txt",
            "https://www.rfc-editor.org/rfc/rfc3275.json",
            "https://example.invalid/xml"
        ]
    );
    let sums = std::fs::read_to_string(directory.path().join("SHA256SUMS")).unwrap();
    let names: Vec<&str> = sums
        .lines()
        .map(|line| line.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(names, ["./rfc3275.json", "./rfc3275.txt", "./xml.html"]);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("retrieved-at.txt")).unwrap(),
        "2026-10-29T12:00:00Z\n"
    );
}

#[test]
fn a_pdf_source_must_deliver_a_pdf() {
    // An HTML error page served for a PDF URL is never kept as the standard.
    let directory = tempfile::tempdir().unwrap();
    let mut publisher = Publisher {
        body: b"<html>moved</html>",
        fetched: Vec::new(),
    };
    let failure = execute(
        &mut publisher,
        &[source("etsi.pdf", "https://example.invalid/etsi.pdf")],
        directory.path(),
        "now",
    )
    .unwrap_err();
    assert!(
        failure.message.contains("Expected PDF"),
        "{}",
        failure.message
    );
    assert!(!directory.path().join("etsi.pdf").exists());
}
