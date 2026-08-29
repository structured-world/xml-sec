use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use pretty_assertions::assert_eq;
use xml_sec_xslt::{
    CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionOptions, Parameters,
    ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Exact,
    Html,
    Semantic,
    DtdRejected,
    StaticRejected,
}

fn cases() -> Vec<(String, Expectation)> {
    std::fs::read_to_string(fixtures().join("cases.tsv"))
        .expect("oracle case manifest exists")
        .lines()
        .map(|line| {
            let (name, expectation) = line.split_once('\t').expect("manifest row has two fields");
            let expectation = match expectation {
                "exact" => Expectation::Exact,
                "html" => Expectation::Html,
                "semantic" => Expectation::Semantic,
                "dtd-rejected" => Expectation::DtdRejected,
                "static-rejected" => Expectation::StaticRejected,
                other => panic!("unknown oracle expectation {other:?}"),
            };
            (name.to_owned(), expectation)
        })
        .collect()
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libxslt-1.1.45")
}

#[derive(Debug)]
struct FixtureResolver {
    directory: PathBuf,
}

impl Resolver for FixtureResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        let relative = Path::new(uri);
        if relative.components().count() != 1 {
            return Err(Error::Resolver {
                uri: uri.into(),
                message: "oracle resolver only serves sibling fixture modules".into(),
            });
        }
        let path = self.directory.join(relative);
        let bytes = std::fs::read(&path).map_err(|error| Error::Resolver {
            uri: uri.into(),
            message: error.to_string(),
        })?;
        Ok(ResolvedResource {
            canonical_uri: path.to_string_lossy().into_owned(),
            identity: ResourceIdentity(format!("libxslt-1.1.45:{uri}")),
            bytes,
            media_type: Some("application/xslt+xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

fn execute(case_name: &str) -> Vec<u8> {
    let directory = fixtures();
    let resolver = Arc::new(FixtureResolver {
        directory: directory.clone(),
    });
    let stylesheet_path = directory.join(format!("{case_name}.xsl"));
    let source_path = directory.join(format!("{case_name}.xml"));
    let stylesheet = std::fs::read_to_string(&stylesheet_path).expect("stylesheet fixture exists");
    let source = std::fs::read_to_string(&source_path).expect("source fixture exists");
    let compiled = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 16, 512, 8 << 20),
    )
    .compile(&stylesheet, stylesheet_path.to_str())
    .unwrap_or_else(|error| panic!("{case_name}: stylesheet compilation failed: {error}"));
    let document = Document::parse(&source, source_path.to_str())
        .unwrap_or_else(|error| panic!("{case_name}: source parsing failed: {error}"));
    compiled
        .execute(
            &document,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: ExecutionBudget {
                    source_bytes: 1 << 20,
                    external_documents: 0,
                    recursion_depth: 512,
                    xpath_evaluations: 1_000_000,
                    template_applications: 1_000_000,
                    sort_comparisons: 1_000_000,
                    key_entries: 1_000_000,
                    result_nodes: 1_000_000,
                    serialized_bytes: 8 << 20,
                    messages: 1_000,
                    owned_bytes: 32 << 20,
                },
                initial_mode: None,
                initial_template: None,
            },
        )
        .unwrap_or_else(|error| panic!("{case_name}: transformation failed: {error}"))
        .serialized
        .bytes
}

fn assert_case(case_name: &str, expectation: Expectation) {
    // The vendored `.out` bytes come from the pinned libxslt oracle, so every
    // case exercises our engine even when no native oracle binary is installed.
    let expected = std::fs::read(fixtures().join(format!("{case_name}.out")))
        .expect("oracle output fixture exists");
    let actual = execute(case_name);
    if expectation == Expectation::Html {
        assert_eq!(
            normalize_intertag_whitespace(&actual),
            normalize_intertag_whitespace(&expected),
            "HTML oracle case {case_name}"
        );
        return;
    }
    if actual != expected {
        eprintln!("actual: {}", String::from_utf8_lossy(&actual));
        eprintln!("expected: {}", String::from_utf8_lossy(&expected));
    }
    assert_eq!(actual, expected, "oracle case {case_name}");
}

fn normalize_intertag_whitespace(bytes: &[u8]) -> String {
    let input = std::str::from_utf8(bytes).expect("HTML oracle output is UTF-8");
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '>' {
            output.push(character);
            let mut whitespace = String::new();
            while characters.peek().is_some_and(|next| next.is_whitespace()) {
                whitespace.push(characters.next().expect("peeked character exists"));
            }
            if characters.peek() != Some(&'<') {
                output.push_str(&whitespace);
            }
        } else {
            output.push(character);
        }
    }
    output.trim_end().to_owned()
}

#[test]
fn libxslt_rec_positive_corpus() {
    for (case_name, expectation) in cases() {
        if matches!(expectation, Expectation::Exact | Expectation::Html) {
            assert_case(&case_name, expectation);
        }
    }
}

#[test]
fn dtd_dependent_rec_cases_are_rejected_by_security_contract() {
    for (case_name, expectation) in cases() {
        if expectation != Expectation::DtdRejected {
            continue;
        }
        let source = std::fs::read_to_string(fixtures().join(format!("{case_name}.xml")))
            .expect("DTD source fixture exists");
        let error = match Document::parse(&source, None) {
            Ok(_) => panic!("{case_name}: DTD-bearing XML must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("DTD"),
            "{case_name}: unexpected error: {error}"
        );
    }
}

#[test]
fn generate_id_covers_every_xpath_node_kind() {
    let case_name = cases()
        .into_iter()
        .find_map(|(name, expectation)| (expectation == Expectation::Semantic).then_some(name))
        .expect("generate-id semantic case exists");
    let bytes = execute(&case_name);
    let output = std::str::from_utf8(&bytes).expect("oracle output is UTF-8");
    let document = roxmltree::Document::parse(output).expect("oracle output is well-formed XML");
    let identifiers = document
        .root_element()
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.text().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(identifiers.len(), 8, "all XPath node kinds are represented");
    assert!(
        identifiers.iter().all(|identifier| !identifier.is_empty()),
        "generate-id() must be non-empty for every non-empty node-set"
    );
    let unique = identifiers
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        unique.len(),
        identifiers.len(),
        "distinct XPath nodes must receive distinct identifiers"
    );
}

#[test]
fn duplicate_named_template_is_a_static_error() {
    let case_name = cases()
        .into_iter()
        .find_map(|(name, expectation)| {
            (expectation == Expectation::StaticRejected).then_some(name)
        })
        .expect("static-error oracle case exists");
    let directory = fixtures();
    let stylesheet = std::fs::read_to_string(directory.join(format!("{case_name}.xsl")))
        .expect("static-error stylesheet exists");
    let error = Compiler::new(
        Arc::new(FixtureResolver { directory }),
        CompileBudget::new(1 << 20, 16, 512, 8 << 20),
    )
    .compile(&stylesheet, None)
    .expect_err("duplicate named templates must fail compilation");
    assert_eq!(error.kind(), xml_sec_xslt::ErrorKind::Static);
}

#[test]
fn vendored_outputs_match_configured_libxslt_oracle() {
    // CI sets LIBXSLT_XSLTPROC and therefore verifies that committed oracle
    // bytes still match the independently built pinned libxslt executable.
    let Some(xsltproc) = std::env::var_os("LIBXSLT_XSLTPROC") else {
        eprintln!("skipping live libxslt check: LIBXSLT_XSLTPROC is not configured");
        return;
    };
    for (case_name, expectation) in cases() {
        if expectation == Expectation::DtdRejected {
            continue;
        }
        let directory = fixtures();
        let output = Command::new(&xsltproc)
            .arg("--nonet")
            .arg(directory.join(format!("{case_name}.xsl")))
            .arg(directory.join(format!("{case_name}.xml")))
            .output()
            .unwrap_or_else(|error| panic!("{case_name}: failed to execute xsltproc: {error}"));
        if expectation == Expectation::StaticRejected {
            assert!(
                !output.status.success(),
                "{case_name}: xsltproc unexpectedly accepted a static error"
            );
            continue;
        }
        assert!(
            output.status.success(),
            "{case_name}: xsltproc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = std::fs::read(directory.join(format!("{case_name}.out")))
            .expect("oracle output fixture exists");
        assert_eq!(output.stdout, expected, "live oracle case {case_name}");
    }
}
