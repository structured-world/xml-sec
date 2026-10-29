use super::{Action, REJECTION, execute, plan, tamper};
use crate::repo::{Run, Step, root};
use crate::test_support::read;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

fn lines(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Run(step) | Action::Capture(step, _) | Action::Refused(step, _) => {
                Some(step.args.join(" "))
            }
            Action::Tamper(..) => None,
        })
        .collect()
}

/// Plays the examples: signing emits an invoice, verification of the
/// tampered copy answers as configured, and one program may fail.
struct Examples {
    fail: Option<&'static str>,
    accept_tamper: bool,
    tamper_error: &'static str,
    calls: Vec<String>,
}

impl Examples {
    fn new() -> Self {
        Self {
            fail: None,
            accept_tamper: false,
            tamper_error: REJECTION,
            calls: Vec::new(),
        }
    }

    fn outcome(&mut self, step: &Step) -> (ExitStatus, String) {
        let line = step.args.join(" ");
        self.calls.push(line.clone());
        if self.fail.is_some_and(|fail| step.args[0] == fail) {
            return (ExitStatus::from_raw(37 << 8), String::new());
        }
        if line.contains("--example sign") {
            return (ExitStatus::from_raw(0), "<Invoice>42.00</Invoice>".into());
        }
        if line.contains("--example verify")
            && line.contains("/tampered.xml")
            && !self.accept_tamper
        {
            return (ExitStatus::from_raw(1 << 8), self.tamper_error.into());
        }
        (ExitStatus::from_raw(0), String::new())
    }
}

impl Run for Examples {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        Ok(self.outcome(step).0)
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Ok(self.outcome(step))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Ok(self.outcome(step))
    }
}

fn qualify(examples: &mut Examples) -> Result<(), crate::repo::Failure> {
    let store = tempfile::tempdir().unwrap();
    let actions = plan("all", store.path(), "").unwrap();
    execute(&actions, store.path(), examples)
}

#[test]
fn docs_only_checks_the_core_and_config_apis_not_private_workspace_kernels() {
    // A private vendor crate's undocumented internals are not the public core contract.
    let actions = plan("docs", Path::new("/store"), "-Zflag").unwrap();
    assert_eq!(
        lines(&actions),
        ["doc -p xml-sec -p xml-sec-config --all-features --no-deps"]
    );
    let Action::Run(doc) = &actions[0] else {
        panic!()
    };
    assert_eq!(
        doc.env,
        [(
            "RUSTDOCFLAGS".into(),
            "-Zflag -D warnings -D missing-docs".into()
        )]
    );
}

#[test]
fn full_qualification_executes_the_examples_and_rejects_accepted_tampering() {
    // Merely compiling examples must not count as runtime qualification.
    let mut examples = Examples::new();
    qualify(&mut examples).unwrap();
    for name in ["sign", "verify", "encrypt", "policy_roundtrip"] {
        assert!(
            examples
                .calls
                .iter()
                .any(|call| call.contains(&format!("--example {name}"))),
            "{name}"
        );
    }
    assert!(
        examples
            .calls
            .iter()
            .any(|call| call.contains("--test documentation"))
    );
    let mut accepting = Examples {
        accept_tamper: true,
        ..Examples::new()
    };
    assert!(qualify(&mut accepting).is_err());
    let mut broken = Examples {
        tamper_error: "compiler or setup failure",
        ..Examples::new()
    };
    assert!(qualify(&mut broken).is_err());
}

#[test]
fn failed_prerequisites_stop_before_later_phases() {
    // A later success or expected negative example cannot hide a real failure.
    for program in ["doc", "test", "nextest"] {
        let mut examples = Examples {
            fail: Some(program),
            ..Examples::new()
        };
        assert_eq!(qualify(&mut examples).unwrap_err().code, 37, "{program}");
        assert!(
            !examples
                .calls
                .iter()
                .any(|call| call.contains("--example sign")),
            "{program}"
        );
    }
}

#[test]
fn an_unknown_phase_never_runs_cargo() {
    // A typo must not silently become a passing docs-only invocation.
    assert_eq!(
        plan("unknown", Path::new("/store"), "").unwrap_err().code,
        2
    );
}

#[test]
fn tampering_changes_the_amount_or_refuses() {
    // Without an amount to change, a passing verification would prove nothing.
    assert_eq!(
        tamper("<a>42.00 42.00</a>\n<b>42.00</b>").unwrap(),
        "<a>99.00 42.00</a>\n<b>99.00</b>"
    );
    assert!(tamper("<a>1.00</a>").is_err());
}

#[test]
fn the_documentation_entry_pages_link_to_existing_local_files() {
    // These owned guides use ordinary inline links, not arbitrary Markdown input.
    // Check destinations without reading imported fixture payloads.
    let link = regex::Regex::new(r"\]\(([^)]+)\)").unwrap();
    for file in [
        "docs/README.md",
        "docs/examples.md",
        "docs/deployment.md",
        "docs/migration-libxmlsec1.md",
        "docs/policy-schema-v1.md",
    ] {
        let directory = root().join(file).parent().unwrap().to_path_buf();
        for target in link.captures_iter(&read(file)) {
            let target = &target[1];
            if ["http:", "https:", "mailto:", "#"]
                .iter()
                .any(|prefix| target.starts_with(prefix))
            {
                continue;
            }
            let path = directory.join(target.split('#').next().unwrap());
            assert!(path.is_file(), "{file}: {target}");
        }
    }
}

#[test]
fn the_schema_reference_lists_every_resource_field_admitted_by_the_loader() {
    // The loader's one macro list drives both admission and effective output.
    // This is a drift check of that list, not a second TOML or policy implementation.
    let source = read("crates/xml-sec-config/src/settings.rs");
    let start = source.find("macro_rules! resource_fields").unwrap();
    let end = start + source[start..].find("macro_rules! update_numbers").unwrap();
    let field = regex::Regex::new(r"\bmax_[a-z0-9_]+\b").unwrap();
    let fields: std::collections::BTreeSet<&str> = field
        .find_iter(&source[start..end])
        .map(|found| found.as_str())
        .collect();
    assert!(!fields.is_empty());
    let guide = read("docs/policy-schema-v1.md");
    for field in fields {
        assert!(
            guide.contains(&format!("`{field}`")),
            "undocumented resource: {field}"
        );
    }
}
