//! `check-features PROFILE [all|lint|test|doc]`: qualifies one documented
//! feature profile of the core package alone. Workspace feature unification
//! could otherwise hide a broken gate.

use crate::repo::{Failure, Run, Step, System, TOOL, require, root};
use serde_json::Value;
use std::path::Path;

#[cfg(test)]
mod tests;

/// Crates a verification-only build must not compile: signing, private-key
/// import, password derivation, an OS randomness source and a second
/// certificate reader. The `cms` feature admits only `structured-cms`, the
/// last entry.
pub(crate) const VERIFY_ONLY_FORBIDDEN: [&str; 9] = [
    "pkcs12",
    "pkcs5",
    "pbkdf2",
    "scrypt",
    "cms",
    "x509-cert",
    "x509-parser",
    "getrandom",
    "structured-cms",
];

const CMS_FORBIDDEN: &[&str] = VERIFY_ONLY_FORBIDDEN
    .split_last()
    .expect("the list is not empty")
    .1;

const BACKEND_DIAGNOSTIC: &str = "compile at least one XML backend";

/// What the embedded post-quantum code relies on from its dependencies.
const EXPERIMENTAL_CONSUMER: [(&str, &str); 1] = [("shake", "zeroize")];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    All,
    Lint,
    Test,
    Doc,
}

impl Phase {
    fn parse(phase: &str) -> Option<Self> {
        Some(match phase {
            "all" => Self::All,
            "lint" => Self::Lint,
            "test" => Self::Test,
            "doc" => Self::Doc,
            _ => return None,
        })
    }

    fn includes(self, phase: Self) -> bool {
        self == Self::All || self == phase
    }
}

/// One step of a qualification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// A process that must succeed.
    Run(Step),
    /// A `cargo tree` listing that must name none of the refused crates.
    VerifyOnlyGraph(Step, &'static [&'static str]),
    /// A build that must fail with the missing-backend diagnostic.
    MissingBackend(Step),
    /// `cargo metadata` of a throwaway consumer, whose graph must enable each
    /// `(package, feature)` pair without asking for it.
    ConsumerFeatures(Step, &'static [(&'static str, &'static str)]),
}

struct Profile {
    name: &'static str,
    features: Option<&'static str>,
    /// Test targets beyond the library, in order.
    targets: &'static [&'static str],
    /// The facade test signs, so verification-only and core profiles omit it.
    facade: bool,
}

const PROFILES: [Profile; 17] = [
    profile("default", None, &["rust_api"], false),
    profile("dom-xmloxide", Some("xml-backend-xmloxide"), &[], false),
    profile("dom-roxmltree", Some("xml-backend-roxmltree"), &[], false),
    profile(
        "c14n-xmloxide",
        Some("c14n,xml-backend-xmloxide"),
        &[],
        false,
    ),
    profile(
        "c14n-roxmltree",
        Some("c14n,xml-backend-roxmltree"),
        &[],
        false,
    ),
    profile(
        "dsig-xmloxide",
        Some("xmldsig,xml-backend-xmloxide"),
        &["verify_only_build"],
        false,
    ),
    profile(
        "dsig-roxmltree",
        Some("xmldsig,xml-backend-roxmltree"),
        &["verify_only_build"],
        false,
    ),
    profile(
        "cms-xmloxide",
        Some("cms,xml-backend-xmloxide"),
        &["cms_timestamp"],
        false,
    ),
    profile(
        "dsig-sign-xmloxide",
        Some("xmldsig-sign,xml-backend-xmloxide"),
        &[],
        true,
    ),
    profile(
        "xmlenc-xmloxide",
        Some("xmlenc,xml-backend-xmloxide"),
        &[],
        true,
    ),
    profile(
        "xmlenc-roxmltree",
        Some("xmlenc,xml-backend-roxmltree"),
        &[],
        true,
    ),
    profile("xslt", Some("xslt,xml-backend-xmloxide"), &[], true),
    profile(
        "legacy",
        Some("xmldsig-sign,legacy-algorithms,xml-backend-xmloxide"),
        &[],
        true,
    ),
    profile(
        "experimental",
        Some("experimental-pq,xmldsig-sign,xml-backend-xmloxide"),
        &["shake_state_clearing"],
        true,
    ),
    profile(
        "dstu4145",
        Some("dstu4145,xml-backend-xmloxide"),
        &["dstu4145_interop"],
        false,
    ),
    profile(
        "fips-dsig",
        Some("aws-lc-fips,xmldsig-sign,xml-backend-xmloxide"),
        &["aws_lc_provider"],
        true,
    ),
    profile("pkcs11", Some("pkcs11,xml-backend-xmloxide"), &[], true),
];

const fn profile(
    name: &'static str,
    features: Option<&'static str>,
    targets: &'static [&'static str],
    facade: bool,
) -> Profile {
    Profile {
        name,
        features,
        targets,
        facade,
    }
}

fn usage(message: String) -> Failure {
    Failure { code: 2, message }
}

/// Plans `profile` for `phase`; `module` is the PKCS#11 test module.
pub(crate) fn plan(
    profile: &str,
    phase: &str,
    module: Option<&str>,
) -> Result<Vec<Action>, Failure> {
    let phase = Phase::parse(phase).ok_or_else(|| usage(format!("unknown phase: {phase}")))?;
    if profile == "no-backend" {
        return Ok(vec![Action::MissingBackend(Step::new(
            "no-backend",
            "cargo",
            &["check", "-p", "xml-sec", "--lib", "--no-default-features"],
        ))]);
    }
    let selected = PROFILES
        .iter()
        .find(|candidate| candidate.name == profile)
        .ok_or_else(|| usage(format!("unknown feature profile: {profile}")))?;
    let mut args = vec!["-p", "xml-sec"];
    if let Some(features) = selected.features {
        args.extend(["--no-default-features", "--features", features]);
    }
    let mut tests = vec!["--lib"];
    for target in selected.targets {
        tests.extend(["--test", target]);
    }
    if selected.facade {
        tests.extend(["--test", "rust_api"]);
    }
    let pkcs11 = profile == "pkcs11";
    let module = module.filter(|module| !module.is_empty());
    if pkcs11 && phase.includes(Phase::Test) && module.is_none() {
        return Err(
            "PKCS11_MODULE: pass an explicit disposable-test SoftHSM module via PKCS11_MODULE"
                .into(),
        );
    }
    let mut actions = Vec::new();
    let forbidden: Option<&'static [&'static str]> = match selected.targets {
        ["verify_only_build"] => Some(&VERIFY_ONLY_FORBIDDEN),
        ["cms_timestamp"] => Some(CMS_FORBIDDEN),
        _ => None,
    };
    if let Some(forbidden) = forbidden.filter(|_| phase.includes(Phase::Lint)) {
        let tree = [
            &["tree"][..],
            &args,
            &["-e", "normal", "--prefix", "none", "--format", "{p}"],
        ]
        .concat();
        actions.push(Action::VerifyOnlyGraph(
            Step::new("dependency graph", "cargo", &tree),
            forbidden,
        ));
    }
    if phase.includes(Phase::Lint) && profile == "experimental" {
        actions.push(Action::ConsumerFeatures(
            Step::new(
                "consumer graph",
                "cargo",
                &["metadata", "--format-version", "1"],
            ),
            &EXPERIMENTAL_CONSUMER,
        ));
    }
    if phase.includes(Phase::Lint) {
        let clippy = [
            &["clippy"][..],
            &args,
            &["--all-targets", "--", "-D", "warnings"],
        ]
        .concat();
        actions.push(Action::Run(Step::new("lint", "cargo", &clippy)));
    }
    if phase.includes(Phase::Test) {
        if let (true, Some(module)) = (pkcs11, module) {
            let run = [&["pkcs11-tests", module][..], &args, &tests].concat();
            actions.push(Action::Run(Step::new("test", TOOL, &run)));
        } else {
            let run = [&["nextest", "run"][..], &args, &tests].concat();
            actions.push(Action::Run(Step::new("test", "cargo", &run)));
        }
    }
    if phase.includes(Phase::Doc) {
        let doc = [&["test", "--doc"][..], &args].concat();
        actions.push(Action::Run(Step::new("doc", "cargo", &doc)));
    }
    Ok(actions)
}

/// The first crate of `forbidden` that `graph` (one `name vVERSION` per line)
/// contains.
pub(crate) fn forbidden_crate(graph: &str, forbidden: &[&'static str]) -> Option<&'static str> {
    forbidden.iter().copied().find(|name| {
        graph.lines().any(|line| {
            line.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(" v"))
        })
    })
}

/// A manifest outside the workspace that depends on `root` like a downstream
/// crate: no dev-dependency or workspace member can unify features into it.
fn consumer_manifest(root: &Path) -> String {
    format!(
        "[package]\nname = \"feature-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n\
         [lib]\npath = \"lib.rs\"\n\n[workspace]\n\n[dependencies]\n\
         xml-sec = {{ path = '{}', default-features = false, \
         features = [\"experimental-pq\", \"xml-backend-roxmltree\"] }}\n",
        root.display()
    )
}

/// The first `(package, feature)` of `required` that `metadata`, the output of
/// `cargo metadata`, leaves off. A package missing from the graph counts: an
/// absent crate must not pass as a clean one.
fn missing_feature(
    metadata: &str,
    required: &[(&'static str, &'static str)],
) -> Result<Option<(&'static str, &'static str)>, String> {
    let metadata: Value =
        serde_json::from_str(metadata).map_err(|error| format!("parse cargo metadata: {error}"))?;
    let list = |value: Option<&Value>| value.and_then(Value::as_array).cloned().unwrap_or_default();
    let packages = list(metadata.get("packages"));
    let nodes = list(metadata.pointer("/resolve/nodes"));
    Ok(required.iter().copied().find(|(package, feature)| {
        let mut identities = packages
            .iter()
            .filter(|candidate| candidate.get("name").and_then(Value::as_str) == Some(package))
            .filter_map(|candidate| candidate.get("id"))
            .peekable();
        identities.peek().is_none()
            || identities.any(|identity| {
                !nodes
                    .iter()
                    .filter(|node| node.get("id") == Some(identity))
                    .any(|node| {
                        list(node.get("features"))
                            .iter()
                            .any(|name| name.as_str() == Some(feature))
                    })
            })
    }))
}

/// Executes `actions` in order; the first failure stops qualification.
pub(crate) fn execute(actions: &[Action], runner: &mut impl Run) -> Result<(), Failure> {
    for action in actions {
        match action {
            Action::Run(step) => require(runner.status(step)?)?,
            Action::VerifyOnlyGraph(step, forbidden) => {
                let (status, graph) = runner.stdout(step)?;
                require(status)?;
                if let Some(name) = forbidden_crate(&graph, forbidden) {
                    return Err(format!("verification-only graph contains {name}").into());
                }
            }
            Action::ConsumerFeatures(step, required) => {
                let consumer = tempfile::tempdir().map_err(|error| error.to_string())?;
                let write = |name: &str, text: String| {
                    std::fs::write(consumer.path().join(name), text)
                        .map_err(|error| error.to_string())
                };
                write("Cargo.toml", consumer_manifest(&root()))?;
                write("lib.rs", String::new())?;
                let (status, metadata) =
                    runner.stdout(&step.clone().in_directory(consumer.path()))?;
                require(status)?;
                if let Some((package, feature)) = missing_feature(&metadata, required)? {
                    return Err(format!(
                        "a downstream consumer does not enable {package}/{feature}"
                    )
                    .into());
                }
            }
            Action::MissingBackend(step) => {
                let (status, diagnostic) = runner.combined(step)?;
                if status.success() {
                    return Err("missing XML backend unexpectedly compiled".into());
                }
                print!("{diagnostic}");
                // Only the intended diagnostic proves the contract; a broken
                // dependency or missing tool does not.
                if !diagnostic.contains(BACKEND_DIAGNOSTIC) {
                    return Err(Failure {
                        code: 1,
                        message: String::new(),
                    });
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let profile = args.next().ok_or("pass a documented feature profile")?;
    let phase = args.next().unwrap_or_else(|| "all".into());
    let module = std::env::var("PKCS11_MODULE").ok();
    let actions = plan(&profile, &phase, module.as_deref())?;
    execute(&actions, &mut System)
}
