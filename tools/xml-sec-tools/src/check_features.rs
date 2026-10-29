//! `check-features PROFILE [all|lint|test|doc]`: qualifies one documented
//! feature profile of the core package alone. Workspace feature unification
//! could otherwise hide a broken gate.

use crate::repo::{Failure, Run, Step, System, TOOL, require};

#[cfg(test)]
mod tests;

/// Crates a verification-only build must not compile: signing, private-key
/// import, password derivation, an OS randomness source and a second
/// certificate reader.
pub(crate) const VERIFY_ONLY_FORBIDDEN: [&str; 8] = [
    "pkcs12",
    "pkcs5",
    "pbkdf2",
    "scrypt",
    "cms",
    "x509-cert",
    "x509-parser",
    "getrandom",
];

const BACKEND_DIAGNOSTIC: &str = "compile at least one XML backend";

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
    /// A `cargo tree` listing that must name no verification-only refusal.
    VerifyOnlyGraph(Step),
    /// A build that must fail with the missing-backend diagnostic.
    MissingBackend(Step),
}

struct Profile {
    name: &'static str,
    features: Option<&'static str>,
    /// Test targets beyond the library, in order.
    targets: &'static [&'static str],
    /// The facade test signs, so verification-only and core profiles omit it.
    facade: bool,
}

const PROFILES: [Profile; 15] = [
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
        &[],
        true,
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
    if selected.targets.contains(&"verify_only_build") && phase.includes(Phase::Lint) {
        let tree = [
            &["tree"][..],
            &args,
            &["-e", "normal", "--prefix", "none", "--format", "{p}"],
        ]
        .concat();
        actions.push(Action::VerifyOnlyGraph(Step::new(
            "dependency graph",
            "cargo",
            &tree,
        )));
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

/// The first crate of `graph` (one `name vVERSION` per line) a
/// verification-only build must not contain.
pub(crate) fn forbidden_crate(graph: &str) -> Option<&'static str> {
    VERIFY_ONLY_FORBIDDEN.into_iter().find(|name| {
        graph.lines().any(|line| {
            line.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(" v"))
        })
    })
}

/// Executes `actions` in order; the first failure stops qualification.
pub(crate) fn execute(actions: &[Action], runner: &mut impl Run) -> Result<(), Failure> {
    for action in actions {
        match action {
            Action::Run(step) => require(runner.status(step)?)?,
            Action::VerifyOnlyGraph(step) => {
                let (status, graph) = runner.stdout(step)?;
                require(status)?;
                if let Some(name) = forbidden_crate(&graph) {
                    return Err(format!("verification-only graph contains {name}").into());
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
