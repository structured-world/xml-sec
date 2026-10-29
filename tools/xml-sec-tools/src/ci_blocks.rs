//! `ci-blocks BLOCK`: one CI test block, each profile a separate Cargo
//! invocation. A block shares runner and setup, never enabled features.

use crate::repo::{Step, TOOL, describe, spawn};
use std::process::ExitStatus;

#[cfg(test)]
mod tests;

/// The Cargo features a profile resolves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Graph {
    /// The package defaults.
    #[default]
    Defaults,
    /// Every feature, including the PKCS#11 token path.
    All,
    Features(String),
}

/// Provider families whose lint builds only their own package targets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Family {
    #[default]
    Ordinary,
    PostQuantum,
    Fips,
}

/// One separately resolved feature graph and the checks run against it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Profile {
    pub(crate) name: String,
    pub(crate) graph: Graph,
    pub(crate) family: Family,
    pub(crate) build: bool,
    pub(crate) lint: bool,
    /// Library-only lint graphs whose cfg combinations no tested profile resolves.
    pub(crate) lint_only: bool,
}

fn backend_feature(backend: &str) -> String {
    if backend == "fat-runtime" {
        "xml-backends-all".into()
    } else {
        format!("xml-backend-{backend}")
    }
}

fn core(backend: &str) -> String {
    format!("xmldsig,xmlenc,c14n,{}", backend_feature(backend))
}

fn profile(name: impl Into<String>, features: Option<String>) -> Profile {
    Profile {
        name: name.into(),
        graph: features.map_or(Graph::Defaults, Graph::Features),
        ..Profile::default()
    }
}

/// The blocks in workflow order. Expensive FIPS compilation keeps its own block.
pub(crate) fn blocks() -> Vec<(&'static str, Vec<Profile>)> {
    let ordinary = |backend: &str| Profile {
        build: true,
        lint: true,
        ..profile(backend, Some(core(backend)))
    };
    let minimal = |feature: &str| Profile {
        lint: true,
        lint_only: true,
        ..profile(
            format!("{feature}-minimal"),
            Some(format!("{feature},xml-backend-differential")),
        )
    };
    let mut core_block = vec![Profile {
        lint: true,
        ..profile("default-features", None)
    }];
    core_block.extend(
        ["xmloxide", "roxmltree", "differential", "fat-runtime"]
            .into_iter()
            .map(ordinary),
    );
    core_block.extend(
        ["xmldsig", "xmldsig-sign", "xmlenc", "xslt"]
            .into_iter()
            .map(minimal),
    );
    let extended = vec![
        Profile {
            graph: Graph::All,
            build: true,
            lint: true,
            ..profile("all-features", None)
        },
        profile(
            "legacy-fat-runtime",
            Some(format!("{},legacy-algorithms", core("fat-runtime"))),
        ),
        Profile {
            lint: true,
            ..profile(
                "xslt-fat-runtime",
                Some(format!("{},xslt", core("fat-runtime"))),
            )
        },
    ];
    let mut experimental: Vec<Profile> = ["xmloxide", "roxmltree", "differential"]
        .into_iter()
        .map(|backend| Profile {
            family: Family::PostQuantum,
            lint: true,
            ..profile(
                format!("experimental-pq-{backend}"),
                Some(format!(
                    "{},legacy-algorithms,experimental-pq",
                    core(backend)
                )),
            )
        })
        .collect();
    experimental.push(Profile {
        lint: true,
        ..profile("xslt-xmloxide", Some(format!("{},xslt", core("xmloxide"))))
    });
    let mut fips = vec![Profile {
        family: Family::Fips,
        lint: true,
        ..profile(
            "legacy-aws-fips",
            Some("aws-lc-fips,xmlenc,c14n,xml-backend-xmloxide,legacy-algorithms".into()),
        )
    }];
    fips.extend(
        ["xmloxide", "roxmltree", "differential", "fat-runtime"]
            .into_iter()
            .map(|backend| Profile {
                family: Family::Fips,
                lint: true,
                ..profile(
                    format!("aws-fips-{backend}"),
                    Some(format!(
                        "aws-lc-fips,xmlenc,c14n,{}",
                        backend_feature(backend)
                    )),
                )
            }),
    );
    vec![
        ("core", core_block),
        ("extended", extended),
        ("experimental", experimental),
        ("fips", fips),
    ]
}

/// Plans the processes of block `name`; `module` is the PKCS#11 test module.
pub(crate) fn plan(name: &str, module: Option<&str>) -> Result<Vec<Step>, String> {
    let profiles = blocks()
        .into_iter()
        .find(|(block, _)| *block == name)
        .ok_or_else(|| format!("Unknown CI test block: {name}"))?
        .1;
    let mut steps = Vec::new();
    if name == "fips" {
        steps.push(Step::new(
            "FIPS without encryption",
            "cargo",
            &[
                "check",
                "--no-default-features",
                "--features",
                "aws-lc-fips,xml-backend-xmloxide",
            ],
        ));
    }
    if name == "core" {
        steps.push(Step::new(
            "xmlenc-inventory: build",
            "cargo",
            &[
                "build",
                "-p",
                "xml-sec",
                "--no-default-features",
                "--features",
                "xmlenc,xml-backend-xmloxide",
            ],
        ));
    }
    for profile in &profiles {
        let features: Vec<&str> = match &profile.graph {
            Graph::Defaults => Vec::new(),
            Graph::All => vec!["--all-features"],
            Graph::Features(features) => vec!["--no-default-features", "--features", features],
        };
        let label = |phase: &str| format!("{}: {phase}", profile.name);
        if profile.build {
            let args = [&["build", "--workspace"][..], &features].concat();
            steps.push(Step::new(label("build"), "cargo", &args));
        }
        if profile.lint {
            let scope: &[&str] = if profile.lint_only {
                &["-p", "xml-sec", "--lib"]
            } else if profile.family != Family::Ordinary {
                &["--all-targets"]
            } else {
                &["--workspace", "--all-targets"]
            };
            let args = [&["clippy"][..], scope, &features, &["--", "-D", "warnings"]].concat();
            steps.push(Step::new(label("lint"), "cargo", &args));
        }
        if profile.lint_only {
            continue;
        }
        let tests = [
            &["--workspace"][..],
            &features,
            &["-E", "not binary(libxslt_oracle)"],
        ]
        .concat();
        if profile.graph == Graph::All {
            let module = module
                .filter(|module| !module.is_empty())
                .ok_or("PKCS11_MODULE is required for all-feature test blocks")?;
            let args = [&["pkcs11-tests", module][..], &tests].concat();
            steps.push(Step::new(label("tests"), TOOL, &args));
        } else {
            let args = [&["nextest", "run"][..], &tests].concat();
            steps.push(Step::new(label("tests"), "cargo", &args));
        }
        let args = [&["test", "--doc", "--workspace"][..], &features].concat();
        steps.push(Step::new(label("docs"), "cargo", &args));
    }
    Ok(steps)
}

/// Runs `steps` in order and stops at the first failure, which it returns.
pub(crate) fn execute(
    steps: &[Step],
    mut run: impl FnMut(&Step) -> Result<ExitStatus, String>,
) -> Result<(), String> {
    for step in steps {
        println!("::group::{}", step.label);
        let status = run(step)?;
        if !status.success() {
            return Err(format!("{}: {}", step.label, describe(status)));
        }
        println!("::endgroup::");
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (Some(block), None) = (args.next(), args.next()) else {
        return Err("Usage: xml-sec-tools ci-blocks BLOCK".into());
    };
    let module = std::env::var("PKCS11_MODULE").ok();
    let steps = plan(&block, module.as_deref())?;
    execute(&steps, spawn)
}
