use super::{build_identity, cargo_configs, selections};
use crate::bench::regression::incomparability;
use serde_json::{Value, json};
use std::path::Path;

fn run_with(build: &Value) -> (Value, Value, Value) {
    let level = json!({ "environment": { "platform": "linux", "architecture": "x64", "cpu": "Xeon", "samples": 30, "repetitions": 3 } });
    let mut cli = level.clone();
    cli["corpus"] = json!([]);
    (cli, level, build.clone())
}

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn select(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    env(pairs)
}

#[test]
fn a_release_profile_or_flag_override_changes_the_build_identity() {
    // Two runs that differ only in Cargo overrides must not be compared.
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_str().unwrap();
    let plain = build_identity(
        &select(&[("cli", "x")]),
        &env(&[("CARGO_HOME", home)]),
        directory.path(),
    )
    .unwrap();
    for (name, value) in [
        ("CARGO_PROFILE_RELEASE_LTO", "thin"),
        ("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-cpu=native"),
        ("CC", "clang-18"),
        ("RUSTC_WRAPPER", "sccache"),
    ] {
        let changed = build_identity(
            &select(&[("cli", "x")]),
            &env(&[("CARGO_HOME", home), (name, value)]),
            directory.path(),
        )
        .unwrap();
        assert_eq!(changed["environment"], json!({ name: value }));
        let (base, next) = (run_with(&plain), run_with(&changed));
        assert_eq!(
            incomparability((&base.0, &base.1, &base.2), (&next.0, &next.1, &next.2)),
            ["build environment differs"]
        );
    }
    let ignored = build_identity(
        &select(&[("cli", "x")]),
        &env(&[
            ("CARGO_HOME", home),
            ("CARGO_TERM_COLOR", "always"),
            ("HOME", "/x"),
        ]),
        directory.path(),
    )
    .unwrap();
    assert_eq!(ignored["environment"], json!({}));
}

#[test]
fn cargo_configuration_files_that_apply_are_part_of_the_identity() {
    // A profile set in a config file changes the build as much as one in the environment.
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let project = directory.path().join("project/nested");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let before = cargo_configs(&project, &home).unwrap();
    std::fs::create_dir(directory.path().join("project/.cargo")).unwrap();
    std::fs::write(
        directory.path().join("project/.cargo/config.toml"),
        "[profile.release]\nlto = \"thin\"\n",
    )
    .unwrap();
    std::fs::write(home.join("config.toml"), "[build]\njobs = 2\n").unwrap();
    assert_eq!(
        cargo_configs(&project, &home).unwrap().len(),
        before.len() + 2
    );
}

#[test]
fn swapping_configuration_between_the_project_and_cargo_home_changes_the_identity() {
    // The deeper directory wins in Cargo, so the same two files in swapped places build differently.
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir_all(project.join(".cargo")).unwrap();
    let write = |project_level: u8, home_level: u8| {
        std::fs::write(
            project.join(".cargo/config.toml"),
            format!("[profile.release]\nopt-level = {project_level}\n"),
        )
        .unwrap();
        std::fs::write(
            home.join("config.toml"),
            format!("[profile.release]\nopt-level = {home_level}\n"),
        )
        .unwrap();
        cargo_configs(&project, &home).unwrap()
    };
    let project_optimized = write(3, 0);
    let home_optimized = write(0, 3);
    assert_ne!(project_optimized, home_optimized);
    let last = project_optimized.last().unwrap();
    assert_eq!(
        (&last["location"], &last["file"]),
        (&json!("cargo_home"), &json!("config.toml"))
    );
    let first = &project_optimized[0];
    assert_eq!(
        (&first["location"], &first["levels"], &first["file"]),
        (&json!("directory"), &json!(0), &json!("config.toml"))
    );
}

#[test]
fn selections_are_name_value_pairs_in_order() {
    // A malformed selection must not record an identity that drops it.
    let args = vec![
        "cli=benchmark-internals,xslt".to_owned(),
        "heap=true".to_owned(),
    ];
    assert_eq!(
        selections(&args).unwrap(),
        select(&[("cli", "benchmark-internals,xslt"), ("heap", "true")])
    );
    assert!(selections(&["no-separator".to_owned()]).is_err());
    assert!(selections(&["=value".to_owned()]).is_err());
}

#[test]
fn an_identity_that_cannot_be_recorded_fails_instead_of_writing_a_partial_one() {
    // Without the configuration a build depends on, the run cannot prove what it measured.
    let directory = tempfile::tempdir().unwrap();
    let unreadable = directory.path().join(".cargo/config.toml");
    std::fs::create_dir_all(&unreadable).unwrap();
    assert!(cargo_configs(directory.path(), Path::new("/nonexistent")).is_err());
}
