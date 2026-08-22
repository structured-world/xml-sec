use std::{fs, path::Path, process::Command};

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
}

fn donor_tests() -> std::path::PathBuf {
    project_root().join("donors/xmlsec/tests")
}

#[test]
fn check_mode_detects_drift_without_replacing_the_snapshot() {
    // The CI reproducibility gate must be observational: drift fails the check
    // and leaves the candidate snapshot untouched for diagnosis.
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("snapshot");
    let donor = donor_tests();
    let script = project_root().join("scripts/import-xmlsec1-cli-fixtures.sh");
    let imported = Command::new(&script)
        .env("XMLSEC_DONOR_ROOT", &donor)
        .env("XMLSEC_FIXTURE_TARGET", &target)
        .status()
        .unwrap();
    assert!(imported.success());

    let changed = target.join("testDSig.sh");
    fs::write(&changed, "local drift\n").unwrap();
    let checked = Command::new(script)
        .arg("--check")
        .env("XMLSEC_DONOR_ROOT", donor)
        .env("XMLSEC_FIXTURE_TARGET", &target)
        .status()
        .unwrap();

    assert!(!checked.success());
    assert_eq!(fs::read_to_string(changed).unwrap(), "local drift\n");
}

#[test]
fn importer_rejects_missing_and_empty_donor_pins() {
    // Provenance is part of the snapshot contract; an import without an exact
    // donor commit must fail rather than producing an unpinned fixture tree.
    let temp = tempfile::tempdir().unwrap();
    let isolated_root = temp.path().join("isolated");
    let scripts = isolated_root.join("scripts");
    let compatibility = isolated_root.join("compatibility");
    fs::create_dir_all(&scripts).unwrap();
    fs::create_dir_all(&compatibility).unwrap();
    let script = scripts.join("import-xmlsec1-cli-fixtures.sh");
    fs::copy(
        project_root().join("scripts/import-xmlsec1-cli-fixtures.sh"),
        &script,
    )
    .unwrap();
    let donor = donor_tests();

    for (case, write_empty_pin) in [("missing", false), ("empty", true)] {
        let pin = compatibility.join("libxmlsec1-1.3.13-donor-commit.txt");
        if write_empty_pin {
            fs::write(&pin, "").unwrap();
        } else if pin.exists() {
            fs::remove_file(&pin).unwrap();
        }
        let status = Command::new("bash")
            .arg(&script)
            .env("XMLSEC_DONOR_ROOT", &donor)
            .env(
                "XMLSEC_FIXTURE_TARGET",
                temp.path().join(format!("snapshot-{case}")),
            )
            .status()
            .unwrap();
        assert!(!status.success(), "{case} donor pin must fail closed");
    }
}

#[test]
fn importer_rejects_a_checkout_at_another_revision() {
    // A syntactically valid pin is not provenance evidence unless it equals the
    // checkout whose bytes are copied into the committed snapshot.
    let temp = tempfile::tempdir().unwrap();
    let isolated_root = temp.path().join("isolated");
    let scripts = isolated_root.join("scripts");
    let compatibility = isolated_root.join("compatibility");
    fs::create_dir_all(&scripts).unwrap();
    fs::create_dir_all(&compatibility).unwrap();
    let script = scripts.join("import-xmlsec1-cli-fixtures.sh");
    fs::copy(
        project_root().join("scripts/import-xmlsec1-cli-fixtures.sh"),
        &script,
    )
    .unwrap();
    fs::write(
        compatibility.join("libxmlsec1-1.3.13-donor-commit.txt"),
        format!("{}\n", "0".repeat(40)),
    )
    .unwrap();

    let output = Command::new("bash")
        .arg(script)
        .env("XMLSEC_DONOR_ROOT", donor_tests())
        .env("XMLSEC_FIXTURE_TARGET", temp.path().join("snapshot"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not match pin"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn interrupted_promotion_restores_the_previous_snapshot() {
    use std::os::unix::fs::PermissionsExt as _;

    // Simulate TERM after target -> backup but before staging -> target. EXIT
    // recovery must restore the tracked snapshot and remove transaction debris.
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("snapshot");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), "previous snapshot").unwrap();
    let tools = temp.path().join("tools");
    fs::create_dir(&tools).unwrap();
    let fake_mv = tools.join("mv");
    fs::write(
        &fake_mv,
        r#"#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "$MV_COUNT_FILE" ]] || count="$(<"$MV_COUNT_FILE")"
count=$((count + 1))
printf '%s\n' "$count" > "$MV_COUNT_FILE"
if (( count == 2 )); then
  kill -TERM "$PPID"
  exit 143
fi
exec /bin/mv "$@"
"#,
    )
    .unwrap();
    fs::set_permissions(&fake_mv, fs::Permissions::from_mode(0o755)).unwrap();
    let inherited_path = std::env::var_os("PATH").unwrap();
    let path =
        std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(&inherited_path)))
            .unwrap();
    let status = Command::new(project_root().join("scripts/import-xmlsec1-cli-fixtures.sh"))
        .env("XMLSEC_DONOR_ROOT", donor_tests())
        .env("XMLSEC_FIXTURE_TARGET", &target)
        .env("MV_COUNT_FILE", temp.path().join("mv-count"))
        .env("PATH", path)
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(
        fs::read_to_string(target.join("sentinel")).unwrap(),
        "previous snapshot"
    );
    let debris = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().starts_with("snapshot."))
        .collect::<Vec<_>>();
    assert!(debris.is_empty(), "transaction debris remains: {debris:?}");
}
