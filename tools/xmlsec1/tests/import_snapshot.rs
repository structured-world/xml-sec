use std::{fs, path::Path, process::Command};

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
}

#[test]
fn check_mode_detects_drift_without_replacing_the_snapshot() {
    // The CI reproducibility gate must be observational: drift fails the check
    // and leaves the candidate snapshot untouched for diagnosis.
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("snapshot");
    let donor = project_root().join("tools/xmlsec1/tests/fixtures/upstream");
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
