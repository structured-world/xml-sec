use super::{ASSETS, execute};
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A donor checkout whose `tests` tree holds every asset, and a target.
struct Donor {
    directory: tempfile::TempDir,
    commit: String,
}

impl Donor {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("xmlsec");
        std::fs::create_dir_all(&repository).unwrap();
        git(&repository, &["init", "--quiet"]);
        for asset in ASSETS {
            let path = repository.join("tests").join(asset);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("donor {asset}\n")).unwrap();
        }
        git(&repository, &["add", "."]);
        git(&repository, &["commit", "--quiet", "-m", "donor"]);
        let commit = git(&repository, &["rev-parse", "HEAD"]);
        Self { directory, commit }
    }

    fn tests(&self) -> PathBuf {
        self.directory.path().join("xmlsec/tests")
    }

    fn target(&self) -> PathBuf {
        self.directory.path().join("snapshot")
    }

    fn import(&self, check: bool) -> Result<String, String> {
        execute(&self.tests(), &self.target(), check)
    }
}

#[test]
fn an_import_copies_every_asset_and_reports_its_commit() {
    // The run names the upstream commit it copied, the snapshot stores none,
    // and runner scripts stay executable.
    use std::os::unix::fs::PermissionsExt as _;
    let donor = Donor::new();
    assert_eq!(donor.import(false).unwrap(), donor.commit);
    let target = donor.target();
    let mut stored: Vec<_> = std::fs::read_dir(&target)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    stored.sort();
    assert_eq!(
        stored,
        [
            "aleksey-xmldsig-01",
            "phaos-xmldsig-three",
            "testDSig.sh",
            "testEnc.sh",
            "testKeys.sh",
            "testrun.sh",
            "xmlenc11-interop-2012",
        ]
    );
    for asset in ASSETS {
        assert_eq!(
            std::fs::read_to_string(target.join(asset)).unwrap(),
            format!("donor {asset}\n")
        );
    }
    let mode = |name: &str| {
        std::fs::metadata(target.join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("testDSig.sh"), 0o755);
    assert_eq!(mode("phaos-xmldsig-three/certs/rsa-ca-cert.der"), 0o644);
    assert_eq!(donor.import(true).unwrap(), donor.commit);
}

#[test]
fn a_check_detects_drift_without_replacing_the_snapshot() {
    // The CI gate observes; drift fails, names the upstream commit and stays
    // in place for diagnosis.
    let donor = Donor::new();
    donor.import(false).unwrap();
    let changed = donor.target().join("testDSig.sh");
    std::fs::write(&changed, "local drift\n").unwrap();
    let error = donor.import(true).unwrap_err();
    assert!(error.contains("testDSig.sh"), "{error}");
    assert!(error.contains(&donor.commit), "{error}");
    assert_eq!(std::fs::read_to_string(changed).unwrap(), "local drift\n");
}

#[test]
fn a_newer_upstream_commit_is_drift_until_regenerated() {
    // Upstream moving on is the signal: the check fails on the changed asset
    // and passes once the snapshot is copied from the new commit.
    let donor = Donor::new();
    donor.import(false).unwrap();
    let repository = donor.directory.path().join("xmlsec");
    std::fs::write(repository.join("tests/testEnc.sh"), "upstream edit\n").unwrap();
    git(&repository, &["commit", "--quiet", "-am", "upstream"]);
    let newer = git(&repository, &["rev-parse", "HEAD"]);
    let error = donor.import(true).unwrap_err();
    assert!(error.contains("testEnc.sh"), "{error}");
    assert!(error.contains(&newer), "{error}");
    assert_eq!(donor.import(false).unwrap(), newer);
    assert_eq!(donor.import(true).unwrap(), newer);
}

#[test]
fn a_locally_changed_asset_is_refused() {
    // The bytes copied must be the checkout commit's, not a worktree edit.
    let donor = Donor::new();
    std::fs::write(donor.tests().join("testEnc.sh"), "edited\n").unwrap();
    let error = donor.import(false).unwrap_err();
    assert!(error.contains("uncommitted changes"), "{error}");
    assert!(!donor.target().exists());
}

#[test]
fn a_failed_import_keeps_the_previous_snapshot_and_no_debris() {
    // Promotion happens only after the complete snapshot is staged.
    let donor = Donor::new();
    std::fs::create_dir_all(donor.target()).unwrap();
    std::fs::write(donor.target().join("sentinel"), "previous snapshot").unwrap();
    std::fs::remove_file(donor.tests().join("testKeys.sh")).unwrap();
    assert!(donor.import(false).is_err());
    assert_eq!(
        std::fs::read_to_string(donor.target().join("sentinel")).unwrap(),
        "previous snapshot"
    );
    let debris: Vec<_> = std::fs::read_dir(donor.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".snapshot"))
        .collect();
    assert_eq!(debris, Vec::<String>::new());
}
