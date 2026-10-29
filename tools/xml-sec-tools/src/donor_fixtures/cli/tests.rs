use super::{ASSETS, execute, pinned};
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

/// A donor checkout whose `tests` tree holds every asset, its pin and a target.
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
        let donor = Self { directory, commit };
        donor.pin(&format!("{}\n", donor.commit));
        donor
    }

    fn tests(&self) -> PathBuf {
        self.directory.path().join("xmlsec/tests")
    }

    fn target(&self) -> PathBuf {
        self.directory.path().join("snapshot")
    }

    fn pin_path(&self) -> PathBuf {
        self.directory.path().join("pin.txt")
    }

    fn pin(&self, text: &str) {
        std::fs::write(self.pin_path(), text).unwrap();
    }

    fn import(&self, check: bool) -> Result<(), String> {
        execute(&self.tests(), &self.target(), &self.pin_path(), check)
    }
}

#[test]
fn an_import_copies_every_asset_with_its_commit_and_runner_modes() {
    // The snapshot names its provenance; runner scripts stay executable.
    use std::os::unix::fs::PermissionsExt as _;
    let donor = Donor::new();
    donor.import(false).unwrap();
    let target = donor.target();
    assert_eq!(
        std::fs::read_to_string(target.join("DONOR_COMMIT")).unwrap(),
        format!("{}\n", donor.commit)
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
    donor.import(true).unwrap();
}

#[test]
fn a_check_detects_drift_without_replacing_the_snapshot() {
    // The CI gate observes; drift fails and stays in place for diagnosis.
    let donor = Donor::new();
    donor.import(false).unwrap();
    let changed = donor.target().join("testDSig.sh");
    std::fs::write(&changed, "local drift\n").unwrap();
    let error = donor.import(true).unwrap_err();
    assert!(error.contains("testDSig.sh"), "{error}");
    assert_eq!(std::fs::read_to_string(changed).unwrap(), "local drift\n");
}

#[test]
fn missing_empty_and_malformed_pins_fail_closed() {
    // Without an exact donor commit there is no provenance for the snapshot.
    let donor = Donor::new();
    for text in ["", "\n", "HEAD\n", "0123\n"] {
        donor.pin(text);
        assert!(pinned(&donor.pin_path()).is_err(), "{text:?}");
        assert!(donor.import(false).is_err(), "{text:?}");
    }
    std::fs::remove_file(donor.pin_path()).unwrap();
    assert!(donor.import(false).is_err());
    assert!(!donor.target().exists());
}

#[test]
fn a_checkout_at_another_revision_is_refused() {
    // A well-formed pin proves nothing unless it is the copied checkout.
    let donor = Donor::new();
    donor.pin(&format!("{}\n", "0".repeat(40)));
    let error = donor.import(false).unwrap_err();
    assert!(error.contains("does not match pin"), "{error}");
}

#[test]
fn a_locally_changed_asset_is_refused() {
    // The bytes copied must be the pinned commit's, not a worktree edit.
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
