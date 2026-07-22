//! Integration coverage for the donor fixture import workflow.

use std::path::{Path, PathBuf};
use std::process::Command;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "xml-sec-fixture-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must follow the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("temporary test directory must be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("temporary test directory must be removable");
    }
}

#[test]
fn directory_import_removes_files_deleted_by_the_donor() {
    // A complete-directory import is a reproducible snapshot, not an overlay:
    // files removed upstream must not survive and alter corpus accounting.
    let root = TestDirectory::new();
    let scripts = root.path().join("scripts");
    let donor = root.path().join("donor/corpus");
    let target = root.path().join("tests/fixtures/xmlenc/corpus");
    std::fs::create_dir_all(&scripts).expect("scripts directory must be creatable");
    std::fs::create_dir_all(&donor).expect("donor directory must be creatable");
    std::fs::create_dir_all(&target).expect("fixture directory must be creatable");
    std::fs::copy(
        "scripts/import-donor-fixtures.sh",
        scripts.join("import-donor-fixtures.sh"),
    )
    .expect("import script must be copied into the isolated repository");
    std::fs::write(donor.join("current.xml"), "<current/>")
        .expect("donor fixture must be writable");
    std::fs::write(target.join("obsolete.xml"), "<obsolete/>")
        .expect("obsolete fixture must be writable");

    let status = Command::new("bash")
        .arg(scripts.join("import-donor-fixtures.sh"))
        .arg("xmlenc/corpus")
        .env("XMLSEC_DONOR_ROOT", root.path().join("donor"))
        .status()
        .expect("fixture import script must run");

    assert!(status.success(), "fixture import must succeed");
    assert_eq!(
        std::fs::read_to_string(target.join("current.xml"))
            .expect("current donor fixture must be imported"),
        "<current/>"
    );
    assert!(
        !target.join("obsolete.xml").exists(),
        "directory import must remove fixtures deleted by the donor"
    );
}

#[test]
fn directory_import_rejects_paths_that_escape_the_fixture_root() {
    // Directory synchronization removes its destination before copying. Reject
    // traversal before that step so only repository fixture trees are mutable.
    let root = TestDirectory::new();
    let scripts = root.path().join("scripts");
    let donor_escape = root.path().join("escape");
    let target_escape = root.path().join("tests/fixtures/escape");
    std::fs::create_dir_all(&scripts).expect("scripts directory must be creatable");
    std::fs::create_dir_all(&donor_escape).expect("donor directory must be creatable");
    std::fs::create_dir_all(&target_escape).expect("fixture directory must be creatable");
    std::fs::copy(
        "scripts/import-donor-fixtures.sh",
        scripts.join("import-donor-fixtures.sh"),
    )
    .expect("import script must be copied into the isolated repository");
    std::fs::write(donor_escape.join("replacement.xml"), "<replacement/>")
        .expect("donor fixture must be writable");
    std::fs::write(target_escape.join("sentinel.xml"), "<sentinel/>")
        .expect("sentinel fixture must be writable");

    let status = Command::new("bash")
        .arg(scripts.join("import-donor-fixtures.sh"))
        .arg("xmlenc/../escape")
        .env("XMLSEC_DONOR_ROOT", root.path().join("donor"))
        .status()
        .expect("fixture import script must run");

    assert!(!status.success(), "path traversal must be rejected");
    assert!(
        target_escape.join("sentinel.xml").exists(),
        "rejected paths must not mutate files outside their corpus"
    );
}

#[test]
fn directory_import_rejects_fixture_root_aliases() {
    // Empty and current-directory components can normalize to the corpus root;
    // no user-supplied path may authorize replacing that whole directory.
    for fixture_path in ["xmlenc/.", "xmlenc//", "xmlenc/./"] {
        let root = TestDirectory::new();
        let scripts = root.path().join("scripts");
        let donor = root.path().join("donor");
        let target = root.path().join("tests/fixtures/xmlenc");
        std::fs::create_dir_all(&scripts).expect("scripts directory must be creatable");
        std::fs::create_dir_all(&donor).expect("donor directory must be creatable");
        std::fs::create_dir_all(&target).expect("fixture directory must be creatable");
        std::fs::copy(
            "scripts/import-donor-fixtures.sh",
            scripts.join("import-donor-fixtures.sh"),
        )
        .expect("import script must be copied into the isolated repository");
        std::fs::write(donor.join("replacement.xml"), "<replacement/>")
            .expect("donor fixture must be writable");
        std::fs::write(target.join("sentinel.xml"), "<sentinel/>")
            .expect("sentinel fixture must be writable");

        let status = Command::new("bash")
            .arg(scripts.join("import-donor-fixtures.sh"))
            .arg(fixture_path)
            .env("XMLSEC_DONOR_ROOT", &donor)
            .status()
            .expect("fixture import script must run");

        assert!(!status.success(), "{fixture_path} must be rejected");
        assert!(
            target.join("sentinel.xml").exists(),
            "rejected alias {fixture_path} must not replace the corpus root"
        );
    }
}
