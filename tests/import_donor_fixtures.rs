//! Integration coverage for the donor fixture import workflow.

use std::path::{Path, PathBuf};
use std::process::Command;

use std::os::unix::fs::PermissionsExt;

/// Isolated repository-shaped directory removed after each importer test.
struct TestDirectory(PathBuf);

impl TestDirectory {
    /// Creates a process-unique temporary directory for one test scenario.
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

    /// Returns the temporary repository root.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    /// Removes every donor, fixture, and fake tool created by the scenario.
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("temporary test directory must be removable");
    }
}

/// Verifies that directory imports are snapshots rather than stale overlays.
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

/// Verifies that parent traversal cannot mutate an adjacent fixture tree.
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

/// Verifies that normalized aliases cannot authorize replacing a corpus root.
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

/// Verifies that enumeration and copy failures preserve the last good snapshot.
#[test]
fn directory_import_failures_preserve_the_existing_snapshot() {
    // Enumeration and copy failures must happen entirely in staging. The last
    // known-good fixture tree remains authoritative until a full import exists.
    for failing_tool in ["find", "install"] {
        let root = TestDirectory::new();
        let scripts = root.path().join("scripts");
        let donor = root.path().join("donor/corpus");
        let target = root.path().join("tests/fixtures/xmlenc/corpus");
        let tools = root.path().join("tools");
        for directory in [&scripts, &donor, &target, &tools] {
            std::fs::create_dir_all(directory).expect("test directory must be creatable");
        }
        std::fs::copy(
            "scripts/import-donor-fixtures.sh",
            scripts.join("import-donor-fixtures.sh"),
        )
        .expect("import script must be copied into the isolated repository");
        std::fs::write(donor.join("current.xml"), "<current/>")
            .expect("donor fixture must be writable");
        std::fs::write(target.join("sentinel.xml"), "<sentinel/>")
            .expect("sentinel fixture must be writable");

        let fake_tool = tools.join(failing_tool);
        std::fs::write(&fake_tool, "#!/bin/sh\nexit 23\n").expect("failing tool must be writable");
        let mut permissions = std::fs::metadata(&fake_tool)
            .expect("failing tool metadata must be readable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_tool, permissions).expect("failing tool must be executable");
        let inherited_path = std::env::var_os("PATH").expect("test process must have PATH");
        let path = std::env::join_paths(
            std::iter::once(tools.clone()).chain(std::env::split_paths(&inherited_path)),
        )
        .expect("test PATH must be joinable");

        let status = Command::new("bash")
            .arg(scripts.join("import-donor-fixtures.sh"))
            .arg("xmlenc/corpus")
            .env("XMLSEC_DONOR_ROOT", root.path().join("donor"))
            .env("PATH", path)
            .status()
            .expect("fixture import script must run");

        assert!(!status.success(), "{failing_tool} failure must propagate");
        assert_eq!(
            std::fs::read_to_string(target.join("sentinel.xml"))
                .expect("existing snapshot must survive a failed import"),
            "<sentinel/>",
            "{failing_tool} failure replaced the existing snapshot"
        );
        assert!(
            !target.join("current.xml").exists(),
            "failed import must not expose a partial replacement"
        );
    }
}

/// Verifies that an upstream directory-to-file transition removes stale children.
#[test]
fn file_import_replaces_an_existing_directory() {
    // A donor path may change type between upstream revisions. Importing a
    // regular file must replace the previous directory snapshot, not copy the
    // file beneath that stale directory.
    let root = TestDirectory::new();
    let scripts = root.path().join("scripts");
    let donor = root.path().join("donor/corpus");
    let target = root.path().join("tests/fixtures/xmlenc/corpus");
    std::fs::create_dir_all(&scripts).expect("scripts directory must be creatable");
    std::fs::create_dir_all(&target).expect("fixture directory must be creatable");
    std::fs::create_dir_all(donor.parent().expect("donor file must have a parent"))
        .expect("donor parent directory must be creatable");
    std::fs::copy(
        "scripts/import-donor-fixtures.sh",
        scripts.join("import-donor-fixtures.sh"),
    )
    .expect("import script must be copied into the isolated repository");
    std::fs::write(&donor, "current fixture").expect("donor fixture must be writable");
    std::fs::write(target.join("obsolete.xml"), "<obsolete/>")
        .expect("stale fixture must be writable");

    let status = Command::new("bash")
        .arg(scripts.join("import-donor-fixtures.sh"))
        .arg("xmlenc/corpus")
        .env("XMLSEC_DONOR_ROOT", root.path().join("donor"))
        .status()
        .expect("fixture import script must run");

    assert!(status.success(), "file import must succeed");
    assert!(target.is_file(), "the target must become a regular file");
    assert_eq!(
        std::fs::read_to_string(&target).expect("imported fixture must be readable"),
        "current fixture"
    );
    assert!(
        !target.join("obsolete.xml").exists(),
        "the previous directory contents must not survive"
    );
}
