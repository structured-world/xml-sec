#![cfg(unix)]

//! Integration coverage for the pinned xmlsec1 installation workflow.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "xml-sec-install-{}-{}",
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

    fn tool(&self, name: &str, source: &str) {
        let path = self.path().join("tools").join(name);
        std::fs::write(&path, source).expect("fake tool must be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("fake tool metadata must be readable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("fake tool must be executable");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("temporary test directory must be removable");
    }
}

struct InstallHarness {
    root: TestDirectory,
    tools: PathBuf,
    prefix: PathBuf,
}

impl InstallHarness {
    fn new() -> Self {
        Self::with_previous_install(true)
    }

    fn without_previous_install() -> Self {
        Self::with_previous_install(false)
    }

    fn with_previous_install(has_previous_install: bool) -> Self {
        let root = TestDirectory::new();
        let tools = root.path().join("tools");
        let prefix = root.path().join("xmlsec-prefix");

        if has_previous_install {
            std::fs::create_dir_all(prefix.join("bin"))
                .expect("old installation must be creatable");
            std::fs::write(prefix.join("sentinel"), "previous installation")
                .expect("old installation sentinel must be writable");
        }
        std::fs::create_dir_all(&tools).expect("fake tool directory must be creatable");

        root.tool(
            "git",
            "#!/bin/sh\nif [ \"$1\" = \"init\" ]; then mkdir -p \"$2\"; exit 0; fi\n[ \"$1\" = \"-C\" ] || exit 2\nsource=$2\nshift 2\ncommand=$1\nshift\ncase \"$command\" in\n  remote) exit 0 ;;\n  fetch)\n    for argument in \"$@\"; do requested=$argument; done\n    printf '%s\\n' \"${GIT_REPORTED_COMMIT:-$requested}\" > \"$GIT_FETCHED_COMMIT_FILE\"\n    printf '#!/bin/sh\\nexit 0\\n' > \"$source/autogen.sh\"\n    chmod +x \"$source/autogen.sh\"\n    ;;\n  rev-parse) cat \"$GIT_FETCHED_COMMIT_FILE\" ;;\n  checkout) exit 0 ;;\n  *) exit 2 ;;\nesac\n",
        );
        root.tool("nproc", "#!/bin/sh\nprintf '1\\n'\n");
        root.tool(
            "make",
            "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in DESTDIR=*) dest=${arg#DESTDIR=} ;; esac\ndone\nif [ -n \"${dest:-}\" ]; then\n  mkdir -p \"$dest$XMLSEC1_PREFIX/bin\"\n  printf '#!/bin/sh\\nexit \"${XMLSEC1_SMOKE_EXIT:-0}\"\\n' > \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\n  chmod +x \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\nfi\n",
        );
        root.tool(
            "mv",
            "#!/bin/sh\ncount=0\n[ ! -f \"$MV_COUNT_FILE\" ] || count=$(cat \"$MV_COUNT_FILE\")\ncount=$((count + 1))\nprintf '%s\\n' \"$count\" > \"$MV_COUNT_FILE\"\n[ \"${MV_FAIL_ON:-0}\" -ne \"$count\" ] || exit 23\nexec /bin/mv \"$@\"\n",
        );

        Self {
            root,
            tools,
            prefix,
        }
    }

    fn run(
        &self,
        mv_fail_on: Option<u8>,
        reported_commit: Option<&str>,
        smoke_exit: Option<u8>,
    ) -> std::process::ExitStatus {
        let inherited_path = std::env::var_os("PATH").expect("test process must have PATH");
        let path = std::env::join_paths(
            std::iter::once(self.tools.clone()).chain(std::env::split_paths(&inherited_path)),
        )
        .expect("test PATH must be joinable");
        let mut command = Command::new("bash");
        command
            .arg("scripts/install-xmlsec1.sh")
            .env("XMLSEC1_PREFIX", &self.prefix)
            .env(
                "GIT_FETCHED_COMMIT_FILE",
                self.root.path().join("fetched-commit"),
            )
            .env("MV_COUNT_FILE", self.root.path().join("mv-count"))
            .env("PATH", path);
        if let Some(mv_fail_on) = mv_fail_on {
            command.env("MV_FAIL_ON", mv_fail_on.to_string());
        }
        if let Some(reported_commit) = reported_commit {
            command.env("GIT_REPORTED_COMMIT", reported_commit);
        }
        if let Some(smoke_exit) = smoke_exit {
            command.env("XMLSEC1_SMOKE_EXIT", smoke_exit.to_string());
        }
        command.status().expect("installation script must run")
    }
}

#[test]
fn failed_install_replacement_restores_previous_xmlsec() {
    // The staged directory move is the commit point. A failure there must
    // leave the previously working installation intact rather than letting
    // EXIT cleanup delete its backup.
    let harness = InstallHarness::new();
    let status = harness.run(Some(2), None, None);

    assert!(
        !status.success(),
        "injected staged move failure must propagate"
    );
    assert_eq!(
        std::fs::read_to_string(harness.prefix.join("sentinel"))
            .expect("previous installation must be restored"),
        "previous installation"
    );
}

#[test]
fn installer_rejects_source_revision_mismatch() {
    // Artifact compression is not source identity. The installer must reject
    // a fetch whose resolved Git object differs from the pinned commit.
    let harness = InstallHarness::new();
    let status = harness.run(None, Some("0000000000000000000000000000000000000000"), None);

    assert!(
        !status.success(),
        "mismatched source revision must fail closed"
    );
    assert_eq!(
        std::fs::read_to_string(harness.prefix.join("sentinel"))
            .expect("failed source verification must preserve the previous installation"),
        "previous installation"
    );
}

#[test]
fn failed_first_install_removes_promoted_prefix() {
    // A failed smoke test must not leave an executable plus source marker that
    // a later invocation could mistake for a validated installation.
    let harness = InstallHarness::without_previous_install();
    let status = harness.run(None, None, Some(17));

    assert!(!status.success(), "injected smoke failure must propagate");
    assert!(
        !harness.prefix.exists(),
        "failed first installation must remove its promoted prefix"
    );
}
