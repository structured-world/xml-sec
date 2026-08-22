#![cfg(unix)]

//! Integration coverage for the pinned xmlsec1 installation workflow.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const DONOR_COMMIT: &str = include_str!("../compatibility/libxmlsec1-1.3.13-donor-commit.txt");

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
            "#!/bin/sh\nif [ \"$1\" = \"init\" ]; then mkdir -p \"$2\"; exit 0; fi\n[ \"$1\" = \"-C\" ] || exit 2\nsource=$2\nshift 2\ncommand=$1\nshift\ncase \"$command\" in\n  remote) exit 0 ;;\n  fetch)\n    for argument in \"$@\"; do requested=$argument; done\n    printf '%s\\n' \"${GIT_REPORTED_COMMIT:-$requested}\" > \"$GIT_FETCHED_COMMIT_FILE\"\n    printf '#!/bin/sh\\nexit 0\\n' > \"$source/autogen.sh\"\n    chmod +x \"$source/autogen.sh\"\n    ;;\n  rev-parse)\n    if [ \"${1:-}\" = \"--is-inside-work-tree\" ]; then\n      [ -e \"$source/.git\" ] || exit 128\n      printf 'true\\n'\n    elif [ -n \"${XMLSEC1_SOURCE_DIR:-}\" ] && [ \"$source\" = \"$XMLSEC1_SOURCE_DIR\" ]; then\n      printf '%s\\n' \"$GIT_REPORTED_COMMIT\"\n    else\n      cat \"$GIT_FETCHED_COMMIT_FILE\"\n    fi\n    ;;\n  archive) /usr/bin/tar -C \"$source\" -cf - autogen.sh ;;\n  checkout) exit 0 ;;\n  *) exit 2 ;;\nesac\n",
        );
        root.tool("nproc", "#!/bin/sh\nprintf '1\\n'\n");
        root.tool(
          "make",
          "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in DESTDIR=*) dest=${arg#DESTDIR=} ;; esac\ndone\nif [ -n \"${dest:-}\" ]; then\n  mkdir -p \"$dest$XMLSEC1_PREFIX/bin\"\n  printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"${XMLSEC1_SMOKE_OUTPUT-xmlsec1 1.3.13 (openssl)}\"\\nexit \"${XMLSEC1_SMOKE_EXIT:-0}\"\\n' > \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\n  chmod +x \"$dest$XMLSEC1_PREFIX/bin/xmlsec1\"\nfi\n",
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
        smoke_output: Option<&str>,
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
        if let Some(smoke_output) = smoke_output {
            command.env("XMLSEC1_SMOKE_OUTPUT", smoke_output);
        }
        command.status().expect("installation script must run")
    }

    fn run_from_source(&self, source: &Path) -> std::process::ExitStatus {
        let inherited_path = std::env::var_os("PATH").expect("test process must have PATH");
        let path = std::env::join_paths(
            std::iter::once(self.tools.clone()).chain(std::env::split_paths(&inherited_path)),
        )
        .expect("test PATH must be joinable");
        Command::new("bash")
            .arg("scripts/install-xmlsec1.sh")
            .env("XMLSEC1_PREFIX", &self.prefix)
            .env("XMLSEC1_SOURCE_DIR", source)
            .env("GIT_REPORTED_COMMIT", DONOR_COMMIT.trim())
            .env(
                "GIT_FETCHED_COMMIT_FILE",
                self.root.path().join("fetched-commit"),
            )
            .env("MV_COUNT_FILE", self.root.path().join("mv-count"))
            .env("PATH", path)
            .status()
            .expect("installation script must run")
    }
}

#[test]
fn failed_install_replacement_restores_previous_xmlsec() {
    // The staged directory move is the commit point. A failure there must
    // leave the previously working installation intact rather than letting
    // EXIT cleanup delete its backup.
    let harness = InstallHarness::new();
    let status = harness.run(Some(2), None, None, None);

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
    let status = harness.run(
        None,
        Some("0000000000000000000000000000000000000000"),
        None,
        None,
    );

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
fn installer_accepts_a_linked_worktree_source_checkout() {
    // Linked worktrees represent .git as a file. Repository identity must come
    // from Git rather than a filesystem-shape assumption.
    let harness = InstallHarness::new();
    let source = harness.root.path().join("linked-worktree");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join(".git"), "gitdir: /tmp/fake-worktree\n").unwrap();
    let autogen = source.join("autogen.sh");
    std::fs::write(&autogen, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&autogen, std::fs::Permissions::from_mode(0o755)).unwrap();

    let status = harness.run_from_source(&source);

    assert!(
        status.success(),
        "linked worktree checkout must be accepted"
    );
    assert!(!harness.prefix.join("sentinel").exists());
}

#[test]
fn failed_first_install_removes_promoted_prefix() {
    // A failed smoke test must not leave an executable plus source marker that
    // a later invocation could mistake for a validated installation.
    let harness = InstallHarness::without_previous_install();
    let status = harness.run(None, None, Some(17), None);

    assert!(!status.success(), "injected smoke failure must propagate");
    assert!(
        !harness.prefix.exists(),
        "failed first installation must remove its promoted prefix"
    );
}

#[test]
fn malformed_version_output_restores_previous_installation() {
    // Exit status alone is not source identity: a successful binary with an
    // unexpected version must not replace the previously validated install.
    let harness = InstallHarness::new();
    for output in ["", "xmlsec1", "xmlsec1 1.3.12", "other 1.3.13"] {
        let status = harness.run(None, None, None, Some(output));

        assert!(
            !status.success(),
            "unexpected version output {output:?} must fail closed"
        );
        assert_eq!(
            std::fs::read_to_string(harness.prefix.join("sentinel"))
                .expect("version mismatch must restore the previous installation"),
            "previous installation"
        );
        assert!(!harness.prefix.join(".xmlsec-source-commit").exists());
    }
}

#[test]
fn exact_version_output_commits_the_new_installation() {
    let harness = InstallHarness::new();
    let status = harness.run(None, None, None, Some("xmlsec1 1.3.13 (openssl)"));

    assert!(status.success(), "the pinned version must pass validation");
    assert!(!harness.prefix.join("sentinel").exists());
    assert_eq!(
        std::fs::read_to_string(harness.prefix.join(".xmlsec-source-commit"))
            .expect("successful validation must write the source marker"),
        format!("{}\n", DONOR_COMMIT.trim())
    );
}

#[test]
fn cached_installation_is_revalidated_before_reuse() {
    // A commit marker authenticates the source used at installation time, not
    // the executable currently occupying the prefix.
    let harness = InstallHarness::new();
    let binary = harness.prefix.join("bin/xmlsec1");
    std::fs::write(&binary, "#!/bin/sh\nprintf 'xmlsec1 1.3.12 (openssl)\\n'\n")
        .expect("cached test binary must be writable");
    let mut permissions = std::fs::metadata(&binary)
        .expect("cached binary metadata must be readable")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&binary, permissions).expect("cached binary must be executable");
    std::fs::write(harness.prefix.join(".xmlsec-source-commit"), DONOR_COMMIT)
        .expect("cached source marker must be writable");

    let status = harness.run(None, None, None, None);

    assert!(
        status.success(),
        "invalid cache must be rebuilt successfully"
    );
    assert!(
        !harness.prefix.join("sentinel").exists(),
        "the stale cached prefix must not be reused"
    );
}
