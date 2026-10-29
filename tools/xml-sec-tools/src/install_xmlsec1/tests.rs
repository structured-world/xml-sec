use super::{COMPATIBILITY, Install, MODERN, execute, version_matches};
use crate::repo::{Run, Step};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

const COMMIT: &str = "5fdd47dc35753438bdc38b6e96c1a3805c67a483";

fn listed(transforms: &[&str]) -> String {
    let quoted: Vec<String> = transforms
        .iter()
        .map(|transform| format!("\"{transform}\""))
        .collect();
    quoted.join(",") + "\n"
}

fn executable(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A build toolchain that records each step and answers the oracle's queries.
struct Toolchain {
    prefix: PathBuf,
    /// The answer of the binary already in the prefix, to the first query.
    cached_version: Option<String>,
    version: String,
    transforms: String,
    revision: String,
    installs: bool,
    labels: Vec<String>,
}

impl Toolchain {
    fn new(prefix: &Path) -> Self {
        Self {
            prefix: prefix.to_owned(),
            cached_version: None,
            version: "xmlsec1 1.3.13 (openssl)\n".into(),
            transforms: listed(&COMPATIBILITY),
            revision: COMMIT.into(),
            installs: true,
            labels: Vec::new(),
        }
    }
}

fn exit(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

impl Run for Toolchain {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        self.labels.push(step.label.clone());
        match step.label.as_str() {
            "source init" => {
                std::fs::create_dir_all(&step.args[1]).map_err(|error| error.to_string())?;
            }
            "source export" => {
                let output = step
                    .args
                    .iter()
                    .find_map(|arg| arg.strip_prefix("--output="))
                    .unwrap();
                let mut archive = tar::Builder::new(std::fs::File::create(output).unwrap());
                let mut header = tar::Header::new_gnu();
                header.set_size(10);
                header.set_mode(0o755);
                archive
                    .append_data(&mut header, "autogen.sh", &b"#!/bin/sh\n"[..])
                    .unwrap();
                archive.finish().unwrap();
            }
            "OpenSSL download" => return Ok(exit(42)),
            "xmlsec1 install" if self.installs => {
                let stage = step
                    .args
                    .iter()
                    .find_map(|arg| arg.strip_prefix("DESTDIR="))
                    .unwrap();
                let staged = Path::new(stage).join(self.prefix.strip_prefix("/").unwrap());
                executable(&staged.join("bin/xmlsec1"), "#!/bin/sh\n");
            }
            _ => {}
        }
        Ok(exit(0))
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        self.labels.push(step.label.clone());
        let answer = match step.label.as_str() {
            "source repository" => "true\n".to_owned(),
            "source revision" | "fetched revision" => format!("{}\n", self.revision),
            "xmlsec1 --version" => self
                .cached_version
                .take()
                .unwrap_or_else(|| self.version.clone()),
            "xmlsec1 --list-transforms" => self.transforms.clone(),
            other => return Err(format!("unexpected query: {other}")),
        };
        Ok((exit(0), answer))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected combined run: {}", step.label))
    }
}

/// A prefix holding a previous installation with a sentinel file.
struct Prefix {
    directory: tempfile::TempDir,
}

impl Prefix {
    fn new(previous: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let prefix = Self { directory };
        if previous {
            std::fs::create_dir_all(prefix.path().join("bin")).unwrap();
            std::fs::write(prefix.path().join("sentinel"), "previous installation").unwrap();
        }
        prefix
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("xmlsec-prefix")
    }

    fn install(&self, modern: bool, source: Option<PathBuf>) -> Install {
        Install {
            prefix: self.path(),
            commit: COMMIT.into(),
            modern,
            source,
            library_path: None,
        }
    }

    fn previous_kept(&self) -> bool {
        std::fs::read_to_string(self.path().join("sentinel"))
            .is_ok_and(|text| text == "previous installation")
    }

    fn debris(&self) -> Vec<String> {
        std::fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".xmlsec1"))
            .collect()
    }
}

#[test]
fn only_the_pinned_version_line_qualifies() {
    // Exit status is not identity: the first line must name xmlsec1 1.3.13.
    assert!(version_matches("xmlsec1 1.3.13 (openssl)\nmore"));
    for output in [
        "",
        "xmlsec1",
        "xmlsec1 1.3.12",
        "other 1.3.13",
        "\nxmlsec1 1.3.13",
    ] {
        assert!(!version_matches(output), "{output:?}");
    }
}

#[test]
fn an_exact_version_commits_the_new_installation_and_its_marker() {
    // The marker is written only after validation, and the previous build goes.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(!prefix.path().join("sentinel").exists());
    assert_eq!(
        std::fs::read_to_string(prefix.path().join(".xmlsec-source-commit")).unwrap(),
        format!("{COMMIT}\n")
    );
    assert_eq!(prefix.debris(), Vec::<String>::new());
}

#[test]
fn an_unexpected_version_restores_the_previous_installation() {
    // A successful binary with another version never replaces a validated one.
    for output in ["", "xmlsec1\n", "xmlsec1 1.3.12\n", "other 1.3.13\n"] {
        let prefix = Prefix::new(true);
        let mut toolchain = Toolchain::new(&prefix.path());
        toolchain.version = output.into();
        let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
        assert!(error.contains("version mismatch"), "{output:?}: {error}");
        assert!(prefix.previous_kept(), "{output:?}");
        assert!(!prefix.path().join(".xmlsec-source-commit").exists());
        assert_eq!(prefix.debris(), Vec::<String>::new());
    }
}

#[test]
fn an_oracle_without_the_xslt_transform_is_refused() {
    // Without libxslt there is no XSLT transform; installation fails instead
    // of the XSLT interoperability tests.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.transforms = listed(&COMPATIBILITY[..7]);
    let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
    assert!(error.contains("missing required"), "{error}");
    assert!(prefix.previous_kept());
}

#[test]
fn a_fetched_revision_other_than_the_pin_is_refused_before_building() {
    // A compressed artifact is not source identity; the resolved commit is.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.revision = "0".repeat(40);
    let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
    assert!(error.contains("revision mismatch"), "{error}");
    assert!(prefix.previous_kept());
    assert!(
        !toolchain
            .labels
            .iter()
            .any(|label| label == "xmlsec1 build")
    );
}

#[test]
fn a_linked_worktree_source_checkout_is_accepted() {
    // Linked worktrees store .git as a file; Git, not the file system shape,
    // decides what a checkout is.
    let prefix = Prefix::new(true);
    let source = prefix.directory.path().join("linked-worktree");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join(".git"), "gitdir: /elsewhere\n").unwrap();
    let mut toolchain = Toolchain::new(&prefix.path());
    execute(&mut toolchain, &prefix.install(false, Some(source))).unwrap();
    assert!(!prefix.path().join("sentinel").exists());
    assert!(
        toolchain
            .labels
            .iter()
            .any(|label| label == "source export")
    );
}

#[test]
fn a_failed_first_installation_leaves_no_prefix() {
    // An executable plus marker from a failed run would pass for a validated cache.
    let prefix = Prefix::new(false);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.version = "xmlsec1 1.3.12\n".into();
    assert!(execute(&mut toolchain, &prefix.install(false, None)).is_err());
    assert!(!prefix.path().exists());
}

#[test]
fn a_failed_promotion_restores_the_previous_installation() {
    // The staged rename is the commit point; failing there keeps the old build.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.installs = false;
    assert!(execute(&mut toolchain, &prefix.install(false, None)).is_err());
    assert!(prefix.previous_kept());
    assert_eq!(prefix.debris(), Vec::<String>::new());
}

/// A prefix whose previous installation is a cache of the pinned commit.
fn cached() -> Prefix {
    let prefix = Prefix::new(true);
    executable(&prefix.path().join("bin/xmlsec1"), "#!/bin/sh\n");
    std::fs::write(
        prefix.path().join(".xmlsec-source-commit"),
        format!("{COMMIT}\n"),
    )
    .unwrap();
    prefix
}

fn built(toolchain: &Toolchain) -> bool {
    toolchain
        .labels
        .iter()
        .any(|label| label == "xmlsec1 build")
}

#[test]
fn a_valid_cache_is_reused_without_building() {
    // A cache that still passes every check needs no rebuild.
    let prefix = cached();
    let mut toolchain = Toolchain::new(&prefix.path());
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(prefix.previous_kept());
    assert!(!built(&toolchain));
}

#[test]
fn a_cached_binary_of_another_version_is_rebuilt() {
    // The marker names the source used then, not the binary there now.
    let prefix = cached();
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.cached_version = Some("xmlsec1 1.3.12 (openssl)\n".into());
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(built(&toolchain));
    assert!(!prefix.path().join("sentinel").exists());
}

#[test]
fn a_modern_cache_without_eddsa_is_rebuilt_and_a_failed_rebuild_keeps_it() {
    // A version marker cannot prove that OpenSSL compiled the required
    // algorithms; an older cached backend never satisfies the modern profile.
    let prefix = cached();
    let mut toolchain = Toolchain::new(&prefix.path());
    assert!(
        !MODERN
            .iter()
            .any(|transform| toolchain.transforms.contains(transform))
    );
    let error = execute(&mut toolchain, &prefix.install(true, None)).unwrap_err();
    assert!(error.contains("OpenSSL download"), "{error}");
    assert!(prefix.previous_kept());
}
