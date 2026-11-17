use super::{
    COMPATIBILITY, Install, MARKER, MODERN, Revision, configured_version, execute, version_matches,
};
use crate::repo::{Run, Step};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

const COMMIT: &str = "90b3d51a2b6f0c9e8d7c6b5a4f3e2d1c0b9a8f7e";
const VERSION: &str = "1.3.14";
const CONFIGURE: &str = "dnl Process this file\nAC_PREREQ([2.69])\nAC_INIT([xmlsec1],[1.3.14],[http://www.aleksey.com/xmlsec])\n";

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
    /// What `git ls-remote` lists for upstream master.
    master: String,
    /// The commit a fetch or a local checkout reports.
    revision: String,
    installs: bool,
    /// A query whose process cannot be started.
    unspawnable: Option<&'static str>,
    labels: Vec<String>,
}

impl Toolchain {
    fn new(prefix: &Path) -> Self {
        Self {
            prefix: prefix.to_owned(),
            cached_version: None,
            version: format!("xmlsec1 {VERSION} (openssl)\n"),
            transforms: listed(&COMPATIBILITY),
            master: format!("{COMMIT}\trefs/heads/master\n"),
            revision: COMMIT.into(),
            installs: true,
            unspawnable: None,
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
            // The fetched tree, as a checkout leaves it.
            "source checkout" => {
                std::fs::write(Path::new(&step.args[1]).join("configure.ac"), CONFIGURE)
                    .map_err(|error| error.to_string())?;
            }
            "source export" => {
                let output = step
                    .args
                    .iter()
                    .find_map(|arg| arg.strip_prefix("--output="))
                    .unwrap();
                let mut archive = tar::Builder::new(std::fs::File::create(output).unwrap());
                for (name, text, mode) in [
                    ("autogen.sh", "#!/bin/sh\n", 0o755),
                    ("configure.ac", CONFIGURE, 0o644),
                ] {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(text.len() as u64);
                    header.set_mode(mode);
                    archive
                        .append_data(&mut header, name, text.as_bytes())
                        .unwrap();
                }
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
        if self.unspawnable == Some(step.label.as_str()) {
            return Err(format!("{}: cannot start", step.label));
        }
        let answer = match step.label.as_str() {
            "upstream master" => self.master.clone(),
            "source repository" => "true\n".to_owned(),
            "source revision" | "fetched revision" => format!("{}\n", self.revision),
            "xmlsec1 --version" => self
                .cached_version
                .take()
                .unwrap_or_else(|| self.version.clone()),
            "xmlsec1 --list-transforms" => self.transforms.clone(),
            "openssl version" => "OpenSSL 3.5.9 30 Sep 2026\n".to_owned(),
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

    fn pin(&self) -> PathBuf {
        self.directory.path().join("donor-commit.txt")
    }

    /// An installation of the pinned commit, with the pin naming [`COMMIT`].
    fn install(&self, modern: bool, source: Option<PathBuf>) -> Install {
        std::fs::write(self.pin(), format!("{COMMIT}\n")).unwrap();
        Install {
            prefix: self.path(),
            modern,
            source,
            library_path: None,
            revision: Revision::Pinned,
            pin: self.pin(),
            record_pin: false,
        }
    }

    /// An installation of upstream master's head.
    fn master(&self) -> Install {
        Install {
            revision: Revision::Master,
            ..self.install(false, None)
        }
    }

    fn previous_kept(&self) -> bool {
        std::fs::read_to_string(self.path().join("sentinel"))
            .is_ok_and(|text| text == "previous installation")
    }

    fn marker(&self) -> Option<String> {
        std::fs::read_to_string(self.path().join(MARKER)).ok()
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
fn only_the_built_version_line_qualifies() {
    // Exit status is not identity: the first line must name xmlsec1 at the
    // version the built source declares.
    assert!(version_matches("xmlsec1 1.3.14 (openssl)\nmore", VERSION));
    for output in [
        "",
        "xmlsec1",
        "xmlsec1 1.3.13",
        "other 1.3.14",
        "\nxmlsec1 1.3.14",
    ] {
        assert!(!version_matches(output, VERSION), "{output:?}");
    }
}

#[test]
fn the_version_comes_from_ac_init() {
    // The second bracketed argument of xmlsec1's AC_INIT, nothing else.
    assert_eq!(configured_version(CONFIGURE).as_deref(), Some(VERSION));
    for configure in [
        "",
        "AC_INIT([other],[1.3.14],[x])\n",
        "AC_INIT([xmlsec1],[],[x])\n",
        "AC_INIT([xmlsec1])\n",
        "dnl AC_INIT([xmlsec1],[1.3.14])\n",
    ] {
        assert_eq!(configured_version(configure), None, "{configure:?}");
    }
}

fn asked_master(toolchain: &Toolchain) -> bool {
    toolchain
        .labels
        .iter()
        .any(|label| label == "upstream master")
}

#[test]
fn a_build_of_the_pin_records_its_commit_and_version() {
    // Without XMLSEC1_REVISION the pinned commit is built, whatever master is;
    // the marker is written only after validation, and the previous build goes.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.master = format!("{}\trefs/heads/master\n", "b".repeat(40));
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(!prefix.path().join("sentinel").exists());
    assert_eq!(prefix.marker(), Some(format!("{COMMIT}\n{VERSION}\n")));
    assert_eq!(prefix.debris(), Vec::<String>::new());
    assert!(!asked_master(&toolchain));
}

#[test]
fn a_build_of_master_builds_its_current_head() {
    // XMLSEC1_REVISION=master builds the head upstream lists now, not the pin.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    let head = "b".repeat(40);
    toolchain.master = format!("{head}\trefs/heads/master\n");
    toolchain.revision = head.clone();
    execute(&mut toolchain, &prefix.master()).unwrap();
    assert!(asked_master(&toolchain));
    assert_eq!(prefix.marker(), Some(format!("{head}\n{VERSION}\n")));
}

#[test]
fn an_explicit_commit_is_built_as_asked() {
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    let commit = "c".repeat(40);
    toolchain.revision = commit.clone();
    let install = Install {
        revision: Revision::Commit(commit.clone()),
        ..prefix.install(false, None)
    };
    execute(&mut toolchain, &install).unwrap();
    assert!(!asked_master(&toolchain));
    assert_eq!(prefix.marker(), Some(format!("{commit}\n{VERSION}\n")));
}

#[test]
fn the_revision_variable_names_the_pin_master_or_one_commit() {
    assert_eq!(Revision::parse(None), Ok(Revision::Pinned));
    assert_eq!(Revision::parse(Some("master")), Ok(Revision::Master));
    assert_eq!(
        Revision::parse(Some(COMMIT)),
        Ok(Revision::Commit(COMMIT.into()))
    );
    // A branch other than master, a short id or an uppercase id would build
    // something no pin can name.
    for value in ["main", "c5ef426d", &COMMIT.to_uppercase(), "", " master"] {
        let error = Revision::parse(Some(value)).unwrap_err();
        assert!(error.contains("XMLSEC1_REVISION"), "{value:?}: {error}");
    }
}

#[test]
fn a_missing_or_malformed_pin_is_refused_before_building() {
    for pin in [
        None,
        Some(""),
        Some("c5ef426d\n"),
        Some(&*format!("{COMMIT}\n{COMMIT}\n")),
    ] {
        let prefix = Prefix::new(true);
        let mut install = prefix.install(false, None);
        match pin {
            Some(text) => std::fs::write(prefix.pin(), text).unwrap(),
            None => std::fs::remove_file(prefix.pin()).unwrap(),
        }
        let mut toolchain = Toolchain::new(&prefix.path());
        install.record_pin = true;
        let error = execute(&mut toolchain, &install).unwrap_err();
        assert!(error.contains("donor-commit.txt"), "{pin:?}: {error}");
        assert!(prefix.previous_kept(), "{pin:?}");
        assert!(!toolchain.labels.iter().any(|label| label == "source init"));
    }
}

#[test]
fn pin_records_the_commit_only_after_its_oracle_passes() {
    // `--pin` moves the oracle: a validated master build becomes the pin, a
    // build that fails its checks leaves the pin where it was.
    let head = "b".repeat(40);
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.master = format!("{head}\trefs/heads/master\n");
    toolchain.revision = head.clone();
    let install = Install {
        record_pin: true,
        ..prefix.master()
    };
    execute(&mut toolchain, &install).unwrap();
    assert_eq!(
        std::fs::read_to_string(prefix.pin()).unwrap(),
        format!("{head}\n")
    );

    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.master = format!("{head}\trefs/heads/master\n");
    toolchain.revision = head;
    toolchain.version = "xmlsec1 1.3.12\n".into();
    let install = Install {
        record_pin: true,
        ..prefix.master()
    };
    assert!(execute(&mut toolchain, &install).is_err());
    assert_eq!(
        std::fs::read_to_string(prefix.pin()).unwrap(),
        format!("{COMMIT}\n")
    );
}

#[test]
fn an_unreadable_master_listing_is_refused_before_building() {
    // A listing without exactly master's commit names nothing to build.
    for listing in [
        "",
        "not-a-commit\trefs/heads/master\n",
        &format!("{COMMIT}\trefs/heads/other\n"),
        &format!("{COMMIT}\trefs/heads/master\n{COMMIT}\trefs/heads/master\n"),
    ] {
        let prefix = Prefix::new(true);
        let mut toolchain = Toolchain::new(&prefix.path());
        toolchain.master = listing.to_owned();
        assert!(
            execute(&mut toolchain, &prefix.master()).is_err(),
            "{listing:?}"
        );
        assert!(prefix.previous_kept(), "{listing:?}");
        assert!(!toolchain.labels.iter().any(|label| label == "source init"));
    }
}

#[test]
fn an_unexpected_version_restores_the_previous_installation() {
    // A successful binary with another version never replaces a validated one.
    for output in ["", "xmlsec1\n", "xmlsec1 1.3.13\n", "other 1.3.14\n"] {
        let prefix = Prefix::new(true);
        let mut toolchain = Toolchain::new(&prefix.path());
        toolchain.version = output.into();
        let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
        assert!(error.contains("version mismatch"), "{output:?}: {error}");
        assert!(prefix.previous_kept(), "{output:?}");
        assert_eq!(prefix.marker(), None);
        assert_eq!(prefix.debris(), Vec::<String>::new());
    }
}

#[test]
fn an_oracle_without_the_xslt_transform_is_refused() {
    // Without libxslt there is no XSLT transform; installation fails instead
    // of the XSLT interoperability tests.
    let prefix = Prefix::new(true);
    let mut toolchain = Toolchain::new(&prefix.path());
    let without_xslt: Vec<&str> = COMPATIBILITY
        .into_iter()
        .filter(|transform| *transform != "xslt")
        .collect();
    toolchain.transforms = listed(&without_xslt);
    let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
    assert!(error.contains("missing required"), "{error}");
    assert!(prefix.previous_kept());
}

#[test]
fn a_fetched_revision_other_than_the_one_asked_is_refused_before_building() {
    // A fetch that brings another commit than the pinned one is not the
    // source asked for.
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

/// A linked worktree under `prefix`'s directory: Git, not the file system
/// shape, decides what a checkout is.
fn worktree(prefix: &Prefix) -> PathBuf {
    let source = prefix.directory.path().join("linked-worktree");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join(".git"), "gitdir: /elsewhere\n").unwrap();
    source
}

#[test]
fn a_local_checkout_at_the_pin_is_exported() {
    let prefix = Prefix::new(true);
    let source = worktree(&prefix);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.master = String::new();
    execute(&mut toolchain, &prefix.install(false, Some(source))).unwrap();
    assert!(!prefix.path().join("sentinel").exists());
    assert_eq!(prefix.marker(), Some(format!("{COMMIT}\n{VERSION}\n")));
    assert!(
        toolchain
            .labels
            .iter()
            .any(|label| label == "source export")
    );
    assert!(!asked_master(&toolchain));
}

#[test]
fn a_local_checkout_elsewhere_is_refused_with_the_commands_that_move_it() {
    // A stale donor checkout would otherwise build an oracle other than the
    // pinned one without anyone noticing.
    let prefix = Prefix::new(true);
    let source = worktree(&prefix);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.revision = "d".repeat(40);
    let error = execute(&mut toolchain, &prefix.install(false, Some(source))).unwrap_err();
    assert!(error.contains(&"d".repeat(40)), "{error}");
    assert!(
        error.contains(&format!("checkout --detach {COMMIT}")),
        "{error}"
    );
    assert!(prefix.previous_kept());
    assert!(
        !toolchain
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

#[test]
fn an_oracle_that_cannot_be_queried_restores_the_previous_installation() {
    // Every failure between promotion and commit rolls back; an early return
    // would delete the backup with the work directory and keep the new build.
    for query in ["xmlsec1 --version", "xmlsec1 --list-transforms"] {
        let prefix = Prefix::new(true);
        let mut toolchain = Toolchain::new(&prefix.path());
        toolchain.unspawnable = Some(query);
        let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
        assert!(error.contains("cannot start"), "{query}: {error}");
        assert!(prefix.previous_kept(), "{query}");
        assert_eq!(prefix.marker(), None);
        assert_eq!(prefix.debris(), Vec::<String>::new());
    }
}

/// A prefix whose previous installation is a cache of `commit`.
fn cached(commit: &str) -> Prefix {
    let prefix = Prefix::new(true);
    executable(&prefix.path().join("bin/xmlsec1"), "#!/bin/sh\n");
    std::fs::write(prefix.path().join(MARKER), format!("{commit}\n{VERSION}\n")).unwrap();
    prefix
}

fn built(toolchain: &Toolchain) -> bool {
    toolchain
        .labels
        .iter()
        .any(|label| label == "xmlsec1 build")
}

#[test]
fn a_cache_of_the_pinned_commit_is_reused_without_building() {
    // A cache of the commit asked for that passes every check needs no
    // rebuild.
    let prefix = cached(COMMIT);
    let mut toolchain = Toolchain::new(&prefix.path());
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(prefix.previous_kept());
    assert!(!built(&toolchain));
}

#[test]
fn a_cache_without_triple_des_is_not_reused() {
    // Upstream master builds Triple DES only on request; a cache of the same
    // commit built before the request would leave the Triple DES corpus
    // without its transform, so it is rebuilt.
    let prefix = cached(COMMIT);
    let mut toolchain = Toolchain::new(&prefix.path());
    toolchain.transforms = listed(&[
        "md5",
        "ripemd160",
        "rsa-md5",
        "rsa-ripemd160",
        "hmac-md5",
        "hmac-ripemd160",
        "ecdsa-ripemd160",
        "xslt",
    ]);
    let error = execute(&mut toolchain, &prefix.install(false, None)).unwrap_err();
    assert!(built(&toolchain));
    assert!(error.contains("missing required"), "{error}");
    assert!(prefix.previous_kept());
}

#[test]
fn a_cache_of_another_commit_is_rebuilt() {
    // The pin moved since the cache was built: the oracle follows it.
    let prefix = cached(&"a".repeat(40));
    let mut toolchain = Toolchain::new(&prefix.path());
    execute(&mut toolchain, &prefix.install(false, None)).unwrap();
    assert!(built(&toolchain));
    assert_eq!(prefix.marker(), Some(format!("{COMMIT}\n{VERSION}\n")));
}

#[test]
fn a_cached_binary_of_another_version_is_rebuilt() {
    // The marker names the source used then, not the binary there now.
    let prefix = cached(COMMIT);
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
    let prefix = cached(COMMIT);
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

#[test]
fn a_modern_cache_is_reused_only_with_its_openssl_configuration() {
    // The oracle's OpenSSL reads its configuration from the installation, so
    // `openssl req` works once the build directory is gone; a cache without
    // that file cannot issue certificates and is rebuilt.
    for configured in [true, false] {
        let prefix = cached(COMMIT);
        executable(&prefix.path().join("bin/openssl"), "#!/bin/sh\n");
        if configured {
            std::fs::create_dir_all(prefix.path().join("ssl")).unwrap();
            std::fs::write(prefix.path().join("ssl/openssl.cnf"), "").unwrap();
        }
        let mut toolchain = Toolchain::new(&prefix.path());
        let mut transforms = COMPATIBILITY.to_vec();
        transforms.extend(MODERN);
        toolchain.transforms = listed(&transforms);
        let result = execute(&mut toolchain, &prefix.install(true, None));
        // A rebuild starts by downloading OpenSSL, which this toolchain refuses.
        let rebuilt = result
            .as_ref()
            .is_err_and(|error| error.contains("OpenSSL download"));
        assert_eq!(rebuilt, !configured, "{result:?}");
        assert_eq!(result.is_ok(), configured, "{result:?}");
        assert!(prefix.previous_kept(), "configured: {configured}");
    }
}
