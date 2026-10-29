//! `install-xmlsec1`: builds the pinned libxmlsec1 1.3.13 test oracle into
//! `XMLSEC1_PREFIX`. A cached build is reused only after its version and
//! transforms are checked again; a new build replaces the previous one only
//! after the same checks pass, and a failure restores it.

use crate::repo::{Failure, Run, Step, System, root};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

const VERSION: &str = "1.3.13";
const REPOSITORY: &str = "https://github.com/lsh123/xmlsec.git";
/// libxmlsec1 enables `EdDSA` only with the OpenSSL 3.5 API. This isolated
/// test-oracle dependency never replaces the host OpenSSL or enters the Rust runtime.
const OPENSSL_VERSION: &str = "3.5.9";
const OPENSSL_SHA256: &str = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a";
/// Historical algorithms are disabled by default upstream; the oracle must
/// expose them to validate the optional compatibility path independently.
/// The XSLT interoperability tests need the transform, which xmlsec1 builds
/// only when libxslt development files are present.
pub(crate) const COMPATIBILITY: [&str; 8] = [
    "md5",
    "ripemd160",
    "rsa-md5",
    "rsa-ripemd160",
    "hmac-md5",
    "hmac-ripemd160",
    "ecdsa-ripemd160",
    "xslt",
];
pub(crate) const MODERN: [&str; 8] = [
    "eddsa-ed25519",
    "eddsa-ed25519ctx",
    "eddsa-ed25519ph",
    "eddsa-ed448",
    "eddsa-ed448ph",
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
];

/// What to install and where.
pub(crate) struct Install {
    pub(crate) prefix: PathBuf,
    pub(crate) commit: String,
    /// Build against a private OpenSSL with `EdDSA` and ML-KEM.
    pub(crate) modern: bool,
    /// A local checkout of the pinned commit instead of a network fetch.
    pub(crate) source: Option<PathBuf>,
    /// The inherited dynamic library path, extended with the oracle's.
    pub(crate) library_path: Option<String>,
}

impl Install {
    fn oracle(&self) -> PathBuf {
        self.prefix.join("bin/xmlsec1")
    }

    /// A query of the installed oracle with its own libraries first.
    fn query(&self, flag: &str) -> Step {
        let variable = if std::env::consts::OS == "macos" {
            "DYLD_LIBRARY_PATH"
        } else {
            "LD_LIBRARY_PATH"
        };
        let own = self.prefix.join("lib").display().to_string();
        let path = match self.library_path.as_deref().filter(|path| !path.is_empty()) {
            Some(inherited) => format!("{own}:{inherited}"),
            None => own,
        };
        Step::new(
            format!("xmlsec1 {flag}"),
            &self.oracle().display().to_string(),
            &[flag],
        )
        .with_env(variable, path)
    }
}

/// Whether `output`'s first line names xmlsec1 at exactly the pinned version.
pub(crate) fn version_matches(output: &str) -> bool {
    let mut words = output.lines().next().unwrap_or_default().split_whitespace();
    words.next() == Some("xmlsec1") && words.next() == Some(VERSION)
}

fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    path.is_file()
}

/// The oracle's version line when both its version and its transforms qualify.
pub(crate) fn validated(run: &mut impl Run, install: &Install) -> Result<Option<String>, String> {
    let (status, version) = run.stdout(&install.query("--version"))?;
    let version = version.trim_end_matches('\n').to_owned();
    if !status.success() || !version_matches(&version) {
        return Ok(None);
    }
    Ok(capable(run, install)?.then_some(version))
}

/// Whether the oracle lists every transform its profile requires.
fn capable(run: &mut impl Run, install: &Install) -> Result<bool, String> {
    let (status, listed) = run.stdout(&install.query("--list-transforms"))?;
    let has = |transform: &&str| listed.contains(&format!("\"{transform}\""));
    if !status.success() || !COMPATIBILITY.iter().all(has) {
        return Ok(false);
    }
    if !install.modern {
        return Ok(true);
    }
    let openssl = install.prefix.join("bin/openssl");
    if !executable(&openssl) {
        return Ok(false);
    }
    let (status, version) = run.stdout(&Step::new(
        "openssl version",
        &openssl.display().to_string(),
        &["version"],
    ))?;
    Ok(status.success()
        && version.starts_with(&format!("OpenSSL {OPENSSL_VERSION} "))
        && MODERN.iter().all(has))
}

fn require(run: &mut impl Run, step: &Step) -> Result<(), String> {
    let status = run.status(step)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            step.label,
            crate::repo::describe(status)
        ))
    }
}

fn query(run: &mut impl Run, step: &Step) -> Result<Option<String>, String> {
    let (status, output) = run.stdout(step)?;
    Ok(status.success().then(|| output.trim().to_owned()))
}

/// A Git command on `directory`.
fn git(label: &str, directory: &Path, args: &[&str]) -> Step {
    let directory = directory.display().to_string();
    let mut all = vec!["-C", directory.as_str()];
    all.extend(args);
    Step::new(label, "git", &all)
}

/// The pinned source in `destination`: exported from a local checkout so the
/// build cannot write into it, or fetched at exactly the pinned commit.
fn obtain_source(
    run: &mut impl Run,
    install: &Install,
    work: &Path,
    destination: &Path,
) -> Result<(), String> {
    match &install.source {
        Some(local) => export(run, local, &install.commit, work, destination),
        None => fetch(run, &install.commit, destination),
    }
}

fn mismatch(commit: &str, got: &str) -> String {
    format!("xmlsec1 source revision mismatch: expected {commit}, got {got}")
}

/// Exports `commit` of a local checkout; configure writes generated files
/// into its source tree, which must stay reusable by other checks.
fn export(
    run: &mut impl Run,
    local: &Path,
    commit: &str,
    work: &Path,
    destination: &Path,
) -> Result<(), String> {
    let refused = || {
        format!(
            "XMLSEC1_SOURCE_DIR must be an absolute git checkout: {}",
            local.display()
        )
    };
    if !local.is_absolute() || !local.is_dir() {
        return Err(refused());
    }
    let inside = query(
        run,
        &git(
            "source repository",
            local,
            &["rev-parse", "--is-inside-work-tree"],
        ),
    )?;
    if inside.as_deref() != Some("true") {
        return Err(refused());
    }
    let head =
        query(run, &git("source revision", local, &["rev-parse", "HEAD"]))?.unwrap_or_default();
    if head != commit {
        return Err(mismatch(commit, &head));
    }
    let archive = work.join("xmlsec.tar");
    let output = format!("--output={}", archive.display());
    require(
        run,
        &git("source export", local, &["archive", &output, commit]),
    )?;
    std::fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    let file =
        std::fs::File::open(&archive).map_err(|error| format!("{}: {error}", archive.display()))?;
    tar::Archive::new(file)
        .unpack(destination)
        .map_err(|error| format!("unpack source: {error}"))
}

/// Fetches exactly `commit` from the upstream repository.
fn fetch(run: &mut impl Run, commit: &str, destination: &Path) -> Result<(), String> {
    let target = destination.display().to_string();
    require(run, &Step::new("source init", "git", &["init", &target]))?;
    require(
        run,
        &git(
            "source remote",
            destination,
            &["remote", "add", "origin", REPOSITORY],
        ),
    )?;
    require(
        run,
        &git(
            "source fetch",
            destination,
            &["fetch", "--depth=1", "origin", commit],
        ),
    )?;
    let fetched = query(
        run,
        &git(
            "fetched revision",
            destination,
            &["rev-parse", "FETCH_HEAD"],
        ),
    )?
    .unwrap_or_default();
    if fetched != commit {
        return Err(mismatch(commit, &fetched));
    }
    require(
        run,
        &git(
            "source checkout",
            destination,
            &["checkout", "--detach", commit],
        ),
    )
}

/// A private static OpenSSL with `EdDSA` and ML-KEM, verified by digest. Its
/// PIC `libcrypto` is embedded in the oracle's backend, so removing the build
/// directory leaves no runtime dependency on it.
fn build_openssl(run: &mut impl Run, work: &Path, jobs: &str) -> Result<PathBuf, String> {
    use sha2::Digest as _;
    let archive = work.join("openssl.tar.gz");
    let url = format!(
        "https://github.com/openssl/openssl/releases/download/openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz"
    );
    let output = archive.display().to_string();
    require(
        run,
        &Step::new(
            "OpenSSL download",
            "curl",
            &[
                "--fail",
                "--location",
                "--retry",
                "3",
                &url,
                "--output",
                &output,
            ],
        ),
    )?;
    let data = std::fs::read(&archive).map_err(|error| format!("{output}: {error}"))?;
    if crate::xades::hex(&sha2::Sha256::digest(&data)) != OPENSSL_SHA256 {
        return Err("OpenSSL oracle source checksum mismatch".into());
    }
    tar::Archive::new(flate2::read::GzDecoder::new(data.as_slice()))
        .unpack(work)
        .map_err(|error| format!("unpack OpenSSL: {error}"))?;
    let source = work.join(format!("openssl-{OPENSSL_VERSION}"));
    let prefix = work.join("openssl-install");
    let configure = source.join("Configure").display().to_string();
    let install_prefix = format!("--prefix={}", prefix.display());
    let configure = Step::new(
        "OpenSSL configure",
        &configure,
        &[
            "no-shared",
            "no-module",
            "no-tests",
            "-fPIC",
            &install_prefix,
            "--libdir=lib",
        ],
    )
    .in_directory(&source);
    require(run, &configure)?;
    let directory = source.display().to_string();
    require(
        run,
        &Step::new(
            "OpenSSL build",
            "make",
            &["--directory", &directory, "--jobs", jobs],
        ),
    )?;
    require(
        run,
        &Step::new(
            "OpenSSL install",
            "make",
            &["--directory", &directory, "install_sw"],
        ),
    )?;
    Ok(prefix)
}

/// Builds and installs the oracle below `stage`; returns the staged prefix.
fn build(run: &mut impl Run, install: &Install, work: &Path) -> Result<PathBuf, String> {
    let (source, build, stage) = (work.join("xmlsec"), work.join("build"), work.join("stage"));
    let jobs = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .to_string();
    obtain_source(run, install, work, &source)?;
    let openssl = if install.modern {
        Some(build_openssl(run, work, &jobs)?)
    } else {
        None
    };
    for directory in [&build, &stage] {
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    let prefix = format!("--prefix={}", install.prefix.display());
    let with_openssl = openssl.as_ref().map_or_else(
        || "--with-openssl".to_owned(),
        |openssl| format!("--with-openssl={}", openssl.display()),
    );
    let mut options = vec![
        prefix.as_str(),
        "--disable-static",
        "--without-gnutls",
        "--without-nss",
        "--enable-md5",
        "--enable-ripemd160",
    ];
    if install.modern {
        options.push("--enable-ml-kem");
    }
    options.push(&with_openssl);
    let autogen = source.join("autogen.sh").display().to_string();
    require(
        run,
        &Step::new("xmlsec1 configure", &autogen, &options)
            .with_env("OBJ_DIR", build.display().to_string()),
    )?;
    let directory = build.display().to_string();
    require(
        run,
        &Step::new(
            "xmlsec1 build",
            "make",
            &["--directory", &directory, "--jobs", &jobs],
        ),
    )?;
    let destination = format!("DESTDIR={}", stage.display());
    require(
        run,
        &Step::new(
            "xmlsec1 install",
            "make",
            &["--directory", &directory, "install", &destination],
        ),
    )?;
    let relative = install
        .prefix
        .strip_prefix("/")
        .map_err(|_| "the prefix is absolute")?;
    let staged = stage.join(relative);
    if let Some(openssl) = openssl {
        // The primitive oracle stays with the installation instead of leaving
        // with its temporary build directory.
        let binary = staged.join("bin/openssl");
        std::fs::copy(openssl.join("bin/openssl"), &binary)
            .map_err(|error| format!("install openssl: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(staged)
}

/// Why an installation was abandoned, and whether the previous one could not
/// be restored and stays in the work directory.
struct Abandoned {
    message: String,
    backup_kept: bool,
}

impl Abandoned {
    /// The failure; the work directory outlives it when it holds the backup.
    fn report(self, work: tempfile::TempDir) -> String {
        if self.backup_kept {
            drop(work.keep());
        }
        self.message
    }
}

/// The previous installation moved aside while the new one is checked.
struct Promotion {
    prefix: PathBuf,
    backup: Option<PathBuf>,
}

impl Promotion {
    /// Moves `staged` to the prefix, the previous installation into `work`.
    fn new(staged: &Path, prefix: &Path, work: &Path) -> Result<Self, Abandoned> {
        let backup = if prefix.exists() {
            let backup = work.join("previous-install");
            std::fs::rename(prefix, &backup).map_err(|error| Abandoned {
                message: format!("move the previous installation aside: {error}"),
                backup_kept: false,
            })?;
            Some(backup)
        } else {
            None
        };
        let promotion = Self {
            prefix: prefix.to_owned(),
            backup,
        };
        match std::fs::rename(staged, prefix) {
            Ok(()) => Ok(promotion),
            Err(error) => Err(promotion.abandon(format!("promote the new installation: {error}"))),
        }
    }

    /// Removes the new installation and restores the previous one. A backup
    /// that cannot be restored is the failure's result, kept in place.
    fn abandon(self, failure: String) -> Abandoned {
        let removal = if self.prefix.exists() {
            std::fs::remove_dir_all(&self.prefix).err()
        } else {
            None
        };
        if let Some(error) = removal {
            let message = format!("{failure}; removing the new installation failed: {error}");
            return Abandoned {
                message,
                backup_kept: self.backup.is_some(),
            };
        }
        let Some(backup) = self.backup else {
            return Abandoned {
                message: failure,
                backup_kept: false,
            };
        };
        match std::fs::rename(&backup, &self.prefix) {
            Ok(()) => Abandoned {
                message: failure,
                backup_kept: false,
            },
            Err(error) => Abandoned {
                message: format!(
                    "{failure}; failed to restore the previous xmlsec1 installation at {}; backup remains at {}: {error}",
                    self.prefix.display(),
                    backup.display()
                ),
                backup_kept: true,
            },
        }
    }

    /// Keeps the new installation and discards the previous one.
    fn commit(self) -> Result<(), String> {
        self.backup.map_or(Ok(()), |backup| {
            std::fs::remove_dir_all(&backup)
                .map_err(|error| format!("remove the previous installation: {error}"))
        })
    }
}

pub(crate) fn execute(run: &mut impl Run, install: &Install) -> Result<(), String> {
    let commit = install.commit.as_str();
    let marker = install.prefix.join(".xmlsec-source-commit");
    let recorded = std::fs::read_to_string(&marker).ok();
    if executable(&install.oracle())
        && recorded.as_deref().map(|text| text.trim_end_matches('\n')) == Some(commit)
    {
        if let Some(version) = validated(run, install)? {
            println!("{version}");
            println!(
                "xmlsec1 {VERSION} is already installed at {}",
                install.prefix.display()
            );
            return Ok(());
        }
        eprintln!(
            "cached xmlsec1 at {} failed version validation; rebuilding",
            install.prefix.display()
        );
    }
    // The build lives beside the prefix, so promotion is a rename on one file system.
    let parent = install.prefix.parent().ok_or("the prefix has a parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let work = tempfile::Builder::new()
        .prefix(&format!(".xmlsec1-{VERSION}."))
        .tempdir_in(parent)
        .map_err(|error| error.to_string())?;
    let staged = build(run, install, work.path())?;
    let promotion = match Promotion::new(&staged, &install.prefix, work.path()) {
        Ok(promotion) => promotion,
        Err(abandoned) => return Err(abandoned.report(work)),
    };
    let (status, version) = run.stdout(&install.query("--version"))?;
    let version = version.trim_end_matches('\n').to_owned();
    let refusal = if !status.success() || !version_matches(&version) {
        let shown = if version.is_empty() {
            "<empty output>"
        } else {
            version.as_str()
        };
        Some(format!(
            "xmlsec1 version mismatch: expected xmlsec1 {VERSION}, got {shown}"
        ))
    } else if !capable(run, install)? {
        Some(
            "xmlsec1 oracle is missing required compatibility, XSLT, EdDSA, or ML-KEM transforms"
                .to_owned(),
        )
    } else {
        None
    };
    if let Some(refusal) = refusal {
        return Err(promotion.abandon(refusal).report(work));
    }
    println!("{version}");
    std::fs::write(&marker, format!("{commit}\n")).map_err(|error| error.to_string())?;
    promotion.commit()?;
    println!(
        "installed xmlsec1 {VERSION} snapshot {} at {}",
        &commit[..12],
        install.prefix.display()
    );
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: install-xmlsec1 (configured by XMLSEC1_PREFIX, XMLSEC1_SOURCE_DIR, XMLSEC1_MODERN_ORACLE)".into());
    }
    let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let modern = match variable("XMLSEC1_MODERN_ORACLE").as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(_) => return Err("XMLSEC1_MODERN_ORACLE must be 0 or 1".into()),
    };
    let root = root();
    let pin = root.join("compatibility/libxmlsec1-1.3.13-donor-commit.txt");
    let commit =
        std::fs::read_to_string(&pin).map_err(|error| format!("{}: {error}", pin.display()))?;
    let commit = commit.trim_end_matches('\n').to_owned();
    let object_id = commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !object_id {
        return Err(format!("invalid xmlsec1 donor commit: {commit}").into());
    }
    let prefix = variable("XMLSEC1_PREFIX").map_or_else(
        || root.join(format!(".tools/xmlsec1-{VERSION}-{}", &commit[..12])),
        PathBuf::from,
    );
    if !prefix.is_absolute() {
        return Err(format!(
            "XMLSEC1_PREFIX must be an absolute path: {}",
            prefix.display()
        )
        .into());
    }
    let library = if std::env::consts::OS == "macos" {
        "DYLD_LIBRARY_PATH"
    } else {
        "LD_LIBRARY_PATH"
    };
    let install = Install {
        prefix,
        commit,
        modern,
        source: variable("XMLSEC1_SOURCE_DIR").map(PathBuf::from),
        library_path: variable(library),
    };
    Ok(execute(&mut System, &install)?)
}
