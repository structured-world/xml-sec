//! `xades package OUTPUT | --refresh-inventory`: archives the corpus with the
//! commit it was built from, excluding tool caches, build outputs and run
//! captures.

use super::{Corpus, digest, read, xml};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// License notices distributed with the corpus.
const NOTICES: [&str; 2] = ["LICENSE", "LICENSE-THIRD-PARTY"];

/// The archived file naming the commit the archive was built from.
const COMMIT: &str = "COMMIT";

/// Maintained corpus files outside the per-case directories.
const DOCUMENTS: [&str; 14] = [
    ".gitattributes",
    "README.md",
    "PROVENANCE.md",
    "COMMENT-DRAFT.md",
    "SHA256SUMS",
    "cases.json",
    "dss/pom.xml",
    "dss/src/main/java/Probe.java",
    "dss/src/main/java/BindingProbe.java",
    "dss-evidence/expectations.json",
    "dss-investigation/README.md",
    "dss-investigation/expectations.json",
    "dss-investigation/strict-policy-expectations.json",
    "dss-investigation/source-audit.json",
];

/// Which corpus files are evidence: declared inputs, independent goldens
/// and their maintained sources. Everything a run produces is excluded.
pub(crate) struct Evidence {
    package: PathBuf,
    fixtures: BTreeSet<String>,
    core: BTreeSet<String>,
    minimal: BTreeSet<String>,
}

impl Evidence {
    pub(crate) fn load(package: &Path) -> Result<Self, String> {
        let read_json = |name: &str| -> Result<Value, String> {
            serde_json::from_str(&xml::read(&package.join(name))?)
                .map_err(|error| format!("{name}: {error}"))
        };
        let cases = read_json("cases.json")?;
        let cases = cases.as_array().map_or(&[][..], Vec::as_slice);
        let field = |case: &Value, name: &str| case[name].as_str().map(str::to_owned);
        let mut fixtures: BTreeSet<String> = cases
            .iter()
            .filter_map(|case| field(case, "file"))
            .collect();
        fixtures.extend(
            [
                "fixtures/enveloped-control.template.xml",
                "fixtures/signer.key",
                "fixtures/signer.pem",
                "fixtures/intermediate.pem",
                "fixtures/baseline/root.der",
                "fixtures/baseline/signer.der",
                "fixtures/baseline/intermediate.der",
            ]
            .map(String::from),
        );
        let minimal = read_json("dss-investigation/expectations.json")?;
        Ok(Self {
            package: package.to_owned(),
            fixtures,
            core: cases
                .iter()
                .filter_map(|case| field(case, "name"))
                .collect(),
            minimal: minimal["cases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|case| field(case, "name"))
                .collect(),
        })
    }

    /// Whether `path`, inside the corpus, is distributable evidence.
    pub(crate) fn includes(&self, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(&self.package) else {
            return false;
        };
        let parts: Vec<String> = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        let posix = parts.join("/");
        if parts.first().is_some_and(|first| first == "fixtures") {
            return self.fixtures.contains(&posix);
        }
        if let [kind, case, file] = parts.as_slice()
            && (kind == "results" || kind == "dss-investigation")
        {
            let names = if kind == "dss-investigation" {
                &self.minimal
            } else {
                &self.core
            };
            if !names.contains(case) {
                return false;
            }
            if golden(file)
                || (kind == "dss-investigation" && (file == "signed.xml" || file == "template.xml"))
            {
                return true;
            }
        }
        DOCUMENTS.contains(&posix.as_str())
    }

    /// Every evidence file except the inventory itself, sorted.
    pub(crate) fn files(&self) -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();
        walk(&self.package, &mut files)?;
        files.retain(|path| {
            path.file_name().is_none_or(|name| name != "SHA256SUMS") && self.includes(path)
        });
        files.sort();
        Ok(files)
    }
}

/// `expected-reference-N.bin` or `expected-signedinfo.bin`.
fn golden(name: &str) -> bool {
    name == "expected-signedinfo.bin"
        || name
            .strip_prefix("expected-reference-")
            .and_then(|rest| rest.strip_suffix(".bin"))
            .is_some_and(|index| {
                !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
            })
}

/// Every regular file below `directory`.
pub(crate) fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            walk(&path, files)?;
        } else if kind.is_file() || kind.is_symlink() {
            files.push(path);
        }
    }
    Ok(())
}

/// The tracked files below `pathspec`, relative to the repository root.
pub(crate) fn tracked(root: &Path, pathspec: &str) -> Result<Vec<String>, String> {
    let listing = git(root, &["ls-files", "-z", "--", pathspec])?;
    Ok(String::from_utf8_lossy(&listing)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Variables that make Git use another repository than its working directory.
pub(crate) const GIT_LOCATION: [&str; 6] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
];

/// Git on the repository at `root`.
pub(crate) fn git_command(root: &Path, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    for variable in GIT_LOCATION {
        command.env_remove(variable);
    }
    command.args(args).current_dir(root);
    command
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = git_command(root, args)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|error| format!("git: {error}"))?;
    if !output.status.success() {
        return Err(format!("git {} failed", args.join(" ")));
    }
    Ok(output.stdout)
}

/// The commit the archive is built from. Every archived file must be
/// committed unchanged there, so the recorded commit reproduces the archive.
pub(crate) fn source_commit(root: &Path, names: &[String]) -> Result<String, String> {
    let head = git(root, &["rev-parse", "--verify", "HEAD"])?;
    let commit = String::from_utf8_lossy(&head).trim_end().to_owned();
    // The working bytes are hashed and compared with the commit's blobs:
    // status depends on the index, which hides ignored files, untracked ones
    // under status.showUntrackedFiles=no and assume-unchanged or
    // skip-worktree edits.
    let mut tree = vec!["ls-tree", "-r", "-z", commit.as_str(), "--"];
    tree.extend(names.iter().map(String::as_str));
    let listed = git(root, &tree)?;
    let committed: BTreeMap<&str, &str> = std::str::from_utf8(&listed)
        .map_err(|error| error.to_string())?
        .split('\0')
        .filter_map(|line| {
            let (meta, path) = line.split_once('\t')?;
            Some((path, meta.rsplit(' ').next()?))
        })
        .collect();
    let mut hash = vec!["hash-object", "--no-filters", "--"];
    hash.extend(names.iter().map(String::as_str));
    let hashed = git(root, &hash)?;
    let actual: Vec<&str> = std::str::from_utf8(&hashed)
        .map_err(|error| error.to_string())?
        .lines()
        .collect();
    if actual.len() != names.len() {
        return Err(format!(
            "git hash-object returned {} ids for {} files",
            actual.len(),
            names.len()
        ));
    }
    let differing: Vec<&str> = names
        .iter()
        .zip(&actual)
        .filter(|(name, blob)| committed.get(name.as_str()) != Some(*blob))
        .map(|(name, _)| name.as_str())
        .collect();
    if !differing.is_empty() {
        return Err(format!(
            "commit the archived files first: {}",
            differing.join(" ")
        ));
    }
    Ok(commit)
}

/// The archived files at `names` followed by the `COMMIT` file, and that
/// commit; refused unless every file is committed unchanged.
pub(crate) fn archive_entries(
    root: &Path,
    names: &[String],
) -> Result<(Vec<Entry>, String), String> {
    let commit = source_commit(root, names)?;
    let mut entries = names
        .iter()
        .map(|name| Entry::file(root, name))
        .collect::<Result<Vec<_>, _>>()?;
    entries.push(Entry {
        name: COMMIT.into(),
        data: format!("{commit}\n").into_bytes(),
        mode: 0o644,
    });
    Ok((entries, commit))
}

/// One archived file.
pub(crate) struct Entry {
    name: String,
    data: Vec<u8>,
    mode: u32,
}

impl Entry {
    /// The repository file at `name`, relative to `root`.
    fn file(root: &Path, name: &str) -> Result<Self, String> {
        let path = root.join(name);
        Ok(Self {
            name: name.to_owned(),
            data: read(&path)?,
            mode: mode(&path)?,
        })
    }

    /// The archived name and bytes.
    #[cfg(test)]
    pub(crate) fn parts(&self) -> (&str, &[u8]) {
        (&self.name, &self.data)
    }
}

/// `sha256  path` lines, paths relative to the repository root.
pub(crate) fn inventory(root: &Path, files: &[PathBuf]) -> Result<String, String> {
    let mut text = String::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .map_err(|_| format!("{} is outside the repository", file.display()))?;
        text.push_str(&digest(&read(file)?));
        text.push_str("  ");
        text.push_str(&relative.display().to_string());
        text.push('\n');
    }
    Ok(text)
}

/// A reproducible header: owner, group and time carry no workstation identity.
fn header(size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header
}

fn mode(path: &Path) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(std::fs::metadata(path)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o7777)
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path).map_err(|error| error.to_string())?;
        Ok(0o644)
    }
}

/// `sha256  path` lines of `entries`.
fn listing(entries: &[Entry]) -> String {
    let mut text = String::new();
    for entry in entries {
        text.push_str(&digest(&entry.data));
        text.push_str("  ");
        text.push_str(&entry.name);
        text.push('\n');
    }
    text
}

/// Writes the archive, then checks every inventoried file inside it.
fn archive(output: &Path, entries: &[Entry], listing: &str) -> Result<(), String> {
    let file = std::fs::File::create(output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let compressed = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    let mut builder = tar::Builder::new(compressed);
    for entry in entries {
        let mut header = header(entry.data.len() as u64, entry.mode);
        builder
            .append_data(&mut header, &entry.name, entry.data.as_slice())
            .map_err(|error| error.to_string())?;
    }
    let mut header = header(listing.len() as u64, 0o644);
    builder
        .append_data(&mut header, "SHA256SUMS", listing.as_bytes())
        .map_err(|error| error.to_string())?;
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .map_err(|error| format!("finish {}: {error}", output.display()))?;
    let file = std::fs::File::open(output).map_err(|error| error.to_string())?;
    let mut archived = std::collections::BTreeMap::new();
    let mut reader = tar::Archive::new(flate2::read::GzDecoder::new(file));
    for entry in reader.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .display()
            .to_string();
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut data).map_err(|error| error.to_string())?;
        archived.insert(path, digest(&data));
    }
    for line in listing.lines() {
        let (expected, path) = line.split_once("  ").ok_or("malformed inventory line")?;
        if archived.get(path).map(String::as_str) != Some(expected) {
            return Err(format!("archive hash mismatch: {path}"));
        }
    }
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let usage = "usage: xades package OUTPUT | xades package --refresh-inventory";
    let package = corpus.package();
    let evidence = Evidence::load(&package)?;
    let checksums = package.join("SHA256SUMS");
    let output = match args {
        [flag] if flag == "--refresh-inventory" => {
            super::write(&checksums, inventory(&corpus.root, &evidence.files()?)?)?;
            return Ok(());
        }
        [output] if !output.starts_with("--") => super::absolute(output)?,
        _ => return Err(usage.into()),
    };
    if output.exists() || output.starts_with(&package) {
        return Err("choose a new archive path outside the corpus".into());
    }
    let mut names: Vec<String> = NOTICES.iter().map(|&name| name.to_owned()).collect();
    for path in evidence.files()? {
        let relative = path
            .strip_prefix(&corpus.root)
            .map_err(|_| format!("{} is outside the repository", path.display()))?;
        names.push(relative.display().to_string());
    }
    let generated = ["target", ".tools"];
    let unexpected = names.iter().any(|name| {
        corpus.root.join(name).is_symlink()
            || Path::new(name).components().any(|part| {
                generated
                    .iter()
                    .any(|generated| part.as_os_str() == *generated)
            })
    });
    if unexpected {
        return Err("unexpected link or build output in corpus".into());
    }
    if xml::read(&checksums)? != inventory(&corpus.root, &evidence.files()?)? {
        return Err("stale corpus inventory; refresh explicitly before packaging".into());
    }
    let inventoried = checksums
        .strip_prefix(&corpus.root)
        .map_err(|error| error.to_string())?;
    names.push(inventoried.display().to_string());
    let (entries, commit) = archive_entries(&corpus.root, &names)?;
    let listing = listing(&entries);
    archive(&output, &entries, &listing)?;
    println!(
        "{}\nSHA256 {}\ncommit {commit}\n{} inventoried files",
        output.display(),
        digest(&read(&output)?),
        entries.len()
    );
    Ok(())
}
