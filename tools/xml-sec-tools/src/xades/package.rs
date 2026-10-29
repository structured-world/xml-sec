//! `xades package OUTPUT | --refresh-inventory`: archives the corpus with its
//! source overlay, excluding tool caches, build outputs and run captures.

use super::{Corpus, digest, read, xml};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Repository files distributed with the corpus.
const SOURCES: [&str; 19] = [
    "LICENSE",
    "LICENSE-THIRD-PARTY",
    "README.md",
    "interop/.gitignore",
    ".github/workflows/ci.yml",
    "crates/xml-sec-xades/examples/interop_probe.rs",
    "tools/xml-sec-tools/Cargo.toml",
    "tools/xml-sec-tools/src/xades/mod.rs",
    "tools/xml-sec-tools/src/xades/binding.rs",
    "tools/xml-sec-tools/src/xades/check.rs",
    "tools/xml-sec-tools/src/xades/corpus.rs",
    "tools/xml-sec-tools/src/xades/dss.rs",
    "tools/xml-sec-tools/src/xades/fixtures.rs",
    "tools/xml-sec-tools/src/xades/fixtures/tests.rs",
    "tools/xml-sec-tools/src/xades/package.rs",
    "tools/xml-sec-tools/src/xades/process.rs",
    "tools/xml-sec-tools/src/xades/process/tests.rs",
    "tools/xml-sec-tools/src/xades/xml.rs",
    "tools/xml-sec-tools/src/xades/tests.rs",
];

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

/// Writes the archive, then checks every inventoried file inside it.
fn archive(root: &Path, output: &Path, files: &[PathBuf], listing: &str) -> Result<(), String> {
    let file = std::fs::File::create(output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let compressed = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    let mut builder = tar::Builder::new(compressed);
    for path in files {
        let data = read(path)?;
        let name = path.strip_prefix(root).map_err(|error| error.to_string())?;
        let mut header = header(data.len() as u64, mode(path)?);
        builder
            .append_data(&mut header, name, data.as_slice())
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
    let mut files: Vec<PathBuf> = SOURCES.iter().map(|name| corpus.root.join(name)).collect();
    files.extend(evidence.files()?);
    let generated = ["target", ".tools"];
    let unexpected = files.iter().any(|path| {
        path.is_symlink()
            || path.strip_prefix(&corpus.root).is_ok_and(|relative| {
                relative
                    .components()
                    .any(|part| generated.iter().any(|name| part.as_os_str() == *name))
            })
    });
    if unexpected {
        return Err("unexpected link or build output in corpus".into());
    }
    if xml::read(&checksums)? != inventory(&corpus.root, &evidence.files()?)? {
        return Err("stale corpus inventory; refresh explicitly before packaging".into());
    }
    files.push(checksums);
    let listing = inventory(&corpus.root, &files)?;
    archive(&corpus.root, &output, &files, &listing)?;
    println!(
        "{}\nSHA256 {}\n{} inventoried files",
        output.display(),
        digest(&read(&output)?),
        files.len() - 1
    );
    Ok(())
}
