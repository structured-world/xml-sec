//! `donor-fixtures [--xmlenc-corpora | PATH... | --cli [--check]]`: copies
//! libxmlsec1 donor test data into the repository. Each target is staged
//! completely and then swapped in, so a failed import keeps the last
//! known-good copy.

use crate::repo::{Failure, root};
use std::path::{Path, PathBuf};

pub(crate) mod cli;
#[cfg(test)]
mod tests;

/// The complete encryption acceptance snapshots, pinned by `corpora.sha256`.
const XMLENC_CORPORA: [&str; 8] = [
    "xmlenc/merlin-xmlenc-five",
    "xmlenc/01-phaos-xmlenc-3",
    "xmlenc/aleksey-xmlenc-01",
    "xmlenc/xmlenc11-interop-2012",
    "xmlenc/nist-aesgcm",
    "xmlenc/keys/xdh",
    "xmlenc/keys/ec",
    "xmlenc/keys/dhx",
];

const CURATED: [&str; 23] = [
    "xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml",
    "xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha256.xml",
    "xmldsig/aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256.tmpl",
    "xmldsig/aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256.xml",
    "xmldsig/keys/dsa/dsa-2048-key.p8-der",
    "xmldsig/keys/dsa/dsa-1024-key.p8-der",
    "xmldsig/keys/dsa/dsa-3072-key.p8-der",
    "xmldsig/keys/dsa/dsa-1024-pubkey.pem",
    "xmldsig/keys/dsa/dsa-2048-pubkey.pem",
    "xmldsig/keys/dsa/dsa-3072-pubkey.pem",
    "xmldsig/keys/ml-kem",
    "xmldsig/merlin-xmldsig-twenty-three",
    "xmldsig/phaos-xmldsig-three",
    "xmldsig/xmldsig11-interop-2012",
    "xmldsig/external-data/xml-stylesheet-2005",
    "xmldsig/external-data/xml-stylesheet-2005.b64",
    "xmldsig/external-data/rfc3161.txt",
    "xmlenc/aleksey-xmlenc-01/enc-aes128cbc-keyname.tmpl",
    "xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl",
    "xmlenc/aleksey-xmlenc-01/enc-aes256cbc-keyname.tmpl",
    "xmlenc/aleksey-xmlenc-01/enc-aes256gcm-keyname.tmpl",
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.tmpl",
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512.tmpl",
];

/// The default import: curated files plus the complete RSA-PSS and ML-KEM
/// families the upstream signature and encryption runners exercise.
pub(crate) fn default_paths() -> Vec<String> {
    let mut paths: Vec<String> = CURATED.iter().map(|path| (*path).to_owned()).collect();
    for hash in [
        "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384",
        "sha3_512",
    ] {
        for extension in ["xml", "tmpl"] {
            paths.push(format!(
                "xmldsig/aleksey-xmldsig-01/enveloping-rsa-pss-{hash}.{extension}"
            ));
            if hash != "sha1" {
                paths.push(format!(
                    "xmldsig/aleksey-xmldsig-01/enveloped-{hash}-rsa-pss-{hash}.{extension}"
                ));
            }
        }
    }
    for size in [512, 768, 1024] {
        for extension in ["xml", "tmpl"] {
            paths.push(format!(
                "xmldsig/aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-em-ml-kem-{size}.{extension}"
            ));
        }
        for extension in ["xml", "tmpl", "data"] {
            paths.push(format!(
                "xmlenc/aleksey-xmlenc-01/enc-aes256-em-ml-kem-{size}.{extension}"
            ));
        }
    }
    for family in [
        "aes128gcm-em-ml-kem-512",
        "aes192gcm-em-ml-kem-768",
        "aes256gcm-em-ml-kem-1024",
    ] {
        for extension in ["xml", "tmpl", "data"] {
            paths.push(format!("xmlenc/aleksey-xmlenc-01/enc-{family}.{extension}"));
        }
    }
    paths
}

/// The donor path below `xmldsig/` or `xmlenc/`, refusing anything that could
/// leave the donor or fixture tree.
pub(crate) fn donor_path(relative: &str) -> Result<&str, String> {
    let rest = relative
        .strip_prefix("xmldsig/")
        .or_else(|| relative.strip_prefix("xmlenc/"))
        .ok_or_else(|| format!("fixture path must start with xmldsig/ or xmlenc/: {relative}"))?;
    let unsafe_component = rest
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..");
    if unsafe_component {
        return Err(format!(
            "fixture path contains an empty, current, or parent component: {relative}"
        ));
    }
    Ok(rest)
}

/// A fresh hidden name beside `target` for staging or backup.
fn beside(target: &Path, purpose: &str) -> Result<PathBuf, String> {
    let parent = target.parent().ok_or("a fixture target has a parent")?;
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut candidate = None;
    for attempt in 0..1000_u32 {
        let path = parent.join(format!(
            ".{name}.{purpose}.{}.{attempt}",
            std::process::id()
        ));
        if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
            candidate = Some(path);
            break;
        }
    }
    candidate.ok_or_else(|| format!("no free staging name beside {}", target.display()))
}

fn remove(path: &Path) -> Result<(), String> {
    let kind = std::fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .file_type();
    let removed = if kind.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    removed.map_err(|error| format!("remove {}: {error}", path.display()))
}

/// Swaps `replacement` in for `target`; on failure the previous target is restored.
pub(crate) fn replace(replacement: &Path, target: &Path) -> Result<(), String> {
    let backup = if std::fs::symlink_metadata(target).is_ok() {
        let backup = beside(target, "backup")?;
        if let Err(error) = std::fs::rename(target, &backup) {
            remove(replacement)?;
            return Err(format!("move {} aside: {error}", target.display()));
        }
        Some(backup)
    } else {
        None
    };
    match std::fs::rename(replacement, target) {
        Ok(()) => backup.map_or(Ok(()), |backup| remove(&backup)),
        Err(error) => {
            remove(replacement)?;
            if let Some(backup) = backup {
                std::fs::rename(&backup, target).map_err(|restore| {
                    format!(
                        "failed to restore fixture target after replacement failure: {}: {restore}",
                        target.display()
                    )
                })?;
            }
            Err(format!("replace {}: {error}", target.display()))
        }
    }
}

/// Copies `from` to `to` as a plain readable file (mode 0644).
fn install(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::copy(from, to).map_err(|error| format!("copy {}: {error}", from.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Every regular file below `directory`, relative to it.
fn regular_files(directory: &Path, base: &Path, into: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        let kind = std::fs::metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            regular_files(&path, base, into)?;
        } else if kind.is_file() {
            into.push(
                path.strip_prefix(base)
                    .map_err(|error| error.to_string())?
                    .to_owned(),
            );
        }
    }
    Ok(())
}

const PHAOS_LABELS: [&str; 2] = [
    "detached 40-byte SHA-1 HMAC signature",
    "detached 40 byte SHA-1 HMAC signature",
];

/// Corrections of known donor defects, applied to a staged snapshot.
pub(crate) fn normalize(relative: &str, staging: &Path) -> Result<(), String> {
    match relative {
        "xmldsig/merlin-xmldsig-twenty-three" => {
            // The donor README has unresolved placeholders; it is not fixture data.
            let readme = staging.join("Readme.txt");
            if readme.exists() {
                remove(&readme)?;
            }
            // xmlsec 1.3.13's historical "-40" names carry an 80-bit HMAC, the
            // XML Signature 1.1 floor; only the local names change.
            for extension in ["tmpl", "xml"] {
                let donor = staging.join(format!("signature-enveloping-hmac-sha1-40.{extension}"));
                let normalized =
                    staging.join(format!("signature-enveloping-hmac-sha1-80.{extension}"));
                if !donor.is_file() {
                    return Err(format!(
                        "donor snapshot no longer provides signature-enveloping-hmac-sha1-40.{extension}; update the normalization"
                    ));
                }
                if normalized.exists() {
                    return Err(format!(
                        "donor snapshot provides both historical and normalized HMAC fixtures: signature-enveloping-hmac-sha1-80.{extension}"
                    ));
                }
                std::fs::rename(&donor, &normalized).map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "xmldsig/phaos-xmldsig-three" => {
            // The historical file names stay, but the donor README calls their
            // HMACOutputLength=80 values 40-byte signatures.
            let readme = staging.join("README.txt");
            let text = std::fs::read_to_string(&readme).map_err(|error| error.to_string())?;
            let once = PHAOS_LABELS
                .iter()
                .all(|label| text.lines().filter(|line| line.contains(label)).count() == 1);
            if !once {
                return Err(
                    "Phaos README HMAC descriptions changed; update the normalization".into(),
                );
            }
            let corrected: String = text
                .split_inclusive('\n')
                .map(|line| {
                    PHAOS_LABELS.iter().fold(line.to_owned(), |line, label| {
                        line.replacen(label, "detached 80-bit SHA-1 HMAC signature", 1)
                    })
                })
                .collect();
            std::fs::write(&readme, corrected).map_err(|error| error.to_string())
        }
        _ => Ok(()),
    }
}

/// Imports one donor file or directory over its fixture target.
pub(crate) fn import(donor_root: &Path, fixture_root: &Path, relative: &str) -> Result<(), String> {
    let relative = relative.trim_end_matches('/');
    let source = donor_root.join(donor_path(relative)?);
    let target = fixture_root.join(relative);
    let parent = target.parent().ok_or("a fixture target has a parent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staging = beside(&target, "import")?;
    if source.is_dir() {
        // The complete snapshot is built before the last known-good target is replaced.
        let mut files = Vec::new();
        let staged = regular_files(&source, &source, &mut files)
            .and_then(|()| {
                files
                    .iter()
                    .try_for_each(|file| install(&source.join(file), &staging.join(file)))
            })
            .and_then(|()| {
                std::fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
                normalize(relative, &staging)
            });
        if let Err(error) = staged {
            if std::fs::symlink_metadata(&staging).is_ok() {
                remove(&staging)?;
            }
            return Err(error);
        }
    } else if let Err(error) = install(&source, &staging) {
        if staging.exists() {
            remove(&staging)?;
        }
        return Err(error);
    }
    replace(&staging, &target)
}

/// `sha256  path` lines of every file below `paths`, sorted by path.
pub(crate) fn corpora_inventory(fixture_root: &Path, paths: &[&str]) -> Result<String, String> {
    let mut files = Vec::new();
    for path in paths {
        regular_files(&fixture_root.join(path), fixture_root, &mut files)?;
    }
    let mut names: Vec<String> = files
        .iter()
        .map(|file| {
            file.components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    names.sort();
    let mut text = String::new();
    for name in names {
        let data = std::fs::read(fixture_root.join(&name)).map_err(|error| error.to_string())?;
        text.push_str(&crate::security_corpus::sha256(&data));
        text.push_str("  ");
        text.push_str(&name);
        text.push('\n');
    }
    Ok(text)
}

/// Imports the paths `args` selects from `donor_root` into `fixture_root`.
pub(crate) fn execute(
    donor_root: &Path,
    fixture_root: &Path,
    args: Vec<String>,
) -> Result<(), String> {
    let corpora = args.first().is_some_and(|arg| arg == "--xmlenc-corpora");
    if corpora && args.len() != 1 {
        return Err("--xmlenc-corpora accepts no additional paths".into());
    }
    let paths = if corpora {
        XMLENC_CORPORA
            .iter()
            .map(|path| (*path).to_owned())
            .collect()
    } else if args.is_empty() {
        default_paths()
    } else {
        args
    };
    for path in &paths {
        import(donor_root, fixture_root, path)?;
    }
    if corpora {
        // Every imported byte is pinned, outside the byte-for-byte donor snapshots.
        let target = fixture_root.join("xmlenc/corpora.sha256");
        let manifest = beside(&target, "manifest")?;
        std::fs::write(&manifest, corpora_inventory(fixture_root, &XMLENC_CORPORA)?)
            .map_err(|error| error.to_string())?;
        replace(&manifest, &target)?;
    }
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    if let Some(rest) = args.strip_prefix(&["--cli".to_owned()]) {
        return Ok(cli::run(rest)?);
    }
    let root = root();
    let donor_root = std::env::var_os("XMLSEC_DONOR_ROOT")
        .filter(|path| !path.is_empty())
        .map_or_else(|| root.join("donors/xmlsec/tests"), PathBuf::from);
    Ok(execute(&donor_root, &root.join("tests/fixtures"), args)?)
}
