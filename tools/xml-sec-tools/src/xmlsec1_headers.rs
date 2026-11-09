//! `xmlsec1-headers [--check]`: the generic `xmlsec/*.h` headers of
//! `xml-sec-xmlsec1` are the pinned libxmlsec1's installed headers, byte for
//! byte, so C sources see exactly the declarations, layouts and macros they
//! were written against. Without arguments the command copies them from the
//! oracle installed under `XMLSEC1_PREFIX`; `--check` fails on any difference.
//! Backend headers (`xmlsec/openssl/...`) are not part of the generic tier.

use crate::repo::{Failure, root};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// Every generic header libxmlsec1 installs.
pub(crate) const HEADERS: [&str; 27] = [
    "app.h",
    "base64.h",
    "bn.h",
    "buffer.h",
    "crypto.h",
    "dl.h",
    "errors.h",
    "exports.h",
    "io.h",
    "keyinfo.h",
    "keys.h",
    "keysdata.h",
    "keysmngr.h",
    "list.h",
    "membuf.h",
    "nodeset.h",
    "parser.h",
    "private.h",
    "strings.h",
    "templates.h",
    "transforms.h",
    "version.h",
    "x509.h",
    "xmldsig.h",
    "xmlenc.h",
    "xmlsec.h",
    "xmltree.h",
];

/// Where the crate keeps its copy.
pub(crate) const TARGET: &str = "crates/xml-sec-xmlsec1/include/xmlsec";

/// The installed headers of the oracle under `prefix`.
pub(crate) fn source(prefix: &Path) -> PathBuf {
    prefix.join("include/xmlsec1/xmlsec")
}

/// Headers whose copy in `target` differs from `source`, or is missing in
/// either directory.
pub(crate) fn differences(source: &Path, target: &Path) -> Result<Vec<String>, Failure> {
    let mut different = Vec::new();
    for header in HEADERS {
        let read = |dir: &Path| {
            let path = dir.join(header);
            match std::fs::read(&path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(Failure::from(format!("read {}: {error}", path.display()))),
            }
        };
        let (expected, actual) = (read(source)?, read(target)?);
        if expected.is_none() || expected != actual {
            different.push(header.to_owned());
        }
    }
    Ok(different)
}

/// Copies every header from `source` to `target`.
pub(crate) fn copy(source: &Path, target: &Path) -> Result<(), Failure> {
    std::fs::create_dir_all(target)
        .map_err(|error| format!("create {}: {error}", target.display()))?;
    for header in HEADERS {
        let from = source.join(header);
        let to = target.join(header);
        std::fs::copy(&from, &to)
            .map_err(|error| format!("copy {} to {}: {error}", from.display(), to.display()))?;
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let check = match (args.next().as_deref(), args.next()) {
        (None, None) => false,
        (Some("--check"), None) => true,
        _ => {
            return Err(Failure {
                code: 2,
                message: "usage: xml-sec-tools xmlsec1-headers [--check] (reads XMLSEC1_PREFIX)"
                    .into(),
            });
        }
    };
    let prefix = std::env::var_os("XMLSEC1_PREFIX")
        .map(PathBuf::from)
        .ok_or("XMLSEC1_PREFIX must name the installed libxmlsec1 oracle")?;
    let source = source(&prefix);
    let target = root().join(TARGET);
    if check {
        let different = differences(&source, &target)?;
        if !different.is_empty() {
            return Err(
                format!("{TARGET} differs from {}: {different:?}", source.display()).into(),
            );
        }
        Ok(())
    } else {
        copy(&source, &target)
    }
}
