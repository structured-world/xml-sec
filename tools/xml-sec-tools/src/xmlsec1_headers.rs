//! `xmlsec1-headers [--check]`: the generic `xmlsec/*.h` headers of
//! `xml-sec-xmlsec1` are the pinned libxmlsec1's installed headers, byte for
//! byte, so C sources see exactly the declarations, layouts and macros they
//! were written against; the string constants those headers declare
//! (`strings.h`) carry the bytes the pinned library exports under the same
//! names, read from its shared library. Without arguments the command copies
//! the headers and generates the string table from the oracle installed under
//! `XMLSEC1_PREFIX`; `--check` fails on any difference. Backend headers
//! (`xmlsec/openssl/...`) are not part of the generic tier.

use crate::repo::{Failure, root};
use object::{NameOrOrdinal, Object as _, ObjectSection as _};
use serde_json::Value;
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
/// The generated string table of the crate.
pub(crate) const STRINGS: &str = "crates/xml-sec-xmlsec1/src/ffi/strings.rs";
/// The ledger listing every exported string constant.
const LEDGER: &str = "compatibility/libxmlsec1-1.3.13.json";

/// The string constants the ledger records as exported variables.
pub(crate) fn declared_strings(ledger: &str) -> Result<Vec<String>, String> {
    let ledger: Value =
        serde_json::from_str(ledger).map_err(|error| format!("parse {LEDGER}: {error}"))?;
    let mut names: Vec<String> = ledger["items"]
        .as_array()
        .ok_or("the ledger has no items")?
        .iter()
        .filter(|item| item["kind"] == "export-variable")
        .filter_map(|item| item["name"].as_str().map(str::to_owned))
        .collect();
    names.sort();
    Ok(names)
}

/// The oracle's shared library under `prefix`.
pub(crate) fn library(prefix: &Path) -> PathBuf {
    prefix.join("lib").join(format!(
        "{}xmlsec1{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ))
}

/// The bytes, through the terminating NUL, of each of `names` the shared
/// library `library` exports as data. Names it does not export are left
/// out: their declarations are conditional on a feature the oracle omits.
pub(crate) fn exported_strings(
    library: &[u8],
    names: &[String],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let file =
        object::File::parse(library).map_err(|error| format!("parse the library: {error}"))?;
    let mut addresses = std::collections::BTreeMap::new();
    for export in file
        .exports()
        .map_err(|error| format!("library exports: {error}"))?
    {
        let export = export.map_err(|error| format!("library export: {error}"))?;
        // Only data in the image has bytes to read.
        let object::ExportTarget::Address { address } = export.target() else {
            continue;
        };
        let NameOrOrdinal::Name(name) = export.into_name() else {
            continue;
        };
        let name = String::from_utf8_lossy(&name).into_owned();
        // Mach-O prefixes C symbols with an underscore.
        let name = match file.format() {
            object::BinaryFormat::MachO => name
                .strip_prefix('_')
                .map_or_else(|| name.clone(), str::to_owned),
            _ => name,
        };
        addresses.insert(name, address);
    }
    let mut strings = Vec::new();
    for name in names {
        let Some(&address) = addresses.get(name) else {
            continue;
        };
        let section = file
            .sections()
            .find(|section| {
                section.address() <= address && address < section.address() + section.size()
            })
            .ok_or_else(|| format!("{name} lies in no section"))?;
        let data = section
            .data()
            .map_err(|error| format!("section of {name}: {error}"))?;
        let start = usize::try_from(address - section.address())
            .map_err(|_| format!("{name} lies beyond the address space"))?;
        // A section without file contents (`.bss`) has fewer bytes than its
        // address range.
        let rest = data
            .get(start..)
            .ok_or_else(|| format!("{name} lies beyond the bytes of its section"))?;
        let end = rest
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| format!("{name} is not NUL-terminated"))?;
        strings.push((name.clone(), rest[..=end].to_vec()));
    }
    Ok(strings)
}

/// The Rust source exporting `strings` under their C names.
pub(crate) fn render(strings: &[(String, Vec<u8>)]) -> String {
    let mut lines = vec![
        "//! `xmlsec/strings.h`: the string constants libxmlsec1 exports, with the".to_owned(),
        "//! bytes the pinned library exports under the same names. Generated by".to_owned(),
        "//! `xml-sec-tools xmlsec1-headers`; edits are overwritten.".to_owned(),
    ];
    for (name, bytes) in strings {
        let text: String = bytes
            .iter()
            .map(|&byte| match byte {
                b'"' => "\\\"".to_owned(),
                b'\\' => "\\\\".to_owned(),
                0 => "\\0".to_owned(),
                0x20..=0x7e => char::from(byte).to_string(),
                _ => format!("\\x{byte:02x}"),
            })
            .collect();
        lines.push(String::new());
        lines.push("#[unsafe(no_mangle)]".to_owned());
        let declaration = format!("pub(crate) static {name}: [u8; {}] =", bytes.len());
        let value = format!("*b\"{text}\";");
        // rustfmt's layout: one line within 100 columns, else the value on
        // its own indented line.
        if declaration.len() + 1 + value.len() <= 100 {
            lines.push(format!("{declaration} {value}"));
        } else {
            lines.push(declaration);
            lines.push(format!("    {value}"));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

/// The string table generated from the oracle under `prefix`.
fn generated_strings(prefix: &Path) -> Result<String, Failure> {
    let ledger = std::fs::read_to_string(root().join(LEDGER))
        .map_err(|error| format!("read {LEDGER}: {error}"))?;
    let path = library(prefix);
    let bytes =
        std::fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(render(&exported_strings(
        &bytes,
        &declared_strings(&ledger)?,
    )?))
}

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
    let strings = generated_strings(&prefix)?;
    let table = root().join(STRINGS);
    if check {
        let different = differences(&source, &target)?;
        if !different.is_empty() {
            return Err(
                format!("{TARGET} differs from {}: {different:?}", source.display()).into(),
            );
        }
        let current = std::fs::read_to_string(&table).unwrap_or_default();
        if current != strings {
            return Err(format!(
                "{STRINGS} differs from the strings {} exports",
                library(&prefix).display()
            )
            .into());
        }
        Ok(())
    } else {
        copy(&source, &target)?;
        std::fs::write(&table, strings)
            .map_err(|error| format!("write {}: {error}", table.display()))?;
        Ok(())
    }
}
