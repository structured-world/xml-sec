//! `xmlsec1-headers [--check]`: the generic `xmlsec/*.h` headers of
//! `xml-sec-xmlsec1` are the oracle libxmlsec1's installed headers with two
//! edits, so C sources see the declarations, layouts and macros they were
//! written against: libxml2's headers are replaced by the library's own tree
//! header (`xs_tree.h`), and the functions that read a file or an external
//! entity themselves or take a libxml2 parser context ([`NOT_OFFERED`]) are
//! left out. The string
//! constants those headers declare (`strings.h`) carry the bytes the oracle
//! library exports under the same names, read from its shared library; its
//! `version.h` numbers become the crate's version module and the `Version:`
//! line of its pkg-config template.
//! Without arguments the command writes the headers and generates the string
//! table from the oracle installed under `XMLSEC1_PREFIX`; `--check` fails on
//! any difference. Backend headers (`xmlsec/openssl/...`) are not part of the
//! generic tier.

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

/// libxmlsec1 functions the library does not offer, with why: they read a
/// file or an external entity themselves, where the caller reads and passes
/// bytes, or take a libxml2 parser context, which the library has none of.
pub(crate) const NOT_OFFERED: [(&str, &str); 8] = [
    (
        "xmlSecBufferReadFile",
        "the library reads no file; the caller passes the bytes",
    ),
    (
        "xmlSecKeyReadBinaryFile",
        "the library reads no file; the caller passes the bytes to xmlSecKeyReadMemory",
    ),
    (
        "xmlSecParseFile",
        "the library reads no file; the caller passes the bytes",
    ),
    (
        "xmlSecSimpleKeysStoreLoad",
        "the library reads no file; the caller reads its keys and adopts them",
    ),
    (
        "xmlSecSimpleKeysStoreLoad_ex",
        "the library reads no file; the caller reads its keys and adopts them",
    ),
    (
        "xmlSecSimpleKeysStoreSave",
        "the library writes no file; the caller writes its keys",
    ),
    (
        "xmlSecParsePrepareCtxt",
        "the library parses with its own parser, not a libxml2 context",
    ),
    (
        "xmlSecSetExternalEntityLoader",
        "the library loads no external entity",
    ),
];

/// The include that replaces libxml2's headers.
const TREE_INCLUDE: &str = "#include <xs_tree.h>";

/// Lines of libxmlsec1's headers that read a field of a tree type, which
/// `xs_tree.h` declares incomplete, with the line that reads it through the
/// tree's accessor instead.
pub(crate) const FIELD_READS: [(&str, &str); 1] = [(
    "    (((node)) ? ((const char*)((node)->name)) : NULL)",
    "    (((node)) ? ((const char*)xsNodeName(node)) : NULL)",
)];

/// `header` with libxml2's includes replaced by one include of the tree
/// header, every declaration of a [`NOT_OFFERED`] function replaced by a
/// comment saying so, and every [`FIELD_READS`] line read through the
/// accessor.
pub(crate) fn adapted(header: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(header).map_err(|_| "a header is not UTF-8")?;
    let mut lines = Vec::new();
    let mut included = false;
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        if skipping {
            skipping = !line.contains(';');
            continue;
        }
        if line.trim_start().starts_with("#include <libxml/") {
            if !included {
                lines.push(format!("{TREE_INCLUDE}\n"));
                included = true;
            }
            continue;
        }
        let declared = NOT_OFFERED.iter().find(|(name, _)| {
            line.starts_with("XMLSEC_EXPORT")
                && line
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .any(|word| word == *name)
        });
        if let Some((name, reason)) = declared {
            lines.push(format!("/* {name} is not offered: {reason}. */\n"));
            skipping = !line.contains(';');
            continue;
        }
        let body = line.trim_end_matches(['\r', '\n']);
        if let Some((_, accessor)) = FIELD_READS.iter().find(|(field, _)| *field == body) {
            lines.push(format!("{accessor}{}", &line[body.len()..]));
            continue;
        }
        lines.push(line.to_owned());
    }
    Ok(lines.concat().into_bytes())
}

/// Where the crate keeps its copy.
pub(crate) const TARGET: &str = "crates/xml-sec-xmlsec1/include/xmlsec";
/// The generated string table of the crate.
pub(crate) const STRINGS: &str = "crates/xml-sec-xmlsec1/src/ffi/strings.rs";
/// The ledger listing every exported string constant.
const LEDGER: &str = "compatibility/libxmlsec1.json";

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
        "//! bytes the oracle library exports under the same names. Generated by".to_owned(),
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

/// The Rust version module of the crate.
pub(crate) const VERSION_MODULE: &str = "crates/xml-sec-xmlsec1/src/ffi/version.rs";
/// The crate's pkg-config template, whose `Version:` line names the version.
pub(crate) const PKG_CONFIG: &str = "crates/xml-sec-xmlsec1/xml-sec-xmlsec1.pc.in";

/// The `XMLSEC_VERSION_MAJOR`, `_MINOR` and `_SUBMINOR` numbers of a
/// `version.h`.
pub(crate) fn header_version(version_h: &str) -> Result<(u32, u32, u32), String> {
    let number = |name: &str| {
        version_h
            .lines()
            .find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("#define") && words.next() == Some(name))
                    .then(|| words.next())
                    .flatten()
            })
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| format!("version.h defines no number {name}"))
    };
    Ok((
        number("XMLSEC_VERSION_MAJOR")?,
        number("XMLSEC_VERSION_MINOR")?,
        number("XMLSEC_VERSION_SUBMINOR")?,
    ))
}

/// The Rust module carrying `version` to the library's version checks.
pub(crate) fn render_version((major, minor, subminor): (u32, u32, u32)) -> String {
    [
        "//! `xmlsec/version.h`: the version of libxmlsec1 the headers are, as".to_owned(),
        "//! `xmlSecCheckVersionExt` compares a caller's against. Generated by".to_owned(),
        "//! `xml-sec-tools xmlsec1-headers`; edits are overwritten.".to_owned(),
        String::new(),
        "/// `XMLSEC_VERSION_MAJOR`, `XMLSEC_VERSION_MINOR`, `XMLSEC_VERSION_SUBMINOR`.".to_owned(),
        format!(
            "pub(crate) const VERSION: (core::ffi::c_int, core::ffi::c_int, core::ffi::c_int) = ({major}, {minor}, {subminor});"
        ),
        String::new(),
    ]
    .join("\n")
}

/// The pkg-config `template` with its `Version:` line naming `version`.
pub(crate) fn versioned_template(
    template: &str,
    (major, minor, subminor): (u32, u32, u32),
) -> Result<String, String> {
    let mut found = false;
    let lines: Vec<String> = template
        .split_inclusive('\n')
        .map(|line| {
            if line.starts_with("Version:") {
                found = true;
                let ending = &line[line.trim_end_matches(['\r', '\n']).len()..];
                format!("Version: {major}.{minor}.{subminor}{ending}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    if found {
        Ok(lines.concat())
    } else {
        Err(format!("{PKG_CONFIG} has no Version line"))
    }
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

/// Headers whose copy in `target` differs from the [`adapted`] header of
/// `source`, or is missing in either directory.
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
        let expected = read(source)?.map(|bytes| adapted(&bytes)).transpose()?;
        let actual = read(target)?;
        if expected.is_none() || expected != actual {
            different.push(header.to_owned());
        }
    }
    Ok(different)
}

/// Writes the [`adapted`] copy of every header of `source` to `target`.
pub(crate) fn copy(source: &Path, target: &Path) -> Result<(), Failure> {
    std::fs::create_dir_all(target)
        .map_err(|error| format!("create {}: {error}", target.display()))?;
    for header in HEADERS {
        let from = source.join(header);
        let to = target.join(header);
        let bytes =
            std::fs::read(&from).map_err(|error| format!("read {}: {error}", from.display()))?;
        std::fs::write(&to, adapted(&bytes)?)
            .map_err(|error| format!("write {}: {error}", to.display()))?;
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
    let version_h = source.join("version.h");
    let version = header_version(
        &std::fs::read_to_string(&version_h)
            .map_err(|error| format!("read {}: {error}", version_h.display()))?,
    )?;
    let module = render_version(version);
    let template_path = root().join(PKG_CONFIG);
    let template = versioned_template(
        &std::fs::read_to_string(&template_path)
            .map_err(|error| format!("read {PKG_CONFIG}: {error}"))?,
        version,
    )?;
    let generated = [
        (root().join(STRINGS), strings),
        (root().join(VERSION_MODULE), module),
        (template_path, template),
    ];
    if check {
        let different = differences(&source, &target)?;
        if !different.is_empty() {
            return Err(
                format!("{TARGET} differs from {}: {different:?}", source.display()).into(),
            );
        }
        for (path, expected) in &generated {
            let current = std::fs::read_to_string(path).unwrap_or_default();
            if current != *expected {
                return Err(format!(
                    "{} differs from what {} generates",
                    path.display(),
                    prefix.display()
                )
                .into());
            }
        }
        Ok(())
    } else {
        copy(&source, &target)?;
        for (path, text) in generated {
            std::fs::write(&path, text)
                .map_err(|error| format!("write {}: {error}", path.display()))?;
        }
        Ok(())
    }
}
