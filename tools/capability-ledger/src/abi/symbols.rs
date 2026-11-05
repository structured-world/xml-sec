//! Exported symbols of the built libraries, each tied to its ledger declaration.

use super::{LIBRARIES, LedgerEntry};
use object::{BinaryFormat, Object, ObjectSymbol, SymbolKind, SymbolScope};
use serde::Serialize;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// The ledger kinds that declare an exported symbol.
const DECLARING_KINDS: [&str; 4] = [
    "export-function",
    "export-variable",
    "backend-api",
    "internal-export",
];

#[derive(Serialize)]
pub(super) struct Library {
    pub(super) name: &'static str,
    pub(super) symbols: Vec<Symbol>,
    /// Exports outside the `xmlSec` namespace: the oracle embeds its OpenSSL
    /// statically, so they are that library's surface, not libxmlsec1's. They
    /// are counted and digested rather than listed, which still detects drift.
    foreign: Foreign,
}

#[derive(Serialize)]
pub(super) struct Symbol {
    pub(super) name: String,
    pub(super) kind: Kind,
    /// The object size where the format records it (ELF data objects).
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// The ledger kind declaring it with an export marker; absent for an
    /// export no header marks, which the ownership rules must list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) declaration: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Kind {
    Function,
    Data,
}

#[derive(Serialize)]
struct Foreign {
    count: usize,
    sha256: String,
}

/// The format and architecture the libraries were built for.
pub(super) struct Binary {
    pub(super) format: String,
    pub(super) architecture: String,
}

pub(super) fn read(
    directory: &Path,
    ledger: &[LedgerEntry],
) -> Result<(Vec<Library>, Binary), String> {
    let declared: BTreeMap<&str, &str> = ledger
        .iter()
        .filter(|item| DECLARING_KINDS.contains(&item.kind.as_str()))
        .map(|item| (item.name.as_str(), item.kind.as_str()))
        .collect();
    let mut binary: Option<Binary> = None;
    let mut libraries = Vec::with_capacity(LIBRARIES.len());
    for name in LIBRARIES {
        let path = library_path(directory, name)?;
        let data = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let file = object::File::parse(&*data)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        let this = Binary {
            format: format_name(file.format())?.to_owned(),
            architecture: format!("{:?}", file.architecture()).to_lowercase(),
        };
        match &binary {
            None => binary = Some(this),
            Some(first)
                if first.format != this.format || first.architecture != this.architecture =>
            {
                return Err(format!("{} targets another platform", path.display()));
            }
            Some(_) => {}
        }
        let exports = exports(&file).map_err(|error| format!("{}: {error}", path.display()))?;
        libraries.push(
            library(name, exports, &declared)
                .map_err(|error| format!("{}: {error}", path.display()))?,
        );
    }
    let binary = binary.ok_or("no library was read")?;
    Ok((libraries, binary))
}

/// The shared library itself, whichever extension the platform uses.
fn library_path(directory: &Path, name: &str) -> Result<std::path::PathBuf, String> {
    ["so", "dylib"]
        .iter()
        .map(|extension| directory.join(format!("{name}.{extension}")))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("{name} is not installed in {}", directory.display()))
}

fn format_name(format: BinaryFormat) -> Result<&'static str, String> {
    match format {
        BinaryFormat::Elf => Ok("elf"),
        BinaryFormat::MachO => Ok("macho"),
        other => Err(format!("unsupported library format {other:?}")),
    }
}

/// One exported definition as the object file states it.
pub(super) struct Export {
    pub(super) name: String,
    pub(super) kind: Kind,
    pub(super) size: Option<u64>,
}

/// Every dynamically exported definition. An export of an unexpected symbol
/// kind is an error rather than skipped.
fn exports(file: &object::File<'_>) -> Result<Vec<Export>, String> {
    let elf = file.format() == BinaryFormat::Elf;
    // ELF exports live in the dynamic table; Mach-O marks them in the symbol table.
    let table = if elf {
        file.dynamic_symbols()
    } else {
        file.symbols()
    };
    let mut exports = Vec::new();
    for symbol in table {
        if !symbol.is_definition() || symbol.scope() != SymbolScope::Dynamic {
            continue;
        }
        let raw = symbol.name().map_err(|error| error.to_string())?;
        // Mach-O prefixes C names with an underscore.
        let name = if elf {
            raw
        } else {
            raw.strip_prefix('_').unwrap_or(raw)
        };
        let kind = match symbol.kind() {
            SymbolKind::Text => Kind::Function,
            SymbolKind::Data => Kind::Data,
            other => return Err(format!("export {name} has unexpected kind {other:?}")),
        };
        let size = (elf && kind == Kind::Data).then(|| symbol.size());
        exports.push(Export {
            name: name.to_owned(),
            kind,
            size,
        });
    }
    Ok(exports)
}

pub(super) fn library(
    name: &'static str,
    exports: Vec<Export>,
    declared: &BTreeMap<&str, &str>,
) -> Result<Library, String> {
    let mut own = BTreeMap::new();
    let mut foreign = BTreeSet::new();
    for export in exports {
        let duplicate = if export.name.starts_with("xmlSec") {
            let declaration = declared
                .get(export.name.as_str())
                .map(|kind| (*kind).to_owned());
            let name = export.name.clone();
            own.insert(
                export.name.clone(),
                Symbol {
                    name,
                    kind: export.kind,
                    size: export.size,
                    declaration,
                },
            )
            .is_some()
        } else {
            !foreign.insert(export.name.clone())
        };
        if duplicate {
            return Err(format!("{} is exported twice", export.name));
        }
    }
    let mut hasher = sha2::Sha256::new();
    for name in &foreign {
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
    }
    let mut sha256 = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(sha256, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(Library {
        name,
        symbols: own.into_values().collect(),
        foreign: Foreign {
            count: foreign.len(),
            sha256,
        },
    })
}
