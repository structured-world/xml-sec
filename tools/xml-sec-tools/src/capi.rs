//! `capi [--sanitize | --xmlsec1]`: qualifies the C ABI as C and C++ callers
//! see it, for the clean C API and, on Linux and macOS, for the libxml2 bridge
//! that exports it together with its own entry point. Cargo builds each shared
//! library and names it in its artifact messages; the round-trip programs are
//! built against the headers and that library with the platform's compiler
//! and run, and the library must export exactly the functions its headers
//! declare. `--sanitize`, on Linux, builds the libraries and runs the crates'
//! tests with the address sanitizer on nightly, and builds the programs with
//! the address (leak checking included) and undefined behavior sanitizers.
//! `--xmlsec1` qualifies the libxmlsec1-compatible library against the pinned
//! libxmlsec1 installed under `XMLSEC1_PREFIX`: every program, including one
//! generated from the binary baseline that prints every recorded structure
//! layout, is built once against the oracle and once against the library,
//! unmodified, and both must print the same.

use crate::repo::{Failure, Run, Step, System, describe, require, root};
use object::{NameOrOrdinal, Object as _};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

const HEADER: &str = "crates/xml-sec-capi/include/xml_sec.h";
/// Declared for libraries built with the FIPS engine only.
const FIPS_ONLY: &str = "xs_provider_new_aws_lc_fips";
/// The libxml2 package `pkg-config` resolves for the bridge's programs, as
/// the bridge's build script does for the bridge itself.
const LIBXML2: &str = "libxml-2.0";

/// How the library and the programs are built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Plain,
    Sanitized,
}

/// A shared library this command qualifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// The clean C API.
    Clean,
    /// The libxml2 bridge, which reexports the clean C API.
    Libxml2,
    /// The libxmlsec1-compatible library, which reexports both.
    Xmlsec1,
}

/// The libxmlsec1-compatible crate, its headers and its pkg-config template.
const XMLSEC1_CRATE: &str = "crates/xml-sec-xmlsec1";
/// The binary baseline of the tuple CI records.
const ABI_BASELINE: &str = "compatibility/libxmlsec1-1.3.13-abi-linux-x86_64.json";
/// The pkg-config package of the oracle.
const XMLSEC1: &str = "xmlsec1";

impl Target {
    pub(crate) const fn package(self) -> &'static str {
        match self {
            Self::Clean => "xml-sec-capi",
            Self::Libxml2 => "xml-sec-libxml2",
            Self::Xmlsec1 => "xml-sec-xmlsec1",
        }
    }

    /// The library name cargo reports and the linker resolves.
    pub(crate) const fn artifact(self) -> &'static str {
        match self {
            Self::Clean => "xml_sec_capi",
            Self::Libxml2 => "xml_sec_libxml2",
            Self::Xmlsec1 => "xml_sec_xmlsec1",
        }
    }

    const fn crate_dir(self) -> &'static str {
        match self {
            Self::Clean => "crates/xml-sec-capi",
            Self::Libxml2 => "crates/xml-sec-libxml2",
            Self::Xmlsec1 => XMLSEC1_CRATE,
        }
    }

    /// Every header of the clean surface whose functions the library exports.
    pub(crate) const fn headers(self) -> &'static [&'static str] {
        match self {
            Self::Clean => &[HEADER],
            Self::Libxml2 | Self::Xmlsec1 => {
                &[HEADER, "crates/xml-sec-libxml2/include/xml_sec_libxml2.h"]
            }
        }
    }

    /// The include directories the target's programs compile with.
    fn includes(self) -> Vec<String> {
        if self == Self::Xmlsec1 {
            // Programs include `<xmlsec/...>` from the crate's tree.
            return vec![
                root()
                    .join(XMLSEC1_CRATE)
                    .join("include")
                    .display()
                    .to_string(),
            ];
        }
        self.headers()
            .iter()
            .map(|header| {
                let header = root().join(header);
                header
                    .parent()
                    .expect("a header lies in a directory")
                    .display()
                    .to_string()
            })
            .collect()
    }

    /// The round-trip programs, relative to the crate.
    const fn sources(self) -> &'static [&'static str] {
        match self {
            Self::Clean => &["tests/c/roundtrip.c", "tests/cpp/roundtrip.cpp"],
            Self::Libxml2 => &["tests/c/roundtrip.c"],
            Self::Xmlsec1 => &[
                "tests/c/core.c",
                "tests/c/nodeset.c",
                "tests/c/base64.c",
                "tests/c/transforms.c",
                "tests/c/xpath.c",
                "tests/c/parser.c",
                "tests/c/keysdata.c",
                "tests/c/errors.c",
            ],
        }
    }
}

/// The libraries qualified on this platform. The bridge has no claimed support
/// level on other systems; it is reported as not qualified rather than built.
pub(crate) const fn targets() -> &'static [Target] {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        &[Target::Clean, Target::Libxml2]
    } else {
        &[Target::Clean]
    }
}

/// The library build: cargo's own messages name the artifacts, whatever the
/// build-directory layout.
pub(crate) fn build_step(target: Target, mode: Mode, host: &str, rustflags: Option<&str>) -> Step {
    cargo_step(
        "build library",
        mode,
        host,
        rustflags,
        &[
            "build",
            "-p",
            target.package(),
            "--lib",
            "--message-format=json-render-diagnostics",
        ],
    )
}

/// The crates' own tests, run under the sanitizer with their libraries.
pub(crate) fn test_step(host: &str, rustflags: Option<&str>) -> Step {
    let mut args = vec!["nextest", "run"];
    for target in targets() {
        args.extend(["-p", target.package()]);
    }
    // The libxmlsec1-compatible library builds where the bridge does.
    if targets().contains(&Target::Libxml2) {
        args.extend(["-p", Target::Xmlsec1.package()]);
    }
    cargo_step("sanitized tests", Mode::Sanitized, host, rustflags, &args)
}

fn cargo_step(label: &str, mode: Mode, host: &str, rustflags: Option<&str>, args: &[&str]) -> Step {
    match mode {
        Mode::Plain => Step::new(label, "cargo", args),
        Mode::Sanitized => {
            // An explicit target keeps the sanitizer out of build scripts and
            // procedural macros, which run on the host toolchain.
            let args = [&["+nightly"][..], args, &["--target", host]].concat();
            let flags = match rustflags.filter(|flags| !flags.trim().is_empty()) {
                Some(flags) => format!("{flags} -Zsanitizer=address"),
                None => "-Zsanitizer=address".to_owned(),
            };
            Step::new(label, "cargo", &args).with_env("RUSTFLAGS", flags)
        }
    }
}

/// The host triple `rustc -vV` reports.
pub(crate) fn host(version: &str) -> Result<String, String> {
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_owned())
        .ok_or_else(|| "rustc -vV reported no host".to_owned())
}

/// The shared library cargo built, and its import library on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Library {
    pub(crate) shared: PathBuf,
    pub(crate) import: Option<PathBuf>,
}

impl Library {
    pub(crate) fn directory(&self) -> &Path {
        self.shared
            .parent()
            .expect("an artifact path names its directory")
    }
}

/// The library named by the `compiler-artifact` message of `target`'s crate
/// in `messages`, cargo's JSON output.
pub(crate) fn library(messages: &str, target: Target, suffix: &str) -> Result<Library, String> {
    let package = target.package();
    for line in messages.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact"
            || message["target"]["name"] != target.artifact()
        {
            continue;
        }
        let files: Vec<PathBuf> = message["filenames"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(PathBuf::from)
            .collect();
        let named = |end: &str| {
            files
                .iter()
                .find(|file| file.to_string_lossy().ends_with(end))
                .cloned()
        };
        let shared = named(suffix)
            .ok_or_else(|| format!("cargo reported no shared library for {package}"))?;
        return Ok(Library {
            shared,
            import: named(".dll.lib"),
        });
    }
    Err(format!("cargo reported no artifact for {package}"))
}

/// Function names of the clean surface `header` declares.
pub(crate) fn declared(header: &str) -> BTreeSet<String> {
    declared_with(header, "xs_")
}

/// Function names starting with `prefix` that `header` declares: the
/// identifier right before a parameter list, outside comments and
/// preprocessor lines. libxmlsec1 aligns its parameter lists with spaces and
/// sometimes starts one on the line after the name.
pub(crate) fn declared_with(header: &str, prefix: &str) -> BTreeSet<String> {
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let code: Vec<&str> = header
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !["/*", "*", "#"]
                .iter()
                .any(|start| trimmed.starts_with(start))
        })
        .collect();
    let code = code.join("\n");
    let mut names = BTreeSet::new();
    let mut rest = code.as_str();
    while let Some(open) = rest.find('(') {
        let before = rest[..open].trim_end();
        let start = before
            .rfind(|c: char| !identifier(c))
            .map_or(0, |at| at + 1);
        rest = &rest[open + 1..];
        // `type (*name)(...)` declares a function pointer, whose return type
        // is not a function.
        let pointer = rest.trim_start().starts_with('*');
        if !pointer && before[start..].starts_with(prefix) {
            names.insert(before[start..].to_owned());
        }
    }
    names
}

/// Function names of the clean surface the shared library at `path` exports.
pub(crate) fn exported(path: &Path) -> Result<BTreeSet<String>, String> {
    exported_with(path, "xs_")
}

/// Names starting with `prefix` the shared library at `path` exports.
pub(crate) fn exported_with(path: &Path, prefix: &str) -> Result<BTreeSet<String>, String> {
    let data = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let file = object::File::parse(&*data)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    let mut names = BTreeSet::new();
    for export in file
        .exports()
        .map_err(|error| format!("exports of {}: {error}", path.display()))?
    {
        let export = export.map_err(|error| format!("export of {}: {error}", path.display()))?;
        let NameOrOrdinal::Name(name) = export.into_name() else {
            continue;
        };
        let name = String::from_utf8_lossy(&name);
        // Mach-O prefixes C symbols with an underscore.
        let name = match file.format() {
            object::BinaryFormat::MachO => name.strip_prefix('_').unwrap_or(&name),
            _ => &name,
        };
        if name.starts_with(prefix) {
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}

/// The header's functions that the library must export: all of them, except
/// the FIPS engine's constructor in a library built without it.
pub(crate) fn symbol_mismatch(
    declared: &BTreeSet<String>,
    exported: &BTreeSet<String>,
) -> Option<String> {
    let undeclared: Vec<&String> = exported.difference(declared).collect();
    let missing: Vec<&String> = declared
        .difference(exported)
        .filter(|name| *name != FIPS_ONLY)
        .collect();
    (!undeclared.is_empty() || !missing.is_empty()).then(|| {
        format!("exported but not declared: {undeclared:?}; declared but not exported: {missing:?}")
    })
}

/// A program to build against `library`: its source, the executable it
/// becomes, and the compiler and linker flags of the libraries it calls
/// directly besides the target's own.
pub(crate) struct Program<'a> {
    pub(crate) source: &'a Path,
    pub(crate) output: &'a Path,
    pub(crate) flags: &'a [String],
}

/// The compiler invocation that builds `program` against `target`'s headers
/// and `library`.
pub(crate) fn compile_step(
    compiler: &cc::Tool,
    mode: Mode,
    target: Target,
    program: &Program<'_>,
    library: &Library,
) -> Result<Step, String> {
    let Program {
        source,
        output,
        flags,
    } = *program;
    let directory = library.directory().display().to_string();
    let cpp = source
        .extension()
        .is_some_and(|extension| extension == "cpp");
    let mut args: Vec<String> = compiler
        .args()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    args.push(source.display().to_string());
    if compiler.is_like_msvc() {
        let import = library
            .import
            .as_ref()
            .ok_or_else(|| format!("cargo reported no import library for {}", target.package()))?;
        args.extend(
            target
                .includes()
                .into_iter()
                .map(|include| format!("/I{include}")),
        );
        args.extend([
            (if cpp { "/std:c++17" } else { "/std:c11" }).to_owned(),
            // The programs read their key files with portable stdio.
            "/D_CRT_SECURE_NO_WARNINGS".to_owned(),
            "/WX".to_owned(),
            format!("/Fe{}", output.display()),
            format!(
                "/Fo{}\\",
                output.parent().expect("output directory").display()
            ),
            "/link".to_owned(),
            import.display().to_string(),
        ]);
    } else {
        for include in target.includes() {
            args.extend(["-I".to_owned(), include]);
        }
        args.extend([
            (if cpp { "-std=c++17" } else { "-std=c99" }).to_owned(),
            "-Werror".to_owned(),
            "-o".to_owned(),
            output.display().to_string(),
            "-L".to_owned(),
            directory.clone(),
            format!("-l{}", target.artifact()),
            format!("-Wl,-rpath,{directory}"),
        ]);
        args.extend(flags.iter().cloned());
        if mode == Mode::Sanitized {
            args.extend([
                "-fsanitize=address,undefined".to_owned(),
                "-fno-sanitize-recover=all".to_owned(),
                "-fno-omit-frame-pointer".to_owned(),
            ]);
        }
    }
    Ok(compiler_step(compiler, source, args))
}

/// Runs `compiler` with `args`, in the environment `cc` resolved for it.
fn compiler_step(compiler: &cc::Tool, source: &Path, args: Vec<String>) -> Step {
    let mut step = Step {
        label: format!("compile {}", source.display()),
        program: compiler.path().display().to_string(),
        args,
        env: Vec::new(),
        unset: Vec::new(),
        directory: None,
    };
    for (key, value) in compiler.get_envs() {
        step = step.with_env(&key.to_string_lossy(), value.to_string_lossy());
    }
    step
}

/// The compiler invocation that builds the C `program` against the oracle,
/// whose compiler and linker flags `program.flags` carries.
pub(crate) fn oracle_compile_step(compiler: &cc::Tool, program: &Program<'_>) -> Step {
    let mut args: Vec<String> = compiler
        .args()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    args.extend([
        program.source.display().to_string(),
        "-std=c99".to_owned(),
        "-Werror".to_owned(),
        "-o".to_owned(),
        program.output.display().to_string(),
    ]);
    args.extend(program.flags.iter().cloned());
    compiler_step(compiler, program.source, args)
}

/// The `-D` flags of the crate's pkg-config template, which a consumer of
/// the libxmlsec1-compatible library compiles with.
pub(crate) fn template_defines(template: &str) -> Result<Vec<String>, String> {
    let cflags = template
        .lines()
        .find_map(|line| line.strip_prefix("Cflags:"))
        .ok_or("the pkg-config template has no Cflags line")?;
    Ok(cflags
        .split_whitespace()
        .filter(|flag| flag.starts_with("-D"))
        .map(str::to_owned)
        .collect())
}

/// A C program printing the size and alignment of every structure of the
/// binary `baseline`, the offset and size of each of its fields, and the
/// value of each enumerator, one per line. Built against the oracle and the
/// library, it compares their layouts under each one's own defines.
pub(crate) fn layout_program(baseline: &str) -> Result<String, String> {
    let baseline: Value =
        serde_json::from_str(baseline).map_err(|error| format!("parse baseline: {error}"))?;
    // `private.h` declares the crypto-library function table and is read
    // only by crypto libraries, which define `XMLSEC_PRIVATE`.
    let mut lines: Vec<String> = [
        "#define XMLSEC_PRIVATE 1",
        "#include <stdio.h>",
        "#include <stddef.h>",
        "#include <stdalign.h>",
        "#include <xmlsec/xmlsec.h>",
    ]
    .map(str::to_owned)
    .into();
    lines.extend(
        LAYOUT_HEADERS
            .iter()
            .map(|header| format!("#include <xmlsec/{header}>")),
    );
    lines.push("int main(void) {".to_owned());
    let structs = baseline["structs"]
        .as_array()
        .ok_or("the baseline has no structs")?;
    for record in structs {
        let name = record["name"].as_str().ok_or("a struct without a name")?;
        lines.push(format!(
            "    printf(\"{name} %zu %zu\\n\", sizeof(struct {name}), alignof(struct {name}));"
        ));
        for field in record["fields"].as_array().into_iter().flatten() {
            let field = field["name"].as_str().ok_or("a field without a name")?;
            lines.push(format!(
                "    printf(\"{name}.{field} %zu %zu\\n\", offsetof(struct {name}, {field}), \
                 sizeof(((struct {name} *)0)->{field}));"
            ));
        }
    }
    for record in baseline["enums"].as_array().into_iter().flatten() {
        for value in record["values"].as_array().into_iter().flatten() {
            let value = value["name"]
                .as_str()
                .ok_or("an enumerator without a name")?;
            lines.push(format!("    printf(\"{value} %d\\n\", (int){value});"));
        }
    }
    lines.extend(["    return 0;".to_owned(), "}".to_owned(), String::new()]);
    let program = lines.join("\n");
    Ok(program)
}

/// The headers the layout program includes: every generic header that
/// declares a structure or enumeration of the baseline.
const LAYOUT_HEADERS: [&str; 14] = [
    "bn.h",
    "buffer.h",
    "keyinfo.h",
    "keys.h",
    "keysdata.h",
    "keysmngr.h",
    "list.h",
    "nodeset.h",
    "private.h",
    "transforms.h",
    "x509.h",
    "xmldsig.h",
    "xmlenc.h",
    "xmltree.h",
];

/// Runs `program` with the library on the loader's search path.
pub(crate) fn program_step(program: &Path, args: &[PathBuf], library: &Library) -> Step {
    let args: Vec<String> = args.iter().map(|arg| arg.display().to_string()).collect();
    let mut step = Step {
        label: format!("run {}", program.display()),
        program: program.display().to_string(),
        args,
        env: Vec::new(),
        unset: Vec::new(),
        directory: None,
    };
    if cfg!(windows) {
        // Windows finds a DLL on PATH; elsewhere the program's rpath names it.
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![library.directory().to_path_buf()];
        dirs.extend(std::env::split_paths(&inherited));
        if let Ok(path) = std::env::join_paths(dirs) {
            step = step.with_env("PATH", path.to_string_lossy());
        }
    }
    step
}

/// Runs `step` with its output captured, and fails with that output.
fn checked(runner: &mut impl Run, step: &Step) -> Result<String, Failure> {
    let (status, output) = runner.combined(step)?;
    if status.success() {
        Ok(output)
    } else {
        Err(format!("{} ({}):\n{output}", step.label, describe(status)).into())
    }
}

/// Every function `target`'s headers declare.
fn declarations(target: Target) -> Result<BTreeSet<String>, Failure> {
    let mut names = BTreeSet::new();
    for header in target.headers() {
        let text = std::fs::read_to_string(root().join(header))
            .map_err(|error| format!("read {header}: {error}"))?;
        names.extend(declared(&text));
    }
    Ok(names)
}

/// The compiler and linker flags the bridge's programs need for libxml2.
fn libxml2_flags(runner: &mut impl Run) -> Result<Vec<String>, Failure> {
    let step = Step::new(
        "libxml2 flags",
        "pkg-config",
        &["--cflags", "--libs", LIBXML2],
    );
    let (status, flags) = runner.stdout(&step)?;
    require(status)?;
    Ok(flags.split_whitespace().map(str::to_owned).collect())
}

pub(crate) fn execute(mode: Mode, runner: &mut impl Run) -> Result<(), Failure> {
    let rustc = match mode {
        Mode::Plain => Step::new("rustc", "rustc", &["-vV"]),
        Mode::Sanitized => Step::new("rustc", "rustc", &["+nightly", "-vV"]),
    };
    let (status, version) = runner.stdout(&rustc)?;
    require(status)?;
    let host = host(&version)?;
    let rustflags = std::env::var("RUSTFLAGS").ok();
    let scratch = tempfile::tempdir().map_err(|error| format!("scratch directory: {error}"))?;
    for &target in targets() {
        qualify(
            target,
            mode,
            &host,
            rustflags.as_deref(),
            scratch.path(),
            runner,
        )?;
    }
    if !targets().contains(&Target::Libxml2) {
        println!(
            "{}: no support level is claimed on {}; not qualified",
            Target::Libxml2.package(),
            std::env::consts::OS
        );
    }
    if mode == Mode::Sanitized {
        if targets().contains(&Target::Libxml2) {
            sanitize_xmlsec1(&host, rustflags.as_deref(), scratch.path(), runner)?;
        }
        require(runner.status(&test_step(&host, rustflags.as_deref()))?)?;
    }
    Ok(())
}

/// Runs the libxmlsec1-compatible library's C programs under the sanitizers;
/// their output is compared with the oracle by `capi --xmlsec1`, here only a
/// sanitizer report or a failing exit fails.
fn sanitize_xmlsec1(
    host: &str,
    rustflags: Option<&str>,
    scratch: &Path,
    runner: &mut impl Run,
) -> Result<(), Failure> {
    let target = Target::Xmlsec1;
    let (status, messages) =
        runner.stdout(&build_step(target, Mode::Sanitized, host, rustflags))?;
    require(status)?;
    let library = library(&messages, target, std::env::consts::DLL_SUFFIX)?;
    let template =
        std::fs::read_to_string(root().join(XMLSEC1_CRATE).join("xml-sec-xmlsec1.pc.in"))
            .map_err(|error| format!("read the pkg-config template: {error}"))?;
    let mut flags = template_defines(&template)?;
    flags.extend(libxml2_flags(runner)?);
    for source in target.sources() {
        let source = root().join(XMLSEC1_CRATE).join(source);
        let compiler = compiler(host, &source)?;
        let name = source
            .file_stem()
            .expect("a source file name")
            .to_string_lossy();
        let output = scratch.join(format!("{name}-sanitized{}", std::env::consts::EXE_SUFFIX));
        let program = Program {
            source: &source,
            output: &output,
            flags: &flags,
        };
        checked(
            runner,
            &compile_step(&compiler, Mode::Sanitized, target, &program, &library)?,
        )?;
        checked(runner, &program_step(&output, &[], &library))?;
        println!("{}: {name}: clean under the sanitizers", target.package());
    }
    Ok(())
}

/// Builds `target`'s library, checks its exports against its headers, and
/// builds and runs its round-trip programs in `scratch`.
fn qualify(
    target: Target,
    mode: Mode,
    host: &str,
    rustflags: Option<&str>,
    scratch: &Path,
    runner: &mut impl Run,
) -> Result<(), Failure> {
    let (status, messages) = runner.stdout(&build_step(target, mode, host, rustflags))?;
    require(status)?;
    let library = library(&messages, target, std::env::consts::DLL_SUFFIX)?;
    if let Some(mismatch) = symbol_mismatch(&declarations(target)?, &exported(&library.shared)?) {
        return Err(format!("{}: {mismatch}", target.package()).into());
    }
    let flags = match target {
        Target::Clean => Vec::new(),
        Target::Libxml2 | Target::Xmlsec1 => libxml2_flags(runner)?,
    };
    let keys = root().join("tests/fixtures/keys/rsa");
    // Every program receives the RSA recipient's private and public key.
    let key_files = [
        keys.join("rsa-2048-key.pem"),
        keys.join("rsa-2048-pubkey.pem"),
    ];
    for source in target.sources() {
        let source = root().join(target.crate_dir()).join(source);
        let compiler = compiler(host, &source)?;
        let name = source
            .file_stem()
            .expect("a source file name")
            .to_string_lossy();
        let extension = source
            .extension()
            .expect("a source extension")
            .to_string_lossy();
        let output = scratch.join(format!(
            "{}-{name}-{extension}{}",
            target.artifact(),
            std::env::consts::EXE_SUFFIX
        ));
        let program = Program {
            source: &source,
            output: &output,
            flags: &flags,
        };
        checked(
            runner,
            &compile_step(&compiler, mode, target, &program, &library)?,
        )?;
        print!(
            "{}: {}",
            target.package(),
            checked(runner, &program_step(&output, &key_files, &library))?
        );
    }
    Ok(())
}

/// The platform's C or C++ compiler for `source`, with warnings as errors.
fn compiler(host: &str, source: &Path) -> Result<cc::Tool, Failure> {
    Ok(cc::Build::new()
        .target(host)
        .host(host)
        .opt_level(0)
        .debug(false)
        .cargo_metadata(false)
        .cpp(
            source
                .extension()
                .is_some_and(|extension| extension == "cpp"),
        )
        .warnings(true)
        .extra_warnings(true)
        .try_get_compiler()
        .map_err(|error| format!("C compiler: {error}"))?)
}

/// The oracle's compiler and linker flags, with its library directory on
/// the program's run path.
fn oracle_flags(runner: &mut impl Run, prefix: &Path) -> Result<Vec<String>, Failure> {
    let step = Step::new(
        "oracle flags",
        "pkg-config",
        &["--cflags", "--libs", XMLSEC1],
    )
    .with_env(
        "PKG_CONFIG_PATH",
        prefix.join("lib/pkgconfig").display().to_string(),
    );
    let (status, flags) = runner.stdout(&step)?;
    require(status)?;
    let mut flags: Vec<String> = flags.split_whitespace().map(str::to_owned).collect();
    flags.push(format!("-Wl,-rpath,{}", prefix.join("lib").display()));
    Ok(flags)
}

/// Exported variables starting with `prefix` that `header` declares:
/// `XMLSEC_EXPORT_VAR <type> name[];` or `... name;`.
pub(crate) fn declared_variables(header: &str, prefix: &str) -> BTreeSet<String> {
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    header
        .lines()
        .filter(|line| line.trim_start().starts_with("XMLSEC_EXPORT_VAR"))
        .filter_map(|line| {
            let end = line.find(['[', ';'])?;
            let before = line[..end].trim_end();
            let start = before
                .rfind(|c: char| !identifier(c))
                .map_or(0, |at| at + 1);
            let name = &before[start..];
            name.starts_with(prefix).then(|| name.to_owned())
        })
        .collect()
}

/// Every function and variable the libxmlsec1-compatible headers declare.
fn xmlsec1_declarations() -> Result<BTreeSet<String>, Failure> {
    let directory = root().join(XMLSEC1_CRATE).join("include/xmlsec");
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("read {}: {error}", directory.display()))?
            .path();
        if path.extension().is_some_and(|extension| extension == "h") {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            names.extend(declared_with(&text, "xmlSec"));
            names.extend(declared_variables(&text, "xmlSec"));
        }
    }
    Ok(names)
}

/// Runs `step` and returns its standard output, failing with its combined
/// output. Diagnostics on standard error are libxmlsec1's error reports,
/// which are not compared.
fn standard_output(runner: &mut impl Run, step: &Step) -> Result<String, Failure> {
    let (status, output) = runner.stdout(step)?;
    if status.success() {
        Ok(output)
    } else {
        Err(format!("{} ({}):\n{output}", step.label, describe(status)).into())
    }
}

/// Builds the libxmlsec1-compatible library, checks its exports, and builds
/// each program against the oracle under `prefix` and against the library,
/// requiring both to print the same.
fn qualify_xmlsec1(
    host: &str,
    rustflags: Option<&str>,
    prefix: &Path,
    scratch: &Path,
    runner: &mut impl Run,
) -> Result<(), Failure> {
    let target = Target::Xmlsec1;
    let (status, messages) = runner.stdout(&build_step(target, Mode::Plain, host, rustflags))?;
    require(status)?;
    let library = library(&messages, target, std::env::consts::DLL_SUFFIX)?;
    // Every export is declared: a libxmlsec1 function by its headers, and any
    // clean C API function its dependencies bring along by the clean
    // headers. A libxmlsec1 declaration without an implementation fails a
    // consumer at link time under its own name.
    let mut declared = xmlsec1_declarations()?;
    declared.extend(declarations(target)?);
    let mut exported = exported_with(&library.shared, "xmlSec")?;
    exported.extend(self::exported(&library.shared)?);
    let undeclared: Vec<&String> = exported.difference(&declared).collect();
    if !undeclared.is_empty() {
        return Err(format!(
            "{}: exported but not declared: {undeclared:?}",
            target.package()
        )
        .into());
    }
    let template =
        std::fs::read_to_string(root().join(XMLSEC1_CRATE).join("xml-sec-xmlsec1.pc.in"))
            .map_err(|error| format!("read the pkg-config template: {error}"))?;
    let mut ours = template_defines(&template)?;
    ours.extend(libxml2_flags(runner)?);
    let oracle = oracle_flags(runner, prefix)?;
    let baseline = std::fs::read_to_string(root().join(ABI_BASELINE))
        .map_err(|error| format!("read {ABI_BASELINE}: {error}"))?;
    let layout = scratch.join("layout.c");
    std::fs::write(&layout, layout_program(&baseline)?)
        .map_err(|error| format!("write {}: {error}", layout.display()))?;
    let mut sources = vec![layout];
    sources.extend(
        target
            .sources()
            .iter()
            .map(|source| root().join(XMLSEC1_CRATE).join(source)),
    );
    for source in &sources {
        let compiler = compiler(host, source)?;
        let name = source
            .file_stem()
            .expect("a source file name")
            .to_string_lossy();
        let mine = scratch.join(format!("{name}-ours{}", std::env::consts::EXE_SUFFIX));
        let theirs = scratch.join(format!("{name}-oracle{}", std::env::consts::EXE_SUFFIX));
        let program = Program {
            source,
            output: &mine,
            flags: &ours,
        };
        checked(
            runner,
            &compile_step(&compiler, Mode::Plain, target, &program, &library)?,
        )?;
        let program = Program {
            source,
            output: &theirs,
            flags: &oracle,
        };
        checked(runner, &oracle_compile_step(&compiler, &program))?;
        let expected = standard_output(runner, &program_step(&theirs, &[], &library))?;
        let actual = standard_output(runner, &program_step(&mine, &[], &library))?;
        if let Some(difference) = first_difference(&expected, &actual) {
            return Err(format!(
                "{}: {} prints differently from libxmlsec1: {difference}",
                target.package(),
                source.display()
            )
            .into());
        }
        println!(
            "{}: {name}: {} lines as libxmlsec1 prints them",
            target.package(),
            actual.lines().count()
        );
    }
    Ok(())
}

/// The first line where `actual` differs from `expected`, described.
pub(crate) fn first_difference(expected: &str, actual: &str) -> Option<String> {
    let mut expected_lines = expected.lines();
    let mut actual_lines = actual.lines();
    for number in 1.. {
        match (expected_lines.next(), actual_lines.next()) {
            (None, None) => return None,
            (left, right) if left == right => {}
            (left, right) => {
                return Some(format!(
                    "line {number}: libxmlsec1 {left:?}, ours {right:?}"
                ));
            }
        }
    }
    None
}

/// `capi --xmlsec1`: the differential qualification against the oracle.
fn execute_xmlsec1(runner: &mut impl Run) -> Result<(), Failure> {
    let prefix = std::env::var_os("XMLSEC1_PREFIX")
        .map(PathBuf::from)
        .ok_or("capi --xmlsec1 needs XMLSEC1_PREFIX naming the installed libxmlsec1 oracle")?;
    let (status, version) = runner.stdout(&Step::new("rustc", "rustc", &["-vV"]))?;
    require(status)?;
    let host = host(&version)?;
    let rustflags = std::env::var("RUSTFLAGS").ok();
    let scratch = tempfile::tempdir().map_err(|error| format!("scratch directory: {error}"))?;
    qualify_xmlsec1(&host, rustflags.as_deref(), &prefix, scratch.path(), runner)
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let mode = match (args.next().as_deref(), args.next()) {
        (None, None) => Mode::Plain,
        // Elsewhere the Rust and C toolchains each load their own dynamic
        // sanitizer runtime into one process; Linux links one, into the program.
        (Some("--sanitize"), None) if cfg!(target_os = "linux") => Mode::Sanitized,
        (Some("--sanitize"), None) => {
            return Err("sanitized C ABI qualification runs on Linux".into());
        }
        (Some("--xmlsec1"), None) => return execute_xmlsec1(&mut System),
        _ => {
            return Err(Failure {
                code: 2,
                message: "usage: xml-sec-tools capi [--sanitize | --xmlsec1]".into(),
            });
        }
    };
    execute(mode, &mut System)
}
