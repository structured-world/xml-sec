//! `capi [--sanitize]`: qualifies the C ABI as C and C++ callers see it, for
//! the clean C API and, on Linux and macOS, for the libxml2 bridge that
//! exports it together with its own entry point. Cargo builds each shared
//! library and names it in its artifact messages; the round-trip programs are
//! built against the headers and that library with the platform's compiler
//! and run, and the library must export exactly the functions its headers
//! declare. `--sanitize`, on Linux, builds the libraries and runs the crates'
//! tests with the address sanitizer on nightly, and builds the programs with
//! the address (leak checking included) and undefined behavior sanitizers.

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
}

impl Target {
    pub(crate) const fn package(self) -> &'static str {
        match self {
            Self::Clean => "xml-sec-capi",
            Self::Libxml2 => "xml-sec-libxml2",
        }
    }

    /// The library name cargo reports and the linker resolves.
    pub(crate) const fn artifact(self) -> &'static str {
        match self {
            Self::Clean => "xml_sec_capi",
            Self::Libxml2 => "xml_sec_libxml2",
        }
    }

    const fn crate_dir(self) -> &'static str {
        match self {
            Self::Clean => "crates/xml-sec-capi",
            Self::Libxml2 => "crates/xml-sec-libxml2",
        }
    }

    /// Every header whose functions the library exports.
    pub(crate) const fn headers(self) -> &'static [&'static str] {
        match self {
            Self::Clean => &[HEADER],
            Self::Libxml2 => &[HEADER, "crates/xml-sec-libxml2/include/xml_sec_libxml2.h"],
        }
    }

    /// The include directories of those headers.
    fn includes(self) -> Vec<String> {
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

/// Function names `header` declares: the identifier right before a parameter
/// list, outside comments and preprocessor lines.
pub(crate) fn declared(header: &str) -> BTreeSet<String> {
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut names = BTreeSet::new();
    for line in header.lines() {
        let trimmed = line.trim_start();
        if ["/*", "*", "#"]
            .iter()
            .any(|start| trimmed.starts_with(start))
        {
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('(') {
            let before = &rest[..open];
            let start = before
                .rfind(|c: char| !identifier(c))
                .map_or(0, |at| at + 1);
            if before[start..].starts_with("xs_") {
                names.insert(before[start..].to_owned());
            }
            rest = &rest[open + 1..];
        }
    }
    names
}

/// Function names the shared library at `path` exports.
pub(crate) fn exported(path: &Path) -> Result<BTreeSet<String>, String> {
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
        if name.starts_with("xs_") {
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
    Ok(step)
}

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
        require(runner.status(&test_step(&host, rustflags.as_deref()))?)?;
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
        Target::Libxml2 => libxml2_flags(runner)?,
    };
    let keys = root().join("tests/fixtures/keys/rsa");
    // Every program receives the RSA recipient's private and public key.
    let key_files = [
        keys.join("rsa-2048-key.pem"),
        keys.join("rsa-2048-pubkey.pem"),
    ];
    for source in target.sources() {
        let source = root().join(target.crate_dir()).join(source);
        let compiler = cc::Build::new()
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
            .map_err(|error| format!("C compiler: {error}"))?;
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

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let mode = match (args.next().as_deref(), args.next()) {
        (None, None) => Mode::Plain,
        // Elsewhere the Rust and C toolchains each load their own dynamic
        // sanitizer runtime into one process; Linux links one, into the program.
        (Some("--sanitize"), None) if cfg!(target_os = "linux") => Mode::Sanitized,
        (Some("--sanitize"), None) => {
            return Err("sanitized C ABI qualification runs on Linux".into());
        }
        _ => {
            return Err(Failure {
                code: 2,
                message: "usage: xml-sec-tools capi [--sanitize]".into(),
            });
        }
    };
    execute(mode, &mut System)
}
