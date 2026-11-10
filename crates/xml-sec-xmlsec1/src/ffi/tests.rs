use super::buffer::XmlSecBuffer;
use super::list::{XmlSecPtrList, XmlSecPtrListKlass};
use super::nodeset::{self, XmlSecNodeSet};
use super::{ALLOC_MODE_DOUBLE, ALLOC_MODE_EXACT, grown};
use std::ffi::c_int;
use std::mem::{offset_of, size_of};
use std::path::Path;
use std::process::Command;

/// The `-D` flags of the pkg-config template's `Cflags:` line, which a
/// consumer compiles with.
fn template_defines(manifest: &Path) -> Vec<String> {
    let template =
        std::fs::read_to_string(manifest.join("xml-sec-xmlsec1.pc.in")).expect("the template");
    template
        .lines()
        .find_map(|line| line.strip_prefix("Cflags:"))
        .expect("a Cflags line")
        .split_whitespace()
        .filter(|flag| flag.starts_with("-D"))
        .map(str::to_owned)
        .collect()
}

/// The layout record of the crate's headers: `tests/layout.c` compiled
/// against them and the installed libxml2 headers, and run. The library is
/// built without any C, so the record is produced here.
fn header_layout() -> Vec<usize> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cflags = Command::new("pkg-config")
        .args(["--cflags", "libxml-2.0"])
        .output()
        .expect("pkg-config runs");
    assert!(cflags.status.success(), "libxml2 headers are installed");
    let cflags = String::from_utf8(cflags.stdout).expect("UTF-8 flags");
    // Removed on every exit path, a failed assertion included.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let program = directory.path().join("layout");
    let mut compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    compile
        .arg(manifest.join("tests/layout.c"))
        .arg("-o")
        .arg(&program)
        .arg(format!("-I{}", manifest.join("include").display()))
        .args(template_defines(manifest));
    for flag in cflags.split_whitespace() {
        compile.arg(flag);
        // Some distributions point at the parent of `libxml/`.
        if let Some(include) = flag.strip_prefix("-I") {
            compile.arg(format!("-I{include}/libxml2"));
        }
    }
    assert!(
        compile.status().expect("the C compiler runs").success(),
        "the layout program compiles"
    );
    let output = Command::new(&program)
        .output()
        .expect("the layout program runs");
    String::from_utf8(output.stdout)
        .expect("UTF-8 output")
        .lines()
        .map(|line| line.parse().expect("one number per line"))
        .collect()
}

/// The Rust declarations stand for the C structures of the crate's headers:
/// a mismatch would make every exported function read the wrong fields.
#[test]
fn rust_layouts_match_the_headers() {
    let expected = [
        size_of::<XmlSecBuffer>(),
        offset_of!(XmlSecBuffer, data),
        offset_of!(XmlSecBuffer, size),
        offset_of!(XmlSecBuffer, max_size),
        offset_of!(XmlSecBuffer, alloc_mode),
        size_of::<c_int>(),
        usize::try_from(ALLOC_MODE_EXACT).expect("non-negative"),
        usize::try_from(ALLOC_MODE_DOUBLE).expect("non-negative"),
        size_of::<XmlSecPtrList>(),
        offset_of!(XmlSecPtrList, id),
        offset_of!(XmlSecPtrList, data),
        offset_of!(XmlSecPtrList, used),
        offset_of!(XmlSecPtrList, max),
        offset_of!(XmlSecPtrList, alloc_mode),
        size_of::<XmlSecPtrListKlass>(),
        offset_of!(XmlSecPtrListKlass, name),
        offset_of!(XmlSecPtrListKlass, duplicate_item),
        offset_of!(XmlSecPtrListKlass, destroy_item),
        offset_of!(XmlSecPtrListKlass, debug_dump_item),
        offset_of!(XmlSecPtrListKlass, debug_xml_dump_item),
        size_of::<XmlSecNodeSet>(),
        offset_of!(XmlSecNodeSet, nodes),
        offset_of!(XmlSecNodeSet, doc),
        offset_of!(XmlSecNodeSet, destroy_doc),
        offset_of!(XmlSecNodeSet, kind),
        offset_of!(XmlSecNodeSet, op),
        offset_of!(XmlSecNodeSet, next),
        offset_of!(XmlSecNodeSet, prev),
        offset_of!(XmlSecNodeSet, reserved),
        usize::try_from(nodeset::TREE_WITHOUT_COMMENTS_INVERT).expect("non-negative"),
        usize::try_from(nodeset::LIST).expect("non-negative"),
        usize::try_from(nodeset::UNION).expect("non-negative"),
    ];
    assert_eq!(header_layout(), expected);
}

/// libxmlsec1's growth rule: exact mode adds 8, double mode doubles and adds
/// 32, neither goes below the initial size, and an overflowing request fails
/// instead of wrapping to a small allocation.
#[test]
fn allocation_growth_follows_libxmlsec1() {
    assert_eq!(grown(ALLOC_MODE_EXACT, 2000, 1024), Some(2008));
    assert_eq!(grown(ALLOC_MODE_DOUBLE, 2000, 1024), Some(4032));
    assert_eq!(grown(ALLOC_MODE_DOUBLE, 10, 1024), Some(1024));
    assert_eq!(grown(7, 10, 64), Some(64));
    assert_eq!(grown(ALLOC_MODE_DOUBLE, usize::MAX / 2, 0), None);
    assert_eq!(grown(ALLOC_MODE_EXACT, usize::MAX - 7, 0), None);
}

/// Asserts that the calling test runs in a process of its own, as cargo
/// nextest runs every test. A test that sets and observes process-global
/// state (report callbacks, registries, the input callback list) would race
/// the other tests of a shared process instead.
pub(super) fn own_process() {
    assert_eq!(
        std::env::var("NEXTEST_EXECUTION_MODE").as_deref(),
        Ok("process-per-test"),
        "this test sets process-global state and needs a process of its own: run it with cargo nextest"
    );
}

/// A panic inside an exported function's body becomes its failure value
/// instead of unwinding across the C boundary, which is undefined behavior.
#[test]
fn a_panicking_body_returns_the_failure_value() {
    let status = super::contain(-1, || -> c_int { panic!("an internal defect") });
    assert_eq!(status, -1);
    let pointer = super::contain(std::ptr::null_mut::<u8>(), || unreachable!("a defect"));
    assert!(pointer.is_null());
    assert_eq!(super::contain(-1, || 7), 7);
}
