use super::buffer::XmlSecBuffer;
use super::list::{XmlSecPtrList, XmlSecPtrListKlass};
use super::nodeset::{self, XmlSecNodeSet};
use super::{ALLOC_MODE_DOUBLE, ALLOC_MODE_EXACT, GrowthRefused, grown};
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
/// against them and the tree header, and run. The library is built without
/// any C, so the record is produced here.
fn header_layout() -> Vec<usize> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Removed on every exit path, a failed assertion included.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let program = directory.path().join("layout");
    let mut compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    compile
        .arg(manifest.join("tests/layout.c"))
        .arg("-o")
        .arg(&program)
        .arg(format!("-I{}", manifest.join("include").display()))
        .arg(format!(
            "-I{}",
            manifest.join("../xml-sec-libxml2/include").display()
        ))
        .args(template_defines(manifest));
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
        offset_of!(XmlSecBuffer, flags),
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
/// 32, neither goes below the initial size; a request whose grown size would
/// overflow is refused with the largest size the mode grows, and an unknown
/// mode is refused rather than clamped to the initial size.
#[test]
fn allocation_growth_follows_libxmlsec1() {
    assert_eq!(grown(ALLOC_MODE_EXACT, 2000, 1024), Ok(2008));
    assert_eq!(grown(ALLOC_MODE_DOUBLE, 2000, 1024), Ok(4032));
    assert_eq!(grown(ALLOC_MODE_DOUBLE, 10, 1024), Ok(1024));
    assert_eq!(grown(7, 10, 64), Err(GrowthRefused::UnknownMode));
    let double = (usize::MAX - 32) / 2;
    assert_eq!(grown(ALLOC_MODE_DOUBLE, double, 0), Ok(usize::MAX - 1));
    assert_eq!(
        grown(ALLOC_MODE_DOUBLE, double + 1, 0),
        Err(GrowthRefused::TooLarge { limit: double })
    );
    assert_eq!(grown(ALLOC_MODE_EXACT, usize::MAX - 8, 0), Ok(usize::MAX));
    assert_eq!(
        grown(ALLOC_MODE_EXACT, usize::MAX - 7, 0),
        Err(GrowthRefused::TooLarge {
            limit: usize::MAX - 8
        })
    );
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

/// Publishes the verification and signing snapshots under an authorization
/// that ends a moment later, and returns once it has ended. A published
/// revision is compiled, and compilation refuses an authorization already
/// over, so a run meets an ended one only when it ends after publication. A
/// publication the clock overtook (the process paused past the end) is
/// tried again with a new end, a few times; any other refusal fails.
pub(super) fn end_signature_authorization() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use xml_sec::policy::{Instant, PolicyValidity};
    let since_epoch = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after the epoch")
    };
    let mut attempts = 0;
    let ends = loop {
        let ends = since_epoch() + Duration::from_secs(1);
        let validity = || {
            Some(PolicyValidity {
                authorization_id: "test".to_owned(),
                authority: "test".to_owned(),
                reason: "an authorization about to end".to_owned(),
                not_before: Instant::new(0, 0).expect("the epoch"),
                expires_at: Instant::new(
                    ends.as_secs().try_into().expect("a near instant"),
                    ends.subsec_nanos(),
                )
                .expect("a second from now"),
            })
        };
        let published = super::policy::republish(
            |verification| verification.validity = validity(),
            |signing| signing.validity = validity(),
        );
        attempts += 1;
        match published {
            Some(()) => break ends,
            None if since_epoch() >= ends && attempts < 5 => {}
            None => panic!("the library policy compiles"),
        }
    };
    while SystemTime::now() <= UNIX_EPOCH + ends {
        std::thread::sleep(Duration::from_millis(50));
    }
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
