use super::{HEADERS, copy, differences};

/// A directory holding every header with its own name as content.
fn installed(dir: &std::path::Path) {
    for header in HEADERS {
        std::fs::write(dir.join(header), header).expect("write a header");
    }
}

#[test]
fn copied_headers_match_their_source() {
    let source = tempfile::tempdir().expect("source directory");
    let target = tempfile::tempdir().expect("target directory");
    installed(source.path());
    copy(source.path(), target.path()).expect("copy");
    assert_eq!(
        differences(source.path(), target.path()).expect("compare"),
        Vec::<String>::new()
    );
}

/// An edited, a missing and an extra-byte header are each reported by name,
/// so a hand edit of the vendored tree cannot pass the check.
#[test]
fn edited_or_missing_headers_are_reported() {
    let source = tempfile::tempdir().expect("source directory");
    let target = tempfile::tempdir().expect("target directory");
    installed(source.path());
    copy(source.path(), target.path()).expect("copy");
    std::fs::write(target.path().join("transforms.h"), "edited").expect("edit");
    std::fs::remove_file(target.path().join("list.h")).expect("remove");
    std::fs::write(target.path().join("buffer.h"), "buffer.h\n").expect("append");
    assert_eq!(
        differences(source.path(), target.path()).expect("compare"),
        ["buffer.h", "list.h", "transforms.h"]
    );
}

/// A source without a header fails the check rather than passing two absent
/// files as equal.
#[test]
fn a_header_missing_from_the_source_is_reported() {
    let source = tempfile::tempdir().expect("source directory");
    let target = tempfile::tempdir().expect("target directory");
    installed(source.path());
    copy(source.path(), target.path()).expect("copy");
    std::fs::remove_file(source.path().join("xmlsec.h")).expect("remove");
    std::fs::remove_file(target.path().join("xmlsec.h")).expect("remove");
    assert_eq!(
        differences(source.path(), target.path()).expect("compare"),
        ["xmlsec.h"]
    );
}
