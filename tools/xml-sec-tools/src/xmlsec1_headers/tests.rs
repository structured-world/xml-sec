use super::{HEADERS, adapted, copy, declared_strings, differences, render};
use crate::test_support::read;

/// libxml2's includes become one include of the tree header, and a
/// function that reads a file is left out with a note, its continuation
/// lines included; every other line stays as it is.
#[test]
fn the_headers_take_the_tree_header_and_leave_out_file_readers() {
    let header = concat!(
        "#include <libxml/tree.h>\n",
        "#include <libxml/xpath.h>\n",
        "#include <xmlsec/exports.h>\n",
        "XMLSEC_EXPORT int xmlSecBufferReverse (xmlSecBufferPtr buf);\n",
        "XMLSEC_EXPORT int xmlSecBufferReadFile (xmlSecBufferPtr buf,\n",
        "                                        const char* filename);\n",
        "XMLSEC_EXPORT xmlDocPtr xmlSecParseFile (const char *filename);\n",
        "XMLSEC_EXPORT xmlDocPtr xmlSecParseFileX (const char *filename);\n",
    );
    let adapted = String::from_utf8(adapted(header.as_bytes()).expect("UTF-8")).expect("UTF-8");
    assert_eq!(
        adapted,
        concat!(
            "#include <xs_tree.h>\n",
            "#include <xmlsec/exports.h>\n",
            "XMLSEC_EXPORT int xmlSecBufferReverse (xmlSecBufferPtr buf);\n",
            "/* xmlSecBufferReadFile is not offered: the library reads no file; the caller passes the bytes. */\n",
            "/* xmlSecParseFile is not offered: the library reads no file; the caller passes the bytes. */\n",
            "XMLSEC_EXPORT xmlDocPtr xmlSecParseFileX (const char *filename);\n",
        )
    );
}

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

/// The ledger names every exported string constant, in a stable order.
#[test]
fn the_ledger_names_the_string_constants() {
    let names = declared_strings(&read("compatibility/libxmlsec1-1.3.13.json")).expect("ledger");
    assert_eq!(names.len(), 435);
    assert!(names.contains(&"xmlSecDSigNs".to_owned()));
    assert!(names.is_sorted());
}

/// The table exports each constant with its exact bytes and NUL, escapes
/// what a byte string cannot hold literally, and wraps lines as rustfmt does.
#[test]
fn the_string_table_keeps_every_byte() {
    let long = format!("{}\0", "x".repeat(80)).into_bytes();
    let table = render(&[
        ("xmlSecA".to_owned(), b"a\"b\\c\x01\0".to_vec()),
        ("xmlSecLong".to_owned(), long),
    ]);
    assert!(table.contains("pub(crate) static xmlSecA: [u8; 7] = *b\"a\\\"b\\\\c\\x01\\0\";"));
    assert!(table.contains("pub(crate) static xmlSecLong: [u8; 81] =\n    *b\"xxx"));
    assert_eq!(table.matches("#[unsafe(no_mangle)]").count(), 2);
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
