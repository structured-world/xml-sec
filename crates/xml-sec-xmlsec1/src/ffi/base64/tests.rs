//! The codec against RFC 4648 vectors and libxmlsec1's own rules: line
//! breaks, whitespace, padding and what follows it. The C program compares
//! the same calls with libxmlsec1 byte for byte.

use super::{
    XmlSecBase64Ctx, decode_size, encode_size, finish, initialize, update, xmlSecBase64Decode_ex,
    xmlSecBase64DecodeInPlace, xmlSecBase64Encode,
};
use std::ffi::CStr;

fn context(encode: i32, columns: i32) -> XmlSecBase64Ctx {
    // SAFETY: an all-zero context is a valid starting value before
    // `initialize` sets every member.
    let mut ctx: XmlSecBase64Ctx = unsafe { std::mem::zeroed() };
    initialize(&mut ctx, encode, columns).expect("a non-negative line size");
    ctx
}

fn encoded(input: &[u8], columns: i32) -> String {
    let mut ctx = context(1, columns);
    let mut output = vec![0; encode_size(ctx.columns, input.len()).expect("size")];
    let written = update(&mut ctx, input, &mut output).expect("encode");
    let last = finish(&mut ctx, &mut output[written..]).expect("final");
    String::from_utf8(output[..written + last].to_vec()).expect("ASCII")
}

fn decoded(input: &str) -> Option<Vec<u8>> {
    let mut ctx = context(0, 0);
    let mut output = vec![0; decode_size(input.len()).expect("size")];
    let written = update(&mut ctx, input.as_bytes(), &mut output)?;
    let last = finish(&mut ctx, &mut output[written..])?;
    Some(output[..written + last].to_vec())
}

/// RFC 4648 section 10 vectors, both directions.
#[test]
fn rfc_4648_vectors() {
    for (plain, base64) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encoded(plain.as_bytes(), 0), base64, "{plain}");
        assert_eq!(
            decoded(base64).as_deref(),
            Some(plain.as_bytes()),
            "{base64}"
        );
    }
}

/// A line break follows every `columns` output characters, padding
/// included, and never ends the output.
#[test]
fn line_breaks_after_columns() {
    assert_eq!(encoded(b"foobar", 4), "Zm9v\nYmFy");
    assert_eq!(encoded(b"foob", 4), "Zm9v\nYg==");
    assert_eq!(encoded(&[0xff; 6], 3), "///\n///\n//");
}

/// Whitespace anywhere is skipped; a character after padding, a misplaced
/// padding and a truncated group fail.
#[test]
fn decoding_rules() {
    assert_eq!(
        decoded(" Zm 9v\r\nYmFy \t").as_deref(),
        Some(&b"foobar"[..])
    );
    assert_eq!(decoded("Zg==\n"), Some(b"f".to_vec()));
    // Data after the padding ends the stream before the input does.
    assert_eq!(decoded("Zg==Zg=="), None);
    assert_eq!(decoded("Z==="), None);
    assert_eq!(decoded("Zm9"), None);
    assert_eq!(decoded("Zm9v!"), None);
}

/// The C entry points: an allocated string, a bounded decode and the
/// in-place decode of a writable string.
#[test]
fn c_entry_points() {
    // SAFETY: the inputs are readable and NUL-terminated as each requires;
    // the encoded string is libxml2-allocated and freed with its allocator.
    unsafe {
        let text = xmlSecBase64Encode(b"foobar".as_ptr(), 6, 0);
        assert_eq!(CStr::from_ptr(text.cast()), c"Zm9vYmFy");
        crate::ffi::free(text.cast());
        let mut out = [0u8; 16];
        let mut written = 0;
        assert_eq!(
            xmlSecBase64Decode_ex(
                c"Zm9v".as_ptr().cast(),
                out.as_mut_ptr(),
                16,
                &raw mut written
            ),
            0
        );
        assert_eq!(&out[..written], b"foo");
        assert_eq!(
            xmlSecBase64Decode_ex(
                c"Zm9v".as_ptr().cast(),
                out.as_mut_ptr(),
                2,
                &raw mut written
            ),
            -1
        );
        let mut in_place = *b"Zm9vYmFy\0";
        assert_eq!(
            xmlSecBase64DecodeInPlace(in_place.as_mut_ptr(), &raw mut written),
            0
        );
        assert_eq!(&in_place[..written], b"foobar");
    }
}
