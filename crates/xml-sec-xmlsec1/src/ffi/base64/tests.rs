//! The C entry points over the core codec: state kept in `xmlSecBase64Ctx`
//! between calls, the terminating NUL and failure values. The codec's own
//! rules are tested in the core; the C program compares these calls with
//! libxmlsec1 byte for byte.

use super::{
    xmlSecBase64CtxCreate, xmlSecBase64CtxDestroy, xmlSecBase64CtxFinal_ex,
    xmlSecBase64CtxUpdate_ex, xmlSecBase64Decode_ex, xmlSecBase64DecodeInPlace, xmlSecBase64Encode,
};
use std::ffi::CStr;

/// A stream fed one byte per call resumes from the state the context keeps,
/// in both directions.
#[test]
fn context_carries_the_stream_between_calls() {
    for (encode, input, expected) in [
        (1, &b"foobar"[..], &b"Zm9v\nYmFy"[..]),
        (0, &b"Zm9v\nYmFy"[..], &b"foobar"[..]),
    ] {
        // SAFETY: the context and buffers are used while live.
        unsafe {
            let ctx = xmlSecBase64CtxCreate(encode, 4);
            assert!(!ctx.is_null());
            let mut out = [0u8; 32];
            let mut total = 0;
            for byte in input {
                let mut written = 0;
                assert_eq!(
                    xmlSecBase64CtxUpdate_ex(
                        ctx,
                        byte,
                        1,
                        out.as_mut_ptr().add(total),
                        out.len() - total,
                        &raw mut written
                    ),
                    0
                );
                total += written;
            }
            let mut written = 0;
            assert_eq!(
                xmlSecBase64CtxFinal_ex(
                    ctx,
                    out.as_mut_ptr().add(total),
                    out.len() - total,
                    &raw mut written
                ),
                0
            );
            total += written;
            assert_eq!(&out[..total], expected);
            xmlSecBase64CtxDestroy(ctx);
        }
    }
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
