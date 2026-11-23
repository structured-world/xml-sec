//! Canonical Base64 text of generated XML values.
//!
//! The text is allocated as the surrounding infallible XML strings are, so a
//! failed allocation aborts like theirs; paths that charge a resource budget
//! use the fallible [`structured_base64::Profile`] calls directly.

use alloc::string::String;

use structured_base64::STANDARD;

/// The canonical Base64 text of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut text = String::new();
    encode_into(bytes, &mut text);
    text
}

/// Appends the canonical Base64 text of `bytes` to `text`.
pub(crate) fn encode_into(bytes: &[u8], text: &mut String) {
    // A slice spans at most `isize::MAX` bytes, whose encoding fits `usize`.
    let len = STANDARD
        .encoded_len(bytes.len())
        .expect("the encoding of a slice fits usize");
    text.reserve(len);
    STANDARD
        .encode_string(bytes, text)
        .expect("the reserved capacity holds the encoding");
}
