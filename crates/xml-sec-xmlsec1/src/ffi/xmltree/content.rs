//! Node content of `xmlsec/xmltree.h`: emptiness, hex and size content,
//! escaped content, printing and qualified names.

use std::ffi::{CStr, c_int, c_void};

use super::super::buffer::{XmlSecBuffer, xmlSecBufferHexRead};
use super::super::errors::{self, check, here};
use super::super::tree::{XML_ATTRIBUTE_NODE, XML_ELEMENT_NODE, XmlNode, c_text, nodes};
use super::super::{contain, free};
use super::{is_space, next_element, trimmed_content, xmlSecGetNodeContentAndTrim};

/// `xmlSecIsEmptyString`: 1 when `str` holds only C-locale white space,
/// otherwise 0; -1 for null.
///
/// # Safety
/// `str` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIsEmptyString(str: *const u8) -> c_int {
    contain(-1, || {
        check!(!str.is_null(), "xmlSecIsEmptyString", c"str != NULL", -1);
        // SAFETY: a non-null `str` is NUL-terminated.
        let text = unsafe { CStr::from_ptr(str.cast()) }.to_bytes();
        c_int::from(text.iter().all(|&byte| is_space(byte)))
    })
}

/// `xmlSecIsEmptyNode`: 1 when `node` has no element child and its text is
/// white space only, otherwise 0; -1 for null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIsEmptyNode(node: *mut XmlNode) -> c_int {
    contain(-1, || {
        check!(!node.is_null(), "xmlSecIsEmptyNode", c"node != NULL", -1);
        if !next_element(nodes::first_child(node)).is_null() {
            return 0;
        }
        let empty = nodes::content(node).is_none_or(|content| content.bytes().all(is_space));
        c_int::from(empty)
    })
}

/// `xmlSecGetNodeContentAsHex`: decodes the trimmed hex content of `cur`
/// into `res`.
///
/// # Safety
/// `res` is null or a buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeContentAsHex(
    cur: *mut XmlNode,
    res: *mut XmlSecBuffer,
) -> c_int {
    contain(-1, || {
        check!(
            !cur.is_null(),
            "xmlSecGetNodeContentAsHex",
            c"cur != NULL",
            -1
        );
        check!(
            !res.is_null(),
            "xmlSecGetNodeContentAsHex",
            c"res != NULL",
            -1
        );
        let here = here!("xmlSecGetNodeContentAsHex");
        // SAFETY: `res` is a buffer; the content is freed here.
        unsafe {
            let content = xmlSecGetNodeContentAndTrim(cur);
            if content.is_null() {
                errors::invalid_node_content(here, cur, std::ptr::null(), "empty");
                return -1;
            }
            let read = xmlSecBufferHexRead(res, content);
            free(content.cast());
            if read < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecBufferHexRead");
                return -1;
            }
        }
        0
    })
}

/// `xmlSecSetNodeContentAsHex`: sets the content of `node` to the lowercase
/// hex encoding of `size` bytes of `data`.
///
/// # Safety
/// `data` is null or holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecSetNodeContentAsHex(
    node: *mut XmlNode,
    data: *const u8,
    size: usize,
) -> c_int {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    contain(-1, || {
        check!(
            !node.is_null(),
            "xmlSecSetNodeContentAsHex",
            c"node != NULL",
            -1
        );
        check!(
            !data.is_null(),
            "xmlSecSetNodeContentAsHex",
            c"data != NULL",
            -1
        );
        let Some(capacity) = size.checked_mul(2) else {
            errors::malloc_failed(
                here!("xmlSecSetNodeContentAsHex"),
                std::ptr::null(),
                usize::MAX,
            );
            return -1;
        };
        // SAFETY: `data` holds `size` bytes by the caller's contract.
        let input = unsafe { std::slice::from_raw_parts(data, size) };
        let mut content = String::with_capacity(capacity);
        for &byte in input {
            content.push(char::from(DIGITS[usize::from(byte >> 4)]));
            content.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        if !set_reported(node, &content, here!("xmlSecSetNodeContentAsHex")) {
            return -1;
        }
        0
    })
}

/// `xmlNodeSetContent(node, content)` for a function that returns a status:
/// a node the tree refuses to edit (a document node, a stale handle) keeps
/// its content and fails the call, reported at `here`, rather than passing
/// for a success.
pub(super) fn set_reported(node: *mut XmlNode, content: &str, here: errors::Here) -> bool {
    let set = nodes::set_content(node, content).is_ok();
    if !set {
        errors::xml_failed(here, std::ptr::null(), c"xmlNodeSetContent");
    }
    set
}

/// Why a node's content is not a size, in libxmlsec1's words.
enum NotSize {
    /// A leading `-` or `+`: the schema types these values come from
    /// (`xs:positiveInteger`, `xs:nonNegativeInteger`) allow no sign.
    Sign,
    /// More digits than an unsigned 64-bit value holds.
    OutOfRange,
    /// Anything but digits, or digits followed by anything but white space.
    Extra,
}

impl NotSize {
    fn reason(&self) -> &'static str {
        match self {
            Self::Sign => "can't parse node content as size (invalid sign)",
            Self::OutOfRange => "can't parse node content as size (value out of range)",
            Self::Extra => "can't parse node content as size (extra characters at the end)",
        }
    }
}

/// C's `isspace` in the C locale, vertical tab included.
fn c_isspace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `text`, which has no leading white space, as libxmlsec1 reads a size:
/// no sign, `strtoull` over the digits, and nothing but white space after.
fn parse_size(text: &[u8]) -> Result<u64, NotSize> {
    if matches!(text.first(), Some(b'-' | b'+')) {
        return Err(NotSize::Sign);
    }
    let digits = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    let value = text[..digits].iter().try_fold(0u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
    });
    let Some(value) = value else {
        return Err(NotSize::OutOfRange);
    };
    // Without digits `strtoull` reads nothing, so the whole text is extra.
    if digits > 0 && text[digits..].iter().all(|byte| c_isspace(*byte)) {
        Ok(value)
    } else {
        Err(NotSize::Extra)
    }
}

/// `xmlSecGetNodeContentAsSize`: the trimmed content of `cur` as an unsigned
/// decimal with nothing but white space after it, or `def_value` when `cur`
/// has no content or only white space.
///
/// # Safety
/// `res` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeContentAsSize(
    cur: *mut XmlNode,
    def_value: usize,
    res: *mut usize,
) -> c_int {
    contain(-1, || {
        check!(
            !cur.is_null(),
            "xmlSecGetNodeContentAsSize",
            c"cur != NULL",
            -1
        );
        check!(
            !res.is_null(),
            "xmlSecGetNodeContentAsSize",
            c"res != NULL",
            -1
        );
        let here = here!("xmlSecGetNodeContentAsSize");
        let Some(content) = trimmed_content(cur) else {
            // SAFETY: writable by the caller's contract.
            unsafe { res.write(def_value) };
            return 0;
        };
        let text = content.as_bytes();
        let start = text.iter().take_while(|byte| c_isspace(**byte)).count();
        if start == text.len() {
            // SAFETY: writable by the caller's contract.
            unsafe { res.write(def_value) };
            return 0;
        }
        let value = match parse_size(&text[start..]) {
            Ok(value) => value,
            Err(not_size) => {
                // SAFETY: `cur` is a node pointer, validated by the report.
                unsafe {
                    errors::invalid_node_content(here, cur, std::ptr::null(), not_size.reason());
                }
                return -1;
            }
        };
        let Ok(size) = usize::try_from(value) else {
            errors::cast_impossible_u64_to_size(here, value);
            return -1;
        };
        // SAFETY: writable by the caller's contract.
        unsafe { res.write(size) };
        0
    })
}

/// libxml2's `xmlEncodeSpecialChars`: `text` with `<`, `>`, `&`, `"` and
/// carriage return written as references.
fn encode_special(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '&' => encoded.push_str("&amp;"),
            '"' => encoded.push_str("&quot;"),
            '\r' => encoded.push_str("&#13;"),
            other => encoded.push(other),
        }
    }
    encoded
}

/// `xmlSecNodeEncodeAndSetContent`: sets the content of `node` to `buffer`
/// with the XML special characters escaped, or removes it for null.
///
/// libxmlsec1 escapes `buffer` and hands it to `xmlNodeSetContent`, which
/// reads an element's or attribute's content as markup, references
/// included, and a leaf's as plain text: an element or attribute ends up
/// holding `buffer` itself, a leaf its escaped form. This tree's setter
/// stores plain text, so it is given what libxml2 ends up storing.
///
/// # Safety
/// `buffer` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeEncodeAndSetContent(
    node: *mut XmlNode,
    buffer: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !node.is_null(),
            "xmlSecNodeEncodeAndSetContent",
            c"node != NULL",
            -1
        );
        check!(
            !nodes::doc(node).is_null(),
            "xmlSecNodeEncodeAndSetContent",
            c"node->doc != NULL",
            -1
        );
        let here = here!("xmlSecNodeEncodeAndSetContent");
        if buffer.is_null() {
            return if set_reported(node, "", here) { 0 } else { -1 };
        }
        // SAFETY: NUL-terminated by the caller's contract.
        let Some(text) = (unsafe { c_text(buffer) }) else {
            errors::xml_failed(here, std::ptr::null(), c"xmlEncodeSpecialChars");
            return -1;
        };
        let stored = if matches!(nodes::kind(node), XML_ELEMENT_NODE | XML_ATTRIBUTE_NODE) {
            String::from(text)
        } else {
            encode_special(text)
        };
        if !set_reported(node, &stored, here) {
            return -1;
        }
        0
    })
}

/// `xmlSecPrintXmlString`: writes `str` with the XML special characters
/// escaped (or `NULL` for null) to `fd`; the number of bytes written.
///
/// # Safety
/// `fd` is a live C stream; `str` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPrintXmlString(fd: *mut c_void, str: *const u8) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecPrintXmlString");
        let written = if str.is_null() {
            // SAFETY: `fd` is a live stream; the text is NUL-terminated.
            let status = unsafe { libc::fputs(c"NULL".as_ptr(), fd.cast()) };
            (status >= 0).then_some(4)
        } else {
            // SAFETY: NUL-terminated by the caller's contract.
            let text = unsafe { CStr::from_ptr(str.cast()) }.to_string_lossy();
            let escaped = encode_special(&text);
            let Ok(line) = std::ffi::CString::new(escaped) else {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlEncodeSpecialChars",
                    &format!("string={text}"),
                );
                return -1;
            };
            // SAFETY: `fd` is a live stream; `line` is NUL-terminated.
            let status = unsafe { libc::fputs(line.as_ptr(), fd.cast()) };
            (status >= 0).then_some(line.as_bytes().len())
        };
        // fprintf reports a count beyond `int` as an error too.
        if let Some(Ok(count)) = written.map(c_int::try_from) {
            return count;
        }
        errors::report(
            here,
            std::ptr::null(),
            c"fprintf".as_ptr(),
            errors::R_IO_FAILED,
            &format!(
                "name=\"NULL\"; errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ),
        );
        -1
    })
}

/// `xmlSecGetQName`: `prefix:local` for the namespace `href` in scope at
/// `node`, or `local` for an unprefixed or absent namespace; the caller
/// frees it. A namespace not in scope is an error: no declaration is added.
///
/// # Safety
/// `href` and `local` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetQName(
    node: *mut XmlNode,
    href: *const u8,
    local: *const u8,
) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        check!(
            !node.is_null(),
            "xmlSecGetQName",
            c"node != NULL",
            std::ptr::null_mut()
        );
        check!(
            !local.is_null(),
            "xmlSecGetQName",
            c"local != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecGetQName");
        // SAFETY: NUL-terminated by the caller's contract.
        let local_name = unsafe { CStr::from_ptr(local.cast()) }.to_bytes();
        // libxml2's xmlSearchNsByHref finds nothing for a null URI.
        // SAFETY: as above.
        let ns = match unsafe { c_text(href) } {
            Some(uri) => nodes::search_namespace_by_uri(node, uri),
            None => std::ptr::null_mut(),
        };
        if ns.is_null() && !href.is_null() {
            let name = nodes::name(node).unwrap_or_else(|| String::from("NULL"));
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSearchNsByHref",
                &format!("node={name}"),
            );
            return std::ptr::null_mut();
        }
        let Some(prefix) = nodes::binding(ns).and_then(|(prefix, _)| prefix) else {
            let copy = xml_sec_libxml2::ffi::memory::copy(local_name);
            if copy.is_null() {
                errors::strdup_failed(here, std::ptr::null(), local_name);
            }
            return copy;
        };
        let copy =
            xml_sec_libxml2::ffi::memory::copy(&[prefix.as_bytes(), b":", local_name].concat());
        if copy.is_null() {
            // libxmlsec1 allocates the prefix, the local name and 4 more bytes.
            errors::malloc_failed(here, std::ptr::null(), prefix.len() + local_name.len() + 4);
        }
        copy
    })
}
