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

/// `strtol(text, &end, 10)` over `text`, which has no leading white space:
/// the value and the number of bytes it read. A value beyond `long` is
/// `long`'s bound, as `strtol` clamps it; no digits read nothing.
fn strtol(text: &[u8]) -> (i128, usize) {
    let (negative, digits_at) = match text.first() {
        Some(b'-') => (true, 1),
        Some(b'+') => (false, 1),
        _ => (false, 0),
    };
    let digits = text[digits_at..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return (0, 0);
    }
    let bound = i128::from(libc::c_long::MAX);
    let mut value: i128 = 0;
    for &digit in &text[digits_at..digits_at + digits] {
        // Accumulation stops above the bound, so it never nears `i128`'s.
        if value <= bound {
            value = value * 10 + i128::from(digit - b'0');
        }
    }
    let value = if negative {
        (-value).max(i128::from(libc::c_long::MIN))
    } else {
        value.min(bound)
    };
    (value, digits_at + digits)
}

/// `xmlSecGetNodeContentAsSize`: the trimmed content of `cur` as a
/// non-negative decimal (`strtol` with nothing but white space after it),
/// or `def_value` when `cur` has no content.
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
        let (value, read) = strtol(content.as_bytes());
        if value < 0 || value == i128::from(libc::c_long::MAX) {
            // SAFETY: `cur` is a node pointer, validated by the report.
            unsafe {
                errors::invalid_node_content(
                    here,
                    cur,
                    std::ptr::null(),
                    "can't parse node content as size",
                );
            }
            return -1;
        }
        // The content is trimmed, so only the end of the number may follow.
        if read != content.len() {
            // SAFETY: as above.
            unsafe {
                errors::invalid_node_content(
                    here,
                    cur,
                    std::ptr::null(),
                    "can't parse node content as size (extra characters at the end)",
                );
            }
            return -1;
        }
        // A non-negative `long` fits a size on every supported target, whose
        // `long` is no wider than a pointer; a target where it does not
        // reports the content as unparsable rather than truncating it.
        let Ok(size) = usize::try_from(value) else {
            // SAFETY: as above.
            unsafe {
                errors::invalid_node_content(
                    here,
                    cur,
                    std::ptr::null(),
                    "can't parse node content as size",
                );
            }
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
