//! The `QName` mappings of `xmlsec/xmltree.h`: tables of qualified names with
//! an integer or a bit each, read from and written to element content and
//! attributes in the namespace context of a node.

use std::ffi::{CStr, c_int, c_uint, c_void};

use xml_sec_libxml2::ffi::tree::{xsFreeNode, xsGetProp, xsSetProp, xsUnlinkNode};

use super::super::errors::{self, Here, check, here};
use super::super::tree::{XmlNode, c_text, nodes, xmlStrEqual};
use super::super::{contain, free, write_stream};
use super::content::{set_reported, xmlSecGetQName};
use super::edit::xmlSecAddChild;
use super::{xmlSecCheckNodeName, xmlSecGetNextElementNode, xmlSecGetNodeContentAndTrim};

/// `xmlSecQName2IntegerInfo`: one entry of a table ending in a null local
/// part.
#[repr(C)]
pub(crate) struct QName2IntegerInfo {
    pub(crate) href: *const u8,
    pub(crate) local: *const u8,
    pub(crate) value: c_int,
}

/// `xmlSecQName2BitMaskInfo`: one entry of a table ending in a null local
/// part; every entry's mask is non-zero.
#[repr(C)]
pub(crate) struct QName2BitMaskInfo {
    pub(crate) href: *const u8,
    pub(crate) local: *const u8,
    pub(crate) mask: c_uint,
}

/// A table entry with its local part, namespace and value.
trait Entry {
    type Value: Copy + PartialEq;
    fn local(&self) -> *const u8;
    fn href(&self) -> *const u8;
    fn value(&self) -> Self::Value;
}

impl Entry for QName2IntegerInfo {
    type Value = c_int;
    fn local(&self) -> *const u8 {
        self.local
    }
    fn href(&self) -> *const u8 {
        self.href
    }
    fn value(&self) -> c_int {
        self.value
    }
}

impl Entry for QName2BitMaskInfo {
    type Value = c_uint;
    fn local(&self) -> *const u8 {
        self.local
    }
    fn href(&self) -> *const u8 {
        self.href
    }
    fn value(&self) -> c_uint {
        self.mask
    }
}

/// The entries of the table at `info`, up to the one with a null local part.
///
/// # Safety
/// `info` points to such a table.
unsafe fn entries<'a, E: Entry + 'a>(info: *const E) -> impl Iterator<Item = &'a E> {
    // SAFETY: by the caller's contract, every entry up to the terminator is
    // readable.
    (0..)
        .map(move |index| unsafe { &*info.add(index) })
        .take_while(|entry| !entry.local().is_null())
}

/// A possibly-null C string for a report.
fn text(value: *const u8) -> String {
    if value.is_null() {
        "NULL".to_owned()
    } else {
        // SAFETY: a non-null string of a node, table or caller is
        // NUL-terminated.
        unsafe { CStr::from_ptr(value.cast()) }
            .to_string_lossy()
            .into_owned()
    }
}

/// A possibly-null C string as printf's `%s` prints it.
fn printed(value: *const u8) -> String {
    if value.is_null() {
        "(null)".to_owned()
    } else {
        text(value)
    }
}

/// The name of `node` for a report.
fn node_name(node: *mut XmlNode) -> String {
    nodes::name(node).unwrap_or_else(|| "NULL".to_owned())
}

/// The namespace and local part `qname` names at `node`: the prefix before
/// `:` is resolved in scope (no prefix means the default namespace, which
/// may be absent); an unbound prefix is reported at `here`. The namespace
/// lives as long as the document, as libxml2's `ns->href` does.
///
/// # Safety
/// `qname` is NUL-terminated.
unsafe fn resolve(
    node: *mut XmlNode,
    qname: *const u8,
    here: Here,
) -> Option<(*const u8, *const u8)> {
    // SAFETY: by the caller's contract; the local part is a suffix of the
    // NUL-terminated `qname`.
    let bytes = unsafe { CStr::from_ptr(qname.cast()) }.to_bytes();
    let (prefix, local) = match bytes.iter().position(|&byte| byte == b':') {
        // SAFETY: as above.
        Some(colon) => (Some(&bytes[..colon]), unsafe { qname.add(colon + 1) }),
        None => (None, qname),
    };
    // A prefix that is not UTF-8 is bound nowhere.
    let ns = match prefix.map(std::str::from_utf8) {
        Some(Ok(prefix)) => nodes::search_namespace(node, Some(prefix)),
        Some(Err(_)) => std::ptr::null_mut(),
        None => nodes::search_namespace(node, None),
    };
    if ns.is_null() && prefix.is_some() {
        errors::xml_failed_with(
            here,
            std::ptr::null(),
            c"xmlSearchNs",
            &format!("node={}", node_name(node)),
        );
        return None;
    }
    let href = match (nodes::binding(ns), nodes::document_of(node)) {
        (Some((_, uri)), Some(document)) => xml_sec_libxml2::handles::intern(document, &uri),
        _ => std::ptr::null(),
    };
    Some((href, local))
}

/// The value of the entry named `local` in namespace `href`.
///
/// # Safety
/// `info` is a table; `href` and `local` are null or NUL-terminated.
unsafe fn value_of<E: Entry>(
    info: *const E,
    href: *const u8,
    local: *const u8,
) -> Option<E::Value> {
    // SAFETY: by the caller's contract.
    unsafe {
        entries(info)
            .find(|entry| {
                xmlStrEqual(entry.local(), local) != 0 && xmlStrEqual(entry.href(), href) != 0
            })
            .map(Entry::value)
    }
}

// ----------------------------------------------------------------------------
// QName <-> integer

/// `xmlSecQName2IntegerGetInfo`: the entry with `int_value`, or null.
///
/// # Safety
/// `info` is null or a table.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerGetInfo(
    info: *const QName2IntegerInfo,
    int_value: c_int,
) -> *const QName2IntegerInfo {
    contain(std::ptr::null(), || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerGetInfo",
            c"info != NULL",
            std::ptr::null()
        );
        // SAFETY: a table.
        unsafe { entries(info) }
            .find(|entry| entry.value == int_value)
            .map_or(std::ptr::null(), std::ptr::from_ref)
    })
}

/// `xmlSecQName2IntegerGetInteger`: the integer of the name `qname_local_part`
/// in namespace `qname_href`; -1 when the table has none.
///
/// # Safety
/// `info` is null or a table; the names are null or NUL-terminated;
/// `int_value` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerGetInteger(
    info: *const QName2IntegerInfo,
    qname_href: *const u8,
    qname_local_part: *const u8,
    int_value: *mut c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerGetInteger",
            c"info != NULL",
            -1
        );
        check!(
            !qname_local_part.is_null(),
            "xmlSecQName2IntegerGetInteger",
            c"qnameLocalPart != NULL",
            -1
        );
        check!(
            !int_value.is_null(),
            "xmlSecQName2IntegerGetInteger",
            c"intValue != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        match unsafe { value_of(info, qname_href, qname_local_part) } {
            Some(value) => {
                // SAFETY: writable.
                unsafe { int_value.write(value) };
                0
            }
            None => -1,
        }
    })
}

/// `xmlSecQName2IntegerGetIntegerFromString`: the integer of `qname`
/// resolved at `node`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; `qname` null or
/// NUL-terminated; `int_value` null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerGetIntegerFromString(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    qname: *const u8,
    int_value: *mut c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerGetIntegerFromString",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerGetIntegerFromString",
            c"node != NULL",
            -1
        );
        check!(
            !qname.is_null(),
            "xmlSecQName2IntegerGetIntegerFromString",
            c"qname != NULL",
            -1
        );
        check!(
            !int_value.is_null(),
            "xmlSecQName2IntegerGetIntegerFromString",
            c"intValue != NULL",
            -1
        );
        let here = here!("xmlSecQName2IntegerGetIntegerFromString");
        // SAFETY: by the caller's contract; libxml2 is available.
        unsafe {
            let Some((href, local)) = resolve(node, qname, here) else {
                return -1;
            };
            if xmlSecQName2IntegerGetInteger(info, href, local, int_value) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetInteger",
                    &format!(
                        "node={},qnameLocalPart={},qnameHref={}",
                        node_name(node),
                        text(local),
                        text(href)
                    ),
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecQName2IntegerGetStringFromInteger`: the qualified name of
/// `int_value` at `node`, which the caller frees.
///
/// # Safety
/// `info` is null or a table; `node` null or live.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerGetStringFromInteger(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    int_value: c_int,
) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerGetStringFromInteger",
            c"info != NULL",
            std::ptr::null_mut()
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerGetStringFromInteger",
            c"node != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: by the caller's contract.
        unsafe {
            let entry = xmlSecQName2IntegerGetInfo(info, int_value);
            if entry.is_null() {
                errors::internal_with(
                    here!("xmlSecQName2IntegerGetStringFromInteger"),
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetInfo",
                    &format!("node={},intValue={int_value}", node_name(node)),
                );
                return std::ptr::null_mut();
            }
            xmlSecGetQName(node, (*entry).href, (*entry).local)
        }
    })
}

/// `xmlSecQName2IntegerNodeRead`: the integer of the trimmed content of
/// `node`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; `int_value` null or
/// writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerNodeRead(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    int_value: *mut c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerNodeRead",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerNodeRead",
            c"node != NULL",
            -1
        );
        check!(
            !int_value.is_null(),
            "xmlSecQName2IntegerNodeRead",
            c"intValue != NULL",
            -1
        );
        let here = here!("xmlSecQName2IntegerNodeRead");
        // SAFETY: by the caller's contract; the content is freed here.
        unsafe {
            let content = xmlSecGetNodeContentAndTrim(node);
            if content.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecGetNodeContentAndTrim",
                    &format!("node={}", node_name(node)),
                );
                return -1;
            }
            let read = xmlSecQName2IntegerGetIntegerFromString(info, node, content, int_value);
            if read < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetIntegerFromString",
                    &format!("node={},value={}", node_name(node), text(content)),
                );
            }
            free(content.cast());
            if read < 0 { -1 } else { 0 }
        }
    })
}

/// `xmlSecQName2IntegerNodeWrite`: appends an element `node_name` in
/// namespace `node_ns` to `node` whose content is the qualified name of
/// `int_value`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; the names null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerNodeWrite(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    node_name_: *const u8,
    node_ns: *const u8,
    int_value: c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerNodeWrite",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerNodeWrite",
            c"node != NULL",
            -1
        );
        check!(
            !node_name_.is_null(),
            "xmlSecQName2IntegerNodeWrite",
            c"nodeName != NULL",
            -1
        );
        let here = here!("xmlSecQName2IntegerNodeWrite");
        // SAFETY: by the caller's contract; the name is freed here.
        unsafe {
            let qname = xmlSecQName2IntegerGetStringFromInteger(info, node, int_value);
            if qname.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetStringFromInteger",
                    &format!("node={},intValue={int_value}", node_name(node)),
                );
                return -1;
            }
            // The name is checked before the child exists, so a failed write
            // leaves no empty element behind.
            let Some(content) = qname_text(qname, here) else {
                free(qname.cast());
                return -1;
            };
            let cur = xmlSecAddChild(node, node_name_, node_ns);
            if cur.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecAddChild",
                    &format!("node={},intValue={int_value}", text(node_name_)),
                );
                free(qname.cast());
                return -1;
            }
            // The entry exists: the name was made from it above.
            let entry = xmlSecQName2IntegerGetInfo(info, int_value);
            if !bound_alike(node, cur, qname, (*entry).href, here) {
                free(qname.cast());
                return -1;
            }
            let set = set_reported(cur, content, here);
            free(qname.cast());
            if !set {
                return -1;
            }
        }
        0
    })
}

/// Whether the prefix of `qname` (none: the default namespace) is bound to
/// `href` (null or empty: no namespace) in the scope of `node`.
///
/// # Safety
/// `node` is a live node; `qname` NUL-terminated; `href` null or
/// NUL-terminated.
unsafe fn names_href(node: *mut XmlNode, qname: *const u8, href: *const u8) -> bool {
    // SAFETY: by the caller's contract.
    let (Some(qname), wanted) = (unsafe { c_text(qname) }, unsafe { c_text(href) }) else {
        return false;
    };
    let prefix = qname.split_once(':').map(|(prefix, _)| prefix);
    nodes::in_scope(node, prefix).as_deref().unwrap_or("") == wanted.unwrap_or("")
}

/// Whether the name `qname`, made in `parent` for an entry in `href`, keeps
/// that namespace in `child`; otherwise reported at `here` and `child` taken
/// back. The child's own namespace can rebind the prefix the name uses (a
/// default namespace for an unprefixed name), and a name read in another
/// namespace is not the value written. A name `parent` already reads in
/// another namespace is libxmlsec1's own (`xmlSecGetQName` writes the bare
/// local part for an entry in no namespace) and is written as libxmlsec1
/// writes it.
///
/// # Safety
/// `parent` and `child` are live nodes; `qname` is NUL-terminated; `href`
/// null or NUL-terminated.
unsafe fn bound_alike(
    parent: *mut XmlNode,
    child: *mut XmlNode,
    qname: *const u8,
    href: *const u8,
    here: Here,
) -> bool {
    // SAFETY: by the caller's contract.
    if unsafe { !names_href(parent, qname, href) || names_href(child, qname, href) } {
        return true;
    }
    errors::other(
        here,
        errors::R_INVALID_DATA,
        std::ptr::null(),
        Some(&format!(
            "qname={} reads as another name in the child",
            text(qname)
        )),
    );
    // SAFETY: by the caller's contract.
    unsafe {
        xsUnlinkNode(child);
        xsFreeNode(child);
    }
    false
}

/// The qualified name `qname` as the text `xmlNodeSetContent` stores; a
/// qualified name holds no markup, so it is stored as it reads. A name that
/// is not UTF-8 cannot be node content and is reported at `here`.
///
/// # Safety
/// `qname` is NUL-terminated and outlives the result.
unsafe fn qname_text<'a>(qname: *const u8, here: errors::Here) -> Option<&'a str> {
    // SAFETY: by the caller's contract.
    let text = unsafe { c_text(qname) };
    if text.is_none() {
        errors::xml_failed_with(
            here,
            std::ptr::null(),
            c"xmlNodeSetContent",
            "the qualified name is not UTF-8",
        );
    }
    text
}

/// `xmlSecQName2IntegerAttributeRead`: the integer of the qualified name in
/// the attribute `attr_name` of `node`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; `attr_name` null or
/// NUL-terminated; `int_value` null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerAttributeRead(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    attr_name: *const u8,
    int_value: *mut c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerAttributeRead",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerAttributeRead",
            c"node != NULL",
            -1
        );
        check!(
            !attr_name.is_null(),
            "xmlSecQName2IntegerAttributeRead",
            c"attrName != NULL",
            -1
        );
        check!(
            !int_value.is_null(),
            "xmlSecQName2IntegerAttributeRead",
            c"intValue != NULL",
            -1
        );
        let here = here!("xmlSecQName2IntegerAttributeRead");
        // SAFETY: by the caller's contract; the value is a copy freed here.
        unsafe {
            let value = xsGetProp(node, attr_name);
            if value.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlGetProp",
                    &format!("node={}", node_name(node)),
                );
                return -1;
            }
            let read = xmlSecQName2IntegerGetIntegerFromString(info, node, value, int_value);
            if read < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetIntegerFromString",
                    &format!(
                        "node={},attrName={},attrValue={}",
                        node_name(node),
                        text(attr_name),
                        text(value)
                    ),
                );
            }
            free(value.cast());
            if read < 0 { -1 } else { 0 }
        }
    })
}

/// `xmlSecQName2IntegerAttributeWrite`: sets the attribute `attr_name` of
/// `node` to the qualified name of `int_value`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; `attr_name` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerAttributeWrite(
    info: *const QName2IntegerInfo,
    node: *mut XmlNode,
    attr_name: *const u8,
    int_value: c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerAttributeWrite",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2IntegerAttributeWrite",
            c"node != NULL",
            -1
        );
        check!(
            !attr_name.is_null(),
            "xmlSecQName2IntegerAttributeWrite",
            c"attrName != NULL",
            -1
        );
        let here = here!("xmlSecQName2IntegerAttributeWrite");
        // SAFETY: by the caller's contract; the name is freed here.
        unsafe {
            let detail = || {
                format!(
                    "node={},attrName={},intValue={int_value}",
                    node_name(node),
                    text(attr_name)
                )
            };
            let qname = xmlSecQName2IntegerGetStringFromInteger(info, node, int_value);
            if qname.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2IntegerGetStringFromInteger",
                    &detail(),
                );
                return -1;
            }
            let attr = xsSetProp(node, attr_name, qname);
            free(qname.cast());
            if attr.is_null() {
                errors::internal_with(here, std::ptr::null(), c"xmlSetProp", &detail());
                return -1;
            }
        }
        0
    })
}

/// `xmlSecQName2IntegerDebugDump`: prints the entry of `int_value`, if any.
///
/// # Safety
/// `info` is null or a table; `name` null or NUL-terminated; `output` null
/// or a live C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerDebugDump(
    info: *const QName2IntegerInfo,
    int_value: c_int,
    name: *const u8,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerDebugDump",
            c"info != NULL"
        );
        check!(
            !name.is_null(),
            "xmlSecQName2IntegerDebugDump",
            c"name != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecQName2IntegerDebugDump",
            c"output != NULL"
        );
        // SAFETY: by the caller's contract.
        unsafe {
            if let Some(entry) = xmlSecQName2IntegerGetInfo(info, int_value).as_ref() {
                write_stream(
                    output,
                    &format!(
                        "== {}: {int_value} (name=\"{}\", href=\"{}\")\n",
                        text(name),
                        printed(entry.local),
                        printed(entry.href)
                    ),
                );
            }
        }
    });
}

/// `xmlSecQName2IntegerDebugXmlDump`: prints the entry of `int_value` as
/// XML, if any.
///
/// # Safety
/// As for [`xmlSecQName2IntegerDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2IntegerDebugXmlDump(
    info: *const QName2IntegerInfo,
    int_value: c_int,
    name: *const u8,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !info.is_null(),
            "xmlSecQName2IntegerDebugXmlDump",
            c"info != NULL"
        );
        check!(
            !name.is_null(),
            "xmlSecQName2IntegerDebugXmlDump",
            c"name != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecQName2IntegerDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: by the caller's contract.
        unsafe {
            if let Some(entry) = xmlSecQName2IntegerGetInfo(info, int_value).as_ref() {
                let name = text(name);
                // libxmlsec1 writes an opening tag where the closing one
                // belongs.
                write_stream(
                    output,
                    &format!(
                        "<{name} value=\"{int_value}\" href=\"{}\">{}<{name}>\n",
                        printed(entry.href),
                        printed(entry.local)
                    ),
                );
            }
        }
    });
}

// ----------------------------------------------------------------------------
// QName <-> bit mask

/// Asserts libxmlsec1's invariant of a bit-mask table at `here`: no entry
/// has a zero mask.
///
/// # Safety
/// `info` is a table.
unsafe fn masks_valid(info: *const QName2BitMaskInfo, here: Here) -> bool {
    // SAFETY: by the caller's contract.
    let valid = unsafe { entries(info) }.all(|entry| entry.mask != 0);
    if !valid {
        errors::assertion(here, c"info[ii].mask != 0");
    }
    valid
}

/// `xmlSecQName2BitMaskGetInfo`: the entry with `mask`, or null.
///
/// # Safety
/// `info` is null or a table.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskGetInfo(
    info: *const QName2BitMaskInfo,
    mask: c_uint,
) -> *const QName2BitMaskInfo {
    contain(std::ptr::null(), || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskGetInfo",
            c"info != NULL",
            std::ptr::null()
        );
        // SAFETY: a table; libxmlsec1 asserts each mask up to the match.
        unsafe {
            for entry in entries(info) {
                if entry.mask == 0 {
                    errors::assertion(here!("xmlSecQName2BitMaskGetInfo"), c"info[ii].mask != 0");
                    return std::ptr::null();
                }
                if entry.mask == mask {
                    return std::ptr::from_ref(entry);
                }
            }
        }
        std::ptr::null()
    })
}

/// `xmlSecQName2BitMaskGetBitMask`: the mask of the name `qname_local_part`
/// in namespace `qname_href`; -1 when the table has none.
///
/// # Safety
/// `info` is null or a table; the names null or NUL-terminated; `mask` null
/// or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskGetBitMask(
    info: *const QName2BitMaskInfo,
    qname_href: *const u8,
    qname_local_part: *const u8,
    mask: *mut c_uint,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskGetBitMask",
            c"info != NULL",
            -1
        );
        check!(
            !qname_local_part.is_null(),
            "xmlSecQName2BitMaskGetBitMask",
            c"qnameLocalPart != NULL",
            -1
        );
        check!(
            !mask.is_null(),
            "xmlSecQName2BitMaskGetBitMask",
            c"mask != NULL",
            -1
        );
        let here = here!("xmlSecQName2BitMaskGetBitMask");
        // SAFETY: by the caller's contract; libxmlsec1 asserts each mask up
        // to the match.
        unsafe {
            for entry in entries(info) {
                if entry.mask == 0 {
                    errors::assertion(here, c"info[ii].mask != 0");
                    return -1;
                }
                if xmlStrEqual(entry.local, qname_local_part) != 0
                    && xmlStrEqual(entry.href, qname_href) != 0
                {
                    mask.write(entry.mask);
                    return 0;
                }
            }
        }
        -1
    })
}

/// `xmlSecQName2BitMaskGetBitMaskFromString`: the mask of `qname` resolved
/// at `node`.
///
/// # Safety
/// `info` is null or a table; `node` null or live; `qname` null or
/// NUL-terminated; `mask` null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskGetBitMaskFromString(
    info: *const QName2BitMaskInfo,
    node: *mut XmlNode,
    qname: *const u8,
    mask: *mut c_uint,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskGetBitMaskFromString",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2BitMaskGetBitMaskFromString",
            c"node != NULL",
            -1
        );
        check!(
            !qname.is_null(),
            "xmlSecQName2BitMaskGetBitMaskFromString",
            c"qname != NULL",
            -1
        );
        check!(
            !mask.is_null(),
            "xmlSecQName2BitMaskGetBitMaskFromString",
            c"mask != NULL",
            -1
        );
        let here = here!("xmlSecQName2BitMaskGetBitMaskFromString");
        // SAFETY: by the caller's contract; libxml2 is available.
        unsafe {
            let Some((href, local)) = resolve(node, qname, here) else {
                return -1;
            };
            if xmlSecQName2BitMaskGetBitMask(info, href, local, mask) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecQName2BitMaskGetBitMask",
                    &format!(
                        "node={},qnameLocalPart={},qnameHref={}",
                        node_name(node),
                        text(local),
                        text(href)
                    ),
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecQName2BitMaskGetStringFromBitMask`: the qualified name of `mask`
/// at `node`, which the caller frees.
///
/// # Safety
/// `info` is null or a table; `node` null or live.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskGetStringFromBitMask(
    info: *const QName2BitMaskInfo,
    node: *mut XmlNode,
    mask: c_uint,
) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskGetStringFromBitMask",
            c"info != NULL",
            std::ptr::null_mut()
        );
        check!(
            !node.is_null(),
            "xmlSecQName2BitMaskGetStringFromBitMask",
            c"node != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: by the caller's contract.
        unsafe {
            let entry = xmlSecQName2BitMaskGetInfo(info, mask);
            if entry.is_null() {
                errors::internal_with(
                    here!("xmlSecQName2BitMaskGetStringFromBitMask"),
                    std::ptr::null(),
                    c"xmlSecQName2BitMaskGetInfo",
                    &format!("node={},mask={mask}", node_name(node)),
                );
                return std::ptr::null_mut();
            }
            xmlSecGetQName(node, (*entry).href, (*entry).local)
        }
    })
}

/// `xmlSecQName2BitMaskNodesRead`: the union of the masks of the
/// consecutive elements `node_name` in namespace `node_ns` from `*node`;
/// `*node` is left at the first element after them. With `stop_on_unknown`
/// a name mapped to no bit fails.
///
/// # Safety
/// `info` is null or a table; `node` null or a writable pointer to null or
/// a live node; the names null or NUL-terminated; `mask` null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskNodesRead(
    info: *const QName2BitMaskInfo,
    node: *mut *mut XmlNode,
    node_name_: *const u8,
    node_ns: *const u8,
    stop_on_unknown: c_int,
    mask: *mut c_uint,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskNodesRead",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2BitMaskNodesRead",
            c"node != NULL",
            -1
        );
        check!(
            !mask.is_null(),
            "xmlSecQName2BitMaskNodesRead",
            c"mask != NULL",
            -1
        );
        let here = here!("xmlSecQName2BitMaskNodesRead");
        // SAFETY: by the caller's contract; each content is freed here.
        unsafe {
            mask.write(0);
            let mut cur = node.read();
            while !cur.is_null() && xmlSecCheckNodeName(cur, node_name_, node_ns) != 0 {
                let content = xmlSecGetNodeContentAndTrim(cur);
                if content.is_null() {
                    errors::internal_with(
                        here,
                        std::ptr::null(),
                        c"xmlSecGetNodeContentAndTrim",
                        &format!("node={}", node_name(cur)),
                    );
                    return -1;
                }
                let mut bit = 0;
                let read =
                    xmlSecQName2BitMaskGetBitMaskFromString(info, cur, content, &raw mut bit);
                if read < 0 || (stop_on_unknown != 0 && bit == 0) {
                    errors::internal_with(
                        here,
                        std::ptr::null(),
                        c"xmlSecQName2BitMaskGetBitMaskFromString",
                        &format!("value={}", text(content)),
                    );
                    free(content.cast());
                    return -1;
                }
                free(content.cast());
                mask.write(mask.read() | bit);
                cur = xmlSecGetNextElementNode(nodes::next(cur));
            }
            node.write(cur);
        }
        0
    })
}

/// `xmlSecQName2BitMaskNodesWrite`: appends to `node` one element
/// `node_name` in namespace `node_ns` per table entry whose bits `mask`
/// shares, holding the entry's qualified name.
///
/// # Safety
/// `info` is null or a table; `node` null or live; the names null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskNodesWrite(
    info: *const QName2BitMaskInfo,
    node: *mut XmlNode,
    node_name_: *const u8,
    node_ns: *const u8,
    mask: c_uint,
) -> c_int {
    contain(-1, || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskNodesWrite",
            c"info != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecQName2BitMaskNodesWrite",
            c"node != NULL",
            -1
        );
        check!(
            !node_name_.is_null(),
            "xmlSecQName2BitMaskNodesWrite",
            c"nodeName != NULL",
            -1
        );
        let here = here!("xmlSecQName2BitMaskNodesWrite");
        if mask == 0 {
            return 0;
        }
        // SAFETY: by the caller's contract; each name is freed here.
        unsafe {
            for entry in entries(info) {
                if entry.mask == 0 {
                    errors::assertion(here, c"info[ii].mask != 0");
                    return -1;
                }
                if mask & entry.mask == 0 {
                    continue;
                }
                let qname = xmlSecGetQName(node, entry.href, entry.local);
                if qname.is_null() {
                    errors::xml_failed_with(
                        here,
                        std::ptr::null(),
                        c"xmlSecGetQName",
                        &format!("node={}", text(node_name_)),
                    );
                    return -1;
                }
                let Some(content) = qname_text(qname, here) else {
                    free(qname.cast());
                    return -1;
                };
                let cur = xmlSecAddChild(node, node_name_, node_ns);
                if cur.is_null() {
                    errors::xml_failed_with(
                        here,
                        std::ptr::null(),
                        c"xmlSecAddChild",
                        &format!("node={}", text(node_name_)),
                    );
                    free(qname.cast());
                    return -1;
                }
                if !bound_alike(node, cur, qname, entry.href, here) {
                    free(qname.cast());
                    return -1;
                }
                let set = set_reported(cur, content, here);
                free(qname.cast());
                if !set {
                    return -1;
                }
            }
        }
        0
    })
}

/// `xmlSecQName2BitMaskDebugDump`: prints the entries `mask` covers.
///
/// # Safety
/// `info` is null or a table; `name` null or NUL-terminated; `output` null
/// or a live C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskDebugDump(
    info: *const QName2BitMaskInfo,
    mask: c_uint,
    name: *const u8,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskDebugDump",
            c"info != NULL"
        );
        check!(
            !name.is_null(),
            "xmlSecQName2BitMaskDebugDump",
            c"name != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecQName2BitMaskDebugDump",
            c"output != NULL"
        );
        if mask == 0 {
            return;
        }
        // SAFETY: by the caller's contract.
        unsafe {
            if !masks_valid(info, here!("xmlSecQName2BitMaskDebugDump")) {
                return;
            }
            write_stream(output, &format!("== {} (0x{mask:08x}): ", text(name)));
            for entry in entries(info).filter(|entry| mask & entry.mask != 0) {
                write_stream(
                    output,
                    &format!(
                        "name=\"{}\" (href=\"{}\"),",
                        printed(entry.local),
                        printed(entry.href)
                    ),
                );
            }
            write_stream(output, "\n");
        }
    });
}

/// `xmlSecQName2BitMaskDebugXmlDump`: prints the entries `mask` covers as
/// XML.
///
/// # Safety
/// As for [`xmlSecQName2BitMaskDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecQName2BitMaskDebugXmlDump(
    info: *const QName2BitMaskInfo,
    mask: c_uint,
    name: *const u8,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !info.is_null(),
            "xmlSecQName2BitMaskDebugXmlDump",
            c"info != NULL"
        );
        check!(
            !name.is_null(),
            "xmlSecQName2BitMaskDebugXmlDump",
            c"name != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecQName2BitMaskDebugXmlDump",
            c"output != NULL"
        );
        if mask == 0 {
            return;
        }
        // SAFETY: by the caller's contract.
        unsafe {
            if !masks_valid(info, here!("xmlSecQName2BitMaskDebugXmlDump")) {
                return;
            }
            let name = text(name);
            write_stream(output, &format!("<{name}List>\n"));
            for entry in entries(info).filter(|entry| mask & entry.mask != 0) {
                write_stream(
                    output,
                    &format!(
                        "<{name} href=\"{}\">{}</{name}>\n",
                        printed(entry.href),
                        printed(entry.local)
                    ),
                );
            }
            write_stream(output, &format!("</{name}List>\n"));
        }
    });
}
