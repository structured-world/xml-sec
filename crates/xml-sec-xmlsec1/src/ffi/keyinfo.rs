//! `xmlsec/keyinfo.h`: the `KeyInfo` processing context and the reading and
//! writing of a `KeyInfo` element through the key-data klasses of its
//! children, as libxmlsec1 processes it.
//!
//! The context has libxmlsec1's layout. Its encryption context is the
//! `xmlSecEncCtx` of the `XMLEnc` tier, which this layer never creates; a
//! caller-set one is released as libxmlsec1 releases it once that tier
//! provides it.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::policy::KeySourceKind;
use xml_sec_libxml2::ffi::tree::xsNodeName;

use super::base64::xmlSecBase64GetDefaultLineSize;
use super::errors::{self, check, here};
use super::keys::{
    XmlSecKey, XmlSecKeyReq, key_valid, xmlSecKeyCopy, xmlSecKeyDestroy, xmlSecKeyEmpty,
    xmlSecKeyMatch, xmlSecKeyReqDebugDump, xmlSecKeyReqDebugXmlDump, xmlSecKeyReqFinalize,
    xmlSecKeyReqInitialize, xmlSecKeyReqMatchKey, xmlSecKeyReqReset, xmlSecKeySetName,
};
use super::keysdata::{
    XmlSecKeyDataKlass, data_valid, xmlSecKeyDataIdListDebugDump, xmlSecKeyDataIdListDebugXmlDump,
    xmlSecKeyDataIdListFind, xmlSecKeyDataIdListFindByNode, xmlSecKeyDataIdListGetKlass,
    xmlSecKeyDataIdsGetEnabled, xmlSecKeyDataNameGetKlass, xmlSecKeyDataValueGetKlass,
    xmlSecKeyDataXmlRead, xmlSecKeyDataXmlWrite,
};
use super::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrFindKey};
use super::list::{
    XmlSecPtrList, xmlSecPtrListCopy, xmlSecPtrListFinalize, xmlSecPtrListGetSize,
    xmlSecPtrListInitialize,
};
use super::transforms::{
    XmlSecTransformCtx,
    ctx::{
        xmlSecTransformCtxCopyUserPref, xmlSecTransformCtxDebugDump,
        xmlSecTransformCtxDebugXmlDump, xmlSecTransformCtxFinalize, xmlSecTransformCtxInitialize,
        xmlSecTransformCtxReset,
    },
};
use super::tree::{XmlNode, nodes, xmlStrEqual};
use super::xmltree::{
    xmlSecAddChild, xmlSecGetNextElementNode, xmlSecGetNodeContentAndTrim, xmlSecGetNodeNsHref,
    xmlSecIsEmptyNode, xmlSecNodeEncodeAndSetContent,
};
use super::{contain, free, malloc, policy, write_stream};

mod references;
#[cfg(test)]
mod tests;
pub(crate) use references::{
    reference_xml_read, reference_xml_write, retrieval_xml_read, retrieval_xml_write,
};

/// The policy revision a read with `ctx` runs under: the one pinned for the
/// running `KeyInfo` read, or the current one for a reader called on its own.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn read_policy(
    ctx: *mut XmlSecKeyInfoCtx,
    here: errors::Here,
) -> Option<policy::Pinned> {
    // SAFETY: by the caller's contract; the slot is null or a pin.
    match unsafe { policy::pinned((*ctx).reserved0) } {
        Some(pinned) => Some(pinned.clone()),
        None => policy::Pinned::current(here),
    }
}

/// Whether a key-store search of the read with `ctx` was refused for the
/// read's candidate allowance: a policy failure, not an unknown name.
///
/// # Safety
/// `ctx` is a context.
unsafe fn candidates_exhausted(ctx: *mut XmlSecKeyInfoCtx) -> bool {
    // SAFETY: by the caller's contract; the slot is null or a pin.
    unsafe { policy::key_candidates((*ctx).reserved0) }.is_some_and(|tally| tally.get().exhausted)
}

/// The key source of the document the klass `id` reads, as the verification
/// policy's `key_sources` names it: a key the document names, carries or
/// references. `None` for a klass whose result another klass reads (a
/// retrieval method), which is checked as that klass.
pub(crate) fn key_source(id: *const XmlSecKeyDataKlass) -> Option<KeySourceKind> {
    if std::ptr::eq(id, xmlSecKeyDataNameGetKlass()) {
        return Some(KeySourceKind::KeyName);
    }
    if std::ptr::eq(id, xmlSecKeyDataValueGetKlass()) {
        return Some(KeySourceKind::KeyValue);
    }
    if std::ptr::eq(id, super::asymkeys::der_encoded_key_value()) {
        return Some(KeySourceKind::DerEncodedKeyValue);
    }
    if std::ptr::eq(id, super::keysdata::xmlSecKeyDataKeyInfoReferenceGetKlass()) {
        return Some(KeySourceKind::KeyInfoReference);
    }
    // A value klass reads key material the document carries, inside
    // KeyValue or where a retrieval method finds it.
    // SAFETY: a klass the caller validated.
    let usage = unsafe { id.as_ref() }.map_or(0, |klass| klass.usage);
    (usage & USAGE_KEY_VALUE_NODE_READ != 0).then_some(KeySourceKind::KeyValue)
}

/// Whether `pinned` refuses the document key source the klass `id` reads,
/// reported at `here` when it does.
pub(crate) fn source_refused(
    id: *const XmlSecKeyDataKlass,
    pinned: &policy::Pinned,
    here: errors::Here,
) -> bool {
    let Some(source) = key_source(id) else {
        return false;
    };
    if pinned.verification.key_sources.contains(source) {
        return false;
    }
    errors::report(
        here,
        // SAFETY: a klass the caller validated.
        unsafe { klass_name(id) },
        std::ptr::null(),
        errors::R_KEYDATA_DISABLED,
        &format!("key source {source:?} is not permitted by the policy"),
    );
    true
}

/// `xmlSecKeyInfoModeRead`.
pub(crate) const MODE_READ: c_int = 0;
/// `xmlSecKeyInfoModeWrite`.
pub(crate) const MODE_WRITE: c_int = 1;

/// `XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND`.
pub(crate) const FLAGS_DONT_STOP_ON_KEY_FOUND: c_uint = 0x0000_0001;
/// `XMLSEC_KEYINFO_FLAGS_STOP_ON_UNKNOWN_CHILD`.
const FLAGS_STOP_ON_UNKNOWN_CHILD: c_uint = 0x0000_0002;
/// `XMLSEC_KEYINFO_FLAGS_KEYNAME_STOP_ON_UNKNOWN`.
const FLAGS_KEYNAME_STOP_ON_UNKNOWN: c_uint = 0x0000_0004;
/// `XMLSEC_KEYINFO_FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD`.
const FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD: c_uint = 0x0000_0008;

/// `xmlSecKeyDataUsageKeyInfoNodeRead`.
const USAGE_KEY_INFO_NODE_READ: c_uint = 0x00001;
/// `xmlSecKeyDataUsageKeyInfoNodeWrite`.
const USAGE_KEY_INFO_NODE_WRITE: c_uint = 0x00002;
/// `xmlSecKeyDataUsageKeyValueNodeRead`.
const USAGE_KEY_VALUE_NODE_READ: c_uint = 0x00004;
/// `xmlSecKeyDataUsageKeyValueNodeWrite`.
const USAGE_KEY_VALUE_NODE_WRITE: c_uint = 0x00008;
use errors::R_INVALID_KEY_DATA;

/// `xmlSecKeyInfoCtx`, with the `XMLEnc` and X.509 members of a build that
/// has both.
#[repr(C)]
pub(crate) struct XmlSecKeyInfoCtx {
    pub(crate) user_data: *mut c_void,
    pub(crate) flags: c_uint,
    pub(crate) flags2: c_uint,
    pub(crate) keys_mngr: *mut XmlSecKeysMngr,
    pub(crate) mode: c_int,
    pub(crate) enabled_key_data: XmlSecPtrList,
    pub(crate) base64_line_size: c_int,
    pub(crate) retrieval_method_ctx: XmlSecTransformCtx,
    pub(crate) max_retrieval_method_level: c_int,
    pub(crate) key_info_reference_ctx: XmlSecTransformCtx,
    pub(crate) max_key_info_reference_level: c_int,
    pub(crate) enc_ctx: *mut c_void,
    pub(crate) max_encrypted_key_level: c_int,
    pub(crate) certs_verification_time: libc::time_t,
    pub(crate) certs_verification_depth: c_int,
    pub(crate) deprecated0: *mut c_void,
    pub(crate) cur_retrieval_method_level: c_int,
    pub(crate) cur_key_info_reference_level: c_int,
    pub(crate) cur_encrypted_key_level: c_int,
    pub(crate) operation: c_int,
    pub(crate) key_req: XmlSecKeyReq,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// The name of `node` for a report.
///
/// # Safety
/// Callable with any pointer; `unsafe` keeps the reporting helpers' shape.
unsafe fn node_name(node: *const XmlNode) -> String {
    nodes::name(node).unwrap_or_else(|| "NULL".to_owned())
}

/// The name of the klass `id` for a report object.
///
/// # Safety
/// `id` is null or a klass.
unsafe fn klass_name(id: *const XmlSecKeyDataKlass) -> *const std::ffi::c_char {
    // SAFETY: by the caller's contract.
    unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name.cast())
}

/// The klass of the child `node` with usage `usage`, from the context's
/// enabled list when it has one and from the registry's enabled subset
/// otherwise.
///
/// # Safety
/// `ctx` is a context; `node` a live element.
unsafe fn child_klass(
    ctx: *mut XmlSecKeyInfoCtx,
    node: *mut XmlNode,
    usage: c_uint,
) -> *const XmlSecKeyDataKlass {
    // SAFETY: by the caller's contract; the registry has a fixed address.
    unsafe {
        let list = &raw mut (*ctx).enabled_key_data;
        let list = if xmlSecPtrListGetSize(list) > 0 {
            list
        } else {
            xmlSecKeyDataIdsGetEnabled()
        };
        xmlSecKeyDataIdListFindByNode(list, xsNodeName(node), xmlSecGetNodeNsHref(node), usage)
    }
}

// ----------------------------------------------------------------------------
// High-level functions

/// `xmlSecKeyInfoNodeRead`: reads the children of `key_info_node` into
/// `key` through the klasses of their elements, until a key meeting the
/// requirements is found (or to the end with
/// `XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND`).
///
/// # Safety
/// `key_info_node` is null or a live node; `key` null or a key; `ctx` null
/// or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoNodeRead(
    key_info_node: *mut XmlNode,
    key: *mut XmlSecKey,
    ctx: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        check!(
            !key_info_node.is_null(),
            "xmlSecKeyInfoNodeRead",
            c"keyInfoNode != NULL",
            -1
        );
        check!(!key.is_null(), "xmlSecKeyInfoNodeRead", c"key != NULL", -1);
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoNodeRead",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_READ,
            "xmlSecKeyInfoNodeRead",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead",
            -1
        );
        let here = here!("xmlSecKeyInfoNodeRead");
        // SAFETY: a key and a context; children are read in document order
        // as libxmlsec1 reads them.
        unsafe {
            // Every child, the references it follows and the chains it runs
            // read one policy revision, pinned for this read.
            let Some(_pin) = policy::SlotPin::hold(&raw mut (*ctx).reserved0, here) else {
                return -1;
            };
            let mut cur = xmlSecGetNextElementNode(nodes::first_child(key_info_node));
            while !cur.is_null()
                && ((*ctx).flags & FLAGS_DONT_STOP_ON_KEY_FOUND != 0
                    || !key_valid(key)
                    || xmlSecKeyMatch(key, std::ptr::null(), &raw mut (*ctx).key_req) == 0)
            {
                let data_id = child_klass(ctx, cur, USAGE_KEY_INFO_NODE_READ);
                if data_id.is_null() {
                    errors::unexpected_node(here, cur, std::ptr::null());
                    if (*ctx).flags & FLAGS_STOP_ON_UNKNOWN_CHILD != 0 {
                        return -1;
                    }
                } else if xmlSecKeyDataXmlRead(data_id, key.cast(), cur.cast(), ctx.cast()) < 0 {
                    errors::internal_with(
                        here,
                        klass_name(data_id),
                        c"xmlSecKeyDataXmlRead",
                        &format!("node={}", node_name(cur)),
                    );
                    return -1;
                }
                cur = xmlSecGetNextElementNode(nodes::next(cur));
            }
        }
        0
    })
}

/// `xmlSecKeyInfoNodeWrite`: writes `key` into the children of the
/// template `key_info_node` through the klasses of their elements.
///
/// # Safety
/// As for [`xmlSecKeyInfoNodeRead`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoNodeWrite(
    key_info_node: *mut XmlNode,
    key: *mut XmlSecKey,
    ctx: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        check!(
            !key_info_node.is_null(),
            "xmlSecKeyInfoNodeWrite",
            c"keyInfoNode != NULL",
            -1
        );
        check!(!key.is_null(), "xmlSecKeyInfoNodeWrite", c"key != NULL", -1);
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoNodeWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_WRITE,
            "xmlSecKeyInfoNodeWrite",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite",
            -1
        );
        let here = here!("xmlSecKeyInfoNodeWrite");
        // SAFETY: a key and a context.
        unsafe {
            let mut cur = xmlSecGetNextElementNode(nodes::first_child(key_info_node));
            while !cur.is_null() {
                let data_id = child_klass(ctx, cur, USAGE_KEY_INFO_NODE_WRITE);
                if !data_id.is_null() {
                    if xmlSecKeyDataXmlWrite(data_id, key.cast(), cur.cast(), ctx.cast()) < 0 {
                        errors::internal_with(
                            here,
                            klass_name(data_id),
                            c"xmlSecKeyDataXmlWrite",
                            &format!("node={}", node_name(cur)),
                        );
                        return -1;
                    }
                } else if (*ctx).flags & FLAGS_STOP_ON_UNKNOWN_CHILD != 0 {
                    errors::unexpected_node(here, cur, std::ptr::null());
                    return -1;
                }
                cur = xmlSecGetNextElementNode(nodes::next(cur));
            }
        }
        0
    })
}

// ----------------------------------------------------------------------------
// The context

/// `xmlSecKeyInfoCtxCreate`: a new context for `keys_mngr`, released with
/// [`xmlSecKeyInfoCtxDestroy`].
///
/// # Safety
/// `keys_mngr` is null or a keys manager outliving the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxCreate(
    keys_mngr: *mut XmlSecKeysMngr,
) -> *mut XmlSecKeyInfoCtx {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecKeyInfoCtxCreate");
        let ctx = malloc(size_of::<XmlSecKeyInfoCtx>()).cast::<XmlSecKeyInfoCtx>();
        if ctx.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecKeyInfoCtx>());
            return ctx;
        }
        // SAFETY: a fresh allocation of the context's size.
        unsafe {
            if xmlSecKeyInfoCtxInitialize(ctx, keys_mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
                xmlSecKeyInfoCtxDestroy(ctx);
                return std::ptr::null_mut();
            }
        }
        ctx
    })
}

/// `xmlSecKeyInfoCtxDestroy`: releases a context from
/// [`xmlSecKeyInfoCtxCreate`].
///
/// # Safety
/// `ctx` is null or a created context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxDestroy(ctx: *mut XmlSecKeyInfoCtx) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxDestroy",
            c"keyInfoCtx != NULL"
        );
        // SAFETY: a created context.
        unsafe {
            xmlSecKeyInfoCtxFinalize(ctx);
            free(ctx.cast());
        }
    });
}

/// `xmlSecKeyInfoCtxInitialize`: a read context for `keys_mngr` with
/// libxmlsec1's defaults: every registered key data enabled, the default
/// Base64 line size, one level of `RetrievalMethod`, `KeyInfoReference` and
/// `EncryptedKey`, a certificate depth of 9 and requirements any key meets.
///
/// # Safety
/// `ctx` is null or writable; `keys_mngr` null or a keys manager outliving
/// the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxInitialize(
    ctx: *mut XmlSecKeyInfoCtx,
    keys_mngr: *mut XmlSecKeysMngr,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxInitialize",
            c"keyInfoCtx != NULL",
            -1
        );
        let here = here!("xmlSecKeyInfoCtxInitialize");
        // SAFETY: writable; every member is set from zero as in libxmlsec1.
        unsafe {
            ctx.cast::<u8>()
                .write_bytes(0, size_of::<XmlSecKeyInfoCtx>());
            let context = &mut *ctx;
            context.keys_mngr = keys_mngr;
            context.base64_line_size = xmlSecBase64GetDefaultLineSize();
            if xmlSecPtrListInitialize(
                &raw mut context.enabled_key_data,
                xmlSecKeyDataIdListGetKlass(),
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListInitialize");
                return -1;
            }
            context.max_retrieval_method_level = 1;
            if xmlSecTransformCtxInitialize(&raw mut context.retrieval_method_ctx) < 0 {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxInitialize(retrievalMethodCtx)",
                );
                return -1;
            }
            context.max_key_info_reference_level = 1;
            if xmlSecTransformCtxInitialize(&raw mut context.key_info_reference_ctx) < 0 {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxInitialize(keyInfoReferenceCtx)",
                );
                return -1;
            }
            context.max_encrypted_key_level = 1;
            context.certs_verification_depth = 9;
            if xmlSecKeyReqInitialize(&raw mut context.key_req) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyReqInitialize");
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyInfoCtxFinalize`: releases what the context owns and zeroes
/// it.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxFinalize(ctx: *mut XmlSecKeyInfoCtx) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxFinalize",
            c"keyInfoCtx != NULL"
        );
        // SAFETY: an initialized context.
        unsafe {
            let context = &mut *ctx;
            xmlSecPtrListFinalize(&raw mut context.enabled_key_data);
            xmlSecTransformCtxFinalize(&raw mut context.retrieval_method_ctx);
            xmlSecTransformCtxFinalize(&raw mut context.key_info_reference_ctx);
            xmlSecKeyReqFinalize(&raw mut context.key_req);
            // A read's guard releases its pin; one left by a context finalized
            // from inside the read is freed rather than zeroed away.
            policy::release(&raw mut context.reserved0);
            ctx.cast::<u8>()
                .write_bytes(0, size_of::<XmlSecKeyInfoCtx>());
        }
    });
}

/// `xmlSecKeyInfoCtxReset`: clears the processing state, keeping the user
/// settings.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxReset(ctx: *mut XmlSecKeyInfoCtx) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxReset",
            c"keyInfoCtx != NULL"
        );
        // SAFETY: an initialized context.
        unsafe {
            let context = &mut *ctx;
            xmlSecTransformCtxReset(&raw mut context.retrieval_method_ctx);
            context.cur_retrieval_method_level = 0;
            xmlSecTransformCtxReset(&raw mut context.key_info_reference_ctx);
            context.cur_key_info_reference_level = 0;
            context.cur_encrypted_key_level = 0;
            // xmlSecTransformOperationNone.
            context.operation = 0;
            xmlSecKeyReqReset(&raw mut context.key_req);
        }
    });
}

/// `xmlSecKeyInfoCtxCopyUserPref`: copies the user settings of `src` into
/// `dst`.
///
/// # Safety
/// `dst` and `src` are null or initialized contexts.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxCopyUserPref(
    dst: *mut XmlSecKeyInfoCtx,
    src: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        check!(
            !dst.is_null(),
            "xmlSecKeyInfoCtxCopyUserPref",
            c"dst != NULL",
            -1
        );
        check!(
            !src.is_null(),
            "xmlSecKeyInfoCtxCopyUserPref",
            c"src != NULL",
            -1
        );
        let here = here!("xmlSecKeyInfoCtxCopyUserPref");
        // SAFETY: initialized contexts.
        unsafe {
            let (to, from) = (&mut *dst, &mut *src);
            to.user_data = from.user_data;
            to.flags = from.flags;
            to.flags2 = from.flags2;
            to.keys_mngr = from.keys_mngr;
            to.base64_line_size = from.base64_line_size;
            if xmlSecPtrListCopy(&raw mut to.enabled_key_data, &raw mut from.enabled_key_data) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListCopy(enabledKeyData)");
                return -1;
            }
            to.max_retrieval_method_level = from.max_retrieval_method_level;
            if xmlSecTransformCtxCopyUserPref(
                &raw mut to.retrieval_method_ctx,
                &raw mut from.retrieval_method_ctx,
            ) < 0
            {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCopyUserPref(enabledKeyData)",
                );
                return -1;
            }
            to.max_key_info_reference_level = from.max_key_info_reference_level;
            if xmlSecTransformCtxCopyUserPref(
                &raw mut to.key_info_reference_ctx,
                &raw mut from.key_info_reference_ctx,
            ) < 0
            {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCopyUserPref(enabledKeyData)",
                );
                return -1;
            }
            to.max_encrypted_key_level = from.max_encrypted_key_level;
            to.certs_verification_time = from.certs_verification_time;
            to.certs_verification_depth = from.certs_verification_depth;
        }
        0
    })
}

/// `xmlSecKeyInfoCtxDebugDump`: prints the settings and state.
///
/// # Safety
/// `ctx` is null or an initialized context; `output` null or a live C
/// stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxDebugDump(
    ctx: *mut XmlSecKeyInfoCtx,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxDebugDump",
            c"keyInfoCtx != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyInfoCtxDebugDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            match context.mode {
                MODE_READ => write_stream(output, "= KEY INFO READ CONTEXT\n"),
                MODE_WRITE => write_stream(output, "= KEY INFO WRITE CONTEXT\n"),
                _ => {}
            }
            write_stream(
                output,
                &format!(
                    "== flags: 0x{:08x}\n== flags2: 0x{:08x}\n",
                    context.flags, context.flags2
                ),
            );
            if xmlSecPtrListGetSize(&raw mut context.enabled_key_data) > 0 {
                write_stream(output, "== enabled key data: ");
                xmlSecKeyDataIdListDebugDump(&raw mut context.enabled_key_data, output);
            } else {
                write_stream(output, "== enabled key data: all\n");
            }
            write_stream(
                output,
                &format!(
                    "== RetrievalMethod level (cur/max): {}/{}\n",
                    context.cur_retrieval_method_level, context.max_retrieval_method_level
                ),
            );
            xmlSecTransformCtxDebugDump(&raw mut context.retrieval_method_ctx, output);
            write_stream(
                output,
                &format!(
                    "== KeyInfoReference level (cur/max): {}/{}\n",
                    context.cur_key_info_reference_level, context.max_key_info_reference_level
                ),
            );
            xmlSecTransformCtxDebugDump(&raw mut context.key_info_reference_ctx, output);
            write_stream(
                output,
                &format!(
                    "== EncryptedKey level (cur/max): {}/{}\n",
                    context.cur_encrypted_key_level, context.max_encrypted_key_level
                ),
            );
            xmlSecKeyReqDebugDump(&raw mut context.key_req, output);
        }
    });
}

/// `xmlSecKeyInfoCtxDebugXmlDump`: prints the settings and state as XML.
///
/// # Safety
/// As for [`xmlSecKeyInfoCtxDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxDebugXmlDump(
    ctx: *mut XmlSecKeyInfoCtx,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxDebugXmlDump",
            c"keyInfoCtx != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyInfoCtxDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            match context.mode {
                MODE_READ => write_stream(output, "<KeyInfoReadContext>\n"),
                MODE_WRITE => write_stream(output, "<KeyInfoWriteContext>\n"),
                _ => {}
            }
            write_stream(
                output,
                &format!(
                    "<Flags>{:08x}</Flags>\n<Flags2>{:08x}</Flags2>\n",
                    context.flags, context.flags2
                ),
            );
            if xmlSecPtrListGetSize(&raw mut context.enabled_key_data) > 0 {
                write_stream(output, "<EnabledKeyData>\n");
                xmlSecKeyDataIdListDebugXmlDump(&raw mut context.enabled_key_data, output);
                write_stream(output, "</EnabledKeyData>\n");
            } else {
                write_stream(output, "<EnabledKeyData>all</EnabledKeyData>\n");
            }
            // libxmlsec1 prints the EncryptedKey levels for all three.
            let levels = format!(
                "cur=\"{}\" max=\"{}\"",
                context.cur_encrypted_key_level, context.max_encrypted_key_level
            );
            write_stream(output, &format!("<RetrievalMethodLevel {levels} />\n"));
            xmlSecTransformCtxDebugXmlDump(&raw mut context.retrieval_method_ctx, output);
            write_stream(output, &format!("<KeyInfoReferenceLevel {levels} />\n"));
            xmlSecTransformCtxDebugXmlDump(&raw mut context.key_info_reference_ctx, output);
            write_stream(output, &format!("<EncryptedKeyLevel {levels} />\n"));
            xmlSecKeyReqDebugXmlDump(&raw mut context.key_req, output);
            match context.mode {
                MODE_READ => write_stream(output, "</KeyInfoReadContext>\n"),
                MODE_WRITE => write_stream(output, "</KeyInfoWriteContext>\n"),
                _ => {}
            }
        }
    });
}

// ----------------------------------------------------------------------------
// <dsig:KeyName/>

/// `xmlRead` of the `KeyName` klass: names the key, or with a keys manager
/// and no value yet, takes the manager's key of that name.
pub(crate) unsafe extern "C" fn name_xml_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecKeyDataNameXmlRead");
        check!(
            std::ptr::eq(id, xmlSecKeyDataNameGetKlass()),
            "xmlSecKeyDataNameXmlRead",
            c"id == xmlSecKeyDataNameId",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecKeyDataNameXmlRead",
            c"key != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecKeyDataNameXmlRead",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataNameXmlRead",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_READ,
            "xmlSecKeyDataNameXmlRead",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead",
            -1
        );
        // SAFETY: a key, a live node and a context; the name is freed here.
        unsafe {
            let object = klass_name(id);
            let new_name = xmlSecGetNodeContentAndTrim(node);
            if new_name.is_null() {
                errors::invalid_node_content(here, node, object, "empty");
                return -1;
            }
            let result = if (*key).value.is_null() && !(*ctx).keys_mngr.is_null() {
                let found = xmlSecKeysMngrFindKey((*ctx).keys_mngr, new_name, ctx);
                if found.is_null() && candidates_exhausted(ctx) {
                    free(new_name.cast());
                    return -1;
                }
                if found.is_null() {
                    // keyinfo.h documents this flag as stopping on a name the
                    // manager does not know; libxmlsec1 1.3.13 defines it
                    // without reading it.
                    if (*ctx).flags & FLAGS_KEYNAME_STOP_ON_UNKNOWN != 0 {
                        let shown = std::ffi::CStr::from_ptr(new_name.cast()).to_string_lossy();
                        errors::other(
                            here,
                            errors::R_KEY_NOT_FOUND,
                            object,
                            Some(&format!("name={shown}")),
                        );
                        free(new_name.cast());
                        return -1;
                    }
                    0
                } else {
                    xmlSecKeyEmpty(key);
                    let copied = xmlSecKeyCopy(key, found);
                    xmlSecKeyDestroy(found);
                    if copied < 0 {
                        errors::internal(here, object, c"xmlSecKeyCopy");
                        -1
                    } else if xmlSecKeySetName(key, new_name) < 0 {
                        errors::internal(here, object, c"xmlSecKeySetName");
                        -1
                    } else {
                        0
                    }
                }
            } else if !(*key).name.is_null() {
                if xmlStrEqual((*key).name, new_name) == 0 {
                    errors::other(
                        here,
                        R_INVALID_KEY_DATA,
                        object,
                        Some("key name is already specified"),
                    );
                    -1
                } else {
                    0
                }
            } else if xmlSecKeySetName(key, new_name) < 0 {
                errors::internal(here, object, c"xmlSecKeySetName");
                -1
            } else {
                0
            };
            free(new_name.cast());
            result
        }
    })
}

/// `xmlWrite` of the `KeyName` klass: writes the key's name into an empty
/// element; 8 when the key has no name, as libxmlsec1 returns.
pub(crate) unsafe extern "C" fn name_xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        check!(
            std::ptr::eq(id, xmlSecKeyDataNameGetKlass()),
            "xmlSecKeyDataNameXmlWrite",
            c"id == xmlSecKeyDataNameId",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecKeyDataNameXmlWrite",
            c"key != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecKeyDataNameXmlWrite",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataNameXmlWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_WRITE,
            "xmlSecKeyDataNameXmlWrite",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite",
            -1
        );
        // SAFETY: a key and a live node.
        unsafe {
            let name = (*key).name;
            if name.is_null() {
                return 8;
            }
            // libxmlsec1 treats the error result -1 as not empty too.
            if xmlSecIsEmptyNode(node) == 0 {
                return 0;
            }
            if xmlSecNodeEncodeAndSetContent(node, name) < 0 {
                errors::internal(
                    here!("xmlSecKeyDataNameXmlWrite"),
                    std::ptr::null(),
                    c"xmlSecNodeEncodeAndSetContent",
                );
                return -1;
            }
        }
        0
    })
}

// ----------------------------------------------------------------------------
// <dsig:KeyValue/>

/// `xmlRead` of the `KeyValue` klass: reads its single child through the
/// klass of that element.
pub(crate) unsafe extern "C" fn value_xml_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        check!(
            std::ptr::eq(id, xmlSecKeyDataValueGetKlass()),
            "xmlSecKeyDataValueXmlRead",
            c"id == xmlSecKeyDataValueId",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecKeyDataValueXmlRead",
            c"key != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecKeyDataValueXmlRead",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataValueXmlRead",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_READ,
            "xmlSecKeyDataValueXmlRead",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead",
            -1
        );
        let here = here!("xmlSecKeyDataValueXmlRead");
        // SAFETY: a key, a live node and a context.
        unsafe {
            let object = klass_name(id);
            let cur = xmlSecGetNextElementNode(nodes::first_child(node));
            if cur.is_null() {
                return 0;
            }
            let data_id = child_klass(ctx, cur, USAGE_KEY_VALUE_NODE_READ);
            if !data_id.is_null() {
                if xmlSecKeyDataXmlRead(data_id, key.cast(), cur.cast(), ctx.cast()) < 0 {
                    errors::internal_with(
                        here,
                        object,
                        c"xmlSecKeyDataXmlRead",
                        &format!("node={}", node_name(cur)),
                    );
                    return -1;
                }
            } else if (*ctx).flags & FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD != 0 {
                errors::unexpected_node(here, cur, object);
                return -1;
            }
            let next = xmlSecGetNextElementNode(nodes::next(cur));
            if !next.is_null() {
                errors::unexpected_node(here, next, object);
                return -1;
            }
        }
        0
    })
}

/// `xmlWrite` of the `KeyValue` klass: replaces the element's content with
/// the key value's element, written by its klass, when the key's value may
/// be written there.
pub(crate) unsafe extern "C" fn value_xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        check!(
            std::ptr::eq(id, xmlSecKeyDataValueGetKlass()),
            "xmlSecKeyDataValueXmlWrite",
            c"id == xmlSecKeyDataValueId",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecKeyDataValueXmlWrite",
            c"key != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecKeyDataValueXmlWrite",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataValueXmlWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let mode = unsafe { (*ctx).mode };
        check!(
            mode == MODE_WRITE,
            "xmlSecKeyDataValueXmlWrite",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite",
            -1
        );
        let here = here!("xmlSecKeyDataValueXmlWrite");
        // SAFETY: a key, a live node and a context.
        unsafe {
            let object = klass_name(id);
            let value = (*key).value;
            if !data_valid(value) || (*(*value).id).usage & USAGE_KEY_VALUE_NODE_WRITE == 0 {
                return 0;
            }
            // An enabled list admits the KeyValue element and, as when it is
            // read (`child_klass`), the value klass inside it: a klass the
            // list leaves out is never written, so a key requirement that
            // admits symmetric keys cannot export a disabled secret.
            // libxmlsec1 checks the KeyValue klass alone.
            let enabled = &raw mut (*ctx).enabled_key_data;
            if xmlSecPtrListGetSize(enabled) > 0
                && (xmlSecKeyDataIdListFind(enabled, id) != 1
                    || xmlSecKeyDataIdListFind(enabled, (*value).id) != 1)
            {
                return 0;
            }
            if xmlSecKeyReqMatchKey(&raw mut (*ctx).key_req, key) != 1 {
                return 0;
            }
            let klass = &*(*value).id;
            check!(
                !klass.data_node_name.is_null(),
                "xmlSecKeyDataValueXmlWrite",
                c"nodeName != NULL",
                -1
            );
            // xmlNodeSetContent(node, NULL), whose outcome libxmlsec1 ignores.
            if nodes::set_content(node, "").is_err() {
                // libxml2's setter returns nothing libxmlsec1 reads.
            }
            let cur = xmlSecAddChild(node, klass.data_node_name, klass.data_node_ns);
            if cur.is_null() {
                errors::internal_with(
                    here,
                    object,
                    c"xmlSecAddChild",
                    &format!("node={}", node_name(node)),
                );
                return -1;
            }
            if xmlSecKeyDataXmlWrite(klass, key.cast(), cur.cast(), ctx.cast()) < 0 {
                errors::internal_with(
                    here,
                    object,
                    c"xmlSecKeyDataXmlWrite",
                    &format!("node={}", node_name(cur)),
                );
                return -1;
            }
        }
        0
    })
}
