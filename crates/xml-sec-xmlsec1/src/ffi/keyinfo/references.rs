//! The `RetrievalMethod` and `KeyInfoReference` klasses: key information at
//! another location, dereferenced through the context's transform contexts.
//!
//! Each reference resolves its URI and transforms as a `Reference` does, so
//! the library policy's URI and transform rules and budgets bound it; the
//! context's levels bound how deep references may chain.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsGetProp, xsReadMemory};

use super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::errors::{self, Here, check, here};
use super::super::keys::XmlSecKey;
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataBinRead, xmlSecKeyDataIdListFindByHref,
    xmlSecKeyDataIdsGetEnabled, xmlSecKeyDataKeyInfoReferenceGetKlass,
    xmlSecKeyDataRetrievalMethodGetKlass, xmlSecKeyDataXmlRead,
};
use super::super::list::xmlSecPtrListGetSize;
use super::super::parser::xmlSecParserGetDefaultOptions;
use super::super::strings::{
    xmlSecAttrType, xmlSecAttrURI, xmlSecDSigNs, xmlSecNodeKeyInfo, xmlSecNodeTransforms,
};
use super::super::transforms::XmlSecTransformCtx;
use super::super::transforms::ctx::{
    xmlSecTransformCtxExecute, xmlSecTransformCtxNodesListRead, xmlSecTransformCtxReset,
    xmlSecTransformCtxSetUri,
};
use super::super::tree::{XmlDoc, XmlNode, nodes};
use super::super::xmltree::{xmlSecCheckNodeName, xmlSecGetNextElementNode};
use super::super::{contain, free, policy};
use super::{
    FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD, MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, child_klass,
    klass_name, node_name, xmlSecKeyInfoNodeRead,
};
use xml_sec::xmldsig::UriTypeSet;

/// `XMLSEC_KEYINFO_FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF`.
const FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF: c_uint = 0x0000_0010;
/// `XMLSEC_KEYINFO_FLAGS_RETRMETHOD_STOP_ON_MISMATCH_HREF`.
const FLAGS_RETRMETHOD_STOP_ON_MISMATCH_HREF: c_uint = 0x0000_0020;
/// `xmlSecKeyDataUsageRetrievalMethodNodeXml`.
const USAGE_RETRIEVAL_METHOD_NODE_XML: c_uint = 0x00010;
/// `xmlSecKeyDataUsageRetrievalMethodNode`: the XML and binary usages.
const USAGE_RETRIEVAL_METHOD_NODE: c_uint = 0x00030;
/// `xmlSecTransformUsageDSigTransform`.
const USAGE_DSIG_TRANSFORM: c_uint = 0x0001;
/// `XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL`, also
/// `XMLSEC_ERRORS_R_MAX_KEYINFOREFERENCE_LEVEL`.
const R_MAX_LEVEL: c_int = 51;
/// `XMLSEC_ERRORS_R_MAX_RETRIEVAL_TYPE_MISMATCH`.
const R_MAX_RETRIEVAL_TYPE_MISMATCH: c_int = 52;
/// libxml2's `XML_PARSE_RECOVER`.
const XML_PARSE_RECOVER: c_int = 1 << 0;

/// Checks the arguments every reference read takes, reporting under `func`.
macro_rules! read_arguments {
    ($func:literal, $id:expr, $klass:expr, $id_expr:literal, $key:expr, $node:expr, $ctx:expr) => {
        check!(std::ptr::eq($id, $klass), $func, $id_expr, -1);
        check!(!$key.is_null(), $func, c"key != NULL", -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        let doc = nodes::doc($node);
        check!(!doc.is_null(), $func, c"node->doc != NULL", -1);
        check!(!$ctx.is_null(), $func, c"keyInfoCtx != NULL", -1);
        // SAFETY: a context.
        let mode = unsafe { (*$ctx).mode };
        check!(
            mode == MODE_READ,
            $func,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead",
            -1
        );
    };
}

/// Checks the arguments of a reference write, which writes nothing.
macro_rules! write_arguments {
    ($func:literal, $id:expr, $klass:expr, $id_expr:literal, $key:expr, $node:expr, $ctx:expr) => {
        check!(std::ptr::eq($id, $klass), $func, $id_expr, -1);
        check!(!$key.is_null(), $func, c"key != NULL", -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        check!(!$ctx.is_null(), $func, c"keyInfoCtx != NULL", -1);
        // SAFETY: a context.
        let mode = unsafe { (*$ctx.cast::<XmlSecKeyInfoCtx>()).mode };
        check!(
            mode == MODE_WRITE,
            $func,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite",
            -1
        );
    };
}

/// The enabled klasses a reference consults: the context's list when it has
/// one, the registry's enabled subset otherwise.
///
/// # Safety
/// `ctx` is a context.
unsafe fn enabled(ctx: *mut XmlSecKeyInfoCtx) -> *mut super::super::list::XmlSecPtrList {
    // SAFETY: by the caller's contract; the registry has a fixed address.
    unsafe {
        let list = &raw mut (*ctx).enabled_key_data;
        if xmlSecPtrListGetSize(list) > 0 {
            list
        } else {
            xmlSecKeyDataIdsGetEnabled()
        }
    }
}

/// Resolves the URI of `node` with the optional `Transforms` child in
/// `transforms` of `context` and executes it on the node's document. The
/// URI must be of a class `admitted` permits: the library policy's classes
/// for this kind of key reference, apart from the ones it grants a
/// signature's references.
///
/// # Safety
/// `context` is a transform context; `node` a live element of a document.
unsafe fn dereference(
    here: Here,
    object: *const std::ffi::c_char,
    context: *mut XmlSecTransformCtx,
    node: *mut XmlNode,
    uri: *const u8,
    transforms: bool,
    admitted: UriTypeSet,
) -> bool {
    let text = if uri.is_null() {
        &[][..]
    } else {
        // SAFETY: a NUL-terminated attribute value.
        unsafe { std::ffi::CStr::from_ptr(uri.cast()) }.to_bytes()
    };
    // A URI that is not UTF-8 is of no class the policy admits.
    if !std::str::from_utf8(text).is_ok_and(|text| admitted.allows(text)) {
        errors::uri_refused(here, object, text);
        return false;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        xmlSecTransformCtxReset(context);
        if xmlSecTransformCtxSetUri(context, uri, node) < 0 {
            let shown = if uri.is_null() {
                "NULL".to_owned()
            } else {
                std::ffi::CStr::from_ptr(uri.cast())
                    .to_string_lossy()
                    .into_owned()
            };
            errors::internal_with(
                here,
                object,
                c"xmlSecTransformCtxSetUri",
                &format!("uri={shown}"),
            );
            return false;
        }
        let mut cur = xmlSecGetNextElementNode(nodes::first_child(node));
        if transforms
            && !cur.is_null()
            && xmlSecCheckNodeName(cur, xmlSecNodeTransforms.as_ptr(), xmlSecDSigNs.as_ptr()) != 0
        {
            if xmlSecTransformCtxNodesListRead(context, cur, USAGE_DSIG_TRANSFORM) < 0 {
                errors::internal_with(
                    here,
                    object,
                    c"xmlSecTransformCtxNodesListRead",
                    &format!("node={}", node_name(cur)),
                );
                return false;
            }
            cur = xmlSecGetNextElementNode(nodes::next(cur));
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, object);
            return false;
        }
        if xmlSecTransformCtxExecute(context, nodes::doc(node)) < 0
            || (*context).result.is_null()
            || xmlSecBufferGetData((*context).result).is_null()
        {
            errors::internal(here, object, c"xmlSecTransformCtxExecute");
            return false;
        }
        true
    }
}

/// The document `context`'s result parses into, recovering as libxmlsec1
/// parses it; null after a report.
///
/// # Safety
/// `context` holds a result.
unsafe fn result_document(
    here: Here,
    object: *const std::ffi::c_char,
    context: *mut XmlSecTransformCtx,
) -> *mut XmlDoc {
    // SAFETY: by the caller's contract.
    unsafe {
        let data = xmlSecBufferGetData((*context).result);
        if xmlSecBufferGetSize((*context).result) == 0 {
            errors::assertion(here, c"bufferSize > 0");
            return std::ptr::null_mut();
        }
        let Ok(size) = c_int::try_from(xmlSecBufferGetSize((*context).result)) else {
            errors::size_to_int_impossible(here, xmlSecBufferGetSize((*context).result));
            return std::ptr::null_mut();
        };
        // The options are libxmlsec1's; the parser recovers from nothing, so
        // malformed retrieved XML is refused.
        let doc = xsReadMemory(
            data.cast(),
            size,
            std::ptr::null(),
            std::ptr::null(),
            xmlSecParserGetDefaultOptions() | XML_PARSE_RECOVER,
        );
        if doc.is_null() {
            errors::xml_failed(here, object, c"xmlReadMemory");
            return std::ptr::null_mut();
        }
        if xsDocGetRootElement(doc).is_null() {
            errors::xml_failed(here, object, c"xmlDocGetRootElement");
            xsFreeDoc(doc);
            return std::ptr::null_mut();
        }
        doc
    }
}

// ----------------------------------------------------------------------------
// <dsig:RetrievalMethod/>

/// `xmlRead` of the `RetrievalMethod` klass: reads the key data of its
/// `Type` from what its URI and transforms retrieve; an unknown or absent
/// type is skipped unless the context stops on it.
pub(crate) unsafe extern "C" fn retrieval_xml_read(
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
        read_arguments!(
            "xmlSecKeyDataRetrievalMethodXmlRead",
            id,
            xmlSecKeyDataRetrievalMethodGetKlass(),
            c"id == xmlSecKeyDataRetrievalMethodId",
            key,
            node,
            ctx
        );
        let here = here!("xmlSecKeyDataRetrievalMethodXmlRead");
        // SAFETY: a key, a live element of a document and a context; the
        // level taken here is returned before leaving.
        unsafe {
            let object = klass_name(id);
            let (current, maximum) = (
                (*ctx).cur_retrieval_method_level,
                (*ctx).max_retrieval_method_level,
            );
            if current >= maximum {
                errors::report(
                    here,
                    object,
                    std::ptr::null(),
                    R_MAX_LEVEL,
                    &format!("cur={current};max={maximum}"),
                );
                return -1;
            }
            (*ctx).cur_retrieval_method_level += 1;
            let result = retrieve(here, object, key, node, ctx);
            (*ctx).cur_retrieval_method_level -= 1;
            result
        }
    })
}

/// The body of [`retrieval_xml_read`] within one retrieval level.
///
/// # Safety
/// As for [`retrieval_xml_read`], after its argument checks.
unsafe fn retrieve(
    here: Here,
    object: *const std::ffi::c_char,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> c_int {
    // SAFETY: by the caller's contract; attribute values are freed here.
    unsafe {
        let retrieval_type = xsGetProp(node, xmlSecAttrType.as_ptr());
        let data_id = if retrieval_type.is_null() {
            std::ptr::null()
        } else {
            xmlSecKeyDataIdListFindByHref(enabled(ctx), retrieval_type, USAGE_RETRIEVAL_METHOD_NODE)
        };
        free(retrieval_type.cast());
        // Lax schema validation unless the caller stops on unknown types. An
        // absent Type names no klass either, so the retrieval is skipped,
        // as libxmlsec1 1.3.13's xmlSecKeyDataRetrievalMethodXmlRead does:
        // it never guesses the result's type from the retrieved XML.
        if data_id.is_null() {
            if (*ctx).flags & FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF != 0 {
                errors::invalid_node_attribute(
                    here,
                    node,
                    c"Type",
                    object,
                    "retrieval type is unknown",
                );
                return -1;
            }
            return 0;
        }
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        let context = &raw mut (*ctx).retrieval_method_ctx;
        let uri = xsGetProp(node, xmlSecAttrURI.as_ptr());
        let dereferenced = dereference(
            here,
            object,
            context,
            node,
            uri,
            true,
            policy.uris.retrieval_methods,
        );
        free(uri.cast());
        if !dereferenced {
            return -1;
        }
        if (*data_id).usage & USAGE_RETRIEVAL_METHOD_NODE_XML != 0 {
            if read_retrieved_xml(data_id, key, context, ctx) < 0 {
                errors::internal(here, object, c"xmlSecKeyDataRetrievalMethodReadXmlResult");
                return -1;
            }
        } else if xmlSecKeyDataBinRead(
            data_id,
            key.cast(),
            xmlSecBufferGetData((*context).result),
            xmlSecBufferGetSize((*context).result),
            ctx.cast(),
        ) < 0
        {
            errors::internal(here, object, c"xmlSecKeyDataBinRead");
            return -1;
        }
        0
    }
}

/// Reads the key data the root of the retrieved XML holds, which must be of
/// `type_id` when the context stops on a mismatch.
///
/// # Safety
/// `type_id` is a klass; `key` a key; `context` holds a result; `ctx` a
/// context.
unsafe fn read_retrieved_xml(
    type_id: *const XmlSecKeyDataKlass,
    key: *mut XmlSecKey,
    context: *mut XmlSecTransformCtx,
    ctx: *mut XmlSecKeyInfoCtx,
) -> c_int {
    let here = here!("xmlSecKeyDataRetrievalMethodReadXmlResult");
    // SAFETY: by the caller's contract; the document is freed here.
    unsafe {
        let object = klass_name(type_id);
        let doc = result_document(here, object, context);
        if doc.is_null() {
            return -1;
        }
        let root = xsDocGetRootElement(doc);
        let data_id = child_klass(ctx, root, USAGE_RETRIEVAL_METHOD_NODE_XML);
        let result = if data_id.is_null() {
            // Lax schema validation unless the caller stops on unknown nodes.
            if (*ctx).flags & FLAGS_KEYVALUE_STOP_ON_UNKNOWN_CHILD != 0 {
                errors::unexpected_node(here, root, object);
                -1
            } else {
                0
            }
        } else if !std::ptr::eq(type_id, data_id)
            && (*ctx).flags & FLAGS_RETRMETHOD_STOP_ON_MISMATCH_HREF != 0
        {
            let type_name = if object.is_null() {
                "NULL".to_owned()
            } else {
                std::ffi::CStr::from_ptr(object)
                    .to_string_lossy()
                    .into_owned()
            };
            errors::report(
                here,
                klass_name(data_id),
                std::ptr::null(),
                R_MAX_RETRIEVAL_TYPE_MISMATCH,
                &format!("typeId={type_name}"),
            );
            -1
        } else if xmlSecKeyDataXmlRead(data_id, key.cast(), root.cast(), ctx.cast()) < 0 {
            errors::internal_with(
                here,
                object,
                c"xmlSecKeyDataXmlRead",
                &format!("node={}", node_name(root)),
            );
            -1
        } else {
            0
        };
        xsFreeDoc(doc);
        result
    }
}

/// `xmlWrite` of the `RetrievalMethod` klass: writes nothing.
pub(crate) unsafe extern "C" fn retrieval_xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    contain(-1, || {
        write_arguments!(
            "xmlSecKeyDataRetrievalMethodXmlWrite",
            id,
            xmlSecKeyDataRetrievalMethodGetKlass(),
            c"id == xmlSecKeyDataRetrievalMethodId",
            key,
            node,
            ctx
        );
        0
    })
}

// ----------------------------------------------------------------------------
// <dsig11:KeyInfoReference/>

/// `xmlRead` of the `KeyInfoReference` klass: reads the `KeyInfo` element
/// its required URI dereferences to.
pub(crate) unsafe extern "C" fn reference_xml_read(
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
        read_arguments!(
            "xmlSecKeyDataKeyInfoReferenceXmlRead",
            id,
            xmlSecKeyDataKeyInfoReferenceGetKlass(),
            c"id == xmlSecKeyDataKeyInfoReferenceId",
            key,
            node,
            ctx
        );
        let here = here!("xmlSecKeyDataKeyInfoReferenceXmlRead");
        // SAFETY: a key, a live element of a document and a context; the
        // level taken here is returned before leaving.
        unsafe {
            let object = klass_name(id);
            let (current, maximum) = (
                (*ctx).cur_key_info_reference_level,
                (*ctx).max_key_info_reference_level,
            );
            if current >= maximum {
                errors::report(
                    here,
                    object,
                    std::ptr::null(),
                    R_MAX_LEVEL,
                    &format!("cur={current};max={maximum}"),
                );
                return -1;
            }
            // The context's level is libxmlsec1's; the library policy bounds
            // the depth as well, whatever the caller set there.
            let Some(policy) = policy::verification_at(here) else {
                return -1;
            };
            let depth = usize::try_from(current).map_or(usize::MAX, |depth| depth + 1);
            if policy
                .resources
                .validate_key_info_reference_depth(depth)
                .is_err()
            {
                errors::limit_exceeded(
                    here,
                    object,
                    "KeyInfoReference depth",
                    policy.resources.max_key_info_reference_depth,
                );
                return -1;
            }
            (*ctx).cur_key_info_reference_level += 1;
            let result = dereference_key_info(here, object, key, node, ctx);
            (*ctx).cur_key_info_reference_level -= 1;
            result
        }
    })
}

/// The body of [`reference_xml_read`] within one reference level.
///
/// # Safety
/// As for [`reference_xml_read`], after its argument checks.
unsafe fn dereference_key_info(
    here: Here,
    object: *const std::ffi::c_char,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> c_int {
    // SAFETY: by the caller's contract; the URI and document are freed here.
    unsafe {
        let uri = xsGetProp(node, xmlSecAttrURI.as_ptr());
        if uri.is_null() {
            errors::invalid_node_attribute(here, node, c"URI", object, "empty");
            return -1;
        }
        let Some(policy) = policy::verification_at(here) else {
            free(uri.cast());
            return -1;
        };
        let context = &raw mut (*ctx).key_info_reference_ctx;
        let dereferenced = dereference(
            here,
            object,
            context,
            node,
            uri,
            false,
            policy.uris.key_info_references,
        );
        free(uri.cast());
        if !dereferenced {
            return -1;
        }
        // XMLDSig 1.1 4.5.10: the result is a KeyInfo element or a document
        // with a KeyInfo root. The unknown type is reported as a null object.
        let inner = here!("xmlSecKeyDataKeyInfoReferenceReadXmlResult");
        let doc = result_document(inner, std::ptr::null(), context);
        let result =
            if doc.is_null() {
                -1
            } else {
                let root = xsDocGetRootElement(doc);
                let result =
                    if xmlSecCheckNodeName(root, xmlSecNodeKeyInfo.as_ptr(), xmlSecDSigNs.as_ptr())
                        == 0
                    {
                        errors::invalid_node(inner, root, "KeyInfo", std::ptr::null());
                        -1
                    } else if xmlSecKeyInfoNodeRead(root, key, ctx) < 0 {
                        errors::internal(inner, std::ptr::null(), c"xmlSecKeyInfoNodeRead");
                        -1
                    } else {
                        0
                    };
                xsFreeDoc(doc);
                result
            };
        if result < 0 {
            errors::internal(here, object, c"xmlSecKeyDataKeyInfoReferenceReadXmlResult");
        }
        result
    }
}

/// `xmlWrite` of the `KeyInfoReference` klass: writes nothing.
pub(crate) unsafe extern "C" fn reference_xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    contain(-1, || {
        write_arguments!(
            "xmlSecKeyDataKeyInfoReferenceXmlWrite",
            id,
            xmlSecKeyDataKeyInfoReferenceGetKlass(),
            c"id == xmlSecKeyDataKeyInfoReferenceId",
            key,
            node,
            ctx
        );
        0
    })
}
