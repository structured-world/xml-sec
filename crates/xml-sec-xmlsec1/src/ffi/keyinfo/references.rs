//! The `RetrievalMethod` and `KeyInfoReference` klasses: key information at
//! another location, dereferenced through the context's transform contexts.
//!
//! Each reference resolves its URI and transforms as a `Reference` does, so
//! the library policy's URI and transform rules and budgets bound it; the
//! context's levels bound how deep references may chain.

use std::cell::Cell;
use std::ffi::{c_int, c_uint, c_void};

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsGetProp};

use super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::errors::{self, Here, check, here};
use super::super::keys::XmlSecKey;
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataBinRead, xmlSecKeyDataIdListFindByHref,
    xmlSecKeyDataIdsGetEnabled, xmlSecKeyDataKeyInfoReferenceGetKlass,
    xmlSecKeyDataRetrievalMethodGetKlass, xmlSecKeyDataXmlRead,
};
use super::super::list::xmlSecPtrListGetSize;
use super::super::strings::{
    xmlSecAttrType, xmlSecAttrURI, xmlSecDSigNs, xmlSecNodeKeyInfo, xmlSecNodeTransforms,
};
use super::super::transforms::XmlSecTransformCtx;
use super::super::transforms::ctx::{
    run_spent, seed_run, xmlSecTransformCtxExecute, xmlSecTransformCtxNodesListRead,
    xmlSecTransformCtxReset, xmlSecTransformCtxSetUri,
};
use super::super::tree::{XmlDoc, XmlNode, nodes};
use super::super::xmltree::{xmlSecCheckNodeName, xmlSecGetNextElementNode};
use super::super::{contain, free, policy};
use super::{
    FLAGS_STOP_ON_UNKNOWN_CHILD, MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, child_klass, klass_name,
    node_name, read_policy, source_refused, xmlSecKeyInfoNodeRead,
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
/// `XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL`.
const R_MAX_RETRIEVALS_LEVEL: c_int = 51;
/// `XMLSEC_ERRORS_R_MAX_KEYINFOREFERENCE_LEVEL`.
const R_MAX_KEYINFOREFERENCE_LEVEL: c_int = 53;
/// `XMLSEC_ERRORS_R_RETRIEVAL_TYPE_MISMATCH`.
const R_RETRIEVAL_TYPE_MISMATCH: c_int = 52;

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

/// The policy terms one dereference runs under: the read's revision, the
/// side of the operation the key is read for, the URI classes that side
/// admits for this kind of key reference, and what the read has spent of
/// its budgets, when the read is pinned.
struct Terms<'a> {
    pinned: &'a policy::Pinned,
    side: policy::Side,
    admitted: UriTypeSet,
    spent: Option<&'a Cell<policy::Spent>>,
}

/// The side of the operation the key read in `ctx` serves: a key read for a
/// decryption dereferences and parses its references under the decryption
/// policy, one of a signature under verification's. A read nested in an
/// `EncryptedKey` decrypts that key for the operation its outermost read
/// serves, whose policy governs its references too.
///
/// # Safety
/// `ctx` is a context whose slot is null or a pin.
pub(super) unsafe fn read_side(ctx: *const XmlSecKeyInfoCtx) -> policy::Side {
    // SAFETY: by the caller's contract.
    let (operation, served) = unsafe {
        (
            (*ctx).operation,
            policy::spent((*ctx).reserved0).and_then(|spent| spent.get().serves),
        )
    };
    served.unwrap_or_else(|| {
        super::super::transforms::ctx::operation_side(operation).unwrap_or(policy::Side::Verify)
    })
}

/// Resolves the URI of `node` with the optional `Transforms` child in
/// `transforms` of `context` and executes it on the node's document, under
/// `terms`. The URI must be of a class the terms admit: the policy's classes
/// for this kind of key reference, apart from the ones it grants a
/// signature's references. The chain charges the read's budgets, so all the
/// references of one read share them.
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
    terms: &Terms<'_>,
) -> bool {
    let Terms {
        pinned,
        side,
        admitted,
        spent,
    } = *terms;
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
        // The chain runs under the read's revision, not a later one, and on
        // the side of the operation the key is read for whatever the chain's
        // transforms say, opens the URI under the classes admitted for this
        // key reference, and charges what the read's earlier references
        // spent.
        seed_run(
            context,
            pinned,
            side,
            Some(admitted),
            spent.map_or_default(Cell::get),
        );
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
        let executed = xmlSecTransformCtxExecute(context, nodes::doc(node));
        if let Some(spent) = spent {
            spent.set(run_spent(context));
        }
        if executed < 0 {
            errors::internal(here, object, c"xmlSecTransformCtxExecute");
            return false;
        }
        if (*context).result.is_null() || xmlSecBufferGetData((*context).result).is_null() {
            errors::other(
                here,
                errors::R_INVALID_RESULT,
                object,
                Some("transform result is empty"),
            );
            return false;
        }
        true
    }
}

/// The document `context`'s result parses into, recovering as libxmlsec1
/// parses it, under the policy of the side `served`; null after a report. The parse
/// runs within what the read has left of its parse work and charges it, so
/// references reparsing the same target, siblings included, cannot parse
/// past the operation's allowance.
///
/// # Safety
/// `context` holds a result.
unsafe fn result_document(
    here: Here,
    object: *const std::ffi::c_char,
    context: *mut XmlSecTransformCtx,
    (pinned, served): (&policy::Pinned, policy::Side),
    spent: Option<&Cell<policy::Spent>>,
) -> *mut XmlDoc {
    // SAFETY: by the caller's contract.
    unsafe {
        let data = xmlSecBufferGetData((*context).result);
        if xmlSecBufferGetSize((*context).result) == 0 {
            errors::assertion(here, c"bufferSize > 0");
            return std::ptr::null_mut();
        }
        let size = xmlSecBufferGetSize((*context).result);
        if c_int::try_from(size).is_err() {
            errors::size_to_int_impossible(here, size);
            return std::ptr::null_mut();
        }
        // libxmlsec1 parses with its default options, which recover from
        // nothing, so malformed retrieved XML is refused. It parses under
        // the read's revision.
        let mut total = spent.map_or_default(Cell::get);
        let bytes = std::slice::from_raw_parts(data, size);
        let doc = policy::with_document_policy!(pinned.of(served), |document_policy| {
            crate::ffi::parser::parse_within(
                bytes,
                here,
                object,
                document_policy,
                &mut total.xml_parse,
            )
        });
        if let Some(spent) = spent {
            spent.set(total);
        }
        if doc.is_null() {
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

/// The resources whose `max_key_info_reference_depth` bounds the key
/// references read in `ctx`: the policy of the operation the key is read
/// for, as an `EncryptedKey` nested with them is bounded, so one depth
/// governs all three kinds on every path.
///
/// # Safety
/// `ctx` is a context.
unsafe fn depth_resources(
    pinned: &policy::Pinned,
    ctx: *const XmlSecKeyInfoCtx,
) -> &xml_sec::policy::ResourcePolicy {
    // SAFETY: by the caller's contract.
    pinned.of(unsafe { read_side(ctx) }).resources()
}

/// The depth of a key reference or `EncryptedKey` read now in `ctx`: the
/// levels taken by all three kinds, as the policy's
/// `max_key_info_reference_depth` bounds their nesting together, plus this
/// one. The context keeps libxmlsec1's three counters, each with its own
/// maximum.
///
/// # Safety
/// `ctx` is a context.
pub(crate) unsafe fn next_reference_depth(ctx: *const XmlSecKeyInfoCtx) -> usize {
    // SAFETY: by the caller's contract.
    let levels = unsafe {
        [
            (*ctx).cur_retrieval_method_level,
            (*ctx).cur_key_info_reference_level,
            (*ctx).cur_encrypted_key_level,
        ]
    };
    // A negative level a caller wrote into the public fields is past every
    // limit, so it cannot lift the policy's bound.
    let mut depth = 1_usize;
    for level in levels {
        // A sum past `usize` (three `c_int` levels on a 32-bit target) is
        // past every limit too.
        let Some(next) = usize::try_from(level)
            .ok()
            .and_then(|level| depth.checked_add(level))
        else {
            return usize::MAX;
        };
        depth = next;
    }
    depth
}

// ----------------------------------------------------------------------------
// <dsig:RetrievalMethod/>

/// `xmlRead` of the `RetrievalMethod` klass: reads the key data of its
/// `Type` from what its URI and transforms retrieve; for an unknown or
/// absent type, unless the context stops on it, the result is read as XML
/// whose root element names the key data.
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
                    R_MAX_RETRIEVALS_LEVEL,
                    &format!("cur={current};max={maximum}"),
                );
                return -1;
            }
            // A retrieved document may hold another key reference: the
            // library policy bounds that nesting as it bounds key references,
            // whatever level the caller set on the context.
            let Some(pinned) = read_policy(ctx, here) else {
                return -1;
            };
            let resources = depth_resources(&pinned, ctx);
            if resources
                .validate_key_info_reference_depth(next_reference_depth(ctx))
                .is_err()
            {
                errors::limit_exceeded(
                    here,
                    object,
                    "RetrievalMethod depth",
                    resources.max_key_info_reference_depth,
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
        // Lax schema validation unless the caller stops on unknown types: an
        // unknown or absent Type leaves the retrieved XML to name its data.
        if data_id.is_null() && (*ctx).flags & FLAGS_RETRMETHOD_STOP_ON_UNKNOWN_HREF != 0 {
            errors::invalid_node_attribute(
                here,
                node,
                c"Type",
                object,
                "retrieval type is unknown",
            );
            return -1;
        }
        let Some(pinned) = read_policy(ctx, here) else {
            return -1;
        };
        let context = &raw mut (*ctx).retrieval_method_ctx;
        let uri = xsGetProp(node, xmlSecAttrURI.as_ptr());
        // RetrievalMethod requires its URI (XMLDSig 1.1 section 4.5.3), and
        // libxmlsec1 reports its absence as such before any dereference.
        if uri.is_null() {
            xmlSecTransformCtxReset(context);
            errors::invalid_node_attribute(here, node, c"URI", object, "missing");
            return -1;
        }
        let side = read_side(ctx);
        let dereferenced = dereference(
            here,
            object,
            context,
            node,
            uri,
            true,
            &Terms {
                pinned: &pinned,
                side,
                admitted: pinned.of(side).retrieval_methods(),
                spent: policy::spent((*ctx).reserved0),
            },
        );
        free(uri.cast());
        if !dereferenced {
            return -1;
        }
        if data_id.is_null() || (*data_id).usage & USAGE_RETRIEVAL_METHOD_NODE_XML != 0 {
            // The retrieved element is read through `xmlSecKeyDataXmlRead`,
            // which checks its key source.
            if read_retrieved_xml(data_id, key, context, ctx, &pinned) < 0 {
                errors::internal(here, object, c"xmlSecKeyDataRetrievalMethodReadXmlResult");
                return -1;
            }
        } else if source_refused(data_id, &pinned, here) {
            return -1;
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
/// `type_id`, when known, if the context stops on a mismatch.
///
/// # Safety
/// `type_id` is null or a klass; `key` a key; `context` holds a result;
/// `ctx` a context.
unsafe fn read_retrieved_xml(
    type_id: *const XmlSecKeyDataKlass,
    key: *mut XmlSecKey,
    context: *mut XmlSecTransformCtx,
    ctx: *mut XmlSecKeyInfoCtx,
    pinned: &policy::Pinned,
) -> c_int {
    let here = here!("xmlSecKeyDataRetrievalMethodReadXmlResult");
    // SAFETY: by the caller's contract; the document is freed here.
    unsafe {
        let object = klass_name(type_id);
        let doc = result_document(
            here,
            object,
            context,
            (pinned, read_side(ctx)),
            policy::spent((*ctx).reserved0),
        );
        if doc.is_null() {
            return -1;
        }
        let root = xsDocGetRootElement(doc);
        let data_id = child_klass(ctx, root, USAGE_RETRIEVAL_METHOD_NODE_XML);
        let result = if data_id.is_null() {
            // Lax schema validation unless the caller stops on unknown nodes.
            if (*ctx).flags & FLAGS_STOP_ON_UNKNOWN_CHILD != 0 {
                errors::unexpected_node(here, root, object);
                -1
            } else {
                0
            }
        } else if !type_id.is_null()
            && !std::ptr::eq(type_id, data_id)
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
                R_RETRIEVAL_TYPE_MISMATCH,
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
                    R_MAX_KEYINFOREFERENCE_LEVEL,
                    &format!("cur={current};max={maximum}"),
                );
                return -1;
            }
            // The context's level is libxmlsec1's; the library policy bounds
            // the depth as well, whatever the caller set there.
            // One revision bounds the depth and admits the URI.
            let Some(pinned) = read_policy(ctx, here) else {
                return -1;
            };
            let resources = depth_resources(&pinned, ctx);
            if resources
                .validate_key_info_reference_depth(next_reference_depth(ctx))
                .is_err()
            {
                errors::limit_exceeded(
                    here,
                    object,
                    "KeyInfoReference depth",
                    resources.max_key_info_reference_depth,
                );
                return -1;
            }
            (*ctx).cur_key_info_reference_level += 1;
            let result = dereference_key_info(here, object, key, node, ctx, &pinned);
            (*ctx).cur_key_info_reference_level -= 1;
            result
        }
    })
}

/// The body of [`reference_xml_read`] within one reference level, under the
/// read's revision `pinned`.
///
/// # Safety
/// As for [`reference_xml_read`], after its argument checks.
unsafe fn dereference_key_info(
    here: Here,
    object: *const std::ffi::c_char,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
    pinned: &policy::Pinned,
) -> c_int {
    // SAFETY: by the caller's contract; the URI and document are freed here.
    unsafe {
        let uri = xsGetProp(node, xmlSecAttrURI.as_ptr());
        if uri.is_null() {
            errors::invalid_node_attribute(here, node, c"URI", object, "missing");
            return -1;
        }
        let context = &raw mut (*ctx).key_info_reference_ctx;
        let side = read_side(ctx);
        let dereferenced = dereference(
            here,
            object,
            context,
            node,
            uri,
            false,
            &Terms {
                pinned,
                side,
                admitted: pinned.of(side).key_info_references(),
                spent: policy::spent((*ctx).reserved0),
            },
        );
        free(uri.cast());
        if !dereferenced {
            return -1;
        }
        // XMLDSig 1.1 4.5.10: the result is a KeyInfo element or a document
        // with a KeyInfo root.
        let inner = here!("xmlSecKeyDataKeyInfoReferenceReadXmlResult");
        let doc = result_document(
            inner,
            object,
            context,
            (pinned, side),
            policy::spent((*ctx).reserved0),
        );
        let result =
            if doc.is_null() {
                -1
            } else {
                let root = xsDocGetRootElement(doc);
                let result =
                    if xmlSecCheckNodeName(root, xmlSecNodeKeyInfo.as_ptr(), xmlSecDSigNs.as_ptr())
                        == 0
                    {
                        errors::invalid_node(inner, root, "KeyInfo", object);
                        -1
                    } else if xmlSecKeyInfoNodeRead(root, key, ctx) < 0 {
                        errors::internal(inner, object, c"xmlSecKeyInfoNodeRead");
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
