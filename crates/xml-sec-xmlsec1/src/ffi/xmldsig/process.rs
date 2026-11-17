//! Signing and verification with a signature context.
//!
//! The `Signature` element is read as libxmlsec1 reads it: its methods into
//! the context's transform context and each `Reference` into a reference
//! context, through the registered klasses, the context's enabled
//! transforms and URIs. The key comes from the read `KeyInfo` context. The
//! core then signs or verifies exactly that element on the caller's tree
//! under the library policy, and its outcome becomes the contexts' status,
//! failure reason, reference statuses and kept buffers.

use std::ffi::{c_int, c_void};
use std::sync::Arc;

use xml_sec::XmlDocument;
use xml_sec::document::external::ExternalNode;
use xml_sec::policy::{
    EcdsaSignatureValueEncoding, EmptyDigestInput, ManifestProcessing, SameDocumentIdSemantics,
    SigningPolicy, VerificationPolicy,
};
use xml_sec::xmldsig::{
    DsigStatus, FailureReason, HmacSigningKey, HmacVerificationKey, ReferenceResult, SignContext,
    SignatureAlgorithm, SignatureTemplateSelection, SigningKey, VerificationKey, VerifyContext,
    VerifyResult, VerifyingKey,
};
use xml_sec_libxml2::ffi::tree::{xsNodeGetChildren, xsNodeGetDoc};

use super::super::asymkeys::material_of;
use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferCreate, xmlSecBufferDestroy, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferSetData,
};
use super::super::errors::{self, here};
use super::super::keyinfo::xmlSecKeyInfoNodeWrite;
use super::super::keys::{XmlSecKey, xmlSecKeyGetValue, xmlSecKeyMatch};
use super::super::keysdata::xmlSecKeyDataBinaryValueGetBuffer;
use super::super::list::{xmlSecPtrListAdd, xmlSecPtrListGetItem, xmlSecPtrListGetSize};
use super::super::policy::Pinned;
use super::super::strings;
use super::super::transforms::builtin::{
    xmlSecTransformBase64GetKlass, xmlSecTransformMemBufGetBuffer, xmlSecTransformMemBufGetKlass,
};
use super::super::transforms::ctx::{
    xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxExecute, xmlSecTransformCtxNodeRead,
    xmlSecTransformCtxNodesListRead, xmlSecTransformCtxSetUri,
};
use super::super::transforms::signatures::signing_key;
use super::super::transforms::{
    OPERATION_ENCODE, OPERATION_SIGN, OPERATION_VERIFY, STATUS_OK, USAGE_C14N_METHOD,
    USAGE_DIGEST_METHOD, USAGE_DSIG_TRANSFORM, USAGE_SIGNATURE_METHOD, xmlSecTransformSetKey,
    xmlSecTransformSetKeyReq, xmlSecTransformVerifyNodeContent,
};
use super::super::tree::{XmlNode, give, nodes};
use super::super::xmltree::{xmlSecAddIDs, xmlSecCheckNodeName, xmlSecGetNextElementNode};
use super::{
    FAILURE_KEY_NOT_FOUND, FAILURE_REFERENCE, FAILURE_SIGNATURE, FAILURE_UNKNOWN,
    FLAGS_ALLOW_EMPTY_INPUT_DSIG, FLAGS_IGNORE_MANIFESTS, FLAGS_STORE_MANIFEST_REFERENCES,
    FLAGS_STORE_SIGNATURE, FLAGS_STORE_SIGNEDINFO_REFERENCES, FLAGS_USE_ASN1_SIGNATURE_VALUES,
    FLAGS_USE_VISA3D_HACK, ORIGIN_MANIFEST, ORIGIN_SIGNED_INFO, STATUS_INVALID, STATUS_SUCCEEDED,
    STATUS_UNKNOWN, TRANSFORMCTX_ASN1_SIGNATURE_VALUES, XmlSecDSigCtx, XmlSecDSigReferenceCtx,
    xmlSecDSigReferenceCtxCreate, xmlSecDSigReferenceCtxDestroy,
};

/// The element names of a signature, in libxmlsec1's strings.
macro_rules! name {
    ($name:ident) => {
        strings::$name.as_ptr()
    };
}

/// Whether `node` is the element `name` of the `XMLDSig` namespace.
///
/// # Safety
/// `node` is null or a live node.
unsafe fn is(node: *mut XmlNode, name: *const u8) -> bool {
    // SAFETY: by the caller's contract.
    !node.is_null() && unsafe { xmlSecCheckNodeName(node, name, name!(xmlSecDSigNs)) } != 0
}

/// The first element child of `node`.
///
/// # Safety
/// `node` is a live node.
unsafe fn first_element(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe { xmlSecGetNextElementNode(xsNodeGetChildren(node)) }
}

/// The next element sibling of `node`.
///
/// # Safety
/// `node` is a live node.
unsafe fn next_element(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe { xmlSecGetNextElementNode(nodes::next(node)) }
}

/// The C copy of the attribute `name` of `node`, null when absent.
fn attribute(node: *mut XmlNode, name: &str) -> *mut u8 {
    give(nodes::property(node, name).as_deref())
}

/// Frees the result buffer the context owns, if any.
pub(super) fn release(ctx: &mut XmlSecDSigCtx) {
    let owned = ctx.reserved0.cast::<XmlSecBuffer>();
    if !owned.is_null() {
        // SAFETY: the context's own buffer, created by `keep_result`.
        unsafe { xmlSecBufferDestroy(owned) };
        ctx.reserved0 = std::ptr::null_mut();
    }
}

/// `xmlSecDSigCtxSign` past its preconditions.
///
/// # Safety
/// `tmpl` is a live node.
pub(super) unsafe fn sign(ctx: &mut XmlSecDSigCtx, tmpl: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxSign");
    begin(ctx, OPERATION_SIGN, tmpl);
    // SAFETY: a live node.
    if unsafe { process_signature_node(ctx, tmpl) } < 0 {
        errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessSignatureNode");
        return -1;
    }
    if ctx.status != STATUS_UNKNOWN {
        return 0;
    }
    if ctx.result.is_null() {
        errors::other(here, errors::R_INVALID_RESULT, std::ptr::null(), None);
        return -1;
    }
    ctx.status = STATUS_SUCCEEDED;
    0
}

/// `xmlSecDSigCtxVerify` past its preconditions.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn verify(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxVerify");
    begin(ctx, OPERATION_VERIFY, node);
    // SAFETY: a live node.
    if unsafe { process_signature_node(ctx, node) } < 0 {
        errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessSignatureNode");
        return -1;
    }
    0
}

/// The state every operation starts from, with the document's `Id`
/// attributes registered as IDs, as libxmlsec1 registers them.
fn begin(ctx: &mut XmlSecDSigCtx, operation: c_int, node: *mut XmlNode) {
    ctx.operation = operation;
    ctx.status = STATUS_UNKNOWN;
    ctx.failure_reason = FAILURE_UNKNOWN;
    ctx.key_info_read_ctx.operation = operation;
    ctx.key_info_write_ctx.operation = operation;
    let ids = [name!(xmlSecAttrId), std::ptr::null()];
    // SAFETY: a live node of its document and a null-terminated list.
    unsafe { xmlSecAddIDs(xsNodeGetDoc(node), node, ids.as_ptr()) };
}

/// Marks the operation failed for `reason`, keeping a reason already set.
fn mark_failed(ctx: &mut XmlSecDSigCtx, reason: c_int) {
    ctx.status = STATUS_INVALID;
    if ctx.failure_reason == FAILURE_UNKNOWN {
        ctx.failure_reason = reason;
    }
}

/// libxmlsec1's `xmlSecDSigCtxProcessSignatureNode`: reads the signature,
/// takes its key and runs the core operation on it.
///
/// # Safety
/// `node` is a live node.
unsafe fn process_signature_node(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxProcessSignatureNode");
    for (holds, expression) in [
        (
            ctx.status == STATUS_UNKNOWN,
            c"dsigCtx->status == xmlSecDSigStatusUnknown",
        ),
        (
            ctx.sign_value_node.is_null(),
            c"dsigCtx->signValueNode == NULL",
        ),
        (ctx.sign_method.is_null(), c"dsigCtx->signMethod == NULL"),
        (ctx.c14n_method.is_null(), c"dsigCtx->c14nMethod == NULL"),
        (ctx.id.is_null(), c"dsigCtx->id == NULL"),
    ] {
        if !holds {
            errors::assertion(here, expression);
            return -1;
        }
    }
    // SAFETY: live nodes of the caller's tree throughout.
    unsafe {
        if !is(node, name!(xmlSecNodeSignature)) {
            errors::invalid_node(here, node, "Signature", std::ptr::null());
            return -1;
        }
        if ctx.flags & FLAGS_USE_ASN1_SIGNATURE_VALUES != 0 {
            ctx.transform_ctx.flags |= TRANSFORMCTX_ASN1_SIGNATURE_VALUES;
        }
        if ctx.flags & FLAGS_ALLOW_EMPTY_INPUT_DSIG != 0 {
            ctx.transform_ctx.flags |= super::super::transforms::ctx::FLAGS_ALLOW_EMPTY_INPUT;
        }
        ctx.id = attribute(node, "Id");

        let signed_info = first_element(node);
        if !is(signed_info, name!(xmlSecNodeSignedInfo)) {
            errors::invalid_node(here, signed_info, "SignedInfo", std::ptr::null());
            return -1;
        }
        let mut cur = next_element(signed_info);
        if !is(cur, name!(xmlSecNodeSignatureValue)) {
            errors::invalid_node(here, cur, "SignatureValue", std::ptr::null());
            return -1;
        }
        ctx.sign_value_node = cur;
        cur = next_element(cur);
        let key_info = if is(cur, name!(xmlSecNodeKeyInfo)) {
            let found = cur;
            cur = next_element(cur);
            found
        } else {
            std::ptr::null_mut()
        };
        while is(cur, name!(xmlSecNodeObject)) {
            if ctx.flags & FLAGS_IGNORE_MANIFESTS == 0 && read_object(ctx, cur) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessObjectNode");
                return -1;
            }
            cur = next_element(cur);
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }

        let Some(first_reference) = read_signed_info(ctx, signed_info) else {
            errors::internal(
                here,
                std::ptr::null(),
                c"xmlSecDSigCtxProcessSignedInfoNode",
            );
            return -1;
        };
        if read_key(ctx, key_info) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessKeyInfoNode");
            return -1;
        }
        if read_references(ctx, first_reference) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessReferences");
            return -1;
        }
        if ctx.operation == OPERATION_SIGN {
            run_signing(ctx, node)
        } else {
            run_verification(ctx, node)
        }
    }
}

/// libxmlsec1's `xmlSecDSigCtxProcessSignedInfoNode`: the canonicalization
/// and signature methods, the kept pre-signature buffer and the first
/// `Reference`.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_signed_info(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> Option<*mut XmlNode> {
    let here = here!("xmlSecDSigCtxProcessSignedInfoNode");
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: live nodes and the context's own transform context.
    unsafe {
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeCanonicalizationMethod)) {
            ctx.c14n_method = xmlSecTransformCtxNodeRead(transforms, cur, USAGE_C14N_METHOD);
            if ctx.c14n_method.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxNodeRead",
                    "node=CanonicalizationMethod",
                );
                return None;
            }
            cur = next_element(cur);
        } else if !ctx.def_c14n_method_id.is_null() {
            ctx.c14n_method = xmlSecTransformCtxCreateAndAppend(transforms, ctx.def_c14n_method_id);
            if ctx.c14n_method.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return None;
            }
        } else {
            errors::invalid_node(here, cur, "CanonicalizationMethod", std::ptr::null());
            return None;
        }
        if ctx.flags & FLAGS_STORE_SIGNATURE != 0 {
            ctx.pre_sign_mem_buf_method =
                xmlSecTransformCtxCreateAndAppend(transforms, xmlSecTransformMemBufGetKlass());
            if ctx.pre_sign_mem_buf_method.is_null() {
                errors::internal(
                    here,
                    c"membuf-transform".as_ptr(),
                    c"xmlSecTransformCtxCreateAndAppend",
                );
                return None;
            }
        }
        if is(cur, name!(xmlSecNodeSignatureMethod)) {
            ctx.sign_method = xmlSecTransformCtxNodeRead(transforms, cur, USAGE_SIGNATURE_METHOD);
            if ctx.sign_method.is_null() {
                errors::internal(
                    here,
                    c"SignatureMethod".as_ptr(),
                    c"xmlSecTransformCtxNodeRead",
                );
                return None;
            }
            cur = next_element(cur);
        } else if !ctx.def_sign_method_id.is_null() {
            ctx.sign_method = xmlSecTransformCtxCreateAndAppend(transforms, ctx.def_sign_method_id);
            if ctx.sign_method.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return None;
            }
        } else {
            errors::invalid_node(here, cur, "SignatureMethod", std::ptr::null());
            return None;
        }
        (*ctx.sign_method).operation = ctx.operation;
        let first = cur;
        let mut count = 0_usize;
        while is(cur, name!(xmlSecNodeReference)) {
            count += 1;
            cur = next_element(cur);
        }
        if count == 0 {
            errors::other(here, errors::R_DSIG_NO_REFERENCES, std::ptr::null(), None);
            return None;
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return None;
        }
        Some(first)
    }
}

/// libxmlsec1's `xmlSecDSigCtxProcessKeyInfoNode`: the key the signature
/// method requires, set on it, and written to `KeyInfo` when signing.
///
/// # Safety
/// `node` is null or a live node.
unsafe fn read_key(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxProcessKeyInfoNode");
    let method = ctx.sign_method;
    // SAFETY: the context's method, its read context and the caller's node.
    unsafe {
        let name = (*(*method).id).name.cast();
        if xmlSecTransformSetKeyReq(method, &raw mut ctx.key_info_read_ctx.key_req) < 0 {
            errors::internal(here, name, c"xmlSecTransformSetKeyReq");
            return -1;
        }
        let read = &raw mut ctx.key_info_read_ctx;
        if ctx.sign_key.is_null() {
            let mngr = ctx.key_info_read_ctx.keys_mngr;
            if let Some(get_key) = mngr.as_ref().and_then(|mngr| mngr.get_key) {
                ctx.sign_key = get_key(node, read);
            }
        }
        if ctx.sign_key.is_null()
            || xmlSecKeyMatch(ctx.sign_key, std::ptr::null(), &raw mut (*read).key_req) == 0
        {
            errors::other(here, errors::R_KEY_NOT_FOUND, std::ptr::null(), None);
            mark_failed(ctx, FAILURE_KEY_NOT_FOUND);
            return -1;
        }
        if xmlSecTransformSetKey(method, ctx.sign_key.cast()) < 0 {
            errors::internal(here, name, c"xmlSecTransformSetKey");
            return -1;
        }
        if !node.is_null()
            && ctx.operation == OPERATION_SIGN
            && xmlSecKeyInfoNodeWrite(node, ctx.sign_key, &raw mut ctx.key_info_write_ctx) < 0
        {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoNodeWrite");
            return -1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecDSigCtxProcessObjectNode`: the `Manifest` children of
/// an `Object`.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_object(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxProcessObjectNode");
    // SAFETY: live nodes.
    unsafe {
        let mut cur = first_element(node);
        while !cur.is_null() {
            if is(cur, name!(xmlSecNodeManifest)) && read_manifest(ctx, cur) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxProcessManifestNode");
                return -1;
            }
            cur = next_element(cur);
        }
    }
    0
}

/// libxmlsec1's `xmlSecDSigCtxProcessManifestNode`: one reference context
/// per `Reference` of a `Manifest`.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_manifest(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxProcessManifestNode");
    let list = &raw mut ctx.manifest_references;
    // SAFETY: live nodes and the context's own list.
    unsafe {
        let mut cur = first_element(node);
        let mut count = 0_usize;
        while is(cur, name!(xmlSecNodeReference)) {
            if add_reference(ctx, list, ORIGIN_MANIFEST, cur).is_null() {
                return -1;
            }
            count += 1;
            cur = next_element(cur);
        }
        if count == 0 {
            errors::other(here, errors::R_DSIG_NO_REFERENCES, std::ptr::null(), None);
            return -1;
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecDSigCtxProcessReferences`, reading each `Reference`
/// of `SignedInfo` into its context.
///
/// # Safety
/// `first` is a live node.
unsafe fn read_references(ctx: &mut XmlSecDSigCtx, first: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxProcessReferences");
    let list = &raw mut ctx.signed_info_references;
    // SAFETY: the context's own list, empty before.
    if unsafe { xmlSecPtrListGetSize(list) } != 0 {
        errors::assertion(
            here,
            c"xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) == 0",
        );
        return -1;
    }
    let mut cur = first;
    while !cur.is_null() {
        // SAFETY: live nodes.
        unsafe {
            if !is(cur, name!(xmlSecNodeReference)) {
                errors::invalid_node(here, cur, "Reference", std::ptr::null());
                return -1;
            }
            if add_reference(ctx, list, ORIGIN_SIGNED_INFO, cur).is_null() {
                return -1;
            }
            cur = next_element(cur);
        }
    }
    0
}

/// A new reference context of `origin` for the `Reference` element `node`,
/// added to `list` and read; null after a report.
///
/// # Safety
/// `list` is one of the context's reference lists; `node` a live node.
unsafe fn add_reference(
    ctx: &mut XmlSecDSigCtx,
    list: *mut super::XmlSecPtrList,
    origin: c_int,
    node: *mut XmlNode,
) -> *mut XmlSecDSigReferenceCtx {
    let here = here!("xmlSecDSigCtxProcessReferences");
    // SAFETY: the context outlives its references; the list owns them.
    unsafe {
        let reference = xmlSecDSigReferenceCtxCreate(ctx, origin);
        if reference.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecDSigReferenceCtxCreate");
            return reference;
        }
        if xmlSecPtrListAdd(list, reference.cast()) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecPtrListAdd");
            xmlSecDSigReferenceCtxDestroy(reference);
            return std::ptr::null_mut();
        }
        if read_reference(&mut *reference, node).is_none() {
            errors::internal(
                here,
                c"Reference".as_ptr(),
                c"xmlSecDSigReferenceCtxProcessNode",
            );
            return std::ptr::null_mut();
        }
        reference
    }
}

/// What reading a `Reference` leaves to run: its `DigestValue` element.
struct ReadReference {
    digest_value: *mut XmlNode,
}

/// The reading half of libxmlsec1's `xmlSecDSigReferenceCtxProcessNode`:
/// the attributes, the start URI, the transforms, the kept pre-digest
/// buffer and the digest method. The `Reference` element is kept in the
/// context's `reserved0` to match the core's result to it.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_reference(
    reference: &mut XmlSecDSigReferenceCtx,
    node: *mut XmlNode,
) -> Option<ReadReference> {
    let here = here!("xmlSecDSigReferenceCtxProcessNode");
    // SAFETY: the reference's parent outlives it.
    let Some(parent) = (unsafe { reference.dsig_ctx.as_ref() }) else {
        errors::assertion(here, c"dsigRefCtx->dsigCtx != NULL");
        return None;
    };
    if !reference.digest_method.is_null() || !reference.pre_digest_mem_buf_method.is_null() {
        errors::assertion(here, c"dsigRefCtx->digestMethod == NULL");
        return None;
    }
    let (flags, operation, default_digest) =
        (parent.flags, parent.operation, parent.def_digest_method_id);
    let transforms = &raw mut reference.transform_ctx;
    reference.reserved0 = node.cast::<c_void>();
    reference.uri = attribute(node, "URI");
    reference.id = attribute(node, "Id");
    reference.type_ = attribute(node, "Type");
    // SAFETY: live nodes and the reference's own transform context.
    unsafe {
        if xmlSecTransformCtxSetUri(transforms, reference.uri, node) < 0 {
            let uri = super::super::tree::c_text(reference.uri).unwrap_or("NULL");
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxSetUri",
                &format!("uri={uri}"),
            );
            return None;
        }
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeTransforms)) {
            if xmlSecTransformCtxNodesListRead(transforms, cur, USAGE_DSIG_TRANSFORM) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxNodesListRead",
                    "node=Transforms",
                );
                return None;
            }
            cur = next_element(cur);
        }
        let store = match reference.origin {
            ORIGIN_SIGNED_INFO => flags & FLAGS_STORE_SIGNEDINFO_REFERENCES != 0,
            _ => flags & FLAGS_STORE_MANIFEST_REFERENCES != 0,
        };
        if store {
            reference.pre_digest_mem_buf_method =
                xmlSecTransformCtxCreateAndAppend(transforms, xmlSecTransformMemBufGetKlass());
            if reference.pre_digest_mem_buf_method.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCreateAndAppend(xmlSecTransformMemBufId)",
                );
                return None;
            }
        }
        if is(cur, name!(xmlSecNodeDigestMethod)) {
            reference.digest_method =
                xmlSecTransformCtxNodeRead(transforms, cur, USAGE_DIGEST_METHOD);
            if reference.digest_method.is_null() {
                errors::internal(
                    here,
                    c"DigestMethod".as_ptr(),
                    c"xmlSecTransformCtxNodeRead",
                );
                return None;
            }
            cur = next_element(cur);
        } else if !default_digest.is_null() {
            reference.digest_method = xmlSecTransformCtxCreateAndAppend(transforms, default_digest);
            if reference.digest_method.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return None;
            }
        } else {
            errors::invalid_node(here, cur, "DigestMethod", std::ptr::null());
            return None;
        }
        (*reference.digest_method).operation = operation;
        if !is(cur, name!(xmlSecNodeDigestValue)) {
            errors::invalid_node(here, cur, "DigestValue", std::ptr::null());
            return None;
        }
        let digest_value = cur;
        cur = next_element(cur);
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return None;
        }
        Some(ReadReference { digest_value })
    }
}

/// `xmlSecDSigReferenceCtxProcessNode` called by an application on its own:
/// the reference is read and its chain run through the transform context,
/// as a standalone chain runs, then its digest written or checked.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn reference_node(
    reference: &mut XmlSecDSigReferenceCtx,
    node: *mut XmlNode,
) -> c_int {
    let here = here!("xmlSecDSigReferenceCtxProcessNode");
    // SAFETY: a live node.
    let Some(read) = (unsafe { read_reference(reference, node) }) else {
        return -1;
    };
    // SAFETY: an initialized parent, checked by the read.
    let operation = unsafe { (*reference.dsig_ctx).operation };
    let transforms = &raw mut reference.transform_ctx;
    // SAFETY: the reference's own transform context and live nodes.
    unsafe {
        if operation == OPERATION_SIGN {
            let encode =
                xmlSecTransformCtxCreateAndAppend(transforms, xmlSecTransformBase64GetKlass());
            if encode.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return -1;
            }
            (*encode).operation = OPERATION_ENCODE;
        }
        if xmlSecTransformCtxExecute(transforms, xsNodeGetDoc(node)) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
            return -1;
        }
        reference.result = reference.transform_ctx.result;
        if operation == OPERATION_SIGN {
            let Some(value) = buffer_text(reference.result) else {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
                return -1;
            };
            if nodes::set_content(read.digest_value, &value).is_err() {
                errors::xml_failed(here, std::ptr::null(), c"xmlNodeSetContentLen");
                return -1;
            }
            reference.status = STATUS_SUCCEEDED;
        } else {
            if xmlSecTransformVerifyNodeContent(
                reference.digest_method,
                read.digest_value,
                transforms,
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformVerifyNodeContent");
                return -1;
            }
            reference.status = if (*reference.digest_method).status == STATUS_OK {
                STATUS_SUCCEEDED
            } else {
                STATUS_INVALID
            };
        }
    }
    0
}

/// The text of `buffer`, `None` for a null or empty one.
///
/// # Safety
/// `buffer` is null or a buffer.
unsafe fn buffer_text(buffer: *mut XmlSecBuffer) -> Option<String> {
    // SAFETY: by the caller's contract.
    unsafe {
        if buffer.is_null() || xmlSecBufferGetData(buffer).is_null() {
            return None;
        }
        let bytes =
            std::slice::from_raw_parts(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer));
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// The algorithm of the context's signature method.
///
/// # Safety
/// The method is set.
unsafe fn algorithm(ctx: &XmlSecDSigCtx) -> Option<SignatureAlgorithm> {
    // SAFETY: a set method's klass outlives it.
    let href = unsafe { super::super::tree::c_text((*(*ctx.sign_method).id).href) }?;
    SignatureAlgorithm::from_uri(href)
}

/// The secret of an HMAC key: its binary value.
///
/// # Safety
/// `key` is a key.
unsafe fn secret(key: *mut XmlSecKey) -> Option<Vec<u8>> {
    // SAFETY: by the caller's contract; a buffer of a binary value.
    unsafe {
        let buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
        if buffer.is_null() || xmlSecBufferGetData(buffer).is_null() {
            return None;
        }
        Some(
            std::slice::from_raw_parts(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer))
                .to_vec(),
        )
    }
}

/// The verification key of `key` for `algorithm`.
///
/// # Safety
/// `key` is a key that matched the method's requirements.
unsafe fn verifying_key(
    key: *mut XmlSecKey,
    algorithm: SignatureAlgorithm,
) -> Option<Box<dyn VerifyingKey>> {
    if algorithm.hmac_output_bits().is_some() {
        // SAFETY: by the caller's contract.
        let secret = unsafe { secret(key) }?;
        return HmacVerificationKey::new(secret)
            .ok()
            .map(|key| Box::new(key) as Box<dyn VerifyingKey>);
    }
    // SAFETY: by the caller's contract.
    let material = unsafe { material_of(xmlSecKeyGetValue(key)) }?;
    let spki = material.value.to_spki_der().ok()?;
    Some(Box::new(VerificationKey {
        algorithm,
        public_key_bytes: spki,
        certificate_der: None,
        name: None,
    }))
}

/// The signing key of `key` for `algorithm` under `policy`.
///
/// # Safety
/// `key` is a key that matched the method's requirements.
unsafe fn signer(
    key: *mut XmlSecKey,
    algorithm: SignatureAlgorithm,
    policy: &SigningPolicy,
) -> Result<Box<dyn SigningKey + Send + Sync>, String> {
    if algorithm.hmac_output_bits().is_some() {
        // SAFETY: by the caller's contract.
        let secret = unsafe { secret(key) }.ok_or("the key holds no secret")?;
        return HmacSigningKey::new(secret)
            .map(|key| Box::new(key) as Box<dyn SigningKey + Send + Sync>)
            .map_err(|error| error.to_string());
    }
    // SAFETY: by the caller's contract.
    let material =
        unsafe { material_of(xmlSecKeyGetValue(key)) }.ok_or("the key holds no value")?;
    let private = material
        .private
        .as_ref()
        .ok_or("the key holds no private key")?;
    signing_key(policy, algorithm, private)
}

/// The verification policy with the context's flags applied: a caller's
/// choice for its own operation, as the flags of a transform context are.
fn verification_policy(
    ctx: &XmlSecDSigCtx,
    policy: &Arc<VerificationPolicy>,
) -> Arc<VerificationPolicy> {
    let mut policy = Arc::clone(policy);
    let manifests = if ctx.flags & FLAGS_IGNORE_MANIFESTS == 0 {
        ManifestProcessing::Process
    } else {
        ManifestProcessing::Ignore
    };
    if policy.manifest_processing != manifests {
        Arc::make_mut(&mut policy).manifest_processing = manifests;
    }
    if ctx.flags & FLAGS_USE_VISA3D_HACK != 0 {
        Arc::make_mut(&mut policy)
            .transforms
            .same_document_id_semantics = SameDocumentIdSemantics::XmlSecVisa3d;
    }
    if ctx.flags & FLAGS_ALLOW_EMPTY_INPUT_DSIG != 0
        && policy.transforms.empty_digest_input != EmptyDigestInput::Accept
    {
        Arc::make_mut(&mut policy).transforms.empty_digest_input = EmptyDigestInput::Accept;
    }
    if ctx.flags & FLAGS_USE_ASN1_SIGNATURE_VALUES != 0 {
        Arc::make_mut(&mut policy).ecdsa_signature_value_encoding =
            EcdsaSignatureValueEncoding::XmlSecAsn1Der;
    }
    policy
}

/// The signing policy with the context's flags applied.
fn signing_policy(ctx: &XmlSecDSigCtx, policy: &Arc<SigningPolicy>) -> Arc<SigningPolicy> {
    let mut policy = Arc::clone(policy);
    if ctx.flags & FLAGS_USE_VISA3D_HACK != 0 {
        Arc::make_mut(&mut policy)
            .transforms
            .same_document_id_semantics = SameDocumentIdSemantics::XmlSecVisa3d;
    }
    if ctx.flags & FLAGS_ALLOW_EMPTY_INPUT_DSIG != 0
        && policy.transforms.empty_digest_input != EmptyDigestInput::Accept
    {
        Arc::make_mut(&mut policy).transforms.empty_digest_input = EmptyDigestInput::Accept;
    }
    if ctx.flags & FLAGS_USE_ASN1_SIGNATURE_VALUES != 0 {
        Arc::make_mut(&mut policy).ecdsa_signature_value_encoding =
            EcdsaSignatureValueEncoding::XmlSecAsn1Der;
    }
    policy
}

/// The tree node `node` is, as the core's documents of its tree name it. A
/// lent tree refuses its handles, so this is read before lending it.
fn external_of(node: *mut XmlNode) -> Option<ExternalNode> {
    nodes::tree_node(node).map(|(_, tree_node)| ExternalNode::from(tree_node))
}

/// The identity of the tree node `external` in `document`, a tree-backed
/// document of its tree.
fn identity_in(document: &XmlDocument, external: ExternalNode) -> Option<xml_sec::NodeIdentity> {
    document.with_view(|view| {
        let found = view.node_of_external(external)?;
        view.identity_of(found).ok()
    })
}

/// Runs the core verification of the `Signature` element `node` and reports
/// its outcome in the contexts.
///
/// # Safety
/// `node` is a live node; the context's method and key are set.
unsafe fn run_verification(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxVerify");
    let Some(pinned) = Pinned::current(here) else {
        return -1;
    };
    // SAFETY: the method was read.
    let Some(algorithm) = (unsafe { algorithm(ctx) }) else {
        errors::internal(here, std::ptr::null(), c"SignatureAlgorithm::from_uri");
        return -1;
    };
    // SAFETY: the key matched the method's requirements.
    let Some(key) = (unsafe { verifying_key(ctx.sign_key, algorithm) }) else {
        errors::internal(here, std::ptr::null(), c"xmlSecKeyGetValue");
        return -1;
    };
    let policy = verification_policy(ctx, &pinned.verification);
    let (document, _) = match xml_sec_libxml2::document::snapshot(node, &*policy) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSecDSigCtxVerify",
                &error.to_string(),
            );
            return -1;
        }
    };
    let Some(signature) = external_of(node).and_then(|external| identity_in(&document, external))
    else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return -1;
    };
    let store = ctx.flags
        & (FLAGS_STORE_SIGNATURE
            | FLAGS_STORE_SIGNEDINFO_REFERENCES
            | FLAGS_STORE_MANIFEST_REFERENCES)
        != 0;
    let outcome = VerifyContext::new()
        .shared_policy(policy)
        .key(key.as_ref())
        .signature(signature)
        .store_pre_digest(store)
        .verify_document(&document);
    let result = match outcome {
        Ok(result) => result,
        Err(error) => {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_XMLSEC_FAILED,
                &error.to_string(),
            );
            return -1;
        }
    };
    // SAFETY: the context's lists and buffers.
    unsafe { report_verification(ctx, &document, &result) }
}

/// The context's status, failure reason, reference statuses and kept
/// buffers from the core's `result`.
///
/// # Safety
/// The context's reference lists hold the references read for `result`.
unsafe fn report_verification(
    ctx: &mut XmlSecDSigCtx,
    document: &XmlDocument,
    result: &VerifyResult,
) -> c_int {
    // SAFETY: the context's own lists of reference contexts.
    unsafe {
        let list = &raw mut ctx.signed_info_references;
        for (index, outcome) in result.signed_info_references.iter().enumerate() {
            let reference = xmlSecPtrListGetItem(list, index).cast::<XmlSecDSigReferenceCtx>();
            if let Some(reference) = reference.as_mut() {
                apply_reference(reference, outcome);
            }
        }
        let list = &raw mut ctx.manifest_references;
        for outcome in &result.manifest_references {
            if let Some(reference) = manifest_reference(list, document, outcome) {
                apply_reference(&mut *reference, outcome);
            }
        }
        if ctx.flags & FLAGS_STORE_SIGNATURE != 0
            && let Some(signed_info) = result.canonicalized_signed_info.as_deref()
        {
            keep(
                xmlSecTransformMemBufGetBuffer(ctx.pre_sign_mem_buf_method),
                signed_info,
            );
        }
    }
    // A mismatch is reported as libxmlsec1's verifying transforms report it,
    // with the method's name: a digest's as invalid data, a signature's as
    // data that does not match.
    let here = here!("xmlSecDSigCtxVerify");
    for outcome in &result.signed_info_references {
        if matches!(
            outcome.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { .. })
        ) {
            errors::other(
                here,
                errors::R_INVALID_DATA,
                std::ptr::null(),
                Some("data and digest do not match"),
            );
        }
    }
    match result.status {
        DsigStatus::Valid => ctx.status = STATUS_SUCCEEDED,
        DsigStatus::Invalid(FailureReason::SignatureMismatch) => {
            errors::other(
                here,
                errors::R_DATA_NOT_MATCH,
                std::ptr::null(),
                Some("signature verification failed"),
            );
            mark_failed(ctx, FAILURE_SIGNATURE);
        }
        DsigStatus::Invalid(FailureReason::KeyNotFound) => mark_failed(ctx, FAILURE_KEY_NOT_FOUND),
        DsigStatus::Invalid(_) => mark_failed(ctx, FAILURE_REFERENCE),
        // `NotProcessed` is never an overall status.
        _ => mark_failed(ctx, FAILURE_UNKNOWN),
    }
    0
}

/// The manifest reference context whose `Reference` element the core's
/// `outcome` is about.
///
/// # Safety
/// `list` holds reference contexts whose `reserved0` is their element.
unsafe fn manifest_reference(
    list: *mut super::XmlSecPtrList,
    document: &XmlDocument,
    outcome: &ReferenceResult,
) -> Option<*mut XmlSecDSigReferenceCtx> {
    let external = document.external_node(outcome.reference_identity?).ok()?;
    // SAFETY: by the caller's contract.
    unsafe {
        for index in 0..xmlSecPtrListGetSize(list) {
            let reference = xmlSecPtrListGetItem(list, index).cast::<XmlSecDSigReferenceCtx>();
            let Some(context) = reference.as_ref() else {
                continue;
            };
            let element = nodes::tree_node(context.reserved0.cast::<XmlNode>())
                .map(|(_, node)| ExternalNode::from(node));
            if element == Some(external) {
                return Some(reference);
            }
        }
    }
    None
}

/// A reference context's status and kept pre-digest bytes from the core's
/// `outcome`.
///
/// # Safety
/// The context's membuf, if any, is live.
unsafe fn apply_reference(reference: &mut XmlSecDSigReferenceCtx, outcome: &ReferenceResult) {
    reference.status = match outcome.status {
        DsigStatus::Valid => STATUS_SUCCEEDED,
        DsigStatus::Invalid(_) => STATUS_INVALID,
        // `NotProcessed`: not dereferenced, the signature value did not verify.
        _ => STATUS_UNKNOWN,
    };
    if let Some(bytes) = outcome.pre_digest_data.as_deref()
        && !reference.pre_digest_mem_buf_method.is_null()
    {
        // SAFETY: the context's own membuf.
        unsafe {
            keep(
                xmlSecTransformMemBufGetBuffer(reference.pre_digest_mem_buf_method),
                bytes,
            );
        }
    }
}

/// Puts `bytes` into the kept `buffer`.
///
/// # Safety
/// `buffer` is null or a membuf's buffer.
unsafe fn keep(buffer: *mut XmlSecBuffer, bytes: &[u8]) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: by the caller's contract.
    if unsafe { xmlSecBufferSetData(buffer, bytes.as_ptr(), bytes.len()) } < 0 {
        errors::internal(
            here!("xmlSecDSigCtxProcessSignatureNode"),
            std::ptr::null(),
            c"xmlSecBufferSetData",
        );
    }
}

/// Runs the core signing of the template `node` in place and reports its
/// outcome in the contexts.
///
/// # Safety
/// `node` is a live node; the context's method and key are set.
unsafe fn run_signing(ctx: &mut XmlSecDSigCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecDSigCtxSign");
    let Some(pinned) = Pinned::current(here) else {
        return -1;
    };
    // SAFETY: the method was read.
    let Some(algorithm) = (unsafe { algorithm(ctx) }) else {
        errors::internal(here, std::ptr::null(), c"SignatureAlgorithm::from_uri");
        return -1;
    };
    let policy = signing_policy(ctx, &pinned.signing);
    // SAFETY: the key matched the method's requirements.
    let key = match unsafe { signer(ctx.sign_key, algorithm, &policy) } {
        Ok(key) => key,
        Err(error) => {
            errors::internal_with(here, std::ptr::null(), c"signing_key", &error);
            return -1;
        }
    };
    let Some(external) = external_of(node) else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return -1;
    };
    // SAFETY: reads the process-global default.
    let line_size =
        usize::try_from(unsafe { super::super::base64::xmlSecBase64GetDefaultLineSize() })
            .ok()
            .and_then(std::num::NonZeroUsize::new);
    let signed = xml_sec_libxml2::document::with_document(node, &*policy, |document, _| {
        let Some(template) = identity_in(document, external) else {
            return Err("the template is not in its document".to_owned());
        };
        SignContext::new(key.as_ref())
            .shared_policy(Arc::clone(&policy))
            // libxmlsec1 writes the values through Base64 transforms of the
            // default line size.
            .base64_line_size(line_size)
            .signature_template_selection(SignatureTemplateSelection::Exact(template))
            .sign_document(document)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    match signed {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_XMLSEC_FAILED,
                &error,
            );
            return -1;
        }
        Err(error) => {
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSecDSigCtxSign",
                &error.to_string(),
            );
            return -1;
        }
    }
    // SAFETY: the context's own lists and its signature value element.
    unsafe {
        let list = &raw mut ctx.signed_info_references;
        for index in 0..xmlSecPtrListGetSize(list) {
            let reference = xmlSecPtrListGetItem(list, index).cast::<XmlSecDSigReferenceCtx>();
            if let Some(reference) = reference.as_mut() {
                reference.status = STATUS_SUCCEEDED;
            }
        }
        keep_result(ctx)
    }
}

/// Makes the written `SignatureValue` the context's `result`, a buffer the
/// context owns.
///
/// # Safety
/// The context's signature value element is live.
unsafe fn keep_result(ctx: &mut XmlSecDSigCtx) -> c_int {
    let here = here!("xmlSecDSigCtxSign");
    let value = nodes::content(ctx.sign_value_node).unwrap_or_default();
    // SAFETY: a fresh buffer, owned through `reserved0`.
    unsafe {
        let buffer = xmlSecBufferCreate(value.len());
        if buffer.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecBufferCreate");
            return -1;
        }
        if xmlSecBufferSetData(buffer, value.as_ptr(), value.len()) < 0 {
            xmlSecBufferDestroy(buffer);
            errors::internal(here, std::ptr::null(), c"xmlSecBufferSetData");
            return -1;
        }
        release(ctx);
        ctx.reserved0 = buffer.cast();
        ctx.result = buffer;
    }
    0
}
