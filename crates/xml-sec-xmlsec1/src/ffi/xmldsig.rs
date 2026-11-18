//! `xmlsec/xmldsig.h`: the signature and reference processing contexts.
//!
//! The contexts have libxmlsec1's layouts and lifecycle. Signing and
//! verification read the `Signature` element as libxmlsec1 does, into the
//! context's transforms and one reference context per `Reference`, resolve
//! the key through the read `KeyInfo` context, and then run the core
//! operation on the caller's tree ([`process`]); the contexts report its
//! outcome in libxmlsec1's fields.

use std::ffi::{c_char, c_int, c_uint, c_void};

use super::buffer::{XmlSecBuffer, xmlSecBufferDebugHexDump, xmlSecBufferGetData};
use super::errors::{self, check, here};
use super::keyinfo::{
    MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, xmlSecKeyInfoCtxDebugDump,
    xmlSecKeyInfoCtxDebugXmlDump, xmlSecKeyInfoCtxFinalize, xmlSecKeyInfoCtxInitialize,
};
use super::keys::{
    TYPE_PUBLIC, XmlSecKey, xmlSecKeyDebugDump, xmlSecKeyDebugXmlDump, xmlSecKeyDestroy,
};
use super::keysmngr::XmlSecKeysMngr;
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListCopy, xmlSecPtrListCreate,
    xmlSecPtrListDebugDump, xmlSecPtrListDebugXmlDump, xmlSecPtrListDestroy, xmlSecPtrListFinalize,
    xmlSecPtrListInitialize,
};
use super::transforms::builtin::xmlSecTransformMemBufGetBuffer;
use super::transforms::ctx::{
    FLAGS_ALLOW_EMPTY_INPUT, PreExecuteCallback, XmlSecTransformCtx, xmlSecTransformCtxDebugDump,
    xmlSecTransformCtxDebugXmlDump, xmlSecTransformCtxFinalize, xmlSecTransformCtxInitialize,
};
use super::transforms::{
    OPERATION_SIGN, XmlSecTransform, XmlSecTransformKlass, xmlSecTransformDebugDump,
    xmlSecTransformDebugXmlDump, xmlSecTransformIdListGetKlass,
};
use super::tree::XmlNode;
use super::xmltree::xmlSecPrintXmlString;
use super::{contain, free, malloc, write_stream};

mod process;
#[cfg(test)]
mod tests;

/// `xmlSecDSigStatusUnknown`.
pub(crate) const STATUS_UNKNOWN: c_int = 0;
/// `xmlSecDSigStatusSucceeded`.
pub(crate) const STATUS_SUCCEEDED: c_int = 1;
/// `xmlSecDSigStatusInvalid`.
pub(crate) const STATUS_INVALID: c_int = 2;

/// `xmlSecDSigFailureReasonUnknown`.
pub(crate) const FAILURE_UNKNOWN: c_int = 0;
/// `xmlSecDSigFailureReasonReference`.
pub(crate) const FAILURE_REFERENCE: c_int = 1;
/// `xmlSecDSigFailureReasonSignature`.
pub(crate) const FAILURE_SIGNATURE: c_int = 2;
/// `xmlSecDSigFailureReasonKeyNotFound`.
pub(crate) const FAILURE_KEY_NOT_FOUND: c_int = 3;

/// `xmlSecDSigReferenceOriginSignedInfo`.
pub(crate) const ORIGIN_SIGNED_INFO: c_int = 0;
/// `xmlSecDSigReferenceOriginManifest`.
pub(crate) const ORIGIN_MANIFEST: c_int = 1;

/// `XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS`.
pub(crate) const FLAGS_IGNORE_MANIFESTS: c_uint = 0x0000_0001;
/// `XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES`.
pub(crate) const FLAGS_STORE_SIGNEDINFO_REFERENCES: c_uint = 0x0000_0002;
/// `XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES`.
pub(crate) const FLAGS_STORE_MANIFEST_REFERENCES: c_uint = 0x0000_0004;
/// `XMLSEC_DSIG_FLAGS_STORE_SIGNATURE`.
pub(crate) const FLAGS_STORE_SIGNATURE: c_uint = 0x0000_0008;
/// `XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK`.
pub(crate) const FLAGS_USE_VISA3D_HACK: c_uint = 0x0000_0010;
/// `XMLSEC_DSIG_FLAGS_USE_ASN1_SIGNATURE_VALUES`.
pub(crate) const FLAGS_USE_ASN1_SIGNATURE_VALUES: c_uint = 0x0000_0020;
/// `XMLSEC_DSIG_FLAGS_RELATIONSHIP_LEGACY`.
pub(crate) const FLAGS_RELATIONSHIP_LEGACY: c_uint = 0x0000_0040;
/// `XMLSEC_DSIG_FLAGS_ALLOW_EMPTY_INPUT`.
pub(crate) const FLAGS_ALLOW_EMPTY_INPUT_DSIG: c_uint = 0x0000_0080;

/// `XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK`.
const TRANSFORMCTX_VISA3D: c_uint = 0x0001;
/// `XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES`.
pub(crate) const TRANSFORMCTX_ASN1_SIGNATURE_VALUES: c_uint = 0x0002;
/// `XMLSEC_TRANSFORMCTX_FLAGS_RELATIONSHIP_LEGACY`.
const TRANSFORMCTX_RELATIONSHIP_LEGACY: c_uint = 0x0004;

/// `xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument`: the
/// reference URIs a context dereferences until its caller enables more. The
/// caller's mask restricts; it never widens the library policy.
const REFERENCE_URIS_DEFAULT: c_uint = 0x0001 | 0x0002;

/// `xmlSecDSigCtx`.
#[repr(C)]
pub(crate) struct XmlSecDSigCtx {
    pub(crate) user_data: *mut c_void,
    pub(crate) flags: c_uint,
    pub(crate) flags2: c_uint,
    pub(crate) key_info_read_ctx: XmlSecKeyInfoCtx,
    pub(crate) key_info_write_ctx: XmlSecKeyInfoCtx,
    pub(crate) transform_ctx: XmlSecTransformCtx,
    pub(crate) enabled_reference_uris: c_uint,
    pub(crate) enabled_reference_transforms: *mut XmlSecPtrList,
    pub(crate) reference_pre_execute_callback: PreExecuteCallback,
    pub(crate) def_sign_method_id: *const XmlSecTransformKlass,
    pub(crate) def_c14n_method_id: *const XmlSecTransformKlass,
    pub(crate) def_digest_method_id: *const XmlSecTransformKlass,
    pub(crate) sign_key: *mut XmlSecKey,
    pub(crate) operation: c_int,
    pub(crate) result: *mut XmlSecBuffer,
    pub(crate) status: c_int,
    pub(crate) failure_reason: c_int,
    pub(crate) sign_method: *mut XmlSecTransform,
    pub(crate) c14n_method: *mut XmlSecTransform,
    pub(crate) pre_sign_mem_buf_method: *mut XmlSecTransform,
    pub(crate) sign_value_node: *mut XmlNode,
    pub(crate) id: *mut u8,
    pub(crate) signed_info_references: XmlSecPtrList,
    pub(crate) manifest_references: XmlSecPtrList,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// `xmlSecDSigReferenceCtx`.
#[repr(C)]
pub(crate) struct XmlSecDSigReferenceCtx {
    pub(crate) user_data: *mut c_void,
    pub(crate) dsig_ctx: *mut XmlSecDSigCtx,
    pub(crate) origin: c_int,
    pub(crate) transform_ctx: XmlSecTransformCtx,
    pub(crate) digest_method: *mut XmlSecTransform,
    pub(crate) result: *mut XmlSecBuffer,
    pub(crate) status: c_int,
    pub(crate) pre_digest_mem_buf_method: *mut XmlSecTransform,
    pub(crate) id: *mut u8,
    pub(crate) uri: *mut u8,
    pub(crate) type_: *mut u8,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

// ----------------------------------------------------------------------------
// The signature context

/// The context `ctx` before any operation filled its result, after
/// libxmlsec1's assertions at `here`.
///
/// # Safety
/// `ctx` is null or an initialized context.
unsafe fn fresh<'a>(ctx: *mut XmlSecDSigCtx, here: errors::Here) -> Option<&'a mut XmlSecDSigCtx> {
    // SAFETY: by the caller's contract.
    let Some(context) = (unsafe { ctx.as_mut() }) else {
        errors::assertion(here, c"dsigCtx != NULL");
        return None;
    };
    if !context.result.is_null() {
        errors::assertion(here, c"dsigCtx->result == NULL");
        return None;
    }
    Some(context)
}

/// `xmlSecDSigCtxCreate`: a new context for `keys_mngr`, released with
/// [`xmlSecDSigCtxDestroy`].
///
/// # Safety
/// `keys_mngr` is null or a keys manager outliving the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxCreate(
    keys_mngr: *mut XmlSecKeysMngr,
) -> *mut XmlSecDSigCtx {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecDSigCtxCreate");
        let ctx = malloc(size_of::<XmlSecDSigCtx>()).cast::<XmlSecDSigCtx>();
        if ctx.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecDSigCtx>());
            return ctx;
        }
        // SAFETY: a fresh allocation of the context's size.
        unsafe {
            if xmlSecDSigCtxInitialize(ctx, keys_mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecDSigCtxInitialize");
                xmlSecDSigCtxDestroy(ctx);
                return std::ptr::null_mut();
            }
        }
        ctx
    })
}

/// `xmlSecDSigCtxDestroy`: releases a context from [`xmlSecDSigCtxCreate`].
///
/// # Safety
/// `ctx` is null or a created context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxDestroy(ctx: *mut XmlSecDSigCtx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecDSigCtxDestroy", c"dsigCtx != NULL");
        // SAFETY: a created context.
        unsafe {
            xmlSecDSigCtxFinalize(ctx);
            free(ctx.cast());
        }
    });
}

/// `xmlSecDSigCtxInitialize`: a context for `keys_mngr` with libxmlsec1's
/// defaults: a read and a write `KeyInfo` context, the latter writing only
/// public key data, empty reference lists and same-document reference URIs.
///
/// # Safety
/// `ctx` is null or writable; `keys_mngr` null or a keys manager outliving
/// the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxInitialize(
    ctx: *mut XmlSecDSigCtx,
    keys_mngr: *mut XmlSecKeysMngr,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigCtxInitialize",
            c"dsigCtx != NULL",
            -1
        );
        let here = here!("xmlSecDSigCtxInitialize");
        // SAFETY: writable; every member is set from zero as in libxmlsec1.
        unsafe {
            ctx.cast::<u8>().write_bytes(0, size_of::<XmlSecDSigCtx>());
            let context = &mut *ctx;
            if xmlSecKeyInfoCtxInitialize(&raw mut context.key_info_read_ctx, keys_mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
                return -1;
            }
            context.key_info_read_ctx.mode = MODE_READ;
            if xmlSecKeyInfoCtxInitialize(&raw mut context.key_info_write_ctx, keys_mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
                return -1;
            }
            context.key_info_write_ctx.mode = MODE_WRITE;
            // A signature never writes its private key.
            context.key_info_write_ctx.key_req.key_type = TYPE_PUBLIC;
            if xmlSecTransformCtxInitialize(&raw mut context.transform_ctx) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxInitialize");
                return -1;
            }
            for list in [
                &raw mut context.signed_info_references,
                &raw mut context.manifest_references,
            ] {
                if xmlSecPtrListInitialize(list, xmlSecDSigReferenceCtxListGetKlass()) < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecPtrListInitialize");
                    return -1;
                }
            }
            context.enabled_reference_uris = REFERENCE_URIS_DEFAULT;
        }
        0
    })
}

/// `xmlSecDSigCtxFinalize`: releases what the context owns, its key
/// included, and zeroes it.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxFinalize(ctx: *mut XmlSecDSigCtx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecDSigCtxFinalize", c"dsigCtx != NULL");
        // SAFETY: an initialized context.
        unsafe {
            let context = &mut *ctx;
            xmlSecTransformCtxFinalize(&raw mut context.transform_ctx);
            xmlSecKeyInfoCtxFinalize(&raw mut context.key_info_read_ctx);
            xmlSecKeyInfoCtxFinalize(&raw mut context.key_info_write_ctx);
            xmlSecPtrListFinalize(&raw mut context.signed_info_references);
            xmlSecPtrListFinalize(&raw mut context.manifest_references);
            if !context.enabled_reference_transforms.is_null() {
                xmlSecPtrListDestroy(context.enabled_reference_transforms);
            }
            if !context.sign_key.is_null() {
                xmlSecKeyDestroy(context.sign_key);
            }
            if !context.id.is_null() {
                free(context.id.cast());
            }
            process::release(context);
            ctx.cast::<u8>().write_bytes(0, size_of::<XmlSecDSigCtx>());
        }
    });
}

/// `xmlSecDSigCtxEnableReferenceTransform`: adds `transform_id` to the
/// transforms a `Reference` may use; with none added, every registered
/// transform the policy admits may.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxEnableReferenceTransform(
    ctx: *mut XmlSecDSigCtx,
    transform_id: *const XmlSecTransformKlass,
) -> c_int {
    contain(-1, || {
        // SAFETY: null or an initialized context.
        let Some(context) = (unsafe { fresh(ctx, here!("xmlSecDSigCtxEnableReferenceTransform")) })
        else {
            return -1;
        };
        check!(
            !transform_id.is_null(),
            "xmlSecDSigCtxEnableReferenceTransform",
            c"transformId != xmlSecTransformIdUnknown",
            -1
        );
        let here = here!("xmlSecDSigCtxEnableReferenceTransform");
        // SAFETY: the context's own list, created on first use.
        unsafe {
            if context.enabled_reference_transforms.is_null() {
                context.enabled_reference_transforms =
                    xmlSecPtrListCreate(xmlSecTransformIdListGetKlass());
                if context.enabled_reference_transforms.is_null() {
                    errors::internal(here, std::ptr::null(), c"xmlSecPtrListCreate");
                    return -1;
                }
            }
            if xmlSecPtrListAdd(
                context.enabled_reference_transforms,
                transform_id.cast_mut().cast(),
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListAdd");
                return -1;
            }
        }
        0
    })
}

/// `xmlSecDSigCtxEnableSignatureTransform`: adds `transform_id` to the
/// transforms `SignedInfo` processing may use.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxEnableSignatureTransform(
    ctx: *mut XmlSecDSigCtx,
    transform_id: *const XmlSecTransformKlass,
) -> c_int {
    contain(-1, || {
        // SAFETY: null or an initialized context.
        let Some(context) = (unsafe { fresh(ctx, here!("xmlSecDSigCtxEnableSignatureTransform")) })
        else {
            return -1;
        };
        check!(
            !transform_id.is_null(),
            "xmlSecDSigCtxEnableSignatureTransform",
            c"transformId != xmlSecTransformIdUnknown",
            -1
        );
        // SAFETY: the context's own list.
        unsafe {
            xmlSecPtrListAdd(
                &raw mut context.transform_ctx.enabled_transforms,
                transform_id.cast_mut().cast(),
            )
        }
    })
}

/// `xmlSecDSigCtxGetPreSignBuffer`: the canonical `SignedInfo` the
/// signature covers, kept with `XMLSEC_DSIG_FLAGS_STORE_SIGNATURE`; null
/// otherwise.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxGetPreSignBuffer(
    ctx: *mut XmlSecDSigCtx,
) -> *mut XmlSecBuffer {
    contain(std::ptr::null_mut(), || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigCtxGetPreSignBuffer",
            c"dsigCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: an initialized context whose membuf, if any, is live.
        unsafe {
            let method = (*ctx).pre_sign_mem_buf_method;
            if method.is_null() {
                std::ptr::null_mut()
            } else {
                xmlSecTransformMemBufGetBuffer(method)
            }
        }
    })
}

/// `xmlSecDSigCtxSign`: signs the template `tmpl` in place, writing its
/// digest and signature values.
///
/// # Safety
/// `ctx` is null or an initialized context; `tmpl` null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxSign(
    ctx: *mut XmlSecDSigCtx,
    tmpl: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        // SAFETY: null or an initialized context.
        let Some(context) = (unsafe { fresh(ctx, here!("xmlSecDSigCtxSign")) }) else {
            return -1;
        };
        check!(!tmpl.is_null(), "xmlSecDSigCtxSign", c"tmpl != NULL", -1);
        // SAFETY: an initialized context and a live node.
        unsafe { process::sign(context, tmpl) }
    })
}

/// `xmlSecDSigCtxVerify`: verifies the `Signature` element `node`; 0 with
/// the outcome in `status` once it ran, negative on an error.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxVerify(
    ctx: *mut XmlSecDSigCtx,
    node: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigCtxVerify",
            c"dsigCtx != NULL",
            -1
        );
        check!(!node.is_null(), "xmlSecDSigCtxVerify", c"node != NULL", -1);
        // SAFETY: an initialized context and a live node.
        unsafe { process::verify(&mut *ctx, node) }
    })
}

/// `xmlSecDSigCtxGetStatusString`.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecDSigCtxGetStatusString(status: c_int) -> *const c_char {
    status_string(status).as_ptr()
}

fn status_string(status: c_int) -> &'static std::ffi::CStr {
    match status {
        STATUS_SUCCEEDED => c"OK",
        STATUS_INVALID => c"FAILED",
        // An unknown status is only left by an error in the operation.
        _ => c"ERROR",
    }
}

/// `xmlSecDSigCtxGetFailureReasonString`.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecDSigCtxGetFailureReasonString(reason: c_int) -> *const c_char {
    failure_string(reason).as_ptr()
}

fn failure_string(reason: c_int) -> &'static std::ffi::CStr {
    match reason {
        FAILURE_REFERENCE => c"REFERENCE",
        FAILURE_SIGNATURE => c"SIGNATURE",
        FAILURE_KEY_NOT_FOUND => c"KEY-NOT-FOUND",
        _ => c"UNKNOWN",
    }
}

/// The text of the C string `text`.
///
/// # Safety
/// `text` is a NUL-terminated string.
unsafe fn text_of(text: *const u8) -> std::borrow::Cow<'static, str> {
    // SAFETY: by the caller's contract; the copy outlives the borrow.
    unsafe { std::ffi::CStr::from_ptr(text.cast()) }
        .to_string_lossy()
        .into_owned()
        .into()
}

/// `xmlSecDSigCtxDebugDump`.
///
/// # Safety
/// `ctx` is null or an initialized context; `output` null or a live stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxDebugDump(
    ctx: *mut XmlSecDSigCtx,
    output: *mut c_void,
) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecDSigCtxDebugDump", c"dsigCtx != NULL");
        check!(
            !output.is_null(),
            "xmlSecDSigCtxDebugDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            write_stream(
                output,
                if context.operation == OPERATION_SIGN {
                    "= SIGNATURE CONTEXT\n"
                } else {
                    "= VERIFICATION CONTEXT\n"
                },
            );
            write_stream(
                output,
                &format!(
                    "== Status: {}\n== Failure reason: {}\n== flags: 0x{:08x}\n== flags2: 0x{:08x}\n",
                    status_string(context.status).to_string_lossy(),
                    failure_string(context.failure_reason).to_string_lossy(),
                    context.flags,
                    context.flags2
                ),
            );
            if !context.id.is_null() {
                write_stream(output, &format!("== Id: \"{}\"\n", text_of(context.id)));
            }
            write_stream(output, "== Key Info Read Ctx:\n");
            xmlSecKeyInfoCtxDebugDump(&raw mut context.key_info_read_ctx, output);
            write_stream(output, "== Key Info Write Ctx:\n");
            xmlSecKeyInfoCtxDebugDump(&raw mut context.key_info_write_ctx, output);
            write_stream(output, "== Signature Transform Ctx:\n");
            xmlSecTransformCtxDebugDump(&raw mut context.transform_ctx, output);
            if !context.sign_method.is_null() {
                write_stream(output, "== Signature Method:\n");
                xmlSecTransformDebugDump(context.sign_method, output);
            }
            if !context.sign_key.is_null() {
                write_stream(output, "== Signature Key:\n");
                xmlSecKeyDebugDump(context.sign_key, output);
            }
            write_stream(output, "== SignedInfo References List:\n");
            xmlSecPtrListDebugDump(&raw mut context.signed_info_references, output);
            write_stream(output, "== Manifest References List:\n");
            xmlSecPtrListDebugDump(&raw mut context.manifest_references, output);
            if has_data(context.result) {
                write_stream(output, "== Result - start buffer:\n");
                xmlSecBufferDebugHexDump(context.result, output);
                write_stream(output, "\n== Result - end buffer\n");
            }
            let pre_sign = xmlSecDSigCtxGetPreSignBuffer(ctx);
            if context.flags & FLAGS_STORE_SIGNATURE != 0 && has_data(pre_sign) {
                write_stream(output, "== PreSign data - start buffer:\n");
                xmlSecBufferDebugHexDump(pre_sign, output);
                write_stream(output, "\n== PreSign data - end buffer\n");
            }
        }
    });
}

/// Whether `buffer` is non-null and holds an allocation.
///
/// # Safety
/// `buffer` is null or a buffer.
unsafe fn has_data(buffer: *mut XmlSecBuffer) -> bool {
    // SAFETY: by the caller's contract.
    !buffer.is_null() && unsafe { !xmlSecBufferGetData(buffer).is_null() }
}

/// `xmlSecDSigCtxDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecDSigCtxDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigCtxDebugXmlDump(
    ctx: *mut XmlSecDSigCtx,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigCtxDebugXmlDump",
            c"dsigCtx != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecDSigCtxDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            let element = if context.operation == OPERATION_SIGN {
                "SignatureContext"
            } else {
                "VerificationContext"
            };
            write_stream(
                output,
                &format!(
                    "<{element} status=\"{}\" failureReason=\"{}\">\n<Flags>{:08x}</Flags>\n<Flags2>{:08x}</Flags2>\n<Id>",
                    status_string(context.status).to_string_lossy(),
                    failure_string(context.failure_reason).to_string_lossy(),
                    context.flags,
                    context.flags2
                ),
            );
            xmlSecPrintXmlString(output, context.id);
            write_stream(output, "</Id>\n<KeyInfoReadCtx>\n");
            xmlSecKeyInfoCtxDebugXmlDump(&raw mut context.key_info_read_ctx, output);
            write_stream(output, "</KeyInfoReadCtx>\n<KeyInfoWriteCtx>\n");
            xmlSecKeyInfoCtxDebugXmlDump(&raw mut context.key_info_write_ctx, output);
            write_stream(output, "</KeyInfoWriteCtx>\n<SignatureTransformCtx>\n");
            xmlSecTransformCtxDebugXmlDump(&raw mut context.transform_ctx, output);
            write_stream(output, "</SignatureTransformCtx>\n");
            if !context.sign_method.is_null() {
                write_stream(output, "<SignatureMethod>\n");
                xmlSecTransformDebugXmlDump(context.sign_method, output);
                write_stream(output, "</SignatureMethod>\n");
            }
            if !context.sign_key.is_null() {
                write_stream(output, "<SignatureKey>\n");
                xmlSecKeyDebugXmlDump(context.sign_key, output);
                write_stream(output, "</SignatureKey>\n");
            }
            write_stream(output, "<SignedInfoReferences>\n");
            xmlSecPtrListDebugXmlDump(&raw mut context.signed_info_references, output);
            write_stream(output, "</SignedInfoReferences>\n<ManifestReferences>\n");
            xmlSecPtrListDebugXmlDump(&raw mut context.manifest_references, output);
            write_stream(output, "</ManifestReferences>\n");
            if has_data(context.result) {
                write_stream(output, "<Result>\n");
                xmlSecBufferDebugHexDump(context.result, output);
                write_stream(output, "\n</Result>\n");
            }
            let pre_sign = xmlSecDSigCtxGetPreSignBuffer(ctx);
            if context.flags & FLAGS_STORE_SIGNATURE != 0 && has_data(pre_sign) {
                write_stream(output, "<PreSignData>\n");
                xmlSecBufferDebugHexDump(pre_sign, output);
                write_stream(output, "\n</PreSignData>\n");
            }
            write_stream(output, &format!("</{element}>\n"));
        }
    });
}

// ----------------------------------------------------------------------------
// The reference context

/// `xmlSecDSigReferenceCtxCreate`: a new context of a `Reference` of
/// `dsig_ctx` from `origin`, released with [`xmlSecDSigReferenceCtxDestroy`].
///
/// # Safety
/// `dsig_ctx` is null or an initialized context outliving the new one.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxCreate(
    dsig_ctx: *mut XmlSecDSigCtx,
    origin: c_int,
) -> *mut XmlSecDSigReferenceCtx {
    contain(std::ptr::null_mut(), || {
        check!(
            !dsig_ctx.is_null(),
            "xmlSecDSigReferenceCtxCreate",
            c"dsigCtx != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecDSigReferenceCtxCreate");
        let ctx = malloc(size_of::<XmlSecDSigReferenceCtx>()).cast::<XmlSecDSigReferenceCtx>();
        if ctx.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecDSigReferenceCtx>());
            return ctx;
        }
        // SAFETY: a fresh allocation of the context's size.
        unsafe {
            if xmlSecDSigReferenceCtxInitialize(ctx, dsig_ctx, origin) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecDSigReferenceCtxInitialize");
                xmlSecDSigReferenceCtxDestroy(ctx);
                return std::ptr::null_mut();
            }
        }
        ctx
    })
}

/// `xmlSecDSigReferenceCtxDestroy`.
///
/// # Safety
/// `ctx` is null or a created context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxDestroy(ctx: *mut XmlSecDSigReferenceCtx) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigReferenceCtxDestroy",
            c"dsigRefCtx != NULL"
        );
        // SAFETY: a created context.
        unsafe {
            xmlSecDSigReferenceCtxFinalize(ctx);
            free(ctx.cast());
        }
    });
}

/// `xmlSecDSigReferenceCtxInitialize`: a context of a `Reference` of
/// `dsig_ctx`, with its enabled transforms, URIs, callback, user data and
/// transform flags.
///
/// # Safety
/// `ctx` is null or writable; `dsig_ctx` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxInitialize(
    ctx: *mut XmlSecDSigReferenceCtx,
    dsig_ctx: *mut XmlSecDSigCtx,
    origin: c_int,
) -> c_int {
    contain(-1, || {
        check!(
            !dsig_ctx.is_null(),
            "xmlSecDSigReferenceCtxInitialize",
            c"dsigCtx != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecDSigReferenceCtxInitialize",
            c"dsigRefCtx != NULL",
            -1
        );
        let here = here!("xmlSecDSigReferenceCtxInitialize");
        // SAFETY: writable and an initialized parent.
        unsafe {
            ctx.cast::<u8>()
                .write_bytes(0, size_of::<XmlSecDSigReferenceCtx>());
            let context = &mut *ctx;
            let parent = &mut *dsig_ctx;
            context.dsig_ctx = dsig_ctx;
            context.origin = origin;
            if xmlSecTransformCtxInitialize(&raw mut context.transform_ctx) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxInitialize");
                return -1;
            }
            if !parent.enabled_reference_transforms.is_null()
                && xmlSecPtrListCopy(
                    &raw mut context.transform_ctx.enabled_transforms,
                    parent.enabled_reference_transforms,
                ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListCopy");
                return -1;
            }
            let transforms = &mut context.transform_ctx;
            transforms.pre_exec_callback = parent.reference_pre_execute_callback;
            transforms.enabled_uris = parent.enabled_reference_uris;
            transforms.user_data = parent.user_data;
            for (flag, transform_flag) in [
                (FLAGS_USE_VISA3D_HACK, TRANSFORMCTX_VISA3D),
                (
                    FLAGS_USE_ASN1_SIGNATURE_VALUES,
                    TRANSFORMCTX_ASN1_SIGNATURE_VALUES,
                ),
                (FLAGS_RELATIONSHIP_LEGACY, TRANSFORMCTX_RELATIONSHIP_LEGACY),
                (FLAGS_ALLOW_EMPTY_INPUT_DSIG, FLAGS_ALLOW_EMPTY_INPUT),
            ] {
                if parent.flags & flag != 0 {
                    transforms.flags |= transform_flag;
                }
            }
        }
        0
    })
}

/// `xmlSecDSigReferenceCtxFinalize`.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxFinalize(ctx: *mut XmlSecDSigReferenceCtx) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigReferenceCtxFinalize",
            c"dsigRefCtx != NULL"
        );
        // SAFETY: an initialized context.
        unsafe {
            let context = &mut *ctx;
            xmlSecTransformCtxFinalize(&raw mut context.transform_ctx);
            for text in [context.id, context.uri, context.type_] {
                if !text.is_null() {
                    free(text.cast());
                }
            }
            ctx.cast::<u8>()
                .write_bytes(0, size_of::<XmlSecDSigReferenceCtx>());
        }
    });
}

/// `xmlSecDSigReferenceCtxGetPreDigestBuffer`: the bytes the reference's
/// digest covers, kept with the store flags of its origin; null otherwise.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxGetPreDigestBuffer(
    ctx: *mut XmlSecDSigReferenceCtx,
) -> *mut XmlSecBuffer {
    contain(std::ptr::null_mut(), || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigReferenceCtxGetPreDigestBuffer",
            c"dsigRefCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: an initialized context whose membuf, if any, is live.
        unsafe {
            let method = (*ctx).pre_digest_mem_buf_method;
            if method.is_null() {
                std::ptr::null_mut()
            } else {
                xmlSecTransformMemBufGetBuffer(method)
            }
        }
    })
}

/// `xmlSecDSigReferenceCtxProcessNode`: computes (signing) or checks
/// (verifying) the digest of the `Reference` element `node` on its own,
/// outside a signature, as libxmlsec1 does for an application that walks
/// references itself.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxProcessNode(
    ctx: *mut XmlSecDSigReferenceCtx,
    node: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecDSigReferenceCtxProcessNode",
            c"dsigRefCtx != NULL",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecDSigReferenceCtxProcessNode",
            c"node != NULL",
            -1
        );
        // SAFETY: an initialized context and a live node.
        unsafe { process::reference_node(&mut *ctx, node) }
    })
}

/// Whether a reference dump at `here` may print `ctx` to `output`, after
/// libxmlsec1's assertions.
fn dumpable(ctx: *mut XmlSecDSigReferenceCtx, output: *mut c_void, here: errors::Here) -> bool {
    // SAFETY: null or an initialized context, by the dump's contract.
    let Some(context) = (unsafe { ctx.as_ref() }) else {
        errors::assertion(here, c"dsigRefCtx != NULL");
        return false;
    };
    if context.dsig_ctx.is_null() {
        errors::assertion(here, c"dsigRefCtx->dsigCtx != NULL");
        return false;
    }
    if output.is_null() {
        errors::assertion(here, c"output != NULL");
        return false;
    }
    true
}

/// The origin's word for the reference dumps.
fn reference_element(ctx: &XmlSecDSigReferenceCtx) -> (&'static str, &'static str) {
    // SAFETY: a reference context's parent outlives it while it is dumped.
    let signing =
        unsafe { ctx.dsig_ctx.as_ref() }.is_some_and(|dsig| dsig.operation == OPERATION_SIGN);
    if signing {
        (
            "REFERENCE CALCULATION CONTEXT",
            "ReferenceCalculationContext",
        )
    } else {
        (
            "REFERENCE VERIFICATION CONTEXT",
            "ReferenceVerificationContext",
        )
    }
}

/// `xmlSecDSigReferenceCtxDebugDump`.
///
/// # Safety
/// `ctx` is null or an initialized context; `output` null or a live stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxDebugDump(
    ctx: *mut XmlSecDSigReferenceCtx,
    output: *mut c_void,
) {
    contain((), || {
        if !dumpable(ctx, output, here!("xmlSecDSigReferenceCtxDebugDump")) {
            return;
        }
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            let (title, _) = reference_element(context);
            write_stream(
                output,
                &format!(
                    "= {title}\n== Status: {}\n",
                    status_string(context.status).to_string_lossy()
                ),
            );
            for (label, text) in [
                ("Id", context.id),
                ("URI", context.uri),
                ("Type", context.type_),
            ] {
                if !text.is_null() {
                    write_stream(output, &format!("== {label}: \"{}\"\n", text_of(text)));
                }
            }
            write_stream(output, "== Reference Transform Ctx:\n");
            xmlSecTransformCtxDebugDump(&raw mut context.transform_ctx, output);
            if !context.digest_method.is_null() {
                write_stream(output, "== Digest Method:\n");
                xmlSecTransformDebugDump(context.digest_method, output);
            }
            if has_data(context.result) {
                write_stream(output, "== Result - start buffer:\n");
                xmlSecBufferDebugHexDump(context.result, output);
                write_stream(output, "\n== Result - end buffer\n");
            }
            let pre_digest = xmlSecDSigReferenceCtxGetPreDigestBuffer(ctx);
            if has_data(pre_digest) {
                write_stream(output, "== PreDigest data - start buffer:\n");
                xmlSecBufferDebugHexDump(pre_digest, output);
                write_stream(output, "\n== PreDigest data - end buffer\n");
            }
        }
    });
}

/// `xmlSecDSigReferenceCtxDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecDSigReferenceCtxDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDSigReferenceCtxDebugXmlDump(
    ctx: *mut XmlSecDSigReferenceCtx,
    output: *mut c_void,
) {
    contain((), || {
        if !dumpable(ctx, output, here!("xmlSecDSigReferenceCtxDebugXmlDump")) {
            return;
        }
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            let (_, element) = reference_element(context);
            write_stream(
                output,
                &format!(
                    "<{element} status=\"{}\">\n",
                    status_string(context.status).to_string_lossy()
                ),
            );
            for (label, text) in [
                ("Id", context.id),
                ("URI", context.uri),
                ("Type", context.type_),
            ] {
                write_stream(output, &format!("<{label}>"));
                xmlSecPrintXmlString(output, text);
                write_stream(output, &format!("</{label}>\n"));
            }
            write_stream(output, "<ReferenceTransformCtx>\n");
            xmlSecTransformCtxDebugXmlDump(&raw mut context.transform_ctx, output);
            write_stream(output, "</ReferenceTransformCtx>\n");
            if !context.digest_method.is_null() {
                write_stream(output, "<DigestMethod>\n");
                xmlSecTransformDebugXmlDump(context.digest_method, output);
                write_stream(output, "</DigestMethod>\n");
            }
            if has_data(context.result) {
                write_stream(output, "<Result>");
                xmlSecBufferDebugHexDump(context.result, output);
                write_stream(output, "</Result>\n");
            }
            let pre_digest = xmlSecDSigReferenceCtxGetPreDigestBuffer(ctx);
            if has_data(pre_digest) {
                write_stream(output, "<PreDigestData>");
                xmlSecBufferDebugHexDump(pre_digest, output);
                write_stream(output, "</PreDigestData>\n");
            }
            write_stream(output, &format!("</{element}>\n"));
        }
    });
}

unsafe extern "C" fn reference_destroy(item: *mut c_void) {
    // SAFETY: the list holds reference contexts.
    unsafe { xmlSecDSigReferenceCtxDestroy(item.cast()) };
}

unsafe extern "C" fn reference_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: the list holds reference contexts.
    unsafe { xmlSecDSigReferenceCtxDebugDump(item.cast(), output) };
}

unsafe extern "C" fn reference_xml_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: the list holds reference contexts.
    unsafe { xmlSecDSigReferenceCtxDebugXmlDump(item.cast(), output) };
}

static REFERENCE_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"dsig-reference-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: Some(reference_destroy),
    debug_dump_item: Some(reference_dump),
    debug_xml_dump_item: Some(reference_xml_dump),
};

/// `xmlSecDSigReferenceCtxListGetKlass`: the klass of a list of reference
/// contexts, which it destroys.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecDSigReferenceCtxListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const REFERENCE_LIST
}
