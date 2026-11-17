//! `xmlsec/xmlenc.h`: the encryption context.
//!
//! The context has libxmlsec1's layout and lifecycle. Decryption reads the
//! `EncryptedData` element as libxmlsec1 does (its method through the
//! registered klasses, the cipher data, the key through the read `KeyInfo`
//! context), then the core decrypts exactly that element of the caller's
//! tree under the library policy ([`process`]); the plaintext replaces the
//! element as its `Type` asks, through the tree functions, as libxmlsec1
//! replaces it.

use std::ffi::{c_char, c_int, c_uint, c_void};

use super::buffer::{
    XmlSecBuffer, xmlSecBufferDebugHexDump, xmlSecBufferGetData, xmlSecBufferGetSize,
};
use super::errors::{self, check, here};
use super::keyinfo::{
    MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, xmlSecKeyInfoCtxCopyUserPref,
    xmlSecKeyInfoCtxDebugDump, xmlSecKeyInfoCtxDebugXmlDump, xmlSecKeyInfoCtxFinalize,
    xmlSecKeyInfoCtxInitialize, xmlSecKeyInfoCtxReset,
};
use super::keys::{
    TYPE_PUBLIC, XmlSecKey, xmlSecKeyDebugDump, xmlSecKeyDebugXmlDump, xmlSecKeyDestroy,
};
use super::keysmngr::XmlSecKeysMngr;
use super::transforms::ctx::{
    XmlSecTransformCtx, xmlSecTransformCtxCopyUserPref, xmlSecTransformCtxDebugDump,
    xmlSecTransformCtxDebugXmlDump, xmlSecTransformCtxFinalize, xmlSecTransformCtxInitialize,
    xmlSecTransformCtxReset,
};
use super::transforms::{
    OPERATION_ENCRYPT, XmlSecTransform, XmlSecTransformKlass, xmlSecTransformDebugDump,
    xmlSecTransformDebugXmlDump,
};
use super::tree::{XmlNode, nodes};
use super::xmltree::xmlSecPrintXmlString;
use super::{contain, free, malloc, write_stream};

mod process;
#[cfg(test)]
mod tests;

/// `xmlSecEncCtxModeEncryptedData`.
pub(crate) const MODE_ENCRYPTED_DATA: c_int = 0;
/// `xmlSecEncCtxModeEncryptedKey`.
pub(crate) const MODE_ENCRYPTED_KEY: c_int = 1;

/// `xmlSecEncFailureReasonUnknown`.
pub(crate) const FAILURE_UNKNOWN: c_int = 0;
/// `xmlSecEncFailureReasonKeyNotFound`.
pub(crate) const FAILURE_KEY_NOT_FOUND: c_int = 1;

/// `XMLSEC_ENC_FLAGS_RETURN_REPLACED_NODE`.
pub(crate) const FLAGS_RETURN_REPLACED_NODE: c_uint = 0x0000_0001;

/// `xmlSecEncCtx`.
#[repr(C)]
pub(crate) struct XmlSecEncCtx {
    pub(crate) user_data: *mut c_void,
    pub(crate) flags: c_uint,
    pub(crate) flags2: c_uint,
    pub(crate) mode: c_int,
    pub(crate) key_info_read_ctx: XmlSecKeyInfoCtx,
    pub(crate) key_info_write_ctx: XmlSecKeyInfoCtx,
    pub(crate) transform_ctx: XmlSecTransformCtx,
    pub(crate) def_enc_method_id: *const XmlSecTransformKlass,
    pub(crate) enc_key: *mut XmlSecKey,
    pub(crate) operation: c_int,
    pub(crate) result: *mut XmlSecBuffer,
    pub(crate) result_base64_encoded: c_int,
    pub(crate) result_replaced: c_int,
    pub(crate) enc_method: *mut XmlSecTransform,
    pub(crate) failure_reason: c_int,
    pub(crate) id: *mut u8,
    pub(crate) type_: *mut u8,
    pub(crate) mime_type: *mut u8,
    pub(crate) encoding: *mut u8,
    pub(crate) recipient: *mut u8,
    pub(crate) carried_key_name: *mut u8,
    pub(crate) enc_data_node: *mut XmlNode,
    pub(crate) enc_method_node: *mut XmlNode,
    pub(crate) key_info_node: *mut XmlNode,
    pub(crate) cipher_value_node: *mut XmlNode,
    pub(crate) replaced_node_list: *mut XmlNode,
    pub(crate) reserved1: *mut c_void,
}

/// libxmlsec1's `xmlSecEncCtxSetDefaults`: read and write `KeyInfo`
/// contexts, the latter writing only public key data.
fn set_defaults(ctx: &mut XmlSecEncCtx) {
    ctx.key_info_read_ctx.mode = MODE_READ;
    ctx.key_info_write_ctx.mode = MODE_WRITE;
    ctx.key_info_write_ctx.key_req.key_type = TYPE_PUBLIC;
}

/// `xmlSecEncCtxCreate`: a new context for `keys_mngr`, released with
/// [`xmlSecEncCtxDestroy`].
///
/// # Safety
/// `keys_mngr` is null or a keys manager outliving the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxCreate(
    keys_mngr: *mut XmlSecKeysMngr,
) -> *mut XmlSecEncCtx {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecEncCtxCreate");
        let ctx = malloc(size_of::<XmlSecEncCtx>()).cast::<XmlSecEncCtx>();
        if ctx.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecEncCtx>());
            return ctx;
        }
        // SAFETY: a fresh allocation of the context's size.
        unsafe {
            if xmlSecEncCtxInitialize(ctx, keys_mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecEncCtxInitialize");
                xmlSecEncCtxDestroy(ctx);
                return std::ptr::null_mut();
            }
        }
        ctx
    })
}

/// `xmlSecEncCtxDestroy`.
///
/// # Safety
/// `ctx` is null or a created context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDestroy(ctx: *mut XmlSecEncCtx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecEncCtxDestroy", c"encCtx != NULL");
        // SAFETY: a created context.
        unsafe {
            xmlSecEncCtxFinalize(ctx);
            free(ctx.cast());
        }
    });
}

/// `xmlSecEncCtxInitialize`.
///
/// # Safety
/// `ctx` is null or writable; `keys_mngr` null or a keys manager outliving
/// the context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxInitialize(
    ctx: *mut XmlSecEncCtx,
    keys_mngr: *mut XmlSecKeysMngr,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxInitialize",
            c"encCtx != NULL",
            -1
        );
        let here = here!("xmlSecEncCtxInitialize");
        // SAFETY: writable; every member is set from zero as in libxmlsec1.
        unsafe {
            ctx.cast::<u8>().write_bytes(0, size_of::<XmlSecEncCtx>());
            let context = &mut *ctx;
            for key_info in [
                &raw mut context.key_info_read_ctx,
                &raw mut context.key_info_write_ctx,
            ] {
                if xmlSecKeyInfoCtxInitialize(key_info, keys_mngr) < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxInitialize");
                    return -1;
                }
            }
            if xmlSecTransformCtxInitialize(&raw mut context.transform_ctx) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxInitialize");
                return -1;
            }
            set_defaults(context);
        }
        0
    })
}

/// `xmlSecEncCtxFinalize`.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxFinalize(ctx: *mut XmlSecEncCtx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecEncCtxFinalize", c"encCtx != NULL");
        // SAFETY: an initialized context.
        unsafe {
            xmlSecEncCtxReset(ctx);
            let context = &mut *ctx;
            xmlSecTransformCtxFinalize(&raw mut context.transform_ctx);
            xmlSecKeyInfoCtxFinalize(&raw mut context.key_info_read_ctx);
            xmlSecKeyInfoCtxFinalize(&raw mut context.key_info_write_ctx);
            ctx.cast::<u8>().write_bytes(0, size_of::<XmlSecEncCtx>());
        }
    });
}

/// `xmlSecEncCtxReset`: clears the processing state, the key and the
/// returned replaced nodes, keeping the user settings.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxReset(ctx: *mut XmlSecEncCtx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecEncCtxReset", c"encCtx != NULL");
        // SAFETY: an initialized context and what it owns.
        unsafe {
            let context = &mut *ctx;
            xmlSecTransformCtxReset(&raw mut context.transform_ctx);
            xmlSecKeyInfoCtxReset(&raw mut context.key_info_read_ctx);
            xmlSecKeyInfoCtxReset(&raw mut context.key_info_write_ctx);
            context.operation = 0;
            context.result = std::ptr::null_mut();
            context.result_base64_encoded = 0;
            context.result_replaced = 0;
            context.enc_method = std::ptr::null_mut();
            context.failure_reason = FAILURE_UNKNOWN;
            if !context.replaced_node_list.is_null() {
                nodes::free_list(context.replaced_node_list);
                context.replaced_node_list = std::ptr::null_mut();
            }
            if !context.enc_key.is_null() {
                xmlSecKeyDestroy(context.enc_key);
                context.enc_key = std::ptr::null_mut();
            }
            for text in [
                &mut context.id,
                &mut context.type_,
                &mut context.mime_type,
                &mut context.encoding,
                &mut context.recipient,
                &mut context.carried_key_name,
            ] {
                if !text.is_null() {
                    free(text.cast());
                    *text = std::ptr::null_mut();
                }
            }
            context.enc_data_node = std::ptr::null_mut();
            context.enc_method_node = std::ptr::null_mut();
            context.key_info_node = std::ptr::null_mut();
            context.cipher_value_node = std::ptr::null_mut();
            set_defaults(context);
        }
    });
}

/// `xmlSecEncCtxCopyUserPref`.
///
/// # Safety
/// `dst` and `src` are null or initialized contexts.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxCopyUserPref(
    dst: *mut XmlSecEncCtx,
    src: *mut XmlSecEncCtx,
) -> c_int {
    contain(-1, || {
        check!(
            !dst.is_null(),
            "xmlSecEncCtxCopyUserPref",
            c"dst != NULL",
            -1
        );
        check!(
            !src.is_null(),
            "xmlSecEncCtxCopyUserPref",
            c"src != NULL",
            -1
        );
        if dst == src {
            return 0;
        }
        let here = here!("xmlSecEncCtxCopyUserPref");
        // SAFETY: initialized contexts.
        unsafe {
            let (to, from) = (&mut *dst, &mut *src);
            to.user_data = from.user_data;
            to.flags = from.flags;
            to.flags2 = from.flags2;
            to.def_enc_method_id = from.def_enc_method_id;
            to.mode = from.mode;
            if xmlSecTransformCtxCopyUserPref(
                &raw mut to.transform_ctx,
                &raw mut from.transform_ctx,
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCopyUserPref");
                return -1;
            }
            for (to, from) in [
                (
                    &raw mut to.key_info_read_ctx,
                    &raw mut from.key_info_read_ctx,
                ),
                (
                    &raw mut to.key_info_write_ctx,
                    &raw mut from.key_info_write_ctx,
                ),
            ] {
                if xmlSecKeyInfoCtxCopyUserPref(to, from) < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxCopyUserPref");
                    return -1;
                }
            }
        }
        0
    })
}

/// `xmlSecEncCtxBinaryEncrypt`: encrypts `size` bytes at `data` into the
/// template `tmpl`.
///
/// # Safety
/// `ctx` is null or an initialized context; `tmpl` null or a live node;
/// `data` null or `size` readable bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxBinaryEncrypt(
    ctx: *mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxBinaryEncrypt",
            c"encCtx != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        unsafe { process::binary_encrypt(&mut *ctx, tmpl, data, size) }
    })
}

/// `xmlSecEncCtxXmlEncrypt`: encrypts `node` (an `Element` template) or its
/// content (a `Content` one) into the template `tmpl`, which then takes
/// its place.
///
/// # Safety
/// `ctx` is null or an initialized context; `tmpl` and `node` null or live
/// nodes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxXmlEncrypt(
    ctx: *mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    node: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxXmlEncrypt",
            c"encCtx != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        unsafe { process::xml_encrypt(&mut *ctx, tmpl, node) }
    })
}

/// `xmlSecEncCtxDecrypt`: decrypts the `EncryptedData` element `node` and
/// replaces it with the plaintext when its `Type` is `Element` or
/// `Content`; one without a `Type` is left for the caller, who reads the
/// result.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDecrypt(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(!ctx.is_null(), "xmlSecEncCtxDecrypt", c"encCtx != NULL", -1);
        check!(!node.is_null(), "xmlSecEncCtxDecrypt", c"node != NULL", -1);
        // SAFETY: an initialized context and a live node.
        unsafe { process::decrypt(&mut *ctx, node) }
    })
}

/// `xmlSecEncCtxDecryptToBuffer`: decrypts the `EncryptedData` element
/// `node` into the context's result, which it returns, and leaves the tree
/// unchanged.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDecryptToBuffer(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> *mut XmlSecBuffer {
    contain(std::ptr::null_mut(), || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxDecryptToBuffer",
            c"encCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: an initialized context and a null or live node.
        unsafe { process::decrypt_to_buffer(&mut *ctx, node) }
    })
}

/// `xmlSecEncCtxGetFailureReasonString`.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecEncCtxGetFailureReasonString(reason: c_int) -> *const c_char {
    failure_string(reason).as_ptr()
}

fn failure_string(reason: c_int) -> &'static std::ffi::CStr {
    match reason {
        FAILURE_KEY_NOT_FOUND => c"KEY-NOT-FOUND",
        _ => c"UNKNOWN",
    }
}

/// The dump titles of the context's mode and operation.
fn titles(ctx: &XmlSecEncCtx) -> (&'static str, &'static str) {
    let encrypting = ctx.operation == OPERATION_ENCRYPT;
    match (ctx.mode, encrypting) {
        (MODE_ENCRYPTED_KEY, true) => ("KEY ENCRYPTION CONTEXT", "KeyEncryptionContext"),
        (MODE_ENCRYPTED_KEY, false) => ("KEY DECRYPTION CONTEXT", "KeyDecryptionContext"),
        (_, true) => ("DATA ENCRYPTION CONTEXT", "DataEncryptionContext"),
        (_, false) => ("DATA DECRYPTION CONTEXT", "DataDecryptionContext"),
    }
}

/// The text of the C string `text`.
///
/// # Safety
/// `text` is a NUL-terminated string.
unsafe fn text_of(text: *const u8) -> String {
    // SAFETY: by the caller's contract.
    unsafe { std::ffi::CStr::from_ptr(text.cast()) }
        .to_string_lossy()
        .into_owned()
}

/// The status a dump prints.
const fn replaced(ctx: &XmlSecEncCtx) -> &'static str {
    if ctx.result_replaced != 0 {
        "replaced"
    } else {
        "not-replaced"
    }
}

/// The result bytes and whether there are any.
///
/// # Safety
/// `buffer` is a buffer.
unsafe fn result_bytes<'a>(buffer: *mut XmlSecBuffer) -> Option<&'a [u8]> {
    // SAFETY: by the caller's contract.
    unsafe {
        let data = xmlSecBufferGetData(buffer);
        let size = xmlSecBufferGetSize(buffer);
        (!data.is_null() && size > 0).then(|| std::slice::from_raw_parts(data, size))
    }
}

/// `xmlSecEncCtxDebugDump`.
///
/// # Safety
/// `ctx` is null or an initialized context; `output` null or a live stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDebugDump(ctx: *mut XmlSecEncCtx, output: *mut c_void) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecEncCtxDebugDump", c"encCtx != NULL");
        check!(
            !output.is_null(),
            "xmlSecEncCtxDebugDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            let (title, _) = titles(context);
            write_stream(
                output,
                &format!(
                    "= {title}\n== Failure reason: {}\n== Status: {}\n== flags: 0x{:08x}\n== flags2: 0x{:08x}\n",
                    failure_string(context.failure_reason).to_string_lossy(),
                    replaced(context),
                    context.flags,
                    context.flags2
                ),
            );
            for (label, text) in [
                ("Id", context.id),
                ("Type", context.type_),
                ("MimeType", context.mime_type),
                ("Encoding", context.encoding),
                ("Recipient", context.recipient),
                ("CarriedKeyName", context.carried_key_name),
            ] {
                if !text.is_null() {
                    write_stream(output, &format!("== {label}: \"{}\"\n", text_of(text)));
                }
            }
            write_stream(output, "== Key Info Read Ctx:\n");
            xmlSecKeyInfoCtxDebugDump(&raw mut context.key_info_read_ctx, output);
            write_stream(output, "== Key Info Write Ctx:\n");
            xmlSecKeyInfoCtxDebugDump(&raw mut context.key_info_write_ctx, output);
            write_stream(output, "== Encryption Transform Ctx:\n");
            xmlSecTransformCtxDebugDump(&raw mut context.transform_ctx, output);
            if !context.enc_method.is_null() {
                write_stream(output, "== Encryption Method:\n");
                xmlSecTransformDebugDump(context.enc_method, output);
            }
            if !context.enc_key.is_null() {
                write_stream(output, "== Encryption Key:\n");
                xmlSecKeyDebugDump(context.enc_key, output);
            }
            if !context.result.is_null() {
                match result_bytes(context.result) {
                    None => write_stream(output, "== Result - start buffer (empty):\n"),
                    Some(bytes) if context.result_base64_encoded != 0 => write_stream(
                        output,
                        &format!(
                            "== Result - start buffer (base64):\n{}\n",
                            String::from_utf8_lossy(bytes)
                        ),
                    ),
                    Some(_) => {
                        write_stream(output, "== Result - start buffer (hex):\n");
                        xmlSecBufferDebugHexDump(context.result, output);
                    }
                }
                write_stream(output, "\n== Result - end buffer\n");
            }
        }
    });
}

/// `xmlSecEncCtxDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecEncCtxDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDebugXmlDump(
    ctx: *mut XmlSecEncCtx,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxDebugXmlDump",
            c"encCtx != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecEncCtxDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: an initialized context and a live stream.
        unsafe {
            let context = &mut *ctx;
            let (_, element) = titles(context);
            write_stream(
                output,
                &format!(
                    "<{element} status=\"{}\" failureReason=\"{}\">\n<Flags>{:08x}</Flags>\n<Flags2>{:08x}</Flags2>\n",
                    replaced(context),
                    failure_string(context.failure_reason).to_string_lossy(),
                    context.flags,
                    context.flags2
                ),
            );
            for (label, text) in [
                ("Id", context.id),
                ("Type", context.type_),
                ("MimeType", context.mime_type),
                ("Encoding", context.encoding),
                ("Recipient", context.recipient),
                ("CarriedKeyName", context.carried_key_name),
            ] {
                write_stream(output, &format!("<{label}>"));
                xmlSecPrintXmlString(output, text);
                write_stream(output, &format!("</{label}>"));
            }
            write_stream(output, "<KeyInfoReadCtx>\n");
            xmlSecKeyInfoCtxDebugXmlDump(&raw mut context.key_info_read_ctx, output);
            write_stream(output, "</KeyInfoReadCtx>\n<KeyInfoWriteCtx>\n");
            xmlSecKeyInfoCtxDebugXmlDump(&raw mut context.key_info_write_ctx, output);
            write_stream(output, "</KeyInfoWriteCtx>\n<EncryptionTransformCtx>\n");
            xmlSecTransformCtxDebugXmlDump(&raw mut context.transform_ctx, output);
            write_stream(output, "</EncryptionTransformCtx>\n");
            if !context.enc_method.is_null() {
                write_stream(output, "<EncryptionMethod>\n");
                xmlSecTransformDebugXmlDump(context.enc_method, output);
                write_stream(output, "</EncryptionMethod>\n");
            }
            if !context.enc_key.is_null() {
                write_stream(output, "<EncryptionKey>\n");
                xmlSecKeyDebugXmlDump(context.enc_key, output);
                write_stream(output, "</EncryptionKey>\n");
            }
            if !context.result.is_null() {
                match result_bytes(context.result) {
                    None => {
                        write_stream(output, "<Result>");
                        xmlSecBufferDebugHexDump(context.result, output);
                        write_stream(output, "</Result>\n");
                    }
                    Some(bytes) if context.result_base64_encoded != 0 => write_stream(
                        output,
                        &format!(
                            "<Result format=\"base64\">{}\n</Result>\n",
                            String::from_utf8_lossy(bytes)
                        ),
                    ),
                    Some(_) => {
                        write_stream(output, "<Result format=\"hex\">");
                        xmlSecBufferDebugHexDump(context.result, output);
                        write_stream(output, "</Result>\n");
                    }
                }
            }
            write_stream(output, &format!("</{element}>\n"));
        }
    });
}
