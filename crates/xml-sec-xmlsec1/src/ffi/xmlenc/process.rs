//! Decryption with an encryption context.
//!
//! The `EncryptedData` element is read as libxmlsec1 reads it: its method
//! through the registered klasses, its cipher data, its key through the read
//! `KeyInfo` context. The core then decrypts exactly that element of the
//! caller's tree under the library policy; the plaintext becomes the
//! context's result and, when the element's `Type` asks, replaces it.

use std::ffi::c_int;

use xml_sec::document::external::ExternalNode;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DecryptedContent, SymmetricKeyDecryptor,
};
use zeroize::Zeroizing;

use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferSetData,
};
use super::super::errors::{self, here};
use super::super::keyinfo::xmlSecKeyInfoNodeWrite;
use super::super::keys::{xmlSecKeyGetValue, xmlSecKeyMatch};
use super::super::keysdata::xmlSecKeyDataBinaryValueGetBuffer;
use super::super::policy::{Pinned, Side, SlotPin};
use super::super::strings;
use super::super::transforms::builtin::xmlSecTransformBase64GetKlass;
use super::super::transforms::ctx::{
    ReadResources, ResourceScope, charge_key_read, execute_on_bytes, external_spent, read_resource,
    run_budget, run_policy, xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxExecute,
};
use super::super::transforms::ctx::{
    ctx_node_read_for, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxCreateAndPrepend,
    xmlSecTransformCtxNodesListRead, xmlSecTransformCtxSetUri,
};
use super::super::transforms::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, USAGE_DSIG_TRANSFORM, USAGE_ENCRYPTION_METHOD,
    xmlSecTransformSetKey, xmlSecTransformSetKeyReq,
};
use super::super::tree::{XmlNode, c_text, give, nodes};
use super::super::xmltree::{
    xmlSecAddIDs, xmlSecCheckNodeName, xmlSecGetNextElementNode, xmlSecGetNodeContentAndTrim,
    xmlSecReplaceContentAndReturn, xmlSecReplaceNodeAndReturn, xmlSecReplaceNodeBuffer,
    xmlSecReplaceNodeBufferAndReturn,
};
use super::{
    FAILURE_KEY_NOT_FOUND, FAILURE_UNKNOWN, FLAGS_RETURN_REPLACED_NODE, MODE_ENCRYPTED_DATA,
    MODE_ENCRYPTED_KEY, XmlSecEncCtx,
};
use xml_sec_libxml2::ffi::tree::{xsNodeGetChildren, xsNodeGetDoc};

/// A name of libxmlsec1's strings.
macro_rules! name {
    ($name:ident) => {
        strings::$name.as_ptr()
    };
}

/// Whether `node` is the element `name` of the namespace `ns`.
///
/// # Safety
/// `node` is null or a live node.
unsafe fn is(node: *mut XmlNode, name: *const u8, ns: *const u8) -> bool {
    // SAFETY: by the caller's contract.
    !node.is_null() && unsafe { xmlSecCheckNodeName(node, name, ns) } != 0
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

/// Registers the `Id` attributes of `node`'s subtree as IDs, as libxmlsec1
/// registers those of an encryption element.
///
/// # Safety
/// `node` is a live node.
unsafe fn add_ids(node: *mut XmlNode) {
    let ids = [name!(xmlSecAttrId), std::ptr::null()];
    // SAFETY: a live node of its document and a null-terminated list.
    unsafe { xmlSecAddIDs(xsNodeGetDoc(node), node, ids.as_ptr()) };
}

/// The template `tmpl` read for an encryption, its `Id` attributes
/// registered, after libxmlsec1's preconditions at `here`; negative after a
/// report.
///
/// # Safety
/// `tmpl` is null or a live node.
unsafe fn begin_encryption(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    here: errors::Here,
) -> c_int {
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return -1;
    }
    if tmpl.is_null() {
        errors::assertion(here, c"tmpl != NULL");
        return -1;
    }
    ctx.operation = OPERATION_ENCRYPT;
    // SAFETY: a live node.
    unsafe {
        add_ids(tmpl);
        if read_enc_data(ctx, tmpl, true) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return -1;
        }
    }
    0
}

/// Encrypts `data` through the context's chain and writes the template.
///
/// # Safety
/// The template was read.
unsafe fn encrypt_bytes(ctx: &mut XmlSecEncCtx, data: &[u8], here: errors::Here) -> c_int {
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: the context's own transform context and the caller's bytes.
    unsafe {
        if xmlSecTransformCtxBinaryExecute(transforms, data.as_ptr(), data.len()) < 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxBinaryExecute",
                &format!("dataSize={}", data.len()),
            );
            return -1;
        }
        ctx.result = ctx.transform_ctx.result;
        if ctx.result.is_null() {
            errors::assertion(here, c"encCtx->result != NULL");
            return -1;
        }
        if write_enc_data(ctx) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeWrite");
            return -1;
        }
    }
    0
}

/// `xmlSecEncCtxBinaryEncrypt` past its first precondition.
///
/// # Safety
/// `tmpl` is null or a live node; `data` holds `size` bytes or is null.
pub(super) unsafe fn binary_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    data: *const u8,
    size: usize,
) -> c_int {
    let here = here!("xmlSecEncCtxBinaryEncrypt");
    if data.is_null() && size != 0 {
        errors::assertion(here, c"(data != NULL) || (dataSize == 0)");
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        if begin_encryption(ctx, tmpl, here) < 0 {
            return -1;
        }
        let data = if data.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, size)
        };
        encrypt_bytes(ctx, data, here)
    }
}

/// `xmlSecEncCtxXmlEncrypt` past its first precondition: `node` (an
/// `Element` template) or its content (a `Content` one) as libxml2 writes
/// it, encrypted into the template, which then takes its place.
///
/// # Safety
/// `tmpl` and `node` are null or live nodes.
pub(super) unsafe fn xml_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    node: *mut XmlNode,
) -> c_int {
    let here = here!("xmlSecEncCtxXmlEncrypt");
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        if begin_encryption(ctx, tmpl, here) < 0 {
            return -1;
        }
        // libxmlsec1 requires the Type: without it the decryptor could not
        // restore the document (XMLEnc 1.1 section 3.1).
        let element = match c_text(ctx.type_) {
            Some("http://www.w3.org/2001/04/xmlenc#Element") => true,
            Some("http://www.w3.org/2001/04/xmlenc#Content") => false,
            other => {
                // libxmlsec1's xmlSecInvalidStringTypeError.
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_TYPE,
                    &format!(
                        "invalid type for 'encryption type': actual={}; expected=supported encryption type",
                        other.unwrap_or("NULL")
                    ),
                );
                return -1;
            }
        };
        let text = if element {
            nodes::dump(node)
        } else {
            let mut text = String::new();
            let mut child = xsNodeGetChildren(node);
            while !child.is_null() {
                match nodes::dump(child) {
                    Some(dumped) => text.push_str(&dumped),
                    None => break,
                }
                child = nodes::next(child);
            }
            Some(text)
        };
        let Some(text) = text else {
            errors::xml_failed(here, std::ptr::null(), c"xmlNodeDumpOutput");
            return -1;
        };
        if encrypt_bytes(ctx, text.as_bytes(), here) < 0 {
            return -1;
        }
        let returned = if ctx.flags & FLAGS_RETURN_REPLACED_NODE != 0 {
            &raw mut ctx.replaced_node_list
        } else {
            std::ptr::null_mut()
        };
        let replaced = if element {
            xmlSecReplaceNodeAndReturn(node, tmpl, returned)
        } else {
            xmlSecReplaceContentAndReturn(node, tmpl, returned)
        };
        if replaced < 0 {
            let object = super::super::tree::name_for_report(node);
            errors::internal(here, object.as_ptr(), c"xmlSecReplaceNode");
            return -1;
        }
        ctx.result_replaced = 1;
    }
    0
}

/// `xmlSecTransformUriTypeLocal | xmlSecTransformUriTypeRemote`.
const URI_TYPES_EXTERNAL: std::ffi::c_uint = 0x0004 | 0x0008;

/// `xmlSecEncCtxUriEncrypt` past its first precondition: the resource `uri`
/// names, read through the caller's input callbacks, encrypted into the
/// template `tmpl`.
///
/// # Safety
/// `tmpl` is null or a live node; `uri` null or NUL-terminated.
pub(super) unsafe fn uri_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    uri: *const u8,
) -> c_int {
    let here = here!("xmlSecEncCtxUriEncrypt");
    for (holds, expression) in [
        (ctx.result.is_null(), c"encCtx->result == NULL"),
        (!tmpl.is_null(), c"tmpl != NULL"),
        (!uri.is_null(), c"uri != NULL"),
    ] {
        if !holds {
            errors::assertion(here, expression);
            return -1;
        }
    }
    ctx.operation = OPERATION_ENCRYPT;
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: a live node, the caller's string and the context's own
    // transform context.
    unsafe {
        add_ids(tmpl);
        // The caller names the resource, so local and remote URIs are
        // enabled for it; the encryption policy, which the chain's cipher
        // selects, bounds what is read.
        let saved = ctx.transform_ctx.enabled_uris;
        ctx.transform_ctx.enabled_uris |= URI_TYPES_EXTERNAL;
        let set = xmlSecTransformCtxSetUri(transforms, uri, tmpl);
        ctx.transform_ctx.enabled_uris = saved;
        if set < 0 {
            let text = c_text(uri).unwrap_or("NULL");
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxSetUri",
                &format!("uri={text}"),
            );
            return -1;
        }
        if read_enc_data(ctx, tmpl, true) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return -1;
        }
        if xmlSecTransformCtxExecute(transforms, xsNodeGetDoc(tmpl)) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
            return -1;
        }
        ctx.result = ctx.transform_ctx.result;
        if ctx.result.is_null() {
            errors::assertion(here, c"encCtx->result != NULL");
            return -1;
        }
        if write_enc_data(ctx) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeWrite");
            return -1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecEncCtxEncDataNodeWrite`: the method's parameters,
/// the cipher value and the `KeyInfo` of the template.
///
/// # Safety
/// The template was read and its result computed.
unsafe fn write_enc_data(ctx: &mut XmlSecEncCtx) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeWrite");
    // SAFETY: the context's method, nodes and result.
    unsafe {
        if !ctx.enc_method_node.is_null()
            && let Some(write) = (*(*ctx.enc_method).id).write_node
            && write(
                ctx.enc_method,
                ctx.enc_method_node,
                &raw mut ctx.transform_ctx,
            ) < 0
        {
            let object = super::super::tree::name_for_report(ctx.enc_method_node);
            errors::internal(here, object.as_ptr(), c"writeNode");
            return -1;
        }
        if !ctx.cipher_value_node.is_null() {
            let data = xmlSecBufferGetData(ctx.result);
            let size = xmlSecBufferGetSize(ctx.result);
            let text = if data.is_null() {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(data, size)).into_owned()
            };
            if nodes::set_content(ctx.cipher_value_node, &text).is_err() {
                errors::xml_failed(here, std::ptr::null(), c"xmlNodeSetContentLen");
                return -1;
            }
            ctx.result_replaced = 1;
        }
        if !ctx.key_info_node.is_null()
            && xmlSecKeyInfoNodeWrite(
                ctx.key_info_node,
                ctx.enc_key,
                &raw mut ctx.key_info_write_ctx,
            ) < 0
        {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoNodeWrite");
            return -1;
        }
    }
    0
}

/// `xmlSecEncCtxDecrypt` past its preconditions.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn decrypt(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxDecrypt");
    ctx.operation = OPERATION_DECRYPT;
    // SAFETY: a live node.
    let buffer = unsafe { decrypt_to_buffer(ctx, node) };
    if buffer.is_null() {
        errors::internal(here, std::ptr::null(), c"xmlSecEncCtxDecryptToBuffer");
        return -1;
    }
    // SAFETY: the context's result buffer.
    let (data, size) = unsafe { (xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer)) };
    let empty = [0_u8; 1];
    let (data, size) = if data.is_null() {
        (empty.as_ptr(), 0)
    } else {
        (data.cast_const(), size)
    };
    // An EncryptedData without a Type stays for the caller, who reads the
    // result as bytes.
    // SAFETY: the context's attribute string.
    let replace = matches!(
        unsafe { c_text(ctx.type_) },
        Some(
            "http://www.w3.org/2001/04/xmlenc#Element" | "http://www.w3.org/2001/04/xmlenc#Content"
        )
    );
    if !replace {
        return 0;
    }
    // SAFETY: the node and the result's bytes; the replaced list is the
    // context's.
    let replaced = unsafe {
        if ctx.flags & FLAGS_RETURN_REPLACED_NODE != 0 {
            xmlSecReplaceNodeBufferAndReturn(node, data, size, &raw mut ctx.replaced_node_list)
        } else {
            xmlSecReplaceNodeBuffer(node, data, size)
        }
    };
    if replaced < 0 {
        let object = super::super::tree::name_for_report(node);
        errors::internal(here, object.as_ptr(), c"xmlSecReplaceNodeBuffer");
        return -1;
    }
    ctx.result_replaced = 1;
    0
}

/// `xmlSecEncCtxDecryptToBuffer` past its first precondition.
///
/// # Safety
/// `node` is null or a live node.
pub(super) unsafe fn decrypt_to_buffer(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxDecryptToBuffer");
    ctx.operation = OPERATION_DECRYPT;
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return std::ptr::null_mut();
    }
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return std::ptr::null_mut();
    }
    // SAFETY: a live node.
    unsafe {
        if ctx.mode == MODE_ENCRYPTED_KEY {
            return encrypt_or_decrypt_to_buffer(ctx, node);
        }
        add_ids(node);
        if read_enc_data(ctx, node, false) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return std::ptr::null_mut();
        }
        // libxmlsec1 runs the callback when it prepares the decryption chain:
        // before any resource is read or anything decrypted, a negative
        // return refuses the operation.
        let transforms = &raw mut ctx.transform_ctx;
        if let Some(callback) = ctx.transform_ctx.pre_exec_callback
            && callback(transforms) < 0
        {
            errors::internal(
                here!("xmlSecTransformCtxPrepare"),
                std::ptr::null(),
                c"ctx->preExecCallback",
            );
            return std::ptr::null_mut();
        }
        run_decryption(ctx, node)
    }
}

/// libxmlsec1's `xmlSecEncCtxEncryptOrDecryptToBuffer` for an
/// `EncryptedKey`: the element read, then its chain run over the cipher
/// value or the data its `CipherReference` names, in the context's
/// operation. The key's own transport or wrap klass admits the method and
/// the key under the library policy, as a standalone chain does.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn encrypt_or_decrypt_to_buffer(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxEncryptOrDecryptToBuffer");
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return std::ptr::null_mut();
    }
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return std::ptr::null_mut();
    }
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: a live node, the context's own members and the trimmed copy
    // freed here.
    unsafe {
        add_ids(node);
        if read_enc_data(ctx, node, false) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return std::ptr::null_mut();
        }
        if ctx.cipher_value_node.is_null() {
            // An external CipherReference is read once, its octets kept for
            // the operation whose key this is: the core resolves every
            // CipherReference of the element it decrypts.
            let read = if ctx.operation == OPERATION_DECRYPT {
                let Some(pinned) = run_policy(transforms, here) else {
                    return std::ptr::null_mut();
                };
                let Some(read) = cipher_reference_resources(ctx, node, &pinned) else {
                    errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxUriExecute");
                    return std::ptr::null_mut();
                };
                read
            } else {
                ReadResources::default()
            };
            let executed = match read.first_bytes() {
                Some(bytes) => execute_on_bytes(transforms, bytes.as_ptr(), bytes.len()),
                None => xmlSecTransformCtxExecute(transforms, xsNodeGetDoc(node)),
            };
            run_budget(transforms).key_resources.append(read);
            if executed < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
                return std::ptr::null_mut();
            }
        } else {
            let data = xmlSecGetNodeContentAndTrim(ctx.cipher_value_node);
            if data.is_null() {
                errors::invalid_node_content(
                    here,
                    ctx.cipher_value_node,
                    std::ptr::null(),
                    "empty",
                );
                return std::ptr::null_mut();
            }
            let size = std::ffi::CStr::from_ptr(data.cast()).count_bytes();
            let executed = xmlSecTransformCtxBinaryExecute(transforms, data, size);
            super::super::free(data.cast());
            if executed < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxBinaryExecute");
                return std::ptr::null_mut();
            }
        }
        ctx.result = ctx.transform_ctx.result;
        if ctx.result.is_null() {
            errors::assertion(here, c"encCtx->result != NULL");
        }
        ctx.result
    }
}

/// libxmlsec1's `xmlSecEncCtxEncryptedKeyXmlWrite` past its preconditions:
/// the `EncryptedKey` template `node` read for an encryption, the key's
/// binary value encrypted through its chain and written into it.
///
/// # Safety
/// `node` is a live node; `key` a valid key; `key_info` the writing
/// `KeyInfo` context.
pub(super) unsafe fn encrypted_key_write(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
    key: *mut super::super::keys::XmlSecKey,
    key_info: *mut super::super::keyinfo::XmlSecKeyInfoCtx,
) -> c_int {
    let here = here!("xmlSecEncCtxEncryptedKeyXmlWrite");
    // SAFETY: by the caller's contract.
    unsafe {
        ctx.operation = super::encrypted_key::map_operation((*key_info).operation);
        if ctx.operation == 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"invalid operation",
                &format!("operation={}", (*key_info).operation),
            );
            return -1;
        }
        add_ids(node);
        if read_enc_data(ctx, node, true) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return -1;
        }
        let Some(value) = super::encrypted_key::key_binary(key, key_info) else {
            errors::internal(
                here,
                std::ptr::null(),
                c"xmlSecEncCtxEncryptedKeyWriteKeyToBinary",
            );
            return -1;
        };
        let written = encrypt_bytes(ctx, &value, here);
        ctx.result = std::ptr::null_mut();
        written
    }
}

/// libxmlsec1's `xmlSecEncCtxEncDataNodeRead`: the attributes, the method,
/// the cipher data and the key of the `EncryptedData` or `EncryptedKey`
/// element `node`, with a Base64 encoder after the method when an
/// encryption writes a `CipherValue` and `add_base64` asks.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_enc_data(ctx: &mut XmlSecEncCtx, node: *mut XmlNode, add_base64: bool) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeRead");
    let enc_ns = name!(xmlSecEncNs);
    for (holds, expression) in [
        (
            ctx.operation == OPERATION_ENCRYPT || ctx.operation == OPERATION_DECRYPT,
            c"(encCtx->operation == xmlSecTransformOperationEncrypt) || (encCtx->operation == xmlSecTransformOperationDecrypt)",
        ),
        (ctx.enc_data_node.is_null(), c"encCtx->encDataNode == NULL"),
        (ctx.id.is_null(), c"encCtx->id == NULL"),
        (ctx.type_.is_null(), c"encCtx->type == NULL"),
        (ctx.enc_method_node.is_null(), c"encCtx->encMethodNode == NULL"),
        (ctx.key_info_node.is_null(), c"encCtx->keyInfoNode == NULL"),
        (ctx.enc_method.is_null(), c"encCtx->encMethod == NULL"),
    ] {
        if !holds {
            errors::assertion(here, expression);
            return -1;
        }
    }
    ctx.enc_data_node = node;
    // SAFETY: live nodes of the caller's tree and the context's own members.
    unsafe {
        let (expected, label) = match ctx.mode {
            MODE_ENCRYPTED_KEY => (name!(xmlSecNodeEncryptedKey), "EncryptedKey"),
            _ => (name!(xmlSecNodeEncryptedData), "EncryptedData"),
        };
        if ctx.mode != MODE_ENCRYPTED_DATA && ctx.mode != MODE_ENCRYPTED_KEY {
            errors::unsupported_enum(here, std::ptr::null(), "mode", ctx.mode);
            return -1;
        }
        if !is(node, expected, enc_ns) {
            errors::invalid_node(here, node, label, std::ptr::null());
            return -1;
        }
        ctx.id = attribute(node, "Id");
        ctx.type_ = attribute(node, "Type");
        ctx.mime_type = attribute(node, "MimeType");
        ctx.encoding = attribute(node, "Encoding");
        if ctx.mode == MODE_ENCRYPTED_KEY {
            ctx.recipient = attribute(node, "Recipient");
        }
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeEncryptionMethod), enc_ns) {
            ctx.enc_method_node = cur;
            cur = next_element(cur);
        }
        if is(cur, name!(xmlSecNodeKeyInfo), name!(xmlSecDSigNs)) {
            ctx.key_info_node = cur;
            cur = next_element(cur);
        }
        if !is(cur, name!(xmlSecNodeCipherData), enc_ns) {
            errors::invalid_node(here, cur, "CipherData", std::ptr::null());
            return -1;
        }
        if read_cipher_data(ctx, cur) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxCipherDataNodeRead");
            return -1;
        }
        cur = next_element(cur);
        if is(cur, name!(xmlSecNodeEncryptionProperties), enc_ns) {
            cur = next_element(cur);
        }
        if ctx.mode == MODE_ENCRYPTED_KEY {
            if is(cur, name!(xmlSecNodeReferenceList), enc_ns) {
                cur = next_element(cur);
            }
            if is(cur, name!(xmlSecNodeCarriedKeyName), enc_ns) {
                ctx.carried_key_name = xmlSecGetNodeContentAndTrim(cur);
                if ctx.carried_key_name.is_null() {
                    errors::invalid_node_content(here, cur, std::ptr::null(), "empty");
                    return -1;
                }
                cur = next_element(cur);
            }
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
        read_method_and_key(ctx, add_base64)
    }
}

/// The method and key half of libxmlsec1's `xmlSecEncCtxEncDataNodeRead`:
/// the method from `EncryptionMethod` or the context's default, the key it
/// requires through the read `KeyInfo` context, and the Base64 encoder of
/// an encryption that writes a `CipherValue`.
///
/// # Safety
/// The context's element nodes were read.
unsafe fn read_method_and_key(ctx: &mut XmlSecEncCtx, add_base64: bool) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeRead");
    // SAFETY: the context's nodes and its own members.
    unsafe {
        let transforms = &raw mut ctx.transform_ctx;
        if !ctx.enc_method_node.is_null() {
            // The operation is known before the method is read, so a klass
            // reads its parameters under that operation's policy.
            ctx.enc_method = ctx_node_read_for(
                transforms,
                ctx.enc_method_node,
                USAGE_ENCRYPTION_METHOD,
                ctx.operation,
            );
            if ctx.enc_method.is_null() {
                errors::internal(
                    here,
                    c"EncryptionMethod".as_ptr(),
                    c"xmlSecTransformCtxNodeRead",
                );
                return -1;
            }
        } else if !ctx.def_enc_method_id.is_null() {
            ctx.enc_method = xmlSecTransformCtxCreateAndAppend(transforms, ctx.def_enc_method_id);
            if ctx.enc_method.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return -1;
            }
        } else {
            errors::invalid_data(here, std::ptr::null(), "encryption method not specified");
            return -1;
        }
        (*ctx.enc_method).operation = ctx.operation;
        ctx.key_info_read_ctx.operation = ctx.operation;
        ctx.key_info_write_ctx.operation = ctx.operation;
        let method_name = (*(*ctx.enc_method).id).name.cast();
        if xmlSecTransformSetKeyReq(ctx.enc_method, &raw mut ctx.key_info_read_ctx.key_req) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKeyReq");
            return -1;
        }
        let read = &raw mut ctx.key_info_read_ctx;
        if ctx.enc_key.is_null() {
            // The key is read under the revision the operation runs under,
            // the one its chain and its core decryption use, counting on from
            // what the operation spent.
            let Some(pinned) = run_policy(transforms, here) else {
                return -1;
            };
            let _read_pin = SlotPin::hold_pinned(
                &raw mut (*read).reserved0,
                pinned,
                external_spent(transforms),
            );
            let mngr = ctx.key_info_read_ctx.keys_mngr;
            if let Some(get_key) = mngr.as_ref().and_then(|mngr| mngr.get_key) {
                ctx.enc_key = get_key(ctx.key_info_node, read);
            }
            charge_key_read(transforms, (*read).reserved0);
        }
        if ctx.enc_key.is_null()
            || xmlSecKeyMatch(ctx.enc_key, std::ptr::null(), &raw mut (*read).key_req) == 0
        {
            let method = c_text((*(*ctx.enc_method).id).name).unwrap_or("NULL");
            errors::other(
                here,
                errors::R_KEY_NOT_FOUND,
                std::ptr::null(),
                Some(&format!("encMethod={method}")),
            );
            if ctx.failure_reason == FAILURE_UNKNOWN {
                ctx.failure_reason = FAILURE_KEY_NOT_FOUND;
            }
            return -1;
        }
        if xmlSecTransformSetKey(ctx.enc_method, ctx.enc_key.cast()) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKey");
            return -1;
        }
        if add_base64 && ctx.operation == OPERATION_ENCRYPT && !ctx.cipher_value_node.is_null() {
            let encode =
                xmlSecTransformCtxCreateAndAppend(transforms, xmlSecTransformBase64GetKlass());
            if encode.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return -1;
            }
            (*encode).operation = super::super::transforms::OPERATION_ENCODE;
            ctx.result_base64_encoded = 1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecEncCtxCipherDataNodeRead`: a `CipherValue`, decoded
/// from Base64 when decrypting, or a `CipherReference` read when decrypting.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_cipher_data(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxCipherDataNodeRead");
    let enc_ns = name!(xmlSecEncNs);
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: live nodes and the context's own transform context.
    unsafe {
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeCipherValue), enc_ns) {
            if ctx.operation == OPERATION_DECRYPT
                && xmlSecTransformCtxCreateAndPrepend(transforms, xmlSecTransformBase64GetKlass())
                    .is_null()
            {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCreateAndPrepend",
                );
                return -1;
            }
            ctx.cipher_value_node = cur;
            cur = next_element(cur);
        } else if is(cur, name!(xmlSecNodeCipherReference), enc_ns) {
            if ctx.operation == OPERATION_DECRYPT && read_cipher_reference(ctx, cur) < 0 {
                errors::internal(
                    here,
                    c"CipherReference".as_ptr(),
                    c"xmlSecEncCtxCipherReferenceNodeRead",
                );
                return -1;
            }
            cur = next_element(cur);
        } else if cur.is_null() {
            errors::invalid_data(
                here,
                std::ptr::null(),
                "CipherData node must contain either a CipherValue or a CipherReference node",
            );
            return -1;
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecEncCtxCipherReferenceNodeRead`: the start URI and
/// the transforms of a `CipherReference`.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_cipher_reference(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxCipherReferenceNodeRead");
    let transforms = &raw mut ctx.transform_ctx;
    let uri = attribute(node, "URI");
    // SAFETY: live nodes, the context's own transform context and the
    // copy freed here.
    unsafe {
        let set = xmlSecTransformCtxSetUri(transforms, uri, node);
        let text = c_text(uri).unwrap_or("NULL").to_owned();
        super::super::free(uri.cast());
        if set < 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxSetUri",
                &format!("uri={text}"),
            );
            return -1;
        }
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeTransforms), name!(xmlSecEncNs)) {
            if xmlSecTransformCtxNodesListRead(transforms, cur, USAGE_DSIG_TRANSFORM) < 0 {
                errors::internal(
                    here,
                    c"Transforms".as_ptr(),
                    c"xmlSecTransformCtxNodesListRead",
                );
                return -1;
            }
            cur = next_element(cur);
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
    }
    0
}

/// The content key of the context's key for its method, with the family the
/// core's resolver needs.
///
/// # Safety
/// The context's method and key are set.
unsafe fn content_key(ctx: &XmlSecEncCtx) -> Option<(DataEncryptionAlgorithm, Zeroizing<Vec<u8>>)> {
    // SAFETY: the method's klass and the key's value outlive the call.
    unsafe {
        let href = c_text((*(*ctx.enc_method).id).href)?;
        let algorithm = DataEncryptionAlgorithm::from_uri(href).ok()?;
        let buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(ctx.enc_key));
        let data = xmlSecBufferGetData(buffer);
        let size = xmlSecBufferGetSize(buffer);
        if data.is_null() || size < algorithm.key_len() {
            return None;
        }
        // libxmlsec1 takes the leading bytes of a longer key.
        let bytes = std::slice::from_raw_parts(data, algorithm.key_len()).to_vec();
        Some((algorithm, Zeroizing::new(bytes)))
    }
}

/// The octets of the external resource the `CipherReference` of an
/// `EncryptedData` or `EncryptedKey` names, read through the caller's input
/// callbacks under the decryption policy of the revision `pinned` and
/// charged to the context's chain; empty for a cipher value or a
/// same-document reference, `None` after a report.
///
/// # Safety
/// `node` is the read, live element of the context.
unsafe fn cipher_reference_resources(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
    pinned: &Pinned,
) -> Option<ReadResources> {
    let mut resources = ReadResources::default();
    // SAFETY: live nodes and the context's own transform context.
    unsafe {
        let mut cur = first_element(node);
        while !cur.is_null() && !is(cur, name!(xmlSecNodeCipherData), name!(xmlSecEncNs)) {
            cur = next_element(cur);
        }
        let reference = if cur.is_null() {
            cur
        } else {
            first_element(cur)
        };
        if !is(
            reference,
            name!(xmlSecNodeCipherReference),
            name!(xmlSecEncNs),
        ) {
            return Some(resources);
        }
        let Some(uri) = nodes::property(reference, "URI") else {
            return Some(resources);
        };
        if uri.is_empty() || uri.starts_with('#') {
            return Some(resources);
        }
        let Some(origin) = nodes::tree_node(reference).map(|(_, tree)| ExternalNode::from(tree))
        else {
            errors::internal(
                here!("xmlSecTransformCtxUriExecute"),
                std::ptr::null(),
                c"node identity",
            );
            return None;
        };
        let transforms = &raw mut ctx.transform_ctx;
        // Counted on from what the key's read spent: one allowance.
        let mut scope = ResourceScope::new(pinned, Side::Decrypt, external_spent(transforms));
        let bytes = read_resource(
            transforms,
            uri.as_bytes(),
            reference,
            xsNodeGetDoc(node),
            &mut scope,
        );
        run_budget(transforms).external_resources = scope.spent.external_resources;
        resources.push(origin, uri, bytes?);
    }
    Some(resources)
}

/// Runs the core decryption of the `EncryptedData` element `node` and makes
/// the plaintext the context's result, a buffer of its method.
///
/// # Safety
/// `node` is a live node; the context's method and key are set.
unsafe fn run_decryption(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxDecryptToBuffer");
    // The revision the key was read under (`read_method_and_key`).
    // SAFETY: the context's own transform context.
    let Some(pinned) = (unsafe { run_policy(&raw mut ctx.transform_ctx, here) }) else {
        return std::ptr::null_mut();
    };
    // SAFETY: the context's read nodes.
    let Some(mut resources) = (unsafe { cipher_reference_resources(ctx, node, &pinned) }) else {
        errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxUriExecute");
        return std::ptr::null_mut();
    };
    // The core resolves the CipherReference of every EncryptedKey in the
    // element's KeyInfo too: it takes the octets the key's read read.
    // SAFETY: the context's own transform context.
    resources.append(std::mem::take(unsafe {
        &mut run_budget(&raw mut ctx.transform_ctx).key_resources
    }));
    // SAFETY: the method and key were read.
    let Some((algorithm, key)) = (unsafe { content_key(ctx) }) else {
        errors::internal(here, std::ptr::null(), c"xmlSecKeyGetValue");
        return std::ptr::null_mut();
    };
    let Some(external) = nodes::tree_node(node).map(|(_, tree_node)| ExternalNode::from(tree_node))
    else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return std::ptr::null_mut();
    };
    let policy = std::sync::Arc::clone(&pinned.decryption);
    let (document, _) = match xml_sec_libxml2::document::snapshot(node, &*policy) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSecEncCtxDecryptToBuffer",
                &error.to_string(),
            );
            return std::ptr::null_mut();
        }
    };
    let Some(target) = document.with_view(|view| {
        let found = view.node_of_external(external)?;
        view.identity_of(found).ok()
    }) else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return std::ptr::null_mut();
    };
    let resources = match resources.into_keyed(&document, &policy.resources) {
        Ok(keyed) => keyed,
        Err(error) => {
            errors::invalid_data(here, std::ptr::null(), &error);
            return std::ptr::null_mut();
        }
    };
    let resolver = SymmetricKeyDecryptor::with_kind(key.to_vec(), algorithm.key_kind());
    let mut context = DecryptContext::new(&resolver)
        .shared_policy(policy)
        .external_resources(&resources.by_key);
    // An EncryptedData without EncryptionMethod uses the context's default
    // method, which the method was read from (`read_method_and_key`).
    if ctx.enc_method_node.is_null() {
        context = context.default_encryption_method(algorithm);
    }
    let decrypted = context.decrypt_in_document(&document, target);
    let plaintext = match decrypted.map(|audited| audited.output) {
        Ok(DecryptedContent::Xml(text)) => Zeroizing::new(text.into_bytes()),
        Ok(DecryptedContent::Bytes(bytes)) => Zeroizing::new(bytes),
        Err(error) => {
            // libxmlsec1 checks the padding itself and reports it as invalid
            // data; the crypto library reports the rest.
            let reason = if matches!(error, xml_sec::xmlenc::XmlEncError::InvalidPadding) {
                errors::R_INVALID_DATA
            } else {
                errors::R_CRYPTO_FAILED
            };
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                reason,
                &error.to_string(),
            );
            return std::ptr::null_mut();
        }
    };
    // The method's output buffer holds the plaintext, owned by the chain as
    // libxmlsec1's result is owned by the chain's last transform.
    // SAFETY: the context's method.
    unsafe {
        let buffer = &raw mut (*ctx.enc_method).out_buf;
        if xmlSecBufferSetData(buffer, plaintext.as_ptr(), plaintext.len()) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecBufferSetData");
            return std::ptr::null_mut();
        }
        ctx.result = buffer;
        buffer
    }
}
