//! `AgreementMethod` in a `KeyInfo`: the key data klass and the agreement
//! the encryption context a `KeyInfo` context keeps runs for it.
//!
//! The `AgreementMethod` element is itself the transform: reading it, the
//! nested context reads it through the registered key agreement klasses,
//! which find both parties' keys and derive the key under the library
//! policy; the derived bytes become a key of the klass the `KeyInfo`
//! requires, carrying the parties' keys. Writing puts those parties' public
//! keys into the template's role elements.

use std::cell::Cell;
use std::ffi::{CString, c_int, c_void};

use super::super::contain;
use super::super::errors::{self, check, here};
use super::super::keyinfo::{MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx};
use super::super::keys::{
    XmlSecKey, key_valid, xmlSecKeyAdoptData, xmlSecKeyCopy, xmlSecKeyDestroy, xmlSecKeyGetData,
    xmlSecKeyReqMatchKey,
};
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataAgreementMethodGetKlass, xmlSecKeyDataDestroy,
    xmlSecKeyDataDuplicate,
};
use super::super::transforms::USAGE_AGREEMENT_METHOD;
use super::super::transforms::ctx::{
    ctx_node_read_for, xmlSecTransformCtxExtraKeyDataAdopt, xmlSecTransformCtxExtraKeyDataGet,
};
use super::super::transforms::kam::kam_klass_id;
use super::super::tree::{XmlNode, nodes};
use super::XmlSecEncCtx;
use super::derived_key::generate_key;
use super::encrypted_key::{
    FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION, level_allowed, level_open, map_operation,
    within_key_info, xmlSecKeyInfoCtxCreateEncCtx,
};
use super::process::add_ids;

/// libxmlsec1's assertions of the two `xmlSecEncCtxAgreementMethod*`
/// functions, reported at `here`; false after the first that fails.
///
/// # Safety
/// Each pointer is null or valid.
unsafe fn arguments(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
    here: errors::Here,
) -> bool {
    // SAFETY: each pointer is dereferenced only once the earlier conditions
    // hold.
    let holds = |index: usize| unsafe {
        match index {
            0 => !ctx.is_null(),
            1 => (*ctx).enc_method.is_null(),
            2 => !node.is_null(),
            3 => !nodes::doc(node).is_null(),
            _ => !key_info.is_null(),
        }
    };
    for (index, expression) in [
        c"encCtx != NULL",
        c"encCtx->encMethod == NULL",
        c"node != NULL",
        c"node->doc != NULL",
        c"keyInfoCtx != NULL",
    ]
    .into_iter()
    .enumerate()
    {
        if !holds(index) {
            errors::assertion(here, expression);
            return false;
        }
    }
    true
}

/// Reads the `AgreementMethod` `node` as the method of `ctx` for the
/// operation of `key_info`, the transform taking the parties' keys through
/// that context's keys manager; `false` after a report at `here`.
///
/// # Safety
/// Every pointer is valid.
unsafe fn read_method(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
    here: errors::Here,
) -> bool {
    // SAFETY: the caller's live node and contexts and the context's own
    // members.
    unsafe {
        ctx.operation = map_operation((*key_info).operation);
        if ctx.operation == 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"invalid operation",
                &format!("operation={}", (*key_info).operation),
            );
            return false;
        }
        add_ids(node);
        let transforms = &raw mut ctx.transform_ctx;
        ctx.transform_ctx.parent_key_info_ctx = key_info.cast();
        ctx.enc_method = ctx_node_read_for(transforms, node, USAGE_AGREEMENT_METHOD, ctx.operation);
        if ctx.enc_method.is_null() {
            let name = nodes::name(node).and_then(|name| CString::new(name).ok());
            errors::internal(
                here,
                name.as_deref()
                    .map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
                c"xmlSecTransformCtxNodeRead",
            );
            return false;
        }
        (*ctx.enc_method).operation = ctx.operation;
        ctx.key_info_read_ctx.operation = ctx.operation;
        ctx.key_info_write_ctx.operation = ctx.operation;
        true
    }
}

/// `xmlSecEncCtxAgreementMethodGenerate`: the key the `AgreementMethod`
/// `node` agrees on for `key_info`, a key of `key_id` read from the derived
/// octets; null after a report.
///
/// # Safety
/// `ctx` is null or an initialized context; `key_id` null or a klass;
/// `node` null or a live node; `key_info` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxAgreementMethodGenerate(
    ctx: *mut XmlSecEncCtx,
    key_id: *const XmlSecKeyDataKlass,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecEncCtxAgreementMethodGenerate");
        // SAFETY: by the caller's contract.
        unsafe {
            if !arguments(ctx, node, key_info, here)
                || !read_method(&mut *ctx, node, key_info, here)
            {
                return std::ptr::null_mut();
            }
            let ctx = &mut *ctx;
            // The key's width is the one the `KeyInfo` reading it requires;
            // with none the agreement falls back to its derivation's.
            (*ctx.enc_method).expected_output_size = (*key_info).key_req.key_bits_size / 8;
            // The agreement needs no key of its own: both parties' keys are
            // the ones its element names.
            let key = generate_key(ctx, key_id, key_info);
            if key.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecEncCtxGenerateKey");
            }
            key
        }
    })
}

/// `xmlSecEncCtxAgreementMethodXmlWrite`: writes the parties' public keys
/// into the `AgreementMethod` template `node` with `ctx`.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node;
/// `key_info` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxAgreementMethodXmlWrite(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecEncCtxAgreementMethodXmlWrite");
        // SAFETY: by the caller's contract.
        unsafe {
            if !arguments(ctx, node, key_info, here)
                || !read_method(&mut *ctx, node, key_info, here)
            {
                return -1;
            }
            let ctx = &mut *ctx;
            let method = ctx.enc_method;
            if let Some(write_node) = (*(*method).id).write_node
                && write_node(method, node, &raw mut ctx.transform_ctx) < 0
            {
                let name = nodes::name(node).and_then(|name| CString::new(name).ok());
                errors::internal(
                    here,
                    name.as_deref()
                        .map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
                    c"writeNode",
                );
                return -1;
            }
        }
        0
    })
}

/// Checks the arguments of the klass methods, reporting under `func`.
macro_rules! method_arguments {
    ($func:literal, $id:expr, $key:expr, $node:expr, $ctx:expr, $mode:expr, $mode_expr:literal) => {
        check!(
            std::ptr::eq($id, xmlSecKeyDataAgreementMethodGetKlass()),
            $func,
            c"id == xmlSecKeyDataAgreementMethodId",
            -1
        );
        check!(!$key.is_null(), $func, c"key != NULL", -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        check!(!$ctx.is_null(), $func, c"keyInfoCtx != NULL", -1);
        // SAFETY: a context.
        check!(unsafe { (*$ctx).mode } == $mode, $func, $mode_expr, -1);
    };
}

/// `xmlRead` of the `AgreementMethod` klass: the key the `AgreementMethod`
/// `node` agrees on, by the context's nested encryption context. A key that
/// does not agree, or is not one the `KeyInfo` may use, leaves `key` empty
/// for the next child unless the context stops on it.
pub(crate) unsafe extern "C" fn xml_read(
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
        method_arguments!(
            "xmlSecKeyDataAgreementMethodXmlRead",
            id,
            key,
            node,
            ctx,
            MODE_READ,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead"
        );
        let here = here!("xmlSecKeyDataAgreementMethodXmlRead");
        // SAFETY: a klass, a key, a live node and a context.
        unsafe {
            if !level_allowed(ctx, id, here) || !level_open(ctx, id, here, false) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            // The agreement's run is seeded under the side of the operation
            // the key is read for, the one it agrees under.
            (*enc).operation = map_operation((*ctx).operation);
            (*enc).transform_ctx.parent_key_info_ctx = ctx.cast();
            let generated = Cell::new(std::ptr::null_mut::<XmlSecKey>());
            let done = within_key_info(
                ctx,
                enc,
                || {
                    generated.set(xmlSecEncCtxAgreementMethodGenerate(
                        enc,
                        (*ctx).key_req.key_id,
                        node,
                        ctx,
                    ));
                    0
                },
                || !generated.get().is_null(),
            );
            let generated = generated.get();
            if done < 0 {
                // A limit of the operation refused the agreement.
                if !generated.is_null() {
                    xmlSecKeyDestroy(generated);
                }
                return -1;
            }
            if generated.is_null() {
                // Several AgreementMethod elements may agree for different
                // recipients.
                if (*ctx).flags & FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION != 0 {
                    errors::internal(here, name, c"xmlSecEncCtxAgreementMethodGenerate");
                    return -1;
                }
                return 0;
            }
            let matched = xmlSecKeyReqMatchKey(&raw mut (*ctx).key_req, generated);
            if matched < 0 {
                errors::internal(here, name, c"xmlSecKeyReqMatchKey");
                xmlSecKeyDestroy(generated);
                return -1;
            }
            if matched == 0 {
                // A key the request may not use is passed over.
                xmlSecKeyDestroy(generated);
                return 0;
            }
            let copied = xmlSecKeyCopy(key, generated);
            xmlSecKeyDestroy(generated);
            if copied < 0 {
                errors::internal(here, name, c"xmlSecKeyCopy");
                return -1;
            }
            // The parties' keys go with the key, so writing it reuses them.
            let parties =
                xmlSecTransformCtxExtraKeyDataGet(&raw mut (*enc).transform_ctx, kam_klass_id());
            if !parties.is_null() {
                let copy = xmlSecKeyDataDuplicate(parties);
                if copy.is_null() {
                    errors::internal(here, name, c"xmlSecKeyDataDuplicate(kamKeyData)");
                    return -1;
                }
                if xmlSecKeyAdoptData(key, copy) < 0 {
                    errors::internal(here, name, c"xmlSecKeyAdoptData");
                    xmlSecKeyDataDestroy(copy);
                    return -1;
                }
            }
        }
        0
    })
}

/// `xmlWrite` of the `AgreementMethod` klass: the parties' public keys the
/// key carries, written into the `AgreementMethod` template `node` by the
/// context's nested encryption context.
pub(crate) unsafe extern "C" fn xml_write(
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
        method_arguments!(
            "xmlSecKeyDataAgreementMethodXmlWrite",
            id,
            key,
            node,
            ctx,
            MODE_WRITE,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite"
        );
        let here = here!("xmlSecKeyDataAgreementMethodXmlWrite");
        // SAFETY: a klass, a key, a live node and a context.
        unsafe {
            if !key_valid(key) {
                errors::assertion(here, c"xmlSecKeyIsValid(key)");
                return -1;
            }
            if !level_allowed(ctx, id, here) || !level_open(ctx, id, here, false) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            // The parties' keys the key carries spare the write their lookup.
            let parties = xmlSecKeyGetData(key, kam_klass_id());
            if !parties.is_null() {
                let copy = xmlSecKeyDataDuplicate(parties);
                if copy.is_null() {
                    errors::internal(here, name, c"xmlSecKeyDataDuplicate(kamKeyData)");
                    return -1;
                }
                if xmlSecTransformCtxExtraKeyDataAdopt(&raw mut (*enc).transform_ctx, copy) < 0 {
                    errors::internal(here, name, c"xmlSecTransformCtxExtraKeyDataAdopt");
                    xmlSecKeyDataDestroy(copy);
                    return -1;
                }
            }
            // Writing recovers no key, so no validity rides on its outcome.
            let written = within_key_info(
                ctx,
                enc,
                || xmlSecEncCtxAgreementMethodXmlWrite(enc, node, ctx),
                || true,
            );
            if written < 0 {
                errors::internal(here, name, c"xmlSecEncCtxAgreementMethodXmlWrite");
                return -1;
            }
        }
        0
    })
}
