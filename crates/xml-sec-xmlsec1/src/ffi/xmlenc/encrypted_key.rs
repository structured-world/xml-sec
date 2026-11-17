//! `EncryptedKey` in a `KeyInfo`: the key data klass and the encryption
//! context a `KeyInfo` context keeps for it.
//!
//! Reading, the nested context decrypts the `EncryptedKey` through its
//! chain, the method's transport or wrap klass admitting it under the
//! library policy, and the recovered bytes become a key of the klass the
//! `KeyInfo` requires. Writing, the key's binary value is encrypted into
//! the `EncryptedKey` template as the template's chain encrypts.

use std::ffi::{c_int, c_uint, c_void};

use zeroize::Zeroizing;

use super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::errors::{self, check, here};
use super::super::keyinfo::{
    MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, xmlSecKeyInfoCtxCopyUserPref,
    xmlSecKeyInfoCtxFinalize, xmlSecKeyInfoCtxInitialize,
};
use super::super::keys::{XmlSecKey, key_valid};
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataBinRead, xmlSecKeyDataBinWrite,
    xmlSecKeyDataEncryptedKeyGetKlass,
};
use super::super::list::xmlSecPtrListEmpty;
use super::super::transforms::ctx::pin_run;
use super::super::transforms::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, OPERATION_SIGN, OPERATION_VERIFY,
};
use super::super::tree::{XmlNode, nodes};
use super::super::{contain, free};
use super::{
    MODE_ENCRYPTED_KEY, XmlSecEncCtx, process, xmlSecEncCtxCreate, xmlSecEncCtxDestroy,
    xmlSecEncCtxReset,
};

/// `XMLSEC_KEYINFO_FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION`.
const FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION: c_uint = 0x0000_1000;
/// `XMLSEC_ERRORS_R_MAX_ENCKEY_LEVEL`.
const R_MAX_ENCKEY_LEVEL: c_int = 61;
/// `xmlSecKeyDataTypeAny`.
const TYPE_ANY: c_uint = 0xFFFF;

/// libxmlsec1's `xmlSecEncCtxMapOperation`: the encryption operation of a
/// `KeyInfo` operation, `xmlSecTransformOperationNone` for any other.
pub(super) const fn map_operation(operation: c_int) -> c_int {
    match operation {
        OPERATION_SIGN | OPERATION_ENCRYPT => OPERATION_ENCRYPT,
        OPERATION_VERIFY | OPERATION_DECRYPT => OPERATION_DECRYPT,
        _ => 0,
    }
}

/// libxmlsec1's `xmlSecEncCtxEncryptedKeyWriteKeyToBinary`: the binary
/// value of `key`'s data, written with `key_info`'s preferences for any key
/// type.
///
/// # Safety
/// `key` is a valid key; `key_info` an initialized context.
pub(super) unsafe fn key_binary(
    key: *mut XmlSecKey,
    key_info: *mut XmlSecKeyInfoCtx,
) -> Option<Zeroizing<Vec<u8>>> {
    let mut local = std::mem::MaybeUninit::<XmlSecKeyInfoCtx>::uninit();
    let local = local.as_mut_ptr();
    // SAFETY: a local context initialized here and finalized on every path;
    // the buffer the klass allocates is copied, cleansed and freed.
    unsafe {
        if xmlSecKeyInfoCtxInitialize(local, std::ptr::null_mut()) < 0 {
            return None;
        }
        let mut value = None;
        if xmlSecKeyInfoCtxCopyUserPref(local, key_info) >= 0 {
            (*local).key_req.key_type = TYPE_ANY;
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut size = 0_usize;
            let id = (*(*key).value).id;
            if xmlSecKeyDataBinWrite(id, key.cast(), &raw mut buf, &raw mut size, local.cast()) >= 0
                && !buf.is_null()
            {
                let bytes = std::slice::from_raw_parts_mut(buf, size);
                value = Some(Zeroizing::new(bytes.to_vec()));
                zeroize::Zeroize::zeroize(bytes);
                free(buf.cast());
            }
        }
        xmlSecKeyInfoCtxFinalize(local);
        value
    }
}

/// Empties the user lists of `ctx`, as libxmlsec1's
/// `xmlSecKeyInfoCtxClearUserPrefLists` does before copying preferences
/// again.
///
/// # Safety
/// `ctx` is an initialized context.
unsafe fn clear_user_lists(ctx: *mut XmlSecKeyInfoCtx) {
    // SAFETY: by the caller's contract.
    unsafe {
        xmlSecPtrListEmpty(&raw mut (*ctx).enabled_key_data);
        xmlSecPtrListEmpty(&raw mut (*ctx).retrieval_method_ctx.enabled_transforms);
        xmlSecPtrListEmpty(&raw mut (*ctx).key_info_reference_ctx.enabled_transforms);
    }
}

/// `xmlSecKeyInfoCtxCreateEncCtx`: creates or resets the encryption context
/// `ctx` keeps for an `EncryptedKey` child, one level deeper, with `ctx`'s
/// preferences.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyInfoCtxCreateEncCtx(ctx: *mut XmlSecKeyInfoCtx) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecKeyInfoCtxCreateEncCtx",
            c"keyInfoCtx != NULL",
            -1
        );
        let here = here!("xmlSecKeyInfoCtxCreateEncCtx");
        // SAFETY: an initialized context; the nested context it owns is
        // created here or was created by an earlier call.
        unsafe {
            let context = &mut *ctx;
            let Some(level) = context.cur_encrypted_key_level.checked_add(1) else {
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    R_MAX_ENCKEY_LEVEL,
                    &format!("cur={}", context.cur_encrypted_key_level),
                );
                return -1;
            };
            let mut enc = context.enc_ctx.cast::<XmlSecEncCtx>();
            if enc.is_null() {
                enc = xmlSecEncCtxCreate(context.keys_mngr);
                if enc.is_null() {
                    errors::internal(here, std::ptr::null(), c"xmlSecEncCtxCreate");
                    return -1;
                }
                context.enc_ctx = enc.cast();
            } else {
                xmlSecEncCtxReset(enc);
                clear_user_lists(&raw mut (*enc).key_info_read_ctx);
                clear_user_lists(&raw mut (*enc).key_info_write_ctx);
            }
            let nested = &mut *enc;
            nested.mode = MODE_ENCRYPTED_KEY;
            nested.operation = map_operation(context.operation);
            for inner in [
                &mut nested.key_info_read_ctx,
                &mut nested.key_info_write_ctx,
            ] {
                inner.operation = nested.operation;
                inner.cur_key_info_reference_level = context.cur_key_info_reference_level;
                inner.cur_retrieval_method_level = context.cur_retrieval_method_level;
                inner.cur_encrypted_key_level = level;
            }
            // Writing reads the inner EncryptedKey's KeyInfo through the read
            // context, so both take the preferences.
            let targets: &[*mut XmlSecKeyInfoCtx] = match context.mode {
                MODE_READ => &[&raw mut nested.key_info_read_ctx],
                MODE_WRITE => &[
                    &raw mut nested.key_info_write_ctx,
                    &raw mut nested.key_info_read_ctx,
                ],
                _ => &[],
            };
            for &target in targets {
                if xmlSecKeyInfoCtxCopyUserPref(target, ctx) < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoCtxCopyUserPref");
                    xmlSecEncCtxDestroy(enc);
                    context.enc_ctx = std::ptr::null_mut();
                    return -1;
                }
            }
        }
        0
    })
}

/// `xmlSecEncCtxEncryptedKeyXmlRead`: decrypts the `EncryptedKey` `node`
/// with `ctx` and reads the recovered bytes into `key` as a key of the klass
/// `key_info` requires. A key that does not decrypt leaves `key` empty for
/// the next recipient unless `key_info` stops on it.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node;
/// `key` null or a key; `key_info` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxEncryptedKeyXmlRead(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
    key: *mut XmlSecKey,
    key_info: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        check!(
            !ctx.is_null(),
            "xmlSecEncCtxEncryptedKeyXmlRead",
            c"encCtx != NULL",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecEncCtxEncryptedKeyXmlRead",
            c"key != NULL",
            -1
        );
        // SAFETY: a key.
        let empty = unsafe { (*key).value.is_null() };
        check!(
            empty,
            "xmlSecEncCtxEncryptedKeyXmlRead",
            c"key->value == NULL",
            -1
        );
        check!(
            !key_info.is_null(),
            "xmlSecEncCtxEncryptedKeyXmlRead",
            c"keyInfoCtx != NULL",
            -1
        );
        let here = here!("xmlSecEncCtxEncryptedKeyXmlRead");
        // SAFETY: by the caller's contract; the result is the nested
        // context's buffer.
        unsafe {
            let result = if (*ctx).operation == OPERATION_DECRYPT {
                process::decrypt_to_buffer(&mut *ctx, node)
            } else {
                process::encrypt_or_decrypt_to_buffer(&mut *ctx, node)
            };
            if result.is_null() || xmlSecBufferGetData(result).is_null() {
                // Several EncryptedKey elements may carry the key for
                // different recipients.
                if (*key_info).flags & FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION != 0 {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecEncCtxEncryptOrDecryptToBuffer",
                    );
                    return -1;
                }
                return 0;
            }
            let id = (*key_info).key_req.key_id;
            if id.is_null() {
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_KEY_DATA,
                    "key id is not set",
                );
                return -1;
            }
            if xmlSecKeyDataBinRead(
                id,
                key.cast(),
                xmlSecBufferGetData(result),
                xmlSecBufferGetSize(result),
                key_info.cast(),
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyDataBinRead");
                return -1;
            }
        }
        0
    })
}

/// `xmlSecEncCtxEncryptedKeyXmlWrite`: encrypts `key`'s binary value into
/// the `EncryptedKey` template `node` with `ctx`.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` null or a live node;
/// `key` null or a key; `key_info` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxEncryptedKeyXmlWrite(
    ctx: *mut XmlSecEncCtx,
    node: *mut XmlNode,
    key: *mut XmlSecKey,
    key_info: *mut XmlSecKeyInfoCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecEncCtxEncryptedKeyXmlWrite");
        // SAFETY: each pointer is dereferenced only once the earlier
        // conditions hold.
        let holds = |index: usize| unsafe {
            match index {
                0 => !ctx.is_null(),
                1 => (*ctx).enc_method.is_null(),
                2 => !node.is_null(),
                3 => !nodes::doc(node).is_null(),
                4 => !key.is_null(),
                _ => !key_info.is_null(),
            }
        };
        for (index, expression) in [
            c"encCtx != NULL",
            c"encCtx->encMethod == NULL",
            c"node != NULL",
            c"node->doc != NULL",
            c"key != NULL",
            c"keyInfoCtx != NULL",
        ]
        .into_iter()
        .enumerate()
        {
            if !holds(index) {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: by the caller's contract.
        unsafe {
            if !key_valid(key) {
                errors::assertion(here, c"key->value != NULL");
                return -1;
            }
            process::encrypted_key_write(&mut *ctx, node, key, key_info)
        }
    })
}

/// Checks the arguments of the klass methods, reporting under `func`.
macro_rules! method_arguments {
    ($func:literal, $id:expr, $key:expr, $node:expr, $ctx:expr, $mode:expr, $mode_expr:literal) => {
        check!(
            std::ptr::eq($id, xmlSecKeyDataEncryptedKeyGetKlass()),
            $func,
            c"id == xmlSecKeyDataEncryptedKeyId",
            -1
        );
        check!(!$key.is_null(), $func, c"key != NULL", -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        check!(!$ctx.is_null(), $func, c"keyInfoCtx != NULL", -1);
        // SAFETY: a context.
        check!(unsafe { (*$ctx).mode } == $mode, $func, $mode_expr, -1);
    };
}

/// Whether `ctx` may open one more `EncryptedKey` level, after libxmlsec1's
/// report under `here`.
///
/// # Safety
/// `ctx` is an initialized context; `id` a klass.
unsafe fn level_open(
    ctx: *mut XmlSecKeyInfoCtx,
    id: *const XmlSecKeyDataKlass,
    here: errors::Here,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let (current, maximum) = (
            (*ctx).cur_encrypted_key_level,
            (*ctx).max_encrypted_key_level,
        );
        if current >= maximum {
            errors::report(
                here,
                (*id).name.cast(),
                std::ptr::null(),
                R_MAX_ENCKEY_LEVEL,
                &format!("cur={current};max={maximum}"),
            );
            return false;
        }
    }
    true
}

/// `xmlRead` of the `EncryptedKey` klass: the key the `EncryptedKey` `node`
/// carries, decrypted by the context's nested encryption context.
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
            "xmlSecKeyDataEncryptedKeyXmlRead",
            id,
            key,
            node,
            ctx,
            MODE_READ,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead"
        );
        // SAFETY: a key.
        let empty = unsafe { (*key).value.is_null() };
        check!(
            empty,
            "xmlSecKeyDataEncryptedKeyXmlRead",
            c"key->value == NULL",
            -1
        );
        let here = here!("xmlSecKeyDataEncryptedKeyXmlRead");
        // SAFETY: a klass, a key, a live node and a context.
        unsafe {
            if !level_open(ctx, id, here) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            // A transport recovering a key of a fixed width learns it from
            // the requirements of this context.
            (*enc).transform_ctx.parent_key_info_ctx = ctx.cast();
            // The key is decrypted under the revision of the read it serves.
            if let Some(pinned) = super::super::policy::pinned((*ctx).reserved0) {
                pin_run(&raw mut (*enc).transform_ctx, pinned);
            }
            if xmlSecEncCtxEncryptedKeyXmlRead(enc, node, key, ctx) < 0 {
                errors::internal(here, name, c"xmlSecEncCtxEncryptedKeyXmlRead");
                return -1;
            }
        }
        0
    })
}

/// `xmlWrite` of the `EncryptedKey` klass: `key` encrypted into the
/// `EncryptedKey` template `node` by the context's nested encryption
/// context.
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
            "xmlSecKeyDataEncryptedKeyXmlWrite",
            id,
            key,
            node,
            ctx,
            MODE_WRITE,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite"
        );
        let here = here!("xmlSecKeyDataEncryptedKeyXmlWrite");
        // SAFETY: a klass, a key, a live node and a context.
        unsafe {
            if !key_valid(key) {
                errors::assertion(here, c"xmlSecKeyIsValid(key)");
                return -1;
            }
            if !level_open(ctx, id, here) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            if xmlSecEncCtxEncryptedKeyXmlWrite(enc, node, key, ctx) < 0 {
                errors::internal(here, name, c"xmlSecEncCtxEncryptedKeyXmlWrite");
                return -1;
            }
        }
        0
    })
}
