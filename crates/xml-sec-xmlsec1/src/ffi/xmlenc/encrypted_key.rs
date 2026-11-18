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
use super::super::keyinfo::{next_reference_depth, read_policy};
use super::super::keys::{XmlSecKey, key_valid};
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataBinRead, xmlSecKeyDataBinWrite,
    xmlSecKeyDataEncryptedKeyGetKlass,
};
use super::super::list::xmlSecPtrListEmpty;
use super::super::transforms::ctx::{operation_side, run_budget, run_spent, seed_run};
use super::super::transforms::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, OPERATION_SIGN, OPERATION_VERIFY,
};
use super::super::tree::{XmlNode, nodes};
use super::super::xmltree::{trimmed_content, xmlSecFindChild};
use super::super::{contain, free, policy};
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

/// Whether `ctx` may open one more `EncryptedKey` level under its own
/// maximum, after libxmlsec1's report under `here`; checked before the node
/// is read at all.
///
/// # Safety
/// `ctx` is an initialized context; `id` a klass.
unsafe fn level_allowed(
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

/// Whether the policy admits one more `EncryptedKey` level in `ctx`, whose
/// own maximum [`level_allowed`] checked: the policy's
/// `max_key_info_reference_depth` of the operation the key is decrypted or
/// encrypted for bounds the levels of `EncryptedKey` and key references
/// together, as the core bounds an `EncryptedKey` nested in a `KeyInfo`
/// (XML Encryption 1.1 section 3.5.1), whatever maximum the caller set. A
/// key that `recovers` is bounded by the decryption policy it is recovered
/// under, whatever operation reads it.
///
/// # Safety
/// `ctx` is an initialized context; `id` a klass.
unsafe fn level_open(
    ctx: *mut XmlSecKeyInfoCtx,
    id: *const XmlSecKeyDataKlass,
    here: errors::Here,
    recovers: bool,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let name = (*id).name.cast();
        let Some(pinned) = read_policy(ctx, here) else {
            return false;
        };
        let side = if recovers {
            policy::Side::Decrypt
        } else {
            operation_side(map_operation((*ctx).operation)).unwrap_or(policy::Side::Verify)
        };
        let resources = pinned.of(side).resources();
        if resources
            .validate_key_info_reference_depth(next_reference_depth(ctx))
            .is_err()
        {
            errors::limit_exceeded(
                here,
                name,
                "EncryptedKey depth",
                resources.max_key_info_reference_depth,
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
            // An EncryptedKey that carries its ciphertext is a transported
            // key to recover whatever operation reads it (a signer reusing
            // the session key a request carried). libxmlsec1 follows the
            // outer operation, which wraps the ciphertext text on the
            // signing side; only an empty template, whose key the signing
            // or encrypting side generates, keeps that direction. The
            // direction is chosen first, so its policy bounds the depth;
            // the caller's own maximum is checked before the node is read.
            if !level_allowed(ctx, id, here) {
                return -1;
            }
            let recovers = carries_ciphertext(node);
            if !level_open(ctx, id, here, recovers) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            if recovers {
                (*enc).operation = OPERATION_DECRYPT;
                (*enc).key_info_read_ctx.operation = OPERATION_DECRYPT;
            }
            // A transport recovering a key of a fixed width learns it from
            // the requirements of this context.
            (*enc).transform_ctx.parent_key_info_ctx = ctx.cast();
            let read = within_key_info(
                ctx,
                enc,
                || xmlSecEncCtxEncryptedKeyXmlRead(enc, node, key, ctx),
                // libxmlsec1 returns success without a key for a recipient
                // it could not decrypt, unless told to stop on that.
                || !(*key).value.is_null(),
            );
            if read < 0 {
                errors::internal(here, name, c"xmlSecEncCtxEncryptedKeyXmlRead");
            }
            read
        }
    })
}

/// Whether the `EncryptedKey` `node` already carries its ciphertext: a
/// `CipherReference`, or a `CipherValue` with content. An empty
/// `CipherValue` is a template the signing or encrypting side fills.
///
/// # Safety
/// `node` is a live node.
unsafe fn carries_ciphertext(node: *mut XmlNode) -> bool {
    let ns = c"http://www.w3.org/2001/04/xmlenc#".as_ptr().cast();
    // SAFETY: a live node; the names are NUL-terminated.
    unsafe {
        let data = xmlSecFindChild(node, c"CipherData".as_ptr().cast(), ns);
        if data.is_null() {
            return false;
        }
        if !xmlSecFindChild(data, c"CipherReference".as_ptr().cast(), ns).is_null() {
            return true;
        }
        let value = xmlSecFindChild(data, c"CipherValue".as_ptr().cast(), ns);
        !value.is_null() && trimmed_content(value).is_some_and(|text| !text.is_empty())
    }
}

/// Runs `work`, the decryption or encryption of an `EncryptedKey` with the
/// nested context `enc`, as a part of the `KeyInfo` read or write with
/// `ctx`: under its revision and the side of the nested operation, counting
/// on from what the `KeyInfo` operation spent of the per-operation budgets
/// and key candidates and handing back what `work` spent, whether it
/// succeeds or not, so a failed recipient leaves the next no fresh
/// allowance and one
/// allowance bounds the operation. A resource limit `work` reached ends the
/// `KeyInfo` operation: the budget is spent, so no later recipient is tried
/// under it. `yielded` tells, once `work` succeeded, whether it produced a
/// key: only then does its recoveries' validity go with the operation.
///
/// # Safety
/// `ctx` is a `KeyInfo` context whose nested context is `enc`; `work` runs
/// `enc` for it.
pub(super) unsafe fn within_key_info(
    ctx: *mut XmlSecKeyInfoCtx,
    enc: *mut XmlSecEncCtx,
    work: impl FnOnce() -> c_int,
    yielded: impl FnOnce() -> bool,
) -> c_int {
    // SAFETY: by the caller's contract; the pin outlives the call.
    unsafe {
        let transforms = &raw mut (*enc).transform_ctx;
        let slot = (*ctx).reserved0;
        let before = policy::spent(slot).map_or_default(std::cell::Cell::get);
        if let Some(pinned) = policy::pinned(slot) {
            let side = operation_side((*enc).operation).unwrap_or(policy::Side::Verify);
            seed_run(transforms, pinned, side, None, before);
        }
        if let Some(candidates) = policy::key_candidates(slot) {
            run_budget(transforms).key_candidates = candidates.get();
        }
        let done = work();
        if let Some(spent) = policy::spent(slot) {
            let mut after = run_spent(transforms);
            // A recovery's validity belongs to the key it yields: that of a
            // recipient yielding none, nested recoveries included, goes
            // with it.
            if done < 0 || !yielded() {
                after.recovery = before.recovery;
            }
            spent.set(after);
        }
        if let Some(candidates) = policy::key_candidates(slot) {
            candidates.set(run_budget(transforms).key_candidates);
        }
        if run_budget(transforms).resource_limit_reached {
            return -1;
        }
        done
    }
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
            if !level_allowed(ctx, id, here) || !level_open(ctx, id, here, false) {
                return -1;
            }
            let name = (*id).name.cast();
            if xmlSecKeyInfoCtxCreateEncCtx(ctx) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxCreateEncCtx");
                return -1;
            }
            let enc = (*ctx).enc_ctx.cast::<XmlSecEncCtx>();
            // Writing recovers no key, so no validity rides on its outcome.
            let written = within_key_info(
                ctx,
                enc,
                || xmlSecEncCtxEncryptedKeyXmlWrite(enc, node, key, ctx),
                || true,
            );
            if written < 0 {
                errors::internal(here, name, c"xmlSecEncCtxEncryptedKeyXmlWrite");
                return -1;
            }
        }
        0
    })
}
