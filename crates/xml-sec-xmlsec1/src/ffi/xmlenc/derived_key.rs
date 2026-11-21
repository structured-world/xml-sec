//! `DerivedKey` in a `KeyInfo`: the key data klass and the derivation the
//! encryption context a `KeyInfo` context keeps runs for it.
//!
//! Reading, the nested context reads the `KeyDerivationMethod` through the
//! registered derivation klasses, finds the master key by its
//! `MasterKeyName` and runs the derivation, which the klass admits under the
//! library policy; the derived bytes become a key of the klass the `KeyInfo`
//! requires. Writing changes nothing: the template already names what the
//! recipient derives.

use std::cell::Cell;
use std::ffi::{CString, c_int, c_void};

use xml_sec::policy::KeyNameSemantics;

use super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::errors::{self, check, here};
use super::super::keyinfo::{MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx};
use super::super::keys::{
    XmlSecKey, key_valid, xmlSecKeyCopy, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeyMatch,
    xmlSecKeyReqMatchKey, xmlSecKeySetName,
};
use super::super::keysdata::{
    XmlSecKeyDataKlass, xmlSecKeyDataBinRead, xmlSecKeyDataDerivedKeyGetKlass,
};
use super::super::keysmngr::xmlSecKeysMngrFindKey;
use super::super::policy::{Side, SlotPin};
use super::super::transforms::ctx::{
    charge_key_info, ctx_node_read_for, operation_side, run_budget, run_policy, run_spent,
    xmlSecTransformCtxBinaryExecute,
};
use super::super::transforms::{
    USAGE_KEY_DERIVATION_METHOD, xmlSecTransformSetKey, xmlSecTransformSetKeyReq,
};
use super::super::tree::{XmlNode, c_text, nodes};
use super::super::xmltree::key_name_content;
use super::super::{contain, free, strings};
use super::encrypted_key::{
    FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION, level_allowed, level_open, map_operation,
    within_key_info, xmlSecKeyInfoCtxCreateEncCtx,
};
use super::key_source::{self, Descriptor};
use super::process::{add_ids, first_element, is, next_element};
use super::{FAILURE_KEY_NOT_FOUND, FAILURE_UNKNOWN, XmlSecEncCtx};

#[cfg(test)]
mod tests;

/// The name the key name element `node` carries under `key_names`, copied,
/// after libxmlsec1's report of an unreadable one at `here`.
///
/// # Safety
/// `node` is a live node.
unsafe fn name_of_node(
    node: *mut XmlNode,
    key_names: KeyNameSemantics,
    here: errors::Here,
) -> Option<CString> {
    // SAFETY: a live node; the copy the call returns is freed here.
    unsafe {
        let content = key_name_content(node, key_names);
        if content.is_null() {
            errors::invalid_node_content(here, node, std::ptr::null(), "empty");
            return None;
        }
        let name = std::ffi::CStr::from_ptr(content.cast()).to_owned();
        free(content.cast());
        Some(name)
    }
}

/// `xmlSecEncCtxDerivedKeyGenerate`: the key the `DerivedKey` `node`
/// derives for `key_info`, a key of `key_id` read from the derived octets
/// and named by its `DerivedKeyName`; null after a report.
///
/// # Safety
/// `ctx` is null or an initialized context; `key_id` null or a klass;
/// `node` null or a live node; `key_info` null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEncCtxDerivedKeyGenerate(
    ctx: *mut XmlSecEncCtx,
    key_id: *const XmlSecKeyDataKlass,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecEncCtxDerivedKeyGenerate");
        // SAFETY: each pointer is dereferenced only once the earlier
        // conditions hold.
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
                return std::ptr::null_mut();
            }
        }
        // SAFETY: by the caller's contract.
        unsafe { derive(&mut *ctx, key_id, node, key_info, here) }
    })
}

/// [`xmlSecEncCtxDerivedKeyGenerate`] past its preconditions.
///
/// # Safety
/// As for [`xmlSecEncCtxDerivedKeyGenerate`], with every pointer valid.
unsafe fn derive(
    ctx: &mut XmlSecEncCtx,
    key_id: *const XmlSecKeyDataKlass,
    node: *mut XmlNode,
    key_info: *mut XmlSecKeyInfoCtx,
    here: errors::Here,
) -> *mut XmlSecKey {
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
            return std::ptr::null_mut();
        }
        add_ids(node);
        // libxmlsec1 knows no implied derivation: the method is required,
        // though XML Encryption 1.1 section 5.4 lets a recipient know it.
        let cur = first_element(node);
        if !is(
            cur,
            strings::xmlSecNodeKeyDerivationMethod.as_ptr(),
            strings::xmlSecEnc11Ns.as_ptr(),
        ) {
            errors::invalid_node(here, cur, "KeyDerivationMethod", std::ptr::null());
            return std::ptr::null_mut();
        }
        let transforms = &raw mut ctx.transform_ctx;
        ctx.enc_method =
            ctx_node_read_for(transforms, cur, USAGE_KEY_DERIVATION_METHOD, ctx.operation);
        if ctx.enc_method.is_null() {
            let name = nodes::name(cur).and_then(|name| CString::new(name).ok());
            errors::internal(
                here,
                name.as_deref()
                    .map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
                c"xmlSecTransformCtxNodeRead",
            );
            return std::ptr::null_mut();
        }
        // The key's width is the one the `KeyInfo` reading it requires.
        (*ctx.enc_method).expected_output_size = (*key_info).key_req.key_bits_size / 8;
        (*ctx.enc_method).operation = ctx.operation;
        ctx.key_info_read_ctx.operation = ctx.operation;
        ctx.key_info_write_ctx.operation = ctx.operation;
        let Some(pinned) = run_policy(transforms, here) else {
            return std::ptr::null_mut();
        };
        let key_names = pinned
            .of(operation_side(ctx.operation).unwrap_or(Side::Decrypt))
            .key_names();
        let Some((derived_name, master_name)) = names(next_element(cur), key_names, here) else {
            return std::ptr::null_mut();
        };
        if !key_method(ctx, master_name.as_deref(), here) {
            return std::ptr::null_mut();
        }
        let key = generate_key(ctx, key_id, key_info);
        if key.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxGenerateKey");
            return std::ptr::null_mut();
        }
        if let Some(name) = derived_name
            && xmlSecKeySetName(key, name.as_ptr().cast()) < 0
        {
            errors::internal(here, std::ptr::null(), c"xmlSecKeySetName");
            xmlSecKeyDestroy(key);
            return std::ptr::null_mut();
        }
        key
    }
}

/// The `DerivedKeyName` and `MasterKeyName` of a `DerivedKey` whose children
/// after its method start at `cur`, read under `key_names`; `None` after a
/// report at `here` for an unreadable name or a child past them.
///
/// # Safety
/// `cur` is null or a live node.
unsafe fn names(
    mut cur: *mut XmlNode,
    key_names: KeyNameSemantics,
    here: errors::Here,
) -> Option<(Option<CString>, Option<CString>)> {
    // SAFETY: by the caller's contract; each next sibling is live.
    unsafe {
        // The ReferenceList names the data the key serves; the core holds
        // the decryption to it, the read passes it, as libxmlsec1 does.
        if is(
            cur,
            strings::xmlSecNodeReferenceList.as_ptr(),
            strings::xmlSecEncNs.as_ptr(),
        ) {
            cur = next_element(cur);
        }
        let mut found = [None, None];
        for (slot, name) in found.iter_mut().zip([
            strings::xmlSecNodeDerivedKeyName.as_ptr(),
            strings::xmlSecNodeMasterKeyName.as_ptr(),
        ]) {
            if is(cur, name, strings::xmlSecEnc11Ns.as_ptr()) {
                *slot = Some(name_of_node(cur, key_names, here)?);
                cur = next_element(cur);
            }
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return None;
        }
        let [derived, master] = found;
        Some((derived, master))
    }
}

/// Keys the context's method with its master key: the context's own key, or
/// the one named `master` the keys manager finds, under the operation's
/// revision and key candidates; `false` after a report at `here`, marking
/// the context's failure when no master key matches.
///
/// # Safety
/// The context's method was read.
unsafe fn key_method(
    ctx: &mut XmlSecEncCtx,
    master: Option<&std::ffi::CStr>,
    here: errors::Here,
) -> bool {
    // SAFETY: the context's own members, method and keys manager.
    unsafe {
        let method_name = (*(*ctx.enc_method).id).name.cast();
        let transforms = &raw mut ctx.transform_ctx;
        let read = &raw mut ctx.key_info_read_ctx;
        if xmlSecTransformSetKeyReq(ctx.enc_method, &raw mut (*read).key_req) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKeyReq");
            return false;
        }
        if ctx.enc_key.is_null() && !(*read).keys_mngr.is_null() {
            // The master key is found under the revision the operation runs
            // under, counting on from what the operation spent.
            let Some(pinned) = run_policy(transforms, here) else {
                return false;
            };
            let side = operation_side(ctx.operation).unwrap_or(Side::Decrypt);
            let _read_pin = SlotPin::hold_pinned(
                &raw mut (*read).reserved0,
                pinned.clone(),
                run_spent(transforms),
                run_budget(transforms)
                    .key_candidates
                    .within(pinned.of(side).resources().max_key_candidates),
            );
            ctx.enc_key = xmlSecKeysMngrFindKey(
                (*read).keys_mngr,
                master.map_or(std::ptr::null(), |name| name.as_ptr().cast()),
                read,
            );
            if !charge_key_info(
                transforms,
                (*read).reserved0,
                pinned.of(side).resources(),
                here,
            ) {
                return false;
            }
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
            return false;
        }
        if xmlSecTransformSetKey(ctx.enc_method, ctx.enc_key.cast()) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKey");
            return false;
        }
        true
    }
}

/// libxmlsec1's `xmlSecEncCtxGenerateKey`: runs the context's chain, whose
/// method produces key octets, and reads them as a key of `key_id` with
/// `key_info`; null after a report.
///
/// # Safety
/// The context's method was read and keyed; `key_id` is null or a klass;
/// `key_info` an initialized context.
pub(super) unsafe fn generate_key(
    ctx: &mut XmlSecEncCtx,
    key_id: *const XmlSecKeyDataKlass,
    key_info: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    let here = here!("xmlSecEncCtxGenerateKey");
    if ctx.enc_method.is_null() {
        errors::assertion(here, c"encCtx->encMethod != NULL");
        return std::ptr::null_mut();
    }
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return std::ptr::null_mut();
    }
    // SAFETY: the context's own chain and result buffer, a fresh key and the
    // caller's klass and context.
    unsafe {
        let method_name = (*(*ctx.enc_method).id).name.cast();
        let transforms = &raw mut ctx.transform_ctx;
        if xmlSecTransformCtxBinaryExecute(transforms, std::ptr::null(), 0) < 0
            || (*transforms).result.is_null()
        {
            errors::internal(here, method_name, c"xmlSecTransformCtxBinaryExecute");
            return std::ptr::null_mut();
        }
        ctx.result = (*transforms).result;
        let data = xmlSecBufferGetData(ctx.result);
        let size = xmlSecBufferGetSize(ctx.result);
        if data.is_null() || size == 0 {
            errors::internal(
                here,
                method_name,
                c"xmlSecTransformCtxBinaryExecute(no data)",
            );
            return std::ptr::null_mut();
        }
        let key = xmlSecKeyCreate();
        if key.is_null() {
            errors::internal(here, method_name, c"xmlSecKeyCreate");
            return std::ptr::null_mut();
        }
        if xmlSecKeyDataBinRead(key_id, key.cast(), data, size, key_info.cast()) < 0 {
            let klass_name = key_id
                .as_ref()
                .map_or(std::ptr::null(), |klass| klass.name.cast());
            errors::internal(here, klass_name, c"xmlSecKeyDataBinRead");
            xmlSecKeyDestroy(key);
            return std::ptr::null_mut();
        }
        key
    }
}

/// Checks the arguments of the klass methods, reporting under `func`.
macro_rules! method_arguments {
    ($func:literal, $id:expr, $key:expr, $node:expr, $ctx:expr, $mode:expr, $mode_expr:literal) => {
        check!(
            std::ptr::eq($id, xmlSecKeyDataDerivedKeyGetKlass()),
            $func,
            c"id == xmlSecKeyDataDerivedKeyId",
            -1
        );
        check!(!$key.is_null(), $func, c"key != NULL", -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        check!(!$ctx.is_null(), $func, c"keyInfoCtx != NULL", -1);
        // SAFETY: a context.
        check!(unsafe { (*$ctx).mode } == $mode, $func, $mode_expr, -1);
    };
}

/// `xmlRead` of the `DerivedKey` klass: the key the `DerivedKey` `node`
/// derives, by the context's nested encryption context. A key that is not
/// derived, or not one the `KeyInfo` may use, leaves `key` empty for the
/// next child unless the context stops on it.
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
            "xmlSecKeyDataDerivedKeyXmlRead",
            id,
            key,
            node,
            ctx,
            MODE_READ,
            c"keyInfoCtx->mode == xmlSecKeyInfoModeRead"
        );
        let here = here!("xmlSecKeyDataDerivedKeyXmlRead");
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
            // The derivation's run is seeded under the side of the operation
            // the key is read for, the one the generation derives under.
            (*enc).operation = map_operation((*ctx).operation);
            (*enc).transform_ctx.parent_key_info_ctx = ctx.cast();
            let generated = Cell::new(std::ptr::null_mut::<XmlSecKey>());
            let done = within_key_info(
                ctx,
                enc,
                || {
                    generated.set(xmlSecEncCtxDerivedKeyGenerate(
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
                // A limit of the operation refused the derivation.
                if !generated.is_null() {
                    xmlSecKeyDestroy(generated);
                }
                return -1;
            }
            if generated.is_null() {
                // Several DerivedKey elements may derive the key for
                // different recipients.
                if (*ctx).flags & FLAGS_ENCKEY_STOP_ON_FAILED_DECRYPTION != 0 {
                    errors::internal(here, name, c"xmlSecEncCtxDerivedKeyGenerate");
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
            let source = key_source::of(ctx, node, generated, Descriptor::derived);
            let copied = xmlSecKeyCopy(key, generated);
            xmlSecKeyDestroy(generated);
            if copied < 0 {
                errors::internal(here, name, c"xmlSecKeyCopy");
                return -1;
            }
            // The decryption reading with this key takes it for this
            // DerivedKey alone.
            key_source::record(ctx, source);
        }
        0
    })
}

/// `xmlWrite` of the `DerivedKey` klass: the template already names what the
/// recipient derives, so nothing is written.
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
        check!(
            std::ptr::eq(id, xmlSecKeyDataDerivedKeyGetKlass()),
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"id == xmlSecKeyDataDerivedKeyId",
            -1
        );
        check!(
            !key.is_null(),
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"key != NULL",
            -1
        );
        // SAFETY: a key.
        let valid = unsafe { key_valid(key) };
        check!(
            valid,
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"xmlSecKeyIsValid(key)",
            -1
        );
        check!(
            !node.is_null(),
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        let writes = unsafe { (*ctx).mode } == MODE_WRITE;
        check!(
            writes,
            "xmlSecKeyDataDerivedKeyXmlWrite",
            c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite",
            -1
        );
        0
    })
}
