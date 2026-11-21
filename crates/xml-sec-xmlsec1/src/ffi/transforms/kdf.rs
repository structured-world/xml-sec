//! The built-in provider's key derivation klasses: `ConcatKDF`, PBKDF2 and
//! HKDF, the `KeyDerivationMethod` of a `DerivedKey` or an `AgreementMethod`.
//!
//! Reading its `KeyDerivationMethod` the transform takes the parameters the
//! core parses there. It takes no input: on the final call it derives the
//! width its reader expects (`expectedOutputSize`) from the key's binary
//! value through the selected provider, once the run's policy admitted the
//! derivation and its digest, charging the operation's key establishment
//! allowance.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::policy::PolicyViolation;
use xml_sec::xmlenc::{KeyDerivationMethod, KeyEstablishmentBudget, XmlEncError};
use zeroize::Zeroizing;

use super::super::buffer::{xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::errors::{self, Here, here};
use super::super::keys::{TYPE_SYMMETRIC, XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::{XmlSecKeyDataKlass, check_id, xmlSecKeyDataBinaryValueGetBuffer};
use super::super::policy::{OperationPolicy, Pinned, Side, with_document_policy};
use super::super::tree::XmlNode;
use super::super::{contain, strings, symkeys};
use super::builtin::klass;
use super::ctx::{Limit, operation_side, run_budget, run_policy, run_scope};
use super::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, STATUS_FINISHED, STATUS_NONE, STATUS_WORKING,
    USAGE_KEY_DERIVATION_METHOD, WithContext, XmlSecKeyReq, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, valid, xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPushBin,
};

/// `xmlSecKeyUsageKeyDerive`.
const KEY_USAGE_KEY_DERIVE: c_uint = 0x0000_0020;

/// The state of a key derivation.
struct Kdf {
    /// The parameters the `KeyDerivationMethod` names, with the side whose
    /// policy they were read under.
    method: Option<(KeyDerivationMethod, Side)>,
    /// The key's binary value, from `setKey`.
    secret: Option<Zeroizing<Vec<u8>>>,
}

#[cfg(test)]
mod tests;

/// A derivation klass of `name` and `href`.
const fn kdf_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        read_node: Some(read_node),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Kdf>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_KEY_DERIVATION_METHOD,
        )
    }
}

static CONCAT_KDF: XmlSecTransformKlass =
    kdf_klass(&strings::xmlSecNameConcatKdf, &strings::xmlSecHrefConcatKdf);
static PBKDF2: XmlSecTransformKlass =
    kdf_klass(&strings::xmlSecNamePbkdf2, &strings::xmlSecHrefPbkdf2);
static HKDF: XmlSecTransformKlass = kdf_klass(&strings::xmlSecNameHkdf, &strings::xmlSecHrefHkdf);

/// The built-in table's `ConcatKDF` klass.
pub(crate) extern "C" fn concat_kdf() -> *const XmlSecTransformKlass {
    &raw const CONCAT_KDF
}

/// The built-in table's PBKDF2 klass.
pub(crate) extern "C" fn pbkdf2() -> *const XmlSecTransformKlass {
    &raw const PBKDF2
}

/// The built-in table's HKDF klass.
pub(crate) extern "C" fn hkdf() -> *const XmlSecTransformKlass {
    &raw const HKDF
}

/// The key-data klass whose binary value klass `id` derives from, `None`
/// for any other klass.
fn key_klass(id: *const XmlSecTransformKlass) -> Option<*const XmlSecKeyDataKlass> {
    if std::ptr::eq(id, &raw const CONCAT_KDF) {
        Some(symkeys::concat_kdf())
    } else if std::ptr::eq(id, &raw const PBKDF2) {
        Some(symkeys::pbkdf2())
    } else if std::ptr::eq(id, &raw const HKDF) {
        Some(symkeys::hkdf())
    } else {
        None
    }
}

/// The derivation object of a valid transform of these klasses, with the
/// key-data klass it derives from, after libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform; a transform of these klasses was
/// initialized.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(
    &'a mut XmlSecTransform,
    *const XmlSecKeyDataKlass,
    &'a mut Kdf,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the derivation layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = key_klass(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Kdf>>()).then_some(found)
        });
        let Some(key_id) = found else {
            errors::assertion(here, c"xmlSecOpenSSLKdfCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Kdf>>();
        Some((&mut with.transform, key_id, &mut with.context))
    }
}

/// The transform's name for a report.
fn name_of(transform: &XmlSecTransform) -> *const std::ffi::c_char {
    // SAFETY: a valid transform's klass outlives it.
    unsafe { (*transform.id).name.cast() }
}

/// Whether `transform` encrypts or decrypts, after libxmlsec1's assertion.
fn encrypts_or_decrypts(transform: &XmlSecTransform, here: Here) -> bool {
    let holds =
        transform.operation == OPERATION_ENCRYPT || transform.operation == OPERATION_DECRYPT;
    if !holds {
        errors::assertion(
            here,
            c"((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt))",
        );
    }
    holds
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    contain(-1, || {
        // SAFETY: the dispatcher passes a transform of these klasses, whose
        // zeroed tail is written here.
        unsafe {
            if valid(transform)
                .and_then(|(object, _)| key_klass(object.id))
                .is_none()
            {
                errors::assertion(
                    here!("xmlSecOpenSSLKdfInitialize"),
                    c"xmlSecOpenSSLKdfCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Kdf>>()).context).write(Kdf {
                method: None,
                secret: None,
            });
        }
        0
    })
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    contain((), || {
        // SAFETY: an initialized transform of these klasses; its state is
        // dropped once.
        unsafe {
            if valid(transform)
                .and_then(|(object, _)| key_klass(object.id))
                .is_some()
            {
                std::ptr::drop_in_place(&raw mut (*transform.cast::<WithContext<Kdf>>()).context);
            }
        }
    });
}

/// The policy revision of the run of `ctx` and the side a derivation by
/// `transform` falls under: the operation the transform serves once it is
/// known, which a reader naming it sets before the transform joins a chain,
/// and the run's side before that.
///
/// # Safety
/// `ctx` is an initialized context whose chain is live.
pub(super) unsafe fn scope(
    transform: &XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    here: Here,
) -> Option<(Pinned, Side)> {
    // SAFETY: by the caller's contract.
    unsafe {
        match operation_side(transform.operation) {
            Some(side) => Some((run_policy(ctx, here)?, side)),
            None => run_scope(ctx, here),
        }
    }
}

/// The parameters of the `KeyDerivationMethod` element `node`, as the core
/// parses them under `operation`'s policy; the reason otherwise.
pub(super) fn parse_method(
    node: *mut XmlNode,
    operation: OperationPolicy<'_>,
) -> Result<KeyDerivationMethod, String> {
    with_document_policy!(operation, |policy| {
        xml_sec_libxml2::document::subtree(node, policy)
            .map_err(|error| error.to_string())
            .and_then(|document| {
                document.with_view(|view| {
                    KeyDerivationMethod::from_element(
                        view.document().root_element(),
                        operation.resources(),
                    )
                    .map_err(|error| error.to_string())
                })
            })
    })
}

/// The read `method` under the policy of `side`, `operation`: a method read
/// before its operation was known is read again from its element `node`;
/// `None` after a report at `here`.
pub(super) fn method_under<'a>(
    method: &'a mut Option<(KeyDerivationMethod, Side)>,
    node: *mut XmlNode,
    operation: OperationPolicy<'_>,
    side: Side,
    here: Here,
) -> Option<&'a KeyDerivationMethod> {
    match method {
        None => {
            errors::assertion(here, c"ctx->paramsInitialized != 0");
            return None;
        }
        Some((_, read)) if *read != side => {
            if node.is_null() {
                errors::assertion(here, c"transform->hereNode != NULL");
                return None;
            }
            match parse_method(node, operation) {
                Ok(parsed) => *method = Some((parsed, side)),
                Err(error) => {
                    errors::report(
                        here,
                        std::ptr::null(),
                        std::ptr::null(),
                        errors::R_INVALID_TRANSFORM,
                        &error,
                    );
                    return None;
                }
            }
        }
        Some(_) => {}
    }
    method.as_ref().map(|(parsed, _)| parsed)
}

/// `readNode`: the parameters of the `KeyDerivationMethod` element `node`,
/// as the core parses them under the policy of the derivation's side.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKdfNodeRead");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, kdf)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        // SAFETY: a non-null, initialized context.
        let Some((pinned, side)) = (unsafe { scope(object, ctx, here) }) else {
            return -1;
        };
        match parse_method(node, pinned.of(side)) {
            Ok(method) => {
                kdf.method = Some((method, side));
                0
            }
            Err(error) => {
                errors::report(
                    here,
                    name_of(object),
                    std::ptr::null(),
                    errors::R_INVALID_TRANSFORM,
                    &error,
                );
                -1
            }
        }
    })
}

/// `setKeyReq`: a symmetric key of the derivation's key-data klass.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKdfSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((_, key_id, _)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        // SAFETY: null or the caller's key requirements.
        let Some(req) = (unsafe { req.as_mut() }) else {
            errors::assertion(here, c"keyReq != NULL");
            return -1;
        };
        req.key_id = key_id;
        req.key_type = TYPE_SYMMETRIC;
        req.key_usage = KEY_USAGE_KEY_DERIVE;
        0
    })
}

/// `setKey`: the binary value of a key of the derivation's key-data klass.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKdfSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, key_id, kdf)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !encrypts_or_decrypts(object, here) {
            return -1;
        }
        if key.is_null() {
            errors::assertion(here, c"key != NULL");
            return -1;
        }
        // SAFETY: a key whose value is null or key data.
        unsafe {
            let value = xmlSecKeyGetValue(key);
            if !check_id(value, key_id) {
                errors::assertion(here, c"xmlSecKeyCheckId(key, ctx->keyId)");
                return -1;
            }
            let buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
            let size = xmlSecBufferGetSize(buffer);
            let data = xmlSecBufferGetData(buffer);
            if size == 0 || data.is_null() {
                errors::report(
                    here,
                    name_of(object),
                    std::ptr::null(),
                    errors::R_INVALID_KEY_DATA_SIZE,
                    "invalid zero key data size",
                );
                return -1;
            }
            kdf.secret = Some(Zeroizing::new(
                std::slice::from_raw_parts(data, size).to_vec(),
            ));
        }
        0
    })
}

/// `execute`: takes no input; on the final call derives the expected width.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKdfExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, kdf)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !encrypts_or_decrypts(object, here) {
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        // A derivation consumes no input: data pushed into it is the
        // caller's error, never dropped silently.
        // SAFETY: the transform's own input buffer.
        if unsafe { xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
            errors::assertion(here, c"xmlSecBufferGetSize(in) == 0");
            return -1;
        }
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        if object.status == STATUS_FINISHED {
            return 0;
        }
        if object.status != STATUS_WORKING {
            errors::invalid_status(here, name_of(object), object.status);
            return -1;
        }
        if last == 0 {
            return 0;
        }
        let name = name_of(object);
        let width = object.expected_output_size;
        if width == 0 {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_SIZE,
                "KDF output key size is not specified",
            );
            return -1;
        }
        // SAFETY: a non-null, initialized context.
        let Some((pinned, side)) = (unsafe { scope(object, ctx, here) }) else {
            return -1;
        };
        let Some(method) = method_under(
            &mut kdf.method,
            object.here_node,
            pinned.of(side),
            side,
            here,
        ) else {
            return -1;
        };
        let Some(secret) = kdf.secret.as_deref() else {
            errors::assertion(here, c"ctx->paramsInitialized != 0");
            return -1;
        };
        // SAFETY: a non-null, initialized context.
        let run = unsafe { run_budget(ctx) };
        // A refusal ends the operation: no later part derives under it.
        if let Some(limit) = run.refused_by {
            errors::limit_exceeded(here, name, limit.name, limit.max);
            return -1;
        }
        let output = match derive(
            method,
            width,
            secret,
            pinned.of(side).key_establishment(),
            &mut run.key_establishment,
        ) {
            Ok(output) => output,
            Err(XmlEncError::Policy(PolicyViolation::ResourceLimit {
                resource, maximum, ..
            })) => {
                // The operation's allowance is spent: the operation ends
                // wherever its parts hand it back.
                run.refused_by = run.refused_by.or(Some(Limit {
                    name: resource,
                    max: maximum,
                }));
                errors::limit_exceeded(here, name, resource, maximum);
                return -1;
            }
            Err(error) => {
                errors::report(
                    here,
                    name,
                    std::ptr::null(),
                    errors::R_CRYPTO_FAILED,
                    &error.to_string(),
                );
                return -1;
            }
        };
        // The output buffer of a derivation was made secure when the
        // transform was created, as libxmlsec1 makes it.
        // SAFETY: the transform's own output buffer.
        let appended =
            unsafe { xmlSecBufferAppend(&raw mut object.out_buf, output.as_ptr(), output.len()) };
        if appended < 0 {
            errors::internal(here, name, c"xmlSecBufferAppend");
            return -1;
        }
        object.status = STATUS_FINISHED;
        0
    })
}

/// Derives `width` octets from `secret` by `method` under `policy`, counting
/// on from `usage`, the operation's earlier reservations, and leaving it
/// what the operation has reserved, failed attempts included.
fn derive(
    method: &KeyDerivationMethod,
    width: usize,
    secret: &[u8],
    policy: &xml_sec::policy::KeyEstablishmentPolicy,
    usage: &mut xml_sec::key_establishment::KeyEstablishmentUsage,
) -> Result<Zeroizing<Vec<u8>>, XmlEncError> {
    let mut budget = KeyEstablishmentBudget::resume(policy, *usage)?;
    let derived = method.derive_key(
        width,
        xml_sec::provider::default_provider(),
        secret,
        &mut budget,
    );
    *usage = budget.usage();
    derived
}
