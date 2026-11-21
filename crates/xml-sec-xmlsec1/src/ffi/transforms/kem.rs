//! The built-in provider's ML-KEM key transport klasses (`ml-kem-512`,
//! `ml-kem-768`, `ml-kem-1024`): an `EncryptedKey` whose `EncryptionMethod`
//! names one carries the FIPS 203 ciphertext in its `CipherValue`
//! (draft-eastlake-rfc9231bis-xmlsec-uris section 3.6.9), and the shared
//! secret is the key it transports.
//!
//! Encrypting, the transform takes no input: it encapsulates to the
//! recipient's public key and keeps the ciphertext in the context's
//! `kem-cipher-value` key data, which the `EncryptedKey` write serializes;
//! when that key data already holds a ciphertext, the transform outputs it.
//! Decrypting, it decapsulates its input with the recipient's private key.
//! The secret is cut to the width the reading `KeyInfo` requires, as
//! libxmlsec1 cuts it. Encapsulation and decapsulation run in the core under
//! the run's key establishment policy and allowance.

use std::ffi::{c_char, c_int, c_uint, c_void};

use xml_sec::key_establishment::KeyEstablishmentError;
use xml_sec::policy::PolicyViolation;
use xml_sec::provider::{
    KeyEncapsulationAlgorithm, RustCryptoMlKemPrivateKey, RustCryptoMlKemPublicKey,
};
use zeroize::Zeroizing;

use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferAppend, xmlSecBufferEmpty, xmlSecBufferFinalize, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferInitialize, xmlSecBufferMakeSecure, xmlSecBufferSetData,
    xmlSecBufferSetSize,
};
use super::super::errors::{self, Here, here};
use super::super::keys::{TYPE_PRIVATE, TYPE_PUBLIC, XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::{XmlSecKeyData, XmlSecKeyDataKlass, check_id, data_valid};
use super::super::mlkemkeys;
use super::super::strings::{
    xmlSecHrefMLKEM512, xmlSecHrefMLKEM768, xmlSecHrefMLKEM1024, xmlSecNameMLKEM512,
    xmlSecNameMLKEM768, xmlSecNameMLKEM1024,
};
use super::super::{contain, write_stream};
use super::builtin::klass;
use super::ctx::{Limit, run_budget, xmlSecTransformCtxExtraKeyDataEnsure};
use super::kdf::scope;
use super::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, STATUS_FINISHED, STATUS_NONE, STATUS_WORKING,
    USAGE_ENCRYPTION_METHOD, WithContext, XmlSecKeyReq, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, valid, xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPushBin,
};

#[cfg(test)]
mod tests;

/// `xmlSecKeyUsageKeyEncapsulate`.
const KEY_USAGE_KEY_ENCAPSULATE: c_uint = 0x0000_0080;
/// `xmlSecKeyDataUsageUnknown`.
const DATA_USAGE_UNKNOWN: c_uint = 0;
/// libxmlsec1's initial size of the `kem-cipher-value` buffer.
const CIPHER_VALUE_INITIAL_SIZE: usize = 256;

/// The keys of a key transport, from `setKey`.
#[derive(Default)]
struct Kem {
    /// The recipient's public key.
    spki: Option<Vec<u8>>,
    /// The recipient's PKCS#8 private key, when decrypting.
    private: Option<Zeroizing<Vec<u8>>>,
}

/// A transport klass of `name` and `href`.
const fn kem_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Kem>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_ENCRYPTION_METHOD,
        )
    }
}

static MLKEM512: XmlSecTransformKlass = kem_klass(&xmlSecNameMLKEM512, &xmlSecHrefMLKEM512);
static MLKEM768: XmlSecTransformKlass = kem_klass(&xmlSecNameMLKEM768, &xmlSecHrefMLKEM768);
static MLKEM1024: XmlSecTransformKlass = kem_klass(&xmlSecNameMLKEM1024, &xmlSecHrefMLKEM1024);

/// The built-in table's `ml-kem-512` klass.
pub(crate) extern "C" fn mlkem512() -> *const XmlSecTransformKlass {
    &raw const MLKEM512
}

/// The built-in table's `ml-kem-768` klass.
pub(crate) extern "C" fn mlkem768() -> *const XmlSecTransformKlass {
    &raw const MLKEM768
}

/// The built-in table's `ml-kem-1024` klass.
pub(crate) extern "C" fn mlkem1024() -> *const XmlSecTransformKlass {
    &raw const MLKEM1024
}

/// The parameter set of klass `id`; `None` for any other klass.
fn parameter_set(id: *const XmlSecTransformKlass) -> Option<KeyEncapsulationAlgorithm> {
    if std::ptr::eq(id, &raw const MLKEM512) {
        Some(KeyEncapsulationAlgorithm::MlKem512)
    } else if std::ptr::eq(id, &raw const MLKEM768) {
        Some(KeyEncapsulationAlgorithm::MlKem768)
    } else if std::ptr::eq(id, &raw const MLKEM1024) {
        Some(KeyEncapsulationAlgorithm::MlKem1024)
    } else {
        None
    }
}

/// The transport object of a valid transform of these klasses, with its
/// parameter set, after libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform; a transform of these klasses was
/// initialized.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(
    &'a mut XmlSecTransform,
    KeyEncapsulationAlgorithm,
    &'a mut Kem,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the transport layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = parameter_set(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Kem>>()).then_some(found)
        });
        let Some(algorithm) = found else {
            errors::assertion(here, c"xmlSecOpenSSLMLKEMCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Kem>>();
        Some((&mut with.transform, algorithm, &mut with.context))
    }
}

/// The transform's name for a report.
fn name_of(transform: &XmlSecTransform) -> *const c_char {
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
            c"(transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)",
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
                .and_then(|(object, _)| parameter_set(object.id))
                .is_none()
            {
                errors::assertion(
                    here!("xmlSecOpenSSLMLKEMInitialize"),
                    c"xmlSecOpenSSLMLKEMCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Kem>>()).context).write(Kem::default());
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
                .and_then(|(object, _)| parameter_set(object.id))
                .is_some()
            {
                std::ptr::drop_in_place(&raw mut (*transform.cast::<WithContext<Kem>>()).context);
            }
        }
    });
}

/// `setKeyReq`: an ML-KEM key for key encapsulation, public or private to
/// encapsulate and private to decapsulate.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLMLKEMSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, _)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !encrypts_or_decrypts(object, here) {
            return -1;
        }
        // SAFETY: null or the caller's key requirements.
        let Some(req) = (unsafe { req.as_mut() }) else {
            errors::assertion(here, c"keyReq != NULL");
            return -1;
        };
        req.key_usage = KEY_USAGE_KEY_ENCAPSULATE;
        req.key_id = mlkemkeys::mlkem();
        req.key_type = if object.operation == OPERATION_ENCRYPT {
            TYPE_PRIVATE | TYPE_PUBLIC
        } else {
            TYPE_PRIVATE
        };
        0
    })
}

/// `setKey`: the recipient's key, of the klass's parameter set.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLMLKEMSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, kem)) = (unsafe { object(transform, here) }) else {
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
            if !check_id(value, mlkemkeys::mlkem()) {
                errors::assertion(
                    here,
                    c"xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataMLKEMId)",
                );
                return -1;
            }
            if kem.spki.is_some() {
                errors::assertion(here, c"ctx->pKey == NULL");
                return -1;
            }
            let Some(found) = mlkemkeys::key_of(value) else {
                errors::internal(here, name_of(object), c"xmlSecOpenSSLKeyDataMLKEMGetEvp");
                return -1;
            };
            if found.algorithm != algorithm {
                errors::report(
                    here,
                    name_of(object),
                    std::ptr::null(),
                    errors::R_INVALID_TYPE,
                    "ML-KEM key parameter set mismatch",
                );
                return -1;
            }
            kem.spki = Some(found.spki.clone());
            kem.private.clone_from(&found.private);
        }
        0
    })
}

/// `execute`: on the final call encapsulates, writes the kept ciphertext or
/// decapsulates, as the operation and the context's key data ask.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLMLKEMExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, kem)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !encrypts_or_decrypts(object, here) {
            return -1;
        }
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        if object.status == STATUS_WORKING {
            if last == 0 {
                return 0;
            }
            if ctx.is_null() {
                errors::assertion(here, c"transformCtx != NULL");
                return -1;
            }
            // SAFETY: a non-null, initialized context; the object's own
            // buffers.
            if !unsafe { process(object, algorithm, kem, ctx) } {
                errors::internal(here, name_of(object), c"xmlSecOpenSSLMLKEMProcess");
                return -1;
            }
            object.status = STATUS_FINISHED;
            return 0;
        }
        if object.status == STATUS_FINISHED {
            // Only an empty input reaches a finished transform.
            // SAFETY: the transform's own input buffer.
            if unsafe { xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
                errors::assertion(here, c"xmlSecBufferGetSize(&(transform->inBuf)) == 0");
                return -1;
            }
            return 0;
        }
        errors::invalid_status(here, name_of(object), object.status);
        -1
    })
}

/// libxmlsec1's `xmlSecOpenSSLMLKEMProcess`: the secret, or the kept
/// ciphertext, into the output buffer, cut to the expected width; `false`
/// after a report.
///
/// # Safety
/// `ctx` is the chain's initialized context.
unsafe fn process(
    object: &mut XmlSecTransform,
    algorithm: KeyEncapsulationAlgorithm,
    kem: &Kem,
    ctx: *mut XmlSecTransformCtx,
) -> bool {
    let here = here!("xmlSecOpenSSLMLKEMProcess");
    let name = name_of(object);
    // SAFETY: by the caller's contract; the object's own buffers.
    unsafe {
        let input = &raw mut object.in_buf;
        let output = &raw mut object.out_buf;
        if xmlSecBufferGetSize(output) != 0 {
            errors::assertion(here, c"xmlSecBufferGetSize(out) == 0");
            return false;
        }
        // The output holds a secret, so it is secure before it is written.
        xmlSecBufferMakeSecure(output);
        let input_size = xmlSecBufferGetSize(input);
        let written = if object.operation == OPERATION_ENCRYPT {
            let data = xmlSecTransformCtxExtraKeyDataEnsure(ctx, &raw const KEM_DATA);
            let Some(stored) = kem_data(data) else {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxExtraKeyDataEnsure(xmlSecKeyDataKEMId)",
                );
                return false;
            };
            let ciphertext = &raw mut stored.ciphertext;
            let held = xmlSecBufferGetSize(ciphertext);
            if held == 0 {
                // An encapsulation takes no input; its ciphertext is kept for
                // the EncryptedKey write.
                if input_size != 0 {
                    errors::invalid_data(
                        here,
                        std::ptr::null(),
                        "Unexpected input for KEM encapsulation",
                    );
                    return false;
                }
                encapsulate(object, algorithm, kem, ctx, ciphertext, output, name)
            } else {
                // The write phase outputs the ciphertext of the earlier
                // encapsulation, whatever the input.
                if held != algorithm.ciphertext_len() {
                    invalid_size(here, "KEM ciphertext", held, algorithm.ciphertext_len());
                    return false;
                }
                xmlSecBufferSetData(output, xmlSecBufferGetData(ciphertext), held) >= 0
            }
        } else {
            if input_size == 0 {
                errors::invalid_data(here, std::ptr::null(), "Empty KEM ciphertext");
                return false;
            }
            if input_size != algorithm.ciphertext_len() {
                invalid_size(
                    here!("xmlSecOpenSSLMLKEMDecapsulate"),
                    "Input ciphertext",
                    input_size,
                    algorithm.ciphertext_len(),
                );
                errors::internal(here, name, c"xmlSecOpenSSLMLKEMDecapsulate");
                return false;
            }
            let ciphertext = std::slice::from_raw_parts(xmlSecBufferGetData(input), input_size);
            decapsulate(object, algorithm, kem, ctx, ciphertext, output, name)
        };
        if !written {
            return false;
        }
        xmlSecBufferEmpty(input);
        // The secret is cut to the width the reading KeyInfo requires (a
        // 16-octet AES-128 key from the 32-octet ML-KEM secret); a wider
        // requirement than the secret is refused.
        let expected = object.expected_output_size;
        if expected > 0 {
            let size = xmlSecBufferGetSize(output);
            if expected > size {
                errors::report(
                    here,
                    name,
                    std::ptr::null(),
                    errors::R_INVALID_SIZE,
                    &format!(
                        "invalid size for 'Output data': actual={size} is less than expected={expected}"
                    ),
                );
                return false;
            }
            if expected < size && xmlSecBufferSetSize(output, expected) < 0 {
                errors::internal_with(
                    here,
                    name,
                    c"xmlSecBufferSetSize",
                    &format!("size={expected}"),
                );
                return false;
            }
        }
        true
    }
}

/// libxmlsec1's `xmlSecInvalidSizeError`.
fn invalid_size(here: Here, name: &str, actual: usize, expected: usize) {
    errors::report(
        here,
        std::ptr::null(),
        std::ptr::null(),
        errors::R_INVALID_SIZE,
        &format!("invalid size for '{name}': actual={actual} and expected={expected}"),
    );
}

/// Encapsulates to the recipient's public key in the core under the run's
/// key establishment policy and allowance, the ciphertext into `ciphertext`
/// and the secret into `output`; `false` after a report.
///
/// # Safety
/// `ctx` is the chain's initialized context; the buffers are live.
unsafe fn encapsulate(
    object: &XmlSecTransform,
    algorithm: KeyEncapsulationAlgorithm,
    kem: &Kem,
    ctx: *mut XmlSecTransformCtx,
    ciphertext: *mut XmlSecBuffer,
    output: *mut XmlSecBuffer,
    name: *const c_char,
) -> bool {
    let here = here!("xmlSecOpenSSLMLKEMEncapsulate");
    let Some(spki) = kem.spki.as_deref() else {
        errors::invalid_data(
            here,
            std::ptr::null(),
            "encapsulation requires the ML-KEM public key",
        );
        return false;
    };
    let key = match RustCryptoMlKemPublicKey::from_spki_der(spki) {
        Ok(key) if xml_sec::provider::KeyEncapsulationKey::algorithm(&key) == algorithm => key,
        Ok(_) | Err(_) => {
            errors::invalid_data(here, name, "invalid ML-KEM public key");
            return false;
        }
    };
    // SAFETY: by the caller's contract.
    let encapsulated = unsafe {
        with_allowance(object, ctx, here, |policy, usage| {
            usage.encapsulate(policy, xml_sec::provider::default_provider(), &key)
        })
    };
    let Some(encapsulated) = encapsulated else {
        return false;
    };
    // SAFETY: by the caller's contract.
    unsafe {
        if xmlSecBufferSetData(
            ciphertext,
            encapsulated.ciphertext.as_ptr(),
            encapsulated.ciphertext.len(),
        ) < 0
        {
            errors::internal(here, name, c"xmlSecBufferSetData(ct)");
            return false;
        }
        let secret = encapsulated.shared_secret;
        if xmlSecBufferAppend(output, secret.as_ptr(), secret.len()) < 0 {
            errors::internal(here, name, c"xmlSecBufferSetData(ss)");
            return false;
        }
    }
    true
}

/// Decapsulates `ciphertext` with the recipient's private key in the core
/// under the run's key establishment policy and allowance, the secret into
/// `output`; `false` after a report.
///
/// # Safety
/// `ctx` is the chain's initialized context; `output` is live.
unsafe fn decapsulate(
    object: &XmlSecTransform,
    algorithm: KeyEncapsulationAlgorithm,
    kem: &Kem,
    ctx: *mut XmlSecTransformCtx,
    ciphertext: &[u8],
    output: *mut XmlSecBuffer,
    name: *const c_char,
) -> bool {
    let here = here!("xmlSecOpenSSLMLKEMDecapsulate");
    let Some(private) = kem.private.as_deref() else {
        errors::invalid_data(here, name, "decapsulation requires the ML-KEM private key");
        return false;
    };
    let Ok(key) = RustCryptoMlKemPrivateKey::from_pkcs8_der(private) else {
        errors::invalid_data(here, name, "invalid ML-KEM private key");
        return false;
    };
    // SAFETY: by the caller's contract.
    let secret = unsafe {
        with_allowance(object, ctx, here, |policy, usage| {
            usage.decapsulate(
                policy,
                xml_sec::provider::default_provider(),
                &key,
                algorithm,
                ciphertext,
            )
        })
    };
    let Some(secret) = secret else {
        return false;
    };
    // SAFETY: by the caller's contract.
    if unsafe { xmlSecBufferAppend(output, secret.as_ptr(), secret.len()) } < 0 {
        errors::internal(here, name, c"xmlSecBufferSetData(ss)");
        return false;
    }
    true
}

/// Runs `work` under the key establishment policy of the run's side, counting
/// on from the operation's allowance; a resource refusal ends the operation,
/// as every part of it is then refused. `None` after a report at `here`.
///
/// # Safety
/// `ctx` is the chain's initialized context.
unsafe fn with_allowance<T>(
    object: &XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    here: Here,
    work: impl FnOnce(
        &xml_sec::policy::KeyEstablishmentPolicy,
        &mut xml_sec::key_establishment::KeyEstablishmentUsage,
    ) -> Result<T, KeyEstablishmentError>,
) -> Option<T> {
    let name = name_of(object);
    // SAFETY: by the caller's contract.
    let (pinned, side) = unsafe { scope(object, ctx, here) }?;
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    if let Some(limit) = run.refused_by {
        errors::limit_exceeded(here, name, limit.name, limit.max);
        return None;
    }
    match work(
        pinned.of(side).key_establishment(),
        &mut run.key_establishment,
    ) {
        Ok(value) => Some(value),
        Err(KeyEstablishmentError::Policy(PolicyViolation::ResourceLimit {
            resource,
            maximum,
            ..
        })) => {
            run.refused_by = run.refused_by.or(Some(Limit {
                name: resource,
                max: maximum,
            }));
            errors::limit_exceeded(here, name, resource, maximum);
            None
        }
        Err(error) => {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_CRYPTO_FAILED,
                &error.to_string(),
            );
            None
        }
    }
}

// ----------------------------------------------------------------------------
// kem-cipher-value

/// libxmlsec1's internal `kem-cipher-value` key data: the ciphertext an
/// encapsulation produced, kept by the context that ran it and carried to
/// the key it yields, so writing the key serializes it.
#[repr(C)]
struct KemData {
    data: XmlSecKeyData,
    ciphertext: XmlSecBuffer,
}

static KEM_DATA: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<KemData>(),
    name: c"kem-cipher-value".as_ptr().cast(),
    usage: DATA_USAGE_UNKNOWN,
    href: std::ptr::null(),
    data_node_name: std::ptr::null(),
    data_node_ns: std::ptr::null(),
    initialize: Some(kem_initialize),
    duplicate: Some(kem_duplicate),
    finalize: Some(kem_finalize),
    generate: None,
    get_type: None,
    get_size: None,
    deprecated0: std::ptr::null_mut(),
    xml_read: None,
    xml_write: None,
    bin_read: None,
    bin_write: None,
    debug_dump: Some(kem_debug_dump),
    debug_xml_dump: Some(kem_debug_xml_dump),
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// The `kem-cipher-value` klass.
pub(crate) fn kem_klass_id() -> *const XmlSecKeyDataKlass {
    &raw const KEM_DATA
}

/// The object of valid `kem-cipher-value` key data.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn kem_data<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut KemData> {
    // SAFETY: by the caller's contract; a valid object of the klass has the
    // `kem-cipher-value` layout.
    unsafe {
        (data_valid(data) && check_id(data, &raw const KEM_DATA))
            .then(|| &mut *data.cast::<KemData>())
    }
}

unsafe extern "C" fn kem_initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecKeyDataKEMInitialize");
        // SAFETY: the registry passes key data of this klass.
        let Some(object) = (unsafe { kem_data(data) }) else {
            errors::assertion(here, c"xmlSecKeyDataIsValid(data)");
            return -1;
        };
        // SAFETY: the object's own buffer, initialized once.
        unsafe {
            if xmlSecBufferInitialize(&raw mut object.ciphertext, CIPHER_VALUE_INITIAL_SIZE) < 0 {
                errors::internal(
                    here,
                    c"kem-cipher-value".as_ptr(),
                    c"xmlSecBufferInitialize(ciphertext)",
                );
                return -1;
            }
            xmlSecBufferMakeSecure(&raw mut object.ciphertext);
        }
        0
    })
}

unsafe extern "C" fn kem_duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecKeyDataKEMDuplicate");
        // SAFETY: the registry passes key data of this klass.
        let (Some(target), Some(source)) = (unsafe { kem_data(dst) }, unsafe { kem_data(src) })
        else {
            errors::assertion(
                here,
                c"xmlSecKeyDataIsValid(dst) && xmlSecKeyDataIsValid(src)",
            );
            return -1;
        };
        // SAFETY: both objects' own buffers.
        unsafe {
            let from = &raw mut source.ciphertext;
            if xmlSecBufferSetData(
                &raw mut target.ciphertext,
                xmlSecBufferGetData(from),
                xmlSecBufferGetSize(from),
            ) < 0
            {
                errors::internal(
                    here,
                    c"kem-cipher-value".as_ptr(),
                    c"xmlSecBufferSetData(ciphertext)",
                );
                return -1;
            }
        }
        0
    })
}

unsafe extern "C" fn kem_finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        if let Some(object) = unsafe { kem_data(data) } {
            // SAFETY: the object's own buffer, finalized once.
            unsafe { xmlSecBufferFinalize(&raw mut object.ciphertext) };
        }
    });
}

unsafe extern "C" fn kem_debug_dump(_data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes a C stream.
        unsafe { write_stream(output, "=== kem-cipher-value key: size = 0\n") };
    });
}

unsafe extern "C" fn kem_debug_xml_dump(_data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes a C stream.
        unsafe { write_stream(output, "<kem-cipher-value size=\"0\"/>\n") };
    });
}
