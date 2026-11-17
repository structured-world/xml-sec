//! The built-in provider's block cipher transform klasses: AES-CBC, AES-GCM
//! and Camellia-CBC.
//!
//! A transform collects its binary input. On the final chunk it encrypts or
//! decrypts it as one `XMLEnc` cipher value (the IV or nonce in front, CBC
//! padding as `XMLEnc` defines it, the GCM tag behind) through the selected
//! provider, after the run's policy admitted the algorithm, with the
//! symmetric key of the klass's family.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::policy::PolicyViolation;
use xml_sec::xmlenc::DataEncryptionAlgorithm;
use zeroize::Zeroizing;

use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferRemoveHead,
};
use super::super::errors::{self, Here, here};
use super::super::keys::{TYPE_SYMMETRIC, XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::{XmlSecKeyDataKlass, check_id, xmlSecKeyDataBinaryValueGetBuffer};
use super::super::{contain, policy, strings, symkeys};
use super::builtin::klass;
use super::ctx::run_policy;
use super::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, STATUS_FINISHED, STATUS_NONE, STATUS_WORKING,
    USAGE_ENCRYPTION_METHOD, WithContext, XmlSecKeyReq, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, valid, xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPushBin,
};

/// `xmlSecKeyUsageEncrypt`.
const KEY_USAGE_ENCRYPT: c_uint = 0x0000_0004;
/// `xmlSecKeyUsageDecrypt`.
const KEY_USAGE_DECRYPT: c_uint = 0x0000_0008;
/// The most a cipher value adds to its plaintext: a 16-octet IV and a
/// block of CBC padding, or a 12-octet GCM nonce and a 16-octet tag.
const CIPHER_FRAMING: usize = 32;

/// The state of a cipher transform.
struct Cipher {
    /// The key bytes, from `setKey`.
    key: Option<Zeroizing<Vec<u8>>>,
    /// The input collected so far.
    data: Zeroizing<Vec<u8>>,
    /// The library policy the run started under, taken at the first
    /// `execute` and kept, so its admission and its bound on the collected
    /// bytes come from one revision.
    policy: Option<policy::Pinned>,
}

/// A cipher klass of `name` and `href`.
const fn cipher_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Cipher>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_ENCRYPTION_METHOD,
        )
    }
}

macro_rules! ciphers {
    ($($(#[$meta:meta])* $klass:ident, $getter:ident, $name:ident, $href:ident, $algorithm:ident;)*) => {
        $(
            $(#[$meta])*
            static $klass: XmlSecTransformKlass =
                cipher_klass(&strings::$name, &strings::$href);

            $(#[$meta])*
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $getter() -> *const XmlSecTransformKlass {
                &raw const $klass
            }
        )*

        /// The algorithm of klass `id`, `None` for any other.
        fn method(id: *const XmlSecTransformKlass) -> Option<DataEncryptionAlgorithm> {
            $(
                $(#[$meta])*
                if std::ptr::eq(id, &raw const $klass) {
                    return Some(DataEncryptionAlgorithm::$algorithm);
                }
            )*
            None
        }
    };
}

ciphers! {
    AES128_CBC, aes128_cbc, xmlSecNameAes128Cbc, xmlSecHrefAes128Cbc, Aes128Cbc;
    #[cfg(feature = "legacy-algorithms")]
    AES192_CBC, aes192_cbc, xmlSecNameAes192Cbc, xmlSecHrefAes192Cbc, Aes192Cbc;
    AES256_CBC, aes256_cbc, xmlSecNameAes256Cbc, xmlSecHrefAes256Cbc, Aes256Cbc;
    AES128_GCM, aes128_gcm, xmlSecNameAes128Gcm, xmlSecHrefAes128Gcm, Aes128Gcm;
    #[cfg(feature = "legacy-algorithms")]
    AES192_GCM, aes192_gcm, xmlSecNameAes192Gcm, xmlSecHrefAes192Gcm, Aes192Gcm;
    AES256_GCM, aes256_gcm, xmlSecNameAes256Gcm, xmlSecHrefAes256Gcm, Aes256Gcm;
    CAMELLIA128_CBC, camellia128_cbc, xmlSecNameCamellia128Cbc, xmlSecHrefCamellia128Cbc, Camellia128Cbc;
    CAMELLIA192_CBC, camellia192_cbc, xmlSecNameCamellia192Cbc, xmlSecHrefCamellia192Cbc, Camellia192Cbc;
    CAMELLIA256_CBC, camellia256_cbc, xmlSecNameCamellia256Cbc, xmlSecHrefCamellia256Cbc, Camellia256Cbc;
}

/// The key-data klass of the family `algorithm` takes its key from.
fn key_klass(algorithm: DataEncryptionAlgorithm) -> *const XmlSecKeyDataKlass {
    match algorithm.key_kind() {
        xml_sec::key_manager::SymmetricKeyKind::Camellia => symkeys::camellia(),
        _ => symkeys::aes(),
    }
}

/// The cipher object of a valid transform of these klasses, after
/// libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform; a transform of these klasses was
/// initialized.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(
    &'a mut XmlSecTransform,
    DataEncryptionAlgorithm,
    &'a mut Cipher,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the cipher layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = method(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Cipher>>()).then_some(found)
        });
        let Some(algorithm) = found else {
            errors::assertion(here, c"xmlSecOpenSSLEvpBlockCipherCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Cipher>>();
        Some((&mut with.transform, algorithm, &mut with.context))
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
                .and_then(|(object, _)| method(object.id))
                .is_none()
            {
                errors::assertion(
                    here!("xmlSecOpenSSLEvpBlockCipherInitialize"),
                    c"xmlSecOpenSSLEvpBlockCipherCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Cipher>>()).context).write(Cipher {
                key: None,
                data: Zeroizing::new(Vec::new()),
                policy: None,
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
                .and_then(|(object, _)| method(object.id))
                .is_some()
            {
                std::ptr::drop_in_place(
                    &raw mut (*transform.cast::<WithContext<Cipher>>()).context,
                );
            }
        }
    });
}

/// `setKeyReq`: a symmetric key of the algorithm's family and size, to
/// encrypt or decrypt.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpBlockCipherSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, _)) = (unsafe { object(transform, here) }) else {
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
        req.key_id = key_klass(algorithm).cast();
        req.key_type = TYPE_SYMMETRIC;
        req.key_usage = if object.operation == OPERATION_ENCRYPT {
            KEY_USAGE_ENCRYPT
        } else {
            KEY_USAGE_DECRYPT
        };
        // A key length in bytes; its bits cannot overflow.
        req.key_bits_size = algorithm.key_len() * 8;
        0
    })
}

/// `setKey`: the key bytes of the key's value, of the algorithm's family
/// and at least its size.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpBlockCipherSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, cipher)) = (unsafe { object(transform, here) }) else {
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
            if !check_id(value, key_klass(algorithm)) {
                errors::assertion(
                    here,
                    c"xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), ctx->keyId)",
                );
                return -1;
            }
            let buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
            let size = xmlSecBufferGetSize(buffer);
            if size < algorithm.key_len() || xmlSecBufferGetData(buffer).is_null() {
                errors::size_more_than(here, name_of(object), "key", size, algorithm.key_len());
                return -1;
            }
            // libxmlsec1 takes the leading bytes of a longer key.
            let bytes =
                std::slice::from_raw_parts(xmlSecBufferGetData(buffer), algorithm.key_len());
            cipher.key = Some(Zeroizing::new(bytes.to_vec()));
        }
        0
    })
}

/// The run's admission of `algorithm` for `operation` under `pinned`.
fn admit(
    pinned: &policy::Pinned,
    operation: c_int,
    algorithm: DataEncryptionAlgorithm,
) -> Result<usize, PolicyViolation> {
    if operation == OPERATION_ENCRYPT {
        pinned.encryption.validate()?;
        pinned.encryption.check_data_algorithm(algorithm)?;
        Ok(pinned.encryption.resources.max_encryption_plaintext_bytes)
    } else {
        pinned.decryption.validate()?;
        pinned.decryption.check_data_algorithm(algorithm)?;
        Ok(pinned.decryption.resources.max_encryption_plaintext_bytes)
    }
}

/// Collects the input buffer; on the `last` chunk encrypts or decrypts it.
fn collect(
    object: &mut XmlSecTransform,
    algorithm: DataEncryptionAlgorithm,
    cipher: &mut Cipher,
    last: bool,
    here: Here,
) -> c_int {
    let name = name_of(object);
    let input = &raw mut object.in_buf;
    let Some(pinned) = cipher.policy.as_ref() else {
        errors::assertion(here, c"ctx->policy != NULL");
        return -1;
    };
    let maximum = match admit(pinned, object.operation, algorithm) {
        Ok(maximum) => maximum,
        Err(violation) => {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_TRANSFORM_DISABLED,
                &violation.to_string(),
            );
            return -1;
        }
    };
    // SAFETY: the transform's own input buffer.
    unsafe {
        let size = xmlSecBufferGetSize(input);
        if size > 0 {
            // Plaintext is bounded by the ceiling; a cipher value also by
            // its framing (an IV or nonce, padding or a tag).
            let ceiling = if object.operation == OPERATION_ENCRYPT {
                Some(maximum)
            } else {
                maximum.checked_add(CIPHER_FRAMING)
            };
            if cipher
                .data
                .len()
                .checked_add(size)
                .zip(ceiling)
                .is_none_or(|(total, ceiling)| total > ceiling)
            {
                errors::limit_exceeded(here, name, "max_encryption_plaintext_bytes", maximum);
                return -1;
            }
            cipher
                .data
                .extend_from_slice(std::slice::from_raw_parts(xmlSecBufferGetData(input), size));
            if xmlSecBufferRemoveHead(input, size) < 0 {
                errors::internal_with(
                    here,
                    name,
                    c"xmlSecBufferRemoveHead",
                    &format!("size={size}"),
                );
                return -1;
            }
        }
    }
    if !last {
        return 0;
    }
    let Some(key) = cipher.key.as_deref() else {
        errors::assertion(here, c"ctx->keyInitialized != 0");
        return -1;
    };
    let provider = xml_sec::provider::default_provider();
    let output = if object.operation == OPERATION_ENCRYPT {
        provider.encrypt_data(algorithm, key, &cipher.data)
    } else {
        provider.decrypt_data(algorithm, key, &cipher.data)
    };
    let output = match output {
        Ok(output) => Zeroizing::new(output),
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
    // SAFETY: the transform's own output buffer.
    let appended =
        unsafe { xmlSecBufferAppend(&raw mut object.out_buf, output.as_ptr(), output.len()) };
    if appended < 0 {
        errors::internal_with(
            here,
            name,
            c"xmlSecBufferAppend",
            &format!("size={}", output.len()),
        );
        return -1;
    }
    object.status = STATUS_FINISHED;
    0
}

/// `execute`: libxmlsec1's state machine over [`collect`]; the key must
/// have been set.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpBlockCipherExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, cipher)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !encrypts_or_decrypts(object, here) {
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        if object.status == STATUS_NONE {
            // SAFETY: a non-null context, initialized by the dispatcher's
            // contract.
            let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
                return -1;
            };
            cipher.policy = Some(pinned);
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => collect(object, algorithm, cipher, last != 0, here),
            STATUS_FINISHED => {
                // SAFETY: the transform's own input buffer.
                if unsafe { xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
                    errors::assertion(here, c"xmlSecBufferGetSize(&(transform->inBuf)) == 0");
                    return -1;
                }
                0
            }
            status => {
                errors::invalid_status(here, name_of(object), status);
                -1
            }
        }
    })
}

#[cfg(test)]
mod tests;
