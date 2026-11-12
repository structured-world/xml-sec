//! The built-in provider's RSA, RSA-PSS, ECDSA and DSA signature transform
//! klasses.
//!
//! A transform collects its binary input, the signed bytes. Verifying, it
//! checks a signature value over them with the key's public key through the
//! core's policy-checked signature verification; signing, it signs them with
//! the key's private key through the core's policy-checked signing key and
//! outputs the value. Both run under the library policy, with the key of the
//! RSA, DSA or EC klass the method requires.

use std::ffi::{c_char, c_int, c_uint, c_void};

use xml_sec::key_manager::{KeyInventory, KeyUsages};
use xml_sec::xmldsig::verify::verify_signature_value;
use xml_sec::xmldsig::{SignatureAlgorithm, VerificationKey};
use zeroize::Zeroizing;

use super::super::asymkeys::{self, material_of};
use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferRemoveHead,
};
use super::super::errors::{self, Here, here};
use super::super::keys::{
    TYPE_PRIVATE, TYPE_PUBLIC, XmlSecKey, xmlSecKeyGetSize, xmlSecKeyGetValue,
};
use super::super::keysdata::{XmlSecKeyDataKlass, check_id};
use super::super::strings;
use super::super::{contain, policy};
use super::builtin::klass;
use super::{
    OPERATION_SIGN, OPERATION_VERIFY, STATUS_FAIL, STATUS_FINISHED, STATUS_NONE, STATUS_OK,
    STATUS_WORKING, USAGE_SIGNATURE_METHOD, WithContext, XmlSecKeyReq, XmlSecTransform,
    XmlSecTransformCtx, XmlSecTransformKlass, valid, xmlSecTransformDefaultPopBin,
    xmlSecTransformDefaultPushBin,
};

/// `xmlSecKeyUsageSign`.
const KEY_USAGE_SIGN: c_uint = 0x0000_0001;
/// `xmlSecKeyUsageVerify`.
const KEY_USAGE_VERIFY: c_uint = 0x0000_0002;

/// The key family a method requires.
#[derive(Clone, Copy)]
enum Family {
    Rsa,
    Dsa,
    Ec,
}

impl Family {
    fn klass(self) -> *const XmlSecKeyDataKlass {
        match self {
            Self::Rsa => asymkeys::rsa(),
            Self::Dsa => asymkeys::dsa(),
            Self::Ec => asymkeys::ec(),
        }
    }
}

/// The state of a signature transform.
struct Signature {
    /// The verifying key, from `setKey`.
    key: Option<VerificationKey>,
    /// The PKCS#8 DER of the signing key, from `setKey` when signing.
    private: Option<Zeroizing<Vec<u8>>>,
    /// The signed bytes collected so far.
    data: Vec<u8>,
}

/// A signature klass of `name` and `href`.
const fn signature_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        verify: Some(verify),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Signature>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_SIGNATURE_METHOD,
        )
    }
}

macro_rules! signatures {
    ($($(#[$meta:meta])* $klass:ident, $getter:ident, $name:ident, $href:ident, $algorithm:ident, $family:ident;)*) => {
        $(
            $(#[$meta])*
            static $klass: XmlSecTransformKlass =
                signature_klass(&strings::$name, &strings::$href);

            $(#[$meta])*
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $getter() -> *const XmlSecTransformKlass {
                &raw const $klass
            }
        )*

        /// The method and key family of klass `id`, `None` for any other.
        fn method(id: *const XmlSecTransformKlass) -> Option<(SignatureAlgorithm, Family)> {
            $(
                $(#[$meta])*
                if std::ptr::eq(id, &raw const $klass) {
                    return Some((SignatureAlgorithm::$algorithm, Family::$family));
                }
            )*
            None
        }
    };
}

signatures! {
    #[cfg(feature = "legacy-algorithms")]
    RSA_MD5, rsa_md5, xmlSecNameRsaMd5, xmlSecHrefRsaMd5, RsaMd5, Rsa;
    #[cfg(feature = "legacy-algorithms")]
    RSA_RIPEMD160, rsa_ripemd160, xmlSecNameRsaRipemd160, xmlSecHrefRsaRipemd160, RsaRipemd160, Rsa;
    RSA_SHA1, rsa_sha1, xmlSecNameRsaSha1, xmlSecHrefRsaSha1, RsaSha1, Rsa;
    RSA_SHA224, rsa_sha224, xmlSecNameRsaSha224, xmlSecHrefRsaSha224, RsaSha224, Rsa;
    RSA_SHA256, rsa_sha256, xmlSecNameRsaSha256, xmlSecHrefRsaSha256, RsaSha256, Rsa;
    RSA_SHA384, rsa_sha384, xmlSecNameRsaSha384, xmlSecHrefRsaSha384, RsaSha384, Rsa;
    RSA_SHA512, rsa_sha512, xmlSecNameRsaSha512, xmlSecHrefRsaSha512, RsaSha512, Rsa;
    RSA_PSS_SHA1, rsa_pss_sha1, xmlSecNameRsaPssSha1, xmlSecHrefRsaPssSha1, RsaPssSha1, Rsa;
    RSA_PSS_SHA224, rsa_pss_sha224, xmlSecNameRsaPssSha224, xmlSecHrefRsaPssSha224, RsaPssSha224, Rsa;
    RSA_PSS_SHA256, rsa_pss_sha256, xmlSecNameRsaPssSha256, xmlSecHrefRsaPssSha256, RsaPssSha256, Rsa;
    RSA_PSS_SHA384, rsa_pss_sha384, xmlSecNameRsaPssSha384, xmlSecHrefRsaPssSha384, RsaPssSha384, Rsa;
    RSA_PSS_SHA512, rsa_pss_sha512, xmlSecNameRsaPssSha512, xmlSecHrefRsaPssSha512, RsaPssSha512, Rsa;
    RSA_PSS_SHA3_224, rsa_pss_sha3_224, xmlSecNameRsaPssSha3_224, xmlSecHrefRsaPssSha3_224, RsaPssSha3_224, Rsa;
    RSA_PSS_SHA3_256, rsa_pss_sha3_256, xmlSecNameRsaPssSha3_256, xmlSecHrefRsaPssSha3_256, RsaPssSha3_256, Rsa;
    RSA_PSS_SHA3_384, rsa_pss_sha3_384, xmlSecNameRsaPssSha3_384, xmlSecHrefRsaPssSha3_384, RsaPssSha3_384, Rsa;
    RSA_PSS_SHA3_512, rsa_pss_sha3_512, xmlSecNameRsaPssSha3_512, xmlSecHrefRsaPssSha3_512, RsaPssSha3_512, Rsa;
    DSA_SHA1, dsa_sha1, xmlSecNameDsaSha1, xmlSecHrefDsaSha1, DsaSha1, Dsa;
    DSA_SHA256, dsa_sha256, xmlSecNameDsaSha256, xmlSecHrefDsaSha256, DsaSha256, Dsa;
    #[cfg(feature = "legacy-algorithms")]
    ECDSA_RIPEMD160, ecdsa_ripemd160, xmlSecNameEcdsaRipemd160, xmlSecHrefEcdsaRipemd160, EcdsaRipemd160, Ec;
    ECDSA_SHA1, ecdsa_sha1, xmlSecNameEcdsaSha1, xmlSecHrefEcdsaSha1, EcdsaSha1, Ec;
    ECDSA_SHA224, ecdsa_sha224, xmlSecNameEcdsaSha224, xmlSecHrefEcdsaSha224, EcdsaSha224, Ec;
    ECDSA_SHA256, ecdsa_sha256, xmlSecNameEcdsaSha256, xmlSecHrefEcdsaSha256, EcdsaSha256, Ec;
    ECDSA_SHA384, ecdsa_sha384, xmlSecNameEcdsaSha384, xmlSecHrefEcdsaSha384, EcdsaSha384, Ec;
    ECDSA_SHA512, ecdsa_sha512, xmlSecNameEcdsaSha512, xmlSecHrefEcdsaSha512, EcdsaSha512, Ec;
    ECDSA_SHA3_224, ecdsa_sha3_224, xmlSecNameEcdsaSha3_224, xmlSecHrefEcdsaSha3_224, EcdsaSha3_224, Ec;
    ECDSA_SHA3_256, ecdsa_sha3_256, xmlSecNameEcdsaSha3_256, xmlSecHrefEcdsaSha3_256, EcdsaSha3_256, Ec;
    ECDSA_SHA3_384, ecdsa_sha3_384, xmlSecNameEcdsaSha3_384, xmlSecHrefEcdsaSha3_384, EcdsaSha3_384, Ec;
    ECDSA_SHA3_512, ecdsa_sha3_512, xmlSecNameEcdsaSha3_512, xmlSecHrefEcdsaSha3_512, EcdsaSha3_512, Ec;
}

/// The signature object of a valid transform of these klasses, after
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
    SignatureAlgorithm,
    Family,
    &'a mut Signature,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the signature layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = method(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Signature>>()).then_some(found)
        });
        let Some((algorithm, family)) = found else {
            errors::assertion(here, c"xmlSecOpenSSLEvpSignatureCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Signature>>();
        Some((&mut with.transform, algorithm, family, &mut with.context))
    }
}

/// The transform's name for a report.
fn name_of(transform: &XmlSecTransform) -> *const c_char {
    // SAFETY: a valid transform's klass outlives it.
    unsafe { (*transform.id).name.cast() }
}

/// Whether `transform` signs or verifies, after libxmlsec1's assertion.
fn signs_or_verifies(transform: &XmlSecTransform, here: Here) -> bool {
    let holds = transform.operation == OPERATION_SIGN || transform.operation == OPERATION_VERIFY;
    if !holds {
        errors::assertion(
            here,
            c"(transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify)",
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
                    here!("xmlSecOpenSSLEvpSignatureInitialize"),
                    c"xmlSecOpenSSLEvpSignatureCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Signature>>()).context).write(Signature {
                key: None,
                private: None,
                data: Vec::new(),
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
                    &raw mut (*transform.cast::<WithContext<Signature>>()).context,
                );
            }
        }
    });
}

/// `setKeyReq`: a key of the method's family, private to sign and public to
/// verify.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpSignatureSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, family, _)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !signs_or_verifies(object, here) {
            return -1;
        }
        // SAFETY: null or the caller's key requirements.
        let Some(req) = (unsafe { req.as_mut() }) else {
            errors::assertion(here, c"keyReq != NULL");
            return -1;
        };
        req.key_id = family.klass().cast();
        (req.key_type, req.key_usage) = if object.operation == OPERATION_SIGN {
            (TYPE_PRIVATE, KEY_USAGE_SIGN)
        } else {
            (TYPE_PUBLIC, KEY_USAGE_VERIFY)
        };
        0
    })
}

/// `setKey`: the public key of the key's value, of the method's family.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpSignatureSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, family, signature)) = (unsafe { object(transform, here) })
        else {
            return -1;
        };
        if !signs_or_verifies(object, here) {
            return -1;
        }
        if key.is_null() {
            errors::assertion(here, c"key != NULL");
            return -1;
        }
        let name = name_of(object);
        // SAFETY: a key whose value is null or key data.
        unsafe {
            let value = xmlSecKeyGetValue(key);
            if !check_id(value, family.klass()) {
                errors::assertion(here, c"xmlSecKeyCheckId(key, ctx->keyId)");
                return -1;
            }
            if xmlSecKeyGetSize(key) == 0 {
                errors::internal(here, name, c"xmlSecKeyGetSize");
                return -1;
            }
            let Some(material) = material_of(value) else {
                errors::internal(here, name, c"xmlSecKeyGetValue");
                return -1;
            };
            let Ok(spki) = material.value.to_spki_der() else {
                errors::internal(here, name, c"KeyValueInfo::to_spki_der");
                return -1;
            };
            if object.operation == OPERATION_SIGN {
                let Some(private) = material.private.clone() else {
                    errors::report(
                        here,
                        name,
                        std::ptr::null(),
                        errors::R_INVALID_KEY_DATA,
                        "the key holds no private key",
                    );
                    return -1;
                };
                signature.private = Some(private);
            }
            signature.key = Some(VerificationKey {
                algorithm,
                public_key_bytes: spki,
                certificate_der: None,
                name: None,
            });
        }
        0
    })
}

/// `verify`: the signature value of `size` bytes at `data` over the signed
/// bytes; a mismatch is a failed status, not an error.
unsafe extern "C" fn verify(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpSignatureVerify");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, _, signature)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        for (holds, expression) in [
            (
                object.operation == OPERATION_VERIFY,
                c"transform->operation == xmlSecTransformOperationVerify",
            ),
            (
                object.status == STATUS_FINISHED,
                c"transform->status == xmlSecTransformStatusFinished",
            ),
            (!data.is_null(), c"data != NULL"),
            (!ctx.is_null(), c"transformCtx != NULL"),
            // The signed bytes may be empty: the method digests them, and the
            // digest is never empty.
            (signature.key.is_some(), c"ctx->pKey != NULL"),
        ] {
            if !holds {
                errors::assertion(here, expression);
                return -1;
            }
        }
        let Some(key) = signature.key.as_ref() else {
            return -1;
        };
        let name = name_of(object);
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        // SAFETY: the caller's `size` bytes.
        let value = unsafe { std::slice::from_raw_parts(data, size) };
        match verify_signature_value(
            &policy,
            xml_sec::provider::default_provider(),
            key,
            algorithm,
            &signature.data,
            value,
        ) {
            Ok(true) => object.status = STATUS_OK,
            Ok(false) => {
                errors::other(
                    here,
                    errors::R_DATA_NOT_MATCH,
                    name,
                    Some("Signature verification failed"),
                );
                object.status = STATUS_FAIL;
            }
            Err(error) => {
                errors::internal_with(here, name, c"verify_signature_value", &error.to_string());
                return -1;
            }
        }
        0
    })
}

/// Collects the input buffer of a working transform; on the `last` chunk
/// the transform is finished. Signing needs a private key, which no key of
/// these klasses holds yet.
fn collect(
    object: &mut XmlSecTransform,
    signature: &mut Signature,
    last: bool,
    here: Here,
) -> c_int {
    let name = name_of(object);
    let input = &raw mut object.in_buf;
    // SAFETY: the transform's own input buffer.
    unsafe {
        let size = xmlSecBufferGetSize(input);
        if size > 0 {
            // The collected bytes are signed data: the policy of the
            // operation bounds them before the buffer grows.
            let maximum = if object.operation == OPERATION_SIGN {
                policy::signing_at(here).map(|policy| policy.resources.max_canonicalized_bytes)
            } else {
                policy::verification_at(here).map(|policy| policy.resources.max_canonicalized_bytes)
            };
            let Some(maximum) = maximum else {
                return -1;
            };
            if signature
                .data
                .len()
                .checked_add(size)
                .is_none_or(|total| total > maximum)
            {
                errors::limit_exceeded(here, name, "canonicalized bytes", maximum);
                return -1;
            }
            signature
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
    if object.operation == OPERATION_SIGN {
        let algorithm = method(object.id).map(|(algorithm, _)| algorithm);
        let (Some(algorithm), Some(private)) = (algorithm, signature.private.as_ref()) else {
            errors::assertion(here, c"ctx->pKey != NULL");
            return -1;
        };
        let value = match sign(here, algorithm, private, &signature.data) {
            Ok(value) => value,
            Err(error) => {
                errors::internal_with(here, name, c"SigningKey::sign", &error);
                return -1;
            }
        };
        // SAFETY: the transform's own output buffer.
        let appended =
            unsafe { xmlSecBufferAppend(&raw mut object.out_buf, value.as_ptr(), value.len()) };
        if appended < 0 {
            errors::internal_with(
                here,
                name,
                c"xmlSecBufferAppend",
                &format!("size={}", value.len()),
            );
            return -1;
        }
    }
    object.status = STATUS_FINISHED;
    0
}

/// The signature value of `data` by the PKCS#8 key `private` under the
/// library's signing policy, which admits the method and the key.
fn sign(
    here: Here,
    algorithm: SignatureAlgorithm,
    private: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let policy = policy::signing_at(here).ok_or("the library policy is unavailable")?;
    let mut inventory = KeyInventory::default();
    inventory
        .add_private_der(
            "key".to_owned(),
            private,
            None,
            KeyUsages::SIGN,
            &policy.resources,
        )
        .map_err(|error| error.to_string())?;
    let key = inventory
        .signing_key("key", algorithm, &policy)
        .map_err(|error| error.to_string())?;
    key.sign_with_provider(xml_sec::provider::default_provider(), algorithm, data)
        .map_err(|error| error.to_string())
}

/// `execute`: libxmlsec1's state machine over [`collect`]; the key must
/// have been set.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpSignatureExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, _, signature)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !signs_or_verifies(object, here) {
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        if signature.key.is_none() {
            errors::assertion(here, c"ctx->pKey != NULL");
            return -1;
        }
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => collect(object, signature, last != 0, here),
            // Only reached without input.
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
