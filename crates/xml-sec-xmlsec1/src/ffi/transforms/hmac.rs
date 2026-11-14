//! The built-in provider's HMAC signature transform klasses and the
//! library's HMAC minimum output length.
//!
//! A klass reads `HMACOutputLength` and checks it against the library
//! policy's HMAC output minimum and the `XMLDSig` floor the core applies,
//! takes an HMAC key of the binary value klass, computes the MAC through
//! the core's incremental HMAC and writes or compares it truncated to the
//! selected length. `xmlSecTransformHmacSetMinOutputBitsSize` republishes
//! the library policy with the new minimum.

use std::ffi::{c_char, c_int, c_uint, c_void};

use xml_sec::xmldsig::{HmacTag, IncrementalHmac, SignatureAlgorithm};

use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferRemoveHead,
};
use super::super::errors::{self, Here, here};
use super::super::keys::{TYPE_SYMMETRIC, XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::{check_id, xmlSecKeyDataBinaryValueGetBuffer};
use super::super::strings::{
    xmlSecDSigNs, xmlSecHrefHmacSha1, xmlSecHrefHmacSha224, xmlSecHrefHmacSha256,
    xmlSecHrefHmacSha384, xmlSecHrefHmacSha512, xmlSecNameHmacSha1, xmlSecNameHmacSha224,
    xmlSecNameHmacSha256, xmlSecNameHmacSha384, xmlSecNameHmacSha512, xmlSecNodeHMACOutputLength,
};
#[cfg(feature = "legacy-algorithms")]
use super::super::strings::{
    xmlSecHrefHmacMd5, xmlSecHrefHmacRipemd160, xmlSecNameHmacMd5, xmlSecNameHmacRipemd160,
};
use super::super::symkeys;
use super::super::tree::{XmlNode, nodes};
use super::super::xmltree::{
    xmlSecCheckNodeName, xmlSecGetNextElementNode, xmlSecGetNodeContentAsSize,
};
use super::super::{contain, policy};
use super::builtin::klass;
use super::ctx::run_policy;
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
/// The bits kept of a truncated MAC's last byte, by the selected length
/// modulo 8 (`XMLDSig` 1.1 section 6.3.1: the leftmost bits).
const LAST_BYTE_MASKS: [u8; 8] = [0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE];

/// The state of an HMAC transform.
struct Hmac {
    /// The running MAC, from the key until the last chunk; boxed, as its
    /// state is more aligned than the libxml2 allocation holding the object.
    mac: Option<Box<IncrementalHmac>>,
    /// The selected output length in bits, zero for the full MAC.
    output_bits: usize,
    /// The length of the secret the MAC was started with, admitted again
    /// under the run's policy revision.
    secret_len: usize,
    /// Whether a key started the MAC; it stays set after the MAC finishes,
    /// so the result keeps the key it was computed with.
    keyed: bool,
    /// The revision the method was read under, which admits the key.
    pinned: Option<policy::Pinned>,
    /// The full MAC once finished.
    result: Option<HmacTag>,
}

/// An HMAC klass of `name` and `href`.
const fn hmac_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        read_node: Some(read_node),
        set_key_req: Some(set_key_req),
        set_key: Some(set_key),
        verify: Some(verify),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Hmac>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_SIGNATURE_METHOD,
        )
    }
}

macro_rules! hmacs {
    ($($(#[$meta:meta])* $klass:ident, $getter:ident, $name:ident, $href:ident, $algorithm:ident;)*) => {
        $(
            $(#[$meta])*
            static $klass: XmlSecTransformKlass = hmac_klass(&$name, &$href);

            $(#[$meta])*
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $getter() -> *const XmlSecTransformKlass {
                &raw const $klass
            }
        )*

        /// The signature method of klass `id`, `None` for any other klass.
        fn algorithm(id: *const XmlSecTransformKlass) -> Option<SignatureAlgorithm> {
            $(
                $(#[$meta])*
                if std::ptr::eq(id, &raw const $klass) {
                    return Some(SignatureAlgorithm::$algorithm);
                }
            )*
            None
        }
    };
}

hmacs! {
    #[cfg(feature = "legacy-algorithms")]
    HMAC_MD5, hmac_md5, xmlSecNameHmacMd5, xmlSecHrefHmacMd5, HmacMd5;
    #[cfg(feature = "legacy-algorithms")]
    HMAC_RIPEMD160, hmac_ripemd160, xmlSecNameHmacRipemd160, xmlSecHrefHmacRipemd160, HmacRipemd160;
    HMAC_SHA1, hmac_sha1, xmlSecNameHmacSha1, xmlSecHrefHmacSha1, HmacSha1;
    HMAC_SHA224, hmac_sha224, xmlSecNameHmacSha224, xmlSecHrefHmacSha224, HmacSha224;
    HMAC_SHA256, hmac_sha256, xmlSecNameHmacSha256, xmlSecHrefHmacSha256, HmacSha256;
    HMAC_SHA384, hmac_sha384, xmlSecNameHmacSha384, xmlSecHrefHmacSha384, HmacSha384;
    HMAC_SHA512, hmac_sha512, xmlSecNameHmacSha512, xmlSecHrefHmacSha512, HmacSha512;
}

/// The HMAC object of a valid transform of these klasses, after
/// libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform; a transform of these klasses was
/// initialized.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(&'a mut XmlSecTransform, SignatureAlgorithm, &'a mut Hmac)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the HMAC layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let algorithm = algorithm(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Hmac>>()).then_some(algorithm)
        });
        let Some(algorithm) = found else {
            errors::assertion(here, c"xmlSecOpenSSLHmacCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Hmac>>();
        Some((&mut with.transform, algorithm, &mut with.context))
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
                .and_then(|(object, _)| algorithm(object.id))
                .is_none()
            {
                errors::assertion(
                    here!("xmlSecOpenSSLHmacInitialize"),
                    c"xmlSecOpenSSLHmacCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Hmac>>()).context).write(Hmac {
                mac: None,
                output_bits: 0,
                secret_len: 0,
                keyed: false,
                pinned: None,
                result: None,
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
                .and_then(|(object, _)| algorithm(object.id))
                .is_some()
            {
                std::ptr::drop_in_place(&raw mut (*transform.cast::<WithContext<Hmac>>()).context);
            }
        }
    });
}

/// `readNode`: the optional `HMACOutputLength` child of the signature
/// method, checked against the library policy.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecTransformHmacReadOutputBitsSize");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, hmac)) =
            (unsafe { object(transform, here!("xmlSecOpenSSLHmacNodeRead")) })
        else {
            return -1;
        };
        if node.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        let name = name_of(object);
        // Within a run the method is read under the run's revision, which
        // then admits the key too, with or without an output length.
        if !ctx.is_null() {
            // SAFETY: a non-null context of the dispatcher.
            let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
                return -1;
            };
            hmac.pinned = Some(pinned);
        }
        // SAFETY: the out-pointer is a local.
        unsafe {
            let mut child = xmlSecGetNextElementNode(nodes::first_child(node));
            if !child.is_null()
                && xmlSecCheckNodeName(
                    child,
                    xmlSecNodeHMACOutputLength.as_ptr(),
                    xmlSecDSigNs.as_ptr(),
                ) != 0
            {
                let mut bits = hmac.output_bits;
                if xmlSecGetNodeContentAsSize(child, hmac.output_bits, &raw mut bits) != 0 {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecGetNodeContentAsSize(HMACOutputLength)",
                    );
                    return -1;
                }
                // The method is read before its operation may be set: a
                // length is refused here when the operation's policy refuses
                // it, or with no operation yet when neither policy admits it.
                // `set_key` checks it again under the operation's policy. The
                // revision is the context's run's, when there is a context.
                let pinned = match hmac.pinned.clone() {
                    Some(pinned) => Some(pinned),
                    None => policy::Pinned::current(here),
                };
                let Some(pinned) = pinned else {
                    return -1;
                };
                let verifying = pinned.verification.hmac.validate_output(algorithm, bits);
                let signing = pinned.signing.hmac.validate_output(algorithm, bits);
                let admitted = match object.operation {
                    OPERATION_SIGN => signing,
                    OPERATION_VERIFY => verifying,
                    _ => signing.or(verifying),
                };
                if let Err(violation) = admitted {
                    errors::invalid_node_content(
                        here,
                        child,
                        std::ptr::null(),
                        &violation.to_string(),
                    );
                    return -1;
                }
                hmac.output_bits = bits;
                hmac.pinned = Some(pinned);
                child = xmlSecGetNextElementNode(nodes::next(child));
            }
            if !child.is_null() {
                errors::unexpected_node(here, child, std::ptr::null());
                errors::internal(
                    here!("xmlSecOpenSSLHmacNodeRead"),
                    name,
                    c"xmlSecTransformHmacReadOutputBitsSize()",
                );
                return -1;
            }
        }
        0
    })
}

/// `setKeyReq`: a symmetric HMAC key for signing or verifying.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLHmacSetKeyReq");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, _)) = (unsafe { object(transform, here) }) else {
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
        req.key_id = symkeys::hmac().cast();
        req.key_type = TYPE_SYMMETRIC;
        req.key_usage = if object.operation == OPERATION_SIGN {
            KEY_USAGE_SIGN
        } else {
            KEY_USAGE_VERIFY
        };
        0
    })
}

/// `setKey`: the secret of the key's HMAC value starts the MAC.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLHmacSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, hmac)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !signs_or_verifies(object, here) {
            return -1;
        }
        if key.is_null() {
            errors::assertion(here, c"key != NULL");
            return -1;
        }
        if hmac.keyed {
            errors::assertion(here, c"ctx->ctxInitialized == 0");
            return -1;
        }
        let name = name_of(object);
        // SAFETY: a key whose value is null or key data.
        unsafe {
            let value = xmlSecKeyGetValue(key);
            if !check_id(value, symkeys::hmac()) {
                errors::assertion(
                    here,
                    c"xmlSecKeyDataCheckId(value, xmlSecOpenSSLKeyDataHmacId)",
                );
                return -1;
            }
            let buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
            let size = xmlSecBufferGetSize(buffer);
            if size == 0 {
                errors::report(
                    here,
                    name,
                    std::ptr::null(),
                    errors::R_INVALID_KEY_DATA_SIZE,
                    "invalid zero key data size",
                );
                return -1;
            }
            let secret = std::slice::from_raw_parts(xmlSecBufferGetData(buffer), size);
            // The revision the method was read under admits the key, else
            // the current one; the run's revision admits it again before
            // taking input.
            let Some(pinned) = hmac
                .pinned
                .clone()
                .or_else(|| policy::Pinned::current(here))
            else {
                return -1;
            };
            if let Err(refusal) =
                admit(object.operation, algorithm, size, hmac.output_bits, &pinned)
            {
                errors::internal_with(here, name, c"policy", &refusal);
                return -1;
            }
            hmac.secret_len = size;
            match IncrementalHmac::begin(algorithm, secret) {
                Ok(mac) => {
                    hmac.mac = Some(Box::new(mac));
                    hmac.keyed = true;
                }
                Err(error) => {
                    errors::internal_with(
                        here,
                        name,
                        c"IncrementalHmac::begin",
                        &error.to_string(),
                    );
                    return -1;
                }
            }
        }
        0
    })
}

/// Checks the method, a secret of `secret_len` bytes and the output length,
/// the full MAC when none is selected, against the policy of `operation` in
/// `pinned`, as signing-key validation and signature verification admit an
/// HMAC key.
fn admit(
    operation: c_int,
    algorithm: SignatureAlgorithm,
    secret_len: usize,
    output_bits: usize,
    pinned: &policy::Pinned,
) -> Result<(), String> {
    let refused = |error: &dyn std::fmt::Display| error.to_string();
    let full = algorithm
        .hmac_output_bits()
        .ok_or_else(|| "not an HMAC method".to_owned())?;
    let bits = if output_bits == 0 { full } else { output_bits };
    // Each branch first checks the snapshot itself, its authorization
    // lifetime included, before any of its rules admits the key.
    if operation == OPERATION_SIGN {
        let policy = &pinned.signing;
        policy.validate().map_err(|error| refused(&error))?;
        policy
            .resources
            .validate_key_candidates(1)
            .map_err(|error| refused(&error))?;
        policy
            .check_signature_algorithm(algorithm)
            .map_err(|error| refused(&error))?;
        policy
            .hmac
            .validate_key_bytes(secret_len)
            .map_err(|error| refused(&error))?;
        policy
            .hmac
            .validate_output(algorithm, bits)
            .map_err(|error| refused(&error))
    } else {
        let policy = &pinned.verification;
        // The key set on the transform is one the caller resolved, verified
        // without expected targets: the admission `verify_signature_value`
        // applies to the asymmetric transforms, and one inspected candidate.
        policy
            .check_supplied_key_verification(algorithm)
            .map_err(|error| refused(&error))?;
        policy
            .resources
            .validate_key_candidates(1)
            .map_err(|error| refused(&error))?;
        policy
            .hmac
            .validate_key_bytes(secret_len)
            .map_err(|error| refused(&error))?;
        policy
            .hmac
            .validate_output(algorithm, bits)
            .map_err(|error| refused(&error))
    }
}

/// The selected output length of `bits` in bytes, with the mask of its last
/// byte.
fn selected(bits: usize) -> (usize, u8) {
    (bits.div_ceil(8), LAST_BYTE_MASKS[bits % 8])
}

/// `verify`: the truncated MAC against `size` bytes at `data`, in constant
/// time; a mismatch is a failed status, not an error.
unsafe extern "C" fn verify(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    _ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLHmacVerify");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, hmac)) = (unsafe { object(transform, here) }) else {
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
            (hmac.output_bits > 0, c"ctx->dgstSizeInBits > 0"),
        ] {
            if !holds {
                errors::assertion(here, expression);
                return -1;
            }
        }
        let helper = here!("xmlSecTransformHmacVerify");
        if size == 0 {
            errors::assertion(helper, c"dataSize > 0");
            return -1;
        }
        let (length, _) = selected(hmac.output_bits);
        if size != length {
            errors::report(
                helper,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_SIZE,
                &format!(
                    "invalid size for 'HMAC digest': actual={size} is not equal to expected={length}"
                ),
            );
            object.status = STATUS_FAIL;
            return 0;
        }
        // SAFETY: the caller's `size` bytes.
        let expected = unsafe { std::slice::from_raw_parts(data, size) };
        let Some(tag) = hmac.result.as_ref() else {
            errors::assertion(here, c"transform->status == xmlSecTransformStatusFinished");
            return -1;
        };
        if tag.matches_truncated(expected, hmac.output_bits) {
            object.status = STATUS_OK;
        } else {
            errors::other(
                helper,
                errors::R_DATA_NOT_MATCH,
                std::ptr::null(),
                Some("data and digest do not match"),
            );
            object.status = STATUS_FAIL;
        }
        0
    })
}

/// Absorbs the input buffer of a working transform; on the `last` chunk
/// finishes the MAC and, when signing, writes it truncated to the output.
fn absorb(object: &mut XmlSecTransform, hmac: &mut Hmac, last: bool, here: Here) -> c_int {
    let name = name_of(object);
    let Some(mac) = hmac.mac.as_mut() else {
        errors::invalid_status(here, name, object.status);
        return -1;
    };
    let input = &raw mut object.in_buf;
    // SAFETY: the transform's own input buffer.
    unsafe {
        let size = xmlSecBufferGetSize(input);
        if size > 0 {
            mac.update(std::slice::from_raw_parts(xmlSecBufferGetData(input), size));
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
    let Some(mac) = hmac.mac.take() else {
        return -1;
    };
    let tag = hmac.result.insert(mac.finish());
    let full = tag.as_bytes().len();
    if hmac.output_bits == 0 {
        hmac.output_bits = full * 8;
    }
    let (length, mask) = selected(hmac.output_bits);
    if length > full {
        errors::report(
            here,
            name,
            std::ptr::null(),
            errors::R_NOT_IMPLEMENTED,
            &format!(
                "invalid size for 'HMAC output length': actual={length} is more than expected={full}"
            ),
        );
        return -1;
    }
    if object.operation == OPERATION_SIGN {
        let mut output = tag.as_bytes()[..length].to_vec();
        output[length - 1] &= mask;
        // SAFETY: the transform's own output buffer.
        if unsafe { xmlSecBufferAppend(&raw mut object.out_buf, output.as_ptr(), length) } < 0 {
            errors::internal_with(here, name, c"xmlSecBufferAppend", &format!("size={length}"));
            return -1;
        }
    }
    object.status = STATUS_FINISHED;
    0
}

/// `execute`: libxmlsec1's state machine over [`absorb`]; the key must have
/// been set.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLHmacExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, hmac)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if !signs_or_verifies(object, here) {
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        if object.status == STATUS_NONE {
            if hmac.mac.is_none() {
                errors::assertion(here, c"ctx->ctxInitialized != 0");
                return -1;
            }
            // The run's revision admits the method, the key and the output
            // length again before the first chunk: the key was admitted
            // under the revision current when it was set.
            // SAFETY: a non-null context, initialized by the dispatcher's
            // contract.
            let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
                return -1;
            };
            if let Err(refusal) = admit(
                object.operation,
                algorithm,
                hmac.secret_len,
                hmac.output_bits,
                &pinned,
            ) {
                errors::report(
                    here,
                    name_of(object),
                    std::ptr::null(),
                    errors::R_TRANSFORM_DISABLED,
                    &refusal,
                );
                return -1;
            }
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => absorb(object, hmac, last != 0, here),
            // Only reached without input.
            STATUS_FINISHED => {
                // SAFETY: the transform's own input buffer.
                if unsafe { xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
                    errors::assertion(here, c"xmlSecBufferGetSize(in) == 0");
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

/// `xmlSecTransformHmacGetMinOutputBitsSize`: the library policy's minimum
/// HMAC output length in bits.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecTransformHmacGetMinOutputBitsSize() -> usize {
    contain(0, || {
        policy::verification().map_or(0, |policy| policy.hmac.minimum_output_bits)
    })
}

/// `xmlSecTransformHmacSetMinOutputBitsSize`: republishes the library policy
/// with `val` as its minimum HMAC output length. The `XMLDSig` floor (80 bits
/// and half the digest) still applies below it, so a smaller value cannot
/// weaken verification; zero is kept as one, the policy's least value.
///
/// # Safety
/// Callable at any time; like libxmlsec1's setter, it is meant for
/// initialization, and a run already started keeps its snapshot.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecTransformHmacSetMinOutputBitsSize(val: usize) {
    contain((), || {
        let minimum = val.max(1);
        let published = policy::republish(
            |policy| policy.hmac.minimum_output_bits = minimum,
            |policy| policy.hmac.minimum_output_bits = minimum,
        );
        if published.is_none() {
            errors::policy_unavailable(here!("xmlSecTransformHmacSetMinOutputBitsSize"));
        }
    });
}

#[cfg(test)]
mod tests;
