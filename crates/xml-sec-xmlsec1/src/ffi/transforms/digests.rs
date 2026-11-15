//! The built-in provider's digest transform klasses: one klass per digest
//! method URI, hashing its binary input through the provider and either
//! producing the digest (sign) or comparing it with an expected value
//! (verify), with libxmlsec1's state machine.

use std::ffi::{c_char, c_int};

use xml_sec::xmldsig::{DigestAlgorithm, IncrementalDigest, constant_time_eq};

use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferRemoveHead,
};
use super::super::contain;
use super::super::errors::{self, Here, here};
#[cfg(feature = "legacy-algorithms")]
use super::super::strings::{
    xmlSecHrefMd5, xmlSecHrefRipemd160, xmlSecNameMd5, xmlSecNameRipemd160,
};
use super::super::strings::{
    xmlSecHrefSha1, xmlSecHrefSha3_224, xmlSecHrefSha3_256, xmlSecHrefSha3_384, xmlSecHrefSha3_512,
    xmlSecHrefSha224, xmlSecHrefSha256, xmlSecHrefSha384, xmlSecHrefSha512, xmlSecNameSha1,
    xmlSecNameSha3_224, xmlSecNameSha3_256, xmlSecNameSha3_384, xmlSecNameSha3_512,
    xmlSecNameSha224, xmlSecNameSha256, xmlSecNameSha384, xmlSecNameSha512,
};
use super::builtin::klass;
use super::ctx::run_policy;
use super::{
    OPERATION_SIGN, OPERATION_VERIFY, STATUS_FAIL, STATUS_FINISHED, STATUS_NONE, STATUS_OK,
    STATUS_WORKING, USAGE_DIGEST_METHOD, WithContext, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, valid, xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPushBin,
};

/// The state of a digest transform: the running digest until the last
/// chunk, then the result.
struct Digest {
    state: Option<IncrementalDigest<'static>>,
    result: Vec<u8>,
}

/// A digest klass of `name` and `href`.
const fn digest_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        verify: Some(verify),
        push_bin: Some(xmlSecTransformDefaultPushBin),
        pop_bin: Some(xmlSecTransformDefaultPopBin),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<Digest>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_DIGEST_METHOD,
        )
    }
}

macro_rules! digests {
    ($($(#[$meta:meta])* $klass:ident, $getter:ident, $name:ident, $href:ident, $algorithm:ident;)*) => {
        $(
            $(#[$meta])*
            static $klass: XmlSecTransformKlass = digest_klass(&$name, &$href);

            $(#[$meta])*
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $getter() -> *const XmlSecTransformKlass {
                &raw const $klass
            }
        )*

        /// The digest algorithm of klass `id`, `None` for any other klass.
        fn algorithm(id: *const XmlSecTransformKlass) -> Option<DigestAlgorithm> {
            $(
                $(#[$meta])*
                if std::ptr::eq(id, &raw const $klass) {
                    return Some(DigestAlgorithm::$algorithm);
                }
            )*
            None
        }
    };
}

digests! {
    #[cfg(feature = "legacy-algorithms")]
    MD5, md5, xmlSecNameMd5, xmlSecHrefMd5, Md5;
    #[cfg(feature = "legacy-algorithms")]
    RIPEMD160, ripemd160, xmlSecNameRipemd160, xmlSecHrefRipemd160, Ripemd160;
    SHA1, sha1, xmlSecNameSha1, xmlSecHrefSha1, Sha1;
    SHA224, sha224, xmlSecNameSha224, xmlSecHrefSha224, Sha224;
    SHA256, sha256, xmlSecNameSha256, xmlSecHrefSha256, Sha256;
    SHA384, sha384, xmlSecNameSha384, xmlSecHrefSha384, Sha384;
    SHA512, sha512, xmlSecNameSha512, xmlSecHrefSha512, Sha512;
    SHA3_224, sha3_224, xmlSecNameSha3_224, xmlSecHrefSha3_224, Sha3_224;
    SHA3_256, sha3_256, xmlSecNameSha3_256, xmlSecHrefSha3_256, Sha3_256;
    SHA3_384, sha3_384, xmlSecNameSha3_384, xmlSecHrefSha3_384, Sha3_384;
    SHA3_512, sha3_512, xmlSecNameSha3_512, xmlSecHrefSha3_512, Sha3_512;
}

/// The digest object of a valid transform of these klasses, after
/// libxmlsec1's assertion at `here`.
///
/// # Safety
/// `transform` is null or a transform.
unsafe fn object<'a>(
    transform: *mut XmlSecTransform,
    here: Here,
) -> Option<(&'a mut XmlSecTransform, DigestAlgorithm, &'a mut Digest)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the digest layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let algorithm = algorithm(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Digest>>()).then_some(algorithm)
        });
        let Some(algorithm) = found else {
            errors::assertion(here, c"xmlSecOpenSSLEvpDigestCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Digest>>();
        Some((&mut with.transform, algorithm, &mut with.context))
    }
}

/// The transform's name for a report.
fn name_of(transform: &XmlSecTransform) -> *const c_char {
    // SAFETY: a valid transform's klass outlives it.
    unsafe { (*transform.id).name.cast() }
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpDigestInitialize");
        // SAFETY: the dispatcher passes a transform of these klasses, whose
        // zeroed tail is written here.
        unsafe {
            let found = valid(transform).and_then(|(object, _)| algorithm(object.id));
            if found.is_none() {
                errors::assertion(here, c"xmlSecOpenSSLEvpDigestCheckId(transform)");
                return -1;
            }
            let with = transform.cast::<WithContext<Digest>>();
            (&raw mut (*with).context).write(Digest {
                state: None,
                result: Vec::new(),
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
                std::ptr::drop_in_place(
                    &raw mut (*transform.cast::<WithContext<Digest>>()).context,
                );
            }
        }
    });
}

/// `verify`: the transform's digest against `size` bytes at `data`; a
/// mismatch is a failed status, not an error.
unsafe extern "C" fn verify(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpDigestVerify");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, digest)) = (unsafe { object(transform, here) }) else {
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
            (!digest.result.is_empty(), c"ctx->dgstSize > 0"),
        ] {
            if !holds {
                errors::assertion(here, expression);
                return -1;
            }
        }
        let name = name_of(object);
        if size != digest.result.len() {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_INVALID_SIZE,
                &format!(
                    "invalid size for 'Digest': actual={size} is not equal to expected={}",
                    digest.result.len()
                ),
            );
            object.status = STATUS_FAIL;
            return 0;
        }
        // SAFETY: the caller's `size` bytes.
        let expected = unsafe { std::slice::from_raw_parts(data, size) };
        if constant_time_eq(&digest.result, expected) {
            object.status = STATUS_OK;
        } else {
            errors::invalid_data(here, name, "data and digest do not match");
            object.status = STATUS_FAIL;
        }
        0
    })
}

/// Hashes the input buffer of a working transform; on the `last` chunk
/// finishes the digest and, when signing, writes it to the output buffer.
fn absorb(
    object: &mut XmlSecTransform,
    digest: &mut Digest,
    last: bool,
    here: Here,
    failed: &dyn Fn(&str, &dyn std::fmt::Display),
) -> c_int {
    let name = name_of(object);
    let Some(state) = digest.state.as_mut() else {
        errors::invalid_status(here, name, object.status);
        return -1;
    };
    let input = &raw mut object.in_buf;
    // SAFETY: the transform's own input buffer.
    unsafe {
        let size = xmlSecBufferGetSize(input);
        if size > 0 {
            let bytes = std::slice::from_raw_parts(xmlSecBufferGetData(input), size);
            if let Err(error) = state.update(bytes) {
                failed("update", &error);
                return -1;
            }
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
    let Some(state) = digest.state.take() else {
        return -1;
    };
    match state.finish() {
        Ok(output) => digest.result = output.to_vec(),
        Err(error) => {
            failed("finish", &error);
            return -1;
        }
    }
    if object.operation == OPERATION_SIGN {
        let size = digest.result.len();
        // SAFETY: the transform's own output buffer.
        let appended =
            unsafe { xmlSecBufferAppend(&raw mut object.out_buf, digest.result.as_ptr(), size) };
        if appended < 0 {
            errors::internal_with(here, name, c"xmlSecBufferAppend", &format!("size={size}"));
            return -1;
        }
    }
    object.status = STATUS_FINISHED;
    0
}

/// `execute`: hashes the input buffer; on the last chunk finishes the
/// digest and, when signing, writes it to the output buffer.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLEvpDigestExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, digest)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if object.operation != OPERATION_SIGN && object.operation != OPERATION_VERIFY {
            errors::assertion(
                here,
                c"(transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify)",
            );
            return -1;
        }
        if ctx.is_null() {
            errors::assertion(here, c"transformCtx != NULL");
            return -1;
        }
        let name = name_of(object);
        let failed = |step: &str, error: &dyn std::fmt::Display| {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_CRYPTO_FAILED,
                &format!("{step}: {error}"),
            );
        };
        if object.status == STATUS_NONE {
            // The operation's policy, of the run's revision, admits the
            // method before any input is hashed: the provider's capability
            // alone does not.
            // SAFETY: a non-null context, initialized by the dispatcher's
            // contract.
            let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
                return -1;
            };
            let admitted = if object.operation == OPERATION_SIGN {
                pinned
                    .signing
                    .validate()
                    .and_then(|()| pinned.signing.check_digest_algorithm(algorithm))
            } else {
                pinned
                    .verification
                    .validate()
                    .and_then(|()| pinned.verification.check_digest_algorithm(algorithm))
            };
            match admitted {
                Ok(()) => {}
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
            }
            match IncrementalDigest::begin(xml_sec::provider::default_provider(), algorithm) {
                Ok(state) => digest.state = Some(state),
                Err(error) => {
                    failed("begin", &error);
                    return -1;
                }
            }
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => absorb(object, digest, last != 0, here, &failed),
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
                errors::invalid_status(here, name, status);
                -1
            }
        }
    })
}

#[cfg(test)]
mod tests;
