//! The built-in provider's RSA key transport klasses: `rsa-oaep-mgf1p`, the
//! XML Encryption 1.1 `rsa-oaep` and, with historical algorithms compiled in,
//! `rsa-1_5`.
//!
//! Reading its `EncryptionMethod` the transform takes the OAEP digest, mask
//! digest and label the core parses there. It collects its input and, on the
//! final chunk, transports it to the key's public key or recovers it with the
//! key's private key through the selected provider, once the run's policy
//! admitted the transport, its digests and the RSA key.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::Arc;

use xml_sec::provider::{CryptoProvider, RecoveryValidity, RustCryptoRsaPublicKey};
use xml_sec::xmlenc::{
    EncryptionMethod, KEY_TRANSPORT_CIPHERTEXT_CEILING, KeyTransportAlgorithm, OaepDigestAlgorithm,
    RsaOaepParameters, XmlEncError, admit_key_transport_method, admit_oaep_parameters,
    validate_key_recovery_key, validate_key_transport_recipient,
};
use zeroize::Zeroizing;

use super::super::asymkeys::{self, material_of};
use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferMakeSecure,
    xmlSecBufferRemoveHead,
};
use super::super::errors::{self, Here, here};
use super::super::keys::{TYPE_PRIVATE, TYPE_PUBLIC, XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::check_id;
use super::super::tree::XmlNode;
use super::super::{contain, policy, strings};
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

/// The state of a key transport.
struct Transport {
    /// The OAEP parameters the `EncryptionMethod` names; the defaults
    /// without one.
    method: Option<EncryptionMethod>,
    /// The key's public key, from `setKey`.
    spki: Option<Vec<u8>>,
    /// The key's PKCS#8 private key, from `setKey` when decrypting.
    private: Option<Zeroizing<Vec<u8>>>,
    /// The input collected so far.
    data: Zeroizing<Vec<u8>>,
    /// The library policy the run started under.
    policy: Option<policy::Pinned>,
    /// The key width, in bytes, the `KeyInfo` reading the chain's
    /// `EncryptedKey` requires, taken when the run starts.
    #[cfg(feature = "legacy-algorithms")]
    expected: Option<usize>,
}

#[cfg(test)]
mod tests;

/// A transport klass of `name` and `href`.
const fn transport_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
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
            size_of::<WithContext<Transport>>(),
            name.as_ptr(),
            href.as_ptr(),
            USAGE_ENCRYPTION_METHOD,
        )
    }
}

static RSA_OAEP: XmlSecTransformKlass =
    transport_klass(&strings::xmlSecNameRsaOaep, &strings::xmlSecHrefRsaOaep);
static RSA_OAEP_ENC11: XmlSecTransformKlass = transport_klass(
    &strings::xmlSecNameRsaOaepEnc11,
    &strings::xmlSecHrefRsaOaepEnc11,
);

/// The built-in table's `rsa-oaep-mgf1p` klass.
pub(crate) extern "C" fn rsa_oaep() -> *const XmlSecTransformKlass {
    &raw const RSA_OAEP
}

/// The built-in table's XML Encryption 1.1 `rsa-oaep` klass.
pub(crate) extern "C" fn rsa_oaep_enc11() -> *const XmlSecTransformKlass {
    &raw const RSA_OAEP_ENC11
}

#[cfg(feature = "legacy-algorithms")]
static RSA_PKCS1: XmlSecTransformKlass =
    transport_klass(&strings::xmlSecNameRsaPkcs1, &strings::xmlSecHrefRsaPkcs1);

/// The built-in table's historical `rsa-1_5` klass.
#[cfg(feature = "legacy-algorithms")]
pub(crate) extern "C" fn rsa_pkcs1() -> *const XmlSecTransformKlass {
    &raw const RSA_PKCS1
}

/// The transport algorithm of klass `id`, `None` for any other.
fn method(id: *const XmlSecTransformKlass) -> Option<KeyTransportAlgorithm> {
    #[cfg(feature = "legacy-algorithms")]
    if std::ptr::eq(id, &raw const RSA_PKCS1) {
        return Some(KeyTransportAlgorithm::RsaPkcs1v15);
    }
    if std::ptr::eq(id, &raw const RSA_OAEP) {
        Some(KeyTransportAlgorithm::RsaOaepMgf1p)
    } else if std::ptr::eq(id, &raw const RSA_OAEP_ENC11) {
        Some(KeyTransportAlgorithm::RsaOaep11)
    } else {
        None
    }
}

/// The transport object of a valid transform of these klasses, after
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
    KeyTransportAlgorithm,
    &'a mut Transport,
)> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the transport layout.
    unsafe {
        let found = valid(transform).and_then(|(object, klass)| {
            let found = method(object.id)?;
            (klass.obj_size >= size_of::<WithContext<Transport>>()).then_some(found)
        });
        let Some(algorithm) = found else {
            errors::assertion(here, c"xmlSecOpenSSLRsaOaepCheckId(transform)");
            return None;
        };
        let with = &mut *transform.cast::<WithContext<Transport>>();
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
                    here!("xmlSecOpenSSLRsaOaepInitialize"),
                    c"xmlSecOpenSSLRsaOaepCheckId(transform)",
                );
                return -1;
            }
            (&raw mut (*transform.cast::<WithContext<Transport>>()).context).write(Transport {
                method: None,
                spki: None,
                private: None,
                data: Zeroizing::new(Vec::new()),
                policy: None,
                #[cfg(feature = "legacy-algorithms")]
                expected: None,
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
                    &raw mut (*transform.cast::<WithContext<Transport>>()).context,
                );
            }
        }
    });
}

/// `readNode`: the OAEP parameters of the `EncryptionMethod` element `node`,
/// as the core parses them.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLRsaOaepNodeRead");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, transport)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        // SAFETY: a non-null, initialized context.
        let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
            return -1;
        };
        // An encryption context sets the operation before the method is read.
        // A chain read before its operation is known, as libxmlsec1 reads a
        // standalone one, takes the element as untrusted input; `run` checks
        // an encryption's label against the encryption policy again.
        let parsed = if object.operation == OPERATION_ENCRYPT {
            parse_method(node, &*pinned.encryption, &pinned.encryption.resources)
        } else {
            parse_method(node, &*pinned.decryption, &pinned.decryption.resources)
        };
        // An OAEP method's digest and MGF identifiers are resolved as they
        // are read, as libxmlsec1's reader resolves them; whether the policy
        // admits them is decided when the transform runs.
        let parsed = parsed.and_then(|method| {
            if matches!(
                algorithm,
                KeyTransportAlgorithm::RsaOaepMgf1p | KeyTransportAlgorithm::RsaOaep11
            ) {
                parameters(algorithm, Some(&method)).map_err(|error| error.to_string())?;
            }
            Ok(method)
        });
        match parsed {
            Ok(method) => {
                transport.method = Some(method);
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

/// The `EncryptionMethod` element `node` as the core parses it, read under
/// the operation's `policy` and bounded by its `resources`.
fn parse_method(
    node: *mut XmlNode,
    policy: &impl xml_sec::XmlDocumentPolicy,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Result<EncryptionMethod, String> {
    let document =
        xml_sec_libxml2::document::subtree(node, policy).map_err(|error| error.to_string())?;
    document.with_view(|view| {
        EncryptionMethod::from_element(view.document().root_element(), resources)
            .map_err(|error| error.to_string())
    })
}

/// `setKeyReq`: an RSA key, public to encrypt and private to decrypt.
unsafe extern "C" fn set_key_req(transform: *mut XmlSecTransform, req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLRsaOaepSetKeyReq");
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
        req.key_id = asymkeys::rsa();
        (req.key_type, req.key_usage) = if object.operation == OPERATION_ENCRYPT {
            (TYPE_PUBLIC, KEY_USAGE_ENCRYPT)
        } else {
            (TYPE_PRIVATE, KEY_USAGE_DECRYPT)
        };
        0
    })
}

/// `setKey`: the key's public key, and its private key to decrypt.
unsafe extern "C" fn set_key(transform: *mut XmlSecTransform, key: *mut c_void) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLRsaOaepSetKey");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, transport)) = (unsafe { object(transform, here) }) else {
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
            if !check_id(value, asymkeys::rsa()) {
                errors::assertion(
                    here,
                    c"xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId)",
                );
                return -1;
            }
            let Some(material) = material_of(value) else {
                errors::internal(here, name_of(object), c"xmlSecKeyGetValue");
                return -1;
            };
            let Ok(spki) = material.value.to_spki_der() else {
                errors::internal(here, name_of(object), c"KeyValueInfo::to_spki_der");
                return -1;
            };
            if object.operation == OPERATION_DECRYPT && material.private.is_none() {
                errors::report(
                    here,
                    name_of(object),
                    std::ptr::null(),
                    errors::R_INVALID_KEY_DATA,
                    "the key holds no private key",
                );
                return -1;
            }
            transport.spki = Some(spki);
            transport.private = if object.operation == OPERATION_DECRYPT {
                material.private.clone()
            } else {
                None
            };
        }
        0
    })
}

/// The OAEP parameters `method` names for `algorithm`, defaults included.
fn parameters(
    algorithm: KeyTransportAlgorithm,
    method: Option<&EncryptionMethod>,
) -> Result<RsaOaepParameters, XmlEncError> {
    let digest_uri = method
        .and_then(|method| method.oaep_digest.as_deref())
        .unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1");
    let mgf_uri = method
        .and_then(|method| method.mgf_algorithm.as_deref())
        .unwrap_or("http://www.w3.org/2009/xmlenc11#mgf1sha1");
    Ok(RsaOaepParameters {
        algorithm,
        digest: OaepDigestAlgorithm::from_uri(digest_uri)
            .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(digest_uri.to_owned()))?,
        mgf_digest: OaepDigestAlgorithm::from_mgf_uri(mgf_uri)
            .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(mgf_uri.to_owned()))?,
        label: method
            .and_then(|method| method.oaep_params.clone())
            .unwrap_or_default(),
    })
}

/// Recovers an RSAES-PKCS1-v1_5 transported key of the width the reading
/// `KeyInfo` requires.
///
/// Departure: libxmlsec1 recovers a key of any width. Here the width is the
/// one the `EncryptedKey`'s consumer requires, and a rejected recovery
/// yields a random key of that width rather than an error, so the result
/// never reveals padding validity (XML Encryption 1.1 section 6.1.2). A chain
/// run outside a `KeyInfo` has no expected width and is refused.
/// <https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-bleichenbacher-attack>
#[cfg(feature = "legacy-algorithms")]
fn recover_pkcs1v15(
    provider: &dyn CryptoProvider,
    transport: &Transport,
    policy: &xml_sec::policy::DecryptionPolicy,
) -> Result<(Zeroizing<Vec<u8>>, RecoveryValidity), String> {
    let expected = transport.expected.ok_or(
        "RSAES-PKCS1-v1_5 recovery needs the key width the EncryptedKey's consumer requires",
    )?;
    policy
        .check_key_transport_algorithm(KeyTransportAlgorithm::RsaPkcs1v15)
        .map_err(|error| error.to_string())?;
    let private = transport.private.as_deref().ok_or("no private key")?;
    let recovery: Arc<dyn xml_sec::provider::KeyRecoveryKey> = provider
        .import_recovery_key(private)
        .map_err(|error| error.to_string())?;
    validate_key_recovery_key(recovery.as_ref(), policy).map_err(|error| error.to_string())?;
    provider
        .recover_pkcs1v15(recovery.as_ref(), &transport.data, expected)
        .and_then(xml_sec::provider::RecoveredContentKey::into_key_with_validity)
        .map_err(|error| error.to_string())
}

/// Transports or recovers the collected key under the run's policy, with
/// the validity of a recovery that rejects implicitly.
fn run(
    operation: c_int,
    algorithm: KeyTransportAlgorithm,
    transport: &Transport,
    pinned: &policy::Pinned,
) -> Result<(Zeroizing<Vec<u8>>, RecoveryValidity), String> {
    // Every transport but a PKCS #1 v1.5 recovery fails openly.
    let accepted = |key| (key, RecoveryValidity::accepted());
    let spki = transport.spki.as_deref().ok_or("no key")?;
    let public = RustCryptoRsaPublicKey::from_spki_der(spki).map_err(|error| error.to_string())?;
    let provider: &dyn CryptoProvider = xml_sec::provider::default_provider();
    if operation == OPERATION_ENCRYPT {
        pinned
            .encryption
            .validate()
            .map_err(|error| error.to_string())?;
        validate_key_transport_recipient(&public, &pinned.encryption)
            .map_err(|error| error.to_string())?;
        #[cfg(feature = "legacy-algorithms")]
        if algorithm == KeyTransportAlgorithm::RsaPkcs1v15 {
            pinned
                .encryption
                .check_key_transport_algorithm(algorithm)
                .map_err(|error| error.to_string())?;
            return provider
                .transport_pkcs1v15(&public, &transport.data)
                .map(|key| accepted(Zeroizing::new(key)))
                .map_err(|error| error.to_string());
        }
        let parameters =
            parameters(algorithm, transport.method.as_ref()).map_err(|error| error.to_string())?;
        admit_oaep_parameters(&parameters, &pinned.encryption)
            .map_err(|error| error.to_string())?;
        return provider
            .transport_key(&public, &parameters, &transport.data)
            .map(|key| accepted(Zeroizing::new(key)))
            .map_err(|error| error.to_string());
    }
    let policy = &pinned.decryption;
    policy.validate().map_err(|error| error.to_string())?;
    #[cfg(feature = "legacy-algorithms")]
    if algorithm == KeyTransportAlgorithm::RsaPkcs1v15 {
        return recover_pkcs1v15(provider, transport, policy);
    }
    let method = transport
        .method
        .clone()
        .unwrap_or_else(|| EncryptionMethod {
            algorithm: algorithm.uri().to_owned(),
            key_size_bits: None,
            oaep_digest: None,
            mgf_algorithm: None,
            oaep_params: None,
            chacha: None,
        });
    let parameters = admit_key_transport_method(&method, policy)
        .map_err(|error| error.to_string())?
        .ok_or("not an RSA-OAEP transport")?;
    let private = transport.private.as_deref().ok_or("no private key")?;
    let recovery: Arc<dyn xml_sec::provider::KeyRecoveryKey> = provider
        .import_recovery_key(private)
        .map_err(|error| error.to_string())?;
    validate_key_recovery_key(recovery.as_ref(), policy).map_err(|error| error.to_string())?;
    provider
        .recover_key(recovery.as_ref(), &parameters, &transport.data)
        .map(|key| accepted(Zeroizing::new(key)))
        .map_err(|error| error.to_string())
}

/// The key width, in bytes, the `KeyInfo` reading the chain's
/// `EncryptedKey` requires; `None` outside a `KeyInfo` or without a width.
///
/// # Safety
/// `ctx` is an initialized context whose parent is null or a live
/// `KeyInfo` context.
#[cfg(feature = "legacy-algorithms")]
unsafe fn expected_width(ctx: *mut XmlSecTransformCtx) -> Option<usize> {
    // SAFETY: by the caller's contract.
    let parent = unsafe {
        (*ctx)
            .parent_key_info_ctx
            .cast::<super::super::keyinfo::XmlSecKeyInfoCtx>()
            .as_ref()
    }?;
    let bits = parent.key_req.key_bits_size;
    (bits != 0 && bits % 8 == 0).then_some(bits / 8)
}

/// `execute`: collects the input; on the last chunk transports or recovers
/// it.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLRsaOaepExecute");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, algorithm, transport)) = (unsafe { object(transform, here) }) else {
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
            // SAFETY: a non-null, initialized context.
            let Some(pinned) = (unsafe { run_policy(ctx, here) }) else {
                return -1;
            };
            transport.policy = Some(pinned);
            #[cfg(feature = "legacy-algorithms")]
            {
                // SAFETY: a non-null, initialized context.
                transport.expected = unsafe { expected_width(ctx) };
            }
            object.status = STATUS_WORKING;
        }
        if object.status == STATUS_FINISHED {
            // SAFETY: the transform's own input buffer.
            if unsafe { xmlSecBufferGetSize(&raw mut object.in_buf) } != 0 {
                errors::assertion(here, c"xmlSecBufferGetSize(&(transform->inBuf)) == 0");
                return -1;
            }
            return 0;
        }
        if object.status != STATUS_WORKING {
            errors::invalid_status(here, name_of(object), object.status);
            return -1;
        }
        let name = name_of(object);
        let input = &raw mut object.in_buf;
        // SAFETY: the transform's own input buffer.
        unsafe {
            let size = xmlSecBufferGetSize(input);
            if size > 0 {
                if transport
                    .data
                    .len()
                    .checked_add(size)
                    .is_none_or(|total| total > KEY_TRANSPORT_CIPHERTEXT_CEILING)
                {
                    errors::limit_exceeded(
                        here,
                        name,
                        "RSA transport input",
                        KEY_TRANSPORT_CIPHERTEXT_CEILING,
                    );
                    return -1;
                }
                transport.data.extend_from_slice(std::slice::from_raw_parts(
                    xmlSecBufferGetData(input),
                    size,
                ));
                if xmlSecBufferRemoveHead(input, size) < 0 {
                    errors::internal(here, name, c"xmlSecBufferRemoveHead");
                    return -1;
                }
            }
        }
        if last == 0 {
            return 0;
        }
        let Some(pinned) = transport.policy.as_ref() else {
            errors::assertion(here, c"ctx->policy != NULL");
            return -1;
        };
        let output = match run(object.operation, algorithm, transport, pinned) {
            Ok((output, validity)) => {
                // The validity travels with the operation's spending, so the
                // content operation the key serves consults it once its
                // content work is done (XML Encryption 1.1 section 6.1.2).
                // SAFETY: a non-null, initialized context.
                let run = unsafe { super::ctx::run_budget(ctx) };
                run.recovery = run.recovery.and(validity);
                output
            }
            Err(error) => {
                errors::report(
                    here,
                    name,
                    std::ptr::null(),
                    errors::R_CRYPTO_FAILED,
                    &error,
                );
                return -1;
            }
        };
        // A decryption's output is the recovered key, marked as a secret as
        // libxmlsec1 marks it.
        if object.operation == OPERATION_DECRYPT {
            // SAFETY: the transform's own output buffer.
            unsafe { xmlSecBufferMakeSecure(&raw mut object.out_buf) };
        }
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
