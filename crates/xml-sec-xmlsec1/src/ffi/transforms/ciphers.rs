//! The built-in provider's symmetric cipher transform klasses: the AES-CBC,
//! AES-GCM, Camellia-CBC, `ChaCha20` and `ChaCha20-Poly1305` content ciphers and
//! the AES and Camellia key wraps.
//!
//! A transform collects its binary input. On the final chunk it encrypts or
//! decrypts it as one `XMLEnc` cipher value (the IV or nonce in front, CBC
//! padding as `XMLEnc` defines it, the GCM or Poly1305 tag behind), or wraps
//! or unwraps it as a key, through the selected provider, after the run's
//! policy admitted the algorithm, with the symmetric key of the klass's
//! family. The `ChaCha` klasses carry their nonce, counter and AAD in the
//! `EncryptionMethod` (draft-eastlake-rfc9231bis sections 2.6.7 and 2.6.8):
//! they read them as the core parses them, an encryption whose template
//! names no nonce draws one, and writing the method puts it there, as
//! libxmlsec1 does.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::policy::PolicyViolation;
use xml_sec::xmlenc::{
    ChaChaParameters, DataEncryptionAlgorithm, EncryptionMethod, KeyWrapAlgorithm,
};
use zeroize::Zeroizing;

use super::super::buffer::{
    xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferMakeSecure,
    xmlSecBufferRemoveHead,
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
/// block of CBC padding, or a 12-octet GCM nonce and a 16-octet tag; a key
/// wrap adds 8 octets.
const CIPHER_FRAMING: usize = 32;

/// What a klass of this module does.
#[derive(Clone, Copy)]
enum Method {
    /// Encrypts or decrypts content.
    Data(DataEncryptionAlgorithm),
    /// Wraps or unwraps a key.
    Wrap(KeyWrapAlgorithm),
}

impl Method {
    fn key_kind(self) -> xml_sec::key_manager::SymmetricKeyKind {
        match self {
            Self::Data(algorithm) => algorithm.key_kind(),
            Self::Wrap(algorithm) => algorithm.key_kind(),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Data(algorithm) => algorithm.key_len(),
            Self::Wrap(algorithm) => algorithm.key_len(),
        }
    }
}

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
    /// The run's method carries a key, taken with the policy: a block
    /// cipher is then admitted as a CBC key wrap, not as content.
    wraps_key: bool,
    /// A `ChaCha` klass's parameters, as `readNode` read them; an encryption
    /// that drew the nonce keeps it here for `writeNode`.
    chacha: Option<ChaChaParameters>,
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

/// A `ChaCha` klass of `name` and `href`, which reads and writes its
/// `EncryptionMethod` parameters.
const fn chacha_klass(name: &'static [u8], href: &'static [u8]) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        read_node: Some(read_node),
        write_node: Some(write_node),
        ..cipher_klass(name, href)
    }
}

macro_rules! ciphers {
    ($($(#[$meta:meta])* $klass:ident, $getter:ident, $make:ident($name:ident, $href:ident), $method:expr;)*) => {
        $(
            $(#[$meta])*
            static $klass: XmlSecTransformKlass =
                $make(&strings::$name, &strings::$href);

            $(#[$meta])*
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $getter() -> *const XmlSecTransformKlass {
                &raw const $klass
            }
        )*

        /// What klass `id` does, `None` for any other klass.
        fn method(id: *const XmlSecTransformKlass) -> Option<Method> {
            $(
                $(#[$meta])*
                if std::ptr::eq(id, &raw const $klass) {
                    return Some($method);
                }
            )*
            None
        }
    };
}

ciphers! {
    AES128_CBC, aes128_cbc, cipher_klass(xmlSecNameAes128Cbc, xmlSecHrefAes128Cbc), Method::Data(DataEncryptionAlgorithm::Aes128Cbc);
    #[cfg(feature = "legacy-algorithms")]
    AES192_CBC, aes192_cbc, cipher_klass(xmlSecNameAes192Cbc, xmlSecHrefAes192Cbc), Method::Data(DataEncryptionAlgorithm::Aes192Cbc);
    AES256_CBC, aes256_cbc, cipher_klass(xmlSecNameAes256Cbc, xmlSecHrefAes256Cbc), Method::Data(DataEncryptionAlgorithm::Aes256Cbc);
    AES128_GCM, aes128_gcm, cipher_klass(xmlSecNameAes128Gcm, xmlSecHrefAes128Gcm), Method::Data(DataEncryptionAlgorithm::Aes128Gcm);
    #[cfg(feature = "legacy-algorithms")]
    AES192_GCM, aes192_gcm, cipher_klass(xmlSecNameAes192Gcm, xmlSecHrefAes192Gcm), Method::Data(DataEncryptionAlgorithm::Aes192Gcm);
    AES256_GCM, aes256_gcm, cipher_klass(xmlSecNameAes256Gcm, xmlSecHrefAes256Gcm), Method::Data(DataEncryptionAlgorithm::Aes256Gcm);
    CAMELLIA128_CBC, camellia128_cbc, cipher_klass(xmlSecNameCamellia128Cbc, xmlSecHrefCamellia128Cbc), Method::Data(DataEncryptionAlgorithm::Camellia128Cbc);
    CAMELLIA192_CBC, camellia192_cbc, cipher_klass(xmlSecNameCamellia192Cbc, xmlSecHrefCamellia192Cbc), Method::Data(DataEncryptionAlgorithm::Camellia192Cbc);
    CAMELLIA256_CBC, camellia256_cbc, cipher_klass(xmlSecNameCamellia256Cbc, xmlSecHrefCamellia256Cbc), Method::Data(DataEncryptionAlgorithm::Camellia256Cbc);
    CHACHA20, chacha20, chacha_klass(xmlSecNameChaCha20, xmlSecHrefChaCha20), Method::Data(DataEncryptionAlgorithm::ChaCha20);
    CHACHA20_POLY1305, chacha20_poly1305, chacha_klass(xmlSecNameChaCha20Poly1305, xmlSecHrefChaCha20Poly1305), Method::Data(DataEncryptionAlgorithm::ChaCha20Poly1305);
    KW_AES128, kw_aes128, cipher_klass(xmlSecNameKWAes128, xmlSecHrefKWAes128), Method::Wrap(KeyWrapAlgorithm::AesKw128);
    #[cfg(feature = "legacy-algorithms")]
    KW_AES192, kw_aes192, cipher_klass(xmlSecNameKWAes192, xmlSecHrefKWAes192), Method::Wrap(KeyWrapAlgorithm::AesKw192);
    KW_AES256, kw_aes256, cipher_klass(xmlSecNameKWAes256, xmlSecHrefKWAes256), Method::Wrap(KeyWrapAlgorithm::AesKw256);
    KW_CAMELLIA128, kw_camellia128, cipher_klass(xmlSecNameKWCamellia128, xmlSecHrefKWCamellia128), Method::Wrap(KeyWrapAlgorithm::CamelliaKw128);
    KW_CAMELLIA192, kw_camellia192, cipher_klass(xmlSecNameKWCamellia192, xmlSecHrefKWCamellia192), Method::Wrap(KeyWrapAlgorithm::CamelliaKw192);
    KW_CAMELLIA256, kw_camellia256, cipher_klass(xmlSecNameKWCamellia256, xmlSecHrefKWCamellia256), Method::Wrap(KeyWrapAlgorithm::CamelliaKw256);
}

/// The key-data klass of the family `method` takes its key from.
fn key_klass(method: Method) -> *const XmlSecKeyDataKlass {
    match method.key_kind() {
        xml_sec::key_manager::SymmetricKeyKind::Camellia => symkeys::camellia(),
        xml_sec::key_manager::SymmetricKeyKind::ChaCha20 => symkeys::chacha20(),
        _ => symkeys::aes(),
    }
}

/// Whether `method` is a `ChaCha` profile, whose parameters live in its
/// `EncryptionMethod`.
fn is_chacha(method: Method) -> bool {
    matches!(
        method,
        Method::Data(DataEncryptionAlgorithm::ChaCha20 | DataEncryptionAlgorithm::ChaCha20Poly1305)
    )
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
) -> Option<(&'a mut XmlSecTransform, Method, &'a mut Cipher)> {
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
                wraps_key: false,
                chacha: None,
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
        req.key_id = key_klass(algorithm);
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

/// The run's admission of `method` for `operation` under `pinned`; a content
/// cipher of a run that wraps a key is admitted as that CBC key wrap, the
/// one permission its `EncryptedKey` was admitted under.
fn admit(
    pinned: &policy::Pinned,
    operation: c_int,
    method: Method,
    wraps_key: bool,
) -> Result<usize, PolicyViolation> {
    let method = match method {
        Method::Data(algorithm) if wraps_key => Method::Wrap(KeyWrapAlgorithm::Cbc(algorithm)),
        method => method,
    };
    if operation == OPERATION_ENCRYPT {
        let policy = &pinned.encryption;
        policy.validate()?;
        match method {
            Method::Data(algorithm) => policy.check_data_algorithm(algorithm)?,
            Method::Wrap(algorithm) => policy.check_key_wrap_algorithm(algorithm)?,
        }
        Ok(policy.resources.max_encryption_plaintext_bytes)
    } else {
        let policy = &pinned.decryption;
        policy.validate()?;
        match method {
            Method::Data(algorithm) => policy.check_data_algorithm(algorithm)?,
            Method::Wrap(algorithm) => policy.check_key_wrap_algorithm(algorithm)?,
        }
        Ok(policy.resources.max_encryption_plaintext_bytes)
    }
}

/// Moves the octets of the input buffer of `object` onto `data` within
/// `limit`: plaintext is bounded by it, a cipher value also by its framing
/// (an IV or nonce, padding or a tag). `None` after a report at `here`; a
/// refusal by the limit is recorded in `refused_by`.
fn take_input(
    object: &mut XmlSecTransform,
    data: &mut Vec<u8>,
    (limit, refused_by): (super::ctx::Limit, &mut Option<super::ctx::Limit>),
    here: Here,
) -> Option<()> {
    let name = name_of(object);
    let input = &raw mut object.in_buf;
    // SAFETY: the transform's own input buffer.
    unsafe {
        let size = xmlSecBufferGetSize(input);
        if size == 0 {
            return Some(());
        }
        let ceiling = if object.operation == OPERATION_ENCRYPT {
            Some(limit.max)
        } else {
            limit.max.checked_add(CIPHER_FRAMING)
        };
        if data
            .len()
            .checked_add(size)
            .zip(ceiling)
            .is_none_or(|(total, ceiling)| total > ceiling)
        {
            errors::limit_exceeded(here, name, limit.name, limit.max);
            refused_by.get_or_insert(limit);
            return None;
        }
        data.extend_from_slice(std::slice::from_raw_parts(xmlSecBufferGetData(input), size));
        if xmlSecBufferRemoveHead(input, size) < 0 {
            errors::internal_with(
                here,
                name,
                c"xmlSecBufferRemoveHead",
                &format!("size={size}"),
            );
            return None;
        }
    }
    Some(())
}

/// Collects the input buffer; on the `last` chunk encrypts or decrypts it.
/// A size refusal is recorded in `refused_by`, the run's: the operation's
/// plaintext allowance is spent, which ends the operation, as a resource
/// limit does, rather than one recipient.
fn collect(
    object: &mut XmlSecTransform,
    method: Method,
    cipher: &mut Cipher,
    (last, refused_by): (bool, &mut Option<super::ctx::Limit>),
    here: Here,
) -> c_int {
    let name = name_of(object);
    let Some(pinned) = cipher.policy.as_ref() else {
        errors::assertion(here, c"ctx->policy != NULL");
        return -1;
    };
    let maximum = match admit(pinned, object.operation, method, cipher.wraps_key) {
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
    let limit = super::ctx::Limit {
        name: "max_encryption_plaintext_bytes",
        max: maximum,
    };
    if take_input(object, &mut cipher.data, (limit, &mut *refused_by), here).is_none() {
        return -1;
    }
    if !last {
        return 0;
    }
    let Some(key) = cipher.key.as_deref() else {
        errors::assertion(here, c"ctx->keyInitialized != 0");
        return -1;
    };
    let provider = xml_sec::provider::default_provider();
    let encrypting = object.operation == OPERATION_ENCRYPT;
    let output = match method {
        Method::Data(algorithm) if is_chacha(method) => chacha_crypt(
            algorithm,
            key,
            (&mut cipher.chacha, &cipher.data),
            encrypting,
            provider,
        ),
        Method::Data(algorithm) if encrypting => provider
            .encrypt_data(algorithm, key, &cipher.data)
            .map_err(|error| error.to_string()),
        Method::Data(algorithm) => provider
            .decrypt_data(algorithm, key, &cipher.data)
            .map_err(|error| error.to_string()),
        Method::Wrap(algorithm) if encrypting => provider
            .wrap_key(algorithm, key, &cipher.data)
            .map_err(|error| error.to_string()),
        Method::Wrap(algorithm) => provider
            .unwrap_key(algorithm, key, &cipher.data)
            .map_err(|error| error.to_string()),
    };
    let output = match output {
        Ok(output) => Zeroizing::new(output),
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
    // The input allowance covers the framing, not the plaintext it frames.
    if !encrypting && output.len() > maximum {
        errors::limit_exceeded(here, name, limit.name, limit.max);
        refused_by.get_or_insert(limit);
        return -1;
    }
    // An unwrap's output is the recovered key, marked as a secret as
    // libxmlsec1 marks it.
    if !encrypting && matches!(method, Method::Wrap(_)) {
        // SAFETY: the transform's own output buffer.
        unsafe { xmlSecBufferMakeSecure(&raw mut object.out_buf) };
    }
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

/// `ChaCha` encryption or decryption of `data` with the method's `parameters`.
/// An encryption whose parameters name no nonce draws one from the provider
/// and keeps it in `parameters` for `writeNode`, as libxmlsec1 draws it; a
/// decryption needs the nonce its `EncryptionMethod` carries.
fn chacha_crypt(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    (parameters, data): (&mut Option<ChaChaParameters>, &[u8]),
    encrypting: bool,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<Vec<u8>, String> {
    let parameters = parameters.get_or_insert_with(ChaChaParameters::default);
    if parameters.nonce.is_none() {
        if !encrypting {
            return Err("the nonce is expected in the EncryptionMethod".to_owned());
        }
        let mut nonce = [0; 12];
        provider
            .fill_random(&mut nonce)
            .map_err(|error| error.to_string())?;
        parameters.nonce = Some(nonce);
    }
    let parameters = Some(parameters.borrowed());
    if encrypting {
        provider.encrypt_data_with_parameters(algorithm, key, data, parameters)
    } else {
        provider.decrypt_data_with_parameters(algorithm, key, data, parameters)
    }
    .map_err(|error| error.to_string())
}

/// `readNode` of the `ChaCha` klasses (libxmlsec1's
/// `xmlSecOpenSSLChaCha20NodeRead`): the nonce, counter and AAD of the
/// `EncryptionMethod` element `node`, as the core parses them under the
/// run's policy.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut super::super::tree::XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLChaCha20NodeRead");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, _, cipher)) = (unsafe { object(transform, here) }) else {
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
        let parsed = if object.operation == OPERATION_ENCRYPT {
            parse_method(node, &*pinned.encryption, &pinned.encryption.resources)
        } else {
            parse_method(node, &*pinned.decryption, &pinned.decryption.resources)
        };
        match parsed {
            Ok(method) => {
                cipher.chacha = method.chacha;
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
    node: *mut super::super::tree::XmlNode,
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

/// `writeNode` of the `ChaCha` klasses (libxmlsec1's
/// `xmlSecTransformChaCha20ParamsWrite` and its Poly1305 sibling): the nonce
/// the encryption used, and the `ChaCha20` counter after it, as the first
/// children of the `EncryptionMethod` element `node`, replacing ones there
/// and leaving an AAD in place.
unsafe extern "C" fn write_node(
    transform: *mut XmlSecTransform,
    node: *mut super::super::tree::XmlNode,
    _ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecOpenSSLChaCha20NodeWrite");
        // SAFETY: the dispatcher passes a transform.
        let Some((object, method, cipher)) = (unsafe { object(transform, here) }) else {
            return -1;
        };
        if node.is_null() {
            errors::assertion(here, c"node != NULL");
            return -1;
        }
        let Some(parameters) = cipher.chacha.as_ref() else {
            errors::assertion(here, c"ctx->ivInitialized != 0");
            return -1;
        };
        let Some(nonce) = parameters.nonce else {
            errors::assertion(here, c"ctx->ivInitialized != 0");
            return -1;
        };
        let mut fields: Vec<(&[u8], &[u8])> = vec![(&strings::xmlSecNodeChaCha20Nonce, &nonce)];
        let counter;
        if matches!(method, Method::Data(DataEncryptionAlgorithm::ChaCha20)) {
            let Some(value) = parameters.counter else {
                errors::assertion(here, c"ctx->ivInitialized != 0");
                return -1;
            };
            counter = value;
            fields.push((&strings::xmlSecNodeChaCha20Counter, &counter));
        }
        // SAFETY: the caller's live element.
        if unsafe { write_parameters(node, &fields) } {
            0
        } else {
            errors::internal(here, name_of(object), c"xmlSecTransformChaCha20ParamsWrite");
            -1
        }
    })
}

/// Writes each `(name, value)` of `fields` as a hexBinary child of `node`:
/// a parameter already there, in either form the reader accepts (RFC 9231's
/// unqualified one or the 2021 xmldsig-more namespace), is overwritten in
/// place, so it is never duplicated; a missing one is added in the 2021
/// namespace, in order, after any `KeySize`, which the reader requires first.
///
/// # Safety
/// `node` is a live element.
unsafe fn write_parameters(
    node: *mut super::super::tree::XmlNode,
    fields: &[(&[u8], &[u8])],
) -> bool {
    use super::super::tree::nodes;
    use super::super::xmltree::{
        xmlSecAddChild, xmlSecAddPrevSibling, xmlSecCheckNodeName, xmlSecGetNextElementNode,
        xmlSecSetNodeContentAsHex,
    };
    let namespace = strings::xmlSecDSig2021MoreNs.as_ptr();
    // SAFETY: by the caller's contract; every node handled is a live child
    // of `node` or a node just added to it.
    unsafe {
        let children = || {
            std::iter::successors(
                Some(xmlSecGetNextElementNode(nodes::first_child(node))).filter(|n| !n.is_null()),
                |&cur| Some(xmlSecGetNextElementNode(nodes::next(cur))).filter(|n| !n.is_null()),
            )
        };
        // New parameters go before the first child that is not a KeySize.
        let anchor = children().find(|&child| {
            xmlSecCheckNodeName(
                child,
                c"KeySize".as_ptr().cast(),
                strings::xmlSecEncNs.as_ptr(),
            ) == 0
        });
        for (name, value) in fields {
            let existing = children().find(|&child| {
                xmlSecCheckNodeName(child, name.as_ptr(), namespace) != 0
                    || xmlSecCheckNodeName(child, name.as_ptr(), std::ptr::null()) != 0
            });
            let target = match (existing, anchor) {
                (Some(existing), _) => existing,
                (None, Some(anchor)) => xmlSecAddPrevSibling(anchor, name.as_ptr(), namespace),
                (None, None) => xmlSecAddChild(node, name.as_ptr(), namespace),
            };
            if target.is_null()
                || xmlSecSetNodeContentAsHex(target, value.as_ptr(), value.len()) < 0
            {
                return false;
            }
        }
    }
    true
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
            // SAFETY: as above.
            cipher.wraps_key = unsafe { super::ctx::run_budget(ctx) }.wraps_key;
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                // SAFETY: as above.
                let refused_by = unsafe { &mut super::ctx::run_budget(ctx).refused_by };
                collect(object, algorithm, cipher, (last != 0, refused_by), here)
            }
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
