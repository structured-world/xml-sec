//! `xmlsec/app.h`, `xmlsec/dl.h` and `xmlSecCryptoDLFunctions`: the crypto
//! function table, its loading by name and the `xmlSecCrypto*` entry points
//! that dispatch through the current table.
//!
//! libxmlsec1 loads a crypto library (`libxmlsec1-openssl`, ...) by name and
//! takes its function table. This library loads no library: the one name it
//! knows is its built-in provider's, [`xmlSecGetDefaultCrypto`], whose table
//! it holds itself; any other name is refused. A caller may still install
//! its own table with `xmlSecCryptoDLSetFunctions` and register its klasses
//! with `xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms`, as with
//! libxmlsec1. An entry point whose table entry is missing reports
//! libxmlsec1's "method is missing" error and fails.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

use super::contain;
use super::errors::{self, check, here};
use super::keysdata::{
    XmlSecKeyDataKlass, XmlSecKeyDataStoreKlass, xmlSecKeyDataIdsRegister,
    xmlSecKeyDataIdsRegisterDisabled,
};
use super::library::xmlSecGetDefaultCrypto;
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListInitialize, xmlSecPtrListRemove,
};
use super::transforms::{Global, XmlSecTransformKlass, xmlSecTransformIdsRegister, zero_list};

/// An opaque `xmlSecKeysMngrPtr`, `xmlSecKeyPtr` or `xmlSecKeyInfoCtxPtr`.
type Opaque = *mut c_void;

/// A key-data klass getter of the table.
type KeyDataGetter = Option<unsafe extern "C" fn() -> *const XmlSecKeyDataKlass>;
/// A transform klass getter of the table.
type TransformGetter = Option<unsafe extern "C" fn() -> *const XmlSecTransformKlass>;

/// Declares `xmlSecCryptoDLFunctions` in libxmlsec1's member order, with
/// the key-data and transform klass getters between the crypto and the
/// application methods.
macro_rules! functions_table {
    (
        crypto { $($crypto:ident: $crypto_ty:ty,)* }
        key_data { $($key_data:ident,)* }
        store { $store:ident }
        transforms { $($transform:ident,)* }
        app { $($app:ident: $app_ty:ty,)* }
    ) => {
        /// `xmlSecCryptoDLFunctions`.
        #[repr(C)]
        pub(crate) struct XmlSecCryptoDLFunctions {
            $(pub(crate) $crypto: $crypto_ty,)*
            $(pub(crate) $key_data: KeyDataGetter,)*
            pub(crate) $store: Option<unsafe extern "C" fn() -> *const XmlSecKeyDataStoreKlass>,
            $(pub(crate) $transform: TransformGetter,)*
            $(pub(crate) $app: $app_ty,)*
            pub(crate) crypto_app_default_pwd_callback: *mut c_void,
        }

        impl XmlSecCryptoDLFunctions {
            /// A table with no method.
            const fn empty() -> Self {
                Self {
                    $($crypto: None,)*
                    $($key_data: None,)*
                    $store: None,
                    $($transform: None,)*
                    $($app: None,)*
                    crypto_app_default_pwd_callback: std::ptr::null_mut(),
                }
            }
        }
    };
}

functions_table! {
    crypto {
        crypto_init: Option<unsafe extern "C" fn() -> c_int>,
        crypto_shutdown: Option<unsafe extern "C" fn() -> c_int>,
        crypto_keys_mngr_init: Option<unsafe extern "C" fn(Opaque) -> c_int>,
    }
    key_data {
        key_data_aes, key_data_camellia, key_data_chacha20, key_data_concat_kdf, key_data_des,
        key_data_dh, key_data_dsa, key_data_ec, key_data_gost2001,
        key_data_gost_r3410_2012_256, key_data_gost_r3410_2012_512, key_data_hkdf,
        key_data_hmac, key_data_mldsa, key_data_mlkem, key_data_pbkdf2, key_data_rsa,
        key_data_slhdsa, key_data_eddsa, key_data_xdh, key_data_x509, key_data_raw_x509_cert,
        key_data_der_encoded_key_value,
    }
    store { x509_store }
    transforms {
        transform_aes128_cbc, transform_aes192_cbc, transform_aes256_cbc,
        transform_aes128_gcm, transform_aes192_gcm, transform_aes256_gcm,
        transform_kw_aes128, transform_kw_aes192, transform_kw_aes256,
        transform_camellia128_cbc, transform_camellia192_cbc, transform_camellia256_cbc,
        transform_kw_camellia128, transform_kw_camellia192, transform_kw_camellia256,
        transform_chacha20, transform_chacha20_poly1305,
        transform_concat_kdf,
        transform_des3_cbc, transform_kw_des3,
        transform_dh_es,
        transform_dsa_sha1, transform_dsa_sha256,
        transform_ecdh,
        transform_x448, transform_x25519,
        transform_ecdsa_ripemd160, transform_ecdsa_sha1, transform_ecdsa_sha224,
        transform_ecdsa_sha256, transform_ecdsa_sha384, transform_ecdsa_sha512,
        transform_ecdsa_sha3_224, transform_ecdsa_sha3_256, transform_ecdsa_sha3_384,
        transform_ecdsa_sha3_512,
        transform_gost2001_gost_r3411_94, transform_gost_r3410_2012_gost_r3411_2012_256,
        transform_gost_r3410_2012_gost_r3411_2012_512,
        transform_gost_r3411_94, transform_gost_r3411_2012_256, transform_gost_r3411_2012_512,
        transform_hkdf,
        transform_hmac_md5, transform_hmac_ripemd160, transform_hmac_sha1,
        transform_hmac_sha224, transform_hmac_sha256, transform_hmac_sha384,
        transform_hmac_sha512,
        transform_mldsa44, transform_mldsa65, transform_mldsa87,
        transform_mlkem512, transform_mlkem768, transform_mlkem1024,
        transform_md5, transform_pbkdf2, transform_ripemd160,
        transform_rsa_md5, transform_rsa_ripemd160, transform_rsa_sha1, transform_rsa_sha224,
        transform_rsa_sha256, transform_rsa_sha384, transform_rsa_sha512,
        transform_rsa_pss_sha1,
        transform_rsa_pss_sha224, transform_rsa_pss_sha256, transform_rsa_pss_sha384,
        transform_rsa_pss_sha512,
        transform_rsa_pss_sha3_224, transform_rsa_pss_sha3_256, transform_rsa_pss_sha3_384,
        transform_rsa_pss_sha3_512,
        transform_rsa_pkcs1, transform_rsa_oaep, transform_rsa_oaep_enc11,
        transform_slhdsa_sha2_128f, transform_slhdsa_sha2_128s, transform_slhdsa_sha2_192f,
        transform_slhdsa_sha2_192s, transform_slhdsa_sha2_256f, transform_slhdsa_sha2_256s,
        transform_eddsa_ed25519, transform_eddsa_ed25519ctx, transform_eddsa_ed25519ph,
        transform_eddsa_ed448, transform_eddsa_ed448ph,
        transform_sha1,
        transform_sha224, transform_sha256, transform_sha384, transform_sha512,
        transform_sha3_224, transform_sha3_256, transform_sha3_384, transform_sha3_512,
    }
    app {
        crypto_app_init: Option<unsafe extern "C" fn(*const c_char) -> c_int>,
        crypto_app_shutdown: Option<unsafe extern "C" fn() -> c_int>,
        crypto_app_default_keys_mngr_init: Option<unsafe extern "C" fn(Opaque) -> c_int>,
        crypto_app_default_keys_mngr_adopt_key: Option<unsafe extern "C" fn(Opaque, Opaque) -> c_int>,
        crypto_app_default_keys_mngr_verify_key:
            Option<unsafe extern "C" fn(Opaque, Opaque, Opaque) -> c_int>,
        crypto_app_default_keys_mngr_load: Option<unsafe extern "C" fn(Opaque, *const c_char) -> c_int>,
        crypto_app_default_keys_mngr_save:
            Option<unsafe extern "C" fn(Opaque, *const c_char, c_uint) -> c_int>,
        crypto_app_keys_mngr_cert_load:
            Option<unsafe extern "C" fn(Opaque, *const c_char, c_int, c_uint) -> c_int>,
        crypto_app_keys_mngr_cert_load_memory:
            Option<unsafe extern "C" fn(Opaque, *const u8, usize, c_int, c_uint) -> c_int>,
        crypto_app_keys_mngr_crl_load: Option<unsafe extern "C" fn(Opaque, *const c_char, c_int) -> c_int>,
        crypto_app_keys_mngr_crl_load_and_verify:
            Option<unsafe extern "C" fn(Opaque, *const c_char, c_int, Opaque) -> c_int>,
        crypto_app_keys_mngr_crl_load_memory:
            Option<unsafe extern "C" fn(Opaque, *const u8, usize, c_int) -> c_int>,
        crypto_app_key_load: Option<
            unsafe extern "C" fn(*const c_char, c_int, *const c_char, *mut c_void, *mut c_void) -> Opaque,
        >,
        crypto_app_key_load_ex: Option<
            unsafe extern "C" fn(
                *const c_char,
                c_uint,
                c_int,
                *const c_char,
                *mut c_void,
                *mut c_void,
            ) -> Opaque,
        >,
        crypto_app_key_load_memory: Option<
            unsafe extern "C" fn(*const u8, usize, c_int, *const c_char, *mut c_void, *mut c_void) -> Opaque,
        >,
        crypto_app_pkcs12_load:
            Option<unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, *mut c_void) -> Opaque>,
        crypto_app_pkcs12_load_memory: Option<
            unsafe extern "C" fn(*const u8, usize, *const c_char, *mut c_void, *mut c_void) -> Opaque,
        >,
        crypto_app_key_cert_load: Option<unsafe extern "C" fn(Opaque, *const c_char, c_int) -> c_int>,
        crypto_app_key_cert_load_memory:
            Option<unsafe extern "C" fn(Opaque, *const u8, usize, c_int) -> c_int>,
    }
}

/// The table of the built-in provider, at a fixed address: libxmlsec1
/// hands a crypto library's table out by pointer, and callers may change it
/// before installing it, as with a loaded library's.
static BUILTIN: Global<XmlSecCryptoDLFunctions> = Global::new(XmlSecCryptoDLFunctions {
    crypto_init: Some(builtin_crypto_init),
    crypto_shutdown: Some(builtin_crypto_shutdown),
    crypto_app_init: Some(builtin_crypto_app_init),
    crypto_app_shutdown: Some(builtin_crypto_app_shutdown),
    ..XmlSecCryptoDLFunctions::empty()
});

/// `cryptoInit` of the built-in table: registers its klasses, as a crypto
/// library's initialization registers its own.
unsafe extern "C" fn builtin_crypto_init() -> c_int {
    // SAFETY: the built-in table has a fixed address.
    if unsafe { xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(BUILTIN.get()) } < 0 {
        errors::internal(
            here!("xmlSecCryptoInit"),
            std::ptr::null(),
            c"xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms",
        );
        return -1;
    }
    0
}

/// `cryptoShutdown` of the built-in table: the provider holds no state.
unsafe extern "C" fn builtin_crypto_shutdown() -> c_int {
    0
}

/// `cryptoAppInit` of the built-in table: the provider takes no
/// configuration, so a configuration path is refused rather than ignored.
unsafe extern "C" fn builtin_crypto_app_init(config: *const c_char) -> c_int {
    if !config.is_null() {
        errors::not_implemented(
            here!("xmlSecCryptoAppInit"),
            "the built-in crypto provider takes no configuration",
        );
        return -1;
    }
    0
}

/// `cryptoAppShutdown` of the built-in table.
unsafe extern "C" fn builtin_crypto_app_shutdown() -> c_int {
    0
}

// ----------------------------------------------------------------------------
// Loading by name

/// One library of the loaded list: its name and its table.
struct Library {
    name: Vec<u8>,
    functions: *mut XmlSecCryptoDLFunctions,
}

unsafe extern "C" fn duplicate_library(item: *mut c_void) -> *mut c_void {
    // SAFETY: every item of the library list is a leaked `Library`.
    let Some(library) = (unsafe { item.cast::<Library>().as_ref() }) else {
        errors::assertion(here!("xmlSecCryptoDLLibraryDuplicate"), c"lib != NULL");
        return std::ptr::null_mut();
    };
    create_library(&library.name).cast()
}

unsafe extern "C" fn destroy_library(item: *mut c_void) {
    if !item.is_null() {
        // SAFETY: every item of the library list is a leaked `Library`.
        drop(unsafe { Box::from_raw(item.cast::<Library>()) });
    }
}

static LIBRARY_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"dl-libraries-list".as_ptr().cast(),
    duplicate_item: Some(duplicate_library),
    destroy_item: Some(destroy_library),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// The libraries loaded so far.
static LIBRARIES: Global<XmlSecPtrList> = Global::new(zero_list());
/// The table the `xmlSecCrypto*` entry points dispatch through.
static CURRENT: AtomicPtr<XmlSecCryptoDLFunctions> = AtomicPtr::new(std::ptr::null_mut());

/// The library `name` names: the built-in provider's table for its name;
/// any other name is refused, as libxmlsec1 refuses a name it cannot load.
fn create_library(name: &[u8]) -> *mut Library {
    let here = here!("xmlSecCryptoDLLibraryCreate");
    // SAFETY: the default crypto name is a static NUL-terminated string.
    let builtin = unsafe { CStr::from_ptr(xmlSecGetDefaultCrypto().cast()) }.to_bytes();
    if name != builtin {
        // libxmlsec1's report when it has no way to load a library: this
        // library loads none.
        errors::internal(
            here,
            std::ptr::null(),
            c"invalid configuration: no way to load library",
        );
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(Library {
        name: name.to_vec(),
        functions: BUILTIN.get(),
    }))
}

/// The position of the library `name` in the loaded list.
fn find_library(name: &[u8]) -> Option<usize> {
    // SAFETY: the list has a fixed address.
    let list = unsafe { &*LIBRARIES.get() };
    if !std::ptr::eq(list.id, &raw const LIBRARY_LIST) {
        errors::assertion(
            here!("xmlSecCryptoDLLibrariesListFindByName"),
            c"xmlSecPtrListCheckId(list, xmlSecCryptoDLLibrariesListGetKlass())",
        );
        return None;
    }
    let items: &[*mut Library] = if list.used == 0 || list.data.is_null() {
        &[]
    } else {
        // SAFETY: a list's first `used` items are its entries.
        unsafe { std::slice::from_raw_parts(list.data.cast(), list.used) }
    };
    items.iter().position(|&item| {
        // SAFETY: the list holds the libraries `create_library` made.
        unsafe { item.as_ref() }.is_some_and(|library| library.name == name)
    })
}

/// `xmlSecCryptoDLInit`: an empty list of loaded libraries.
///
/// # Safety
/// Called during initialization, while nothing reads the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLInit() -> c_int {
    contain(-1, || {
        // SAFETY: the list has a fixed address and is not in use.
        if unsafe { xmlSecPtrListInitialize(LIBRARIES.get(), &raw const LIBRARY_LIST) } < 0 {
            errors::internal(
                here!("xmlSecCryptoDLInit"),
                c"xmlSecCryptoDLLibrariesListGetKlass".as_ptr(),
                c"xmlSecPtrListInitialize",
            );
            return -1;
        }
        0
    })
}

/// `xmlSecCryptoDLShutdown`: releases the loaded libraries; the current
/// table stays as libxmlsec1 leaves it.
///
/// # Safety
/// Called during shutdown, while nothing reads the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLShutdown() -> c_int {
    contain(-1, || {
        // SAFETY: the list has a fixed address and is not in use.
        unsafe { xmlSecPtrListFinalize(LIBRARIES.get()) };
        0
    })
}

/// `xmlSecCryptoDLLoadLibrary`: installs the table of the library `crypto`
/// names, the default crypto when null.
///
/// # Safety
/// `crypto` is null or NUL-terminated; called while nothing dispatches.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLLoadLibrary(crypto: *const u8) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecCryptoDLLoadLibrary");
        let name = if crypto.is_null() {
            xmlSecGetDefaultCrypto()
        } else {
            crypto
        };
        // SAFETY: by the caller's contract.
        let functions = unsafe { xmlSecCryptoDLGetLibraryFunctions(name) };
        if functions.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecCryptoDLGetLibraryFunctions");
            return -1;
        }
        // SAFETY: a library's table.
        if unsafe { xmlSecCryptoDLSetFunctions(functions) } < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecCryptoDLSetFunctions");
            return -1;
        }
        0
    })
}

/// `xmlSecCryptoDLGetLibraryFunctions`: the table of the library `crypto`
/// names, loaded once.
///
/// # Safety
/// `crypto` is null or NUL-terminated; called while nothing dispatches.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLGetLibraryFunctions(
    crypto: *const u8,
) -> *mut XmlSecCryptoDLFunctions {
    contain(std::ptr::null_mut(), || {
        let null = std::ptr::null_mut();
        check!(
            !crypto.is_null(),
            "xmlSecCryptoDLGetLibraryFunctions",
            c"crypto != NULL",
            null
        );
        let here = here!("xmlSecCryptoDLGetLibraryFunctions");
        // SAFETY: `crypto` is NUL-terminated.
        let name = unsafe { CStr::from_ptr(crypto.cast()) }.to_bytes();
        if let Some(position) = find_library(name) {
            // SAFETY: the list holds the libraries `create_library` made.
            let library =
                unsafe { &**(*LIBRARIES.get()).data.add(position).cast::<*mut Library>() };
            return library.functions;
        }
        let detail = format!("crypto={}", String::from_utf8_lossy(name));
        let library = create_library(name);
        if library.is_null() {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecCryptoDLLibraryCreate",
                &detail,
            );
            return null;
        }
        // SAFETY: the list has a fixed address; it owns the library from here.
        if unsafe { xmlSecPtrListAdd(LIBRARIES.get(), library.cast()) } < 0 {
            errors::internal_with(here, std::ptr::null(), c"xmlSecPtrListAdd", &detail);
            // SAFETY: the list did not take the library.
            unsafe { destroy_library(library.cast()) };
            return null;
        }
        // SAFETY: the library just made.
        unsafe { (*library).functions }
    })
}

/// `xmlSecCryptoDLUnloadLibrary`: forgets the library `crypto` names; its
/// table stops being the current one.
///
/// # Safety
/// `crypto` is null or NUL-terminated; called while nothing dispatches.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLUnloadLibrary(crypto: *const u8) -> c_int {
    contain(-1, || {
        check!(
            !crypto.is_null(),
            "xmlSecCryptoDLUnloadLibrary",
            c"crypto != NULL",
            -1
        );
        // SAFETY: `crypto` is NUL-terminated.
        let name = unsafe { CStr::from_ptr(crypto.cast()) }.to_bytes();
        // libxmlsec1 treats a library that is not loaded as unloaded.
        let Some(position) = find_library(name) else {
            return 0;
        };
        // SAFETY: the list holds the libraries `create_library` made.
        let library = unsafe { *(*LIBRARIES.get()).data.add(position).cast::<*mut Library>() };
        // SAFETY: a listed library.
        if let Some(library) = unsafe { library.as_ref() }
            && std::ptr::eq(CURRENT.load(Ordering::Acquire), library.functions)
        {
            // Unloading is not thread-safe, as libxmlsec1 documents: no
            // installation runs concurrently.
            CURRENT.store(std::ptr::null_mut(), Ordering::Release);
        }
        // SAFETY: the list has a fixed address.
        if unsafe { xmlSecPtrListRemove(LIBRARIES.get(), position) } < 0 {
            errors::internal(
                here!("xmlSecCryptoDLUnloadLibrary"),
                std::ptr::null(),
                c"xmlSecPtrListRemove",
            );
            return -1;
        }
        0
    })
}

/// `xmlSecCryptoDLSetFunctions`: the table the entry points dispatch
/// through from now on.
///
/// # Safety
/// `functions` is null or a table that outlives its use.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLSetFunctions(
    functions: *mut XmlSecCryptoDLFunctions,
) -> c_int {
    contain(-1, || {
        check!(
            !functions.is_null(),
            "xmlSecCryptoDLSetFunctions",
            c"functions != NULL",
            -1
        );
        CURRENT.store(functions, Ordering::Release);
        0
    })
}

/// `xmlSecCryptoDLGetFunctions`: the current table, null before one is
/// installed.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLGetFunctions() -> *mut XmlSecCryptoDLFunctions {
    CURRENT.load(Ordering::Acquire)
}

/// Registers the klass a key-data getter of a table returns, enabled or not.
///
/// # Safety
/// `getter` returns a klass that outlives its registration.
unsafe fn register_key_data(getter: KeyDataGetter, enabled: bool) -> Option<()> {
    let Some(getter) = getter else {
        return Some(());
    };
    // SAFETY: by the caller's contract.
    let id = unsafe { getter() };
    // SAFETY: registering a klass during initialization.
    let (registered, step) = unsafe {
        if enabled {
            (xmlSecKeyDataIdsRegister(id), c"xmlSecKeyDataIdsRegister")
        } else {
            (
                xmlSecKeyDataIdsRegisterDisabled(id),
                c"xmlSecKeyDataIdsRegisterDisabled",
            )
        }
    };
    if registered < 0 {
        // SAFETY: a klass is null or has a name.
        let name = unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name.cast());
        errors::internal(
            here!("xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms"),
            name,
            step,
        );
        return None;
    }
    Some(())
}

/// Registers the klass a transform getter of a table returns.
///
/// # Safety
/// `getter` returns a klass that outlives its registration.
unsafe fn register_transform(getter: TransformGetter) -> Option<()> {
    let Some(getter) = getter else {
        return Some(());
    };
    // SAFETY: by the caller's contract.
    let id = unsafe { getter() };
    // SAFETY: registering a klass during initialization.
    if unsafe { xmlSecTransformIdsRegister(id) } < 0 {
        // SAFETY: a klass is null or has a name.
        let name = unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name.cast());
        errors::internal(
            here!("xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms"),
            name,
            c"xmlSecTransformIdsRegister",
        );
        return None;
    }
    Some(())
}

/// `xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms`: registers every
/// klass the table provides, in libxmlsec1's order and with its enabled
/// subset: raw key values and DER-encoded key values are registered
/// disabled, X.509 data enabled.
///
/// # Safety
/// `functions` is null or a table whose getters return klasses that outlive
/// their registration; called during initialization.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(
    functions: *mut XmlSecCryptoDLFunctions,
) -> c_int {
    contain(-1, || {
        check!(
            !functions.is_null(),
            "xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms",
            c"functions != NULL",
            -1
        );
        // SAFETY: a table by the caller's contract.
        let table = unsafe { &*functions };
        // SAFETY: the table's getters return klasses by the caller's contract.
        let registered = unsafe {
            table
                .disabled_key_data()
                .into_iter()
                .try_for_each(|getter| register_key_data(getter, false))
                .and_then(|()| {
                    [table.key_data_x509, table.key_data_raw_x509_cert]
                        .into_iter()
                        .try_for_each(|getter| register_key_data(getter, true))
                })
                .and_then(|()| {
                    table
                        .transforms_in_registration_order()
                        .into_iter()
                        .chain(table.later_transforms_in_registration_order())
                        .try_for_each(|getter| register_transform(getter))
                })
        };
        if registered.is_some() { 0 } else { -1 }
    })
}

impl XmlSecCryptoDLFunctions {
    /// The key-data getters libxmlsec1 registers disabled, in its order:
    /// raw key values and DER-encoded key values.
    fn disabled_key_data(&self) -> [KeyDataGetter; 21] {
        let table = self;
        [
            table.key_data_aes,
            table.key_data_camellia,
            table.key_data_chacha20,
            table.key_data_concat_kdf,
            table.key_data_des,
            table.key_data_dh,
            table.key_data_dsa,
            table.key_data_ec,
            table.key_data_gost2001,
            table.key_data_gost_r3410_2012_256,
            table.key_data_gost_r3410_2012_512,
            table.key_data_hmac,
            table.key_data_hkdf,
            table.key_data_mldsa,
            table.key_data_mlkem,
            table.key_data_pbkdf2,
            table.key_data_rsa,
            table.key_data_slhdsa,
            table.key_data_eddsa,
            table.key_data_xdh,
            table.key_data_der_encoded_key_value,
        ]
    }

    /// The first transform getters in libxmlsec1's registration order;
    /// AES-192-CBC comes twice, as libxmlsec1 registers it.
    fn transforms_in_registration_order(&self) -> [TransformGetter; 50] {
        let table = self;
        [
            table.transform_aes128_cbc,
            table.transform_aes192_cbc,
            table.transform_aes192_cbc,
            table.transform_aes256_cbc,
            table.transform_aes128_gcm,
            table.transform_aes192_gcm,
            table.transform_aes256_gcm,
            table.transform_concat_kdf,
            table.transform_kw_aes128,
            table.transform_kw_aes192,
            table.transform_kw_aes256,
            table.transform_camellia128_cbc,
            table.transform_camellia192_cbc,
            table.transform_camellia256_cbc,
            table.transform_kw_camellia128,
            table.transform_kw_camellia192,
            table.transform_kw_camellia256,
            table.transform_chacha20,
            table.transform_chacha20_poly1305,
            table.transform_des3_cbc,
            table.transform_kw_des3,
            table.transform_gost2001_gost_r3411_94,
            table.transform_gost_r3410_2012_gost_r3411_2012_256,
            table.transform_gost_r3410_2012_gost_r3411_2012_512,
            table.transform_gost_r3411_94,
            table.transform_gost_r3411_2012_256,
            table.transform_gost_r3411_2012_512,
            table.transform_dh_es,
            table.transform_dsa_sha1,
            table.transform_dsa_sha256,
            table.transform_ecdh,
            table.transform_x25519,
            table.transform_x448,
            table.transform_ecdsa_ripemd160,
            table.transform_ecdsa_sha1,
            table.transform_ecdsa_sha224,
            table.transform_ecdsa_sha256,
            table.transform_ecdsa_sha384,
            table.transform_ecdsa_sha512,
            table.transform_ecdsa_sha3_224,
            table.transform_ecdsa_sha3_256,
            table.transform_ecdsa_sha3_384,
            table.transform_ecdsa_sha3_512,
            table.transform_hmac_md5,
            table.transform_hmac_ripemd160,
            table.transform_hmac_sha1,
            table.transform_hmac_sha224,
            table.transform_hmac_sha256,
            table.transform_hmac_sha384,
            table.transform_hmac_sha512,
        ]
    }

    /// The transform getters libxmlsec1 registers after
    /// [`Self::transforms_in_registration_order`]'s, in its order.
    fn later_transforms_in_registration_order(&self) -> [TransformGetter; 49] {
        let table = self;
        [
            table.transform_md5,
            table.transform_mldsa44,
            table.transform_mldsa65,
            table.transform_mldsa87,
            table.transform_mlkem512,
            table.transform_mlkem768,
            table.transform_mlkem1024,
            table.transform_hkdf,
            table.transform_pbkdf2,
            table.transform_ripemd160,
            table.transform_rsa_md5,
            table.transform_rsa_ripemd160,
            table.transform_rsa_sha1,
            table.transform_rsa_sha224,
            table.transform_rsa_sha256,
            table.transform_rsa_sha384,
            table.transform_rsa_sha512,
            table.transform_rsa_pss_sha1,
            table.transform_rsa_pss_sha224,
            table.transform_rsa_pss_sha256,
            table.transform_rsa_pss_sha384,
            table.transform_rsa_pss_sha512,
            table.transform_rsa_pss_sha3_224,
            table.transform_rsa_pss_sha3_256,
            table.transform_rsa_pss_sha3_384,
            table.transform_rsa_pss_sha3_512,
            table.transform_rsa_pkcs1,
            table.transform_rsa_oaep,
            table.transform_rsa_oaep_enc11,
            table.transform_slhdsa_sha2_128f,
            table.transform_slhdsa_sha2_128s,
            table.transform_slhdsa_sha2_192f,
            table.transform_slhdsa_sha2_192s,
            table.transform_slhdsa_sha2_256f,
            table.transform_slhdsa_sha2_256s,
            table.transform_eddsa_ed25519,
            table.transform_eddsa_ed25519ctx,
            table.transform_eddsa_ed25519ph,
            table.transform_eddsa_ed448,
            table.transform_eddsa_ed448ph,
            table.transform_sha1,
            table.transform_sha224,
            table.transform_sha256,
            table.transform_sha384,
            table.transform_sha512,
            table.transform_sha3_224,
            table.transform_sha3_256,
            table.transform_sha3_384,
            table.transform_sha3_512,
        ]
    }
}

// ----------------------------------------------------------------------------
// Dispatch

/// The current table's entry `$field`, or libxmlsec1's "method is missing"
/// report named `$name` from the entry point `$export` and `$ret`.
macro_rules! method_or {
    ($field:ident, $export:ident, $name:literal, $ret:expr) => {{
        // SAFETY: the current table is null or a table that outlives its use.
        let table = unsafe { CURRENT.load(Ordering::Acquire).as_ref() };
        let Some(method) = table.and_then(|table| table.$field) else {
            let here = errors::Here {
                file: concat!(file!(), "\0").as_ptr().cast(),
                line: line!(),
                func: concat!(stringify!($export), "\0").as_ptr().cast(),
            };
            missing_method(here, $name);
            return $ret;
        };
        method
    }};
}

/// libxmlsec1's report for a table entry that is missing.
fn missing_method(here: errors::Here, name: &str) {
    errors::report(
        here,
        std::ptr::null(),
        std::ptr::null(),
        errors::R_NOT_IMPLEMENTED,
        &format!("Method is missing in the dynamically loaded library: {name}"),
    );
}

/// Declares klass getters that return the current table's klass, or null
/// with libxmlsec1's report when the table has none.
macro_rules! klass_getters {
    ($klass:ty => $($export:ident = $field:ident, $name:literal;)*) => {
        $(
            #[doc = concat!("`", stringify!($export), "`: the current crypto table's klass.")]
            ///
            /// # Safety
            /// Callable at any time; the current table outlives its use.
            #[unsafe(no_mangle)]
            pub(crate) unsafe extern "C" fn $export() -> *const $klass {
                contain(std::ptr::null(), || {
                    let getter = method_or!($field, $export, $name, std::ptr::null());
                    // SAFETY: a getter of the current table.
                    unsafe { getter() }
                })
            }
        )*
    };
}

klass_getters! { XmlSecKeyDataKlass =>
    xmlSecKeyDataAesGetKlass = key_data_aes, "keyDataAesGetKlass";
    xmlSecKeyDataConcatKdfGetKlass = key_data_concat_kdf, "keyDataConcatKdfGetKlass";
    xmlSecKeyDataDesGetKlass = key_data_des, "keyDataDesGetKlass";
    xmlSecKeyDataDhGetKlass = key_data_dh, "keyDataDhGetKlass";
    xmlSecKeyDataDsaGetKlass = key_data_dsa, "keyDataDsaGetKlass";
    xmlSecKeyDataEcGetKlass = key_data_ec, "keyDataEcGetKlass";
    xmlSecKeyDataGost2001GetKlass = key_data_gost2001, "keyDataGost2001GetKlass";
    xmlSecKeyDataGostR3410_2012_256GetKlass = key_data_gost_r3410_2012_256, "keyDataGostR3410_2012_256GetKlass";
    xmlSecKeyDataGostR3410_2012_512GetKlass = key_data_gost_r3410_2012_512, "keyDataGostR3410_2012_512GetKlass";
    xmlSecKeyDataHmacGetKlass = key_data_hmac, "keyDataHmacGetKlass";
    xmlSecKeyDataHkdfGetKlass = key_data_hkdf, "keyDataHkdfGetKlass";
    xmlSecKeyDataPbkdf2GetKlass = key_data_pbkdf2, "keyDataPbkdf2GetKlass";
    xmlSecKeyDataRsaGetKlass = key_data_rsa, "keyDataRsaGetKlass";
    xmlSecKeyDataMLDSAGetKlass = key_data_mldsa, "keyDataMLDSAGetKlass";
    xmlSecKeyDataMLKEMGetKlass = key_data_mlkem, "keyDataMLKEMGetKlass";
    xmlSecKeyDataSLHDSAGetKlass = key_data_slhdsa, "keyDataSLHDSAGetKlass";
    xmlSecKeyDataEdDSAGetKlass = key_data_eddsa, "keyDataEdDSAGetKlass";
    xmlSecKeyDataXdhGetKlass = key_data_xdh, "keyDataXdhGetKlass";
    xmlSecKeyDataX509GetKlass = key_data_x509, "keyDataX509GetKlass";
    xmlSecKeyDataRawX509CertGetKlass = key_data_raw_x509_cert, "keyDataRawX509CertGetKlass";
    xmlSecKeyDataDEREncodedKeyValueGetKlass = key_data_der_encoded_key_value, "keyDataDEREncodedKeyValueGetKlass";
}

klass_getters! { XmlSecKeyDataStoreKlass =>
    xmlSecX509StoreGetKlass = x509_store, "x509StoreGetKlass";
}

klass_getters! { XmlSecTransformKlass =>
    xmlSecTransformAes128CbcGetKlass = transform_aes128_cbc, "transformAes128CbcGetKlass";
    xmlSecTransformAes192CbcGetKlass = transform_aes192_cbc, "transformAes192CbcGetKlass";
    xmlSecTransformAes256CbcGetKlass = transform_aes256_cbc, "transformAes256CbcGetKlass";
    xmlSecTransformAes128GcmGetKlass = transform_aes128_gcm, "transformAes128GcmGetKlass";
    xmlSecTransformAes192GcmGetKlass = transform_aes192_gcm, "transformAes192GcmGetKlass";
    xmlSecTransformAes256GcmGetKlass = transform_aes256_gcm, "transformAes256GcmGetKlass";
    xmlSecTransformConcatKdfGetKlass = transform_concat_kdf, "transformConcatKdfGetKlass";
    xmlSecTransformKWAes128GetKlass = transform_kw_aes128, "transformKWAes128GetKlass";
    xmlSecTransformKWAes192GetKlass = transform_kw_aes192, "transformKWAes192GetKlass";
    xmlSecTransformKWAes256GetKlass = transform_kw_aes256, "transformKWAes256GetKlass";
    xmlSecTransformDes3CbcGetKlass = transform_des3_cbc, "transformDes3CbcGetKlass";
    xmlSecTransformKWDes3GetKlass = transform_kw_des3, "transformKWDes3GetKlass";
    xmlSecTransformDhEsGetKlass = transform_dh_es, "transformDhEsGetKlass";
    xmlSecTransformDsaSha1GetKlass = transform_dsa_sha1, "transformDsaSha1GetKlass";
    xmlSecTransformHkdfGetKlass = transform_hkdf, "transformHkdfGetKlass";
    xmlSecTransformDsaSha256GetKlass = transform_dsa_sha256, "transformDsaSha256GetKlass";
    xmlSecTransformEcdhGetKlass = transform_ecdh, "transformEcdhGetKlass";
    xmlSecTransformX25519GetKlass = transform_x25519, "transformX25519GetKlass";
    xmlSecTransformX448GetKlass = transform_x448, "transformX448GetKlass";
    xmlSecTransformEcdsaRipemd160GetKlass = transform_ecdsa_ripemd160, "transformEcdsaRipemd160GetKlass";
    xmlSecTransformEcdsaSha1GetKlass = transform_ecdsa_sha1, "transformEcdsaSha1GetKlass";
    xmlSecTransformEcdsaSha224GetKlass = transform_ecdsa_sha224, "transformEcdsaSha224GetKlass";
    xmlSecTransformEcdsaSha256GetKlass = transform_ecdsa_sha256, "transformEcdsaSha256GetKlass";
    xmlSecTransformEcdsaSha384GetKlass = transform_ecdsa_sha384, "transformEcdsaSha384GetKlass";
    xmlSecTransformEcdsaSha512GetKlass = transform_ecdsa_sha512, "transformEcdsaSha512GetKlass";
    xmlSecTransformEcdsaSha3_224GetKlass = transform_ecdsa_sha3_224, "transformEcdsaSha3_224GetKlass";
    xmlSecTransformEcdsaSha3_256GetKlass = transform_ecdsa_sha3_256, "transformEcdsaSha3_256GetKlass";
    xmlSecTransformEcdsaSha3_384GetKlass = transform_ecdsa_sha3_384, "transformEcdsaSha3_384GetKlass";
    xmlSecTransformEcdsaSha3_512GetKlass = transform_ecdsa_sha3_512, "transformEcdsaSha3_512GetKlass";
    xmlSecTransformGost2001GostR3411_94GetKlass = transform_gost2001_gost_r3411_94, "transformGost2001GostR3411_94GetKlass";
    xmlSecTransformGostR3410_2012GostR3411_2012_256GetKlass = transform_gost_r3410_2012_gost_r3411_2012_256, "transformGostR3410_2012GostR3411_2012_256GetKlass";
    xmlSecTransformGostR3410_2012GostR3411_2012_512GetKlass = transform_gost_r3410_2012_gost_r3411_2012_512, "transformGostR3410_2012GostR3411_2012_512GetKlass";
    xmlSecTransformRsaOaepEnc11GetKlass = transform_rsa_oaep_enc11, "transformRsaOaepEnc11GetKlass";
    xmlSecTransformGostR3411_94GetKlass = transform_gost_r3411_94, "transformGostR3411_94GetKlass";
    xmlSecTransformGostR3411_2012_256GetKlass = transform_gost_r3411_2012_256, "transformGostR3411_2012_256GetKlass";
    xmlSecTransformHmacMd5GetKlass = transform_hmac_md5, "transformHmacMd5GetKlass";
    xmlSecTransformHmacRipemd160GetKlass = transform_hmac_ripemd160, "transformHmacRipemd160GetKlass";
    xmlSecTransformHmacSha1GetKlass = transform_hmac_sha1, "transformHmacSha1GetKlass";
    xmlSecTransformHmacSha224GetKlass = transform_hmac_sha224, "transformHmacSha224GetKlass";
    xmlSecTransformHmacSha256GetKlass = transform_hmac_sha256, "transformHmacSha256GetKlass";
    xmlSecTransformHmacSha384GetKlass = transform_hmac_sha384, "transformHmacSha384GetKlass";
    xmlSecTransformHmacSha512GetKlass = transform_hmac_sha512, "transformHmacSha512GetKlass";
    xmlSecTransformMd5GetKlass = transform_md5, "transformMd5GetKlass";
    xmlSecTransformMLDSA44GetKlass = transform_mldsa44, "transformMLDSA44GetKlass";
    xmlSecTransformMLDSA65GetKlass = transform_mldsa65, "transformMLDSA65GetKlass";
    xmlSecTransformMLDSA87GetKlass = transform_mldsa87, "transformMLDSA87GetKlass";
    xmlSecTransformMLKEM512GetKlass = transform_mlkem512, "transformMLKEM512GetKlass";
    xmlSecTransformMLKEM768GetKlass = transform_mlkem768, "transformMLKEM768GetKlass";
    xmlSecTransformMLKEM1024GetKlass = transform_mlkem1024, "transformMLKEM1024GetKlass";
    xmlSecTransformPbkdf2GetKlass = transform_pbkdf2, "transformPbkdf2GetKlass";
    xmlSecTransformRipemd160GetKlass = transform_ripemd160, "transformRipemd160GetKlass";
    xmlSecTransformRsaMd5GetKlass = transform_rsa_md5, "transformRsaMd5GetKlass";
    xmlSecTransformRsaRipemd160GetKlass = transform_rsa_ripemd160, "transformRsaRipemd160GetKlass";
    xmlSecTransformRsaSha1GetKlass = transform_rsa_sha1, "transformRsaSha1GetKlass";
    xmlSecTransformRsaSha224GetKlass = transform_rsa_sha224, "transformRsaSha224GetKlass";
    xmlSecTransformRsaSha256GetKlass = transform_rsa_sha256, "transformRsaSha256GetKlass";
    xmlSecTransformRsaSha384GetKlass = transform_rsa_sha384, "transformRsaSha384GetKlass";
    xmlSecTransformRsaSha512GetKlass = transform_rsa_sha512, "transformRsaSha512GetKlass";
    xmlSecTransformRsaPssSha1GetKlass = transform_rsa_pss_sha1, "transformRsaPssSha1GetKlass";
    xmlSecTransformRsaPssSha224GetKlass = transform_rsa_pss_sha224, "transformRsaPssSha224GetKlass";
    xmlSecTransformRsaPssSha256GetKlass = transform_rsa_pss_sha256, "transformRsaPssSha256GetKlass";
    xmlSecTransformRsaPssSha384GetKlass = transform_rsa_pss_sha384, "transformRsaPssSha384GetKlass";
    xmlSecTransformRsaPssSha512GetKlass = transform_rsa_pss_sha512, "transformRsaPssSha512GetKlass";
    xmlSecTransformRsaPssSha3_224GetKlass = transform_rsa_pss_sha3_224, "transformRsaPssSha3_224GetKlass";
    xmlSecTransformRsaPssSha3_256GetKlass = transform_rsa_pss_sha3_256, "transformRsaPssSha3_256GetKlass";
    xmlSecTransformRsaPssSha3_384GetKlass = transform_rsa_pss_sha3_384, "transformRsaPssSha3_384GetKlass";
    xmlSecTransformRsaPssSha3_512GetKlass = transform_rsa_pss_sha3_512, "transformRsaPssSha3_512GetKlass";
    xmlSecTransformRsaPkcs1GetKlass = transform_rsa_pkcs1, "transformRsaPkcs1GetKlass";
    xmlSecTransformRsaOaepGetKlass = transform_rsa_oaep, "transformRsaOaepGetKlass";
    xmlSecTransformSLHDSA_SHA2_128fGetKlass = transform_slhdsa_sha2_128f, "transformSLHDSA_SHA2_128fGetKlass";
    xmlSecTransformSLHDSA_SHA2_128sGetKlass = transform_slhdsa_sha2_128s, "transformSLHDSA_SHA2_128sGetKlass";
    xmlSecTransformSLHDSA_SHA2_192fGetKlass = transform_slhdsa_sha2_192f, "transformSLHDSA_SHA2_192fGetKlass";
    xmlSecTransformSLHDSA_SHA2_192sGetKlass = transform_slhdsa_sha2_192s, "transformSLHDSA_SHA2_192sGetKlass";
    xmlSecTransformSLHDSA_SHA2_256fGetKlass = transform_slhdsa_sha2_256f, "transformSLHDSA_SHA2_256fGetKlass";
    xmlSecTransformSLHDSA_SHA2_256sGetKlass = transform_slhdsa_sha2_256s, "transformSLHDSA_SHA2_256sGetKlass";
    xmlSecTransformEdDSAEd25519GetKlass = transform_eddsa_ed25519, "transformEdDSAEd25519GetKlass";
    xmlSecTransformEdDSAEd25519ctxGetKlass = transform_eddsa_ed25519ctx, "transformEdDSAEd25519ctxGetKlass";
    xmlSecTransformEdDSAEd25519phGetKlass = transform_eddsa_ed25519ph, "transformEdDSAEd25519phGetKlass";
    xmlSecTransformEdDSAEd448GetKlass = transform_eddsa_ed448, "transformEdDSAEd448GetKlass";
    xmlSecTransformEdDSAEd448phGetKlass = transform_eddsa_ed448ph, "transformEdDSAEd448phGetKlass";
    xmlSecTransformGostR3411_2012_512GetKlass = transform_gost_r3411_2012_512, "transformGostR3411_2012_512GetKlass";
    xmlSecTransformSha1GetKlass = transform_sha1, "transformSha1GetKlass";
    xmlSecTransformSha224GetKlass = transform_sha224, "transformSha224GetKlass";
    xmlSecTransformSha256GetKlass = transform_sha256, "transformSha256GetKlass";
    xmlSecTransformSha384GetKlass = transform_sha384, "transformSha384GetKlass";
    xmlSecTransformSha512GetKlass = transform_sha512, "transformSha512GetKlass";
    xmlSecTransformSha3_224GetKlass = transform_sha3_224, "transformSha3_224GetKlass";
    xmlSecTransformSha3_256GetKlass = transform_sha3_256, "transformSha3_256GetKlass";
    xmlSecTransformSha3_384GetKlass = transform_sha3_384, "transformSha3_384GetKlass";
    xmlSecTransformSha3_512GetKlass = transform_sha3_512, "transformSha3_512GetKlass";
}

/// Declares entry points that call the current table's method with their
/// arguments, or fail with libxmlsec1's report when the table has none.
macro_rules! method_dispatch {
    ($($export:ident = $field:ident, $name:literal, ($($arg:ident: $ty:ty),*) -> $ret:ty, $fail:expr;)*) => {
        $(
            #[doc = concat!("`", stringify!($export), "`: the current crypto table's method.")]
            ///
            /// # Safety
            /// The arguments are what the current table's method expects; the
            /// table outlives its use.
            #[unsafe(no_mangle)]
            pub(crate) unsafe extern "C" fn $export($($arg: $ty),*) -> $ret {
                contain($fail, || {
                    let method = method_or!($field, $export, $name, $fail);
                    // SAFETY: a method of the current table, with the
                    // caller's arguments.
                    unsafe { method($($arg),*) }
                })
            }
        )*
    };
}

method_dispatch! {
    xmlSecCryptoInit = crypto_init, "cryptoInit", () -> c_int, -1;
    xmlSecCryptoShutdown = crypto_shutdown, "cryptoShutdown", () -> c_int, -1;
    xmlSecCryptoKeysMngrInit = crypto_keys_mngr_init, "cryptoKeysMngrInit", (mngr: Opaque) -> c_int, -1;
    xmlSecCryptoAppInit = crypto_app_init, "cryptoAppInit", (config: *const c_char) -> c_int, -1;
    xmlSecCryptoAppShutdown = crypto_app_shutdown, "cryptoAppShutdown", () -> c_int, -1;
    xmlSecCryptoAppDefaultKeysMngrInit = crypto_app_default_keys_mngr_init,
        "cryptoAppDefaultKeysMngrInit", (mngr: Opaque) -> c_int, -1;
    xmlSecCryptoAppDefaultKeysMngrAdoptKey = crypto_app_default_keys_mngr_adopt_key,
        "cryptoAppDefaultKeysMngrAdoptKey", (mngr: Opaque, key: Opaque) -> c_int, -1;
    xmlSecCryptoAppDefaultKeysMngrVerifyKey = crypto_app_default_keys_mngr_verify_key,
        "cryptoAppDefaultKeysMngrVerifyKey", (mngr: Opaque, key: Opaque, key_info_ctx: Opaque) -> c_int, -1;
    xmlSecCryptoAppDefaultKeysMngrLoad = crypto_app_default_keys_mngr_load,
        "cryptoAppDefaultKeysMngrLoad", (mngr: Opaque, uri: *const c_char) -> c_int, -1;
    xmlSecCryptoAppDefaultKeysMngrSave = crypto_app_default_keys_mngr_save,
        "cryptoAppDefaultKeysMngrSave", (mngr: Opaque, filename: *const c_char, kind: c_uint) -> c_int, -1;
    xmlSecCryptoAppKeysMngrCertLoad = crypto_app_keys_mngr_cert_load,
        "cryptoAppKeysMngrCertLoad",
        (mngr: Opaque, filename: *const c_char, format: c_int, kind: c_uint) -> c_int, -1;
    xmlSecCryptoAppKeysMngrCertLoadMemory = crypto_app_keys_mngr_cert_load_memory,
        "cryptoAppKeysMngrCertLoadMemory",
        (mngr: Opaque, data: *const u8, size: usize, format: c_int, kind: c_uint) -> c_int, -1;
    xmlSecCryptoAppKeysMngrCrlLoad = crypto_app_keys_mngr_crl_load,
        "cryptoAppKeysMngrCrlLoad", (mngr: Opaque, filename: *const c_char, format: c_int) -> c_int, -1;
    xmlSecCryptoAppKeysMngrCrlLoadAndVerify = crypto_app_keys_mngr_crl_load_and_verify,
        "cryptoAppKeysMngrCrlLoadAndVerify",
        (mngr: Opaque, filename: *const c_char, format: c_int, key_info_ctx: Opaque) -> c_int, -1;
    xmlSecCryptoAppKeysMngrCrlLoadMemory = crypto_app_keys_mngr_crl_load_memory,
        "cryptoAppKeysMngrCrlLoadMemory",
        (mngr: Opaque, data: *const u8, size: usize, format: c_int) -> c_int, -1;
    xmlSecCryptoAppKeyLoadEx = crypto_app_key_load_ex, "cryptoAppKeyLoadEx",
        (
            filename: *const c_char,
            kind: c_uint,
            format: c_int,
            pwd: *const c_char,
            pwd_callback: *mut c_void,
            pwd_callback_ctx: *mut c_void
        ) -> Opaque, std::ptr::null_mut();
    xmlSecCryptoAppKeyLoadMemory = crypto_app_key_load_memory, "cryptoAppKeyLoadMemory",
        (
            data: *const u8,
            size: usize,
            format: c_int,
            pwd: *const c_char,
            pwd_callback: *mut c_void,
            pwd_callback_ctx: *mut c_void
        ) -> Opaque, std::ptr::null_mut();
    xmlSecCryptoAppPkcs12Load = crypto_app_pkcs12_load, "cryptoAppPkcs12Load",
        (
            filename: *const c_char,
            pwd: *const c_char,
            pwd_callback: *mut c_void,
            pwd_callback_ctx: *mut c_void
        ) -> Opaque, std::ptr::null_mut();
    xmlSecCryptoAppPkcs12LoadMemory = crypto_app_pkcs12_load_memory, "cryptoAppPkcs12LoadMemory",
        (
            data: *const u8,
            size: usize,
            pwd: *const c_char,
            pwd_callback: *mut c_void,
            pwd_callback_ctx: *mut c_void
        ) -> Opaque, std::ptr::null_mut();
    xmlSecCryptoAppKeyCertLoad = crypto_app_key_cert_load, "cryptoAppKeyCertLoad",
        (key: Opaque, filename: *const c_char, format: c_int) -> c_int, -1;
    xmlSecCryptoAppKeyCertLoadMemory = crypto_app_key_cert_load_memory, "cryptoAppKeyCertLoadMemory",
        (key: Opaque, data: *const u8, size: usize, format: c_int) -> c_int, -1;
}

/// `xmlSecCryptoAppGetDefaultPwdCallback`: the current table's default
/// password callback.
///
/// # Safety
/// Callable at any time; the current table outlives its use.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCryptoAppGetDefaultPwdCallback() -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the current table is null or a table that outlives its use.
        let Some(table) = (unsafe { CURRENT.load(Ordering::Acquire).as_ref() }) else {
            missing_method(
                here!("xmlSecCryptoAppGetDefaultPwdCallback"),
                "cryptoAppDefaultPwdCallback",
            );
            return std::ptr::null_mut();
        };
        table.crypto_app_default_pwd_callback
    })
}
