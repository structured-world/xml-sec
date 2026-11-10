//! `xmlsec/xmlsec.h`: library initialization and shutdown, the version
//! check, the default crypto name and the external entity loader.
//!
//! libxmlsec1 asks its caller to initialize and shut down once per process
//! and not concurrently. This library serializes `xmlSecInit` and
//! `xmlSecShutdown` against each other, so calls that race do not corrupt
//! the registries they set up; operations still run only between them, as
//! libxmlsec1 requires.

use std::ffi::{CString, c_int};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use xml_sec_libxml2::ffi::libxml2::{self, EntityLoader};

use super::contain;
use super::crypto::{xmlSecCryptoDLInit, xmlSecCryptoDLShutdown};
use super::errors::{self, here, xmlSecErrorsInit, xmlSecErrorsShutdown};
use super::keysdata::{xmlSecKeyDataIdsInit, xmlSecKeyDataIdsShutdown};
use super::transforms::io::{xmlSecIOInit, xmlSecIOShutdown};
use super::transforms::{xmlSecTransformIdsInit, xmlSecTransformIdsShutdown};

#[cfg(test)]
mod tests;

/// `xmlSecCheckVersionExactMatch`.
const VERSION_EXACT: c_int = 0;
/// `xmlSecCheckVersionABICompatible`.
const VERSION_ABI_COMPATIBLE: c_int = 1;
/// libxmlsec1's release this library is compatible with (`XMLSEC_VERSION_*`
/// of its headers).
const VERSION: (c_int, c_int, c_int) = (1, 3, 13);

/// Held while `xmlSecInit` or `xmlSecShutdown` runs.
static LIFECYCLE: AtomicBool = AtomicBool::new(false);

/// Runs `body` while no other initialization or shutdown runs.
fn serialized<T>(body: impl FnOnce() -> T) -> T {
    /// Releases the lifecycle on every exit, a panic included.
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            LIFECYCLE.store(false, Ordering::Release);
        }
    }
    while LIFECYCLE
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        std::thread::yield_now();
    }
    let _release = Release;
    body()
}

/// libxml2's external entity loader when the library was first initialized,
/// which `xmlSecSetExternalEntityLoader(NULL)` restores.
static DEFAULT_ENTITY_LOADER: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// `xmlSecInit`: sets up error reporting, the I/O callback list, the crypto
/// library list and the key-data and transform registries, and records
/// libxml2's external entity loader.
///
/// The default parser options keep external entities out on every libxml2
/// release, so no loader of this library's is installed (libxmlsec1 installs
/// one before libxml2 2.13).
///
/// # Safety
/// No operation of the library runs concurrently.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecInit() -> c_int {
    contain(-1, || {
        serialized(|| {
            let here = here!("xmlSecInit");
            // SAFETY: initialization while no operation runs; libxmlsec1
            // ignores the I/O initialization's result.
            unsafe {
                xmlSecErrorsInit();
                xmlSecIOInit();
                if xmlSecCryptoDLInit() < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecCryptoDLInit");
                    return -1;
                }
                if xmlSecKeyDataIdsInit() < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyDataIdsInit");
                    return -1;
                }
                if xmlSecTransformIdsInit() < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecTransformIdsInit");
                    return -1;
                }
            }
            if libxml2::available() && DEFAULT_ENTITY_LOADER.load(Ordering::Acquire).is_null() {
                // SAFETY: libxml2 is available.
                let loader = unsafe { libxml2::xml_get_external_entity_loader() };
                let address = loader.map_or(std::ptr::null_mut(), |loader| loader as *mut ());
                DEFAULT_ENTITY_LOADER.store(address, Ordering::Release);
            }
            0
        })
    })
}

/// `xmlSecShutdown`: releases what `xmlSecInit` set up.
///
/// # Safety
/// No operation of the library runs concurrently, and none runs afterwards
/// until the library is initialized again.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecShutdown() -> c_int {
    contain(-1, || {
        serialized(|| {
            let mut result = 0;
            // SAFETY: shutdown while no operation runs.
            unsafe {
                xmlSecTransformIdsShutdown();
                xmlSecKeyDataIdsShutdown();
                if xmlSecCryptoDLShutdown() < 0 {
                    errors::internal(
                        here!("xmlSecShutdown"),
                        std::ptr::null(),
                        c"xmlSecCryptoDLShutdown",
                    );
                    result = -1;
                }
                xmlSecIOShutdown();
                xmlSecErrorsShutdown();
            }
            result
        })
    })
}

/// `xmlSecSetExternalEntityLoader`: installs `loader` as libxml2's external
/// entity loader, or the loader libxml2 had when the library was first
/// initialized when `loader` is null.
///
/// # Safety
/// `loader` is null or a function of libxml2's loader signature.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecSetExternalEntityLoader(loader: Option<EntityLoader>) {
    contain((), || {
        if !libxml2::available() {
            errors::no_libxml2(here!("xmlSecSetExternalEntityLoader"));
            return;
        }
        let loader = loader.or_else(|| {
            let address = DEFAULT_ENTITY_LOADER.load(Ordering::Acquire);
            // SAFETY: a non-null address is the loader libxml2 returned.
            (!address.is_null())
                .then(|| unsafe { std::mem::transmute::<*mut (), EntityLoader>(address) })
        });
        // SAFETY: libxml2 is available; the loader is null or one.
        unsafe { libxml2::xml_set_external_entity_loader(loader) };
    });
}

/// `xmlSecGetDefaultCrypto`: the name of the built-in crypto provider, the
/// one crypto library `xmlSecCryptoDLLoadLibrary` loads.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecGetDefaultCrypto() -> *const u8 {
    static NAME: OnceLock<CString> = OnceLock::new();
    NAME.get_or_init(|| {
        let name = xml_sec::provider::default_provider().name();
        CString::new(name).expect("a provider name has no NUL")
    })
    .as_ptr()
    .cast()
}

/// `xmlSecStrlen`: the length of `text`, 0 for null.
///
/// # Safety
/// `text` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecStrlen(text: *const u8) -> usize {
    if text.is_null() {
        return 0;
    }
    // SAFETY: by the caller's contract.
    unsafe { std::ffi::CStr::from_ptr(text.cast()) }
        .to_bytes()
        .len()
}

/// `xmlSecCheckVersionExt`: 1 when a caller built against libxmlsec1
/// `major.minor.subminor` can use this library under `mode`, otherwise 0
/// with libxmlsec1's report.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCheckVersionExt(
    major: c_int,
    minor: c_int,
    subminor: c_int,
    mode: c_int,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecCheckVersionExt");
        let (our_major, our_minor, our_subminor) = VERSION;
        let refuse = |message: String| {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_VERSION,
                &message,
            );
            0
        };
        if major != our_major {
            return refuse(format!(
                "expected major version={our_major};real major version={major}"
            ));
        }
        let detail = |name: &str| {
            format!(
                "mode={name};expected minor version={our_minor};real minor version={minor};expected subminor version={our_subminor};real subminor version={subminor}"
            )
        };
        match mode {
            VERSION_EXACT if minor != our_minor || subminor != our_subminor => {
                refuse(detail("exact"))
            }
            VERSION_ABI_COMPATIBLE
                if minor > our_minor || (minor == our_minor && subminor > our_subminor) =>
            {
                refuse(detail("abi compatible"))
            }
            _ => 1,
        }
    })
}
