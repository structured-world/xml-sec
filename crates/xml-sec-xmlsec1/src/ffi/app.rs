//! The built-in crypto table's application key loading (`xmlsec/app.h`):
//! keys from PEM, DER and PKCS#8 in memory.
//!
//! The core's key importers read the material: a private key, in any
//! container OpenSSL reads, becomes provider-neutral PKCS#8 with the public
//! key derived from it, a public key its key value, both checked against the
//! library policy's resource limits. A password is the caller's explicit one
//! or, only for a protected container, the one its OpenSSL-style password
//! callback returns. The table loads no file: the caller reads it and passes
//! the bytes to `xmlSecCryptoAppKeyLoadMemory`.

use std::ffi::{CStr, c_char, c_int, c_void};

use xml_sec::key_manager::{KeyInventory, KeyStoreError, KeyUsages, PrivateKeyContainer};
use xml_sec::policy::ResourcePolicy;
use xml_sec::xmldsig::{KeyInfoSource, KeyValueInfo};
use zeroize::Zeroizing;

use super::asymkeys::{self, Material};
use super::errors::{self, Here, here};
use super::keys::{XmlSecKey, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeySetValue};
use super::{contain, policy};

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;
/// `xmlSecKeyDataFormatDer`.
const FORMAT_DER: c_int = 3;
/// `xmlSecKeyDataFormatPkcs8Pem`.
const FORMAT_PKCS8_PEM: c_int = 4;
/// `xmlSecKeyDataFormatPkcs8Der`.
const FORMAT_PKCS8_DER: c_int = 5;
/// The largest password a callback may return, as OpenSSL's `PEM_BUFSIZE`
/// buffer (1024 bytes).
const PASSWORD_CAPACITY: c_int = 1024;

/// OpenSSL's `pem_password_cb`: writes the password to the buffer of the
/// given size and returns its length, or a negative value.
type PasswordCallback = unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int;

/// Where the password of a protected key comes from.
struct Password {
    explicit: *const c_char,
    callback: *mut c_void,
    context: *mut c_void,
}

/// A password as the key importer reads it: the caller's explicit string in
/// place, or the bytes a callback wrote into our buffer.
enum Secret<'a> {
    Explicit(&'a [u8]),
    Returned(Zeroizing<Vec<u8>>),
}

impl Secret<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Explicit(bytes) => bytes,
            Self::Returned(buffer) => buffer,
        }
    }
}

impl Password {
    /// The caller's password, from the explicit string or the callback;
    /// `None` when there is neither or the callback declines. The explicit
    /// string is read in place, not copied, so the importer's resource
    /// check meets it before any allocation.
    ///
    /// # Safety
    /// `explicit` is null or NUL-terminated and outlives the result;
    /// `callback` is null or a `pem_password_cb` taking `context`.
    unsafe fn get(&self) -> Option<Secret<'_>> {
        if !self.explicit.is_null() {
            // SAFETY: by the caller's contract.
            let text = unsafe { CStr::from_ptr(self.explicit) };
            return Some(Secret::Explicit(text.to_bytes()));
        }
        if self.callback.is_null() {
            return None;
        }
        // SAFETY: a non-null callback is a `pem_password_cb`.
        let callback: PasswordCallback = unsafe { std::mem::transmute(self.callback) };
        let capacity = usize::try_from(PASSWORD_CAPACITY).ok()?;
        let mut buffer = Zeroizing::new(vec![0_u8; capacity]);
        // SAFETY: the buffer holds `PASSWORD_CAPACITY` bytes; rwflag 0 asks
        // for a password to decrypt.
        let length = unsafe {
            callback(
                buffer.as_mut_ptr().cast(),
                PASSWORD_CAPACITY,
                0,
                self.context,
            )
        };
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length <= capacity)?;
        buffer.truncate(length);
        Some(Secret::Returned(buffer))
    }
}

/// The material of the private key `bytes` hold in `container`, asking
/// `password` only when the container is protected.
fn private_key(
    bytes: &[u8],
    container: PrivateKeyContainer,
    password: &Password,
    resources: &ResourcePolicy,
) -> Result<Material, KeyStoreError> {
    let import = |secret: Option<&[u8]>| {
        let mut inventory = KeyInventory::default();
        inventory.add_openssl_private_key(
            "key".to_owned(),
            bytes,
            container,
            secret,
            KeyUsages::SIGN,
            resources,
        )?;
        Ok::<_, KeyStoreError>(inventory)
    };
    let inventory = match import(None) {
        Err(KeyStoreError::ProtectedContainer) => {
            // SAFETY: the password sources are the caller's arguments.
            let secret = unsafe { password.get() }.ok_or(KeyStoreError::ProtectedContainer)?;
            import(Some(secret.bytes()))?
        }
        other => other?,
    };
    let key = inventory
        .private_keys()
        .first()
        .ok_or(KeyStoreError::Selection("no private key imported"))?;
    let spki = key.public_key_spki_der()?;
    let value = KeyValueInfo::from_spki_der(&spki, resources)
        .map_err(|_| KeyStoreError::Selection("unsupported private key family"))?;
    Ok(Material {
        value,
        private: Some(Zeroizing::new(key.pkcs8_der().to_vec())),
    })
}

/// The material of the public key in PEM (`pem`) or DER `bytes`.
fn public_key(
    bytes: &[u8],
    pem: bool,
    resources: &ResourcePolicy,
) -> Result<Material, KeyStoreError> {
    let mut inventory = KeyInventory::default();
    if pem {
        inventory.add_public_pem("key", bytes, resources)?;
    } else {
        inventory.add_public_der("key".to_owned(), bytes.to_vec(), resources)?;
    }
    let key = inventory
        .public_keys()
        .first()
        .ok_or(KeyStoreError::Selection("no public key imported"))?;
    let value = key
        .key_info
        .sources
        .iter()
        .find_map(|source| match source {
            KeyInfoSource::KeyValue(value) => Some(Ok(value.clone())),
            KeyInfoSource::DerEncodedKeyValue(spki) => Some(
                KeyValueInfo::from_spki_der(spki, resources)
                    .map_err(|_| KeyStoreError::Selection("unsupported public key family")),
            ),
            _ => None,
        })
        .ok_or(KeyStoreError::Selection("no public key imported"))??;
    Ok(Material {
        value,
        private: None,
    })
}

/// The key material `bytes` of `format` hold: for PEM and DER a private
/// key, or else a public key, as libxmlsec1's OpenSSL library tries them.
fn material(
    bytes: &[u8],
    format: c_int,
    password: &Password,
    resources: &ResourcePolicy,
) -> Result<Option<Material>, KeyStoreError> {
    // A protected container or a policy refusal is the private key's own
    // failure: only bytes that hold no private key are read as a public one.
    let or_public = |private: Result<Material, KeyStoreError>, pem: bool| match private {
        Err(error @ (KeyStoreError::ProtectedContainer | KeyStoreError::Policy(_))) => Err(error),
        Err(_) => public_key(bytes, pem, resources),
        found => found,
    };
    Ok(Some(match format {
        FORMAT_PEM => or_public(
            private_key(bytes, PrivateKeyContainer::Pem, password, resources),
            true,
        )?,
        FORMAT_DER => or_public(
            private_key(bytes, PrivateKeyContainer::Der, password, resources),
            false,
        )?,
        FORMAT_PKCS8_PEM => private_key(bytes, PrivateKeyContainer::Pkcs8Pem, password, resources)?,
        FORMAT_PKCS8_DER => private_key(bytes, PrivateKeyContainer::Pkcs8Der, password, resources)?,
        _ => return Ok(None),
    }))
}

/// A new key holding the key `bytes` of `format` hold, read under
/// `resources`; null after a report at `here`.
///
/// # Safety
/// The password sources are null or valid as [`Password::get`] requires.
unsafe fn load(
    here: Here,
    bytes: &[u8],
    format: c_int,
    password: &Password,
    resources: &ResourcePolicy,
) -> *mut c_void {
    let null = std::ptr::null_mut();
    let material = match material(bytes, format, password, resources) {
        Ok(Some(material)) => material,
        Ok(None) => {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_FORMAT,
                &format!("format={format}"),
            );
            return null;
        }
        Err(error) => {
            errors::internal_with(here, std::ptr::null(), c"KeyInventory", &error.to_string());
            return null;
        }
    };
    key_with(here, material, None)
}

/// A new key whose value holds `material`, with `x509` as its X.509 data
/// when given; null after a report at `here`.
pub(crate) fn key_with(
    here: Here,
    material: Material,
    x509: Option<super::x509::data::X509State>,
) -> *mut c_void {
    let null = std::ptr::null_mut();
    let data = asymkeys::adopt(material);
    if data.is_null() {
        errors::internal(here, std::ptr::null(), c"xmlSecKeyDataCreate");
        return null;
    }
    // SAFETY: a new key adopts the new key data.
    unsafe {
        let key: *mut XmlSecKey = xmlSecKeyCreate();
        if key.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyCreate");
            super::keysdata::xmlSecKeyDataDestroy(data);
            return null;
        }
        if xmlSecKeySetValue(key, data) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecKeySetValue");
            xmlSecKeyDestroy(key);
            super::keysdata::xmlSecKeyDataDestroy(data);
            return null;
        }
        if let Some(state) = x509 {
            let certificates = super::x509::data::create(here, state);
            if certificates.is_null() || super::keys::xmlSecKeyAdoptData(key, certificates) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyAdoptData");
                if !certificates.is_null() {
                    super::keysdata::xmlSecKeyDataDestroy(certificates);
                }
                xmlSecKeyDestroy(key);
                return null;
            }
        }
        key.cast()
    }
}

/// `cryptoAppKeyLoadMemory` of the built-in table.
pub(crate) unsafe extern "C" fn key_load_memory(
    data: *const u8,
    size: usize,
    format: c_int,
    pwd: *const c_char,
    callback: *mut c_void,
    context: *mut c_void,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecCryptoAppKeyLoadMemory");
        if data.is_null() {
            errors::assertion(here, c"data != NULL");
            return std::ptr::null_mut();
        }
        if format == 0 {
            errors::assertion(here, c"format != xmlSecKeyDataFormatUnknown");
            return std::ptr::null_mut();
        }
        let Some(policy) = policy::verification_at(here) else {
            return std::ptr::null_mut();
        };
        // SAFETY: the caller's `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, size) };
        if matches!(
            format,
            super::x509::FORMAT_CERT_PEM | super::x509::FORMAT_CERT_DER
        ) {
            return super::x509::load::key_from_certificate(here, bytes, format);
        }
        let password = Password {
            explicit: pwd,
            callback,
            context,
        };
        // SAFETY: the caller's password sources.
        unsafe { load(here, bytes, format, &password, &policy.resources) }
    })
}

/// `cryptoAppPkcs12LoadMemory` of the built-in table: the private key of the
/// PKCS#12 bundle, with the certificate of its key and the bundle's other
/// certificates as its X.509 data.
pub(crate) unsafe extern "C" fn pkcs12_load_memory(
    data: *const u8,
    size: usize,
    pwd: *const c_char,
    callback: *mut c_void,
    context: *mut c_void,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecOpenSSLAppPkcs12LoadMemory");
        if data.is_null() {
            errors::assertion(here, c"data != NULL");
            return std::ptr::null_mut();
        }
        let Some(policy) = policy::verification_at(here) else {
            return std::ptr::null_mut();
        };
        let password = Password {
            explicit: pwd,
            callback,
            context,
        };
        // SAFETY: the caller's `size` bytes and password sources.
        let (bytes, secret) = unsafe {
            (
                std::slice::from_raw_parts(data, size),
                password
                    .get()
                    .map(|secret| Zeroizing::new(secret.bytes().to_vec())),
            )
        };
        let mut inventory = KeyInventory::default();
        let imported = inventory.add_pkcs12_with_password_callback(
            "key".to_owned(),
            bytes,
            || {
                secret
                    .as_deref()
                    .and_then(|secret| std::str::from_utf8(secret).ok())
                    .map(|secret| Zeroizing::new(secret.to_owned()))
            },
            KeyUsages::SIGN,
            &policy.resources,
        );
        if let Err(error) = imported {
            errors::internal_with(here, std::ptr::null(), c"PKCS12_parse", &error.to_string());
            return std::ptr::null_mut();
        }
        let Some(key) = inventory.private_keys().first() else {
            errors::internal(here, std::ptr::null(), c"PKCS12_parse");
            return std::ptr::null_mut();
        };
        let value = key.public_key_spki_der().and_then(|spki| {
            KeyValueInfo::from_spki_der(&spki, &policy.resources)
                .map_err(|_| KeyStoreError::Selection("unsupported private key family"))
        });
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecOpenSSLCreateKey",
                    &error.to_string(),
                );
                return std::ptr::null_mut();
            }
        };
        // The key's own certificate leads the bundle when it has one; the
        // bundle's other certificates are the key's too, trusted for nothing.
        let has_leaf = key.matching_certificate_chain().is_some();
        let mut x509 = super::x509::data::X509State::default();
        for (position, cert) in key.certificates().iter().enumerate() {
            x509.add_cert(cert.clone(), has_leaf && position == 0);
        }
        key_with(
            here,
            Material {
                value,
                private: Some(Zeroizing::new(key.pkcs8_der().to_vec())),
            },
            Some(x509),
        )
    })
}

#[cfg(test)]
mod tests;
