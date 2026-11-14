//! Private keys in the containers OpenSSL reads, an explicit import boundary
//! for compatibility callers such as the xmlsec1 command and library.
//!
//! Besides PKCS#8, the generic PEM and DER forms accept PKCS#1 RSA, SEC1 EC
//! and DSA keys, PEM ones also in the traditional envelope OpenSSL encrypts
//! with a password (RFC 1421 `Proc-Type`/`DEK-Info` headers). The envelope
//! and the normalization of SEC1 and DSA keys to PKCS#8 are the shared
//! `structured_cms::openssl` primitive's; this adapter selects the container,
//! charges the operation's resource budget and imports into the inventory.
//! The strict PKCS#8 importers never reach this path.

use alloc::{string::String, sync::Arc, vec, vec::Vec};

use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_cms::openssl::{Envelope, Error as OpenSslError, Key, KeyFamily};
use zeroize::Zeroizing;

use super::{
    BorrowedPem, KeyInventory, KeyStoreError, KeyUsages, import_resource_limit,
    validate_private_key_usages,
};
use crate::policy::{ResourcePolicy, resource_name};

/// How the bytes of an OpenSSL-compatible private-key import are framed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateKeyContainer {
    /// PEM holding PKCS#8 (plain or encrypted), or a PKCS#1 RSA, SEC1 EC or
    /// DSA key, plain or in the traditional password envelope.
    Pem,
    /// DER holding PKCS#8 (plain or encrypted), or a PKCS#1 RSA, SEC1 EC or
    /// DSA key.
    Der,
    /// PEM holding PKCS#8 only.
    Pkcs8Pem,
    /// DER holding PKCS#8 only.
    Pkcs8Der,
}

/// The error of bytes that are not a key of the selected container.
const UNSUPPORTED: KeyStoreError = KeyStoreError::Selection("unsupported private key container");

/// A traditional key's DER, whether a password envelope protected it, and
/// the bytes of the password that opened it, live until the import ends.
struct Traditional {
    der: Zeroizing<Vec<u8>>,
    encrypted: bool,
    password_len: usize,
}

/// A traditional key family by its PEM label.
#[derive(Clone, Copy)]
enum Family {
    Rsa,
    Ec,
    Dsa,
}

impl KeyInventory {
    /// Import the private key `bytes` hold in `container` under `name`.
    ///
    /// Passwords are consulted only for a structurally protected container:
    /// encrypted PKCS#8 under the inventory's KDF policy, or the traditional
    /// PEM envelope. Once an envelope is recognized, a key that does not
    /// decode is reported as [`KeyStoreError::ProtectedContainer`] and never
    /// retried as plaintext, since CBC padding does not authenticate it.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::key_manager::{KeyInventory, KeyUsages, PrivateKeyContainer};
    /// use xml_sec::policy::ResourcePolicy;
    ///
    /// let pem = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    /// let mut inventory = KeyInventory::default();
    /// inventory.add_openssl_private_key(
    ///     "signer".to_owned(),
    ///     pem,
    ///     PrivateKeyContainer::Pem,
    ///     None,
    ///     KeyUsages::SIGN,
    ///     &ResourcePolicy::default(),
    /// )?;
    /// assert_eq!(inventory.private_keys().len(), 1);
    /// # Ok::<(), xml_sec::key_manager::KeyStoreError>(())
    /// ```
    ///
    /// # Errors
    /// Returns bytes that are not a key of `container`, a missing or wrong
    /// password, malformed key material, name/usage refusal and resource or
    /// KDF budget exhaustion.
    pub fn add_openssl_private_key(
        &mut self,
        name: String,
        bytes: &[u8],
        container: PrivateKeyContainer,
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        validate_private_key_usages(usages)?;
        match container {
            PrivateKeyContainer::Pkcs8Pem => {
                let block = BorrowedPem::parse(bytes, resources.max_external_resource_bytes)?;
                if !matches!(block.label, "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY") {
                    return Err(UNSUPPORTED);
                }
                self.add_private_pem(name, bytes, password, usages, resources)
            }
            PrivateKeyContainer::Pkcs8Der => {
                if !is_pkcs8(bytes) {
                    return Err(UNSUPPORTED);
                }
                self.add_private_der(name, bytes, password, usages, resources)
            }
            PrivateKeyContainer::Der => {
                if is_pkcs8(bytes) {
                    return self.add_private_der(name, bytes, password, usages, resources);
                }
                self.add_traditional(name, bytes, None, usages, resources, 0)
            }
            PrivateKeyContainer::Pem => {
                let block = BorrowedPem::parse(bytes, resources.max_external_resource_bytes)
                    .map_err(|error| match error {
                        KeyStoreError::Policy(_) => error,
                        // A damaged body of a recognized envelope stays a
                        // protected-container failure, never a candidate miss.
                        _ if declares_envelope(bytes) => KeyStoreError::ProtectedContainer,
                        _ => error,
                    })?;
                let family = match block.label {
                    "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
                        return self.add_private_pem(name, bytes, password, usages, resources);
                    }
                    "RSA PRIVATE KEY" => Family::Rsa,
                    "EC PRIVATE KEY" => Family::Ec,
                    "DSA PRIVATE KEY" => Family::Dsa,
                    _ => return Err(UNSUPPORTED),
                };
                // The inventory's material and the new name stay retained
                // beside the input while it is decoded.
                let source = self
                    .retained_with_name(&name, resources)?
                    .checked_add(bytes.len())
                    .ok_or_else(|| aggregate_limit(resources))?;
                let traditional = decode_pem(&block, password, source, resources)?;
                // Besides the decoded DER, the encoded input, the password
                // and the DER buffer's unused capacity stay live while the
                // key is normalized and imported.
                let outside = bytes
                    .len()
                    .checked_add(traditional.password_len)
                    .and_then(|live| {
                        live.checked_add(traditional.der.capacity() - traditional.der.len())
                    })
                    .ok_or_else(|| aggregate_limit(resources))?;
                self.add_traditional(
                    name,
                    &traditional.der,
                    Some(family),
                    usages,
                    resources,
                    outside,
                )
                .map_err(|error| match error {
                    // A decrypted key over a safety ceiling, or of a family
                    // that cannot serve the requested usage, is that key's
                    // failure, not the password's.
                    KeyStoreError::Policy(_) | KeyStoreError::Selection(super::CANNOT_DECRYPT) => {
                        error
                    }
                    _ if error.is_component_limit() => error,
                    _ if traditional.encrypted => KeyStoreError::ProtectedContainer,
                    _ => error,
                })
            }
        }
    }

    /// Import the traditional key `der` of `family`, or of whichever family
    /// it decodes as when unknown; `outside` bytes are live besides `der`
    /// and count against the operation's aggregate budget once.
    fn add_traditional(
        &mut self,
        name: String,
        der: &[u8],
        family: Option<Family>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
        outside: usize,
    ) -> Result<(), KeyStoreError> {
        // `der` stays live beside a normalized copy.
        let live = outside
            .checked_add(der.len())
            .ok_or_else(|| aggregate_limit(resources))?;
        // Normalization also runs beside the inventory's retained material
        // and the new name, which the import below counts itself.
        let peak = self
            .retained_with_name(&name, resources)?
            .checked_add(live)
            .ok_or_else(|| aggregate_limit(resources))?;
        let shared = match family {
            // The label promises PKCS#1, never another container.
            Some(Family::Rsa) if is_pkcs8(der) => return Err(UNSUPPORTED),
            Some(Family::Rsa) => None,
            Some(Family::Ec) => Some(KeyFamily::Ec),
            Some(Family::Dsa) => Some(KeyFamily::Dsa),
            // Unlabelled DER: whichever family it is structurally, PKCS#1
            // RSA when neither.
            None => match normalize(der, None, resources, peak) {
                Err(KeyStoreError::Selection(NOT_TRADITIONAL)) => {
                    return self.add_private_der_inner(name, der, None, usages, resources, outside);
                }
                normalized => {
                    let normalized = normalized?;
                    return self.add_private_der_inner(
                        name,
                        &normalized,
                        None,
                        usages,
                        resources,
                        live,
                    );
                }
            },
        };
        match shared {
            // The inventory counts the normalized copy it receives.
            Some(family) => {
                let normalized =
                    normalize(der, Some(family), resources, peak).map_err(|error| match error {
                        KeyStoreError::Selection(NOT_TRADITIONAL) => UNSUPPORTED,
                        error => error,
                    })?;
                self.add_private_der_inner(name, &normalized, None, usages, resources, live)
            }
            // The inventory counts `der` and wraps PKCS#1 RSA itself.
            None => self.add_private_der_inner(name, der, None, usages, resources, outside),
        }
    }

    /// The material the inventory retains with an entry named `name` added,
    /// within the aggregate budget.
    fn retained_with_name(
        &self,
        name: &str,
        resources: &ResourcePolicy,
    ) -> Result<usize, KeyStoreError> {
        self.check_material_capacity(super::named_material_length(name, 0, 1)?, resources)
    }
}

/// Bytes that are no traditional key of either family: unlabelled DER then
/// is PKCS#1 RSA, a labelled one is no key of its container.
const NOT_TRADITIONAL: &str = "not a traditional EC or DSA private key";

/// Whether the header lines after the PEM `BEGIN` line declare the
/// traditional envelope.
fn declares_envelope(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes).is_ok_and(|text| {
        text.trim_start()
            .lines()
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .any(|line| {
                let line = line.trim_start();
                line.starts_with("Proc-Type:") || line.starts_with("DEK-Info:")
            })
    })
}

fn is_pkcs8(bytes: &[u8]) -> bool {
    PrivateKeyInfoRef::try_from(bytes).is_ok()
        || EncryptedPrivateKeyInfoRef::try_from(bytes).is_ok()
}

fn aggregate_limit(resources: &ResourcePolicy) -> KeyStoreError {
    import_resource_limit(
        resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
        resources.max_external_resource_total_bytes,
    )
}

/// The work account of one traditional key's decoding: the policy's X.509
/// work, which bounds the shared primitive's parsing, key derivation and
/// key checks. Buffers are admitted by [`reserve`] against the byte budgets.
fn work_account(resources: &ResourcePolicy) -> (Memory, usize) {
    let work = resources
        .max_x509_work
        .min(crate::hard_limits::X509_WORK_CEILING);
    let memory = Memory::new(Arc::new(MemoryAccount::new(
        resources.max_external_resource_total_bytes,
        work,
    )));
    (memory, work)
}

/// The refusal of the shared primitive's work account.
fn work_limit(error: MemoryError, work: usize, resources: &ResourcePolicy) -> KeyStoreError {
    if error == MemoryError::WorkExceeded {
        import_resource_limit(resource_name::X509_WORK, work)
    } else {
        aggregate_limit(resources)
    }
}

/// Refuses an `output` allocation beside `live` bytes over the budget.
fn reserve(resources: &ResourcePolicy, live: usize, output: usize) -> Result<(), KeyStoreError> {
    if output > resources.max_external_resource_bytes {
        return Err(import_resource_limit(
            resource_name::EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_bytes,
        ));
    }
    if live
        .checked_add(output)
        .is_none_or(|peak| peak > resources.max_external_resource_total_bytes)
    {
        return Err(aggregate_limit(resources));
    }
    Ok(())
}

/// The DER of the traditional PEM `block`, decrypted with `password` when
/// its headers declare the OpenSSL envelope.
fn decode_pem(
    block: &BorrowedPem<'_>,
    password: Option<&[u8]>,
    source_len: usize,
    resources: &ResourcePolicy,
) -> Result<Traditional, KeyStoreError> {
    let (memory, work) = work_account(resources);
    let envelope = Envelope::read(block.headers, &memory).map_err(|error| match error {
        OpenSslError::NotTraditional => UNSUPPORTED,
        OpenSslError::Resource(error) => work_limit(error, work, resources),
        _ => KeyStoreError::ProtectedContainer,
    })?;
    // A password is required before anything is decoded or allocated.
    if envelope.is_some() && password.is_none() {
        return Err(KeyStoreError::ProtectedContainer);
    }
    // The password the envelope uses is external material, bounded as one
    // resource and live beside everything the import holds.
    let password_len = password
        .filter(|_| envelope.is_some())
        .map_or(0, <[u8]>::len);
    if password_len > resources.max_external_resource_bytes {
        return Err(import_resource_limit(
            resource_name::EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_bytes,
        ));
    }
    let source_len = source_len
        .checked_add(password_len)
        .ok_or_else(|| aggregate_limit(resources))?;
    reserve(resources, source_len, block.decoded_len)?;
    let mut der = Zeroizing::new(vec![0; block.decoded_len]);
    block.decode_into(&mut der).map_err(|error| {
        if envelope.is_some() {
            KeyStoreError::ProtectedContainer
        } else {
            error
        }
    })?;
    if let Some(envelope) = envelope {
        let length = envelope
            .decrypt_in_place(&mut der, password, &memory)
            .map_err(|error| match error {
                OpenSslError::Resource(error) => work_limit(error, work, resources),
                _ => KeyStoreError::ProtectedContainer,
            })?;
        der.truncate(length);
    }
    Ok(Traditional {
        der,
        encrypted: envelope.is_some(),
        password_len,
    })
}

/// The traditional key `der` of `family`, or of the family it decodes as,
/// written as PKCS#8 beside `live` bytes.
fn normalize(
    der: &[u8],
    family: Option<KeyFamily>,
    resources: &ResourcePolicy,
    live: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
    let (memory, work) = work_account(resources);
    let refused = |error| match error {
        OpenSslError::NotTraditional => KeyStoreError::Selection(NOT_TRADITIONAL),
        OpenSslError::ComponentLimit => {
            KeyStoreError::Selection("invalid or oversized DSA private key")
        }
        OpenSslError::Resource(error) => work_limit(error, work, resources),
        _ => UNSUPPORTED,
    };
    let key = Key::read(
        der,
        family,
        crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING,
        &memory,
    )
    .map_err(refused)?;
    let length = key.encoded_len();
    reserve(resources, live, length)?;
    let mut normalized = Zeroizing::new(vec![0; length]);
    key.write(&mut normalized, &memory).map_err(refused)?;
    Ok(normalized)
}

#[cfg(test)]
mod tests;
