//! Private keys in the containers OpenSSL reads, an explicit import boundary
//! for compatibility callers such as the xmlsec1 command and library.
//!
//! Besides PKCS#8, the generic PEM and DER forms accept PKCS#1 RSA, SEC1 EC
//! and DSA keys, PEM ones also in the traditional envelope OpenSSL encrypts
//! with a password (RFC 1421 `Proc-Type`/`DEK-Info` headers). Every key is
//! normalized to PKCS#8 under the operation's resource budget before the
//! inventory imports it. The strict PKCS#8 importers never reach this path.

use alloc::{string::String, vec, vec::Vec};

use aes::cipher::{BlockModeDecrypt as _, KeyIvInit as _, block_padding::Pkcs7};
use crypto_bigint::{
    BoxedUint, Resize as _,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use der::{
    Decode as _, Encode as _,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef},
};
use dsa::{
    Components as DsaComponents, SigningKey as NativeDsaSigningKey,
    VerifyingKey as DsaVerifyingKey, pkcs8::EncodePrivateKey as _,
};
use md5::{Digest as _, Md5};
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
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

/// An upper bound of a DSA PKCS#8 document's framing: its version, the
/// algorithm identifier, and the tag and length octets of every DER element
/// (RFC 5958 section 2, RFC 3279 section 2.3.2).
const PKCS8_DSA_FRAMING: usize = 64;

/// The error of bytes that are not a key of the selected container.
const UNSUPPORTED: KeyStoreError = KeyStoreError::Selection("unsupported private key container");

/// A traditional key's DER and whether a password envelope protected it.
struct Traditional {
    der: Zeroizing<Vec<u8>>,
    encrypted: bool,
}

/// A traditional key family by its PEM label.
#[derive(Clone, Copy)]
enum Family {
    Rsa,
    Ec,
    Dsa,
}

#[derive(der::Sequence)]
struct TraditionalEcPrivateKey<'a> {
    version: u8,
    private_key: &'a OctetStringRef,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}

#[derive(der::Sequence)]
struct TraditionalDsaPrivateKey<'a> {
    version: u8,
    p: UintRef<'a>,
    q: UintRef<'a>,
    g: UintRef<'a>,
    y: UintRef<'a>,
    x: UintRef<'a>,
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
                // Besides the decoded DER, the encoded input and the DER
                // buffer's unused capacity stay live while the key is
                // normalized and imported.
                let outside = bytes
                    .len()
                    .checked_add(traditional.der.capacity() - traditional.der.len())
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
                    // A decrypted key over a safety ceiling is that key's
                    // failure, not the password's.
                    KeyStoreError::Policy(_)
                    | KeyStoreError::Selection(
                        "RSA modulus exceeds safety limit" | "RSA component exceeds safety limit",
                    ) => error,
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
        let normalized = match family {
            // The label promises PKCS#1, never another container.
            Some(Family::Rsa) if is_pkcs8(der) => return Err(UNSUPPORTED),
            Some(Family::Rsa) => None,
            Some(Family::Ec) => Some(normalize_ec(der, resources, peak)?.ok_or(UNSUPPORTED)?),
            Some(Family::Dsa) => Some(normalize_dsa(der, resources, peak)?.ok_or(UNSUPPORTED)?),
            None => match normalize_ec(der, resources, peak)? {
                Some(normalized) => Some(normalized),
                None => normalize_dsa(der, resources, peak)?,
            },
        };
        match normalized {
            // The inventory counts the normalized copy it receives.
            Some(normalized) => {
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
    let mut proc_type = None;
    let mut dek_info = None;
    for line in block.headers.lines() {
        let Some((header, value)) = line.trim().split_once(':') else {
            continue;
        };
        match header.trim() {
            "Proc-Type" if proc_type.is_none() => proc_type = Some(value.trim()),
            "DEK-Info" if dek_info.is_none() => dek_info = Some(value.trim()),
            _ if proc_type.is_some() || dek_info.is_some() => {
                return Err(KeyStoreError::ProtectedContainer);
            }
            _ => return Err(UNSUPPORTED),
        }
    }
    let encrypted = proc_type.is_some() || dek_info.is_some();
    let envelope = if encrypted {
        // RFC 1421 4.6.1.1: "4,ENCRYPTED" marks an encrypted message.
        if proc_type != Some("4,ENCRYPTED") {
            return Err(KeyStoreError::ProtectedContainer);
        }
        let (cipher, encoded_iv) = dek_info
            .and_then(|value| value.split_once(','))
            .ok_or(KeyStoreError::ProtectedContainer)?;
        let cipher = Cipher::named(cipher).ok_or(KeyStoreError::ProtectedContainer)?;
        // Two hex digits per IV octet: any other length is refused before
        // it is decoded.
        if encoded_iv.len() != 2 * cipher.iv_len() {
            return Err(KeyStoreError::ProtectedContainer);
        }
        let iv = decode_hex(encoded_iv).ok_or(KeyStoreError::ProtectedContainer)?;
        Some((
            cipher,
            iv,
            password.ok_or(KeyStoreError::ProtectedContainer)?,
        ))
    } else {
        None
    };
    reserve(resources, source_len, block.decoded_len)?;
    let mut der = Zeroizing::new(vec![0; block.decoded_len]);
    block.decode_into(&mut der).map_err(|error| {
        if encrypted {
            KeyStoreError::ProtectedContainer
        } else {
            error
        }
    })?;
    if let Some((cipher, iv, password)) = envelope {
        der = cipher.decrypt(&iv, der, password)?;
    }
    Ok(Traditional { der, encrypted })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let digit = |byte: u8| char::from(byte).to_digit(16);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| u8::try_from(digit(high)? * 16 + digit(low)?).ok())
        .collect()
}

/// The ciphers OpenSSL writes in a traditional envelope's `DEK-Info`.
#[derive(Clone, Copy)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    Des,
    DesEde,
    DesEde3,
}

impl Cipher {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "AES-128-CBC" => Self::Aes128,
            "AES-192-CBC" => Self::Aes192,
            "AES-256-CBC" => Self::Aes256,
            "DES-CBC" => Self::Des,
            "DES-EDE-CBC" => Self::DesEde,
            "DES-EDE3-CBC" => Self::DesEde3,
            _ => return None,
        })
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128 | Self::DesEde => 16,
            Self::Aes192 | Self::DesEde3 => 24,
            Self::Aes256 => 32,
            Self::Des => 8,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            Self::Des | Self::DesEde | Self::DesEde3 => 8,
        }
    }

    /// `ciphertext` decrypted in place with the key `password` derives.
    fn decrypt(
        self,
        iv: &[u8],
        mut ciphertext: Zeroizing<Vec<u8>>,
        password: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(self.iv_len()) {
            return Err(KeyStoreError::ProtectedContainer);
        }
        let key = envelope_key(password, &iv[..8], self.key_len());
        macro_rules! decrypt {
            ($cipher:ty) => {
                cbc::Decryptor::<$cipher>::new_from_slices(&key, iv)
                    .map_err(|_| KeyStoreError::ProtectedContainer)?
                    .decrypt_padded::<Pkcs7>(&mut ciphertext)
                    .map_err(|_| KeyStoreError::ProtectedContainer)?
                    .len()
            };
        }
        let length = match self {
            Self::Aes128 => decrypt!(aes::Aes128),
            Self::Aes192 => decrypt!(aes::Aes192),
            Self::Aes256 => decrypt!(aes::Aes256),
            Self::Des => decrypt!(des::Des),
            Self::DesEde => decrypt!(des::TdesEde2),
            Self::DesEde3 => decrypt!(des::TdesEde3),
        };
        ciphertext.truncate(length);
        Ok(ciphertext)
    }
}

/// OpenSSL `EVP_BytesToKey` with MD5, one iteration and the first eight IV
/// bytes as salt, as the traditional envelope derives its key; `DEK-Info`
/// carries the whole IV.
fn envelope_key(password: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    // Whole MD5 blocks are derived even for a 24-byte key; reserve them once.
    let mut key = Zeroizing::new(Vec::with_capacity(key_len.div_ceil(16) * 16));
    let mut previous: Option<Zeroizing<[u8; 16]>> = None;
    while key.len() < key_len {
        let mut digest = Md5::new();
        if let Some(previous) = previous.as_deref() {
            digest.update(previous);
        }
        digest.update(password);
        digest.update(salt);
        let block = Zeroizing::new(<[u8; 16]>::from(digest.finalize()));
        key.extend_from_slice(block.as_ref());
        previous = Some(block);
    }
    key.truncate(key_len);
    key
}

/// The SEC1 `ECPrivateKey` `der` wrapped as PKCS#8, or `None` when `der` is
/// not one.
fn normalize_ec(
    der: &[u8],
    resources: &ResourcePolicy,
    live: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    let Ok(ec) = TraditionalEcPrivateKey::from_der(der) else {
        return Ok(None);
    };
    if ec.version != 1 {
        return Err(UNSUPPORTED);
    }
    // RFC 5915 sections 1/3 and RFC 5958 section 2: keep the ECPrivateKey
    // octets; the PKCS#8 algorithm carries the named curve.
    let curve = match ec.parameters {
        Some(curve) => curve,
        // RFC 5915 section 3 requires the parameters of conforming
        // generators; OpenSSL also reads SEC1 without them, so the curve is
        // the one the typed decoders validate the key and public point on.
        None if p256::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
        }
        None if p384::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.3.132.0.34")
        }
        None if p521::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.3.132.0.35")
        }
        None => return Err(UNSUPPORTED),
    };
    let algorithm = pkcs8::AlgorithmIdentifierRef {
        // RFC 5480 2.1.1: id-ecPublicKey.
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
        parameters: Some(AnyRef::from(&curve)),
    };
    let info = PrivateKeyInfoRef::new(
        algorithm,
        OctetStringRef::new(der).map_err(|_| UNSUPPORTED)?,
    );
    let size = usize::try_from(info.encoded_len().map_err(|_| UNSUPPORTED)?)
        .map_err(|_| aggregate_limit(resources))?;
    reserve(resources, live, size)?;
    Ok(Some(Zeroizing::new(
        info.to_der().map_err(|_| UNSUPPORTED)?,
    )))
}

/// The OpenSSL DSA private key `der` as PKCS#8, or `None` when `der` is not
/// one.
fn normalize_dsa(
    der: &[u8],
    resources: &ResourcePolicy,
    live: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    let Ok(key) = TraditionalDsaPrivateKey::from_der(der) else {
        return Ok(None);
    };
    if key.version != 0 {
        return Err(UNSUPPORTED);
    }
    // Bound the components before any bigint work.
    if [key.p, key.q, key.g, key.y, key.x].iter().any(|component| {
        component.as_bytes().len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING
    }) {
        return Err(KeyStoreError::Selection(
            "invalid or oversized DSA private key",
        ));
    }
    let p = BoxedUint::from_be_slice_vartime(key.p.as_bytes());
    let q = BoxedUint::from_be_slice_vartime(key.q.as_bytes());
    let g = BoxedUint::from_be_slice_vartime(key.g.as_bytes());
    let public = BoxedUint::from_be_slice_vartime(key.y.as_bytes());
    // The private exponent is wiped on every path out, refusals included.
    let secret = Zeroizing::new(BoxedUint::from_be_slice_vartime(key.x.as_bytes()));
    let components = DsaComponents::from_components(p, q, g).map_err(|_| UNSUPPORTED)?;
    // FIPS 186-4 4.1: the stored public key must equal g^x mod p. The
    // Montgomery form needs g at p's precision; a g that does not fit there
    // is not below p (FIPS 186-4 4.1 requires 1 < g < p).
    let generator = BoxedUint::clone(components.g())
        .try_resize(components.p().bits_precision())
        .ok_or(UNSUPPORTED)?;
    let params = BoxedMontyParams::new(components.p().clone());
    let expected = BoxedMontyForm::new(generator, &params)
        .pow(&secret)
        .retrieve();
    if expected != public {
        return Err(UNSUPPORTED);
    }
    // The encoded document and its owned copy coexist, each no larger than
    // the domain parameters and the private value plus the PKCS#8 framing:
    // admit both before encoding. Each is one resource; the first is live
    // while the copy is made.
    let document = [key.p, key.q, key.g, key.x]
        .iter()
        .try_fold(PKCS8_DSA_FRAMING, |total, component| {
            total.checked_add(component.as_bytes().len())
        })
        .ok_or_else(|| aggregate_limit(resources))?;
    reserve(resources, live, document)?;
    let with_document = live
        .checked_add(document)
        .ok_or_else(|| aggregate_limit(resources))?;
    reserve(resources, with_document, document)?;
    let verifying =
        DsaVerifyingKey::from_components(components, public).map_err(|_| UNSUPPORTED)?;
    // The signing key owns its copy and zeroizes it on drop.
    let signing = NativeDsaSigningKey::from_components(verifying, BoxedUint::clone(&secret))
        .map_err(|_| UNSUPPORTED)?;
    let normalized = signing.to_pkcs8_der().map_err(|_| UNSUPPORTED)?;
    Ok(Some(Zeroizing::new(normalized.as_bytes().to_vec())))
}

#[cfg(test)]
mod tests;
