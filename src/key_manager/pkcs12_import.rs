//! PKCS#12 import over the shared `structured_cms::personal` container reader.
//!
//! The shared reader owns PFX, safe and bag framing and authenticates the whole
//! safe before extraction. This adapter owns the password, the MAC, KDF and
//! cipher work and their admission under the compiled resource policy.

use std::sync::Arc;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use der::asn1::ObjectIdentifier as Oid;
use hmac::{Hmac, KeyInit as _, Mac as _};
use pkcs12::kdf::{Pkcs12KeyType, derive_key};
use structured_asn1::length::DerLength;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, MemoryReservation};
use structured_asn1::{Encoding, Integer, Limit, Parser, Reader, Tag};
use structured_cms::Octets;
use structured_cms::personal::protection::{Prf, Protection, Salt};
use structured_cms::personal::{
    self, Backend, Bag, BagValue, Cause, Decision, Failure, Integrity, MacData, Pfx, Plaintext,
    PrivateKey, Safe, ShroudedKey, Source,
};
use structured_pkix::AlgorithmIdentifier;
use zeroize::Zeroizing;

use super::KeyStoreError;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};

type Result<T> = core::result::Result<T, KeyStoreError>;
const FIELD: &str = "PKCS#12 import";

pub(super) struct Limits {
    pub resources: ResourcePolicy,
    pub candidates: usize,
    pub memory_available: usize,
}

pub(super) struct Contents {
    pub private_key: Option<Zeroizing<Vec<u8>>>,
    pub certificates: Vec<Vec<u8>>,
}

/// A password and the capacity of the buffer that holds it; that buffer stays
/// live for the whole import.
pub(super) trait Secret {
    fn text(&self) -> &str;
    fn capacity(&self) -> usize;
}

impl Secret for &str {
    fn text(&self) -> &str {
        self
    }
    fn capacity(&self) -> usize {
        self.len()
    }
}

impl Secret for Zeroizing<String> {
    fn text(&self) -> &str {
        self.as_str()
    }
    fn capacity(&self) -> usize {
        String::capacity(self)
    }
}

/// Import one PFX in a single pass. `password` is called once, when the MAC or
/// a decryption first needs it and after that step's KDF and memory admission;
/// a container that needs no password never calls it. Work spent is kept in
/// `work` on failure too.
pub(super) fn import<S: Secret, F: FnOnce() -> Option<S>>(
    bytes: &[u8],
    limits: &Limits,
    work: &mut usize,
    password: F,
) -> Result<Contents> {
    let maximum = limits.resources.max_key_import_kdf_work;
    if *work > maximum {
        return Err(denial(resource_name::KEY_IMPORT_KDF_WORK, maximum));
    }
    let ceilings = Ceilings {
        memory: limits.resources.max_external_resource_total_bytes,
        work: limits
            .resources
            .max_x509_work
            .min(crate::hard_limits::X509_WORK_CEILING),
    };
    let parser = Parser::new(
        Encoding::Ber,
        structured_asn1::Limits {
            max_depth: crate::hard_limits::ASN1_DEPTH_CEILING,
            max_elements: ceilings.work as u64,
            // The caller already bounded the input; nested plaintext is
            // bounded by the memory account below.
            max_element_length: u64::MAX,
            max_work: ceilings.work as u64,
        },
        Memory::new(Arc::new(MemoryAccount::new(
            limits.memory_available,
            ceilings.work,
        ))),
    );
    let mut reader = parser.read(bytes, 0).map_err(|e| ceilings.refuse(&e))?;
    let pfx = Pfx::read(&mut reader).map_err(|e| {
        if e.code() == structured_cms::ErrorCode::UnexpectedContentType {
            KeyStoreError::Selection("unsupported PKCS#12 integrity mode")
        } else {
            ceilings.refuse(&e)
        }
    })?;
    let mut adapter = Adapter {
        password: Password {
            request: Some(password),
            secret: None,
        },
        bmp: None,
        charges: Charges::new(limits, ceilings, *work),
        key: None,
        certificates: Vec::new(),
        reservations: Vec::new(),
    };
    let outcome = personal::process(&pfx, &reader, &mut adapter);
    // Work is not refunded by password, encoding or later association failures.
    *work = adapter.charges.work;
    match outcome {
        Ok(Decision::Accept) => Ok(adapter.into_contents()),
        Ok(Decision::Reject) => Err(KeyStoreError::ProtectedContainer),
        Ok(Decision::Unsupported) => Err(KeyStoreError::Selection(
            "unsupported PKCS#12 integrity mode",
        )),
        Err(failure) => Err(ceilings.failure(failure)),
    }
}

fn denial(resource: &'static str, maximum: usize) -> KeyStoreError {
    PolicyViolation::ResourceLimitExceeded { resource, maximum }.into()
}

fn malformed<T>() -> Result<T> {
    Err(KeyStoreError::ProtectedContainer)
}

fn remaining(memory: &Memory) -> usize {
    memory.limit() - memory.used()
}

/// A shared-reader refusal: its reader code and whether it is a resource limit.
trait Refusal {
    fn reader_code(&self) -> Option<structured_asn1::ErrorCode>;
    fn is_resource(&self) -> bool;
}

impl Refusal for structured_asn1::Error {
    fn reader_code(&self) -> Option<structured_asn1::ErrorCode> {
        Some(self.code())
    }
    fn is_resource(&self) -> bool {
        structured_asn1::Error::is_resource(self)
    }
}

impl Refusal for structured_pkix::Error {
    fn reader_code(&self) -> Option<structured_asn1::ErrorCode> {
        match self.code() {
            structured_pkix::ErrorCode::Encoding(code) => Some(code),
            _ => None,
        }
    }
    fn is_resource(&self) -> bool {
        structured_pkix::Error::is_resource(self)
    }
}

impl Refusal for structured_cms::Error {
    fn reader_code(&self) -> Option<structured_asn1::ErrorCode> {
        match self.code() {
            structured_cms::ErrorCode::Encoding(code)
            | structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::Encoding(code)) => {
                Some(code)
            }
            _ => None,
        }
    }
    fn is_resource(&self) -> bool {
        structured_cms::Error::is_resource(self)
    }
}

/// The policy ceilings a shared-reader resource refusal is reported against.
#[derive(Clone, Copy)]
struct Ceilings {
    memory: usize,
    work: usize,
}

impl Ceilings {
    fn refuse(self, error: &impl Refusal) -> KeyStoreError {
        use structured_asn1::ErrorCode as Code;
        let code = error.reader_code();
        // Excess nesting describes the encoding, not an exhausted allowance.
        if !error.is_resource() || matches!(code, Some(Code::LimitExceeded(Limit::Depth))) {
            return KeyStoreError::ProtectedContainer;
        }
        if matches!(
            code,
            Some(
                Code::LimitExceeded(Limit::Memory)
                    | Code::AllocatorExhausted
                    | Code::CapacityOverflow
            )
        ) {
            denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.memory,
            )
        } else {
            denial(resource_name::X509_WORK, self.work)
        }
    }

    fn memory(self, error: MemoryError) -> KeyStoreError {
        if error == MemoryError::WorkExceeded {
            denial(resource_name::X509_WORK, self.work)
        } else {
            denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.memory,
            )
        }
    }

    fn failure(self, failure: Failure<KeyStoreError>) -> KeyStoreError {
        match failure.cause {
            Cause::Callback(error) => error,
            // An AuthenticatedSafe member of any content type other than
            // data or encrypted data names a privacy mode this import lacks.
            Cause::Processing(error)
                if error.code() == structured_cms::ErrorCode::UnexpectedContentType =>
            {
                KeyStoreError::Selection("unsupported PKCS#12 privacy mode")
            }
            Cause::Processing(error) => self.refuse(&error),
        }
    }
}

/// Bag count and KDF work of one pass over the container.
struct Charges<'l> {
    limits: &'l Limits,
    ceilings: Ceilings,
    work: usize,
    candidates: usize,
}

impl<'l> Charges<'l> {
    fn new(limits: &'l Limits, ceilings: Ceilings, work: usize) -> Self {
        Self {
            limits,
            ceilings,
            work,
            candidates: 0,
        }
    }

    fn count(&mut self) -> Result<()> {
        if self.candidates >= self.limits.candidates {
            return Err(denial(
                resource_name::KEY_CANDIDATES,
                self.limits.candidates,
            ));
        }
        self.candidates += 1;
        Ok(())
    }

    fn kdf(&mut self, rounds: u32, blocks: usize, salt: usize) -> Result<()> {
        let salt_maximum = self.limits.resources.max_external_resource_bytes;
        if salt > salt_maximum {
            return Err(denial("PKCS#12 salt bytes", salt_maximum));
        }
        let maximum = self.limits.resources.max_key_import_kdf_work;
        let work = (rounds as usize)
            .checked_mul(blocks)
            .ok_or_else(|| denial(resource_name::KEY_IMPORT_KDF_WORK, maximum))?;
        if work > maximum - self.work {
            return Err(denial(resource_name::KEY_IMPORT_KDF_WORK, maximum));
        }
        self.work += work;
        Ok(())
    }

    fn admit(&mut self, scheme: &Scheme<'_, '_>) -> Result<()> {
        let blocks = match scheme.prf {
            Some(prf) => scheme.cipher.key_len().div_ceil(prf.size()),
            // Appendix B.2 derives key and IV separately; 24-byte SHA-1
            // keys need two digest blocks, not one iteration charge.
            None => scheme.cipher.key_len().div_ceil(20) + 1,
        };
        self.kdf(scheme.rounds, blocks, scheme.salt.len())
    }

    /// Product work accounting matches PKCS#8: password-keyed HMAC
    /// preprocessing is charged for each PBES2 derivation, hidden bags included.
    fn hash_password(&mut self, password: usize) -> Result<()> {
        let maximum = self.limits.resources.max_key_import_kdf_work;
        let work = password.div_ceil(64);
        if work > maximum - self.work {
            return Err(denial(resource_name::KEY_IMPORT_KDF_WORK, maximum));
        }
        self.work += work;
        Ok(())
    }

    fn legacy_workspace(
        &self,
        salt: usize,
        password: usize,
        block: usize,
        output: usize,
        memory: &Memory,
    ) -> Result<()> {
        // RFC 7292 B.2 rounds salt and password up to digest blocks. Account
        // for the KDF's I, diversifier and output before RustCrypto allocates.
        // https://www.rfc-editor.org/rfc/rfc7292#appendix-B.2
        let maximum = self.limits.resources.max_key_import_kdf_memory_bytes;
        let size = salt
            .div_ceil(block)
            .checked_add(password.div_ceil(block))
            .and_then(|n| n.checked_mul(block))
            .and_then(|n| n.checked_add(block + output))
            .ok_or_else(|| denial(resource_name::KEY_IMPORT_KDF_MEMORY, maximum))?;
        if size > maximum {
            return Err(denial(resource_name::KEY_IMPORT_KDF_MEMORY, maximum));
        }
        if size > remaining(memory) {
            return Err(denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.ceilings.memory,
            ));
        }
        Ok(())
    }
}

/// RFC 7292 section 4 uses BER INTEGERs, not machine-width counters. A
/// positive value beyond the work ceiling is a policy denial; the shared reader
/// has already refused malformed, zero and negative encodings.
/// <https://www.rfc-editor.org/rfc/rfc7292#section-4>
fn rounds(value: Integer<'_>, maximum: usize) -> Result<u32> {
    value
        .as_u64()
        .filter(|rounds| *rounds <= maximum as u64)
        .and_then(|rounds| i32::try_from(rounds).ok())
        .and_then(|rounds| u32::try_from(rounds).ok())
        .ok_or_else(|| PolicyViolation::KdfIterationsOutsideLimit { maximum }.into())
}

#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    const ALL: [Self; 5] = [
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
    ];
    const DIGESTS: [Oid; 5] = [
        Oid::new_unwrap("1.3.14.3.2.26"),
        Oid::new_unwrap("2.16.840.1.101.3.4.2.4"),
        Oid::new_unwrap("2.16.840.1.101.3.4.2.1"),
        Oid::new_unwrap("2.16.840.1.101.3.4.2.2"),
        Oid::new_unwrap("2.16.840.1.101.3.4.2.3"),
    ];
    const HMACS: [Oid; 5] = [
        Oid::new_unwrap("1.2.840.113549.2.7"),
        Oid::new_unwrap("1.2.840.113549.2.8"),
        Oid::new_unwrap("1.2.840.113549.2.9"),
        Oid::new_unwrap("1.2.840.113549.2.10"),
        Oid::new_unwrap("1.2.840.113549.2.11"),
    ];

    fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn block(self) -> usize {
        match self {
            Self::Sha384 | Self::Sha512 => 128,
            _ => 64,
        }
    }

    fn select(oid: &[u8], table: &[Oid; 5], unsupported: &'static str) -> Result<Self> {
        table
            .iter()
            .zip(Self::ALL)
            .find_map(|(known, hash)| (known.as_bytes() == oid).then_some(hash))
            .ok_or(KeyStoreError::Selection(unsupported))
    }
}

macro_rules! with_hash {
    ($hash:expr, $digest:ident, $body:expr) => {
        match $hash {
            Hash::Sha1 => {
                type $digest = sha1::Sha1;
                $body
            }
            Hash::Sha224 => {
                type $digest = sha2::Sha224;
                $body
            }
            Hash::Sha256 => {
                type $digest = sha2::Sha256;
                $body
            }
            Hash::Sha384 => {
                type $digest = sha2::Sha384;
                $body
            }
            Hash::Sha512 => {
                type $digest = sha2::Sha512;
                $body
            }
        }
    };
}

#[derive(Clone, Copy)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    DoubleDes,
}

impl Cipher {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128 | Self::DoubleDes => 16,
            Self::Aes192 | Self::TripleDes => 24,
            Self::Aes256 => 32,
        }
    }

    fn block(self) -> usize {
        match self {
            Self::TripleDes | Self::DoubleDes => 8,
            _ => 16,
        }
    }
}

/// One supported password-protection scheme, read before any password work.
struct Scheme<'s, 'a> {
    cipher: Cipher,
    salt: &'s Octets<'a>,
    rounds: u32,
    /// PBES2 PRF; `None` selects the RFC 7292 Appendix B KDF.
    prf: Option<Hash>,
    iv: [u8; 16],
}

fn scheme<'s, 'a>(
    protection: &'s Protection<'a>,
    algorithm: AlgorithmIdentifier<'a>,
    query: &Reader<'_>,
    limits: &Limits,
    ceilings: Ceilings,
) -> Result<Scheme<'s, 'a>> {
    let maximum = limits.resources.max_key_import_kdf_work;
    match protection {
        Protection::Pbes2(pair) => {
            let kdf = pair.pbkdf2.as_ref().ok_or(KeyStoreError::Selection(
                "unsupported PKCS#12 PBES2 KDF algorithm",
            ))?;
            let Salt::Specified(salt) = &kdf.salt else {
                return malformed();
            };
            let rounds = rounds(kdf.iterations, maximum)?;
            let prf = match kdf.prf {
                Prf::DefaultSha1 => Hash::Sha1,
                Prf::Written(written) => Hash::select(
                    written.algorithm().as_bytes(),
                    &Hash::HMACS,
                    "unsupported PKCS#12 PRF algorithm",
                )?,
            };
            let scheme_oid = pair.scheme.algorithm();
            let cipher = [
                (pkcs8::pkcs5::pbes2::AES_128_CBC_OID, Cipher::Aes128),
                (pkcs8::pkcs5::pbes2::AES_192_CBC_OID, Cipher::Aes192),
                (pkcs8::pkcs5::pbes2::AES_256_CBC_OID, Cipher::Aes256),
            ]
            .into_iter()
            .find_map(|(oid, cipher)| (oid.as_bytes() == scheme_oid.as_bytes()).then_some(cipher))
            .ok_or(KeyStoreError::Selection(
                "unsupported PKCS#12 PBES2 encryption scheme",
            ))?;
            let iv = aes_iv(pair.scheme, query, ceilings)?;
            if kdf
                .key_length
                .is_some_and(|length| length.as_u64() != Some(cipher.key_len() as u64))
            {
                return malformed();
            }
            Ok(Scheme {
                cipher,
                salt,
                rounds,
                prf: Some(prf),
                iv,
            })
        }
        Protection::Pkcs12(legacy) => {
            let oid = algorithm.algorithm();
            let cipher = if oid.as_bytes()
                == pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC.as_bytes()
            {
                Cipher::TripleDes
            } else if oid.as_bytes()
                == pkcs12::PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC.as_bytes()
            {
                Cipher::DoubleDes
            } else {
                return Err(KeyStoreError::Selection(
                    "unsupported PKCS#12 encryption algorithm",
                ));
            };
            Ok(Scheme {
                cipher,
                salt: &legacy.salt,
                rounds: rounds(legacy.iterations, maximum)?,
                prf: None,
                iv: [0; 16],
            })
        }
        Protection::Pbes1(_) | Protection::Other(_) => Err(KeyStoreError::Selection(
            "unsupported PKCS#12 encryption algorithm",
        )),
    }
}

/// RFC 8018 B.2.5 makes the AES-CBC parameter the 16-octet IV. RFC 7292
/// section 4 requires BER, whose OCTET STRINGs may be constructed (X.690
/// 8.7.1, 8.7.3); segments are copied into fixed cipher state.
/// <https://www.rfc-editor.org/rfc/rfc8018#appendix-B.2.5>
fn aes_iv(
    scheme: AlgorithmIdentifier<'_>,
    query: &Reader<'_>,
    ceilings: Ceilings,
) -> Result<[u8; 16]> {
    let mut reader = scheme
        .parameters_reader_in(query, FIELD)
        .map_err(|e| ceilings.refuse(&e))?
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let element = reader
        .next_element()
        .map_err(|e| ceilings.refuse(&e))?
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let octets = Octets::read(&reader, &element, FIELD).map_err(|e| ceilings.refuse(&e))?;
    if !reader.is_empty() || octets.len() != 16 {
        return malformed();
    }
    let mut iv = [0; 16];
    let mut at = 0;
    for piece in octets.pieces() {
        let bytes = piece.as_bytes();
        iv[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    }
    Ok(iv)
}

/// The legacy MAC scheme, admitted against the KDF budget before the password.
struct MacScheme<'s, 'a> {
    hash: Hash,
    salt: &'s Octets<'a>,
    digest: &'s Octets<'a>,
    rounds: u32,
}

fn mac_scheme<'s, 'a>(
    mac: &'s MacData<'a>,
    charges: &mut Charges<'_>,
) -> Result<MacScheme<'s, 'a>> {
    if mac.pbmac1.is_some() {
        return Err(KeyStoreError::Selection(
            "unsupported PKCS#12 MAC algorithm",
        ));
    }
    let hash = Hash::select(
        mac.algorithm.algorithm().as_bytes(),
        &Hash::DIGESTS,
        "unsupported PKCS#12 digest algorithm",
    )?;
    if mac.digest.len() != hash.size() {
        return malformed();
    }
    let maximum = charges.limits.resources.max_key_import_kdf_work;
    let rounds = match mac.iterations {
        None => 1,
        Some(value) => rounds(value, maximum)?,
    };
    charges.kdf(rounds, 1, mac.salt.len())?;
    Ok(MacScheme {
        hash,
        salt: &mac.salt,
        digest: &mac.digest,
        rounds,
    })
}

/// Logical octets as one slice: borrowed when the encoding has one segment.
enum Contiguous<'a> {
    Borrowed(&'a [u8]),
    Joined(Plaintext),
}

impl core::ops::Deref for Contiguous<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Joined(plain) => plain.as_bytes(),
        }
    }
}

fn contiguous<'a>(
    octets: &Octets<'a>,
    query: &Reader<'_>,
    ceilings: Ceilings,
) -> Result<Contiguous<'a>> {
    if let [piece] = octets.pieces() {
        return Ok(Contiguous::Borrowed(piece.as_bytes()));
    }
    Plaintext::copy_octets(octets, query)
        .map(Contiguous::Joined)
        .map_err(|e| ceilings.refuse(&e))
}

fn header_len(length: usize) -> usize {
    1 + DerLength::new(length as u64).as_bytes().len()
}

fn framed(length: usize) -> Option<usize> {
    length.checked_add(header_len(length))
}

fn header(output: &mut Vec<u8>, tag: u8, length: usize) {
    output.push(tag);
    output.extend_from_slice(DerLength::new(length as u64).as_bytes());
}

/// RFC 7292 4.2.1 permits a BER `PrivateKeyInfo`; the key decoders read DER.
/// Only framing is rewritten: algorithm parameters must already be DER, as for
/// the shared effective-SPKI framing, and attributes are validated, not kept.
/// <https://www.rfc-editor.org/rfc/rfc7292#section-4.2.1>
fn private_key_der(
    key: &PrivateKey<'_>,
    query: &Reader<'_>,
    ceilings: Ceilings,
) -> Result<(Zeroizing<Vec<u8>>, MemoryReservation)> {
    use der::Decode as _;
    let algorithm = key.algorithm;
    let parameters = algorithm.parameters().unwrap_or(&[]);
    if !parameters.is_empty() && !algorithm.encoding().is_der() {
        let mut reader = algorithm
            .parameters_reader_in(query, FIELD)
            .map_err(|e| ceilings.refuse(&e))?
            .ok_or(KeyStoreError::ProtectedContainer)?;
        let element = reader
            .next_element()
            .map_err(|e| ceilings.refuse(&e))?
            .ok_or(KeyStoreError::ProtectedContainer)?;
        let mut strict = reader
            .reread(&element, Encoding::Der)
            .map_err(|_| KeyStoreError::ProtectedContainer)?;
        let original = strict
            .next_element()
            .map_err(|_| KeyStoreError::ProtectedContainer)?
            .ok_or(KeyStoreError::ProtectedContainer)?;
        structured_pkix::der::conforms(&strict, &original, FIELD)
            .map_err(|e| ceilings.refuse(&e))?;
    }
    // The shared reader admits a constructed BER public key; contents of a
    // primitive [1] BIT STRING are already its DER contents.
    let public = match &key.public_key {
        None => None,
        Some(value) if value.element().tag() == Tag::context(false, 1) => {
            Some(value.element().contents())
        }
        Some(_) => return malformed(),
    };
    let oid = algorithm.algorithm().as_bytes();
    let version = u8::try_from(key.version).map_err(|_| KeyStoreError::ProtectedContainer)?;
    let identifier = framed(oid.len())
        .and_then(|n| n.checked_add(parameters.len()))
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let body = framed(identifier)
        .and_then(|n| n.checked_add(3))
        .and_then(|n| n.checked_add(framed(key.secret.len())?))
        .and_then(|n| n.checked_add(public.map_or(Some(0), |p| framed(p.len()))?))
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let total = framed(body).ok_or(KeyStoreError::ProtectedContainer)?;
    let reservation = query
        .memory()
        .reserve(total)
        .map_err(|e| ceilings.memory(e))?;
    query
        .charge(total as u64)
        .map_err(|e| ceilings.refuse(&e))?;
    let mut output = Zeroizing::new(Vec::with_capacity(total));
    header(&mut output, 0x30, body);
    output.extend_from_slice(&[2, 1, version]);
    header(&mut output, 0x30, identifier);
    header(&mut output, 6, oid.len());
    output.extend_from_slice(oid);
    output.extend_from_slice(parameters);
    header(&mut output, 4, key.secret.len());
    for piece in key.secret.pieces() {
        output.extend_from_slice(piece.as_bytes());
    }
    if let Some(public) = public {
        header(&mut output, 0x81, public.len());
        output.extend_from_slice(public);
    }
    pkcs8::PrivateKeyInfoRef::from_der(&output).map_err(|_| KeyStoreError::ProtectedContainer)?;
    Ok((output, reservation))
}

/// The caller's password, requested once and only when a step needs it.
struct Password<F, S> {
    request: Option<F>,
    /// The obtained password and the live charge for its whole buffer.
    secret: Option<(S, MemoryReservation)>,
}

impl<S: Secret, F: FnOnce() -> Option<S>> Password<F, S> {
    fn text(&mut self, limits: &Limits, ceilings: Ceilings, query: &Reader<'_>) -> Result<&str> {
        if self.secret.is_none() {
            let request = self
                .request
                .take()
                .ok_or(KeyStoreError::ProtectedContainer)?;
            let secret = request().ok_or(KeyStoreError::ProtectedContainer)?;
            let maximum = limits.resources.max_external_resource_bytes;
            if secret.text().len() > maximum {
                return Err(denial(resource_name::EXTERNAL_RESOURCE_BYTES, maximum));
            }
            // A callback can return spare capacity; the whole buffer stays live.
            let reservation = query
                .memory()
                .reserve(secret.capacity())
                .map_err(|e| ceilings.memory(e))?;
            self.secret = Some((secret, reservation));
        }
        Ok(self.secret.as_ref().map_or("", |(secret, _)| secret.text()))
    }
}

/// The selected container backend: `RustCrypto` MAC, KDF and cipher work over a
/// caller password. Retained outputs keep their memory reservation until the
/// import returns them.
struct Adapter<'l, F, S> {
    password: Password<F, S>,
    /// RFC 7292 B.1 `BMPString` form, derived on the first legacy use.
    bmp: Option<Plaintext>,
    charges: Charges<'l>,
    key: Option<Zeroizing<Vec<u8>>>,
    certificates: Vec<Vec<u8>>,
    /// Charges for `key` and `certificates`, held until the import returns.
    reservations: Vec<MemoryReservation>,
}

impl<S: Secret, F: FnOnce() -> Option<S>> Adapter<'_, F, S> {
    fn into_contents(self) -> Contents {
        Contents {
            private_key: self.key,
            certificates: self.certificates,
        }
    }

    fn one_key(&self) -> Result<()> {
        if self.key.is_some() {
            return Err(KeyStoreError::Selection(
                "PKCS#12 bundle must contain exactly one private key",
            ));
        }
        Ok(())
    }

    fn retain_key(&mut self, key: &PrivateKey<'_>, query: &Reader<'_>) -> Result<()> {
        self.one_key()?;
        let (der, reservation) = private_key_der(key, query, self.charges.ceilings)?;
        self.reservations.push(reservation);
        self.key = Some(der);
        Ok(())
    }

    fn retain_certificate(&mut self, certificate: &Octets<'_>, query: &Reader<'_>) -> Result<()> {
        let ceilings = self.charges.ceilings;
        let size = certificate.len()
            + core::mem::size_of::<Vec<u8>>()
            + core::mem::size_of::<MemoryReservation>();
        let reservation = query
            .memory()
            .reserve(size)
            .map_err(|e| ceilings.memory(e))?;
        query
            .charge(certificate.len() as u64)
            .map_err(|e| ceilings.refuse(&e))?;
        let mut copy = Vec::with_capacity(certificate.len());
        for piece in certificate.pieces() {
            copy.extend_from_slice(piece.as_bytes());
        }
        self.reservations.push(reservation);
        self.certificates.push(copy);
        Ok(())
    }

    fn decrypt(
        &mut self,
        protection: &Protection<'_>,
        algorithm: AlgorithmIdentifier<'_>,
        ciphertext: &Octets<'_>,
        query: &Reader<'_>,
    ) -> Result<Plaintext> {
        let ceilings = self.charges.ceilings;
        let scheme = scheme(protection, algorithm, query, self.charges.limits, ceilings)?;
        let block = scheme.cipher.block();
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(block) {
            return malformed();
        }
        // KDF work and the plaintext copy are admitted before the password is
        // requested, so a refused step never prompts for one.
        self.charges.admit(&scheme)?;
        if ciphertext.len() > remaining(query.memory()) {
            return Err(denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ceilings.memory,
            ));
        }
        let password = self.password.text(self.charges.limits, ceilings, query)?;
        if scheme.prf.is_some() {
            self.charges.hash_password(password.len())?;
        }
        let salt = contiguous(scheme.salt, query, ceilings)?;
        let key_len = scheme.cipher.key_len();
        let rounds =
            i32::try_from(scheme.rounds).expect("KDF admission limits iterations to i32::MAX");
        let mut key = Zeroizing::new([0_u8; 32]);
        let mut iv = Zeroizing::new([0_u8; 16]);
        if let Some(prf) = scheme.prf {
            with_hash!(
                prf,
                D,
                pbkdf2::pbkdf2_hmac::<D>(
                    password.as_bytes(),
                    &salt,
                    scheme.rounds,
                    &mut key[..key_len]
                )
            );
            iv.copy_from_slice(&scheme.iv);
        } else {
            let bmp = legacy_password(&mut self.bmp, password, query, ceilings)?;
            self.charges
                .legacy_workspace(salt.len(), bmp.len(), 64, key_len, query.memory())?;
            let derived = Zeroizing::new(derive_key::<sha1::Sha1>(
                bmp,
                &salt,
                Pkcs12KeyType::EncryptionKey,
                rounds,
                key_len,
            ));
            key[..key_len].copy_from_slice(&derived);
            let derived = Zeroizing::new(derive_key::<sha1::Sha1>(
                bmp,
                &salt,
                Pkcs12KeyType::Iv,
                rounds,
                8,
            ));
            iv[..8].copy_from_slice(&derived);
        }
        drop(salt);
        let mut plain =
            Plaintext::copy_octets(ciphertext, query).map_err(|e| ceilings.refuse(&e))?;
        query
            .charge(ciphertext.len() as u64)
            .map_err(|e| ceilings.refuse(&e))?;
        macro_rules! decrypt {
            ($cipher:ty) => {
                cbc::Decryptor::<$cipher>::new_from_slices(&key[..key_len], &iv[..block])
                    .map_err(|_| KeyStoreError::ProtectedContainer)?
                    .decrypt_padded::<Pkcs7>(plain.as_mut_bytes())
                    .map_err(|_| KeyStoreError::ProtectedContainer)?
                    .len()
            };
        }
        let length = match scheme.cipher {
            Cipher::Aes128 => decrypt!(aes::Aes128Dec),
            Cipher::Aes192 => decrypt!(aes::Aes192Dec),
            Cipher::Aes256 => decrypt!(aes::Aes256Dec),
            Cipher::TripleDes => decrypt!(des::TdesEde3),
            Cipher::DoubleDes => decrypt!(des::TdesEde2),
        };
        plain.truncate(length);
        Ok(plain)
    }
}

/// The RFC 7292 B.1 password form, shared by the legacy MAC and legacy
/// encryption even when another layer of the same PFX uses PBES2.
/// <https://www.rfc-editor.org/rfc/rfc7292#appendix-B.1>
fn legacy_password<'s>(
    slot: &'s mut Option<Plaintext>,
    password: &str,
    query: &Reader<'_>,
    ceilings: Ceilings,
) -> Result<&'s [u8]> {
    if slot.is_none() {
        *slot = Some(personal::legacy_password(password, query).map_err(|e| ceilings.refuse(&e))?);
    }
    Ok(slot.as_ref().map_or(&[][..], Plaintext::as_bytes))
}

impl<S: Secret, F: FnOnce() -> Option<S>> Backend for Adapter<'_, F, S> {
    type Error = KeyStoreError;

    fn authenticate(&mut self, integrity: &Integrity<'_>, query: &Reader<'_>) -> Result<Decision> {
        let Integrity::Password { safe, mac } = integrity else {
            return Ok(Decision::Unsupported);
        };
        // RFC 7292 section 4 makes MacData OPTIONAL; a PFX without it has
        // always been imported, so its absence is accepted here explicitly.
        let Some(mac) = mac else {
            return Ok(Decision::Accept);
        };
        let ceilings = self.charges.ceilings;
        let scheme = mac_scheme(mac, &mut self.charges)?;
        let salt = contiguous(scheme.salt, query, ceilings)?;
        let expected = contiguous(scheme.digest, query, ceilings)?;
        query
            .charge(safe.len() as u64)
            .map_err(|e| ceilings.refuse(&e))?;
        let password = self.password.text(self.charges.limits, ceilings, query)?;
        let bmp = legacy_password(&mut self.bmp, password, query, ceilings)?;
        self.charges.legacy_workspace(
            salt.len(),
            bmp.len(),
            scheme.hash.block(),
            scheme.hash.size(),
            query.memory(),
        )?;
        let rounds =
            i32::try_from(scheme.rounds).expect("KDF admission limits iterations to i32::MAX");
        let key = Zeroizing::new(with_hash!(
            scheme.hash,
            D,
            derive_key::<D>(bmp, &salt, Pkcs12KeyType::Mac, rounds, scheme.hash.size())
        ));
        let verified = with_hash!(scheme.hash, D, {
            let mut mac =
                Hmac::<D>::new_from_slice(&key).map_err(|_| KeyStoreError::ProtectedContainer)?;
            for piece in safe.pieces() {
                mac.update(piece.as_bytes());
            }
            mac.verify_slice(&expected).is_ok()
        });
        Ok(if verified {
            Decision::Accept
        } else {
            Decision::Reject
        })
    }

    fn decrypt_safe(
        &mut self,
        safe: &Safe<'_>,
        query: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext> {
        let Safe::Encrypted(encrypted) = safe else {
            return Err(KeyStoreError::Selection("unsupported PKCS#12 privacy mode"));
        };
        // Decrypting a safe is key-source expansion; its bags count separately.
        self.charges.count()?;
        let ciphertext = encrypted
            .content
            .ciphertext
            .as_ref()
            .ok_or(KeyStoreError::ProtectedContainer)?;
        self.decrypt(
            &encrypted.protection,
            encrypted.content.algorithm,
            ciphertext,
            query,
        )
    }

    fn decrypt_key(
        &mut self,
        key: &ShroudedKey<'_>,
        query: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext> {
        self.decrypt(&key.protection, key.algorithm, &key.encrypted, query)
    }

    fn bag(&mut self, bag: &Bag<'_>, query: &Reader<'_>, _: &Source<'_>) -> Result<()> {
        self.charges.count()?;
        match &bag.value {
            BagValue::Key(key) => self.retain_key(key, query),
            // Refuse a second key before spending its KDF work.
            BagValue::Shrouded(_) => self.one_key(),
            BagValue::Certificate(certificate) => self.retain_certificate(certificate, query),
            BagValue::Contents(_) => Ok(()),
            _ => Err(KeyStoreError::Selection("unsupported PKCS#12 bag type")),
        }
    }

    fn key(&mut self, key: &PrivateKey<'_>, query: &Reader<'_>, _: &Source<'_>) -> Result<()> {
        self.retain_key(key, query)
    }
}

#[cfg(test)]
mod tests;
