//! PKCS#12 import over the shared `structured_cms::personal` container reader
//! and its password engine.
//!
//! The shared reader owns PFX, safe and bag framing and authenticates the whole
//! safe before extraction; its password engine owns the MAC, KDF and cipher
//! work and states what each step costs before the password is needed. This
//! adapter owns the password, the admission of those costs under the compiled
//! resource policy, and the key and certificates it keeps.

use std::sync::Arc;

use structured_asn1::length::DerLength;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, MemoryReservation};
use structured_asn1::{Encoding, Limit, Parser, Reader, Tag};
use structured_cms::Octets;
use structured_cms::personal::password::{
    self as engine, Authentication, Cost, Decryption, KdfCost, Password as Input,
};
use structured_cms::personal::{
    self, Backend, Bag, BagValue, Cause, Decision, Failure, Integrity, Pfx, Plaintext, PrivateKey,
    Safe, ShroudedKey, Source,
};
use zeroize::Zeroizing;

use super::{KeyStoreError, PrivateKeyDer};
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};

type Result<T> = core::result::Result<T, KeyStoreError>;
const FIELD: &str = "PKCS#12 import";

pub(super) struct Limits {
    pub resources: ResourcePolicy,
    pub candidates: usize,
    pub memory_available: usize,
}

pub(super) struct Contents {
    pub private_key: Option<PrivateKeyDer>,
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
        // The password engine charges its own execution work to this session
        // too; the policy's KDF budget is admitted separately, in its own
        // units, from the parameters the engine states.
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
        keep_decrypted: false,
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
pub(super) trait Refusal {
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
pub(super) struct Ceilings {
    pub(super) memory: usize,
    pub(super) work: usize,
}

impl Ceilings {
    pub(super) fn refuse(self, error: &impl Refusal) -> KeyStoreError {
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

    /// A password-engine refusal while it runs. `unsupported` names the step
    /// whose scheme the engine lacks; a failed check is a protected-container
    /// failure.
    pub(super) fn engine(self, error: engine::Error, unsupported: &'static str) -> KeyStoreError {
        match error {
            engine::Error::Encoding(error) => self.refuse(&error),
            engine::Error::Resource(error) => self.memory(error),
            engine::Error::Unsupported => KeyStoreError::Selection(unsupported),
            _ => KeyStoreError::ProtectedContainer,
        }
    }

    /// A refusal while the engine reads a scheme or states its cost: work it
    /// cannot even represent is an iteration count outside the KDF limit
    /// `kdf_maximum`.
    pub(super) fn plan(
        self,
        error: engine::Error,
        unsupported: &'static str,
        kdf_maximum: usize,
    ) -> KeyStoreError {
        match error {
            engine::Error::Resource(MemoryError::WorkExceeded) => {
                PolicyViolation::KdfIterationsOutsideLimit {
                    maximum: kdf_maximum,
                }
                .into()
            }
            error => self.engine(error, unsupported),
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

/// The policy's work for the key derivation `kdf`: hash rounds times output
/// blocks (RFC 8018 5.2, RFC 7292 B.2) or scrypt's N·r·p, with the rounds
/// whose count alone the policy bounds. `None` for a derivation it lacks.
fn kdf_work(kdf: KdfCost) -> Option<(Option<u64>, Option<u32>)> {
    Some(match kdf {
        KdfCost::Pbkdf2 {
            iterations, blocks, ..
        } => (
            u64::from(iterations).checked_mul(blocks as u64),
            Some(iterations),
        ),
        KdfCost::Pkcs12 {
            iterations,
            key_blocks,
            iv_blocks,
            ..
        } => (
            u64::from(iterations).checked_mul((key_blocks + iv_blocks) as u64),
            Some(iterations),
        ),
        KdfCost::Scrypt { n, r, p, .. } => {
            (n.checked_mul(r).and_then(|nr| nr.checked_mul(p)), None)
        }
        _ => return None,
    })
}

/// Hash rounds over the password the policy counts, one per 64 octets for
/// each password-keyed HMAC set-up: once for PBKDF2, before and after `ROMix`
/// for scrypt. RFC 7292 B.2 hashes the password within its counted rounds.
fn password_work(kdf: KdfCost, password: usize) -> usize {
    match kdf {
        KdfCost::Pbkdf2 { .. } => password.div_ceil(64),
        KdfCost::Scrypt { .. } => 2 * password.div_ceil(64),
        _ => 0,
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

    /// Admits `work` more KDF work.
    fn work(&mut self, work: Option<u64>) -> Result<()> {
        let maximum = self.limits.resources.max_key_import_kdf_work;
        let work = work
            .and_then(|work| usize::try_from(work).ok())
            .filter(|work| *work <= maximum - self.work)
            .ok_or_else(|| denial(resource_name::KEY_IMPORT_KDF_WORK, maximum))?;
        self.work += work;
        Ok(())
    }

    /// Admits a step's key derivation `kdf` before the password: its rounds,
    /// its work against the KDF budget, and the engine's `cost` scratch and
    /// output against the KDF memory limit and the bytes `memory` still holds.
    /// A count of rounds over the whole budget is outside the KDF limit.
    fn admit(&mut self, kdf: KdfCost, cost: Cost, memory: &Memory) -> Result<()> {
        let maximum = self.limits.resources.max_key_import_kdf_work;
        let (work, rounds) = kdf_work(kdf).ok_or(KeyStoreError::Selection(
            "unsupported PKCS#12 key derivation",
        ))?;
        if rounds.is_some_and(|rounds| rounds as usize > maximum) {
            return Err(PolicyViolation::KdfIterationsOutsideLimit { maximum }.into());
        }
        self.work(work)?;
        self.live(cost.scratch, cost.output, memory)
    }

    /// Admits the password's hashing and the scratch it adds, `scratch` in
    /// all, after the password is known.
    fn admit_password(
        &mut self,
        kdf: KdfCost,
        password: usize,
        scratch: usize,
        output: usize,
        memory: &Memory,
    ) -> Result<()> {
        self.work(Some(password_work(kdf, password) as u64))?;
        self.live(scratch, output, memory)
    }

    /// Refuses KDF scratch over the KDF memory limit, or scratch and output
    /// over the bytes `memory` still holds.
    fn live(&self, scratch: usize, output: usize, memory: &Memory) -> Result<()> {
        let maximum = self.limits.resources.max_key_import_kdf_memory_bytes;
        if scratch > maximum {
            return Err(denial(resource_name::KEY_IMPORT_KDF_MEMORY, maximum));
        }
        if scratch
            .checked_add(output)
            .is_none_or(|live| live > remaining(memory))
        {
            return Err(denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.ceilings.memory,
            ));
        }
        Ok(())
    }
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

/// Whether the whole original `PrivateKeyInfo` is already DER, so its decrypted
/// buffer can be stored as is. A rule violation means BER, not a refusal.
fn der_conforms(key: &PrivateKey<'_>, query: &Reader<'_>, ceilings: Ceilings) -> Result<bool> {
    let mut reader = key
        .original
        .reader_in(query)
        .map_err(|e| ceilings.refuse(&e))?;
    let element = reader
        .next_element()
        .map_err(|e| ceilings.refuse(&e))?
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let mut strict = match reader.reread(&element, Encoding::Der) {
        Ok(strict) => strict,
        Err(e) if e.is_resource() => return Err(ceilings.refuse(&e)),
        Err(_) => return Ok(false),
    };
    let original = match strict.next_element() {
        Ok(Some(original)) => original,
        Ok(None) => return malformed(),
        Err(e) if e.is_resource() => return Err(ceilings.refuse(&e)),
        Err(_) => return Ok(false),
    };
    match structured_pkix::der::conforms(&strict, &original, FIELD) {
        Ok(()) => Ok(true),
        Err(e) if e.is_resource() => Err(ceilings.refuse(&e)),
        Err(_) => Ok(false),
    }
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

/// The selected container backend: the shared password engine over a caller
/// password. Retained outputs keep their memory reservation until the import
/// returns them.
struct Adapter<'l, F, S> {
    password: Password<F, S>,
    /// RFC 7292 B.1 `BMPString` form, derived on the first use that needs it.
    bmp: Option<Plaintext>,
    charges: Charges<'l>,
    key: Option<PrivateKeyDer>,
    /// The decrypted key inspected by `key` is DER and `retain_key` keeps it.
    keep_decrypted: bool,
    certificates: Vec<Vec<u8>>,
    /// Charges for a rewritten `key` and `certificates`, held until the
    /// import returns; a kept decrypted key carries its own.
    reservations: Vec<MemoryReservation>,
}

/// The password in the form a plan asks for.
macro_rules! input {
    ($adapter:expr, $plan:expr, $query:expr) => {{
        let ceilings = $adapter.charges.ceilings;
        let password = $adapter
            .password
            .text($adapter.charges.limits, ceilings, $query)?;
        if $plan.uses_legacy_password() {
            Input::Legacy(bmp_password(&mut $adapter.bmp, password, $query, ceilings)?)
        } else {
            Input::Octets(password.as_bytes())
        }
    }};
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

    fn rewrite_key(&mut self, key: &PrivateKey<'_>, query: &Reader<'_>) -> Result<()> {
        self.one_key()?;
        let (der, reservation) = private_key_der(key, query, self.charges.ceilings)?;
        self.reservations.push(reservation);
        self.key = Some(PrivateKeyDer::Owned(der));
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
        plan: core::result::Result<Decryption<'_, '_>, engine::Error>,
        query: &Reader<'_>,
    ) -> Result<Plaintext> {
        const UNSUPPORTED: &str = "unsupported PKCS#12 encryption algorithm";
        let ceilings = self.charges.ceilings;
        let kdf = self.charges.limits.resources.max_key_import_kdf_work;
        let plan = plan.map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        // KDF work, scratch and the plaintext are admitted before the password
        // is requested, so a refused step never prompts for one.
        let derivation = plan
            .kdf_cost()
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        let cost = plan
            .cost()
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        self.charges.admit(derivation, cost, query.memory())?;
        let password = input!(self, plan, query);
        let extra = plan
            .password_cost(password)
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        let all = cost.scratch + extra.scratch;
        self.charges.admit_password(
            derivation,
            input_len(password),
            all,
            cost.output,
            query.memory(),
        )?;
        let (mut scratch, _reservation) = scratch(all, query, ceilings)?;
        plan.decrypt_owned(password, &mut scratch, query)
            .map_err(|e| ceilings.engine(e, UNSUPPORTED))
    }
}

/// The octets of a password input.
fn input_len(input: Input<'_>) -> usize {
    match input {
        Input::Octets(bytes) | Input::Legacy(bytes) => bytes.len(),
    }
}

/// A wiping scratch buffer of `size` bytes, charged as live memory while the
/// engine uses it.
fn scratch(
    size: usize,
    query: &Reader<'_>,
    ceilings: Ceilings,
) -> Result<(Zeroizing<Vec<u8>>, MemoryReservation)> {
    let reservation = query
        .memory()
        .reserve(size)
        .map_err(|e| ceilings.memory(e))?;
    Ok((Zeroizing::new(vec![0; size]), reservation))
}

/// The RFC 7292 B.1 password form, shared by every step that uses it even
/// when another layer of the same PFX uses PBES2.
/// <https://www.rfc-editor.org/rfc/rfc7292#appendix-B.1>
fn bmp_password<'s>(
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
        const UNSUPPORTED: &str = "unsupported PKCS#12 MAC algorithm";
        let ceilings = self.charges.ceilings;
        let kdf = self.charges.limits.resources.max_key_import_kdf_work;
        let plan = match Authentication::prepare(integrity, query) {
            // RFC 7292 section 4 makes MacData OPTIONAL; a PFX without it has
            // always been imported, so its absence is accepted here explicitly.
            Ok(None) => return Ok(Decision::Accept),
            Ok(Some(plan)) => plan,
            Err(engine::Error::Unsupported) if !matches!(integrity, Integrity::Password { .. }) => {
                return Ok(Decision::Unsupported);
            }
            Err(error) => return Err(ceilings.plan(error, UNSUPPORTED, kdf)),
        };
        let derivation = plan
            .kdf_cost()
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        let cost = plan
            .cost()
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        self.charges.admit(derivation, cost, query.memory())?;
        let password = input!(self, plan, query);
        let extra = plan
            .password_cost(password)
            .map_err(|e| ceilings.plan(e, UNSUPPORTED, kdf))?;
        let all = cost.scratch + extra.scratch;
        self.charges.admit_password(
            derivation,
            input_len(password),
            all,
            cost.output,
            query.memory(),
        )?;
        let (mut scratch, _reservation) = scratch(all, query, ceilings)?;
        match plan.verify(password, &mut scratch, query) {
            Ok(()) => Ok(Decision::Accept),
            Err(engine::Error::Rejected) => Ok(Decision::Reject),
            Err(error) => Err(ceilings.engine(error, UNSUPPORTED)),
        }
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
        self.decrypt(Decryption::safe(encrypted, query), query)
    }

    fn decrypt_key(
        &mut self,
        key: &ShroudedKey<'_>,
        query: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext> {
        self.decrypt(Decryption::key(key, query), query)
    }

    fn bag(&mut self, bag: &Bag<'_>, query: &Reader<'_>, _: &Source<'_>) -> Result<()> {
        self.charges.count()?;
        match &bag.value {
            // A clear key borrows the input, so it is copied once either way.
            BagValue::Key(key) => self.rewrite_key(key, query),
            // Refuse a second key before spending its KDF work.
            BagValue::Shrouded(_) => self.one_key(),
            BagValue::Certificate(certificate) => self.retain_certificate(certificate, query),
            BagValue::Contents(_) => Ok(()),
            _ => Err(KeyStoreError::Selection("unsupported PKCS#12 bag type")),
        }
    }

    fn key(&mut self, key: &PrivateKey<'_>, query: &Reader<'_>, _: &Source<'_>) -> Result<()> {
        self.one_key()?;
        if der_conforms(key, query, self.charges.ceilings)? {
            self.keep_decrypted = true;
            Ok(())
        } else {
            self.rewrite_key(key, query)
        }
    }

    fn retain_key(&mut self, plaintext: Plaintext) -> Result<()> {
        use der::Decode as _;
        if !core::mem::take(&mut self.keep_decrypted) {
            // The BER original was rewritten; its buffer is released here.
            return Ok(());
        }
        pkcs8::PrivateKeyInfoRef::from_der(plaintext.as_bytes())
            .map_err(|_| KeyStoreError::ProtectedContainer)?;
        self.key = Some(PrivateKeyDer::Retained(plaintext));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
