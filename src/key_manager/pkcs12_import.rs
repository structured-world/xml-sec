//! Borrowed BER import orchestration; RustCrypto supplies cryptographic primitives.

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use core::ops::Deref;
use der::asn1::ObjectIdentifier as Oid;
use hmac::{Hmac, KeyInit as _, Mac as _};
use pkcs12::kdf::{Pkcs12KeyType, derive_key};
use zeroize::Zeroizing;

use super::KeyStoreError;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};

type Result<T> = core::result::Result<T, KeyStoreError>;
const DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");
const PBKDF2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.12");

pub(super) struct Limits {
    pub resources: ResourcePolicy,
    pub candidates: usize,
    pub memory_available: usize,
}

pub(super) struct Contents {
    pub private_keys: Vec<Zeroizing<Vec<u8>>>,
    pub certificates: Vec<Vec<u8>>,
}

struct Budget<'a> {
    limits: &'a Limits,
    work: usize,
    memory: usize,
    candidates: usize,
}

fn denial(resource: &'static str, maximum: usize) -> KeyStoreError {
    PolicyViolation::ResourceLimitExceeded { resource, maximum }.into()
}

fn malformed<T>() -> Result<T> {
    Err(KeyStoreError::ProtectedContainer)
}

impl<'a> Budget<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            work: 0,
            memory: 0,
            candidates: 0,
        }
    }

    fn check_allocation(&self, size: usize) -> Result<()> {
        let maximum = self.limits.resources.max_external_resource_total_bytes;
        if size > self.limits.memory_available - self.memory {
            return Err(denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                maximum,
            ));
        }
        Ok(())
    }

    fn allocate(&mut self, size: usize) -> Result<()> {
        self.check_allocation(size)?;
        self.memory += size;
        Ok(())
    }

    fn copy(&mut self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.allocate(bytes.len())?;
        Ok(Zeroizing::new(bytes.to_vec()))
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

    fn kdf(&mut self, rounds: u32, blocks: usize, salt: &[u8]) -> Result<()> {
        let maximum = self.limits.resources.max_key_import_kdf_work;
        if rounds == 0 || u64::from(rounds) > maximum as u64 || rounds > i32::MAX as u32 {
            return Err(PolicyViolation::KdfIterationsOutsideLimit { maximum }.into());
        }
        let salt_maximum = self.limits.resources.max_external_resource_bytes;
        if salt.len() > salt_maximum {
            return Err(denial("PKCS#12 salt bytes", salt_maximum));
        }
        let work = (rounds as usize)
            .checked_mul(blocks)
            .ok_or_else(|| denial(resource_name::KEY_IMPORT_KDF_WORK, maximum))?;
        if work > maximum - self.work {
            return Err(denial(resource_name::KEY_IMPORT_KDF_WORK, maximum));
        }
        self.work += work;
        Ok(())
    }

    fn legacy_workspace(
        &self,
        salt: &[u8],
        password: &[u8],
        block: usize,
        output: usize,
    ) -> Result<()> {
        // RFC 7292 B.2 rounds salt and password up to digest blocks. Account
        // for the KDF's I, diversifier and output before RustCrypto allocates.
        // https://www.rfc-editor.org/rfc/rfc7292#appendix-B.2
        let size = salt
            .len()
            .div_ceil(block)
            .checked_add(password.len().div_ceil(block))
            .and_then(|n| n.checked_mul(block))
            .and_then(|n| n.checked_add(block + output))
            .ok_or_else(|| {
                denial(
                    resource_name::KEY_IMPORT_KDF_MEMORY,
                    self.limits.resources.max_key_import_kdf_memory_bytes,
                )
            })?;
        if size > self.limits.resources.max_key_import_kdf_memory_bytes {
            return Err(denial(
                resource_name::KEY_IMPORT_KDF_MEMORY,
                self.limits.resources.max_key_import_kdf_memory_bytes,
            ));
        }
        if size > self.limits.memory_available - self.memory {
            return Err(denial(
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.limits.resources.max_external_resource_total_bytes,
            ));
        }
        Ok(())
    }
}

/// A TLV view never creates an ASN.1 object tree. Indefinite BER is accepted
/// as required by RFC 7292 4.1; recursion has an absolute stack-safety ceiling.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn tlv(bytes: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8])> {
    if depth >= crate::hard_limits::PKCS12_NESTING_CEILING || bytes.len() < 2 {
        return malformed();
    }
    let tag = bytes[0];
    if tag == 0 {
        return malformed();
    }
    let mut identifier_end = 1;
    if tag & 0x1f == 0x1f {
        // X.690 (2021) 8.1.2.4: high tags use nonzero base-128 groups.
        // Unknown attribute tags need framing, not an integer materialization;
        // scanning borrowed octets also accepts numbers wider than usize.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        let first = bytes[identifier_end];
        if first & 0x7f == 0 || first < 31 {
            return malformed();
        }
        loop {
            let byte = *bytes
                .get(identifier_end)
                .ok_or(KeyStoreError::ProtectedContainer)?;
            identifier_end += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let length_octet = *bytes
        .get(identifier_end)
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let mut start = identifier_end + 1;
    let end;
    let consumed;
    if length_octet == 0x80 {
        if tag & 0x20 == 0 {
            return malformed();
        }
        let mut remaining = &bytes[start..];
        loop {
            if remaining.starts_with(&[0, 0]) {
                end = bytes.len() - remaining.len();
                consumed = end + 2;
                break;
            }
            remaining = tlv(remaining, depth + 1)?.1;
        }
    } else {
        let mut length = usize::from(length_octet);
        if length & 0x80 != 0 {
            let count = length & 0x7f;
            if count == 0 || count > core::mem::size_of::<usize>() || count > bytes.len() - start {
                return malformed();
            }
            length = 0;
            for byte in &bytes[start..start + count] {
                length = length
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(usize::from(*byte)))
                    .ok_or(KeyStoreError::ProtectedContainer)?;
            }
            start += count;
        }
        if length > bytes.len() - start {
            return malformed();
        }
        end = start + length;
        consumed = end;
    }
    Ok((
        Tlv {
            tag,
            value: &bytes[start..end],
        },
        &bytes[consumed..],
    ))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, tag: u8) -> Result<Tlv<'a>> {
        let (value, rest) = tlv(self.0, 0)?;
        if value.tag != tag {
            return malformed();
        }
        self.0 = rest;
        Ok(value)
    }
    fn sequence(bytes: &'a [u8]) -> Result<Self> {
        let mut outer = Self(bytes);
        let sequence = outer.take(0x30)?;
        outer.finish()?;
        Ok(Self(sequence.value))
    }
    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            malformed()
        }
    }
    fn oid(&mut self) -> Result<Oid> {
        Oid::from_bytes(self.take(6)?.value).map_err(|_| KeyStoreError::ProtectedContainer)
    }
    fn nonnegative_integer(&mut self) -> Result<&'a [u8]> {
        let bytes = self.take(2)?.value;
        // X.690 8.3.2 forbids redundant sign octets in BER INTEGER too,
        // not only DER; all these fields require nonnegative values.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        if bytes.is_empty()
            || bytes[0] & 0x80 != 0
            || (bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0)
        {
            return malformed();
        }
        Ok(bytes)
    }
    fn integer(&mut self) -> Result<u32> {
        let bytes = self.nonnegative_integer()?;
        bytes
            .iter()
            .try_fold(0_u32, |n, b| {
                n.checked_mul(256)
                    .and_then(|n| n.checked_add(u32::from(*b)))
            })
            .ok_or(KeyStoreError::ProtectedContainer)
    }
    fn kdf_iterations(&mut self, budget: &Budget<'_>) -> Result<u32> {
        let bytes = self.nonnegative_integer()?;
        let significant = if bytes[0] == 0 { &bytes[1..] } else { bytes };
        let maximum = budget.limits.resources.max_key_import_kdf_work;
        // RFC 7292 section 4 uses BER INTEGERs, not machine-width counters.
        // A canonical positive value beyond the application's work ceiling
        // is a policy denial; malformed sign encoding remains a format error.
        // https://www.rfc-editor.org/rfc/rfc7292#section-4
        if significant.len() > 4 {
            return Err(PolicyViolation::KdfIterationsOutsideLimit { maximum }.into());
        }
        let mut rounds = 0_u32;
        for byte in significant {
            rounds = rounds * 256 + u32::from(*byte);
        }
        if rounds == 0 || u64::from(rounds) > maximum as u64 || rounds > i32::MAX as u32 {
            return Err(PolicyViolation::KdfIterationsOutsideLimit { maximum }.into());
        }
        Ok(rounds)
    }
    fn null_or_absent(&mut self) -> Result<()> {
        if !self.0.is_empty() && !self.take(5)?.value.is_empty() {
            return malformed();
        }
        Self(self.0).finish()
    }
}

enum Bytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Zeroizing<Vec<u8>>),
}
impl Deref for Bytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(v) => v,
            Self::Owned(v) => v,
        }
    }
}
impl Bytes<'_> {
    fn owned_capacity(&self) -> usize {
        match self {
            Self::Borrowed(_) => 0,
            Self::Owned(v) => v.capacity(),
        }
    }
    fn release(&self, budget: &mut Budget<'_>) {
        if let Self::Owned(v) = self {
            budget.memory -= v.capacity();
        }
    }
}

fn octet_visit<F>(value: Tlv<'_>, primitive: u8, depth: usize, visit: &mut F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    if depth >= crate::hard_limits::PKCS12_NESTING_CEILING {
        return malformed();
    }
    if value.tag == primitive {
        return visit(value.value);
    }
    if value.tag != primitive | 0x20 {
        return malformed();
    }
    let mut children = value.value;
    while !children.is_empty() {
        let (child, rest) = tlv(children, depth)?;
        // Constructed implicit [0] OCTET STRING has universal OCTET children.
        octet_visit(child, 4, depth + 1, visit)?;
        children = rest;
    }
    Ok(())
}

fn octets<'a>(value: Tlv<'a>, primitive: u8, budget: &mut Budget<'_>) -> Result<Bytes<'a>> {
    if value.tag == primitive {
        return Ok(Bytes::Borrowed(value.value));
    }
    let mut size = 0_usize;
    octet_visit(value, primitive, 0, &mut |bytes| {
        size = size
            .checked_add(bytes.len())
            .ok_or(KeyStoreError::ProtectedContainer)?;
        Ok(())
    })?;
    budget.allocate(size)?;
    let mut output = Zeroizing::new(Vec::with_capacity(size));
    octet_visit(value, primitive, 0, &mut |bytes| {
        output.extend_from_slice(bytes);
        Ok(())
    })?;
    Ok(Bytes::Owned(output))
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
    fn from_oid(oid: Oid, hmac: bool) -> Result<Self> {
        let choices = if hmac {
            [
                "1.2.840.113549.2.7",
                "1.2.840.113549.2.8",
                "1.2.840.113549.2.9",
                "1.2.840.113549.2.10",
                "1.2.840.113549.2.11",
            ]
        } else {
            [
                "1.3.14.3.2.26",
                "2.16.840.1.101.3.4.2.4",
                "2.16.840.1.101.3.4.2.1",
                "2.16.840.1.101.3.4.2.2",
                "2.16.840.1.101.3.4.2.3",
            ]
        };
        for (text, hash) in choices.into_iter().zip([
            Self::Sha1,
            Self::Sha224,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
        ]) {
            if oid == Oid::new_unwrap(text) {
                return Ok(hash);
            }
        }
        Err(KeyStoreError::Selection(if hmac {
            "unsupported PKCS#12 PRF algorithm"
        } else {
            "unsupported PKCS#12 digest algorithm"
        }))
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

struct Mac<'a> {
    hash: Hash,
    digest: Bytes<'a>,
    salt: Bytes<'a>,
    rounds: u32,
}
impl<'a> Mac<'a> {
    fn parse(encoded: Tlv<'a>, budget: &mut Budget<'_>) -> Result<Self> {
        let mut mac = Reader(encoded.value);
        let mut digest_info = Reader(mac.take(0x30)?.value);
        let mut algorithm = Reader(digest_info.take(0x30)?.value);
        let hash = Hash::from_oid(algorithm.oid()?, false)?;
        algorithm.null_or_absent()?;
        let (value, rest) = tlv(digest_info.0, 0)?;
        let digest = octets(value, 4, budget)?;
        digest_info.0 = rest;
        digest_info.finish()?;
        if digest.len() != hash.size() {
            return malformed();
        }
        let (salt_tlv, rest) = tlv(mac.0, 0)?;
        let salt = octets(salt_tlv, 4, budget)?;
        mac.0 = rest;
        let rounds = if mac.0.is_empty() {
            1
        } else {
            mac.kdf_iterations(budget)?
        };
        mac.finish()?;
        budget.kdf(rounds, 1, &salt)?;
        Ok(Self {
            hash,
            digest,
            salt,
            rounds,
        })
    }
    fn verify(&self, bytes: &[u8], password: &[u8], budget: &Budget<'_>) -> Result<()> {
        budget.legacy_workspace(&self.salt, password, self.hash.block(), self.hash.size())?;
        let key = Zeroizing::new(with_hash!(
            self.hash,
            D,
            derive_key::<D>(
                password,
                &self.salt,
                Pkcs12KeyType::Mac,
                self.rounds as i32,
                self.hash.size()
            )
        ));
        with_hash!(self.hash, D, {
            let mut mac =
                Hmac::<D>::new_from_slice(&key).map_err(|_| KeyStoreError::ProtectedContainer)?;
            mac.update(bytes);
            mac.verify_slice(&self.digest)
                .map_err(|_| KeyStoreError::ProtectedContainer)
        })
    }
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

struct Encryption<'a> {
    cipher: Cipher,
    salt: Bytes<'a>,
    rounds: u32,
    hash: Option<Hash>,
    iv: [u8; 16],
}
impl<'a> Encryption<'a> {
    fn parse(encoded: Tlv<'a>, budget: &mut Budget<'_>) -> Result<Self> {
        let mut algorithm = Reader(encoded.value);
        let oid = algorithm.oid()?;
        let mut params = Reader(algorithm.take(0x30)?.value);
        algorithm.finish()?;
        let (cipher, salt, rounds, hash, iv);
        if oid == PBES2 {
            let mut kdf = Reader(params.take(0x30)?.value);
            if kdf.oid()? != PBKDF2 {
                return Err(KeyStoreError::Selection(
                    "unsupported PKCS#12 PBES2 KDF algorithm",
                ));
            }
            let mut derivation = Reader(kdf.take(0x30)?.value);
            kdf.finish()?;
            let (value, rest) = tlv(derivation.0, 0)?;
            salt = octets(value, 4, budget)?;
            derivation.0 = rest;
            rounds = derivation.kdf_iterations(budget)?;
            let length = if derivation.0.first() == Some(&2) {
                Some(derivation.integer()?)
            } else {
                None
            };
            let mut prf = Hash::Sha1;
            if !derivation.0.is_empty() {
                let mut algorithm = Reader(derivation.take(0x30)?.value);
                prf = Hash::from_oid(algorithm.oid()?, true)?;
                algorithm.null_or_absent()?;
            }
            derivation.finish()?;
            let mut scheme = Reader(params.take(0x30)?.value);
            let oid = scheme.oid()?;
            cipher = if oid == pkcs8::pkcs5::pbes2::AES_128_CBC_OID {
                Cipher::Aes128
            } else if oid == pkcs8::pkcs5::pbes2::AES_192_CBC_OID {
                Cipher::Aes192
            } else if oid == pkcs8::pkcs5::pbes2::AES_256_CBC_OID {
                Cipher::Aes256
            } else {
                return Err(KeyStoreError::Selection(
                    "unsupported PKCS#12 PBES2 encryption scheme",
                ));
            };
            let (value, rest) = tlv(scheme.0, 0)?;
            // RFC 7292 section 4 requires BER, whose OCTET STRINGs may be
            // constructed (X.690 8.7.1, 8.7.3). AES IVs are exactly 16 bytes;
            // stream segments into fixed cipher state rather than flattening
            // attacker-controlled segmentation into a temporary heap buffer.
            // https://www.itu.int/rec/T-REC-X.690-202102-I/en
            let mut decoded_iv = [0; 16];
            let mut length_so_far = 0;
            octet_visit(value, 4, 0, &mut |segment| {
                if segment.len() > decoded_iv.len() - length_so_far {
                    return malformed();
                }
                decoded_iv[length_so_far..length_so_far + segment.len()].copy_from_slice(segment);
                length_so_far += segment.len();
                Ok(())
            })?;
            if length_so_far != decoded_iv.len() {
                return malformed();
            }
            iv = decoded_iv;
            scheme.0 = rest;
            scheme.finish()?;
            if length.is_some_and(|length| length as usize != cipher.key_len()) {
                return malformed();
            }
            hash = Some(prf);
            budget.kdf(rounds, cipher.key_len().div_ceil(prf.size()), &salt)?;
        } else {
            cipher = if oid == pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC {
                Cipher::TripleDes
            } else if oid == pkcs12::PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC {
                Cipher::DoubleDes
            } else {
                return Err(KeyStoreError::Selection(
                    "unsupported PKCS#12 encryption algorithm",
                ));
            };
            let (value, rest) = tlv(params.0, 0)?;
            salt = octets(value, 4, budget)?;
            params.0 = rest;
            rounds = params.kdf_iterations(budget)?;
            hash = None;
            iv = [0; 16];
            // Appendix B.2 derives key and IV separately; 24-byte SHA-1
            // keys need two digest blocks, not one iteration charge.
            budget.kdf(rounds, cipher.key_len().div_ceil(20) + 1, &salt)?;
        }
        params.finish()?;
        Ok(Self {
            cipher,
            salt,
            rounds,
            hash,
            iv,
        })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        password: &mut Password<'_>,
        budget: &mut Budget<'_>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(self.cipher.block()) {
            return malformed();
        }
        // Preflight output before KDF work; allocate/charge it only when live,
        // rather than invent overlap with the legacy KDF's temporary workspace.
        budget.check_allocation(ciphertext.len())?;
        let mut key = Zeroizing::new([0_u8; 32]);
        let mut iv = Zeroizing::new([0_u8; 16]);
        if let Some(hash) = self.hash {
            // Product work accounting matches PKCS#8: charge password-keyed
            // HMAC preprocessing for each derivation, including hidden bags.
            let work = password.utf8.len().div_ceil(64);
            let maximum = budget.limits.resources.max_key_import_kdf_work;
            if work > maximum - budget.work {
                return Err(denial(resource_name::KEY_IMPORT_KDF_WORK, maximum));
            }
            budget.work += work;
            with_hash!(
                hash,
                D,
                pbkdf2::pbkdf2_hmac::<D>(
                    password.utf8.as_bytes(),
                    &self.salt,
                    self.rounds,
                    &mut key[..self.cipher.key_len()]
                )
            );
            iv.copy_from_slice(&self.iv);
        } else {
            let bmp = password.bmp(budget)?;
            budget.check_allocation(ciphertext.len())?;
            budget.legacy_workspace(&self.salt, bmp, 64, self.cipher.key_len())?;
            let derived = Zeroizing::new(derive_key::<sha1::Sha1>(
                bmp,
                &self.salt,
                Pkcs12KeyType::EncryptionKey,
                self.rounds as i32,
                self.cipher.key_len(),
            ));
            key[..derived.len()].copy_from_slice(&derived);
            drop(derived);
            let derived = Zeroizing::new(derive_key::<sha1::Sha1>(
                bmp,
                &self.salt,
                Pkcs12KeyType::Iv,
                self.rounds as i32,
                8,
            ));
            iv[..8].copy_from_slice(&derived);
            drop(derived);
        }
        let mut plaintext = budget.copy(ciphertext)?;
        macro_rules! decrypt {
            ($cipher:ty) => {
                cbc::Decryptor::<$cipher>::new_from_slices(
                    &key[..self.cipher.key_len()],
                    &iv[..self.cipher.block()],
                )
                .map_err(|_| KeyStoreError::ProtectedContainer)?
                .decrypt_padded::<Pkcs7>(&mut plaintext)
                .map_err(|_| KeyStoreError::ProtectedContainer)?
                .len()
            };
        }
        let length = match self.cipher {
            Cipher::Aes128 => decrypt!(aes::Aes128Dec),
            Cipher::Aes192 => decrypt!(aes::Aes192Dec),
            Cipher::Aes256 => decrypt!(aes::Aes256Dec),
            Cipher::TripleDes => decrypt!(des::TdesEde3),
            Cipher::DoubleDes => decrypt!(des::TdesEde2),
        };
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

fn content_info<'a>(encoded: Tlv<'a>) -> Result<(Oid, Tlv<'a>)> {
    let mut info = Reader(encoded.value);
    let oid = info.oid()?;
    let explicit = info.take(0xa0)?;
    info.finish()?;
    let (content, rest) = tlv(explicit.value, 0)?;
    Reader(rest).finish()?;
    Ok((oid, content))
}

fn encrypted_content<'a>(
    encoded: Tlv<'a>,
    budget: &mut Budget<'_>,
) -> Result<(Encryption<'a>, Bytes<'a>)> {
    if encoded.tag != 0x30 {
        return malformed();
    }
    let mut data = Reader(encoded.value);
    let version = data.integer()?;
    let mut info = Reader(data.take(0x30)?.value);
    let attributes_present = !data.0.is_empty();
    if attributes_present {
        let attributes = data.take(0xa1)?;
        // UnprotectedAttributes is SET SIZE (1..MAX) OF Attribute (6.1).
        // https://www.rfc-editor.org/rfc/rfc5652#section-6.1
        if attributes.value.is_empty() {
            return malformed();
        }
        validate_attributes(Reader(attributes.value))?;
    }
    data.finish()?;
    // RFC 5652 8: version is 2 with unprotectedAttrs, otherwise 0.
    // Unknown metadata does not affect key selection, but must be well framed.
    // https://www.rfc-editor.org/rfc/rfc5652#section-8
    if version != if attributes_present { 2 } else { 0 } {
        return malformed();
    }
    if info.oid()? != DATA {
        return malformed();
    }
    let encryption = Encryption::parse(info.take(0x30)?, budget)?;
    let (value, rest) = tlv(info.0, 0)?;
    Reader(rest).finish()?;
    Ok((encryption, octets(value, 0x80, budget)?))
}

struct Password<'a> {
    utf8: &'a str,
    bmp: Option<Zeroizing<Vec<u8>>>,
}

impl Password<'_> {
    fn bmp(&mut self, budget: &mut Budget<'_>) -> Result<&[u8]> {
        if self.bmp.is_none() {
            // RFC 7292 B.1 requires BMPString for both the legacy encryption
            // KDF and the legacy MAC, even when encryption itself is PBES2.
            // BMPString is not UTF-16: supplementary characters cannot be
            // represented by surrogate pairs. PBES2-only (no legacy MAC/KDF)
            // uses UTF-8 directly; RFC 9879 section 6 distinguishes PBMAC1.
            // https://www.rfc-editor.org/rfc/rfc7292#appendix-B.1
            // https://www.rfc-editor.org/rfc/rfc9879#section-6
            let mut units = 1_usize;
            for ch in self.utf8.chars() {
                if u32::from(ch) > u16::MAX as u32 {
                    return malformed();
                }
                units = units
                    .checked_add(1)
                    .ok_or(KeyStoreError::ProtectedContainer)?;
            }
            let size = units
                .checked_mul(2)
                .ok_or(KeyStoreError::ProtectedContainer)?;
            budget.allocate(size)?;
            let mut bmp = Zeroizing::new(Vec::with_capacity(size));
            for ch in self.utf8.chars() {
                bmp.extend_from_slice(&(u32::from(ch) as u16).to_be_bytes());
            }
            bmp.extend_from_slice(&[0, 0]);
            self.bmp = Some(bmp);
        }
        self.bmp
            .as_deref()
            .map(|bytes| bytes.as_slice())
            .ok_or(KeyStoreError::ProtectedContainer)
    }
}

fn validate_attribute_values(mut bytes: &[u8], depth: usize) -> Result<()> {
    if depth >= crate::hard_limits::PKCS12_NESTING_CEILING {
        return malformed();
    }
    while !bytes.is_empty() {
        let (value, rest) = tlv(bytes, depth)?;
        if value.tag & 0x20 != 0 {
            validate_attribute_values(value.value, depth + 1)?;
        }
        bytes = rest;
    }
    Ok(())
}

fn validate_attributes(mut attributes: Reader<'_>) -> Result<()> {
    // RFC 7292 4.2 and RFC 5652 5.3 define attributes as an OID and
    // a SET OF values, with no generic minimum number of values. The
    // SIZE (1..MAX) constraint in CMS 6.1 is on UnprotectedAttributes,
    // not attrValues: do not reject an empty SET for an unknown attribute.
    // Ignoring its meaning does not waive framing; validate borrowed bytes.
    // https://www.rfc-editor.org/rfc/rfc7292#section-4.2
    // https://www.rfc-editor.org/rfc/rfc5652#section-5.3
    while !attributes.0.is_empty() {
        let mut attribute = Reader(attributes.take(0x30)?.value);
        attribute.oid()?;
        validate_attribute_values(attribute.take(0x31)?.value, 0)?;
        attribute.finish()?;
    }
    Ok(())
}

fn der_header_length(length: usize) -> usize {
    if length < 128 {
        2
    } else {
        2 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

fn append_der_header(output: &mut Vec<u8>, tag: u8, length: usize) {
    output.push(tag);
    if length < 128 {
        output.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        output.push(0x80 | (bytes.len() - first) as u8);
        output.extend_from_slice(&bytes[first..]);
    }
}

// AlgorithmIdentifier parameters used by supported keys are primitive values
// or a SEQUENCE of integers (DSA). Normalize framing without a heap object tree.
fn parameter_length(value: Tlv<'_>, depth: usize) -> Result<usize> {
    let length = parameter_body_length(value, depth)?;
    length
        .checked_add(der_header_length(length))
        .ok_or(KeyStoreError::ProtectedContainer)
}

fn parameter_body_length(value: Tlv<'_>, depth: usize) -> Result<usize> {
    if depth >= crate::hard_limits::PKCS12_NESTING_CEILING || value.tag & 0x1f == 0x1f {
        return malformed();
    }
    let mut length = value.value.len();
    if value.tag & 0x20 != 0 {
        if value.tag != 0x30 {
            return malformed();
        }
        length = 0;
        let mut children = value.value;
        while !children.is_empty() {
            let (child, rest) = tlv(children, depth + 1)?;
            length = length
                .checked_add(parameter_length(child, depth + 1)?)
                .ok_or(KeyStoreError::ProtectedContainer)?;
            children = rest;
        }
    }
    Ok(length)
}

fn append_parameter(output: &mut Vec<u8>, value: Tlv<'_>, depth: usize) -> Result<()> {
    let body = parameter_body_length(value, depth)?;
    append_der_header(output, value.tag, body);
    if value.tag == 0x30 {
        let mut children = value.value;
        while !children.is_empty() {
            let (child, rest) = tlv(children, depth + 1)?;
            append_parameter(output, child, depth + 1)?;
            children = rest;
        }
    } else {
        output.extend_from_slice(value.value);
    }
    Ok(())
}

fn normalize_private_key(bytes: &[u8], budget: &mut Budget<'_>) -> Result<Zeroizing<Vec<u8>>> {
    use der::Decode as _;
    if pkcs8::PrivateKeyInfoRef::from_der(bytes).is_ok() {
        return budget.copy(bytes);
    }
    // RFC 7292 4/4.2.1 permits BER KeyBag PrivateKeyInfo. Rebuild its
    // framing and flatten OCTET STRING fragments before DER-only decoding.
    // Attributes are ignored by the key decoder, but validated before discard.
    // https://www.rfc-editor.org/rfc/rfc7292#section-4.2.1
    let mut key = Reader::sequence(bytes)?;
    let version = key.integer()?;
    if version > 1 {
        return malformed();
    }
    let algorithm = key.take(0x30)?;
    let (secret, rest) = tlv(key.0, 0)?;
    key.0 = rest;
    let mut secret_length = 0usize;
    octet_visit(secret, 4, 0, &mut |part| {
        secret_length = secret_length
            .checked_add(part.len())
            .ok_or(KeyStoreError::ProtectedContainer)?;
        Ok(())
    })?;
    if key.0.first() == Some(&0xa0) {
        validate_attributes(Reader(key.take(0xa0)?.value))?;
    }
    let public = if !key.0.is_empty() {
        Some(key.take(0x81)?)
    } else {
        None
    };
    key.finish()?;
    if (version == 1) != public.is_some() {
        return malformed();
    }
    let public_length = public.map_or(0, |value| {
        value.value.len() + der_header_length(value.value.len())
    });
    let body_length = 3usize
        .checked_add(parameter_length(algorithm, 0)?)
        .and_then(|length| length.checked_add(secret_length))
        .and_then(|length| length.checked_add(der_header_length(secret_length)))
        .and_then(|length| length.checked_add(public_length))
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let length = body_length
        .checked_add(der_header_length(body_length))
        .ok_or(KeyStoreError::ProtectedContainer)?;
    budget.allocate(length)?;
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    append_der_header(&mut output, 0x30, body_length);
    output.extend_from_slice(&[2, 1, version as u8]);
    append_parameter(&mut output, algorithm, 0)?;
    append_der_header(&mut output, 4, secret_length);
    octet_visit(secret, 4, 0, &mut |part| {
        output.extend_from_slice(part);
        Ok(())
    })?;
    if let Some(public) = public {
        append_der_header(&mut output, 0x81, public.value.len());
        output.extend_from_slice(public.value);
    }
    pkcs8::PrivateKeyInfoRef::from_der(&output).map_err(|_| KeyStoreError::ProtectedContainer)?;
    Ok(output)
}

fn safe_contents(
    bytes: &[u8],
    budget: &mut Budget<'_>,
    mut password: Option<&mut Password<'_>>,
    contents: &mut Contents,
    depth: usize,
) -> Result<()> {
    if depth >= crate::hard_limits::PKCS12_NESTING_CEILING {
        return malformed();
    }
    let mut safe = Reader::sequence(bytes)?;
    while !safe.0.is_empty() {
        budget.count()?;
        let mut bag = Reader(safe.take(0x30)?.value);
        let oid = bag.oid()?;
        let value = bag.take(0xa0)?.value;
        if !bag.0.is_empty() {
            validate_attributes(Reader(bag.take(0x31)?.value))?;
        }
        bag.finish()?;
        if oid == pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID {
            safe_contents(value, budget, password.as_deref_mut(), contents, depth + 1)?;
        } else if oid == pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
            let mut key = Reader::sequence(value)?;
            let encryption = Encryption::parse(key.take(0x30)?, budget)?;
            let (encrypted, rest) = tlv(key.0, 0)?;
            Reader(rest).finish()?;
            let encrypted = octets(encrypted, 4, budget)?;
            if let Some(password) = password.as_deref_mut() {
                if !contents.private_keys.is_empty() {
                    return Err(KeyStoreError::Selection(
                        "PKCS#12 bundle must contain exactly one private key",
                    ));
                }
                budget.allocate(core::mem::size_of::<Zeroizing<Vec<u8>>>())?;
                contents.private_keys.reserve_exact(1);
                let plaintext = encryption.decrypt(&encrypted, password, budget)?;
                use der::Decode as _;
                let private_key = if pkcs8::PrivateKeyInfoRef::from_der(&plaintext).is_ok() {
                    plaintext
                } else {
                    let normalized = normalize_private_key(&plaintext, budget)?;
                    budget.memory -= plaintext.capacity();
                    normalized
                };
                contents.private_keys.push(private_key);
            }
            encrypted.release(budget);
            encryption.salt.release(budget);
        } else if oid == pkcs12::PKCS_12_KEY_BAG_OID {
            if password.is_some() {
                if !contents.private_keys.is_empty() {
                    return Err(KeyStoreError::Selection(
                        "PKCS#12 bundle must contain exactly one private key",
                    ));
                }
                budget.allocate(core::mem::size_of::<Zeroizing<Vec<u8>>>())?;
                contents.private_keys.reserve_exact(1);
                contents
                    .private_keys
                    .push(normalize_private_key(value, budget)?);
            }
        } else if oid == pkcs12::PKCS_12_CERT_BAG_OID {
            let mut cert = Reader::sequence(value)?;
            if cert.oid()? != pkcs12::PKCS_12_X509_CERT_OID {
                return malformed();
            }
            let explicit = cert.take(0xa0)?;
            cert.finish()?;
            let (value, rest) = tlv(explicit.value, 0)?;
            Reader(rest).finish()?;
            let certificate = octets(value, 4, budget)?;
            if password.is_some() {
                if contents.certificates.capacity() == 0 {
                    // Reserve the bounded bag allowance only when a certificate
                    // actually exists, avoiding speculative allocation for
                    // key-only containers and growth during hidden-bag traversal.
                    budget.allocate(budget.limits.candidates * core::mem::size_of::<Vec<u8>>())?;
                    contents
                        .certificates
                        .reserve_exact(budget.limits.candidates);
                }
                // Retained public certificate is independent of temporary decrypted bags.
                budget.allocate(certificate.len())?;
                contents.certificates.push(certificate.to_vec());
            }
            certificate.release(budget);
        } else {
            return Err(KeyStoreError::Selection("unsupported PKCS#12 bag type"));
        }
    }
    Ok(())
}

fn walk_safe(
    bytes: &[u8],
    budget: &mut Budget<'_>,
    mut password: Option<&mut Password<'_>>,
    contents: &mut Contents,
) -> Result<()> {
    let mut safe = Reader::sequence(bytes)?;
    while !safe.0.is_empty() {
        budget.count()?;
        let (oid, content) = content_info(safe.take(0x30)?)?;
        if oid == DATA {
            let data = octets(content, 4, budget)?;
            safe_contents(&data, budget, password.as_deref_mut(), contents, 0)?;
            data.release(budget);
        } else if oid == ENCRYPTED_DATA {
            let (encryption, encrypted) = encrypted_content(content, budget)?;
            if let Some(password) = password.as_deref_mut() {
                let data = encryption.decrypt(&encrypted, password, budget)?;
                // RFC 7292 4.1/4.2.2 allows shrouded bags inside encrypted
                // SafeContents. Their parameters cannot be known before the
                // password; the shared budget checks them before their KDF.
                // https://www.rfc-editor.org/rfc/rfc7292#section-4.1
                safe_contents(&data, budget, Some(password), contents, 0)?;
                budget.memory -= data.capacity();
            }
            encrypted.release(budget);
            encryption.salt.release(budget);
        } else {
            return Err(KeyStoreError::Selection("unsupported PKCS#12 privacy mode"));
        }
    }
    Ok(())
}

struct Pfx<'a> {
    safe: Bytes<'a>,
    mac: Option<Mac<'a>>,
}
impl<'a> Pfx<'a> {
    fn parse(bytes: &'a [u8], budget: &mut Budget<'_>) -> Result<Self> {
        let mut pfx = Reader::sequence(bytes)?;
        if pfx.integer()? != 3 {
            return malformed();
        }
        let (oid, content) = content_info(pfx.take(0x30)?)?;
        if oid != DATA {
            return Err(KeyStoreError::Selection(
                "unsupported PKCS#12 integrity mode",
            ));
        }
        let safe = octets(content, 4, budget)?;
        let mac = if pfx.0.is_empty() {
            None
        } else {
            Some(Mac::parse(pfx.take(0x30)?, budget)?)
        };
        pfx.finish()?;
        Ok(Self { safe, mac })
    }
}

pub(super) struct Prepared<'a, 'l> {
    pfx: Pfx<'a>,
    limits: &'l Limits,
}

#[cfg(test)]
pub(super) fn prepare<'a, 'l>(bytes: &'a [u8], limits: &'l Limits) -> Result<Prepared<'a, 'l>> {
    prepare_with_work(bytes, limits, 0)
}

pub(super) fn prepare_with_work<'a, 'l>(
    bytes: &'a [u8],
    limits: &'l Limits,
    work: usize,
) -> Result<Prepared<'a, 'l>> {
    let mut budget = Budget::new(limits);
    if work > limits.resources.max_key_import_kdf_work {
        return Err(denial(
            resource_name::KEY_IMPORT_KDF_WORK,
            limits.resources.max_key_import_kdf_work,
        ));
    }
    budget.work = work;
    let pfx = Pfx::parse(bytes, &mut budget)?;
    walk_safe(
        &pfx.safe,
        &mut budget,
        None,
        &mut Contents {
            private_keys: Vec::new(),
            certificates: Vec::new(),
        },
    )?;
    Ok(Prepared { pfx, limits })
}

impl Prepared<'_, '_> {
    #[cfg(test)]
    pub(super) fn decrypt(self, password: &str) -> Result<Contents> {
        self.decrypt_with_password_capacity(password, password.len())
    }

    #[cfg(test)]
    pub(super) fn decrypt_with_password_capacity(
        self,
        password: &str,
        capacity: usize,
    ) -> Result<Contents> {
        self.decrypt_with_work(password, capacity, &mut 0)
    }

    pub(super) fn decrypt_with_work(
        self,
        password: &str,
        capacity: usize,
        work: &mut usize,
    ) -> Result<Contents> {
        let Self { pfx, limits } = self;
        let mut budget = Budget::new(limits);
        if *work > limits.resources.max_key_import_kdf_work {
            return Err(denial(
                resource_name::KEY_IMPORT_KDF_WORK,
                limits.resources.max_key_import_kdf_work,
            ));
        }
        budget.work = *work;
        let result = (|| {
            // The original UTF-8 buffer remains live alongside BER views, BMP
            // conversion, and decrypted contents; a callback can retain spare capacity.
            if password.len() > limits.resources.max_external_resource_bytes {
                return Err(denial(
                    resource_name::EXTERNAL_RESOURCE_BYTES,
                    limits.resources.max_external_resource_bytes,
                ));
            }
            debug_assert!(capacity >= password.len());
            budget.allocate(capacity)?;
            budget.allocate(pfx.safe.owned_capacity())?;
            if let Some(mac) = &pfx.mac {
                budget.allocate(mac.salt.owned_capacity() + mac.digest.owned_capacity())?;
                budget.kdf(mac.rounds, 1, &mac.salt)?;
            }
            let mut password = Password {
                utf8: password,
                bmp: None,
            };
            if let Some(mac) = &pfx.mac {
                mac.verify(&pfx.safe, password.bmp(&mut budget)?, &budget)?;
            }
            let mut contents = Contents {
                private_keys: Vec::new(),
                certificates: Vec::new(),
            };
            walk_safe(&pfx.safe, &mut budget, Some(&mut password), &mut contents)?;
            Ok(contents)
        })();
        // Work is not refunded by password, DER, or later association failures.
        *work = budget.work;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt as _;

    fn encoded(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 128 {
            out.push(value.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }
    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        encoded(0x30, &parts.concat())
    }
    fn oid(value: Oid) -> Vec<u8> {
        encoded(6, value.as_bytes())
    }
    fn integer(value: u16) -> Vec<u8> {
        let mut bytes = value.to_be_bytes().to_vec();
        if bytes[0] == 0 && bytes[1] < 128 {
            bytes.remove(0);
        } else if bytes[0] & 128 != 0 {
            bytes.insert(0, 0);
        }
        encoded(2, &bytes)
    }
    fn bag(kind: Oid, value: &[u8]) -> Vec<u8> {
        sequence(&[oid(kind), encoded(0xa0, value)])
    }
    fn data(safe: &[u8]) -> Vec<u8> {
        sequence(&[oid(DATA), encoded(0xa0, &encoded(4, safe))])
    }
    fn pfx(infos: &[Vec<u8>]) -> Vec<u8> {
        sequence(&[integer(3), data(&sequence(infos))])
    }
    fn limits(candidates: usize) -> Limits {
        Limits {
            resources: ResourcePolicy::default(),
            candidates,
            memory_available: ResourcePolicy::default().max_external_resource_total_bytes,
        }
    }

    #[test]
    fn legacy_password_format_is_bmp_not_utf16() {
        // RFC 7292 B.1 is shared by legacy MAC and encryption derivation;
        // surrogate-pair interoperability must not silently replace BMPString.
        let limits = limits(64);
        let mut budget = Budget::new(&limits);
        let mut password = Password {
            utf8: "p\u{ffff}",
            bmp: None,
        };
        assert_eq!(
            password.bmp(&mut budget).expect("BMP password"),
            &[0, b'p', 255, 255, 0, 0]
        );
        let mut password = Password {
            utf8: "secret\u{1f512}",
            bmp: None,
        };
        let before = budget.memory;
        assert!(matches!(
            password.bmp(&mut budget),
            Err(KeyStoreError::ProtectedContainer)
        ));
        assert_eq!(budget.memory, before, "reject before allocating conversion");
        assert!(password.bmp.is_none());
    }

    #[test]
    fn ciphertext_capacity_is_checked_before_password_derivation() {
        // An already-live callback buffer must stop both PBES2 and legacy KDF
        // paths before any password preprocessing or BMP conversion.
        for hash in [Some(Hash::Sha1), None] {
            let mut limits = limits(64);
            limits.memory_available = 31;
            let mut budget = Budget::new(&limits);
            budget.allocate(16).expect("live password capacity");
            let mut password = Password {
                utf8: "password",
                bmp: None,
            };
            let encryption = Encryption {
                cipher: if hash.is_some() {
                    Cipher::Aes128
                } else {
                    Cipher::TripleDes
                },
                salt: Bytes::Borrowed(b"salt"),
                rounds: 2,
                hash,
                iv: [0; 16],
            };
            assert!(matches!(
                encryption.decrypt(&[0; 16], &mut password, &mut budget),
                Err(KeyStoreError::Policy(_))
            ));
            assert_eq!(budget.work, 0, "no password hashing before memory denial");
            assert!(
                password.bmp.is_none(),
                "no lazy BMP allocation before denial"
            );
        }
    }

    #[test]
    fn ber_private_key_info_is_normalized_before_storage() {
        // KeyBag inherits the PFX BER contract; an indefinite SEQUENCE and
        // constructed OCTET STRING must reach the DER-only key decoder intact.
        let der = sequence(&[
            integer(0),
            sequence(&[
                oid(pkcs8::spki::ObjectIdentifier::new_unwrap(
                    "1.2.840.113549.1.1.1",
                )),
                encoded(5, &[]),
            ]),
            encoded(4, b"private"),
        ]);
        let mut ber = vec![0x30, 0x80];
        ber.extend(integer(0));
        ber.extend(sequence(&[
            oid(Oid::new_unwrap("1.2.840.113549.1.1.1")),
            encoded(5, &[]),
        ]));
        ber.extend([
            0x24, 0x80, 4, 3, b'p', b'r', b'i', 4, 4, b'v', b'a', b't', b'e', 0, 0, 0, 0,
        ]);
        let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
        let limits = limits(64);
        let imported = prepare(&bytes, &limits)
            .expect("BER preflight")
            .decrypt("secret")
            .expect("BER key import");
        assert_eq!(&*imported.private_keys[0], &der);
        let mut tight = limits;
        tight.memory_available = der.len() - 1;
        let mut budget = Budget::new(&tight);
        assert!(matches!(
            normalize_private_key(&ber, &mut budget),
            Err(KeyStoreError::Policy(_))
        ));
        assert_eq!(budget.memory, 0, "denial precedes output allocation");
    }

    #[cfg(feature = "experimental-pq")]
    #[test]
    fn kem_key_bag_reaches_public_inventory() {
        // The full PFX entry point must infer decapsulation-only usage, not
        // reject a valid ML-KEM bag because it inherited signing usage.
        let key = crate::provider::RustCryptoMlKemPrivateKey::from_seed(
            crate::provider::KeyEncapsulationAlgorithm::MlKem512,
            &[3; 64],
        )
        .expect("valid ML-KEM seed");
        let private = key
            .to_pkcs8_der(crate::provider::MlKemPrivateKeyEncoding::Seed)
            .expect("seed PKCS#8 export");
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_KEY_BAG_OID,
            private.as_bytes(),
        )]))]);
        let mut inventory = crate::key_manager::KeyInventory::default();
        inventory
            .add_pkcs12(
                "recipient".into(),
                &bytes,
                "secret",
                &ResourcePolicy::default(),
            )
            .expect("ML-KEM PKCS#12 import");
        assert_eq!(
            inventory.private_keys()[0].usages,
            crate::key_manager::KeyUsages::DECRYPT
        );
    }

    #[test]
    fn ber_key_bag_reaches_public_inventory() {
        // Public import must normalize the actual key, not merely accept BER
        // framing in preflight and fail in the later PKCS#8 decoder.
        let private = pem::parse(include_bytes!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("PKCS#8 fixture")
        .into_contents();
        let sequence_value = tlv(&private, 0).expect("PrivateKeyInfo sequence").0;
        let mut ber = vec![0x30, 0x80];
        ber.extend_from_slice(sequence_value.value);
        ber.extend_from_slice(&[0, 0]);
        let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
        let mut inventory = crate::key_manager::KeyInventory::default();
        inventory
            .add_pkcs12(
                "signer".into(),
                &bytes,
                "secret",
                &ResourcePolicy::default(),
            )
            .expect("public BER import");
        assert_eq!(inventory.private_keys().len(), 1);
    }

    #[test]
    fn encrypted_data_version_tracks_unprotected_attributes() {
        // CMS version 2 is required exactly when [1] attributes are present.
        // Validate them before password processing, including malformed tails.
        let algorithm = sequence(&[
            oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
            sequence(&[encoded(4, b"12345678"), integer(2)]),
        ]);
        let info = sequence(&[oid(DATA), algorithm, encoded(0x80, &[0; 8])]);
        let attribute = sequence(&[
            oid(Oid::new_unwrap("1.2.3.4")),
            encoded(0x31, &encoded(4, b"value")),
        ]);
        // RFC 5652 5.3 constrains the outer attribute collection, not the
        // generic Attribute.attrValues SET OF. Empty unknown values are valid.
        let empty_values = sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, &[])]);
        for (version, attrs, accepted) in [
            (0, None, true),
            (2, Some(attribute.clone()), true),
            (2, Some(empty_values), true),
            (0, Some(attribute), false),
            (2, None, false),
            (2, Some(Vec::new()), false),
            (2, Some(vec![0xff]), false),
        ] {
            let mut parts = vec![integer(version), info.clone()];
            if let Some(attrs) = attrs {
                parts.push(encoded(0xa1, &attrs));
            }
            let limits = limits(64);
            let mut budget = Budget::new(&limits);
            let bytes = sequence(&parts);
            assert_eq!(
                encrypted_content(
                    tlv(&bytes, 0).expect("EncryptedData sequence").0,
                    &mut budget
                )
                .is_ok(),
                accepted,
                "version {version}"
            );
        }
    }

    #[test]
    fn unsupported_algorithms_are_distinct_from_bad_passwords() {
        // Unsupported capabilities must fail during preflight, rather than
        // suggesting that a password was tried and could not decode the key.
        let unsupported = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
        for hmac in [false, true] {
            assert!(matches!(
                Hash::from_oid(unsupported, hmac),
                Err(KeyStoreError::Selection(_))
            ));
        }
        let derivation = sequence(&[encoded(4, b"salt"), integer(2)]);
        for algorithm in [
            sequence(&[oid(unsupported), derivation.clone()]),
            sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[oid(PBKDF2), derivation.clone()]),
                    sequence(&[oid(unsupported), encoded(4, &[0; 16])]),
                ]),
            ]),
            sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[oid(unsupported), derivation]),
                    sequence(&[
                        oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                        encoded(4, &[0; 16]),
                    ]),
                ]),
            ]),
        ] {
            let bytes = pfx(&[data(&sequence(&[bag(
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                &sequence(&[algorithm, encoded(4, &[0; 16])]),
            )]))]);
            assert!(matches!(
                prepare(&bytes, &limits(64)),
                Err(KeyStoreError::Selection(_))
            ));
        }
    }

    #[test]
    fn high_tag_attributes_are_valid_ber() {
        // Unknown attributes are ignorable, but their high-number identifiers
        // must remain well framed for primitive, constructed and indefinite BER.
        for value in [
            vec![0x9f, 31, 1, 7],
            vec![0xbf, 0x81, 0, 2, 4, 0],
            vec![0xbf, 31, 0x80, 4, 0, 0, 0],
            vec![
                0x9f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0,
            ],
        ] {
            let key = sequence(&[
                oid(pkcs12::PKCS_12_KEY_BAG_OID),
                encoded(0xa0, &[0x30, 0]),
                encoded(
                    0x31,
                    &sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, &value)]),
                ),
            ]);
            assert!(prepare(&pfx(&[data(&sequence(&[key]))]), &limits(64)).is_ok());
        }
        for value in [
            &[0x9f, 0, 0][..],
            &[0x9f, 0x80, 31, 0],
            &[0x9f, 30, 0],
            &[0x9f, 0x81],
            &[0x9f, 31],
            &[0x9f, 31, 0x80, 0, 0],
        ] {
            assert!(
                tlv(value, 0).is_err(),
                "malformed identifier/length {value:?}"
            );
        }
    }

    #[test]
    fn malformed_bag_attributes_are_rejected_before_password() {
        // Optional attributes are still ASN.1 Attribute records, not an
        // unchecked opaque tail that can hide malformed BER.
        let key = sequence(&[
            oid(pkcs12::PKCS_12_KEY_BAG_OID),
            encoded(0xa0, &[0x30, 0]),
            encoded(0x31, &[0xff]),
        ]);
        assert!(prepare(&pfx(&[data(&sequence(&[key]))]), &limits(64)).is_err());
    }

    #[test]
    fn redundant_integer_octets_are_not_ber() {
        // X.690 8.3.2 disallows a redundant leading zero even for BER.
        assert!(Reader(&[2, 2, 0, 3]).integer().is_err());
    }

    #[test]
    fn content_infos_and_bags_share_candidate_count() {
        // Empty ContentInfos still inspect a source; bags cannot start a new allowance.
        let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &[0x30, 0]);
        let bytes = pfx(&[data(&sequence(&[])), data(&sequence(&[key]))]);
        assert!(matches!(
            prepare(&bytes, &limits(2)),
            Err(KeyStoreError::Policy(
                PolicyViolation::ResourceLimitExceeded {
                    resource: resource_name::KEY_CANDIDATES,
                    maximum: 2
                }
            ))
        ));
        assert!(prepare(&bytes, &limits(3)).is_ok());
    }

    #[test]
    fn nested_bags_share_candidate_count() {
        // A nested SafeContentsBag is not a reset of the outer bag budget.
        let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &[0x30, 0]);
        let nested = bag(pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID, &sequence(&[key]));
        assert!(matches!(
            prepare(&pfx(&[data(&sequence(&[nested]))]), &limits(1)),
            Err(KeyStoreError::Policy(
                PolicyViolation::ResourceLimitExceeded {
                    resource: resource_name::KEY_CANDIDATES,
                    maximum: 1
                }
            ))
        ));
    }

    #[test]
    fn constructed_octets_preserve_mac_input_and_ownership() {
        // Constructed OCTET STRING concatenates primitive contents; its
        // allocation must be charged once and released by retained capacity.
        let value = [0x24, 0x80, 4, 2, b'a', b'b', 0x24, 3, 4, 1, b'c', 0, 0];
        let limits = limits(64);
        let mut budget = Budget::new(&limits);
        let bytes = octets(tlv(&value, 0).expect("BER").0, 4, &mut budget).expect("flatten");
        assert_eq!(&*bytes, b"abc");
        assert_eq!(budget.memory, 3);
        bytes.release(&mut budget);
        assert_eq!(budget.memory, 0);
        assert!(tlv(&[4, 0x80, 0, 0], 0).is_err());
        assert!(tlv(&[0x30, 0x80, 4, 1, 7], 0).is_err());
    }

    #[test]
    fn legacy_shrouded_key_and_hidden_limits() {
        // Exercise RustCrypto's PKCS#12 KDF with legacy SHA-1/3DES, then
        // prove an encrypted SafeContents cannot reset the inner KDF budget.
        let password = "secret";
        let bmp: Vec<u8> = password
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_be_bytes)
            .collect();
        let salt = b"12345678";
        let key = derive_key::<sha1::Sha1>(&bmp, salt, Pkcs12KeyType::EncryptionKey, 2, 24);
        let iv = derive_key::<sha1::Sha1>(&bmp, salt, Pkcs12KeyType::Iv, 2, 8);
        let algorithm = sequence(&[
            oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
            sequence(&[encoded(4, salt), integer(2)]),
        ]);
        let private = pem::parse(include_bytes!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("key")
        .into_contents();
        let encrypt = |bytes: &[u8]| {
            let mut output = vec![0; bytes.len() + 8];
            cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                .expect("cipher")
                .encrypt_padded_b2b::<Pkcs7>(bytes, &mut output)
                .expect("padding")
                .to_vec()
        };
        let shrouded = bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[algorithm.clone(), encoded(4, &encrypt(&private))]),
        );
        let bytes = pfx(&[data(&sequence(std::slice::from_ref(&shrouded)))]);
        let limits = limits(64);
        let contents = prepare(&bytes, &limits)
            .expect("preflight")
            .decrypt(password)
            .expect("legacy import");
        assert_eq!(&*contents.private_keys[0], &private);
        assert!(
            prepare(&bytes, &limits)
                .expect("preflight")
                .decrypt("wrong")
                .is_err()
        );
        let encrypted_safe = sequence(&[
            oid(ENCRYPTED_DATA),
            encoded(
                0xa0,
                &sequence(&[
                    integer(0),
                    sequence(&[
                        oid(DATA),
                        algorithm,
                        encoded(0x80, &encrypt(&sequence(&[shrouded]))),
                    ]),
                ]),
            ),
        ]);
        let bytes = pfx(&[encrypted_safe]);
        let tight = Limits {
            resources: ResourcePolicy {
                max_key_import_kdf_work: 6,
                ..ResourcePolicy::default()
            },
            candidates: 64,
            memory_available: ResourcePolicy::default().max_external_resource_total_bytes,
        };
        let prepared = prepare(&bytes, &tight).expect("outer KDF fits");
        assert!(matches!(
            prepared.decrypt(password),
            Err(KeyStoreError::Policy(
                PolicyViolation::ResourceLimitExceeded {
                    resource: resource_name::KEY_IMPORT_KDF_WORK,
                    maximum: 6
                }
            ))
        ));
    }

    #[test]
    fn pbes2_ber_iv_forms_preserve_decryption() {
        // RFC 7292 section 4 accepts BER; X.690 8.7 permits nested,
        // definite or indefinite OCTET STRING segmentation for the IV.
        let private = pem::parse(include_bytes!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("key")
        .into_contents();
        let iv = [7; 16];
        let mut key = [0; 16];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"secret", b"12345678", 2, &mut key);
        let mut output = vec![0; private.len() + 16];
        let ciphertext = cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key, &iv)
            .expect("cipher")
            .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
            .expect("padding")
            .to_vec();
        let segments = [encoded(4, &iv[..5]), encoded(4, &iv[5..])].concat();
        for encoded_iv in [
            encoded(4, &iv),
            encoded(0x24, &segments),
            [vec![0x24, 0x80], segments.clone(), vec![0, 0]].concat(),
            encoded(0x24, &encoded(0x24, &segments)),
        ] {
            let algorithm = sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[
                        oid(PBKDF2),
                        sequence(&[encoded(4, b"12345678"), integer(2)]),
                    ]),
                    sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), encoded_iv]),
                ]),
            ]);
            let bytes = pfx(&[data(&sequence(&[bag(
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                &sequence(&[algorithm, encoded(4, &ciphertext)]),
            )]))]);
            let mut inventory = super::super::KeyInventory::default();
            inventory
                .add_pkcs12("key".into(), &bytes, "secret", &ResourcePolicy::default())
                .expect("all BER IV forms import");
            assert_eq!(inventory.private_keys()[0].pkcs8_der.as_slice(), private);
        }
    }

    #[test]
    fn pbes2_ber_iv_rejects_invalid_segments_and_lengths() {
        // Segmentation changes framing, never AES's required IV length or
        // the universal OCTET STRING type of each component.
        for iv in [
            encoded(4, &[0; 15]),
            encoded(4, &[0; 17]),
            encoded(0x24, &encoded(4, &[0; 17])),
            encoded(0x24, &encoded(2, &[0; 16])),
            [vec![0x24, 0x80], encoded(4, &[0; 16])].concat(),
        ] {
            let algorithm = sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[oid(PBKDF2), sequence(&[encoded(4, b"salt"), integer(2)])]),
                    sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), iv]),
                ]),
            ]);
            let limits = limits(64);
            let mut budget = Budget::new(&limits);
            let result =
                tlv(&algorithm, 0).and_then(|(value, _)| Encryption::parse(value, &mut budget));
            assert!(matches!(result, Err(KeyStoreError::ProtectedContainer)));
            assert_eq!(budget.memory, 0, "IV framing requires no heap allocation");
        }
    }

    #[test]
    fn kdf_integer_classification_preserves_ber_errors() {
        // Machine-width-independent policy denial must not hide malformed
        // negative/redundant/empty INTEGER encodings (X.690 8.3.2).
        let limits = Limits {
            resources: ResourcePolicy {
                max_key_import_kdf_work: 128,
                ..ResourcePolicy::default()
            },
            ..limits(64)
        };
        let budget = Budget::new(&limits);
        for value in [&[][..], &[0x80][..], &[0, 1][..]] {
            let encoded = encoded(2, value);
            assert!(matches!(
                Reader(&encoded).kdf_iterations(&budget),
                Err(KeyStoreError::ProtectedContainer)
            ));
        }
        let exact = encoded(2, &[0, 128]);
        assert_eq!(
            Reader(&exact).kdf_iterations(&budget).expect("exact limit"),
            128
        );
        let exceeded = encoded(2, &[0, 129]);
        assert!(matches!(
            Reader(&exceeded).kdf_iterations(&budget),
            Err(KeyStoreError::Policy(
                PolicyViolation::KdfIterationsOutsideLimit { maximum: 128 }
            ))
        ));
    }

    #[test]
    fn oversized_kdf_integers_are_policy_failures() {
        // Positive BER INTEGERs do not become malformed merely because
        // they exceed a machine integer; reject work before any password.
        for value in [&[1, 0, 0, 0, 0][..], &[1, 0, 0, 0, 0, 0, 0, 0, 0][..]] {
            let rounds = encoded(2, value);
            let pbes2 = sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[
                        oid(PBKDF2),
                        sequence(&[encoded(4, b"salt"), rounds.clone()]),
                    ]),
                    sequence(&[
                        oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                        encoded(4, &[0; 16]),
                    ]),
                ]),
            ]);
            let legacy = sequence(&[
                oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
                sequence(&[encoded(4, b"salt"), rounds.clone()]),
            ]);
            for algorithm in [pbes2, legacy] {
                let bytes = pfx(&[data(&sequence(&[bag(
                    pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                    &sequence(&[algorithm, encoded(4, &[0; 16])]),
                )]))]);
                let limits = limits(64);
                assert!(matches!(
                    prepare(&bytes, &limits),
                    Err(KeyStoreError::Policy(
                        PolicyViolation::KdfIterationsOutsideLimit { .. }
                    ))
                ));
                let calls = std::cell::Cell::new(0);
                let result = super::super::KeyInventory::default()
                    .add_pkcs12_with_password_callback(
                        "key".into(),
                        &bytes,
                        || {
                            calls.set(calls.get() + 1);
                            None
                        },
                        super::super::KeyUsages::SIGN,
                        &limits.resources,
                    );
                assert!(matches!(
                    result,
                    Err(KeyStoreError::Policy(
                        PolicyViolation::KdfIterationsOutsideLimit { .. }
                    ))
                ));
                assert_eq!(
                    calls.get(),
                    0,
                    "oversized work is rejected before password delivery"
                );
            }
            let mac = sequence(&[
                sequence(&[
                    sequence(&[oid(Oid::new_unwrap("1.3.14.3.2.26")), encoded(5, &[])]),
                    encoded(4, &[0; 20]),
                ]),
                encoded(4, b"salt"),
                rounds,
            ]);
            let bytes = sequence(&[integer(3), data(&sequence(&[])), mac]);
            assert!(matches!(
                prepare(&bytes, &limits(64)),
                Err(KeyStoreError::Policy(
                    PolicyViolation::KdfIterationsOutsideLimit { .. }
                ))
            ));
        }
    }

    #[test]
    fn pbes2_password_shares_work_and_live_memory_budget() {
        // A no-MAC PFX still hashes its UTF-8 password before PBKDF2. Policy
        // denial must precede derivation, and callback spare capacity is live.
        let password = "p".repeat(256);
        let private = pem::parse(include_bytes!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("key")
        .into_contents();
        let mut key = [0; 16];
        let iv = [7; 16];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), b"salt", 2, &mut key);
        let mut output = vec![0; private.len() + 16];
        let ciphertext = cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key, &iv)
            .expect("cipher")
            .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
            .expect("padding")
            .to_vec();
        let algorithm = sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[oid(PBKDF2), sequence(&[encoded(4, b"salt"), integer(2)])]),
                sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), encoded(4, &iv)]),
            ]),
        ]);
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[algorithm, encoded(4, &ciphertext)]),
        )]))]);
        let peak = password.len() + ciphertext.len() + core::mem::size_of::<Zeroizing<Vec<u8>>>();
        for (work, memory, per_resource) in [(5, peak, 256), (6, peak - 1, 256), (6, peak, 255)] {
            let mut limits = limits(64);
            limits.resources.max_key_import_kdf_work = work;
            limits.resources.max_external_resource_bytes = per_resource;
            limits.memory_available = memory;
            assert!(matches!(
                prepare(&bytes, &limits)
                    .expect("visible KDF fits")
                    .decrypt(&password),
                Err(KeyStoreError::Policy(_))
            ));
        }
        let mut exact = limits(64);
        exact.resources.max_key_import_kdf_work = 6;
        exact.memory_available = peak;
        assert_eq!(
            &*prepare(&bytes, &exact)
                .expect("preflight")
                .decrypt(&password)
                .expect("exact password allowances")
                .private_keys[0],
            &private
        );
        let mut secret = String::with_capacity(4096);
        secret.push_str(&password);
        let resources = ResourcePolicy {
            max_external_resource_total_bytes: bytes.len() + peak + 3,
            ..ResourcePolicy::default()
        };
        let mut inventory = super::super::KeyInventory::default();
        assert!(matches!(
            inventory.add_pkcs12_with_password_callback(
                "new".into(),
                &bytes,
                || Some(Zeroizing::new(secret)),
                super::super::KeyUsages::SIGN,
                &resources
            ),
            Err(KeyStoreError::Policy(_))
        ));
        assert!(inventory.private_keys().is_empty());
    }

    #[test]
    fn pbes2_cipher_prf_matrix_accepts_utf8_passwords_without_legacy_kdf() {
        // RFC 8018 PBES2 does not impose RFC 7292's legacy BMP password
        // conversion. Test every supported AES width and HMAC PRF with a
        // non-BMP UTF-8 password, including the default SHA-1 PRF.
        let password = "secret\u{1f512}";
        let private = pem::parse(include_bytes!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("private key")
        .into_contents();
        let salt = b"salt beyond the old fixed thirty-two byte representation";
        let iv = [7_u8; 16];
        let prfs = [
            (Hash::Sha1, "1.2.840.113549.2.7"),
            (Hash::Sha224, "1.2.840.113549.2.8"),
            (Hash::Sha256, "1.2.840.113549.2.9"),
            (Hash::Sha384, "1.2.840.113549.2.10"),
            (Hash::Sha512, "1.2.840.113549.2.11"),
        ];
        for (cipher, cipher_oid) in [
            (Cipher::Aes128, pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
            (Cipher::Aes192, pkcs8::pkcs5::pbes2::AES_192_CBC_OID),
            (Cipher::Aes256, pkcs8::pkcs5::pbes2::AES_256_CBC_OID),
        ] {
            for (hash, prf_oid) in prfs {
                let mut key = Zeroizing::new([0_u8; 32]);
                with_hash!(
                    hash,
                    D,
                    pbkdf2::pbkdf2_hmac::<D>(
                        password.as_bytes(),
                        salt,
                        2,
                        &mut key[..cipher.key_len()]
                    )
                );
                let mut output = vec![0; private.len() + 16];
                macro_rules! encrypt {
                    ($cipher:ty) => {
                        cbc::Encryptor::<$cipher>::new_from_slices(&key[..cipher.key_len()], &iv)
                            .expect("cipher")
                            .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
                            .expect("padding")
                            .to_vec()
                    };
                }
                let ciphertext = match cipher {
                    Cipher::Aes128 => encrypt!(aes::Aes128Enc),
                    Cipher::Aes192 => encrypt!(aes::Aes192Enc),
                    Cipher::Aes256 => encrypt!(aes::Aes256Enc),
                    _ => unreachable!(),
                };
                let mut params = vec![
                    encoded(4, salt),
                    integer(2),
                    integer(cipher.key_len() as u16),
                ];
                if !matches!(hash, Hash::Sha1) {
                    params.push(sequence(&[oid(Oid::new_unwrap(prf_oid)), encoded(5, &[])]));
                }
                let algorithm = sequence(&[
                    oid(PBES2),
                    sequence(&[
                        sequence(&[oid(PBKDF2), sequence(&params)]),
                        sequence(&[oid(cipher_oid), encoded(4, &iv)]),
                    ]),
                ]);
                let shrouded = bag(
                    pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                    &sequence(&[algorithm, encoded(4, &ciphertext)]),
                );
                let bytes = pfx(&[data(&sequence(&[shrouded]))]);
                let limits = limits(64);
                let contents = prepare(&bytes, &limits)
                    .expect("PBES2 preflight")
                    .decrypt(password)
                    .expect("UTF-8 PBES2 import");
                assert_eq!(&*contents.private_keys[0], &private);
            }
        }
    }
}
