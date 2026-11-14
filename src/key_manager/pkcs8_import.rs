//! Encrypted PKCS#8 (RFC 5958 section 3) over the shared password engine of
//! `structured_cms::personal::password`: the engine reads the protection,
//! states its key-derivation parameters and decrypts; the inventory admits
//! those parameters under the policy before any password is used.

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::personal::password::{self as engine, Decryption, KdfCost, Password};
use structured_cms::personal::{self, ShroudedKey};
use zeroize::Zeroizing;

use super::KeyStoreError;
use super::pkcs12_import::Ceilings;
use crate::policy::ResourcePolicy;

type Result<T> = core::result::Result<T, KeyStoreError>;

const UNSUPPORTED: &str = "unsupported PKCS#8 encryption algorithm";

/// What admission needs of an encrypted key before its password: the KDF's
/// parameters, the plaintext buffer the decryption fills and the scratch
/// every password needs.
pub(super) struct Shape {
    pub(super) kdf: KdfCost,
    pub(super) output: usize,
    pub(super) scratch: usize,
}

/// The shape of the encrypted key `bytes`.
pub(super) fn shape(bytes: &[u8], resources: &ResourcePolicy) -> Result<Shape> {
    with_plan(bytes, resources, |plan, _, ceilings| {
        let kdf = plan
            .kdf_cost()
            .map_err(|e| ceilings.engine(e, UNSUPPORTED))?;
        let cost = plan.cost().map_err(|e| ceilings.engine(e, UNSUPPORTED))?;
        Ok(Shape {
            kdf,
            output: cost.output,
            scratch: cost.scratch,
        })
    })
}

/// The `PrivateKeyInfo` the encrypted key `bytes` holds, decrypted with
/// `password` into one wiping buffer. The caller has admitted the KDF;
/// `admit_scratch` admits the full scratch, which grows with the password
/// for a legacy one, before it is allocated.
pub(super) fn decrypt(
    bytes: &[u8],
    password: &[u8],
    resources: &ResourcePolicy,
    admit_scratch: impl FnOnce(usize) -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    with_plan(bytes, resources, |plan, query, ceilings| {
        let engine = |error| ceilings.engine(error, UNSUPPORTED);
        let bmp;
        let input = if plan.uses_legacy_password() {
            // RFC 7292 B.1 reads the password as text.
            let text =
                core::str::from_utf8(password).map_err(|_| KeyStoreError::ProtectedContainer)?;
            bmp = personal::legacy_password(text, query).map_err(|e| ceilings.refuse(&e))?;
            Password::Legacy(bmp.as_bytes())
        } else {
            Password::Octets(password)
        };
        let cost = plan.cost().map_err(engine)?;
        let extra = plan.password_cost(input).map_err(engine)?;
        let scratch = cost
            .scratch
            .checked_add(extra.scratch)
            .ok_or(KeyStoreError::ProtectedContainer)?;
        admit_scratch(scratch)?;
        let mut output = Zeroizing::new(vec![0; cost.output]);
        let mut scratch = Zeroizing::new(vec![0; scratch]);
        let length = plan
            .decrypt(input, &mut output, &mut scratch, query)
            .map_err(engine)?;
        output.truncate(length);
        Ok(output)
    })
}

/// Runs `run` over the decryption plan of the encrypted key `bytes`.
fn with_plan<R>(
    bytes: &[u8],
    resources: &ResourcePolicy,
    run: impl FnOnce(&Decryption<'_, '_>, &Reader<'_>, Ceilings) -> Result<R>,
) -> Result<R> {
    let ceilings = Ceilings {
        memory: resources.max_external_resource_total_bytes,
        work: resources
            .max_x509_work
            .min(crate::hard_limits::X509_WORK_CEILING),
    };
    // The engine's own work is charged to this session; the policy's KDF
    // limits are admitted by the caller from the stated parameters. The
    // caller counts the input and every buffer against the aggregate budget;
    // the reader's own bookkeeping over the document is bounded as one
    // resource.
    let parser = Parser::new(
        Encoding::Der,
        structured_asn1::Limits {
            max_depth: crate::hard_limits::ASN1_DEPTH_CEILING,
            max_elements: ceilings.work as u64,
            max_element_length: u64::MAX,
            max_work: ceilings.work as u64,
        },
        Memory::new(Arc::new(MemoryAccount::new(
            resources.max_external_resource_bytes,
            ceilings.work,
        ))),
    );
    let mut reader = parser.read(bytes, 0).map_err(|e| ceilings.refuse(&e))?;
    let element = reader
        .next_element()
        .map_err(|e| ceilings.refuse(&e))?
        .ok_or(KeyStoreError::ProtectedContainer)?;
    let key = ShroudedKey::read(&reader, &element).map_err(|e| ceilings.refuse(&e))?;
    let plan = Decryption::key(&key, &reader).map_err(|e| match e {
        engine::Error::Unsupported => KeyStoreError::ProtectedContainer,
        error => ceilings.engine(error, UNSUPPORTED),
    })?;
    run(&plan, &reader, ceilings)
}
