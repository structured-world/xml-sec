//! The `KeyInfo` child a read derived, agreed or decapsulated its key by, with the octets
//! it yielded, kept in the read context's `reserved1` until the decryption
//! reading with that context takes the key: the core takes such a key for
//! that element alone. A signature operation takes an ML-KEM `EncryptedKey`
//! its read decapsulated, or its write encapsulated, the same way.

use xml_sec::Node;
use xml_sec::policy::DecryptionPolicy;
use xml_sec::provider::KeyEncapsulationAlgorithm;
use xml_sec::xmlenc::{AgreementMethod, DerivedKey};
use zeroize::Zeroizing;

use super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::keyinfo::XmlSecKeyInfoCtx;
use super::super::keys::{XmlSecKey, xmlSecKeyGetValue};
use super::super::keysdata::xmlSecKeyDataBinaryValueGetBuffer;
use super::super::policy::{self, Side, with_document_policy};
use super::super::tree::XmlNode;

/// The element a key came from, as the core reads it among the descriptors
/// of an `EncryptedData`'s `KeyInfo`.
pub(super) enum Descriptor {
    /// A `DerivedKey`.
    Derived(DerivedKey),
    /// An `AgreementMethod` that yields the content key itself.
    Agreement(AgreementMethod),
    /// An ML-KEM `EncryptedKey`, named by its parameter set and ciphertext:
    /// the ciphertext is the encapsulation's own, so no other element
    /// decapsulates to the same key.
    Encapsulation {
        /// The parameter set.
        algorithm: KeyEncapsulationAlgorithm,
        /// The FIPS 203 ciphertext.
        ciphertext: Vec<u8>,
    },
}

impl Descriptor {
    /// The `DerivedKey` element `node` under `policy`.
    pub(super) fn derived(node: Node<'_, '_>, policy: &DecryptionPolicy) -> Option<Self> {
        DerivedKey::from_element(node, policy)
            .ok()
            .map(Self::Derived)
    }

    /// The `AgreementMethod` element `node` under `policy`.
    pub(super) fn agreement(node: Node<'_, '_>, policy: &DecryptionPolicy) -> Option<Self> {
        AgreementMethod::from_element(node, policy)
            .ok()
            .map(Self::Agreement)
    }

    /// The ML-KEM `EncryptedKey` element `node`, as the core reads it among
    /// an `EncryptedData`'s key sources; `None` for any other element.
    pub(super) fn encapsulation(node: Node<'_, '_>, _policy: &DecryptionPolicy) -> Option<Self> {
        xml_sec::key_establishment::parse_encapsulation(node, false)
            .ok()
            .map(|parsed| Self::Encapsulation {
                algorithm: parsed.algorithm,
                ciphertext: parsed.ciphertext().to_vec(),
            })
    }

    /// Whether this is the encapsulation `descriptor` the core reads.
    pub(super) fn is_encapsulation(
        &self,
        descriptor: &xml_sec::key_establishment::EncapsulationMechanism,
    ) -> bool {
        matches!(self, Self::Encapsulation { algorithm, ciphertext }
            if *algorithm == descriptor.algorithm && *ciphertext == descriptor.ciphertext)
    }
}

/// A key's element and the octets it yielded.
pub(super) struct KeySource {
    /// The element the key came from.
    pub(super) descriptor: Descriptor,
    key: Zeroizing<Vec<u8>>,
}

impl KeySource {
    /// Whether `key` holds the octets this source yielded: a later child of
    /// a read that does not stop on the key may have replaced them.
    pub(super) fn yielded(&self, key: &[u8]) -> bool {
        self.key.as_slice() == key
    }
}

/// The source by which the element `node` yielded `key`, the element read by
/// `parse` under the decryption policy of the read with `ctx`; `None` when
/// that read pins no revision or the core reads no descriptor there, so no
/// decryption takes the key for the element.
///
/// # Safety
/// `ctx` is an initialized context; `node` a live node; `key` a key.
pub(super) unsafe fn of(
    ctx: *mut XmlSecKeyInfoCtx,
    node: *mut XmlNode,
    key: *mut XmlSecKey,
    parse: fn(Node<'_, '_>, &DecryptionPolicy) -> Option<Descriptor>,
) -> Option<KeySource> {
    // SAFETY: by the caller's contract.
    unsafe {
        let pinned = policy::pinned((*ctx).reserved0)?;
        let operation = pinned.of(Side::Decrypt);
        let descriptor = with_document_policy!(operation, |policy| {
            xml_sec_libxml2::document::subtree(node, policy)
                .ok()
                .and_then(|document| {
                    document
                        .with_view(|view| parse(view.document().root_element(), &pinned.decryption))
                })
        })?;
        let buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
        let data = xmlSecBufferGetData(buffer);
        if data.is_null() {
            return None;
        }
        let key = std::slice::from_raw_parts(data, xmlSecBufferGetSize(buffer));
        Some(KeySource {
            descriptor,
            key: Zeroizing::new(key.to_vec()),
        })
    }
}

/// Makes `source` the one the read with `ctx` recorded, forgetting an
/// earlier one; with none, the read records nothing.
///
/// # Safety
/// `ctx` is an initialized context.
pub(super) unsafe fn record(ctx: *mut XmlSecKeyInfoCtx, source: Option<KeySource>) {
    // SAFETY: by the caller's contract.
    unsafe {
        forget(ctx);
        if let Some(source) = source {
            (*ctx).reserved1 = Box::into_raw(Box::new(source)).cast();
        }
    }
}

/// Forgets the source the read with `ctx` recorded.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn forget(ctx: *mut XmlSecKeyInfoCtx) {
    // SAFETY: by the caller's contract; the slot is null or a recorded
    // source, released once.
    unsafe {
        let slot = (*ctx).reserved1;
        if !slot.is_null() {
            drop(Box::from_raw(slot.cast::<KeySource>()));
            (*ctx).reserved1 = std::ptr::null_mut();
        }
    }
}

/// The ML-KEM `EncryptedKey` the read or write with `ctx` recorded `key`'s
/// octets by, taken from it: the parameter set and ciphertext a signature
/// operation hands the core with that key. `None` when it recorded no
/// encapsulation, or another key's octets.
///
/// # Safety
/// `ctx` is an initialized context; `key` is null or a key.
pub(crate) unsafe fn take_encapsulation(
    ctx: *mut XmlSecKeyInfoCtx,
    key: *mut XmlSecKey,
) -> Option<(KeyEncapsulationAlgorithm, Vec<u8>)> {
    // SAFETY: by the caller's contract.
    unsafe {
        let source = take(ctx)?;
        if key.is_null() {
            return None;
        }
        let buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
        let data = xmlSecBufferGetData(buffer);
        if data.is_null()
            || !source.yielded(std::slice::from_raw_parts(
                data,
                xmlSecBufferGetSize(buffer),
            ))
        {
            return None;
        }
        match source.descriptor {
            Descriptor::Encapsulation {
                algorithm,
                ciphertext,
            } => Some((algorithm, ciphertext)),
            Descriptor::Derived(_) | Descriptor::Agreement(_) => None,
        }
    }
}

/// The source the read with `ctx` recorded, taken from it.
///
/// # Safety
/// `ctx` is an initialized context.
pub(super) unsafe fn take(ctx: *mut XmlSecKeyInfoCtx) -> Option<Box<KeySource>> {
    // SAFETY: by the caller's contract; the slot is null or a recorded
    // source, whose ownership moves to the caller.
    unsafe {
        let slot = std::mem::replace(&mut (*ctx).reserved1, std::ptr::null_mut());
        (!slot.is_null()).then(|| Box::from_raw(slot.cast::<KeySource>()))
    }
}
